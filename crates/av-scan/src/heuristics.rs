//! Static heuristics: what a file's structure says about it.
//!
//! # What this is for
//!
//! A signature answers "is this a known sample". A heuristic answers "does this
//! look like it was built the way malware is built" — and the second question
//! is the one that covers the sample nobody has seen yet. Every file here is
//! read-only: nothing in this module writes, deletes, quarantines or blocks.
//! It produces [`Detection`]s and the verdict model decides what they mean.
//!
//! # The accumulation rule, and the rule that bounds it
//!
//! Indicators accumulate. A file that is packed *and* has a writable-executable
//! section *and* carries a high-entropy overlay is not three times as suspicious
//! as one that is only packed — it is a different, much more specific claim,
//! and the score is how that is expressed.
//!
//! What is deliberately *not* done is scoring the same observation twice. A
//! file with four high-entropy sections is one observation ("this file is
//! packed"), not four, and the module reports it once, at the highest entropy
//! it found. Scoring each section separately would turn any sufficiently large
//! executable into a detection, which is exactly how a heuristic engine earns
//! its false positives.
//!
//! # No single heuristic can convict
//!
//! Every severity below is at most [`Severity::Medium`], which scores 60
//! against a malicious threshold of 100. **No detector in this module reaches
//! the malicious band on its own**, and that is a property the tests assert
//! rather than a comment: a heuristic is a probabilistic statement about how a
//! file was built, and probabilistic statements do not get to delete a user's
//! file by themselves. Two independent ones reach the suspicious band, which
//! notifies without acting; three or four reach malicious, and by then the file
//! has independently exhibited several of the things malware does.
//!
//! # Why every score here is discounted by trust
//!
//! Heuristics are the one class of detection that code-signing is genuinely
//! evidence about. "This file is packed" is a claim about how the file was
//! built, and a valid signature from a real publisher is a statement about
//! exactly that. So the trust layer discounts these and never discounts a rule
//! that names a family. See [`crate::trust`].

use av_core::{Detection, DetectionSource, MatchLocation, Severity};
use av_pe::headers::directory;
use av_pe::Imports;
use av_rules::vm::PeInput;

use av_core::stats;

/// When a heuristic fires. Thresholds, not scores: the scores come from
/// [`Severity`], so that the calibration lives in one place.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeuristicConfig {
    /// Whether to run any of this at all. Off for real-time, where a file-open
    /// hook cannot afford to walk a section table.
    pub enabled: bool,
    /// Shannon entropy, in bits per byte, at which a section is called packed.
    ///
    /// 7.2 is the conventional line. Genuine compiled code sits near 6.5 and
    /// compressed or encrypted data sits above 7.9, so the threshold is in the
    /// gap — but the gap is not empty: a section full of x86 floating-point
    /// constants, a large resource, or a statically linked runtime can reach
    /// 7.2 honestly. That is why this is [`Severity::Low`].
    pub section_entropy: f64,
    /// The same, for the file as a whole and only for executable images.
    ///
    /// Higher than the per-section line because a whole file includes its
    /// headers, its import table and its padding, all of which are low-entropy
    /// and pull the average down.
    pub file_entropy: f64,
    /// Sections smaller than this are not measured. Entropy over a few hundred
    /// bytes is noise: the maximum over 256 possible values is reached by any
    /// short run of distinct bytes.
    pub min_section_bytes: usize,
    /// Overlays smaller than this are not measured, for the same reason, and
    /// because a small overlay is routine — the attribute certificate table of
    /// a signed file sits outside the sections and is an overlay.
    pub min_overlay_bytes: u64,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            section_entropy: 7.2,
            file_entropy: 7.5,
            min_section_bytes: 4096,
            min_overlay_bytes: 64 * 1024,
        }
    }
}

impl HeuristicConfig {
    /// Everything off. What a real-time scan uses.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// Run every structural heuristic against a parsed image.
///
/// `pe` is `None` for anything that is not a PE, and then there is nothing here
/// to say: every detector in this module reads the section table, the import
/// table or the overlay, and a text file has none of the three.
pub fn evaluate(data: &[u8], pe: Option<&PeInput<'_>>, config: &HeuristicConfig) -> Vec<Detection> {
    let Some(image) = pe else {
        return Vec::new();
    };
    if !config.enabled {
        return Vec::new();
    }
    let file = image.pe();
    let mut out = Vec::new();

    section_entropy(image, config, &mut out);
    file_entropy(data, config, &mut out);
    writable_and_executable(image, &mut out);
    entry_point_outside_sections(image, &mut out);
    section_without_data(image, &mut out);
    packer_section_names(image, &mut out);
    overlay_entropy(data, image, config, &mut out);
    implausible_timestamp(file.timestamp(), &mut out);
    suspicious_imports(image.imports(), &mut out);

    out
}

// -- packing --------------------------------------------------------------

/// A section whose contents look compressed or encrypted.
///
/// One detection for the file, at the highest entropy found, naming the
/// section. Reporting each section separately would make a file with four
/// packed sections four times as suspicious as one with a single packed
/// section, which is not a distinction anyone can act on.
fn section_entropy(image: &PeInput<'_>, config: &HeuristicConfig, out: &mut Vec<Detection>) {
    let pe = image.pe();
    let mut worst: Option<(usize, f64)> = None;
    for index in 0..pe.number_of_sections() as usize {
        let Some(section) = pe.section(index) else {
            continue;
        };
        if (section.size_of_raw_data as usize) < config.min_section_bytes {
            continue;
        }
        let Some(bytes) = pe.section_data(index) else {
            continue;
        };
        // Trim to what the header claims. A section whose declared size runs
        // past the end of the buffer would otherwise have its entropy measured
        // over whatever follows it in the file.
        let bytes = &bytes[..bytes.len().min(section.size_of_raw_data as usize)];
        let h = stats::entropy(bytes);
        if h < config.section_entropy {
            continue;
        }
        if worst.is_none_or(|(_, best)| h > best) {
            worst = Some((index, h));
        }
    }
    let Some((index, h)) = worst else { return };
    let Some(section) = pe.section(index) else {
        return;
    };
    out.push(
        Detection::new(
            "heuristic/packed/section-entropy",
            format!(
                "The `{}` section is packed or encrypted: its entropy is {h:.2} bits per byte, \
                 against {:.1} for ordinary compiled code.",
                section.name(),
                config.section_entropy,
            ),
            Severity::Low,
            DetectionSource::Heuristic,
        )
        .with_location(section_location(pe, index, "packed section")),
    );
}

/// A whole executable image whose bytes are near-uniform.
///
/// Only for images. A `.zip` is high-entropy by construction and saying so
/// would be saying nothing.
fn file_entropy(data: &[u8], config: &HeuristicConfig, out: &mut Vec<Detection>) {
    if data.len() < config.min_section_bytes * 4 {
        return;
    }
    let h = stats::entropy(data);
    if h < config.file_entropy {
        return;
    }
    // Skipped when a section already reported the same thing at a higher
    // entropy: the file being uniformly random *because* every section is
    // uniformly random is one observation, not two.
    if out
        .iter()
        .any(|d| d.rule_id == "heuristic/packed/section-entropy")
    {
        return;
    }
    out.push(Detection::new(
        "heuristic/packed/file-entropy",
        format!(
            "The whole file is compressed or encrypted: its entropy is {h:.2} bits per byte. \
             Executable code is not distributed that way."
        ),
        Severity::Low,
        DetectionSource::Heuristic,
    ));
}

/// A section that is both writable and executable at run time.
///
/// No compiler emits one. A section has to be executable to hold code and
/// writable to hold data, and asking for both is what a program does when it
/// intends to *write code and then run it* — a packer's unpacking stub, a
/// shellcode loader, a just-in-time compiler, and, occasionally, a program with
/// a hand-written assembly routine that patches itself.
fn writable_and_executable(image: &PeInput<'_>, out: &mut Vec<Detection>) {
    let pe = image.pe();
    for index in 0..pe.number_of_sections() as usize {
        let Some(section) = pe.section(index) else {
            continue;
        };
        // A writable, executable section with no bytes in the file has nothing
        // to self-modify yet; that shape is reported by
        // `heuristic/packed/section-without-data` instead.
        if !section.is_writable() || !section.is_executable() || section.size_of_raw_data == 0 {
            continue;
        }
        out.push(
            Detection::new(
                "heuristic/packed/writable-executable",
                format!(
                    "The `{}` section is both writable and executable. Legitimate compilers do \
                     not emit that; unpacking stubs and code loaders do.",
                    section.name(),
                ),
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_location(section_location(pe, index, "writable+executable section")),
        );
        // One is enough to make the point, and a file with six of them has not
        // made it six times.
        return;
    }
}

/// An entry point that lies in no section.
///
/// The loader jumps to whatever `AddressOfEntryPoint` says, and a section table
/// is how everything else — debuggers, disassemblers, and most analysis tools —
/// finds the code. An entry point outside every section is a file that runs
/// code no one is looking at.
///
/// # The files that have no code to run, and the two guards that say so
///
/// That sentence is only true of a file that *has* code, and the guards below
/// are the difference between a heuristic and a false-positive generator. Three
/// separate populations carry an entry point that no section contains, and the
/// first two are ordinary rather than anomalous:
///
/// - **A resource-only image** — a `.mui` localisation library, a satellite
///   resource DLL — is a normal, correct PE with `AddressOfEntryPoint` of zero
///   and no section marked executable, because there is nothing in it to
///   execute: the loader maps it, reads its resources and never jumps anywhere.
///   Measured: of the 18 files directly inside `C:\Windows\System32\zh-TW`, 12
///   are `.mui` files of exactly that shape.
/// - **A DLL with a zero entry point** has no `DllMain` to call, which is legal
///   and documented. Measured over `System32`: 265 of the 273 files this
///   heuristic would otherwise report are in this group.
/// - **A managed assembly** has no native entry point at all — the runtime
///   finds the managed one through the COR header. All 8 of the zero-entry-point
///   `.exe` files measured carry a COM descriptor.
///
/// What is left is the anomaly the heuristic is for, and the guards are
/// deliberately narrow enough to keep it: an unmanaged EXE with a real `.text`
/// and an entry point of zero is pointing the loader at its own headers, and
/// neither "is a DLL" nor "has a CLR header" is true of it.
///
/// Note the shape of the second and third guards: they are about *why* the
/// entry point is zero, not about the value. A test on the value alone would
/// suppress the anomaly above along with the noise.
fn entry_point_outside_sections(image: &PeInput<'_>, out: &mut Vec<Detection>) {
    let pe = image.pe();
    if pe.number_of_sections() == 0 {
        return;
    }
    let entry = pe.entry_point();
    // An entry point of zero is how two ordinary kinds of image say "there is no
    // native entry point", and neither is an anomaly. Measured over every `.dll`
    // and `.exe` under an installed `System32`: 573 files carry one, and the
    // guard below turns 565 of them off — 265 of the 273 this heuristic would
    // otherwise report, which is very nearly the whole of the largest single
    // source of findings on an untouched machine.
    //
    // **A DLL with a zero entry point has no `DllMain`.** The loader calls a
    // DLL's entry point as `DllMain`, so zero means there is nothing to call,
    // which is legal, documented and what a keyboard-layout driver does — the
    // 265 are overwhelmingly `kbd*.dll`, `*res.dll` and message tables that
    // export a table and initialise nothing.
    //
    // **An image with a CLR header has no native entry point either.** A
    // managed assembly's entry point is found by the runtime through the COR
    // header, not by the loader, so `AddressOfEntryPoint` is not where anything
    // starts. All 8 of the `.exe` files with a zero entry point measured above
    // carry a COM descriptor at RVA `0x2000`, and every one of them is a
    // Microsoft or Intel .NET binary — `powershell_ise.exe` among them.
    //
    // Note that this is *not* "any image with an executable section and a zero
    // entry point is fine": an unmanaged EXE with a real `.text` and an entry
    // point of zero is pointing the loader at its own headers, which is exactly
    // the anomaly this looks for, and neither guard suppresses it.
    let no_entry_point =
        entry == 0 && (pe.is_dll() || pe.data_directory(directory::COM_DESCRIPTOR).is_present());
    if no_entry_point {
        return;
    }
    let has_code = (0..pe.number_of_sections() as usize)
        .any(|index| pe.section(index).is_some_and(|s| s.is_executable()));
    if !has_code {
        return;
    }
    // `entry_point` is a *file offset*, in the manner of the `pe` module this
    // engine implements. Comparing it against a section's raw range is
    // therefore the comparison, and comparing it against `virtual_address`
    // would be comparing two different coordinate systems.
    let inside = (0..pe.number_of_sections() as usize).any(|index| {
        pe.section(index).is_some_and(|s| {
            let start = u64::from(s.pointer_to_raw_data);
            entry >= start && entry < s.raw_end()
        })
    });
    if inside {
        return;
    }
    out.push(Detection::new(
        "heuristic/packed/entry-point-outside-sections",
        format!(
            "The entry point at file offset {entry:#x} lies outside every section, so the code \
             the loader runs is not the code the section table describes."
        ),
        Severity::Low,
        DetectionSource::Heuristic,
    ));
}

/// An executable section with a size in memory but no bytes in the file.
///
/// The content is produced at run time rather than being present on disk, which
/// is precisely what an unpacking stub does with the section it is about to
/// fill. An ordinary `.bss` is the same shape and is not executable.
fn section_without_data(image: &PeInput<'_>, out: &mut Vec<Detection>) {
    let pe = image.pe();
    for index in 0..pe.number_of_sections() as usize {
        let Some(section) = pe.section(index) else {
            continue;
        };
        if !section.is_executable() || section.size_of_raw_data != 0 || section.virtual_size == 0 {
            continue;
        }
        out.push(
            Detection::new(
                "heuristic/packed/section-without-data",
                format!(
                "The `{}` section claims {} bytes of executable code but has none in the file, \
                 so it is written at run time.",
                section.name(),
                section.virtual_size,
            ),
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_location(section_location(pe, index, "empty executable section")),
        );
        return;
    }
}

/// A section named after a packer or a protector.
///
/// The weakest and most useful signal in this module. Weak, because a section
/// name is two bytes of attacker-controlled string and a packer that renames
/// its sections is trivially built — every one of these is a name a *legitimate*
/// user of that packer will also have. Useful, because most packers do not
/// bother, and because a protector's name is the single most informative thing
/// a rule engine can learn from an otherwise opaque binary.
fn packer_section_names(image: &PeInput<'_>, out: &mut Vec<Detection>) {
    let pe = image.pe();
    let mut found: Vec<&'static PackerName> = Vec::new();
    for index in 0..pe.number_of_sections() as usize {
        let Some(section) = pe.section(index) else {
            continue;
        };
        let name = section.name_bytes();
        if let Some(known) = PACKER_NAMES
            .iter()
            .find(|known| name.eq_ignore_ascii_case(known.name))
        {
            if !found.iter().any(|f| f.product == known.product) {
                found.push(known);
            }
        }
    }
    let Some(worst) = found.iter().max_by_key(|known| known.severity).copied() else {
        return;
    };
    // One detection naming every product found, scored at the highest severity
    // among them. Two names in one file is one observation about one file.
    let products: Vec<&str> = found.iter().map(|known| known.product).collect();
    out.push(Detection::new(
        "heuristic/packed/section-name",
        format!(
            "The file carries sections named for {} ({}). Its code is packed or protected, so \
             what is on disk is not what will run.",
            products.join(", "),
            // A section name is eight bytes out of a file, so it is bytes and
            // not text: a name that is not UTF-8 is rendered lossily rather
            // than dropped, because a garbled name is still evidence that
            // something named the section.
            found
                .iter()
                .map(|known| String::from_utf8_lossy(known.name).into_owned())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        worst.severity,
        DetectionSource::Heuristic,
    ));
}

/// A packer or protector section name, and how much it is worth on its own.
#[derive(Debug, Clone, Copy)]
struct PackerName {
    /// The section name, as it appears in the section table.
    name: &'static [u8],
    /// The product it belongs to, as it should be shown to a user.
    product: &'static str,
    /// How strong a signal the name is.
    ///
    /// A generic packer is [`Severity::Low`]: UPX ships in every Linux
    /// distribution, and a program being small is not a crime. A commercial
    /// protector is [`Severity::Medium`], because these exist to make a binary
    /// unanalysable and that is a thing malware pays for.
    severity: Severity,
}

/// Known packer and protector section names.
///
/// Deliberately short. A long list of names costs nothing to match but makes
/// the detection harder to explain, and every entry that fires on ordinary
/// software is a false positive that the rest of the module has to pay for.
const PACKER_NAMES: &[PackerName] = &[
    // -- protectors: virtualisers and commercial obfuscators -----------------
    PackerName {
        name: b".vmp0",
        product: "VMProtect",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".vmp1",
        product: "VMProtect",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".vmp2",
        product: "VMProtect",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".themida",
        product: "Themida",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".winlice",
        product: "WinLicense",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".enigma1",
        product: "Enigma Protector",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".enigma2",
        product: "Enigma Protector",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".aspr",
        product: "ASProtect",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".obsidium",
        product: "Obsidium",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".y0da",
        product: "Yoda's Crypter",
        severity: Severity::Medium,
    },
    PackerName {
        name: b".taz",
        product: "PESpin",
        severity: Severity::Medium,
    },
    // -- packers: compressors with a self-extracting stub --------------------
    PackerName {
        name: b".upx0",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b".upx1",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b".upx2",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b"upx0",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b"upx1",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b"upx!",
        product: "UPX",
        severity: Severity::Low,
    },
    PackerName {
        name: b".aspack",
        product: "ASPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".adata",
        product: "ASPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".nsp0",
        product: "NsPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".nsp1",
        product: "NsPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".nsp2",
        product: "NsPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".mpress1",
        product: "MPRESS",
        severity: Severity::Low,
    },
    PackerName {
        name: b".mpress2",
        product: "MPRESS",
        severity: Severity::Low,
    },
    PackerName {
        name: b".pec",
        product: "PECompact",
        severity: Severity::Low,
    },
    PackerName {
        name: b".pecompact",
        product: "PECompact",
        severity: Severity::Low,
    },
    PackerName {
        name: b".petite",
        product: "Petite",
        severity: Severity::Low,
    },
    PackerName {
        name: b".fsg",
        product: "FSG",
        severity: Severity::Low,
    },
    PackerName {
        name: b".rlpack",
        product: "RLPack",
        severity: Severity::Low,
    },
    PackerName {
        name: b".molebox",
        product: "MoleBox",
        severity: Severity::Low,
    },
    PackerName {
        name: b".exestealth",
        product: "ExeStealth",
        severity: Severity::Low,
    },
    PackerName {
        name: b".packed",
        product: "an unnamed packer",
        severity: Severity::Low,
    },
    PackerName {
        name: b".boom",
        product: "The Boomerang",
        severity: Severity::Low,
    },
    PackerName {
        name: b".seau",
        product: "SeauSFX",
        severity: Severity::Low,
    },
    PackerName {
        name: b".shrink1",
        product: "Shrinker",
        severity: Severity::Low,
    },
    PackerName {
        name: b".shrink2",
        product: "Shrinker",
        severity: Severity::Low,
    },
    PackerName {
        name: b".shrink3",
        product: "Shrinker",
        severity: Severity::Low,
    },
];

/// Data appended after the last section that looks compressed or encrypted.
///
/// The classic dropper shape: a small executable whose real payload is a
/// compressed blob at the end of the file, expanded into memory and run. It is
/// also the shape of every self-extracting installer, which is why this is
/// [`Severity::Medium`] and not more — and why the *size* threshold matters.
/// A signature, by contrast, is also an overlay and is neither large nor
/// high-entropy, so a signed file does not report this.
fn overlay_entropy(
    data: &[u8],
    image: &PeInput<'_>,
    config: &HeuristicConfig,
    out: &mut Vec<Detection>,
) {
    let overlay = image.pe().overlay();
    if overlay.size < config.min_overlay_bytes {
        return;
    }
    let start = overlay.offset as usize;
    let end = start.saturating_add(overlay.size as usize).min(data.len());
    let Some(bytes) = data.get(start..end) else {
        return;
    };
    // Sampled rather than measured whole. An overlay can be a gigabyte, and
    // entropy over the first quarter-megabyte of a compressed stream is the
    // same number to two decimal places as over all of it.
    const SAMPLE: usize = 256 * 1024;
    let sample = &bytes[..bytes.len().min(SAMPLE)];
    let h = stats::entropy(sample);
    if h < config.file_entropy {
        return;
    }
    out.push(
        Detection::new(
            "heuristic/packed/overlay-entropy",
            format!(
                "{} bytes are appended after the last section and are compressed or encrypted \
                 ({h:.2} bits per byte). An executable carrying an opaque payload is how a \
                 dropper is built.",
                overlay.size,
            ),
            Severity::Medium,
            DetectionSource::Heuristic,
        )
        .with_location(MatchLocation::new(
            overlay.offset,
            u32::try_from(sample.len()).unwrap_or(u32::MAX),
            "overlay",
            sample,
        )),
    );
}

// -- imports --------------------------------------------------------------

/// What the import table says the program intends to do.
///
/// Each of these is a *combination* of symbols rather than a single one, and
/// that is the whole design. `WriteProcessMemory` on its own is imported by
/// every debugger, every profiler and every crash reporter on the system;
/// `WriteProcessMemory` together with `VirtualAllocEx` and `CreateRemoteThread`
/// is the three-call sequence for injecting code into another process, and
/// almost nothing else needs all three.
///
/// Even so, every one of these scores [`Severity::Low`] except the ransomware
/// shape. A security product that flags `IsDebuggerPresent` heavily is a
/// security product that flags itself.
fn suspicious_imports(imports: &Imports<'_>, out: &mut Vec<Detection>) {
    let has = |name: &str| imports.has_symbol(name);
    let any = |names: &[&str]| names.iter().any(|name| has(name));

    // -- process injection ---------------------------------------------------
    let writes = any(&[
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "ZwWriteVirtualMemory",
    ]);
    let allocates = any(&["VirtualAllocEx", "NtAllocateVirtualMemory"]);
    let executes = any(&[
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetThreadContext",
    ]);
    if writes && allocates && executes {
        out.push(heuristic(
            "heuristic/imports/process-injection",
            "The program imports the sequence for writing into another process: it allocates \
             memory there, writes to it, and starts a thread on it. That is how code is injected.",
            Severity::Low,
        ));
    }

    // -- anti-analysis -------------------------------------------------------
    // Only the undocumented route counts, and it takes two of them.
    //
    // `IsDebuggerPresent` and `OutputDebugStringA` used to be two of the four
    // signals here, and that was measured wrong against an installed
    // `System32`: of thirty DLLs, 22 import `IsDebuggerPresent` — it is what a
    // debug build and an assert macro compile to — and 6 import
    // `OutputDebugStringA`, which is a logging call. The old predicate fired on
    // ten of those thirty, marking a third of the operating system suspicious
    // with nothing but a code-signing certificate to argue with it. Timing
    // calls were the same mistake: `GetTickCount64` is imported by six of the
    // thirty.
    //
    // What is left is the set a program reaches for when it wants to know
    // whether a debugger is attached *and does not want the documented answer*:
    // the debug-port and debug-object queries, the call that hides a thread
    // from the debugger, and the kernel-debugger query. The documented call is
    // absent from the list entirely, so a program that uses only it is not
    // flagged at all — the intended trade, because that call is what ordinary
    // software compiles to and this heuristic has nothing else to go on.
    //
    // Two of them, not one: any single member can appear for an incidental
    // reason. AcLayers.dll, the application-compatibility shim, imports three
    // and is the one file of the thirty this still fires on — a compat shim
    // introspecting foreign processes is doing legitimately what a packer does
    // illegitimately, and a `Low` observation reported to the user is the right
    // answer to that, not silence.
    let stealth = [
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtQueryObject",
        "NtSetInformationThread",
        "NtQuerySystemInformation",
    ]
    .iter()
    .filter(|name| has(name))
    .count();
    if stealth >= 2 {
        out.push(heuristic(
            "heuristic/imports/anti-analysis",
            "The program imports several ways of asking the system whether it is being \
             debugged, and none of them the documented one. Ordinary software has no reason to \
             ask twice.",
            Severity::Low,
        ));
    }

    // -- input capture -------------------------------------------------------
    if any(&["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"])
        && any(&[
            "GetKeyNameTextA",
            "GetKeyNameTextW",
            "MapVirtualKeyA",
            "GetKeyboardState",
        ])
    {
        out.push(heuristic(
            "heuristic/imports/input-capture",
            "The program installs a keyboard hook and translates key codes into characters, \
             which is what recording what a user types requires.",
            Severity::Low,
        ));
    }

    // -- credential access ---------------------------------------------------
    if any(&[
        "CredEnumerateA",
        "CredEnumerateW",
        "CredReadA",
        "CredReadW",
        "LsaEnumerateLogonSessions",
        "SamQueryInformationUser",
        "VaultEnumerateVaults",
    ]) {
        out.push(heuristic(
            "heuristic/imports/credential-access",
            "The program imports the API for reading stored credentials and logon sessions.",
            Severity::Low,
        ));
    }

    // -- the ransomware shape ------------------------------------------------
    // Encryption, plus a walk of the filesystem, plus destruction. Backup and
    // archiving software does the first two and this scores it as suspicious,
    // which is the notification the user should get rather than an action taken
    // on their behalf.
    let encrypts = any(&[
        "CryptEncrypt",
        "BCryptEncrypt",
        "CryptGenKey",
        "NCryptEncrypt",
    ]);
    let walks = any(&["FindFirstFileExW", "FindFirstFileW", "NtQueryDirectoryFile"]);
    let destroys = any(&[
        "MoveFileExW",
        "DeleteFileW",
        "NtSetInformationFile",
        "SHFileOperationW",
    ]);
    if encrypts && walks && destroys {
        out.push(heuristic(
            "heuristic/imports/ransomware-shape",
            "The program encrypts data, walks the filesystem and moves or deletes files. That is \
             the shape of a ransomware payload, and also of a backup tool.",
            Severity::Medium,
        ));
    }

    // -- persistence ---------------------------------------------------------
    if any(&[
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
    ]) && any(&["CreateServiceA", "CreateServiceW", "ChangeServiceConfigA"])
    {
        out.push(heuristic(
            "heuristic/imports/persistence",
            "The program writes the registry and creates a service, which is how it arranges to \
             be started again after a reboot.",
            Severity::Low,
        ));
    }
}

/// A detection from this module, with the source already filled in.
fn heuristic(id: &str, description: impl Into<String>, severity: Severity) -> Detection {
    Detection::new(id, description, severity, DetectionSource::Heuristic)
}

// -- structure ------------------------------------------------------------

/// A compile timestamp that cannot be true.
///
/// [`Severity::Info`], which scores nothing: this is recorded so that a report
/// can explain a file, never so that it can convict one. Reproducible builds
/// zero the field on purpose and are the reason that has to be said out loud.
fn implausible_timestamp(timestamp: u32, out: &mut Vec<Detection>) {
    if timestamp != 0 {
        return;
    }
    out.push(heuristic(
        "heuristic/structure/zero-timestamp",
        "The PE header's build timestamp is zero, which is what a reproducible build produces \
         and also what packing tools that rebuild the header produce.",
        Severity::Info,
    ));
}

/// A location pointing at the start of a section.
///
/// The preview is written rather than taken from the section's first bytes.
/// Those bytes are usually a jump table or a run of padding, so a rendering of
/// them tells a reader nothing, while the section's name and size tell them
/// which part of the file the detection is about. The bytes are still carried
/// in `length`, so a caller that wants to look at them can.
fn section_location(pe: &av_pe::PeFile<'_>, index: usize, label: &str) -> MatchLocation {
    let Some(section) = pe.section(index) else {
        return MatchLocation::new(0, 0, label, &[]);
    };
    let name = section.name();
    let identifier = match name.is_empty() {
        true => label.to_owned(),
        false => format!("{label}: {name}"),
    };
    let mut location = MatchLocation::new(
        u64::from(section.pointer_to_raw_data),
        section.size_of_raw_data,
        identifier,
        &[],
    );
    location.preview = format!(
        "{} at file offset {:#x}, {} bytes",
        match name.is_empty() {
            true => "<unnamed section>".to_owned(),
            false => format!("`{name}`"),
        },
        section.pointer_to_raw_data,
        section.size_of_raw_data,
    );
    location
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::VerdictThresholds;
    use av_pe::testing::{minimal_pe32, minimal_pe64};

    fn config() -> HeuristicConfig {
        HeuristicConfig::default()
    }

    fn parse(data: &[u8]) -> PeInput<'_> {
        PeInput::parse(data).expect("the fixture is a PE")
    }

    fn ids(detections: &[Detection]) -> Vec<&str> {
        detections.iter().map(|d| d.rule_id.as_str()).collect()
    }

    #[test]
    fn no_single_detector_reaches_the_malicious_band() {
        // The property this module is built around, checked against the
        // detectors rather than against a list of severities someone has to
        // remember to update: every fixture below trips one or two detectors,
        // and not one of the detections any of them produce may score high
        // enough to convict a file on its own.
        let thresholds = VerdictThresholds::default();
        let fixtures = [
            pe_with_text(b".text", &pseudo_random(8192), EXECUTE_READ),
            pe_with_text(b".vmp0", &vec![0u8; 4096], EXECUTE_READ),
            pe_with_text(b"UPX0", &vec![0u8; 4096], EXECUTE_READ),
            pe_with_text(b".text", &vec![0x90u8; 4096], EXECUTE_READ_WRITE),
            section_without_data(),
        ];
        let mut seen = 0usize;
        for data in &fixtures {
            let found = evaluate(data, Some(&parse(data)), &config());
            seen += found.len();
            for detection in &found {
                assert!(
                    detection.score < thresholds.malicious,
                    "{} scores {}, which reaches {} on its own",
                    detection.rule_id,
                    detection.score,
                    thresholds.classify(detection.score),
                );
            }
        }
        assert!(
            seen > 0,
            "the fixtures trip nothing, so this proves nothing"
        );
    }

    #[test]
    fn a_plain_fixture_reports_nothing_alarming() {
        // The canary. A heuristic set that fires on a minimal, ordinary PE is a
        // heuristic set that will fire on the machine.
        let data = minimal_pe32();
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            found.iter().all(|d| d.score == 0),
            "something scored on a minimal PE: {:?}",
            ids(&found)
        );
    }

    #[test]
    fn a_non_pe_is_not_measured() {
        let data = b"hello, world";
        assert!(evaluate(data, None, &config()).is_empty());
    }

    #[test]
    fn disabling_the_module_disables_all_of_it() {
        let data = pe_with_text(b".vmp0", &pseudo_random(8192), EXECUTE_READ_WRITE);
        let off = HeuristicConfig::disabled();
        assert!(evaluate(&data, Some(&parse(&data)), &off).is_empty());
    }

    #[test]
    fn a_high_entropy_section_is_reported_once_however_many_there_are() {
        // Two packed sections are one observation about one file. Reporting
        // each would make any sufficiently large executable a detection.
        let mut data = pe_with_text(b".text", &pseudo_random(8192), EXECUTE_READ);
        set_section(&mut data, 1, b".data", &pseudo_random(8192), EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let packed: Vec<_> = found
            .iter()
            .filter(|d| d.rule_id == "heuristic/packed/section-entropy")
            .collect();
        assert_eq!(packed.len(), 1, "{:?}", ids(&found));
    }

    #[test]
    fn a_short_section_is_not_measured_for_entropy() {
        // Entropy over a few hundred bytes is noise: a short run of distinct
        // bytes reaches the maximum for its length whatever its content.
        let data = pe_with_text(b".text", &pseudo_random(512), EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/section-entropy"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn a_low_entropy_section_is_not_called_packed() {
        let data = pe_with_text(b".text", &vec![0x90u8; 8192], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/section-entropy"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn a_writable_executable_section_is_reported() {
        let data = pe_with_text(b".text", &vec![0x90u8; 4096], EXECUTE_READ_WRITE);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/writable-executable"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn a_read_only_executable_section_is_not_reported() {
        let data = pe_with_text(b".text", &vec![0x90u8; 4096], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/writable-executable"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn an_executable_section_with_no_data_is_reported() {
        // The shape an unpacking stub leaves behind: the section it is about to
        // fill exists in memory and not on disk.
        let data = section_without_data();
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/section-without-data"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn an_executable_section_with_no_data_but_no_size_is_not_reported() {
        // The control for the test above. A section that is empty in both
        // directions is a section with nothing to say, and treating it as an
        // unpacking stub would report every stripped binary in existence.
        let mut data = section_without_data();
        let entry = section_entry(&data, 0);
        data[entry + 8..entry + 12].copy_from_slice(&0u32.to_le_bytes());
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/section-without-data"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn a_file_with_no_code_to_run_is_not_an_anomaly() {
        // The false positive this guard was written for. Every one of these
        // files has an entry point of zero, and zero lies in no section, so the
        // rule fired on all of them: 12 of the 18 files in `System32\zh-TW`,
        // which are `.mui` localisation libraries. A library with no code has
        // nowhere for its entry point to be.
        let data = resource_only();
        // Asserted rather than assumed, because "nothing was reported" is also
        // what a fixture that could never have been reported would say. Both
        // halves of the guard are checked here, so if either stops holding the
        // assertion below goes back to being about something real.
        let parsed = parse(&data);
        let pe = parsed.pe();
        assert!(
            (0..pe.number_of_sections() as usize)
                .all(|i| pe.section(i).is_some_and(|s| !s.is_executable())),
            "the fixture must have no executable section"
        );
        let entry = pe.entry_point();
        assert!(
            !(0..pe.number_of_sections() as usize).any(|i| {
                pe.section(i).is_some_and(|s| {
                    entry >= u64::from(s.pointer_to_raw_data) && entry < s.raw_end()
                })
            }),
            "the fixture's entry point must be outside every section"
        );

        let found = evaluate(&data, Some(&parsed), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/entry-point-outside-sections"),
            "{:?}",
            ids(&found)
        );
    }

    /// Whether the rule fired, for the three tests below.
    fn entry_point_reported(data: &[u8]) -> bool {
        evaluate(data, Some(&parse(data)), &config())
            .iter()
            .any(|d| d.rule_id == "heuristic/packed/entry-point-outside-sections")
    }

    #[test]
    fn a_dll_with_no_entry_point_is_not_an_anomaly() {
        // The single largest source of findings on an untouched machine, and a
        // correct file shape rather than a defect: a DLL's entry point *is* its
        // `DllMain`, so zero means there is nothing to call. Measured over an
        // installed `System32`: 265 of the 273 files this rule reported.
        let data = dll_with_no_entry_point();
        let parsed = parse(&data);
        let pe = parsed.pe();
        assert!(pe.is_dll(), "the fixture must be a DLL");
        assert_eq!(pe.entry_point(), 0);
        assert!(
            (0..pe.number_of_sections() as usize)
                .any(|i| pe.section(i).is_some_and(|s| s.is_executable())),
            "the fixture must have an executable section, or the guard under test \
             would be the one for resource-only images instead"
        );
        assert!(
            !entry_point_reported(&data),
            "{:?}",
            ids(&evaluate(&data, Some(&parsed), &config()))
        );
    }

    #[test]
    fn a_managed_executable_with_no_entry_point_is_not_an_anomaly() {
        // A CLR header means the runtime finds the managed entry point through
        // the COR header, so the loader's `AddressOfEntryPoint` is not where
        // anything starts. Measured: all 8 of the zero-entry-point `.exe` files
        // in an installed `System32` — `powershell_ise.exe` among them — carry a
        // COM descriptor.
        //
        // Note this is an *executable*, so the DLL guard cannot be what
        // suppresses it; the two guards are independent and this test fails if
        // either is removed.
        let data = dotnet_executable_with_no_entry_point();
        let parsed = parse(&data);
        let pe = parsed.pe();
        assert!(!pe.is_dll(), "the fixture must not be a DLL");
        assert_eq!(pe.entry_point(), 0);
        assert!(
            pe.data_directory(av_pe::headers::directory::COM_DESCRIPTOR)
                .is_present(),
            "the fixture must carry a CLR header"
        );
        assert!(
            !entry_point_reported(&data),
            "{:?}",
            ids(&evaluate(&data, Some(&parsed), &config()))
        );
    }

    #[test]
    fn an_unmanaged_executable_with_no_entry_point_is_still_reported() {
        // The bound, and the reason the two guards above are not "a zero entry
        // point is fine". An ordinary executable whose loader entry point is
        // zero is aimed at its own headers — the DOS stub and the PE signature,
        // not code — and neither guard is true of it.
        let mut data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        set_entry_point(&mut data, 0);
        let parsed = parse(&data);
        assert!(!parsed.pe().is_dll());
        assert!(!parsed
            .pe()
            .data_directory(av_pe::headers::directory::COM_DESCRIPTOR)
            .is_present());
        assert!(
            entry_point_reported(&data),
            "{:?}",
            ids(&evaluate(&data, Some(&parsed), &config()))
        );
    }

    #[test]
    fn an_entry_point_outside_every_section_is_reported_when_there_is_code() {
        // The control for the test above, and the case the rule exists for: the
        // guard must not be "a zero entry point is fine" but "a file with no
        // executable section is fine", or an image with a real `.text` whose
        // entry point points at its own headers — the loader being aimed at
        // something that is not code — would be suppressed too.
        let mut data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        // Below the first section's virtual address, so the RVA maps to no
        // section and the file offset lands in the headers.
        set_entry_point(&mut data, 0x100);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let detection = found
            .iter()
            .find(|d| d.rule_id == "heuristic/packed/entry-point-outside-sections")
            .expect("a code section with an entry point outside it");
        assert_eq!(detection.severity, Severity::Low);
        assert!(
            detection.description.contains("0x100"),
            "{}",
            detection.description
        );
    }

    #[test]
    fn a_packer_section_name_is_recognised_whatever_its_case() {
        let data = pe_with_text(b"UPX0", &vec![0u8; 4096], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let detection = found
            .iter()
            .find(|d| d.rule_id == "heuristic/packed/section-name")
            .expect("UPX0 is a known name");
        assert!(
            detection.description.contains("UPX"),
            "{}",
            detection.description
        );
        // A generic packer is Low, so it cannot convict on its own.
        assert_eq!(detection.severity, Severity::Low);
    }

    #[test]
    fn a_protector_section_name_outscores_a_packer_one() {
        let data = pe_with_text(b".vmp0", &vec![0u8; 4096], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let detection = found
            .iter()
            .find(|d| d.rule_id == "heuristic/packed/section-name")
            .expect("a known protector name");
        assert_eq!(detection.severity, Severity::Medium);
        assert!(
            detection.description.contains("VMProtect"),
            "{}",
            detection.description
        );
    }

    #[test]
    fn an_ordinary_section_name_is_not_a_packer() {
        let data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/packed/section-name"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn two_named_sections_are_one_detection_naming_both() {
        // A file is one file. Two packer names in it is a more specific
        // statement about that file, not two statements.
        let mut data = pe_with_text(b"UPX0", &vec![0u8; 4096], EXECUTE_READ);
        set_section(&mut data, 1, b".vmp0", &vec![0u8; 4096], EXECUTE_READ);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let named: Vec<_> = found
            .iter()
            .filter(|d| d.rule_id == "heuristic/packed/section-name")
            .collect();
        assert_eq!(named.len(), 1, "{:?}", ids(&found));
        // Scored at the strongest name found, and both are named in the text.
        assert_eq!(named[0].severity, Severity::Medium);
        assert!(
            named[0].description.contains("UPX"),
            "{}",
            named[0].description
        );
        assert!(
            named[0].description.contains("VMProtect"),
            "{}",
            named[0].description
        );
    }

    #[test]
    fn a_zero_timestamp_is_recorded_but_scores_nothing() {
        let mut data = minimal_pe64();
        // The fixture's timestamp is whatever the PE32 one carried, so the
        // field is zeroed here and the assertion is about that and nothing else.
        let pe_at = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let coff = pe_at + 4;
        data[coff + 4..coff + 8].copy_from_slice(&0u32.to_le_bytes());
        let found = evaluate(&data, Some(&parse(&data)), &config());
        let detection = found
            .iter()
            .find(|d| d.rule_id == "heuristic/structure/zero-timestamp")
            .expect("a zero timestamp is recorded");
        assert_eq!(detection.score, 0);
    }

    #[test]
    fn a_present_timestamp_is_not_remarked_on() {
        let data = minimal_pe32();
        assert_ne!(parse(&data).pe().timestamp(), 0);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id == "heuristic/structure/zero-timestamp"),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn an_absent_import_table_reports_nothing() {
        // A file with no imports is not a file with something to hide; the
        // module must not read "no symbols" as "no suspicious symbols".
        let data = minimal_pe32();
        let pe = parse(&data);
        assert!(pe.imports().entries().is_empty());
        let found = evaluate(&data, Some(&pe), &config());
        assert!(
            !found
                .iter()
                .any(|d| d.rule_id.starts_with("heuristic/imports/")),
            "{:?}",
            ids(&found)
        );
    }

    #[test]
    fn every_detector_that_fires_can_be_explained_to_a_user() {
        // A detection with an empty description is a dialog box with a blank
        // line in it. Cheap to check, and impossible to notice otherwise.
        let fixtures = [
            pe_with_text(b".vmp0", &pseudo_random(8192), EXECUTE_READ_WRITE),
            pe_with_text(b".text", &[], EXECUTE_READ),
        ];
        for data in &fixtures {
            for detection in evaluate(data, Some(&parse(data)), &config()) {
                assert!(
                    detection.description.len() > 20,
                    "{} has nothing to say",
                    detection.rule_id
                );
            }
        }
    }

    // -- fixtures ------------------------------------------------------------

    /// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`.
    const EXECUTE_READ: u32 = 0x6000_0020;
    /// The same with `IMAGE_SCN_MEM_WRITE`, which no compiler emits.
    const EXECUTE_READ_WRITE: u32 = 0xE000_0020;
    /// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`, which is what a
    /// section holding nothing but resources carries.
    const READ_ONLY: u32 = 0x4000_0040;

    /// Bytes with no structure, so that their entropy is close to 8.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// The file offset of a section table entry.
    ///
    /// Derived from the image rather than written as a constant, because the
    /// fixture's header layout is `av-pe`'s business: a constant here would be
    /// a second copy of it that no test would notice going stale.
    fn section_entry(data: &[u8], index: usize) -> usize {
        let pe_at = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let coff = pe_at + 4;
        let optional_len =
            u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;
        coff + 20 + optional_len + index * 40
    }

    /// `minimal_pe32()` with its first section given a name, contents and flags.
    ///
    /// The fixture's first section sits at file offset 0x200 with a raw size of
    /// 0x400; this overwrites both, growing the buffer when the body is larger.
    fn pe_with_text(name: &[u8], body: &[u8], characteristics: u32) -> Vec<u8> {
        let mut data = minimal_pe32();
        set_section(&mut data, 0, name, body, characteristics);
        data
    }

    /// The file offset of the optional header's `AddressOfEntryPoint` field.
    ///
    /// Derived the same way [`section_entry`] is, and for the same reason.
    fn entry_point_field(data: &[u8]) -> usize {
        let pe_at = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        // The COFF header is 20 bytes and `AddressOfEntryPoint` sits 16 bytes
        // into the optional header that follows it.
        pe_at + 4 + 20 + 16
    }

    /// Point the loader at a different RVA.
    fn set_entry_point(data: &mut [u8], rva: u32) {
        let at = entry_point_field(data);
        data[at..at + 4].copy_from_slice(&rva.to_le_bytes());
    }

    /// An image with nothing to execute: neither section is executable and the
    /// entry point is zero.
    ///
    /// Both halves are load-bearing and neither is sufficient alone — that is
    /// the whole point of the pair of tests below. This is the shape of a
    /// resource-only library, which on Windows means the `.mui` files under
    /// `System32` that localise the built-in dialogs.
    fn resource_only() -> Vec<u8> {
        // Section 0 is `.text` and executable in the fixture, so it has to be
        // replaced rather than merely left alone; section 1 is `.data` and
        // already carries `READ_ONLY`-equivalent flags.
        let mut data = pe_with_text(b".rsrc", &vec![0u8; 0x400], READ_ONLY);
        set_entry_point(&mut data, 0);
        data
    }

    /// The file offset of the COFF header's `Characteristics` field.
    fn characteristics_field(data: &[u8]) -> usize {
        let pe_at = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        // `Characteristics` is the last of the COFF header's five fields:
        // Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
        // NumberOfSymbols, SizeOfOptionalHeader, Characteristics.
        pe_at + 4 + 18
    }

    /// Make the image a DLL rather than an executable.
    fn set_dll(data: &mut [u8]) {
        let at = characteristics_field(data);
        let mut flags = u16::from_le_bytes(data[at..at + 2].try_into().unwrap());
        flags |= av_pe::headers::IMAGE_FILE_DLL;
        data[at..at + 2].copy_from_slice(&flags.to_le_bytes());
    }

    /// An image with a real executable section whose loader entry point is zero
    /// because it is a **DLL**, which has no `DllMain` to call.
    ///
    /// The shape of 265 files in one `System32`: `kbd101.dll` and its neighbours
    /// export a table and initialise nothing.
    fn dll_with_no_entry_point() -> Vec<u8> {
        let mut data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        set_dll(&mut data);
        set_entry_point(&mut data, 0);
        data
    }

    /// The same shape in an **executable**, which is only ordinary when the
    /// image is managed: a CLR header means the runtime, not the loader, decides
    /// where execution starts.
    fn dotnet_executable_with_no_entry_point() -> Vec<u8> {
        let mut data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        set_entry_point(&mut data, 0);
        av_pe::testing::add_dotnet(
            &mut data,
            &av_pe::testing::DotNetSpec::new("v4.0.30319").assembly("Managed", [1, 2, 3, 4]),
        );
        data
    }

    /// An image whose first section claims memory and holds no bytes.
    fn section_without_data() -> Vec<u8> {
        let mut data = pe_with_text(b".text", &vec![0u8; 4096], EXECUTE_READ);
        let entry = section_entry(&data, 0);
        data[entry + 8..entry + 12].copy_from_slice(&0x4000u32.to_le_bytes());
        data[entry + 16..entry + 20].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    /// Overwrite one section's name, contents and characteristics.
    ///
    /// Sections are laid out in index order, each starting where the previous
    /// one ended and rounded up to the file alignment, so that a body larger
    /// than the fixture's original 0x400 bytes does not overlap the section
    /// after it. Laying out in order is what makes the earlier sections'
    /// recorded sizes the right input to the next one's offset.
    fn set_section(data: &mut Vec<u8>, index: usize, name: &[u8], body: &[u8], flags: u32) {
        let mut at = 0x200usize;
        for earlier in 0..index {
            let entry = section_entry(data, earlier);
            let raw = u32::from_le_bytes(data[entry + 16..entry + 20].try_into().unwrap());
            at = (at + raw as usize).next_multiple_of(0x200);
        }
        let size = u32::try_from(body.len()).unwrap_or(u32::MAX);
        if data.len() < at + body.len() {
            data.resize(at + body.len(), 0);
        }
        data[at..at + body.len()].copy_from_slice(body);

        let entry = section_entry(data, index);
        let mut raw_name = [0u8; 8];
        let take = name.len().min(8);
        raw_name[..take].copy_from_slice(&name[..take]);
        data[entry..entry + 8].copy_from_slice(&raw_name);
        data[entry + 8..entry + 12].copy_from_slice(&size.to_le_bytes());
        data[entry + 12..entry + 16]
            .copy_from_slice(&(0x1000u32 * (index as u32 + 1)).to_le_bytes());
        data[entry + 16..entry + 20].copy_from_slice(&size.to_le_bytes());
        data[entry + 20..entry + 24].copy_from_slice(&(at as u32).to_le_bytes());
        data[entry + 36..entry + 40].copy_from_slice(&flags.to_le_bytes());
    }

    #[test]
    fn the_section_fixture_builder_produces_what_it_claims() {
        // Every test above depends on this builder, so it is tested itself: a
        // builder that wrote the wrong offsets would make them all vacuous.
        let data = pe_with_text(b".text", &vec![0xAAu8; 4096], EXECUTE_READ);
        let pe = parse(&data);
        assert_eq!(pe.pe().number_of_sections(), 2);
        let section = pe.pe().section(0).expect("a first section");
        assert_eq!(section.name(), ".text");
        assert_eq!(section.size_of_raw_data, 4096);
        assert_eq!(section.pointer_to_raw_data, 0x200);
        assert!(section.is_executable());
        assert!(!section.is_writable());
        assert_eq!(stats::entropy(pe.pe().section_data(0).expect("data")), 0.0);

        let data = pe_with_text(b".vmp0", &pseudo_random(8192), EXECUTE_READ_WRITE);
        let pe = parse(&data);
        let section = pe.pe().section(0).expect("a first section");
        assert_eq!(section.name(), ".vmp0");
        assert_eq!(section.size_of_raw_data, 8192);
        assert!(section.is_writable());
        assert!(stats::entropy(pe.pe().section_data(0).expect("data")) > 7.9);
    }

    // -- the anti-analysis imports, against what a real system binary imports --
    //
    // These three tests exist because the predicate they cover was wrong in a
    // way nothing caught: it fired on ten of thirty DLLs in an installed
    // `System32`. The symbol lists below are the measured ones — see the
    // comment on the predicate itself for the counts.

    /// A PE importing exactly the symbols an ordinary Windows DLL imports:
    /// `IsDebuggerPresent` (22 of the measured 30), `OutputDebugStringA` (6),
    /// and `GetTickCount64` (6). The old predicate scored this as evasive.
    fn pe_importing(symbols: &[&str]) -> Vec<u8> {
        let mut data = minimal_pe32();
        av_pe::testing::add_imports(&mut data, &[("KERNEL32.dll", symbols)]);
        data
    }

    fn anti_analysis_fires(symbols: &[&str]) -> bool {
        let data = pe_importing(symbols);
        let found = evaluate(&data, Some(&parse(&data)), &config());
        ids(&found).contains(&"heuristic/imports/anti-analysis")
    }

    #[test]
    fn the_debugger_checks_ordinary_software_imports_are_not_a_signal() {
        // The regression, stated as a fixture. A product that flags this is a
        // product that flags a third of the operating system.
        assert!(!anti_analysis_fires(&[
            "IsDebuggerPresent",
            "OutputDebugStringA",
            "GetTickCount64",
        ]));
        // And each of them on its own, since a single one is even more common.
        assert!(!anti_analysis_fires(&["IsDebuggerPresent"]));
        assert!(!anti_analysis_fires(&["OutputDebugStringA"]));
    }

    #[test]
    fn two_undocumented_debug_queries_are_a_signal() {
        assert!(anti_analysis_fires(&[
            "NtQueryInformationProcess",
            "NtQueryObject",
        ]));
        // Pairs across the family, since the point is two independent routes
        // rather than any particular one.
        assert!(anti_analysis_fires(&[
            "NtSetInformationThread",
            "NtQuerySystemInformation",
        ]));
    }

    #[test]
    fn one_undocumented_debug_query_is_not_a_signal() {
        // Any single member can appear for an incidental reason, and the
        // documented call being absent does not make one import a check.
        for symbol in [
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtQueryObject",
            "NtSetInformationThread",
            "NtQuerySystemInformation",
        ] {
            assert!(
                !anti_analysis_fires(&[symbol]),
                "{symbol} alone was treated as a signal"
            );
        }
    }
}
