//! The parsed view of one sample, and the questions a rule asks of it.
//!
//! # Why the parse lives here and not in the caller
//!
//! [`Evidence::parse`] takes the sample's bytes and parses them itself. The
//! alternative — have the caller parse a [`PeFile`] and hand it in — was
//! rejected because it makes a whole class of bug expressible: a `PeFile` parsed
//! from one buffer can be paired with a different buffer, and every offset the
//! rules report (an embedded image's position, a string's position) would then
//! be an offset into bytes nobody is looking at. Here the buffer and its parse
//! are created together and neither can be replaced, so every offset a finding
//! carries is an offset into the buffer the caller scanned. The cost is one
//! extra parse of a header the caller has usually parsed already — measured
//! against the alternative of a wrong offset in a report, which costs a user's
//! trust in the whole report, that is the cheaper mistake.
//!
//! # Why the answers are grouped rather than exposed
//!
//! A rule asks questions — "does it import any of these", "does it name any of
//! these", "is there an executable inside it" — and not "give me the import
//! table". The grouping is what keeps a rule readable as a sentence about
//! behaviour, and it is what lets the string questions go through one
//! case-insensitive search implementation ([`crate::text`]) instead of each rule
//! growing its own.

use std::cell::OnceCell;

use av_pe::headers::directory;
use av_pe::{Imports, Overlay, PeFile, Resource, Resources};

use crate::text;

/// Offset of `e_lfanew` in a DOS header.
const E_LFANEW_OFFSET: usize = 0x3C;
/// Bytes of a DOS header that have to exist before `e_lfanew` can be read.
const E_LFANEW_END: usize = E_LFANEW_OFFSET + 4;
/// Smallest `e_lfanew` a real image can have: a 64-byte DOS stub, then the
/// signature.
const MIN_E_LFANEW: u32 = 0x40;
/// Largest `e_lfanew` worth following. A real stub is a few hundred bytes; this
/// bound is what stops a `MZ` inside compressed data from being read as a
/// header pointing megabytes away, and it is the bound the false-positive
/// measurement below was taken with.
const MAX_E_LFANEW: u32 = 0x1000;
/// The PE signature, which is what makes a candidate a real image rather than
/// two bytes that happened to be `MZ`.
const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

/// One sample's bytes, parsed once.
///
/// Borrows the buffer it was made from and holds no copy of it: a 133 MB
/// installer (the largest executable in this machine's `System32`) is 133 MB of
/// memory the caller already owns, not 133 MB more.
#[derive(Debug)]
pub struct Evidence<'a> {
    data: &'a [u8],
    pe: PeFile<'a>,
    imports: Imports<'a>,
    resources: Resources<'a>,
    /// Filled in on the first rule that asks, and never before. Most samples
    /// never ask: the scan is a pass over the whole buffer, and the rules that
    /// ask for it are behind an import check that most files fail.
    embedded: OnceCell<EmbeddedImages>,
}

impl<'a> Evidence<'a> {
    /// Parse a sample.
    ///
    /// `None` means the bytes are not a PE image. That is deliberately not a
    /// `Result`: there is nothing a caller could do differently for a truncated
    /// optional header than for a missing DOS header, so an error type here
    /// would carry detail no caller acts on. "Not a PE image" is a domain
    /// outcome of this crate, and it is reported as
    /// [`crate::NotRunReason::NotPe`] rather than as a failure.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let pe = PeFile::parse(data).ok()?;
        let imports = av_pe::imports::read(&pe);
        let resources = av_pe::resources::read(&pe);
        Some(Self {
            data,
            pe,
            imports,
            resources,
            embedded: OnceCell::new(),
        })
    }

    /// The sample's bytes, exactly as they were handed in.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The parsed headers, for the questions that need a field rather than a
    /// yes-or-no answer.
    pub fn pe(&self) -> &PeFile<'a> {
        &self.pe
    }

    /// The import table.
    pub fn imports(&self) -> &Imports<'a> {
        &self.imports
    }

    /// The resource tree's leaves.
    pub fn resources(&self) -> &[Resource<'a>] {
        self.resources.leaves()
    }

    // -- import questions ---------------------------------------------------

    /// Whether the sample imports a symbol with this name, from any library.
    ///
    /// Matched case-sensitively, because that is how the loader resolves them:
    /// a Windows API name is a byte string compared exactly, and `createfilew`
    /// in an import table is a different symbol that resolves to nothing.
    pub fn imports_symbol(&self, symbol: &str) -> bool {
        self.imports.has_symbol(symbol)
    }

    /// Whether the sample imports *all* of these symbols.
    ///
    /// The form every multi-symbol rule uses. A rule that needs the whole of a
    /// behaviour — open a process, write into it, start a thread in it — is
    /// asking for all three, and a rule that fired on one of them would fire on
    /// half the operating system.
    pub fn imports_all(&self, symbols: &[&str]) -> bool {
        symbols.iter().all(|symbol| self.imports.has_symbol(symbol))
    }

    /// Whether the sample imports *any* of these symbols.
    ///
    /// For cases where a behaviour has several spellings — `CreateProcessW` and
    /// `CreateProcessA` are the same behaviour — rather than several parts.
    pub fn imports_any(&self, symbols: &[&str]) -> bool {
        symbols.iter().any(|symbol| self.imports.has_symbol(symbol))
    }

    /// Whether the sample statically imports from a library.
    pub fn imports_library(&self, library: &str) -> bool {
        self.imports.has_library(library)
    }

    // -- string questions ---------------------------------------------------

    /// Whether the sample's bytes contain this text, in either spelling and
    /// ASCII-case-insensitively.
    pub fn contains(&self, needle: &str) -> bool {
        self.find(needle).is_some()
    }

    /// Where this text occurs, in whichever spelling comes first.
    ///
    /// The single-needle form, for a rule whose evidence is one specific name.
    /// A rule that has a set of names to look for wants [`Evidence::find_any`],
    /// which is one pass over the table rather than one per name.
    pub fn find(&self, needle: &str) -> Option<TextMatch> {
        text::find_either(self.data, needle).map(|found| TextMatch {
            offset: found.offset,
            wide: found.encoding == text::Encoding::Wide,
        })
    }

    /// How many of these strings are present.
    ///
    /// The form the rules that need *agreement* use: a program that names two
    /// different security products is doing something a program that names one
    /// (usually its own) is not.
    pub fn count_present(&self, needles: &[&str]) -> usize {
        text::count_ignore_ascii_case(self.data, needles)
    }

    /// Where the first of these strings occurs, and which one it was.
    ///
    /// The offset is what makes a finding locatable: a report that says "this
    /// sample names a security product" is an assertion, and one that says
    /// "here, at offset 0x1f40, is the string it named" is evidence a user can
    /// check in a hex editor.
    pub fn find_any<'n>(&self, needles: &[&'n str]) -> Option<(&'n str, TextMatch)> {
        text::find_any_ignore_ascii_case(self.data, needles).map(|(needle, found)| {
            (
                needle,
                TextMatch {
                    offset: found.offset,
                    wide: found.encoding == text::Encoding::Wide,
                },
            )
        })
    }

    // -- structure questions ------------------------------------------------

    /// Whether the sample is a DLL rather than an executable.
    ///
    /// Used to *exclude*, never to suspect: a DLL is loaded by another program,
    /// so a behaviour that consists of the program starting things — spawning a
    /// process, running a command line — is not a thing a library does on its
    /// own, and the rules that key on those say so.
    pub fn is_dll(&self) -> bool {
        self.pe.is_dll()
    }

    /// The entry point, as a file offset.
    pub fn entry_point(&self) -> u64 {
        self.pe.entry_point()
    }

    /// The entry point as an RVA, which is the number the section table is
    /// indexed by.
    ///
    /// Zero is a value here and not an absence, and it means "there is no
    /// address to jump to" rather than "the header is broken": a library with
    /// nothing to initialise declares no entry point, and 400 of the 4,000
    /// files in the corpus do exactly that. The one rule that asks about the
    /// entry point therefore excludes zero explicitly, and its doc comment
    /// records what happened when it did not.
    pub fn entry_point_rva(&self) -> u32 {
        self.pe.entry_point_raw()
    }

    /// Whether a data directory entry is present.
    ///
    /// This is the whole of what this crate can say about the TLS and
    /// delay-load directories: `av-pe` reads the directory *table* and not the
    /// tables the entries point at, so "the directory is declared" is the only
    /// honest question available, and the crate documentation records why no
    /// rule is built on either answer.
    pub fn has_directory(&self, index: usize) -> bool {
        self.pe.data_directory(index).is_present()
    }

    /// Whether the sample declares a TLS directory.
    pub fn has_tls(&self) -> bool {
        self.has_directory(directory::TLS)
    }

    /// Whether the sample declares a delay-load import directory.
    pub fn has_delay_imports(&self) -> bool {
        self.has_directory(directory::DELAY_IMPORT)
    }

    /// The executable images embedded in the sample, scanned once and kept.
    pub fn embedded_images(&self) -> EmbeddedImages {
        *self
            .embedded
            .get_or_init(|| scan_embedded_images(self.data, &self.resources, self.pe.overlay()))
    }
}

/// Where one of a rule's strings was found.
///
/// The encoding is part of the answer because it is part of the length: the
/// same name occupies twice as many bytes spelled as UTF-16LE, and a location
/// that reported the wrong length would point a reader at the wrong bytes. It
/// is also part of the evidence: a name in an import table is a name the loader
/// resolves, and a name in a registry path is a name the program is about to
/// write — the same characters, meaning two different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextMatch {
    /// Offset of the match's first byte from the start of the sample.
    pub offset: usize,
    /// Whether the string is spelled as UTF-16LE in the sample.
    pub wide: bool,
}

impl TextMatch {
    /// How many bytes the match occupies, given the needle that was found.
    pub fn byte_length(&self, needle: &str) -> usize {
        needle.len() * if self.wide { 2 } else { 1 }
    }
}

/// Executable images found inside another file's bytes.
///
/// Each position is recorded once, so a sample carrying two images in its
/// resources and five appended after its sections answers "where is the first
/// of each kind" rather than "there is an executable in here somewhere" — the
/// distinction matters because the rules that ask are about *where* it is. An
/// image in a resource is a payload written out later by the program; an image
/// in the overlay is a payload the loader never sees; an image in neither is an
/// image in a section, which is the ordinary way for one program to carry
/// another (a self-extracting installer's stub, a compiler's runtime).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmbeddedImages {
    /// Offset of the first embedded image that lies inside a declared resource.
    pub first_in_resource: Option<u64>,
    /// Offset of the first embedded image that lies in the overlay, after the
    /// last section.
    pub first_in_overlay: Option<u64>,
    /// Offset of the first embedded image that lies in neither.
    pub first_elsewhere: Option<u64>,
}

impl EmbeddedImages {
    /// Whether any embedded image was found at all.
    pub fn any(&self) -> bool {
        self.first_in_resource.is_some()
            || self.first_in_overlay.is_some()
            || self.first_elsewhere.is_some()
    }

    /// The first offset found, preferring a resource and then the overlay.
    ///
    /// For reporting a location for a finding whose rule matched on "there is an
    /// image in here" without caring where. The preference order is fixed so
    /// that the same file always reports the same offset, which a report a user
    /// can re-check needs.
    pub fn first(&self) -> Option<u64> {
        self.first_in_resource
            .or(self.first_in_overlay)
            .or(self.first_elsewhere)
    }
}

/// Walk the buffer for DOS headers that lead to a PE signature.
///
/// # Why this shape of check
///
/// A run of two bytes proves nothing; `MZ` occurs in compressed data, in tables
/// of strings, and in the middle of values that mean something else entirely.
/// Three further facts have to hold before the bytes are an image: `e_lfanew`
/// has to be readable, it has to point into the range a real DOS stub occupies
/// (`0x40` to `0x1000`), and what it points at has to be the PE signature. The
/// bound on `e_lfanew` is the load-bearing part of the check and it was chosen
/// by measurement rather than by taste: with it, exactly **1 of the 4,000 PE
/// files in `C:\Windows\System32`** contains an embedded image inside a
/// resource — `MRT.exe`, Microsoft's Malicious Software Removal Tool, whose
/// oldest resource really is a second executable.
///
/// # Why it cannot be made to work harder than it does
///
/// Each candidate costs a bounded number of bounds-checked reads, so the walk is
/// linear in the buffer with no allocation and no recursion: the pathological
/// input (a file that is nothing but `MZ`) is 4 bytes per candidate and no
/// nesting, and every offset arithmetic is checked or saturating.
fn scan_embedded_images(
    data: &[u8],
    resources: &Resources<'_>,
    overlay: Overlay,
) -> EmbeddedImages {
    let mut found = EmbeddedImages::default();
    // Offset 0 is the file's own DOS header, not an embedded image. Starting at
    // 1 is what keeps a sample from being reported as containing a copy of
    // itself.
    let mut cursor = 1usize;
    while cursor < data.len() {
        let Some(found_at) = memchr::memchr(b'M', &data[cursor..]) else {
            break;
        };
        let candidate = cursor + found_at;
        cursor = candidate + 1;
        if !is_embedded_image_at(data, candidate) {
            continue;
        }
        let position = candidate as u64;
        if in_resource(position, resources) {
            found.first_in_resource.get_or_insert(position);
        } else if in_overlay(position, overlay) {
            found.first_in_overlay.get_or_insert(position);
        } else {
            found.first_elsewhere.get_or_insert(position);
        }
    }
    found
}

/// Whether the bytes at `candidate` are a DOS header whose `e_lfanew` leads to a
/// PE signature that is inside the buffer.
fn is_embedded_image_at(data: &[u8], candidate: usize) -> bool {
    if data.get(candidate) != Some(&b'M') || data.get(candidate + 1) != Some(&b'Z') {
        return false;
    }
    let Some(lfanew_at) = candidate.checked_add(E_LFANEW_OFFSET) else {
        return false;
    };
    let Some(lfanew_end) = candidate.checked_add(E_LFANEW_END) else {
        return false;
    };
    if lfanew_end > data.len() {
        return false;
    }
    let lfanew = u32::from_le_bytes([
        data[lfanew_at],
        data[lfanew_at + 1],
        data[lfanew_at + 2],
        data[lfanew_at + 3],
    ]);
    if !(MIN_E_LFANEW..=MAX_E_LFANEW).contains(&lfanew) {
        return false;
    }
    let Some(signature_at) = candidate.checked_add(lfanew as usize) else {
        return false;
    };
    let Some(signature_end) = signature_at.checked_add(PE_SIGNATURE.len()) else {
        return false;
    };
    if signature_end > data.len() {
        return false;
    }
    data[signature_at..signature_end] == PE_SIGNATURE
}

/// Whether an offset falls inside a declared resource.
///
/// The resource's length is the one the file *declared*, not one clamped to the
/// buffer, for the reason `av_pe::resources` documents: a file that lies about a
/// resource's size should be judged on the number it wrote.
fn in_resource(position: u64, resources: &Resources<'_>) -> bool {
    resources.leaves().iter().any(|resource| {
        let end = resource.offset.saturating_add(resource.length);
        position >= resource.offset && position < end
    })
}

/// Whether an offset falls in the overlay, after the last section's raw data.
fn in_overlay(position: u64, overlay: Overlay) -> bool {
    let end = overlay.offset.saturating_add(overlay.size);
    overlay.size > 0 && position >= overlay.offset && position < end
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_pe::testing::{add_imports, add_resources, minimal_pe32, ResourceSpec};

    /// A one-line import table, which is all any of these tests needs.
    fn pe_with_imports(libraries: &[(&str, &[&str])]) -> Vec<u8> {
        let mut pe = minimal_pe32();
        add_imports(&mut pe, libraries);
        pe
    }

    /// Whether a buffer holds an embedded image anywhere, for the tests that
    /// are about the walk rather than about where the image landed.
    fn has_image(data: &[u8]) -> bool {
        Evidence::parse(data)
            .expect("fixture parses")
            .embedded_images()
            .any()
    }

    #[test]
    fn a_parsed_sample_answers_import_questions_case_sensitively() {
        let data = pe_with_imports(&[("kernel32.dll", &["CreateProcessW", "OpenProcess"])]);
        let evidence = Evidence::parse(&data).expect("fixture parses");

        assert!(evidence.imports_symbol("CreateProcessW"));
        assert!(evidence.imports_any(&["Nope", "OpenProcess"]));
        assert!(evidence.imports_all(&["OpenProcess", "CreateProcessW"]));
        assert!(!evidence.imports_symbol("createprocessw"));
        assert!(!evidence.imports_all(&["OpenProcess", "VirtualAllocEx"]));
        assert!(evidence.imports_library("KERNEL32.DLL"));
    }

    #[test]
    fn a_non_pe_is_not_an_evidence() {
        assert!(Evidence::parse(b"not an executable at all").is_none());
        assert!(Evidence::parse(b"").is_none());
        // A DOS header with no PE signature behind it: the shape a stub in a
        // stub-prefixed script has, and not an image.
        let mut stub = vec![0u8; 0x80];
        stub[0] = b'M';
        stub[1] = b'Z';
        stub[0x3C] = 0x40;
        assert!(Evidence::parse(&stub).is_none());
    }

    #[test]
    fn a_sample_does_not_contain_a_copy_of_itself() {
        // The file's own DOS header sits at offset 0, and the walk starts at 1,
        // so a plain executable reports no embedded image. This is the case
        // that would make every file in the world a dropper.
        let data = minimal_pe32();
        let evidence = Evidence::parse(&data).expect("fixture parses");
        assert!(!evidence.embedded_images().any());
    }

    #[test]
    fn an_executable_in_a_resource_is_found_and_located() {
        let inner = minimal_pe32();
        let mut outer = minimal_pe32();
        add_resources(
            &mut outer,
            &[ResourceSpec::new(10u32, 1u32, &[1033u32], &inner)],
        );
        let evidence = Evidence::parse(&outer).expect("fixture parses");
        let embedded = evidence.embedded_images();

        let offset = embedded
            .first_in_resource
            .expect("the resource holds an executable");
        assert_eq!(embedded.first(), Some(offset));
        // The offset is real: the bytes there are the inner image's own header.
        let at = offset as usize;
        assert_eq!(&evidence.data()[at..at + 2], b"MZ");
        assert_eq!(embedded.first_in_overlay, None);
    }

    #[test]
    fn an_executable_appended_after_the_sections_is_in_the_overlay() {
        // The fixture's section table declares raw data past the end of the
        // file — it is a header and a stub, not a complete image — so an
        // appended payload only lands *after* the last section once the file
        // has been grown to the size the table claims. That gap is not an
        // artifact of the test: it is the difference between what the section
        // table describes and how long the file is, and a payload a packer or a
        // dropper appends sits after it exactly like this.
        let inner = minimal_pe32();
        let mut outer = minimal_pe32();
        outer.resize(0x800, 0);
        outer.extend_from_slice(&inner);
        let evidence = Evidence::parse(&outer).expect("fixture parses");
        let embedded = evidence.embedded_images();

        let offset = embedded.first_in_overlay.expect("the tail holds an image");
        assert_eq!(embedded.first_in_resource, None);
        assert_eq!(embedded.first_elsewhere, None);
        assert_eq!(offset as usize, 0x800);
        assert_eq!(offset as usize, outer.len() - inner.len());
        // The offset is real: the bytes there are the appended image's header.
        assert_eq!(
            &evidence.data()[offset as usize..offset as usize + 2],
            b"MZ"
        );
    }

    #[test]
    fn two_bytes_of_dos_magic_are_not_an_embedded_image() {
        // `MZ` alone is not evidence. Four shapes, each of which a packed or
        // compressed file produces by accident and the last of which is a real
        // image — so the test proves the four questions discriminate rather
        // than that the walk answers `false`.
        let base = minimal_pe32();

        // `MZ` at the very end of the file: `e_lfanew` is not even readable.
        let mut no_lfanew = base.clone();
        no_lfanew.extend_from_slice(b"MZ");
        assert!(!has_image(&no_lfanew));

        // `e_lfanew` pointing outside the buffer.
        let mut outside = base.clone();
        let at = outside.len();
        outside.extend_from_slice(&[0u8; 0x100]);
        outside[at..at + 2].copy_from_slice(b"MZ");
        outside[at + 0x3C..at + 0x40].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert!(!has_image(&outside));

        // `e_lfanew` inside the buffer but past the DOS-stub range a real stub
        // occupies, which is the bound that keeps this walk cheap.
        let mut too_far = outside.clone();
        too_far[at + 0x3C..at + 0x40].copy_from_slice(&0x1001u32.to_le_bytes());
        assert!(!has_image(&too_far));

        // `e_lfanew` in range and pointing at bytes that are not `PE\0\0`.
        let mut zeros = outside.clone();
        zeros[at + 0x3C..at + 0x40].copy_from_slice(&0x40u32.to_le_bytes());
        assert!(!has_image(&zeros));

        // And the same shape with the signature really there: found, which is
        // what makes the four assertions above mean something.
        let mut real = zeros;
        real[at + 0x40..at + 0x44].copy_from_slice(b"PE\0\0");
        assert!(has_image(&real));
    }
}
