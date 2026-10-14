//! What to do about a finding in a running process's memory.
//!
//! # The chain this module is the middle of
//!
//! The product's answer to malware that is already running is a chain of three
//! steps, and each one is somewhere different:
//!
//! 1. **Notice it.** [`av_memory::MemoryScanner`] reads the regions of a process
//!    that are worth reading and hands them to the engine. A match comes back as
//!    a [`MemoryFinding`], attributed to `process:address` because that is what
//!    identifies the evidence.
//! 2. **Find out where it came from.** [`av_memory::provenance::mapped_file_name`]
//!    asks the kernel which file backs that address, and every finding carries
//!    the answer as an [`Origin`].
//! 3. **Deal with the file.** This module. A path is not an action, and the
//!    interesting part of the whole chain is the decision in between.
//!
//! # Why a memory match is a lead and not a verdict about a file
//!
//! It would be a mistake to quarantine whatever file an [`Origin`] names, and
//! the reason is a property of Windows rather than a caution: **the bytes at an
//! address in a mapped image are not the bytes in the file.** The loader
//! relocates an image as it maps it (every absolute address inside it is
//! rewritten to wherever it actually landed), so a rule that matched at
//! `C:\...\libfoo.dll+0x1234` in memory may match nothing at all at `0x1234` in
//! the file on disk. On top of that a process may have patched its own image, or
//! an injected thread may have written into a region that still falls inside a
//! module's range. And for the [`Origin::Image`] case in particular, the kernel
//! would not name a file for the address itself, which is exactly the signal
//! that something about that region is not the plain mapped image.
//!
//! So the file in an origin is treated as a **lead**: a path worth examining. It
//! is then examined in its own right, and only its own verdict moves it. That is
//! the rule this module enforces, and it is enforced in one function so that
//! there is one place where the bar is stated: [`rule`], which reuses
//! [`crate::host::should_take`] so that the bar for a memory lead cannot drift
//! away from the bar for a file the walker found.
//!
//! # The three answers an origin can give, and the fourth that is not an answer
//!
//! `av_memory::Origin` has four variants and they do not divide evenly:
//!
//! * [`Origin::File`]: the kernel named this file for this address. A lead.
//! * [`Origin::Image`]: no file for the address, but the address is inside a
//!   loaded image. Also a lead, and a weaker one: see above for why the file's
//!   own verdict is what decides.
//! * [`Origin::Nothing`]: nothing on disk holds these bytes. **This is the
//!   detection, not a failure to find one.** It is the injected-code shape, the
//!   reason a memory scan is worth running at all, and there is no file to
//!   quarantine. [`Action::Leave`] with [`Left::NoFile`] is what this module
//!   says about it, and a caller must not read that as "nothing to do": the
//!   process is the thing to act on and it is named in the finding.
//! * [`Origin::Unknown`]: the question was never answered. Kept
//!   apart from [`Origin::Nothing`], because acting on "nothing on disk holds
//!   this" when the real fact is "this machine would not tell me" is how a
//!   scanner reports an injection that is not there.
//!
//! # The guard that is not about malware at all
//!
//! A memory scan reads whatever is mapped into a process, and on a healthy
//! machine that is mostly `C:\Windows\System32`. A rule that fires there (a
//! false positive, a packer heuristic, a byte pattern that happens to occur in
//! a system DLL) would otherwise lead straight to the vault, and a product that
//! quarantines `ntdll.dll` because a pattern matched in memory has broken the
//! machine more thoroughly than the malware it was looking for. So the file's
//! own verdict has to clear the bar, which most false positives will not.
//!
//! The second guard is about us rather than about Windows: a path inside the
//! product's own tree is refused before anything else happens. The vault's
//! contents are, by definition, files this product already decided were
//! malicious, and a memory scan of a process that has one mapped would
//! otherwise quarantine the vault's own item, taking it out of the vault and
//! destroying the restore copy. [`crate::engine::is_own_tree`] is the same
//! predicate the file walker refuses on, and the check happens *before* the
//! examination so that the vault is never read for this purpose at all.
//!
//! # What is not here
//!
//! Nothing here kills a process, and nothing here acts on
//! [`Origin::Nothing`] at all. Both are deliberate, and both are the boundary of
//! what this build does: terminating a process is a decision with a blast
//! radius this module has no basis for (a match in a shared process is not
//! evidence that the process is the malware), and it belongs with the
//! kernel callbacks that can also stop the process *before* it runs, which this
//! build does not have. What this module does is make the file actionable,
//! honestly, and say plainly when there is no file to act on. See
//! [`crate::host`] for how the outcome reaches a client.

use std::path::{Path, PathBuf};

use chrono::Utc;

use av_core::paths::AvPaths;
use av_core::scan::{FileScanReport, ScanOptions};
use av_core::{Severity, Verdict};
use av_ipc::{Detection, DetectionAction, MemoryCoverage, MemoryReport, Phase};
use av_memory::{MemoryFinding, Origin, ProcessOutcome, ProcessRef};
use av_quarantine::EntrySource;
use av_scan::ScanEngine;

use crate::engine;

/// What the file behind a memory finding turned out to be.
///
/// Three outcomes and not an `Option<Verdict>`, because "the file is not
/// malicious", "the file could not be read" and "the file is not there" lead to
/// three different sentences in a report and only the first is a statement about
/// the file's contents. Collapsing them would make an unreadable file look
/// examined, which is the same mistake [`av_core::scan::FileScanReport::error`]
/// exists to prevent one level down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Examination {
    /// The file was read and examined, and this is the verdict it earned.
    Verdict(Verdict),
    /// The file is there and could not be read, or could not be scanned.
    Unreadable {
        /// Why, in a sentence a user can read.
        reason: String,
    },
    /// There is no file at that path any more.
    ///
    /// Not a rare case and worth its own variant: malware that deletes itself
    /// after starting leaves its image mapped and its path pointing at nothing,
    /// and a report that called that "unreadable" would hide the most
    /// interesting fact about it. There is genuinely nothing to quarantine, and
    /// saying so is the honest answer.
    Missing,
}

/// Why a file was left where it was.
///
/// Each variant is a different fact and each one is worth a different sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Left {
    /// The file was examined and did not clear the bar to act on it.
    ///
    /// Carries the verdict, because "clean" and "suspicious" are different
    /// answers for the user: the yellow band is a warning, and a warning about a
    /// file that is also in memory is worth seeing.
    NotMalicious {
        /// What the engine said about the file itself.
        verdict: Verdict,
    },
    /// The file could not be examined, so nothing was decided about it.
    Unreadable {
        /// Why.
        reason: String,
    },
    /// The file is gone.
    Gone,
    /// The file is inside the product's own tree and is never acted on from
    /// here. See this module's documentation.
    OwnTree,
    /// Nothing on disk holds the bytes that matched, so there is no file to
    /// examine or to take. The finding is in the process, and the process is
    /// what a caller has to deal with.
    NoFile,
    /// Where the bytes came from was never established, so no file was looked
    /// for and none was ruled out.
    Unestablished,
}

/// What is to be done about one memory finding, before anything is done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The file is malicious in its own right and the vault should take it.
    ///
    /// Nothing has happened yet when this is returned: [`rule`] is a decision,
    /// and the caller is the one that talks to the vault. That separation is
    /// what makes every branch below testable without a service, a vault or a
    /// filesystem.
    Take {
        /// The file to take.
        file: PathBuf,
    },
    /// The file stays where it is, and this is why.
    Leave {
        /// The file the finding pointed at, when it pointed at one.
        file: Option<PathBuf>,
        /// Why it was not taken.
        why: Left,
    },
}

impl Action {
    /// The file this action is about, when it is about one.
    pub fn file(&self) -> Option<&Path> {
        match self {
            Action::Take { file } => Some(file),
            Action::Leave { file, .. } => file.as_deref(),
        }
    }

    /// True when the vault is to be asked for a file.
    pub const fn is_take(&self) -> bool {
        matches!(self, Action::Take { .. })
    }

    /// One sentence for a log line or a report.
    ///
    /// Written as three arms rather than as a subject chosen and then dropped
    /// into one sentence, because the file-less cases have no subject to put in
    /// front of it: "the bytes that matched was not taken" is the kind of line
    /// that makes a reader stop and read it again to find out what was not
    /// taken. Those cases say what they are about in the sentence itself.
    pub fn describe(&self) -> String {
        match self {
            Action::Take { file } => format!("{} is to be quarantined", file.display()),
            Action::Leave { file: None, why } => format!("no file was taken: {}", why.describe()),
            Action::Leave {
                file: Some(file),
                why,
            } => format!("{} was not taken: {}", file.display(), why.describe()),
        }
    }
}

impl Left {
    /// One sentence for a log line or a report.
    pub fn describe(&self) -> String {
        match self {
            Left::NotMalicious { verdict } => format!(
                "the file itself is {}, and a match in memory is a lead rather than a verdict \
                 about the file",
                verdict_word(*verdict)
            ),
            Left::Unreadable { reason } => format!("the file could not be examined: {reason}"),
            Left::Gone => {
                "the file is no longer on disk; its image is still mapped, which is what \
                 self-deleting malware leaves behind"
                    .to_string()
            }
            Left::OwnTree => {
                "the file is inside the product's own directory, whose contents are what this \
                 product already decided was malicious"
                    .to_string()
            }
            Left::NoFile => {
                "nothing on disk holds these bytes, so there is no file to take; the finding is \
                 about a region written into memory that no file backs"
                    .to_string()
            }
            Left::Unestablished => {
                "which file backs these bytes was never established, so no file was ruled out"
                    .to_string()
            }
        }
    }
}

/// The word a verdict is called in a sentence.
///
/// Exhaustive over [`Verdict`] rather than derived, so that a variant added
/// upstream stops this build instead of printing as a debug name.
fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Malicious => "malicious",
        Verdict::Suspicious => "suspicious",
        Verdict::Clean => "clean",
        Verdict::Unknown => "of unknown standing",
    }
}

/// The file a finding's origin points at, when it points at one.
///
/// Both [`Origin::File`] and [`Origin::Image`] name a file and both are worth
/// examining; the difference between them is a difference in how strong the
/// statement is, which the finding keeps in its own field and which a report
/// prints. It is deliberately not a difference in what is done, because the
/// thing done is the same in both cases: examine that file and act on what the
/// examination says, not on what memory said.
///
/// `None` for [`Origin::Nothing`] and [`Origin::Unknown`], and the two are told
/// apart by [`rule`] rather than here, because they need different sentences.
pub fn candidate(origin: &Origin) -> Option<&Path> {
    origin.path()
}

/// Decide what to do about one memory finding.
///
/// `examine` is called only when the decision needs it, which is what keeps the
/// product's own tree from being read at all — and is why the examination is a
/// closure rather than a value. In production it scans the file with the same
/// engine and the same options that a walker would use; in a test it is a
/// constant, which is what makes every branch below testable without a
/// filesystem.
///
/// The bar to take a file is [`crate::host::should_take`], the same function the
/// file walker's decision uses. Reusing it is the point: two bars would be two
/// answers to "is this malicious enough to act on", and the one a user is
/// protected by would depend on which path found the file.
pub fn rule(
    file: Option<&Path>,
    paths: &AvPaths,
    examine: impl FnOnce(&Path) -> Examination,
) -> Action {
    let Some(file) = file else {
        // The origin named no file. The two reasons are not the same reason.
        // `examine` is not called and is dropped: there is nothing to examine.
        return Action::Leave {
            file: None,
            why: Left::NoFile,
        };
    };
    let file = file.to_path_buf();

    // Before the examination, not after: the vault's contents are files this
    // product already took, and reading one to decide whether to take it would
    // be a loop that eats the vault. Refusing first means the vault is never
    // read for this purpose, and it means the answer does not depend on what
    // the examination would have said.
    if engine::is_own_tree(paths, &file) {
        return Action::Leave {
            file: Some(file),
            why: Left::OwnTree,
        };
    }

    // The path is handed back to the caller's closure rather than captured by
    // it, so that the caller never has to work out which path the decision is
    // about — and so that there is no way for the closure to examine one file
    // while the decision is about another.
    let why = match examine(&file) {
        Examination::Verdict(verdict) if crate::host::should_take(verdict) => {
            return Action::Take { file };
        }
        Examination::Verdict(verdict) => Left::NotMalicious { verdict },
        Examination::Unreadable { reason } => Left::Unreadable { reason },
        Examination::Missing => Left::Gone,
    };
    Action::Leave {
        file: Some(file),
        why,
    }
}

/// Decide what to do about a finding whose origin was never established.
///
/// Separate from [`rule`] because the answer does not depend on a path or on an
/// examination, and because the sentence is different: [`Left::Unestablished`]
/// says no file was ruled out, where [`Left::NoFile`] says one was and there is
/// none. A caller holding an [`Origin`] should use [`decide`].
pub const fn unestablished() -> Action {
    Action::Leave {
        file: None,
        why: Left::Unestablished,
    }
}

/// Decide what to do about one finding, from its origin.
///
/// The one entry point a caller needs: it separates an origin that names no file
/// because there is none from one that names none because the machine would not
/// say, and hands everything else to [`rule`].
///
/// Exhaustive over [`Origin`] with no wildcard, so a variant added to it stops
/// this build rather than defaulting to whichever side of the distinction an
/// author happened to write first.
pub fn decide(
    origin: &Origin,
    paths: &AvPaths,
    examine: impl FnOnce(&Path) -> Examination,
) -> Action {
    match origin {
        Origin::File { .. } | Origin::Image { .. } => rule(candidate(origin), paths, examine),
        Origin::Nothing => rule(None, paths, examine),
        Origin::Unknown => unestablished(),
    }
}

/// What an examination of a file produced.
///
/// The decision needs [`Examined::outcome`] and nothing else; the action needs
/// [`Examined::report`], because the vault records the numbers the *file's own*
/// scan reached rather than the ones the memory match did. Both come out of one
/// scan, which is why they are one value: returning them separately would mean
/// either scanning the file twice or having a caller hold a verdict whose report
/// it never saw.
#[derive(Debug, Clone)]
pub struct Examined {
    /// What the decision turns on.
    pub outcome: Examination,
    /// The file's own scan report, when a scan happened.
    ///
    /// `Some` exactly when `outcome` is [`Examination::Verdict`] — a scan that
    /// ran either produced a report or was replaced by
    /// [`Examination::Unreadable`]. It is an `Option` rather than a field of the
    /// `Verdict` variant because the executor keeps it across the decision, and
    /// a report inside the decision's input would make the decision's input
    /// larger than the decision needs.
    pub report: Option<FileScanReport>,
}

impl Examined {
    /// An examination that produced no report, because no file was scanned.
    fn unexamined(outcome: Examination) -> Self {
        Self {
            outcome,
            report: None,
        }
    }
}

/// Examine a file the way a memory finding's lead should be examined.
///
/// The same engine and the same options a walker uses, so that a file found
/// through memory is judged by exactly the rules and thresholds it would have
/// been judged by had the walker reached it first. Nothing here is a second
/// opinion or a cheaper check: this is the whole file scan, on the file.
///
/// The three failure modes are kept apart because the caller's decision turns on
/// them. A `metadata` failure that is not "not found" is [`Examination::Unreadable`]
/// and never [`Examination::Missing`] — a file held open with a deny-read share
/// mode, or one under a directory this process may not traverse, is a file that
/// exists, and calling it gone would report self-deletion that did not happen.
pub fn examine(engine: &ScanEngine, path: &Path, options: &ScanOptions) -> Examined {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                // A directory or a device where a file was expected. Named as
                // unreadable rather than missing, because it is there.
                return Examined::unexamined(Examination::Unreadable {
                    reason: format!("{} is not a file", path.display()),
                });
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Examined::unexamined(Examination::Missing);
        }
        Err(error) => {
            return Examined::unexamined(Examination::Unreadable {
                reason: error.to_string(),
            });
        }
    }

    let report = engine.scan_file(path, options);
    match report.error {
        // A scan that failed is not a verdict. `FileScanReport` promises the
        // verdict is `Unknown` in that case and never silently clean, and this
        // arm is where that promise is kept rather than assumed.
        Some(reason) => Examined::unexamined(Examination::Unreadable { reason }),
        None => Examined {
            outcome: Examination::Verdict(report.verdict()),
            report: Some(report),
        },
    }
}

/// A decision about a memory finding, and the file's own scan behind it.
///
/// The two travel together because a caller acting on the decision needs the
/// report and cannot produce it: a [`Action::Take`] is only ever reached on a
/// verdict, and the vault records the numbers the *file's* scan reached rather
/// than the ones the memory match did. Returning the decision alone would make
/// every caller either scan the file a second time or keep a report it had no
/// way to obtain.
///
/// Nothing has happened when this is returned. The vault is written by the
/// caller — [`crate::host::Host`] and nothing else — which is what keeps this
/// function testable without a vault and keeps the vault's one-writer rule from
/// depending on who called whom.
#[derive(Debug, Clone)]
pub struct Ruling {
    /// What is to be done about the finding.
    pub action: Action,
    /// The file's own scan report, when a scan happened.
    ///
    /// `Some` exactly when a file was scanned, which for a
    /// [`Action::Take`] is always — see [`Examined::report`].
    pub report: Option<FileScanReport>,
}

/// Decide about one finding *and* examine the file the decision turns on.
///
/// [`decide`] plus [`examine`], in the one order they have to happen in: the
/// closure is what [`decide`] calls when — and only when — the decision needs a
/// file read, so the product's own tree is refused without ever being opened.
///
/// This is the whole of the policy a memory finding is subject to, and it is one
/// function so that the two callers that have memory findings — a scan a client
/// asked for, and a process this service saw start — cannot come to different
/// conclusions about the same bytes. See [`crate::host::Host`] for the half that
/// acts, and `crate::process_watch` for the half that watches.
pub fn rule_on(
    origin: &Origin,
    paths: &AvPaths,
    engine: &ScanEngine,
    options: &ScanOptions,
) -> Ruling {
    // Stashed as a side effect of the closure, which is the only way a `FnOnce`
    // that returns one value can hand back two. The report is written before
    // the outcome is returned, so a caller that got a ruling cannot be holding
    // a verdict whose report was never stored.
    let mut report: Option<FileScanReport> = None;
    let action = decide(origin, paths, |path| {
        let examined = examine(engine, path, options);
        report = examined.report;
        examined.outcome
    });
    Ruling { action, report }
}

/// What was decided about one finding, and what the vault did about it.
///
/// Two fields because they are two facts and a caller needs both: the decision
/// is what the summary counts and what a log line explains, and the action is
/// what the protocol carries to a client. They agree by construction — the one
/// action that changes a file is produced only from
/// [`Action::Take`] — but they are not the same
/// value, and collapsing them would either lose the reason or force the summary
/// to parse a protocol type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Why the decision went the way it did.
    pub decision: Action,
    /// What happened, in the protocol's vocabulary.
    pub action: DetectionAction,
}

/// The three numbers a memory summary carries, counted from decisions.
///
/// Counted from the decisions rather than from the findings, because the two
/// differ: a finding whose file was examined and left is not a file that was
/// taken, and a finding with no file behind it is neither. A summary that
/// counted findings would report the first two as the same number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tallies {
    /// Findings whose file was taken into the vault.
    pub taken: u32,
    /// Findings whose file was examined and left where it is.
    pub left: u32,
    /// Findings with no file behind them at all.
    pub without_a_file: u32,
}

/// Count a run of decisions.
///
/// Exhaustive over [`Action`]'s two variants *and* over the reason a file was
/// left, so that a reason added later stops this build rather than silently
/// joining the "left" pile — [`Left::NoFile`] and [`Left::Unestablished`] are
/// not files that were left, they are findings that never had one.
pub fn tally<'a>(decisions: impl IntoIterator<Item = &'a Action>) -> Tallies {
    let mut tallies = Tallies::default();
    for action in decisions {
        match action {
            Action::Take { .. } => tallies.taken = tallies.taken.saturating_add(1),
            Action::Leave { why, .. } => match why {
                Left::NoFile | Left::Unestablished => {
                    tallies.without_a_file = tallies.without_a_file.saturating_add(1)
                }
                Left::NotMalicious { .. }
                | Left::Unreadable { .. }
                | Left::Gone
                | Left::OwnTree => tallies.left = tallies.left.saturating_add(1),
            },
        }
    }
    tallies
}

/// How much of a process a scan got through, as a client's report carries it.
pub fn coverage_of(outcome: &ProcessOutcome) -> MemoryCoverage {
    MemoryCoverage {
        regions_walked: outcome.regions_seen,
        // What was actually read, not what the predicate wanted to read: the
        // difference is exactly the set of regions the scanner looked away
        // from, and it is counted below rather than lost here.
        regions_examined: outcome.regions_read,
        bytes_read: outcome.bytes_read,
        regions_unreadable: outcome.regions_refused,
        regions_over_budget: outcome.regions_over_budget,
    }
}

/// One finding, as a client's detection, with what was done about it.
///
/// # What the path is, and what it is not
///
/// [`Detection::path`] is the file the detection is *about*, and for a memory
/// finding that is the file the bytes came from — which is the thing an action
/// acts on. When there is no such file, the process's own image stands in, and
/// when even that could not be read the process's label does. In every case
/// [`Detection::in_process`] carries the attribution — `process:address` — and
/// that, not the path, is where the evidence is. A client that renders the path
/// as "the file that was found" and `in_process` as "where it was running" says
/// the right thing in all four cases.
///
/// # What the size is
///
/// The region's size, not a file's. A memory finding has no file size, and
/// reporting zero would read as an empty file. The number a reader wants is how
/// much memory the match was found in.
///
/// # What the phase is
///
/// After-the-fact, always, and hardcoded rather than passed in: the process is
/// running by the time anything here happens. There is no argument to this
/// function that could make it claim otherwise, which is the point — see
/// [`Phase::observed`] and `av_service::host`'s note on what this build cannot
/// do.
///
/// # What `terminated` is
///
/// A parameter because it is a fact about the machine rather than about the
/// finding: the *caller* is the one that asked a process to stop, and only it
/// knows whether that happened. It is deliberately not derived from `action` —
/// a finding whose bytes came from no file is left by every decision this
/// module can reach, and its process can still have been terminated.
pub fn detection_for(
    finding: &MemoryFinding,
    action: DetectionAction,
    terminated: bool,
) -> Detection {
    let path = finding
        .origin
        .path()
        .map(Path::to_path_buf)
        .or_else(|| finding.process.image.clone())
        .unwrap_or_else(|| PathBuf::from(finding.process.label()));

    Detection {
        file_name: crate::host::file_name_of(&path),
        path,
        verdict: finding.verdict,
        score: finding.score,
        severity: finding.max_severity().unwrap_or(Severity::High),
        threat: finding.detections.iter().find_map(|one| one.threat.clone()),
        rules: finding
            .detections
            .iter()
            .map(|one| {
                if one.rule_id.is_empty() {
                    one.display_name().to_string()
                } else {
                    one.rule_id.clone()
                }
            })
            .collect(),
        action,
        source: EntrySource::Memory,
        size: finding.region_size as u64,
        at: Utc::now(),
        in_process: Some(finding.container()),
        terminated,
        phase: Phase::observed(EntrySource::Memory, false),
    }
}

/// A report for a process that was not examined at all.
///
/// The one constructor for a refusal, so that every refusal has the same shape:
/// no findings, nothing covered, and a reason that is a sentence. A refusal with
/// an empty reason would be a report that says "not examined" and not why, which
/// is the least useful thing a scan report can be.
pub fn refused_report(process: &ProcessRef, reason: String) -> MemoryReport {
    MemoryReport {
        pid: process.pid,
        process: process.describe(),
        findings: Vec::new(),
        coverage: MemoryCoverage::default(),
        walk_complete: false,
        refused: Some(reason),
        files_taken: 0,
        files_left: 0,
        without_a_file: 0,
        at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths under a temporary directory, so the own-tree check has something
    /// real to answer about.
    ///
    /// `pub(super)` so that [`super::live`] uses this one definition rather than
    /// spelling the layout a second time: two spellings of where the vault is
    /// would be two answers to what "the product's own tree" means.
    pub(super) fn layout(dir: &tempfile::TempDir) -> AvPaths {
        AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"))
    }

    /// A decision for a file whose examination says `examination`.
    fn decided(paths: &AvPaths, file: &str, examination: Examination) -> Action {
        rule(Some(Path::new(file)), paths, |_| examination)
    }

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    #[test]
    fn a_file_that_is_malicious_on_its_own_is_taken() {
        let dir = temp();
        let action = decided(&layout(&dir), r"C:\Users\me\Downloads\invoice.exe", {
            Examination::Verdict(Verdict::Malicious)
        });
        assert!(action.is_take());
        assert_eq!(
            action.file(),
            Some(Path::new(r"C:\Users\me\Downloads\invoice.exe"))
        );
        match action {
            Action::Take { file } => {
                assert_eq!(file, Path::new(r"C:\Users\me\Downloads\invoice.exe"));
            }
            other => panic!("expected a take, got {other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_not_malicious_on_its_own_is_left_and_the_verdict_survives() {
        let dir = temp();
        // The yellow band is the interesting one: it *is* a warning, and it
        // still does not act. That is the same policy the file walker follows.
        for verdict in [Verdict::Suspicious, Verdict::Clean] {
            let action = decided(&layout(&dir), r"C:\x\a.dll", Examination::Verdict(verdict));
            assert!(!action.is_take());
            match action {
                Action::Leave { file, why } => {
                    assert_eq!(file.as_deref(), Some(Path::new(r"C:\x\a.dll")));
                    assert_eq!(why, Left::NotMalicious { verdict });
                }
                other => panic!("expected a leave for {verdict:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_bar_for_a_memory_lead_is_the_bar_for_a_file() {
        // The drift test, and the reason `rule` calls `should_take` instead of
        // comparing against `Malicious` itself. If a verdict is ever added, or
        // the file walker's policy changes, this fails rather than letting the
        // two paths disagree about what is worth acting on.
        let dir = temp();
        let paths = layout(&dir);
        for verdict in [
            Verdict::Malicious,
            Verdict::Suspicious,
            Verdict::Clean,
            Verdict::Unknown,
        ] {
            let action = decided(&paths, r"C:\x\a.dll", Examination::Verdict(verdict));
            assert_eq!(
                action.is_take(),
                crate::host::should_take(verdict),
                "memory and file decisions disagree about {verdict:?}"
            );
        }
    }

    #[test]
    fn a_file_that_cannot_be_examined_is_left_and_says_why() {
        let dir = temp();
        let action = decided(
            &layout(&dir),
            r"C:\x\locked.dll",
            Examination::Unreadable {
                reason: "Access is denied.".to_string(),
            },
        );
        match action {
            Action::Leave { why, .. } => {
                assert_eq!(
                    why,
                    Left::Unreadable {
                        reason: "Access is denied.".to_string()
                    }
                );
            }
            other => panic!("expected a leave, got {other:?}"),
        }
    }

    #[test]
    fn a_file_that_is_gone_is_not_the_same_as_one_that_could_not_be_read() {
        // Both mean "not taken", and they mean opposite things about the file:
        // one is still there and one is not. A report that showed the same
        // sentence for both would hide a self-deleting sample.
        let dir = temp();
        let paths = layout(&dir);
        let gone = decided(&paths, r"C:\x\gone.exe", Examination::Missing);
        let unreadable = decided(
            &paths,
            r"C:\x\gone.exe",
            Examination::Unreadable {
                reason: "Access is denied.".to_string(),
            },
        );
        assert_ne!(gone, unreadable);
        let Action::Leave { why: gone_why, .. } = gone else {
            panic!("expected a leave");
        };
        assert_eq!(gone_why, Left::Gone);
        assert!(gone_why.describe().contains("no longer on disk"));
    }

    #[test]
    fn the_products_own_tree_is_refused_without_ever_being_examined() {
        let dir = temp();
        let paths = layout(&dir);
        // A file inside the vault. The examination closure panics, so this test
        // fails if the guard is moved after the examination: the point is not
        // only that the answer is a refusal but that the vault is never read.
        let inside = paths.quarantine_dir.join("items").join("payload.bin");
        let action = rule(Some(&inside), &paths, |_| {
            panic!("the vault was read to decide whether to take something out of the vault")
        });
        match action {
            Action::Leave { file, why } => {
                assert_eq!(file.as_deref(), Some(inside.as_path()));
                assert_eq!(why, Left::OwnTree);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_origin_that_names_nothing_is_a_finding_and_not_an_absence() {
        let dir = temp();
        let action = decide(&Origin::Nothing, &layout(&dir), |_| {
            panic!("there is no file to examine")
        });
        match action {
            Action::Leave { file, why } => {
                assert!(file.is_none());
                assert_eq!(why, Left::NoFile);
            }
            other => panic!("expected a leave, got {other:?}"),
        }
    }

    #[test]
    fn an_origin_that_was_never_established_is_not_an_origin_that_names_nothing() {
        // The distinction the whole report is built around: "nothing on disk
        // holds this" is a detection, and "this machine would not tell me" is a
        // gap. They must not produce the same sentence.
        let dir = temp();
        let paths = layout(&dir);
        let nothing = decide(&Origin::Nothing, &paths, |_| Examination::Missing);
        let unknown = decide(&Origin::Unknown, &paths, |_| {
            panic!("nothing was established, so there is nothing to examine")
        });
        assert_ne!(nothing, unknown);
        let Action::Leave { why, file } = unknown else {
            panic!("expected a leave");
        };
        assert!(file.is_none());
        assert_eq!(why, Left::Unestablished);
        assert!(why.describe().contains("never established"));
    }

    #[test]
    fn both_kinds_of_origin_that_name_a_file_lead_to_the_file_being_examined() {
        let dir = temp();
        let paths = layout(&dir);
        for origin in [
            Origin::File {
                path: PathBuf::from(r"C:\Users\me\bad.exe"),
            },
            Origin::Image {
                path: PathBuf::from(r"C:\Users\me\bad.exe"),
            },
        ] {
            let action = decide(&origin, &paths, |_| {
                Examination::Verdict(Verdict::Malicious)
            });
            match action {
                Action::Take { file } => assert_eq!(file, Path::new(r"C:\Users\me\bad.exe")),
                other => panic!("expected a take for {origin:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn every_action_and_every_reason_says_something_a_report_can_print() {
        let dir = temp();
        let paths = layout(&dir);
        let actions = [
            decided(
                &paths,
                r"C:\x\a.exe",
                Examination::Verdict(Verdict::Malicious),
            ),
            decided(
                &paths,
                r"C:\x\a.exe",
                Examination::Verdict(Verdict::Suspicious),
            ),
            decided(&paths, r"C:\x\a.exe", Examination::Verdict(Verdict::Clean)),
            decided(
                &paths,
                r"C:\x\a.exe",
                Examination::Verdict(Verdict::Unknown),
            ),
            decided(&paths, r"C:\x\a.exe", Examination::Missing),
            decided(
                &paths,
                r"C:\x\a.exe",
                Examination::Unreadable {
                    reason: "denied".to_string(),
                },
            ),
            decide(&Origin::Nothing, &paths, |_| Examination::Missing),
            unestablished(),
        ];
        for action in &actions {
            let text = action.describe();
            assert!(!text.is_empty(), "an action described itself as nothing");
            // Three shapes, and the third is the one that took a rewrite: a
            // decision about no file at all cannot be phrased as a decision
            // about a subject it does not have.
            assert!(
                text.contains("was not taken")
                    || text.contains("is to be quarantined")
                    || text.starts_with("no file was taken:"),
                "unreadable sentence: {text}"
            );
            // And whatever the shape, it does not open with a bare "was".
            assert!(!text.starts_with("was "), "no subject: {text}");
        }
    }

    #[test]
    fn a_verdict_is_never_printed_as_a_debug_name() {
        // A sentence with `Suspicious` in it reads as a field dump; these are
        // the words the report uses.
        for verdict in [
            Verdict::Malicious,
            Verdict::Suspicious,
            Verdict::Clean,
            Verdict::Unknown,
        ] {
            let text = Left::NotMalicious { verdict }.describe();
            assert!(
                !text.contains(&format!("{verdict:?}")),
                "{text} contains the debug spelling"
            );
            assert!(text.contains(verdict_word(verdict)), "{text}");
        }
    }
}

/// The half of this module that touches a real filesystem.
///
/// The decision above is pure and is tested without one; [`examine`] is the
/// three-way answer about a path on a machine, and the distinctions it draws are
/// exactly the ones that can only be checked against a filesystem: that a file
/// which is there comes back with a verdict from the real engine, that a path
/// which is not there is [`Examination::Missing`], and that a directory — which
/// *is* there — is not mistaken for one that is gone.
///
/// Named `live` rather than `windows` because a module called `windows` would
/// shadow the `windows` crate for everything inside it.
#[cfg(test)]
mod live {
    use super::*;

    use av_rules::database::RuleDatabase;

    use super::tests::layout;

    /// The bytes the test rule looks for.
    const MARKER: &str = "WENLE-MEMORY-PROVENANCE-MARKER";

    /// An engine with one rule, which fires on a file containing [`MARKER`].
    ///
    /// The severity is stated rather than left out, and that is not decoration:
    /// a rule with no severity scores as `Medium`, which is 60, which is the
    /// yellow band — and the yellow band never acts. A rule meant to stand for
    /// a real detection has to clear `VerdictThresholds::malicious`, so the
    /// fixture states the severity a real detection would carry. The whole
    /// point of these tests is the bar, so the fixture has to be over it.
    fn engine() -> ScanEngine {
        let source = format!(
            "rule Test_Finds_Marker {{\n  meta:\n    severity = \"critical\"\n  \
             strings:\n    $a = \"{MARKER}\"\n  condition:\n    $a\n}}\n"
        );
        let (database, report) = RuleDatabase::compile(&source);
        assert!(
            report.refused() == 0 && database.len() == 1,
            "the test rule must compile: {report:?}"
        );
        ScanEngine::new(database)
    }

    /// Options under which the verdict is the rule's and nothing else's.
    ///
    /// Heuristics off because a five-byte test file has a shape a heuristic may
    /// well object to, and the point of these tests is the rule. Archives off
    /// for the same reason: these files are not containers.
    fn options() -> ScanOptions {
        ScanOptions {
            recursive: false,
            heuristics: false,
            archives: false,
            trust: false,
            per_file_timeout: None,
            ..ScanOptions::default()
        }
    }

    #[test]
    fn a_file_that_is_there_is_examined_and_its_verdict_comes_back() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, format!("prefix {MARKER} suffix")).expect("the file is writable");

        let examined = examine(&engine(), &path, &options());
        assert_eq!(
            examined.outcome,
            Examination::Verdict(Verdict::Malicious),
            "a file the rule fires on must come back malicious, which is what lets the vault take it"
        );
        assert!(
            examined.report.is_some(),
            "a verdict comes with the report it was reached from"
        );
    }

    #[test]
    fn a_file_the_rule_does_not_fire_on_is_examined_and_is_not_malicious() {
        // The other direction, and the one that protects the machine: a lead
        // from memory whose file turns out to be ordinary must not be taken.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("ordinary.bin");
        std::fs::write(&path, b"nothing of interest here").expect("the file is writable");

        let examination = examine(&engine(), &path, &options());
        assert_eq!(examination.outcome, Examination::Verdict(Verdict::Clean));
        assert!(!crate::host::should_take(Verdict::Clean));
    }

    #[test]
    fn a_path_that_is_not_there_is_missing_and_never_unreadable() {
        // The self-deleting case: the image is still mapped, the path points at
        // nothing. This must be `Missing` — a fact about the malware — and not
        // the same answer as a file that exists and is locked.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("deleted-itself.exe");
        assert_eq!(
            examine(&engine(), &path, &options()).outcome,
            Examination::Missing
        );
    }

    #[test]
    fn a_directory_is_unreadable_and_not_missing() {
        // A directory is *there*. Reporting it as gone would be a false
        // statement about the machine, and the two answers are deliberately
        // different variants so that it cannot happen by accident.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let examination = examine(&engine(), dir.path(), &options()).outcome;
        match examination {
            Examination::Unreadable { reason } => {
                assert!(reason.contains("not a file"), "{reason}");
            }
            other => panic!("expected a directory to be unreadable, got {other:?}"),
        }
    }

    #[test]
    fn the_end_of_the_whole_chain_is_a_file_in_the_vault() {
        // The chain the product promises, in one test and with nothing faked
        // except the origin: a finding whose bytes came from a file, a real
        // examination of that file by the real engine, and a vault that is
        // really asked to take it. Only the memory read itself is absent, and
        // what it would contribute is the `Origin` this test supplies.
        use av_quarantine::{EntrySource, QuarantineContext, QuarantinePolicy, QuarantineVault};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = layout(&dir);
        std::fs::create_dir_all(&paths.data_dir).expect("the data directory");

        let path = dir.path().join("dropped.exe");
        std::fs::write(&path, MARKER).expect("the file is writable");
        let origin = Origin::File { path: path.clone() };

        let engine = engine();
        let options = options();
        let action = decide(&origin, &paths, |candidate| {
            assert_eq!(
                candidate, path,
                "the decision must examine the file it is about"
            );
            examine(&engine, candidate, &options).outcome
        });

        let Action::Take { file } = action else {
            panic!("the file is malicious on its own, so it must be taken: {action:?}");
        };
        assert_eq!(file, path);
        assert!(
            file.exists(),
            "the decision is a decision and not an action"
        );

        let mut vault =
            QuarantineVault::open(paths.quarantine_dir.clone(), QuarantinePolicy::default())
                .expect("the vault opens");
        let report = engine.scan_file(&file, &options);
        let entry = vault
            .quarantine_file(
                &file,
                &QuarantineContext::from_report(&report, EntrySource::Memory),
            )
            .expect("the vault takes a file the engine called malicious");

        assert_eq!(entry.source, EntrySource::Memory);
        assert!(!path.exists(), "the file is out of the place it was found");
        assert_eq!(vault.list().len(), 1);
    }
}
