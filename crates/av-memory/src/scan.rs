//! Doing the scan, and what the report is allowed to claim.
//!
//! # The rule this module is built around
//!
//! **A scan must never be able to claim completeness it did not have.** That is
//! one sentence and it decides most of the types below. A process whose handle
//! was refused is a process nobody looked at; a region whose read was refused
//! is a region nobody looked at; a region that was read to a cap is a region
//! nobody looked at past the cap; a region the engine declined to judge is a
//! region nobody has an answer about. All five come out of the scan as separate
//! numbers, and [`MemorySummary::is_complete`] is false if any of them is not
//! zero. A caller that wants to print "clean" has to have asked that question
//! first, and cannot get a true answer by accident.
//!
//! # The two numbers that must never be merged
//!
//! `regions_read` and `regions_refused` are separate counters, and a refused
//! read never produces a finding and never produces a "nothing found" either.
//! Collapsing them is the specific bug this crate exists to avoid: it turns
//! "we could not look" into "we looked and it was fine", which is the difference
//! between a scanner that reports what it knows and one that reports what it
//! wishes were true.
//!
//! # Why the engine is reused rather than a second matcher written
//!
//! The rules, the prefilter, the scoring model and the trust layer are all in
//! [`av_scan`], and a memory scan is those things pointed at a different kind
//! of buffer. A second matcher would be a second set of bugs to find, a second
//! scoring model to keep in step, and two answers to "why did this rule fire
//! here and not there". The engine's entry point takes a path because a file
//! scan has one; a region does not, so it is given a synthetic path and the
//! real attribution travels in [`av_core::Detection::container`], which every
//! consumer of a file report already renders. (What a client of the *service*
//! sees is `in_process` on an `av_ipc::Detection`, as [`crate`]'s own
//! documentation explains.)
//!
//! # The defaults, and the measurements behind them
//!
//! The caps in [`MemoryScanConfig::default`] are sized from what real processes
//! turned out to hold, and a whole-machine census is what says which of them
//! actually binds:
//!
//! * A scan of every process on the development machine this was written on
//!   read between 54 and 77 megabytes, out of 319 to 329 regions judged worth
//!   reading in an address space of 190,000 to 205,000 regions. The 256-mebibyte
//!   total was therefore **not** reached by a whole machine in any of six runs —
//!   it is three to five times the whole machine — which is the point: a budget
//!   that bound on a healthy machine would be a budget that made ordinary scans
//!   incomplete. It is sized for the machine that is not healthy.
//! * The four-mebibyte per-region cap *did* bind: 8 to 10 of those regions in
//!   each run were read to the cap and reported as truncated rather than in
//!   full. A cap that never binds is a cap nobody has tested; this one binds on
//!   about 3% of interesting regions, and it is the difference between reading a
//!   region and reading the first megabyte of a gigabyte. A process that wants
//!   to make a scan expensive can allocate a gigabyte of private executable
//!   memory, and the cap is what stops that being a gigabyte of scanning.
//!
//! explorer.exe is the process the numbers were first taken on, and the one
//! number that never moved: 22 regions worth reading, 290,816 bytes, in every
//! run.

use std::path::Path;
use std::time::{Duration, Instant};

use av_core::{Detection, DetectionSource, FileScanReport, ScanOptions, Verdict};
use av_scan::ScanEngine;
use serde::{Deserialize, Serialize};

use crate::error::MemoryError;
use crate::process::ProcessRef;
use crate::provenance::Origin;
use crate::region::{classify, Interest, Protection, RegionInterest, RegionKind, Skip};
use crate::source::{MemorySource, RegionWalk};

/// How many refused reads a single process's outcome lists individually.
///
/// The count is always exact; this only bounds the list. A report is read by a
/// person, and a process with ten thousand unreadable regions would produce a
/// list nobody reads, so the tail is dropped and counted. Sixty-four is enough
/// to see a pattern — every failure being `ERROR_ACCESS_DENIED` at a page
/// boundary, say — which is what the list is for.
pub const MAX_UNREADABLE_LISTED: usize = 64;

/// How much of a process to read, and how to judge what is read.
#[derive(Debug, Clone)]
pub struct MemoryScanConfig {
    /// Most bytes to read from any one region.
    ///
    /// A larger region is read from its start and reported as truncated. The
    /// bytes past the cap were not examined, and
    /// [`MemorySummary::is_complete`] says so.
    pub max_region_bytes: usize,

    /// Most bytes to read from one process, across all its regions.
    ///
    /// Reached regions are counted and listed as over budget rather than
    /// silently skipped.
    pub max_total_bytes: u64,

    /// Most regions to walk in one process before giving up on the walk.
    pub max_regions: usize,

    /// Smallest region worth asking for. See [`classify`].
    pub min_region_bytes: usize,

    /// How long the walk may take before it stops where it is.
    ///
    /// # Why a byte budget is not enough
    ///
    /// Every other cap here bounds *work*, and work is not what a caller on a
    /// deadline is short of. A scan a user asked for has no deadline and the
    /// default is therefore `None`: it runs to the end of the address space and
    /// reports what it could not finish. A scan started because a process
    /// appeared has one, and the difference is what it is competing with — a
    /// process-start scan runs on a queue, and a region walk of a process that
    /// is allocating as fast as it is being read can stay under both byte caps
    /// indefinitely while never finishing.
    ///
    /// # What expiry means, and what it does not
    ///
    /// The walk stops where it is. That is recorded — [`ProcessOutcome::walk_complete`]
    /// becomes false and [`ProcessOutcome::deadline_reached`] becomes true — and
    /// the report says so in [`ProcessOutcome::gaps`]. What has already been
    /// read has already been judged, so findings from the part that was walked
    /// are real findings. What must never happen is expiry reading as
    /// completeness: a caller that reported a deadline-stopped scan as clean
    /// would be reporting an unexamined address space as an examined one, which
    /// is the one thing this module is built to prevent.
    ///
    /// The clock is checked between regions and never inside one. A single
    /// region read is one `ReadProcessMemory` call, which a kernel does not
    /// hold for long, so the overshoot past the deadline is bounded by one read
    /// rather than by the remaining walk.
    pub deadline: Option<Duration>,

    /// What to hand the scan engine.
    pub options: ScanOptions,
}

impl Default for MemoryScanConfig {
    fn default() -> Self {
        Self {
            max_region_bytes: 4 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_regions: 100_000,
            min_region_bytes: 16,
            // No deadline on a scan a caller asked for. The real-time path
            // states one; see the field's documentation.
            deadline: None,
            options: memory_scan_options(),
        }
    }
}

/// The scan options a memory scan wants, and why each differs from the default
/// for a file scan.
///
/// * `recursive` and `follow_links` are off because there is no directory tree
///   here. Nothing downstream should believe it is walking one.
/// * `heuristics` is off. The heuristics are about file structure — the entropy
///   of a whole image, an import table, a packer's section names — and a
///   fragment of a region has none of those. Running them over a four-kilobyte
///   fragment would produce scores calibrated for something else, which is a
///   false-positive generator, not extra coverage. Rules still run.
/// * `archives` is off because a region is not a container. If a caller turns
///   it on anyway, a member found inside a region keeps its own name and gains
///   the region as a prefix — see [`attribute`] — so nothing is lost.
/// * `trust` is off because the trust layer judges a file by where it sits on
///   disk and who signed it. A region has neither, and the synthetic path this
///   module builds would only ever match by accident.
/// * `max_file_size` is `None` on purpose. The cap that applies to a region is
///   [`MemoryScanConfig::max_region_bytes`], and leaving the engine's own cap
///   in place would mean the engine silently judged a prefix while this crate's
///   report said the region had been read in full. One cap, in the place that
///   counts it.
pub fn memory_scan_options() -> ScanOptions {
    ScanOptions {
        recursive: false,
        follow_links: false,
        heuristics: false,
        memory: true,
        trust: false,
        archives: false,
        max_file_size: None,
        ..ScanOptions::default()
    }
}

/// Why a process was not examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Windows refused a handle. The process belongs to another user, or is
    /// protected, or is a system process that refuses everybody — Windows
    /// reports all three the same way, so this records what it said and does
    /// not guess which it was.
    AccessDenied {
        /// The Win32 error code, in practice always
        /// [`ERROR_ACCESS_DENIED`](crate::error::ERROR_ACCESS_DENIED).
        code: u32,
        /// Windows' own message.
        message: String,
    },
    /// The PID does not name a running process.
    ///
    /// The ordinary case on a live machine: the process exited between being
    /// listed and being opened. It says nothing about the machine's health, and
    /// is a separate reason from a refusal precisely so that a report does not
    /// make it look like one.
    Gone,
    /// The handle opened but the process's regions could not be walked.
    ///
    /// Nothing was read from this process, and the reason is recorded at the
    /// process rather than at a region because the failure happened before any
    /// region was known.
    RegionsUnavailable {
        /// The Win32 error code, when the failure came from one.
        code: u32,
        /// What Windows said, or what this crate noticed.
        message: String,
    },
}

impl RefusalReason {
    /// Classify a failure to look at a process.
    ///
    /// Only meaningful for errors from opening or walking a process. A
    /// per-region read failure is not a process refusal and never reaches here
    /// — it lands in [`UnreadableRegion`] instead, where it belongs.
    pub fn from_error(error: &MemoryError) -> Self {
        match error {
            MemoryError::Denied { code, message, .. } => RefusalReason::AccessDenied {
                code: *code,
                message: message.clone(),
            },
            MemoryError::Gone { .. } => RefusalReason::Gone,
            MemoryError::RegionWalk { code, message, .. } => RefusalReason::RegionsUnavailable {
                code: *code,
                message: message.clone(),
            },
            // Anything else here is a failure to get at the process's memory by
            // some other route, which is what this reason means.
            other => RefusalReason::RegionsUnavailable {
                code: other.code().unwrap_or(0),
                message: other.to_string(),
            },
        }
    }

    /// The word to print for this reason.
    pub const fn as_str(&self) -> &'static str {
        match self {
            RefusalReason::AccessDenied { .. } => "access-denied",
            RefusalReason::Gone => "gone",
            RefusalReason::RegionsUnavailable { .. } => "regions-unavailable",
        }
    }

    /// A sentence for a report.
    pub fn describe(&self) -> String {
        match self {
            RefusalReason::AccessDenied { code, message } => {
                format!("Windows refused a handle: {message} (error {code})")
            }
            RefusalReason::Gone => "the process exited before it could be opened".to_string(),
            RefusalReason::RegionsUnavailable { code, message } => {
                format!("the region walk failed: {message} (error {code})")
            }
        }
    }
}

/// A region that was worth reading and could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadableRegion {
    /// The address the region starts at.
    pub base: usize,
    /// How many bytes the region covers.
    pub size: usize,
    /// Why it could not be read.
    pub error: MemoryError,
}

/// One region's worth of findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryFinding {
    /// The process the region belongs to.
    pub process: ProcessRef,
    /// The region's start address.
    pub base: usize,
    /// The region's full size, whether or not all of it was read.
    pub region_size: usize,
    /// How many bytes were actually read and matched against.
    pub bytes_read: usize,
    /// True when only the head of the region was read.
    pub truncated: bool,
    /// Why the region was read at all.
    pub interest: Interest,
    /// The region's protection, as the operating system reported it.
    pub protection: Protection,
    /// What the region is backed by.
    pub kind: RegionKind,
    /// The file on disk these bytes came from, when the machine could say.
    ///
    /// The field that makes a memory finding actionable. A match in a region
    /// backed by a file is a match in *that file*, and the file is what has to
    /// be dealt with: killing the process ends the incident until the file is
    /// run again. A match in a region backed by nothing is the injected-code
    /// shape and has no file to act on, which is why the two are different
    /// values here rather than one optional path — see [`crate::provenance`].
    pub origin: Origin,
    /// The engine's verdict for this region.
    pub verdict: Verdict,
    /// The engine's accumulated score for this region.
    pub score: u16,
    /// The detections, every one of them attributed to this region.
    pub detections: Vec<Detection>,
}

impl MemoryFinding {
    /// The string this finding is attributed to: the process and the address.
    pub fn container(&self) -> String {
        self.process.container(self.base)
    }

    /// The highest severity among the detections, if any.
    pub fn max_severity(&self) -> Option<av_core::Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }
}

/// One line of a process's report: what was read, and what was not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadableRegionList {
    /// The first [`MAX_UNREADABLE_LISTED`] refused regions, in address order.
    pub listed: Vec<UnreadableRegion>,
    /// How many refused regions are not in [`UnreadableRegionList::listed`].
    pub omitted: u64,
}

/// How many regions were passed over for each reason.
///
/// A struct of counters rather than a map, so that the arithmetic in
/// [`MemorySummary`] is over fields a reader can check by eye and so that
/// nothing iterates in hash order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipTally {
    /// Reserved or free.
    pub not_committed: u64,
    /// Below the caller's floor.
    pub too_small: u64,
    /// Guarded.
    pub guard: u64,
    /// Committed and executable but not readable.
    pub not_readable: u64,
    /// Not executable.
    pub not_executable: u64,
    /// Executable and read-only, backed by a section reported as a file.
    pub backed_by_file: u64,
}

impl SkipTally {
    /// Count one passed-over region.
    pub fn record(&mut self, skip: Skip) {
        let counter = match skip {
            Skip::NotCommitted => &mut self.not_committed,
            Skip::TooSmall => &mut self.too_small,
            Skip::Guard => &mut self.guard,
            Skip::NotReadable => &mut self.not_readable,
            Skip::NotExecutable => &mut self.not_executable,
            Skip::BackedByFile => &mut self.backed_by_file,
        };
        *counter = counter.saturating_add(1);
    }

    /// How many passed-over regions this counts.
    pub const fn total(&self) -> u64 {
        self.not_committed
            .saturating_add(self.too_small)
            .saturating_add(self.guard)
            .saturating_add(self.not_readable)
            .saturating_add(self.not_executable)
            .saturating_add(self.backed_by_file)
    }
}

/// What one process's scan found, and what it could not look at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessOutcome {
    /// The process that was examined.
    pub process: ProcessRef,
    /// True when the region walk reached the end of the address space.
    ///
    /// False for either of two reasons, and they are told apart by
    /// [`ProcessOutcome::deadline_reached`]: the walk hit the region cap, or the
    /// deadline for the walk passed. Both mean the address space was not seen in
    /// full and neither may be reported as a clean process.
    pub walk_complete: bool,
    /// True when the walk stopped because [`MemoryScanConfig::deadline`] passed.
    ///
    /// Separate from `walk_complete` because the two stop reasons need different
    /// sentences: a region cap is a property of the process, and a deadline is a
    /// property of the caller. Reading the first as the second would tell a
    /// reader to look for a process with an enormous address space.
    pub deadline_reached: bool,
    /// How many regions the walk was taken through.
    ///
    /// The size of the walk, unless [`ProcessOutcome::deadline_reached`] is
    /// true — a walk that ran out of time was handed regions it never reached,
    /// and counting those would report an address space as seen that was not.
    /// How large the address space is and how much of it was examined are
    /// different questions, and this answers the second.
    pub regions_seen: u64,
    /// How many were passed over, by reason.
    pub skipped: SkipTally,
    /// How many were worth reading.
    pub regions_interesting: u64,
    /// How many were read.
    pub regions_read: u64,
    /// How many could not be read.
    pub regions_refused: u64,
    /// How many were left unread because the process's byte budget ran out.
    pub regions_over_budget: u64,
    /// How many were read only to the per-region cap.
    pub regions_truncated: u64,
    /// How many were read and that the engine declined to judge.
    pub regions_unknown: u64,
    /// Bytes read and examined.
    pub bytes_read: u64,
    /// Bytes of interesting regions that were not examined: refused, over
    /// budget, or past a truncation point.
    pub bytes_unread: u64,
    /// The refused reads, listed up to [`MAX_UNREADABLE_LISTED`].
    pub unreadable: UnreadableRegionList,
    /// The regions that produced a detection.
    pub findings: Vec<MemoryFinding>,
}

impl Default for ProcessOutcome {
    fn default() -> Self {
        Self {
            process: ProcessRef::anonymous(0),
            walk_complete: true,
            deadline_reached: false,
            regions_seen: 0,
            skipped: SkipTally::default(),
            regions_interesting: 0,
            regions_read: 0,
            regions_refused: 0,
            regions_over_budget: 0,
            regions_truncated: 0,
            regions_unknown: 0,
            bytes_read: 0,
            bytes_unread: 0,
            unreadable: UnreadableRegionList::default(),
            findings: Vec::new(),
        }
    }
}

impl ProcessOutcome {
    /// A fresh outcome for a process.
    pub fn new(process: ProcessRef) -> Self {
        Self {
            process,
            ..Self::default()
        }
    }

    /// True when every region of this process that was worth reading was read,
    /// in full, and judged.
    pub const fn is_complete(&self) -> bool {
        self.walk_complete
            && !self.deadline_reached
            && self.regions_refused == 0
            && self.regions_over_budget == 0
            && self.regions_truncated == 0
            && self.regions_unknown == 0
    }

    /// The worst verdict any of this process's regions produced.
    pub fn verdict(&self) -> Verdict {
        worst(self.findings.iter().map(|finding| finding.verdict))
    }

    /// Why this process's scan is incomplete, in sentences.
    pub fn gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        if self.deadline_reached {
            gaps.push(format!(
                "the region walk of {} ran out of time after {} region(s), so the rest of its \
                 address space was not seen at all",
                self.process.label(),
                self.regions_seen
            ));
        } else if !self.walk_complete {
            gaps.push(format!(
                "the region walk of {} stopped at the {} region limit, so its address space \
                 was not seen in full",
                self.process.label(),
                self.regions_seen
            ));
        }
        if self.regions_refused > 0 {
            gaps.push(format!(
                "{} region(s) of {} could not be read, holding {} byte(s) that were never \
                 examined",
                self.regions_refused,
                self.process.label(),
                self.bytes_unread
            ));
        }
        if self.regions_over_budget > 0 {
            gaps.push(format!(
                "{} region(s) of {} were left unread when the byte budget for the process ran out",
                self.regions_over_budget,
                self.process.label()
            ));
        }
        if self.regions_truncated > 0 {
            gaps.push(format!(
                "{} region(s) of {} were read only to the per-region cap",
                self.regions_truncated,
                self.process.label()
            ));
        }
        if self.regions_unknown > 0 {
            gaps.push(format!(
                "{} region(s) of {} were read and the engine declined to judge them",
                self.regions_unknown,
                self.process.label()
            ));
        }
        gaps
    }
}

/// What happened to one process.
///
/// An enum rather than a struct with an optional refusal, so that a process
/// cannot be recorded as both refused and examined. That state would make the
/// report's arithmetic meaningless, and the type is the cheapest place to make
/// it unrepresentable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ProcessScan {
    /// The process was never examined.
    Refused {
        /// The process.
        process: ProcessRef,
        /// Why it was not examined.
        reason: RefusalReason,
    },
    /// The process's regions were walked and the interesting ones read.
    Examined(Box<ProcessOutcome>),
}

impl ProcessScan {
    /// The process this is about.
    pub fn process(&self) -> &ProcessRef {
        match self {
            ProcessScan::Refused { process, .. } => process,
            ProcessScan::Examined(outcome) => &outcome.process,
        }
    }

    /// The outcome, when the process was examined.
    pub fn outcome(&self) -> Option<&ProcessOutcome> {
        match self {
            ProcessScan::Refused { .. } => None,
            ProcessScan::Examined(outcome) => Some(outcome),
        }
    }

    /// Why the process was refused, when it was.
    pub fn refusal(&self) -> Option<&RefusalReason> {
        match self {
            ProcessScan::Refused { reason, .. } => Some(reason),
            ProcessScan::Examined(_) => None,
        }
    }
}

/// Everything a scan found, and everything it could not look at.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemoryScanReport {
    /// One entry per process the caller asked about, in the order asked.
    pub results: Vec<ProcessScan>,
}

impl MemoryScanReport {
    /// An empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one process's result.
    pub fn record(&mut self, scan: ProcessScan) {
        self.results.push(scan);
    }

    /// Add a process that could not be examined.
    pub fn record_refusal(&mut self, process: ProcessRef, error: &MemoryError) {
        self.record(ProcessScan::Refused {
            process,
            reason: RefusalReason::from_error(error),
        });
    }

    /// Every finding, in process order and then address order.
    pub fn findings(&self) -> impl Iterator<Item = &MemoryFinding> {
        self.results
            .iter()
            .filter_map(ProcessScan::outcome)
            .flat_map(|outcome| outcome.findings.iter())
    }

    /// The worst verdict across every process.
    pub fn verdict(&self) -> Verdict {
        worst(self.findings().map(|finding| finding.verdict))
    }

    /// The totals, folded from the per-process outcomes.
    ///
    /// Computed rather than accumulated as the scan runs, so there is one place
    /// the arithmetic lives and a test can check it against a report built by
    /// hand. A stored total and a computed one can disagree; only the computed
    /// one can be wrong in a way a test catches.
    pub fn summary(&self) -> MemorySummary {
        let mut summary = MemorySummary::default();
        for result in &self.results {
            summary.processes_seen = summary.processes_seen.saturating_add(1);
            match result {
                ProcessScan::Refused { reason, .. } => match reason {
                    RefusalReason::AccessDenied { .. } => {
                        summary.refused_denied = summary.refused_denied.saturating_add(1);
                    }
                    RefusalReason::Gone => {
                        summary.refused_gone = summary.refused_gone.saturating_add(1);
                    }
                    RefusalReason::RegionsUnavailable { .. } => {
                        summary.refused_unreadable = summary.refused_unreadable.saturating_add(1);
                    }
                },
                ProcessScan::Examined(outcome) => {
                    summary.processes_examined = summary.processes_examined.saturating_add(1);
                    summary.regions_seen =
                        summary.regions_seen.saturating_add(outcome.regions_seen);
                    summary.skipped.add(&outcome.skipped);
                    summary.regions_interesting = summary
                        .regions_interesting
                        .saturating_add(outcome.regions_interesting);
                    summary.regions_read =
                        summary.regions_read.saturating_add(outcome.regions_read);
                    summary.regions_refused = summary
                        .regions_refused
                        .saturating_add(outcome.regions_refused);
                    summary.regions_over_budget = summary
                        .regions_over_budget
                        .saturating_add(outcome.regions_over_budget);
                    summary.regions_truncated = summary
                        .regions_truncated
                        .saturating_add(outcome.regions_truncated);
                    summary.regions_unknown = summary
                        .regions_unknown
                        .saturating_add(outcome.regions_unknown);
                    summary.bytes_read = summary.bytes_read.saturating_add(outcome.bytes_read);
                    summary.bytes_unread =
                        summary.bytes_unread.saturating_add(outcome.bytes_unread);
                    summary.findings = summary
                        .findings
                        .saturating_add(outcome.findings.len() as u64);
                    if !outcome.walk_complete {
                        summary.walks_incomplete = summary.walks_incomplete.saturating_add(1);
                    }
                    let verdict = outcome.verdict();
                    if verdict == Verdict::Malicious {
                        summary.worst = Verdict::Malicious;
                    } else if verdict == Verdict::Suspicious && summary.worst != Verdict::Malicious
                    {
                        summary.worst = Verdict::Suspicious;
                    }
                }
            }
        }
        summary
    }
}

/// The totals of a scan, and the question a caller must ask before printing a
/// clean verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySummary {
    /// Processes the scan was told about.
    pub processes_seen: u64,
    /// Processes whose regions were walked.
    pub processes_examined: u64,
    /// Processes Windows refused a handle to.
    pub refused_denied: u64,
    /// Processes that exited before they could be opened.
    pub refused_gone: u64,
    /// Processes whose regions could not be walked.
    pub refused_unreadable: u64,
    /// Regions the walks produced.
    pub regions_seen: u64,
    /// Regions passed over, by reason.
    pub skipped: SkipTally,
    /// Regions worth reading.
    pub regions_interesting: u64,
    /// Regions read.
    pub regions_read: u64,
    /// Regions that could not be read.
    pub regions_refused: u64,
    /// Regions left unread when a process's byte budget ran out.
    pub regions_over_budget: u64,
    /// Regions read only to the per-region cap.
    pub regions_truncated: u64,
    /// Regions the engine declined to judge.
    pub regions_unknown: u64,
    /// Processes whose region walk stopped at the caller's limit, so their
    /// address space was not seen in full.
    ///
    /// The only completeness term with no region counter of its own: a walk
    /// that stopped early is a failure to *find* regions rather than a failure
    /// to read them, and the regions it never reached are not in any of the
    /// other counts because nobody knows they exist.
    pub walks_incomplete: u64,
    /// Bytes read and examined.
    pub bytes_read: u64,
    /// Bytes of interesting regions that were never examined.
    pub bytes_unread: u64,
    /// Findings recorded.
    pub findings: u64,
    /// The worst verdict found.
    pub worst: Verdict,
}

impl MemorySummary {
    /// The worst verdict any of the scan's processes produced.
    ///
    /// The same value as [`MemoryScanReport::verdict`], from the folded totals
    /// rather than from the report.
    pub const fn verdict(&self) -> Verdict {
        self.worst
    }

    /// Processes that exist and could not be looked at, for any reason.
    ///
    /// Excludes the ones that had already ended — see
    /// [`MemorySummary::processes_gone`] — because those two are different
    /// facts about a machine and only one of them is about the machine.
    pub const fn processes_refused(&self) -> u64 {
        self.refused_denied.saturating_add(self.refused_unreadable)
    }

    /// Processes that had ended by the time the scan reached them.
    ///
    /// Counted, and not counted against the scan. A whole-machine memory scan
    /// opens processes one after another and a live machine ends some while it
    /// works; a report that treated that as a hole would call every scan of
    /// every machine incomplete, and a caller gating "clean" on
    /// [`MemorySummary::is_complete`] could never print it. The count is kept
    /// anyway, because a scan of two hundred processes and a scan of two
    /// hundred and fifty of which fifty ended first are different amounts of
    /// work and a reader is entitled to know which happened.
    pub const fn processes_gone(&self) -> u64 {
        self.refused_gone
    }

    /// True when the scan examined everything it was asked to examine, in full.
    ///
    /// The one question a caller must answer before describing a result as
    /// clean. Every term is a way the scan could have looked at less than it
    /// appears to, and every term has exactly one sentence of its own in
    /// [`MemorySummary::gaps`]: a refused process, an address space whose walk
    /// stopped early, an unread region, a region past the byte budget, a region
    /// read only to a cap, and a region the engine would not judge.
    ///
    /// The two lists are kept in step by hand, and the tests check them against
    /// each other in both directions, because the one thing worse than a scan
    /// that could not see everything is a scan that says it could.
    ///
    /// A process that had already ended is deliberately not a term here. It has
    /// no regions to examine, so there is nothing the scan failed to look at.
    pub const fn is_complete(&self) -> bool {
        self.processes_refused() == 0
            && self.walks_incomplete == 0
            && self.regions_refused == 0
            && self.regions_over_budget == 0
            && self.regions_truncated == 0
            && self.regions_unknown == 0
    }

    /// Every reason this scan cannot claim completeness, in sentences suitable
    /// for a report.
    ///
    /// Empty exactly when [`MemorySummary::is_complete`] is true, which the
    /// tests check in both directions — a `gaps` that could disagree with
    /// `is_complete` would be a report that contradicts itself.
    ///
    /// A process that exited before it could be opened is *not* listed here,
    /// because it is not a gap in the claim: a memory scan claims something
    /// about what is running, and a process that has ended is not running. It is
    /// still counted, in [`MemorySummary::processes_gone`], because a report
    /// that hid it would leave a reader unable to tell a scan of two hundred
    /// processes from a scan of two hundred and fifty of which fifty ended
    /// first.
    pub fn gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        if self.refused_denied > 0 {
            gaps.push(format!(
                "{} process(es) could not be opened: Windows refused a handle, so nothing in \
                 them was examined",
                self.refused_denied
            ));
        }
        if self.refused_unreadable > 0 {
            gaps.push(format!(
                "{} process(es) were opened but their regions could not be walked",
                self.refused_unreadable
            ));
        }
        if self.walks_incomplete > 0 {
            gaps.push(format!(
                "{} process(es) had their region walk stopped at the limit, so their address \
                 space was not seen in full",
                self.walks_incomplete
            ));
        }
        if self.regions_refused > 0 {
            gaps.push(format!(
                "{} region(s) could not be read, holding {} byte(s) that were never examined",
                self.regions_refused, self.bytes_unread
            ));
        }
        if self.regions_over_budget > 0 {
            gaps.push(format!(
                "{} region(s) were left unread when a process's byte budget ran out",
                self.regions_over_budget
            ));
        }
        if self.regions_truncated > 0 {
            gaps.push(format!(
                "{} region(s) were read only to the per-region cap",
                self.regions_truncated
            ));
        }
        if self.regions_unknown > 0 {
            gaps.push(format!(
                "{} region(s) were read and the engine declined to judge them",
                self.regions_unknown
            ));
        }
        gaps
    }
}

/// The worst of a sequence of verdicts.
///
/// `Verdict` has no ordering of its own — `Unknown` is deliberately not
/// comparable with the others, because "we could not tell" is not between clean
/// and suspicious — so the fold is written out. `Unknown` never outranks a
/// detection: a scan that found something found something even if another
/// process could not be judged.
fn worst(verdicts: impl Iterator<Item = Verdict>) -> Verdict {
    let mut worst = Verdict::Clean;
    for verdict in verdicts {
        match verdict {
            Verdict::Malicious => return Verdict::Malicious,
            Verdict::Suspicious => worst = Verdict::Suspicious,
            Verdict::Clean | Verdict::Unknown => {}
        }
    }
    worst
}

/// Attribute a detection to the region it was found in.
///
/// The region is `process:address`, and it goes in the same field the archive
/// walk uses for a member name. A detection that already carries a container
/// was found inside something *within* the region — an archive member, if a
/// caller turned archive scanning on — and keeps its own name with the region
/// in front of it, joined the way the archive chain is joined. So a match in a
/// member of a zip that a process was holding reads
/// `explorer.exe:0x7ff6a1b20000/payload/inner.exe`, and the offset under it is
/// an offset into that member.
///
/// [`av_core::Detection::within`] is not used here because it replaces a
/// container rather than nesting one, which would drop the member name and
/// point a reader at the region instead of at the thing inside it.
///
/// The source is set to [`DetectionSource::Memory`] here as well, and that is
/// the only place it can honestly be set. The engine builds a rule match as
/// [`DetectionSource::Signature`] because the engine is handed bytes and a path
/// and cannot know what produced them; whether those bytes came off a disk or
/// out of a live process is knowledge that exists only in this crate, at the
/// call site that read the region. Leaving it as `Signature` would be wrong in
/// two directions at once: it would tell a report that a process matched a
/// signature on a file when no file was involved, and it would make the
/// detection look like the kind of evidence that code-signing can clear —
/// [`av_scan::trust::is_generic`] returns `false` for `Memory` and `true` for a
/// low-severity `Signature`, so the label decides whether a signed binary's
/// recommendation survives. It should not: a valid signature says a file on
/// disk is what it claims to be and says nothing about what a process has since
/// written into its own address space.
pub fn attribute(detection: &Detection, region: &str) -> Detection {
    let mut attributed = detection.clone();
    attributed.source = DetectionSource::Memory;
    for location in &mut attributed.locations {
        location.container = Some(prefixed(region, location.container.as_deref()));
    }
    attributed.container = Some(prefixed(region, attributed.container.as_deref()));
    attributed
}

/// Join a region and an inner container the way the archive chain joins names.
fn prefixed(region: &str, inner: Option<&str>) -> String {
    match inner {
        Some(inner) if !inner.is_empty() => format!("{region}/{inner}"),
        _ => region.to_string(),
    }
}

/// Scanning whole machines rather than one source at a time.
///
/// Separate from the rest of the scanner because it is the only part that opens
/// processes, and because the two answers it can give are different in kind: a
/// list of processes is a list, and a list that could not be produced is not.
#[cfg(windows)]
impl MemoryScanner<'_> {
    /// Scan a list of processes, one after another.
    ///
    /// Each process that cannot be opened becomes a refusal in the report rather
    /// than an error, because on a real machine most of them cannot — measured,
    /// 151 to 155 of 270 to 296. A caller that had to handle an error per
    /// process would end up writing `let _ = ...` and losing the count, which is
    /// exactly the count the report exists to carry.
    ///
    /// Sequential. A scan of a machine is dominated by the region walks and the
    /// reads, both of which are kernel calls that a second thread would contend
    /// on rather than overlap; a caller that wants parallelism should split the
    /// list and scan the halves concurrently, which `Win32Source` supports —
    /// see the `Send` note on its handle.
    pub fn scan_processes(&self, processes: &[ProcessRef]) -> MemoryScanReport {
        let mut report = MemoryScanReport::new();
        for process in processes {
            match crate::source::Win32Source::open(process.clone()) {
                Ok(mut source) => report.record(self.scan_process(&mut source)),
                Err(error) => {
                    log::debug!("{}: {error}", process.describe());
                    report.record_refusal(process.clone(), &error);
                }
            }
        }
        report
    }

    /// Scan every process on the machine.
    ///
    /// The one function here that returns an error, and deliberately: a report
    /// with no results is the same value whether the machine had no processes or
    /// the enumeration failed, and a caller that could not tell those apart
    /// would print "nothing found" for a scan that never happened.
    pub fn scan_running_processes(&self) -> crate::error::Result<MemoryScanReport> {
        let processes = crate::process::list_processes()?;
        Ok(self.scan_processes(&processes))
    }
}

/// The engine, the configuration, and the scan itself.
#[derive(Debug)]
pub struct MemoryScanner<'a> {
    engine: &'a ScanEngine,
    config: MemoryScanConfig,
}

impl<'a> MemoryScanner<'a> {
    /// A scanner over a rule set.
    pub const fn new(engine: &'a ScanEngine, config: MemoryScanConfig) -> Self {
        Self { engine, config }
    }

    /// The configuration in use.
    pub const fn config(&self) -> &MemoryScanConfig {
        &self.config
    }

    /// Scan one process.
    ///
    /// Returns a refusal rather than an outcome when the process could not be
    /// looked at at all, so that a caller cannot accidentally treat an
    /// unexamined process as an examined one.
    pub fn scan_process(&self, source: &mut dyn MemorySource) -> ProcessScan {
        let process = source.process().clone();
        let walk = match source.regions(self.config.max_regions) {
            Ok(walk) => walk,
            Err(error) => {
                log::debug!("{}: {error}", process.describe());
                return ProcessScan::Refused {
                    process,
                    reason: RefusalReason::from_error(&error),
                };
            }
        };
        ProcessScan::Examined(Box::new(self.scan_walk(&process, source, walk)))
    }

    /// Read and judge the regions a walk produced.
    ///
    /// Split from [`MemoryScanner::scan_process`] so that the arithmetic below
    /// can be exercised with a walk that was built by hand rather than one that
    /// came from a process.
    fn scan_walk(
        &self,
        process: &ProcessRef,
        source: &mut dyn MemorySource,
        walk: RegionWalk,
    ) -> ProcessOutcome {
        let mut outcome = ProcessOutcome::new(process.clone());
        outcome.walk_complete = walk.complete;
        outcome.regions_seen = walk.regions.len() as u64;
        let mut budget = self.config.max_total_bytes;
        // One scanner for the whole process, not one per region. Building one
        // allocates the rule engine's working state, and a process with a
        // hundred interesting regions would otherwise pay for it a hundred
        // times; the engine's own documentation asks callers to do it this way.
        let mut scanner = self.engine.scanner();
        // Started here rather than at the top of the walk so that the budget
        // covers the reading and judging and not the enumeration, which is a
        // fixed cost the caller cannot influence. See
        // [`MemoryScanConfig::deadline`].
        let started = Instant::now();
        // How far into the walk this got. The walk hands over `walk.regions`;
        // a deadline can stop before the end of them, and `regions_seen`
        // reports this rather than the size of the walk — see its
        // documentation for why the two readings must not be confused.
        let mut reached: u64 = 0;

        for region in &walk.regions {
            // Checked before the region is judged rather than after it is read:
            // an over-deadline scan should stop having decided nothing about
            // this region, not read it and then discover there was no time.
            if let Some(limit) = self.config.deadline {
                if started.elapsed() >= limit {
                    outcome.walk_complete = false;
                    outcome.deadline_reached = true;
                    outcome.regions_seen = reached;
                    break;
                }
            }
            reached = reached.saturating_add(1);
            let interest = match classify(region, self.config.min_region_bytes) {
                RegionInterest::PassedOver(skip) => {
                    outcome.skipped.record(skip);
                    continue;
                }
                RegionInterest::Interesting(interest) => interest,
            };
            outcome.regions_interesting = outcome.regions_interesting.saturating_add(1);

            // Never more than the region holds: a read that crosses the end of
            // a region fails wholesale, so asking for more could only turn a
            // readable region into a refused one.
            let wanted = region.size.min(self.config.max_region_bytes);
            if wanted as u64 > budget {
                outcome.regions_over_budget = outcome.regions_over_budget.saturating_add(1);
                outcome.bytes_unread = outcome.bytes_unread.saturating_add(region.size as u64);
                continue;
            }
            let truncated = wanted < region.size;

            match source.read(region.base, wanted) {
                // A source that returned a short buffer is not trusted to have
                // read what it was asked for. The buffer the engine would judge
                // would be a different one from the region, so the region is
                // recorded as unread rather than scanned.
                Ok(bytes) if bytes.len() != wanted => {
                    let error = MemoryError::ReadRefused {
                        pid: process.pid,
                        address: region.base,
                        length: wanted,
                        code: crate::error::ERROR_PARTIAL_COPY,
                        message: format!("the read returned {} of {wanted} bytes", bytes.len()),
                    };
                    outcome.record_unreadable(region.base, region.size, error);
                    outcome.bytes_unread = outcome.bytes_unread.saturating_add(region.size as u64);
                }
                Ok(bytes) => {
                    budget = budget.saturating_sub(wanted as u64);
                    outcome.regions_read = outcome.regions_read.saturating_add(1);
                    outcome.bytes_read = outcome.bytes_read.saturating_add(bytes.len() as u64);
                    if truncated {
                        outcome.regions_truncated = outcome.regions_truncated.saturating_add(1);
                        outcome.bytes_unread = outcome
                            .bytes_unread
                            .saturating_add((region.size - wanted) as u64);
                    }
                    // The path the engine is given is synthetic, because a
                    // region's address is not a path and the engine's path-based
                    // stage (trust) is off for a memory scan. It is built from
                    // the same string the finding is attributed to, so a log
                    // line about this buffer names the region a reader can find
                    // it by. Where the bytes actually came from is a separate
                    // question, asked below and carried on the finding — the
                    // engine has no use for it and must not: a rule that fired
                    // on an image would otherwise be scored against the file it
                    // was mapped from, which is a file scan's job.
                    let container = process.container(region.base);
                    let report = self.engine.scan_with(
                        &mut scanner,
                        Path::new(&container),
                        &bytes,
                        &self.config.options,
                    );
                    // Asked once per region that was read, and after the scan
                    // rather than before it: the question costs a call into the
                    // kernel, a clean machine has hundreds of read regions and
                    // no findings, and the answer is only kept for a finding —
                    // but it is asked for every read region rather than only for
                    // a detected one so that `record_report` has one shape
                    // instead of two, and so that a later change to what counts
                    // as a finding cannot silently lose it.
                    let origin = source.backing_file(region.base);
                    outcome.record_report(
                        RegionObservation {
                            region,
                            bytes: &bytes,
                            truncated,
                            interest,
                            container: &container,
                            origin,
                        },
                        &report,
                    );
                }
                Err(error) => {
                    outcome.record_unreadable(region.base, region.size, error);
                    outcome.bytes_unread = outcome.bytes_unread.saturating_add(region.size as u64);
                }
            }
        }

        log::debug!(
            "{}: {} regions, {} interesting, {} read, {} refused, {} bytes, {} finding(s)",
            process.label(),
            outcome.regions_seen,
            outcome.regions_interesting,
            outcome.regions_read,
            outcome.regions_refused,
            outcome.bytes_read,
            outcome.findings.len()
        );
        outcome
    }
}

/// One region the scanner read, and everything it established about where the
/// bytes in it came from.
///
/// The six facts live in one value rather than in six parameters because they
/// are all answers about the *same* read: they are produced together in the
/// scan loop and consumed together here, and passing them separately is a
/// signature in which a caller can hand the findings of one region a container
/// belonging to another, which is a misattribution no test would notice.
///
/// Not named `RegionRead`: that name is taken by the public enum in
/// [`crate::region`], which is the *result* of a read rather than the set of
/// facts gathered around one.
struct RegionObservation<'a> {
    /// The region the bytes were taken from.
    region: &'a crate::region::MemoryRegion,
    /// The bytes, never more than the region holds.
    bytes: &'a [u8],
    /// True when only the head of the region was read.
    truncated: bool,
    /// Why the region was read at all.
    interest: Interest,
    /// The synthetic path a finding from this region is attributed to.
    container: &'a str,
    /// The file the address is backed by, as far as the kernel would say.
    origin: Origin,
}

impl ProcessOutcome {
    /// Record what the engine concluded about one region it was given.
    ///
    /// Takes the report rather than the engine so that the recording is plain
    /// logic a test can drive with a report built by hand, and so that the
    /// engine call — and the scanner it needs — stays in one place.
    fn record_report(&mut self, read: RegionObservation<'_>, report: &FileScanReport) {
        let RegionObservation {
            region,
            bytes,
            truncated,
            interest,
            container,
            origin,
        } = read;
        if report.verdict() == Verdict::Unknown {
            // The engine would not judge this region. That is a hole in the
            // scan and is counted as one; it is not a finding, and it is not
            // an absence of one either.
            self.regions_unknown = self.regions_unknown.saturating_add(1);
            return;
        }
        if !report.verdict().is_detection() {
            // Read, judged, and nothing found. This is the answer the whole
            // scan exists to be able to give, and it is only ever given when
            // the read succeeded.
            return;
        }

        let detections: Vec<Detection> = report
            .assessment
            .detections
            .iter()
            .map(|detection| attribute(detection, container))
            .collect();

        self.findings.push(MemoryFinding {
            process: self.process.clone(),
            base: region.base,
            region_size: region.size,
            bytes_read: bytes.len(),
            truncated,
            interest,
            protection: region.protection,
            kind: region.kind,
            origin,
            verdict: report.verdict(),
            score: report.assessment.score,
            detections,
        });
    }

    /// Count and list a region that could not be read.
    fn record_unreadable(&mut self, base: usize, size: usize, error: MemoryError) {
        self.regions_refused = self.regions_refused.saturating_add(1);
        if self.unreadable.listed.len() < MAX_UNREADABLE_LISTED {
            self.unreadable
                .listed
                .push(UnreadableRegion { base, size, error });
        } else {
            self.unreadable.omitted = self.unreadable.omitted.saturating_add(1);
        }
    }
}

impl SkipTally {
    /// Fold another tally into this one.
    fn add(&mut self, other: &SkipTally) {
        self.not_committed = self.not_committed.saturating_add(other.not_committed);
        self.too_small = self.too_small.saturating_add(other.too_small);
        self.guard = self.guard.saturating_add(other.guard);
        self.not_readable = self.not_readable.saturating_add(other.not_readable);
        self.not_executable = self.not_executable.saturating_add(other.not_executable);
        self.backed_by_file = self.backed_by_file.saturating_add(other.backed_by_file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::{MemoryRegion, Protection, RegionKind, RegionState};
    use crate::source::fake::{FakeSource, ScriptedRegion};
    use av_core::{Assessment, DetectionSource, Digests, FileKind, MatchLocation, Severity};
    use av_rules::database::RuleDatabase;

    fn region(base: usize, size: usize, protection: u32, kind: RegionKind) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            state: RegionState::Committed,
            protection: Protection::from_raw(protection),
            kind,
        }
    }

    /// A committed, private, executable region — the shape the scan is for.
    fn injectable(base: usize, size: usize) -> MemoryRegion {
        region(base, size, 0x20, RegionKind::Private)
    }

    /// A committed, read-write, non-executable region — a heap.
    fn heap(base: usize, size: usize) -> MemoryRegion {
        region(base, size, 0x04, RegionKind::Private)
    }

    fn scripted(region: MemoryRegion, contents: &[u8]) -> ScriptedRegion {
        let mut bytes = contents.to_vec();
        bytes.resize(region.size, 0);
        ScriptedRegion {
            region,
            contents: Ok(bytes),
        }
    }

    fn refused(region: MemoryRegion) -> ScriptedRegion {
        ScriptedRegion {
            region,
            contents: Err(MemoryError::ReadRefused {
                pid: 10,
                address: region.base,
                length: region.size,
                code: crate::error::ERROR_ACCESS_DENIED,
                message: "Access is denied.".into(),
            }),
        }
    }

    /// An engine with one rule that matches `marker`.
    fn engine(marker: &str) -> ScanEngine {
        let source = format!(
            r#"
rule test_injected_marker {{
    meta:
        severity = "high"
        description = "a marker this test planted"
    strings:
        $a = "{marker}"
    condition:
        $a
}}
"#
        );
        let (database, report) = RuleDatabase::compile(&source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        assert_eq!(database.len(), 1, "the fixture rule must actually compile");
        ScanEngine::new(database)
    }

    /// A report from an engine that declined to judge a region.
    fn unknown_report(reason: &str) -> FileScanReport {
        FileScanReport {
            path: std::path::PathBuf::from("pid 1:0x1000"),
            kind: FileKind::Unknown,
            size: 4096,
            digests: Digests::default(),
            assessment: Assessment::unknown(reason),
            duration: std::time::Duration::ZERO,
            scanned_bytes: 0,
            from_cache: false,
            error: Some(reason.to_string()),
            archive: None,
        }
    }

    #[test]
    fn a_refused_read_is_not_a_region_that_held_nothing() {
        // The bug this crate exists to avoid. Two regions: one read and clean,
        // one refused. A scanner that collapsed the second into the first would
        // report the same numbers as a scanner that read both and found
        // nothing, and would then call the process clean.
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            10,
            vec![
                scripted(injectable(0x1000, 4096), b"nothing here"),
                refused(injectable(0x2000, 4096)),
            ],
        );

        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };

        assert_eq!(outcome.regions_interesting, 2);
        assert_eq!(outcome.regions_read, 1, "one region was read");
        assert_eq!(outcome.regions_refused, 1, "one region was not");
        assert_eq!(outcome.bytes_read, 4096, "only the readable region counted");
        assert_eq!(
            outcome.bytes_unread, 4096,
            "the refused region's bytes are unaccounted for"
        );
        assert_eq!(outcome.unreadable.listed.len(), 1);
        assert_eq!(outcome.unreadable.listed[0].base, 0x2000);
        assert!(outcome.findings.is_empty());

        // And the report refuses to call the result complete, which is the
        // point of keeping the two apart.
        assert!(!outcome.is_complete());
        let mut report = MemoryScanReport::new();
        report.record(ProcessScan::Examined(outcome));
        let summary = report.summary();
        assert!(!summary.is_complete());
        assert_eq!(summary.verdict(), Verdict::Clean);
        assert!(
            summary
                .gaps()
                .iter()
                .any(|gap| gap.contains("could not be read")),
            "{:?}",
            summary.gaps()
        );
    }

    #[test]
    fn a_region_that_was_read_and_held_nothing_is_counted_as_read() {
        // The other half of the pair above. Same shape of process, no refusal,
        // and the report is willing to say the scan was complete.
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            10,
            vec![
                scripted(injectable(0x1000, 4096), b"nothing here"),
                scripted(injectable(0x2000, 4096), b"nor here"),
            ],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.regions_read, 2);
        assert_eq!(outcome.regions_refused, 0);
        assert_eq!(outcome.bytes_read, 8192);
        assert_eq!(outcome.bytes_unread, 0);
        assert!(outcome.findings.is_empty());
        assert!(outcome.is_complete(), "{:?}", outcome.gaps());
    }

    #[test]
    fn the_arithmetic_of_an_outcome_balances() {
        // The arithmetic of an outcome, over a script chosen so that every
        // counter has something in it.
        let engine = engine("WENLE-NEVER-PRESENT");
        let mut source = FakeSource::named(
            "mixed.exe",
            10,
            vec![
                // Passed over, one of each reason that a plausible region can
                // produce.
                ScriptedRegion {
                    region: {
                        let mut r = heap(0x1000, 4096);
                        r.state = RegionState::Reserved;
                        r
                    },
                    contents: Ok(vec![0; 4096]),
                },
                scripted(heap(0x2000, 4096), b"heap"),
                scripted(region(0x3000, 4096, 0x20, RegionKind::Image), b"image code"),
                scripted(
                    region(0x4000, 4096, 0x04 | Protection::GUARD, RegionKind::Private),
                    b"g",
                ),
                scripted(
                    region(0x5000, 4096, 0x10, RegionKind::Private),
                    b"execute only",
                ),
                scripted(region(0x6000, 8, 0x20, RegionKind::Private), b"tiny"),
                // Interesting, and each of the four fates: read, refused, read
                // to a cap, and left unread when the budget ran out. The order
                // matters — the budget is spent in address order, so the region
                // the budget cannot reach has to come last.
                scripted(injectable(0x7000, 4096), b"read and clean"),
                refused(injectable(0x8000, 4096)),
                scripted(injectable(0x9000, 8192), b"half read"),
                scripted(injectable(0xa000, 4096), b"past the budget"),
            ],
        );
        // Two regions' worth of budget for three readable regions, so the last
        // one is deferred and the middle one is cut off at the cap. A refused
        // read spends none of it: nothing was read, so nothing was examined.
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                max_region_bytes: 4096,
                max_total_bytes: 8192,
                ..MemoryScanConfig::default()
            },
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };

        assert_eq!(outcome.regions_seen, 10);
        assert_eq!(
            outcome.regions_seen,
            outcome.regions_interesting + outcome.skipped.total(),
            "{outcome:?}"
        );
        assert_eq!(
            outcome.regions_interesting,
            outcome.regions_read + outcome.regions_refused + outcome.regions_over_budget,
            "{outcome:?}"
        );
        assert_eq!(outcome.skipped.not_committed, 1);
        assert_eq!(outcome.skipped.not_executable, 1, "the heap");
        assert_eq!(outcome.skipped.backed_by_file, 1, "the image section");
        assert_eq!(outcome.skipped.guard, 1);
        assert_eq!(outcome.skipped.not_readable, 1, "execute-only");
        assert_eq!(outcome.skipped.too_small, 1);
        assert_eq!(outcome.regions_interesting, 4);
        assert_eq!(outcome.regions_read, 2, "the budget covered two regions");
        assert_eq!(outcome.regions_refused, 1);
        assert_eq!(outcome.regions_truncated, 1, "the 8192-byte region");
        assert_eq!(outcome.regions_over_budget, 1);
        assert_eq!(
            outcome.unreadable.listed.len() as u64 + outcome.unreadable.omitted,
            outcome.regions_refused
        );
        assert_eq!(outcome.bytes_read, 8192);
        // The refused region's 4096 bytes, the 4096 the cap left of the
        // truncated one, and the 4096 the budget could not reach.
        assert_eq!(outcome.bytes_unread, 12_288);
        assert!(!outcome.is_complete());
    }

    #[test]
    fn summary_totals_add_up_across_processes() {
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());

        let mut report = MemoryScanReport::new();
        report.record(ProcessScan::Refused {
            process: ProcessRef::anonymous(4),
            reason: RefusalReason::AccessDenied {
                code: crate::error::ERROR_ACCESS_DENIED,
                message: "Access is denied.".into(),
            },
        });
        report.record(ProcessScan::Refused {
            process: ProcessRef::anonymous(9),
            reason: RefusalReason::Gone,
        });
        let mut a = FakeSource::named("a.exe", 11, vec![scripted(injectable(0x1000, 4096), b"x")]);
        report.record(scanner.scan_process(&mut a));
        let mut b = FakeSource::named("b.exe", 12, vec![refused(injectable(0x1000, 4096))]);
        report.record(scanner.scan_process(&mut b));

        let summary = report.summary();
        assert_eq!(summary.processes_seen, 4);
        assert_eq!(summary.processes_examined, 2);
        assert_eq!(summary.processes_refused(), 1);
        assert_eq!(summary.processes_gone(), 1);
        assert_eq!(
            summary.processes_examined + summary.processes_refused() + summary.processes_gone(),
            summary.processes_seen,
            "every process is either examined, refused or already gone, and the totals must \
             say which"
        );
        assert_eq!(summary.refused_denied, 1);
        assert_eq!(summary.refused_gone, 1);
        assert_eq!(summary.refused_unreadable, 0);
        assert_eq!(summary.regions_seen, 2);
        assert_eq!(summary.regions_read, 1);
        assert_eq!(summary.regions_refused, 1);
        assert_eq!(summary.bytes_read, 4096);
        assert_eq!(summary.regions_interesting, 2);
        // Both walks reached the end of their address spaces. What makes this
        // scan incomplete is the region b.exe would not hand over, not a walk
        // that stopped short — and the two are counted apart so that a report
        // can say which happened.
        assert_eq!(summary.walks_incomplete, 0);
        assert!(!summary.is_complete());
        assert!(!summary.gaps().is_empty());
        assert!(
            summary
                .gaps()
                .iter()
                .any(|gap| gap.contains("could not be read")),
            "{:?}",
            summary.gaps()
        );
    }

    #[test]
    fn a_complete_scan_has_no_gaps_and_an_incomplete_one_always_does() {
        // The two must agree in both directions. A `gaps` list that could be
        // empty while `is_complete` is false would be a report that tells a user
        // nothing is missing while knowing otherwise.
        let mut summary = MemorySummary::default();
        assert!(summary.is_complete());
        assert!(summary.gaps().is_empty());

        let manglers: [fn(&mut MemorySummary); 7] = [
            |s| s.refused_denied = 1,
            |s| s.refused_unreadable = 1,
            |s| s.regions_refused = 1,
            |s| s.regions_over_budget = 1,
            |s| s.regions_truncated = 1,
            |s| s.regions_unknown = 1,
            |s| s.walks_incomplete = 1,
        ];
        for mangle in manglers {
            let mut broken = MemorySummary::default();
            mangle(&mut broken);
            assert!(!broken.is_complete(), "{broken:?}");
            assert!(!broken.gaps().is_empty(), "{broken:?}");
        }

        // A process that exited mid-scan is counted but is *not* a gap in the
        // coverage claim: a memory scan claims something about what is running,
        // and a process that has ended is not running. The count still appears,
        // so a reader can tell a scan of two hundred processes from a scan of
        // two hundred and fifty of which fifty ended first.
        summary.refused_gone = 1;
        assert!(
            summary.is_complete(),
            "an exited process is not a hole in the scan"
        );
        assert!(summary.gaps().is_empty(), "and there is nothing to report");
        assert_eq!(summary.processes_gone(), 1, "but it is still counted");
        assert_eq!(
            summary.processes_refused(),
            0,
            "and it is not counted as a process that refused the scan"
        );
    }

    #[test]
    fn a_region_the_engine_will_not_judge_is_a_hole_and_not_a_clean_region() {
        // `Verdict::Unknown` from the engine means the engine looked and could
        // not conclude — a budget overrun, say. Recording that as a clean region
        // would be the same bug as recording a refused read as a clean one, one
        // layer further in.
        let mut outcome = ProcessOutcome::new(ProcessRef::anonymous(1));
        let region = injectable(0x1000, 4096);
        outcome.record_report(
            RegionObservation {
                region: &region,
                bytes: &[0u8; 4096],
                truncated: false,
                interest: Interest::UnbackedCode,
                container: "pid 1:0x1000",
                origin: Origin::Unknown,
            },
            &unknown_report("the scan exceeded its budget"),
        );
        assert_eq!(outcome.regions_unknown, 1);
        assert!(
            outcome.findings.is_empty(),
            "an unknown verdict is not a finding"
        );
        assert!(!outcome.is_complete());
        assert_eq!(
            outcome.verdict(),
            Verdict::Clean,
            "and not a detection either"
        );
        assert!(
            outcome
                .gaps()
                .iter()
                .any(|g| g.contains("declined to judge")),
            "{:?}",
            outcome.gaps()
        );
    }

    #[test]
    fn a_truncated_region_is_read_but_the_scan_is_not_complete() {
        // Reading the first four kilobytes of a megabyte is not reading the
        // region, and a report that said the region was read would be claiming
        // coverage it does not have.
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                max_region_bytes: 4096,
                ..MemoryScanConfig::default()
            },
        );
        let mut source = FakeSource::named(
            "big.exe",
            10,
            vec![scripted(injectable(0x1000, 64 * 1024), b"x")],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.regions_read, 1);
        assert_eq!(outcome.regions_truncated, 1);
        assert_eq!(outcome.bytes_read, 4096);
        assert_eq!(outcome.bytes_unread, 64 * 1024 - 4096);
        assert!(!outcome.is_complete());
        assert!(
            outcome.gaps().iter().any(|g| g.contains("per-region cap")),
            "{:?}",
            outcome.gaps()
        );
    }

    #[test]
    fn a_walk_that_stopped_at_the_limit_makes_the_scan_incomplete() {
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                max_regions: 2,
                ..MemoryScanConfig::default()
            },
        );
        let mut source = FakeSource::named(
            "wide.exe",
            10,
            vec![
                scripted(injectable(0x1000, 4096), b"a"),
                scripted(injectable(0x2000, 4096), b"b"),
                scripted(injectable(0x3000, 4096), b"c"),
            ],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(
            source.last_limit, 2,
            "the walk was given the configured limit"
        );
        assert!(!outcome.walk_complete);
        assert_eq!(outcome.regions_seen, 2);
        assert!(!outcome.is_complete());
        assert!(
            outcome.gaps().iter().any(|g| g.contains("region limit")),
            "{:?}",
            outcome.gaps()
        );
    }

    #[test]
    fn a_walk_that_ran_out_of_time_reports_a_deadline_and_not_a_cap() {
        // The two stop reasons need different sentences. A region cap is a
        // property of the process — an address space too large to walk — and a
        // deadline is a property of the caller. Reading the second as the first
        // sends a reader looking for a process with an enormous address space,
        // which is the wrong thing to go and look for.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                deadline: Some(Duration::from_millis(120)),
                ..MemoryScanConfig::default()
            },
        );
        // The marker is in the first region only, so the number of findings is
        // a statement about which regions were read rather than a coincidence.
        let mut script = vec![scripted(
            injectable(0x1000, 4096),
            b"WENLE-INJECTED-MARKER",
        )];
        for index in 1..4 {
            script.push(scripted(
                injectable(0x1000 + index * 0x1000, 4096),
                b"nothing of interest here",
            ));
        }
        let mut source = FakeSource::named("bursty.exe", 10, script);
        // Each read costs 50 ms, so by the fourth region the clock has moved
        // well past 120 ms. Without a cost the whole walk finishes in
        // microseconds and the deadline never fires, which is why the source
        // takes time rather than the test sleeping around it.
        source.read_delay = Some(Duration::from_millis(50));

        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert!(outcome.deadline_reached, "the deadline is what stopped it");
        assert!(!outcome.walk_complete);
        assert!(!outcome.is_complete());
        // Partway, and not zero: the first region is always reached, and four
        // regions cannot be reached in under 120 ms when each read takes 50 ms.
        assert!(
            outcome.regions_seen >= 1 && outcome.regions_seen < 4,
            "the walk stopped partway, at {} of 4 region(s)",
            outcome.regions_seen
        );
        // What was read before the deadline was judged, and its finding is
        // real: a deadline costs the rest of the walk, never the part of it
        // that already happened.
        assert_eq!(
            outcome.findings.len(),
            1,
            "the region holding the marker was read before the clock ran out"
        );
        let gaps = outcome.gaps();
        assert!(
            gaps.iter().any(|gap| gap.contains("ran out of time")),
            "{gaps:?}"
        );
        assert!(
            !gaps.iter().any(|gap| gap.contains("region limit")),
            "a deadline is not a region cap: {gaps:?}"
        );
    }

    #[test]
    fn a_refused_process_is_never_an_examined_one() {
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named("denied.exe", 77, Vec::new());
        source.walk_failure = Some(MemoryError::RegionWalk {
            pid: 77,
            address: 0x1000,
            code: crate::error::ERROR_ACCESS_DENIED,
            message: "Access is denied.".into(),
        });
        let scan = scanner.scan_process(&mut source);
        assert!(scan.outcome().is_none());
        let reason = scan.refusal().expect("a refusal");
        assert_eq!(reason.as_str(), "regions-unavailable");
        assert_eq!(scan.process().pid, 77);

        // And it lands in the right bucket of the totals.
        let mut report = MemoryScanReport::new();
        report.record(scan);
        let summary = report.summary();
        assert_eq!(summary.processes_examined, 0);
        assert_eq!(summary.refused_unreadable, 1);
    }

    #[test]
    fn a_finding_carries_the_file_its_bytes_came_from() {
        // What makes a memory finding actionable: the file behind the region is
        // the thing that has to be dealt with, because killing the process ends
        // the incident only until the file is run again. The source is the only
        // thing that can know, so a finding that did not carry what the source
        // said would leave a caller with an address and no file.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let file = std::path::PathBuf::from(r"C:\Users\me\Downloads\invoice.exe");
        let mut source = FakeSource::named(
            "invoice.exe",
            4321,
            vec![scripted(
                injectable(0x7ff6_c0de_0000, 4096),
                b"\x00\x90WENLE-INJECTED-MARKER\x90\x00",
            )],
        )
        .with_origin(Origin::File { path: file.clone() });

        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(
            outcome.findings[0].origin,
            Origin::File { path: file },
            "the file the source named is not on the finding"
        );
        // Asked once for the one region that was read, and never for a region
        // that was passed over: the question is a call into the kernel and a
        // clean machine has hundreds of regions.
        assert_eq!(source.origins_asked.get(), 1);
    }

    #[test]
    fn a_source_that_cannot_say_where_the_bytes_came_from_says_so() {
        // The distinction the whole module is built around, at the level of the
        // scan: a source with no way to answer must produce `Unknown`, and
        // `Unknown` must never be `Nothing`. `Nothing` is the injected-code
        // shape — the finding a memory scan exists to make — and reporting it
        // for a question that was never answered would be inventing an
        // injection.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            4321,
            vec![scripted(
                injectable(0x7ff6_c0de_0000, 4096),
                b"\x00\x90WENLE-INJECTED-MARKER\x90\x00",
            )],
        );
        assert_eq!(source.origin, Origin::Unknown, "the fake's default");

        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.findings[0].origin, Origin::Unknown);
        assert_ne!(outcome.findings[0].origin, Origin::Nothing);
        assert!(!outcome.findings[0].origin.is_backed_by_a_file());
        assert!(outcome.findings[0].origin.path().is_none());
    }

    #[test]
    fn a_planted_marker_is_attributed_to_the_process_and_the_address() {
        // The end-to-end shape of a memory finding, with the engine and the
        // attribution both real.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            4321,
            vec![
                scripted(injectable(0x7ff6_a1b2_0000, 4096), b"harmless filler"),
                scripted(
                    injectable(0x7ff6_c0de_0000, 4096),
                    b"\x00\x90WENLE-INJECTED-MARKER\x90\x00",
                ),
            ],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.findings.len(), 1);
        let finding = &outcome.findings[0];

        assert_eq!(finding.base, 0x7ff6_c0de_0000);
        assert_eq!(finding.verdict, Verdict::Malicious, "a high-severity rule");
        assert_eq!(finding.interest, Interest::UnbackedCode);
        assert!(!finding.truncated);

        // The attribution: the process and the address, not a path.
        assert_eq!(finding.container(), "victim.exe:0x7ff6c0de0000");
        let detection = &finding.detections[0];
        assert_eq!(detection.rule_id, "test_injected_marker");
        assert_eq!(
            detection.container.as_deref(),
            Some("victim.exe:0x7ff6c0de0000"),
            "the detection carries the attribution the console renders"
        );
        // And the location's offset is an offset into the region, with the
        // region named in front of it.
        assert_eq!(
            detection.locations[0].container.as_deref(),
            Some("victim.exe:0x7ff6c0de0000")
        );
        assert!(detection.locations[0].offset > 0);

        // The source says where the bytes came from, not what matched them. A
        // finding about a live process is the one kind of evidence that
        // code-signing cannot clear, so this label is load-bearing rather than
        // cosmetic — see `attribute`.
        assert_eq!(
            detection.source,
            DetectionSource::Memory,
            "a match in a region is a memory detection, not a signature match on a file"
        );
    }

    #[test]
    fn a_match_inside_an_archive_member_keeps_the_member_name() {
        // A caller that turned archive scanning on for memory regions gets a
        // chain rather than a replacement: the region names where the bytes
        // were, the member names what they were inside.
        let detection = Detection::new(
            "test/inner",
            "a match inside a member",
            Severity::High,
            DetectionSource::Signature,
        )
        .with_location(MatchLocation::new(0, 4, "$a", b"abcd").within("payload/inner.exe"))
        .within("payload/inner.exe");

        let attributed = attribute(&detection, "explorer.exe:0x7ff6a1b20000");
        assert_eq!(
            attributed.container.as_deref(),
            Some("explorer.exe:0x7ff6a1b20000/payload/inner.exe")
        );
        assert_eq!(
            attributed.locations[0].container.as_deref(),
            Some("explorer.exe:0x7ff6a1b20000/payload/inner.exe")
        );
        // The original is untouched: `attribute` copies.
        assert_eq!(detection.container.as_deref(), Some("payload/inner.exe"));
        assert_eq!(
            detection.source,
            DetectionSource::Signature,
            "`attribute` rewrites the copy, never the detection the engine handed it"
        );

        // A detection with no container of its own gets the region alone.
        let plain = Detection::new("test/plain", "d", Severity::Low, DetectionSource::Signature);
        // Before attribution this is exactly the shape trust is allowed to
        // clear: a low-severity signature match on a file that turned out to be
        // signed. The only thing that changes below is where the bytes came
        // from, and that is enough to make it uncleanable — which is the whole
        // reason `attribute` sets the source instead of leaving the engine's.
        assert!(av_scan::trust::is_generic(&plain));
        let plain = attribute(&plain, "a.exe:0x1000");
        assert_eq!(plain.container.as_deref(), Some("a.exe:0x1000"));
        assert_eq!(plain.source, DetectionSource::Memory);
        assert!(!av_scan::trust::is_generic(&plain));
    }

    #[test]
    fn findings_come_out_in_address_order() {
        // Determinism. The walk is in address order and nothing here sorts or
        // hashes, so two scans of the same process produce the same report in
        // the same order.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            1,
            vec![
                scripted(injectable(0x1000, 4096), b"WENLE-INJECTED-MARKER"),
                scripted(injectable(0x2000, 4096), b"WENLE-INJECTED-MARKER"),
                scripted(injectable(0x3000, 4096), b"WENLE-INJECTED-MARKER"),
            ],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        let addresses: Vec<usize> = outcome.findings.iter().map(|f| f.base).collect();
        assert_eq!(addresses, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn the_report_verdict_is_the_worst_region_not_the_last_one() {
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "victim.exe",
            1,
            vec![
                scripted(injectable(0x1000, 4096), b"WENLE-INJECTED-MARKER"),
                scripted(injectable(0x2000, 4096), b"nothing"),
            ],
        );
        let mut report = MemoryScanReport::new();
        report.record(scanner.scan_process(&mut source));
        assert_eq!(report.verdict(), Verdict::Malicious);
        assert_eq!(report.summary().worst, Verdict::Malicious);
        assert_eq!(report.summary().findings, 1);
    }

    #[test]
    fn a_short_read_is_a_refusal_and_not_a_smaller_region() {
        // A source that hands back fewer bytes than it was asked for is not
        // trusted. The engine would otherwise judge a buffer that is not the
        // region, and the report would say the region was read.
        let engine = engine("WENLE-INJECTED-MARKER");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = FakeSource::named(
            "short.exe",
            1,
            vec![ScriptedRegion {
                region: injectable(0x1000, 4096),
                // Deliberately short: the script's bytes do not fill the region.
                contents: Ok(b"WENLE-INJECTED-MARKER".to_vec()),
            }],
        );
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.regions_read, 0);
        assert_eq!(outcome.regions_refused, 1);
        assert!(
            outcome.findings.is_empty(),
            "no finding from bytes that were not the region"
        );
        assert!(!outcome.is_complete());
        assert!(
            outcome.unreadable.listed[0]
                .error
                .to_string()
                .contains("4096"),
            "{}",
            outcome.unreadable.listed[0].error
        );
    }

    #[test]
    fn the_unreadable_list_is_bounded_and_the_count_is_not() {
        // A hostile process can make the list arbitrarily long; the count
        // carries what the tail of the list would have said.
        let engine = engine("WENLE-NEVER-PRESENT");
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let many: Vec<ScriptedRegion> = (0..MAX_UNREADABLE_LISTED + 10)
            .map(|i| refused(injectable(0x1000 * (i + 1), 4096)))
            .collect();
        let mut source = FakeSource::named("awful.exe", 1, many);
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("the process was walked");
        };
        assert_eq!(outcome.regions_refused, (MAX_UNREADABLE_LISTED + 10) as u64);
        assert_eq!(outcome.unreadable.listed.len(), MAX_UNREADABLE_LISTED);
        assert_eq!(outcome.unreadable.omitted, 10);
    }

    #[test]
    fn the_refusal_reasons_keep_windows_error_codes_apart() {
        // Two processes Windows refuses for entirely different reasons, and one
        // that simply ended. A report that merged these would tell a user to
        // run as administrator when the truth is that nothing was wrong.
        assert_eq!(
            RefusalReason::from_error(&MemoryError::Denied {
                pid: 4,
                code: crate::error::ERROR_ACCESS_DENIED,
                message: "Access is denied.".into(),
            }),
            RefusalReason::AccessDenied {
                code: 5,
                message: "Access is denied.".into(),
            }
        );
        assert_eq!(
            RefusalReason::from_error(&MemoryError::Gone { pid: 4 }),
            RefusalReason::Gone
        );
        assert_eq!(RefusalReason::Gone.as_str(), "gone");
        assert_eq!(
            RefusalReason::from_error(&MemoryError::Unsupported).as_str(),
            "regions-unavailable"
        );
        assert!(RefusalReason::Gone
            .describe()
            .contains("exited before it could be opened"));
    }

    #[test]
    fn the_skip_tally_puts_every_reason_in_its_own_counter() {
        let mut tally = SkipTally::default();
        for skip in [
            Skip::NotCommitted,
            Skip::TooSmall,
            Skip::Guard,
            Skip::NotReadable,
            Skip::NotExecutable,
            Skip::BackedByFile,
        ] {
            tally.record(skip);
        }
        assert_eq!(tally.total(), 6);
        assert_eq!(tally.not_committed, 1);
        assert_eq!(tally.too_small, 1);
        assert_eq!(tally.guard, 1);
        assert_eq!(tally.not_readable, 1);
        assert_eq!(tally.not_executable, 1);
        assert_eq!(tally.backed_by_file, 1);

        // And folding two tallies is a sum of every field rather than of the
        // totals, which a test that only checked `total` would not notice.
        let mut other = SkipTally::default();
        other.record(Skip::Guard);
        other.record(Skip::Guard);
        tally.add(&other);
        assert_eq!(tally.guard, 3);
        assert_eq!(tally.backed_by_file, 1);
        assert_eq!(tally.total(), 8);
    }

    #[test]
    fn the_memory_options_turn_off_what_a_region_has_not_got() {
        let options = memory_scan_options();
        assert!(!options.heuristics, "a region is not an image");
        assert!(!options.archives, "a region is not a container");
        assert!(!options.trust, "a region has no path and no signature");
        assert!(!options.recursive);
        assert!(!options.follow_links);
        assert!(options.memory, "this scan is the reason the flag exists");
        assert!(
            options.max_file_size.is_none(),
            "one cap, in the place that counts it"
        );
    }
}

/// The tests that read the running system.
///
/// Ignored by default and marked with the reason, so that `cargo test` on a
/// machine with a rule set loaded does not open two hundred processes without
/// being asked to. They are run deliberately, with
/// `cargo test -p av-memory -- --ignored --nocapture`.
///
/// # Why these exist when the file above has thirty tests
///
/// The unit tests use a scripted source, which is the right way to pin the
/// arithmetic and the decision — but a scripted source is a source that agrees
/// with the test's assumptions about Windows. Everything this crate believes
/// about the system it runs on is checked here against the system it runs on:
/// that a region walk ends at `0x7fffffff0000` with `ERROR_INVALID_PARAMETER`,
/// that a process can be opened with the rights this crate asks for, that
/// committed private executable memory is what a `VirtualAlloc` produces, and
/// that a marker planted in it comes back out of the report attributed to the
/// right address. Those are the assumptions a fake cannot test.
///
/// # The planted region
///
/// Most of these tests need a region of *this* process that the predicate will
/// judge worth reading, and a Rust test binary has no reason to own one: its
/// own code is file-backed, and its heap is not executable. So the tests make
/// one, the way an injector would — `VirtualAlloc`, write, `VirtualProtect` to
/// execute-read. That is worth being explicit about, because it means these
/// tests do not merely read the system, they modify it: the allocation is freed
/// when the guard drops, and nothing outside this process can see it.
#[cfg(all(test, windows))]
mod live {
    use super::*;
    use crate::process::{current_pid, list_processes};
    use crate::source::Win32Source;
    use av_core::{DetectionSource, Severity};
    use av_rules::database::RuleDatabase;

    /// The marker the attribution test plants, and the string its rule matches.
    ///
    /// **One marker per planting test, and that is not decoration.** These tests
    /// scan the process they are running in, and cargo runs them concurrently in
    /// that one process, so two tests sharing a marker would each find the
    /// other's region: the attribution test asserts on exactly one finding and
    /// would report two. It did, as soon as a third test was added and the
    /// scheduler changed. A distinct marker per test makes each scan's subject a
    /// region no other test can plant, and leaves the assertion meaning what it
    /// says.
    ///
    /// A `const` rather than a built string on purpose: a string built at run
    /// time lives only on the heap, and the point of the attribution test is
    /// that the same bytes are held in three kinds of memory — planted code, a
    /// heap allocation, and this binary's own read-only data.
    const MARKER_ATTRIBUTION: &str = "WENLE-AV-LIVE-PLANTED-MARKER-attr-6f2a91c4";

    /// The marker the truncated-read test plants. See [`MARKER_ATTRIBUTION`].
    const MARKER_TRUNCATED: &str = "WENLE-AV-LIVE-PLANTED-MARKER-trunc-6f2a91c4";

    /// Where in the planted region the marker is written.
    ///
    /// Not zero, deliberately: a finding is attributed to a region and then to
    /// an offset inside it, and an offset of zero would let a scan that dropped
    /// the offset entirely pass.
    const MARKER_OFFSET: usize = 0x800;

    /// A region of this process's own memory, made executable the way an
    /// injector makes one.
    struct Planted {
        base: usize,
        size: usize,
    }

    impl Planted {
        /// Allocate `size` bytes private to this process, write `marker` at
        /// `MARKER_OFFSET`, and leave the page-executable-read.
        fn executable(size: usize, marker: &[u8]) -> Self {
            use windows::Win32::System::Memory::{
                VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
                PAGE_READWRITE,
            };

            assert!(
                MARKER_OFFSET + marker.len() <= size,
                "the region must hold the marker"
            );
            // SAFETY: `VirtualAlloc` is asked for a fresh allocation of `size`
            // bytes, committed and reserved, with no base address requested and
            // no pointer to any memory this code owns. It returns either null
            // or a pointer to a new writable allocation of at least `size`
            // bytes, which is checked before use.
            let base =
                unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
            assert!(!base.is_null(), "VirtualAlloc({size}) returned null");

            // SAFETY: `base` is the start of a live allocation of `size`
            // writable bytes, and the copy writes `marker.len()` bytes at
            // `MARKER_OFFSET`, which the assertion above keeps inside `size`.
            // The source is a live slice owned by the caller, the regions do
            // not overlap because one of them is a fresh allocation, and the
            // allocation is owned by this value alone.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    marker.as_ptr(),
                    (base as *mut u8).add(MARKER_OFFSET),
                    marker.len(),
                );
            }

            let mut previous = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS::default();
            // SAFETY: `base` is the start of the live allocation of `size`
            // bytes, the new protection is a documented page protection, and
            // `previous` is a live local the call writes the old value into.
            // Changing a private allocation's protection affects nothing
            // outside this process.
            unsafe { VirtualProtect(base, size, PAGE_EXECUTE_READ, &mut previous) }
                .expect("VirtualProtect to PAGE_EXECUTE_READ");

            Self {
                base: base as usize,
                size,
            }
        }

        /// The address the region was allocated at.
        fn address(&self) -> usize {
            self.base
        }
    }

    impl Drop for Planted {
        fn drop(&mut self) {
            use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};

            // SAFETY: `self.base` is the base address `VirtualAlloc` returned,
            // is owned by this value alone, and is released exactly once, here.
            // `MEM_RELEASE` requires a size of zero and frees the whole
            // allocation, which is what this is. Nothing uses the address
            // afterwards: the field is not read again and the value is going
            // out of scope.
            unsafe {
                let _ = VirtualFree(self.base as *mut core::ffi::c_void, 0, MEM_RELEASE);
            }
        }
    }

    /// This process, named as well as it can be named from inside itself.
    fn this_process() -> ProcessRef {
        ProcessRef::new(current_pid(), std::env::current_exe().ok())
    }

    /// An engine whose only rule matches the marker this module plants.
    fn marker_engine(rule: &str, marker: &str) -> ScanEngine {
        let source = format!(
            r#"
rule {rule} {{
    meta:
        description = "The marker one live test plants in executable memory."
        severity = "high"
    strings:
        $marker = "{marker}"
    condition:
        $marker
}}
"#
        );
        let (database, report) = RuleDatabase::compile(&source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        assert_eq!(database.len(), 1, "the marker rule must actually compile");
        ScanEngine::new(database)
    }

    /// An engine with a rule that matches nothing, for the tests whose subject
    /// is the arithmetic rather than a finding.
    fn quiet_engine() -> ScanEngine {
        let source = r#"
rule test_never_matches {
    meta:
        description = "A rule no process holds the string of."
        severity = "low"
    strings:
        $nope = "WENLE-AV-A-STRING-NO-PROCESS-HOLDS-5c1e77"
    condition:
        $nope
}
"#;
        let (database, report) = RuleDatabase::compile(source);
        assert_eq!(report.refusals.len(), 0, "{:?}", report.refusals);
        ScanEngine::new(database)
    }

    #[test]
    #[ignore = "reads the running system"]
    fn the_machine_lists_every_process_and_this_one_is_among_them() {
        let processes = list_processes().expect("the process list");
        let named = processes.iter().filter(|p| p.name.is_some()).count();
        let this = current_pid();
        println!(
            "{} processes enumerated, {named} named, {} unnamed",
            processes.len(),
            processes.len() - named
        );

        assert!(!processes.is_empty(), "a running machine has processes");
        assert!(
            processes.iter().any(|p| p.pid == this),
            "a scan of the machine must include the process doing the scanning"
        );
        // PID 0 is the idle process: no image, no address space, and refused
        // with the same code as a PID that was never allocated. Listing it would
        // put a permanent meaningless refusal in every report.
        assert!(
            !processes.iter().any(|p| p.pid == 0),
            "the idle process is not listed"
        );
        // Some processes cannot be named — that is the documented normal case,
        // not a failure — but on any real machine at least one can be.
        assert!(named > 0, "at least one process must be nameable");
    }

    #[test]
    #[ignore = "reads the running system"]
    fn naming_a_process_needs_the_least_right_that_answers_the_question() {
        // The measurement behind `entry_for`'s choice of access mask, on the
        // whole machine rather than on a sample. `PROCESS_QUERY_LIMITED_INFORMATION`
        // is the right Windows added so that a process could be named by a caller
        // that could not read it; the question this test answers is whether it is
        // also the right that names *more* processes, because the two are
        // different claims and only the second one is measured.
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let processes = list_processes().expect("the process list");
        let mut limited = 0u64;
        let mut full = 0u64;
        let mut only_limited = Vec::new();
        let mut only_full = Vec::new();
        for process in &processes {
            let nameable = |access| -> bool {
                // SAFETY: a documented access mask, a PID that came from
                // `EnumProcesses`, and `false` for inheritance, so nothing is
                // inherited. The handle is closed on both paths below and no
                // pointer is passed in.
                let Ok(handle) = (unsafe { OpenProcess(access, false, process.pid) }) else {
                    return false;
                };
                let mut buffer = vec![0u16; 32_768];
                let mut length = buffer.len() as u32;
                // SAFETY: `buffer` holds `length` u16s and the call is told that,
                // so it writes at most that many; `length` is a live local it
                // writes the real length into. The handle is live and was opened
                // for exactly this query.
                let named = unsafe {
                    QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_WIN32,
                        windows::core::PWSTR(buffer.as_mut_ptr()),
                        &mut length,
                    )
                }
                .is_ok();
                // SAFETY: the handle came from `OpenProcess` above, is owned by
                // this closure, and is closed exactly once.
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                named
            };
            let by_limited = nameable(PROCESS_QUERY_LIMITED_INFORMATION);
            let by_full = nameable(PROCESS_QUERY_INFORMATION);
            limited += u64::from(by_limited);
            full += u64::from(by_full);
            if by_limited && !by_full {
                only_limited.push(process.label());
            }
            if by_full && !by_limited {
                only_full.push(process.label());
            }
        }

        println!(
            "\n=== naming rights over {} processes ===\n  \
             PROCESS_QUERY_LIMITED_INFORMATION named {limited}; \
             PROCESS_QUERY_INFORMATION named {full}; \
             {} named only by the limited right, {} only by the full one",
            processes.len(),
            only_limited.len(),
            only_full.len(),
        );
        if !only_limited.is_empty() {
            println!("  named only by the limited right: {only_limited:?}");
        }
        if !only_full.is_empty() {
            println!("  named only by the full right: {only_full:?}");
        }
        println!();

        // The claim `entry_for` is built on: the least right is not a
        // compromise, it is the better right for this job. If this ever fails,
        // the mask in `entry_for` is the thing to change, not this test.
        assert!(
            limited >= full,
            "the limited right named {limited} processes and the full right {full}, \
             so `entry_for`'s access mask is no longer the one that names the most"
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_region_walk_of_this_process_reaches_the_top_of_the_address_space() {
        let mut source = Win32Source::current().expect("this process must open");
        let walk = source
            .regions(1 << 20)
            .expect("this process must be walkable");
        assert!(walk.complete, "a walk of this process must reach the end");
        assert!(walk.regions.len() > 100, "{} regions", walk.regions.len());

        let mut highest = 0;
        for region in &walk.regions {
            assert!(region.size > 0, "{region:#x?}");
            assert!(
                region.base >= highest,
                "the walk is in ascending address order"
            );
            highest = region.end();
        }
        println!(
            "this process: {} regions, top of the address space {highest:#x}",
            walk.regions.len()
        );
        // The top of the user address space on x64. A walk that stopped earlier
        // would have reported itself incomplete, which the assertion above
        // covers; this one says where a complete walk ends on this machine.
        assert!(
            highest >= 0x7fff_0000_0000,
            "the walk stopped at {highest:#x}"
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_planted_marker_is_found_and_attributed_to_the_process_and_the_address() {
        // The centrepiece, end to end against the real system: bytes that exist
        // only in this process's executable memory, a real rule set, the real
        // engine, and a finding that names where it was found.
        let marker = MARKER_ATTRIBUTION.as_bytes();
        let planted = Planted::executable(64 * 1024, marker);
        // The same bytes, held where the predicate must *not* find them: a heap
        // allocation is read-write and not executable, so it is not code.
        let on_the_heap = marker.to_vec();
        assert_eq!(on_the_heap, marker, "the heap copy is the same bytes");

        let engine = marker_engine("test_planted_marker", MARKER_ATTRIBUTION);
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = Win32Source::open(this_process()).expect("this process must open");
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("this process must be walkable");
        };

        println!(
            "planted {} bytes at {:#x}; scan read {} region(s), {} byte(s), {} finding(s)",
            planted.size,
            planted.address(),
            outcome.regions_read,
            outcome.bytes_read,
            outcome.findings.len()
        );

        // Exactly one, and this is the differential part: the same bytes are in
        // this binary's read-only data (file-backed, so passed over) and on the
        // heap (read-write, so not code), and neither may produce a finding.
        assert_eq!(
            outcome.findings.len(),
            1,
            "the marker is in three kinds of memory and only one is code: {:#?}",
            outcome.findings
        );
        let finding = &outcome.findings[0];
        assert_eq!(
            finding.base,
            planted.address(),
            "the finding must name the region the marker was planted in"
        );
        assert_eq!(finding.interest, Interest::UnbackedCode);
        assert_eq!(finding.kind, RegionKind::Private);
        assert_eq!(finding.protection.describe(), "r-x");
        assert_eq!(finding.verdict, Verdict::Malicious);

        // The attribution, which is what a report and a console render.
        let expected = source.process().container(planted.address());
        assert_eq!(finding.container(), expected);
        assert!(finding
            .container()
            .ends_with(&format!(":{:#x}", planted.address())));
        let detection = &finding.detections[0];
        assert_eq!(detection.rule_id, "test_planted_marker");
        assert_eq!(detection.severity, Severity::High);
        // Not `Signature`, although the rule is one: these bytes came out of a
        // process, and that is the fact `attribute` exists to record.
        assert_eq!(detection.source, DetectionSource::Memory);
        assert!(!av_scan::trust::is_generic(detection));
        assert_eq!(detection.container.as_deref(), Some(expected.as_str()));
        // The offset is an offset into the region, and the marker was planted
        // at a known one.
        assert_eq!(detection.locations[0].offset, MARKER_OFFSET as u64);
        assert_eq!(detection.locations[0].preview, MARKER_ATTRIBUTION);
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_bounded_read_reads_the_cap_and_says_the_region_was_truncated() {
        // The cap, against a region whose size is known exactly.
        let planted = Planted::executable(64 * 1024, MARKER_TRUNCATED.as_bytes());
        let engine = marker_engine("test_truncated_marker", MARKER_TRUNCATED);
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                max_region_bytes: 4096,
                ..MemoryScanConfig::default()
            },
        );
        let mut source = Win32Source::open(this_process()).expect("this process must open");
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("this process must be walkable");
        };

        assert!(
            outcome.regions_truncated >= 1,
            "the planted region is 64 KiB"
        );
        assert!(outcome.bytes_unread > 0, "and bytes were left unread");
        assert!(!outcome.is_complete());

        let finding = outcome
            .findings
            .iter()
            .find(|finding| finding.base == planted.address())
            .expect("the marker is in the read prefix");
        assert_eq!(finding.region_size, planted.size);
        assert_eq!(finding.bytes_read, 4096, "the read stopped at the cap");
        assert!(finding.truncated);
        assert_eq!(
            finding.detections[0].locations[0].offset,
            MARKER_OFFSET as u64
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_walk_that_stops_at_the_limit_says_so() {
        let engine = quiet_engine();
        let scanner = MemoryScanner::new(
            &engine,
            MemoryScanConfig {
                max_regions: 8,
                ..MemoryScanConfig::default()
            },
        );
        let mut source = Win32Source::open(this_process()).expect("this process must open");
        let ProcessScan::Examined(outcome) = scanner.scan_process(&mut source) else {
            panic!("this process must be walkable");
        };
        assert_eq!(outcome.regions_seen, 8);
        assert!(!outcome.walk_complete);
        assert!(!outcome.is_complete());
        assert!(
            outcome
                .gaps()
                .iter()
                .any(|gap| gap.contains("region limit")),
            "{:?}",
            outcome.gaps()
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_process_windows_will_not_open_is_refused_and_counted() {
        // PID 4 is the System process. It denies `PROCESS_VM_READ` to every
        // user-mode caller, administrators included, and it is the refusal every
        // whole-machine scan on Windows has to expect — so it is the one worth
        // asserting rather than a process that happens to be asleep.
        let engine = quiet_engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut report = MemoryScanReport::new();
        match Win32Source::open(ProcessRef::anonymous(4)) {
            Ok(mut source) => report.record(scanner.scan_process(&mut source)),
            Err(error) => report.record_refusal(ProcessRef::anonymous(4), &error),
        }

        let summary = report.summary();
        assert_eq!(summary.processes_seen, 1);
        assert_eq!(
            summary.processes_examined, 0,
            "nothing of PID 4 can be read"
        );
        assert_eq!(summary.processes_refused(), 1);
        assert!(
            !summary.is_complete(),
            "a refused process is a hole in the scan"
        );
        let reason = report.results[0].refusal().expect("a refusal");
        println!("PID 4: {reason:?}");
        assert!(
            matches!(
                reason,
                RefusalReason::AccessDenied { .. } | RefusalReason::RegionsUnavailable { .. }
            ),
            "PID 4 exists and cannot be read; it must not be reported as exited: {reason:?}"
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn a_pid_that_cannot_name_a_process_is_reported_as_gone() {
        // `u32::MAX - 1` is not a multiple of four and Windows identifies
        // processes only by multiples of four, so `OpenProcess` refuses it with
        // `ERROR_INVALID_PARAMETER` — which is the code that means "no such
        // process" and the one that keeps a process that exited mid-scan out of
        // the denial count.
        let error = Win32Source::open(ProcessRef::anonymous(u32::MAX - 1))
            .expect_err("no process has this identifier");
        println!("PID {}: {error}", u32::MAX - 1);
        let reason = RefusalReason::from_error(&error);
        assert_eq!(reason, RefusalReason::Gone);
        assert_eq!(reason.as_str(), "gone");
    }

    /// Scan one process, print what happened, and put the result in the report.
    ///
    /// A refusal is recorded in the report rather than only counted here, so
    /// that the summary's own totals are the numbers the assertions read — a
    /// measurement that printed one refusal count and asserted on a different
    /// one would be measuring the printer.
    fn measure(
        scanner: &MemoryScanner<'_>,
        process: &ProcessRef,
        report: &mut MemoryScanReport,
    ) -> bool {
        let mut source = match Win32Source::open(process.clone()) {
            Ok(source) => source,
            Err(error) => {
                println!("  {:>30}  refused: {error}", process.label(),);
                report.record_refusal(process.clone(), &error);
                return false;
            }
        };
        let scan = scanner.scan_process(&mut source);
        if let ProcessScan::Refused { reason, .. } = &scan {
            println!(
                "  {:>30}  refused after opening: {}",
                process.label(),
                reason.describe()
            );
        }
        let examined = scan.outcome().is_some();
        if let Some(outcome) = scan.outcome() {
            println!(
                "  {:>30}  seen {:>5}  committed {:>5}  interesting {:>4}  guarded {:>3}  \
                 file-backed {:>5}  read {:>4}  refused {:>3}  over-budget {:>3}  \
                 bytes read {:>9}  findings {:>2}",
                process.label(),
                outcome.regions_seen,
                outcome
                    .regions_seen
                    .saturating_sub(outcome.skipped.not_committed),
                outcome.regions_interesting,
                outcome.skipped.guard,
                outcome.skipped.backed_by_file,
                outcome.regions_read,
                outcome.regions_refused,
                outcome.regions_over_budget,
                outcome.bytes_read,
                outcome.findings.len(),
            );
        }
        report.record(scan);
        examined
    }

    #[test]
    #[ignore = "reads the running system"]
    fn measurement_of_a_handful_of_real_processes() {
        // The numbers quoted in this crate's doc comments come from here. Run
        // with `--nocapture` to see them.
        let engine = quiet_engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let processes = list_processes().expect("the process list");

        let mut targets = vec![this_process()];
        if let Some(explorer) = processes
            .iter()
            .find(|process| process.name.as_deref() == Some("explorer.exe"))
        {
            targets.push(explorer.clone());
        }
        for process in &processes {
            if targets.len() >= 6 {
                break;
            }
            if targets.iter().all(|target| target.pid != process.pid) && process.name.is_some() {
                targets.push(process.clone());
            }
        }

        println!(
            "\n=== memory scan measurement: {} processes on this machine, {} scanned ===",
            processes.len(),
            targets.len()
        );

        let mut report = MemoryScanReport::new();
        for target in &targets {
            measure(&scanner, target, &mut report);
        }

        let summary = report.summary();
        println!(
            "  totals: {} examined, {} refused, {} gone, {} regions seen, {} interesting, \
             {} read, {} bytes read, {} unread, {} finding(s)",
            summary.processes_examined,
            summary.processes_refused(),
            summary.processes_gone(),
            summary.regions_seen,
            summary.regions_interesting,
            summary.regions_read,
            summary.bytes_read,
            summary.bytes_unread,
            summary.findings,
        );
        println!(
            "  passed over: {} reserved/free, {} too small, {} guarded, {} unreadable, \
             {} not executable, {} file-backed",
            summary.skipped.not_committed,
            summary.skipped.too_small,
            summary.skipped.guard,
            summary.skipped.not_readable,
            summary.skipped.not_executable,
            summary.skipped.backed_by_file,
        );
        println!("  complete: {}", summary.is_complete());
        for gap in summary.gaps() {
            println!("  not examined: {gap}");
        }
        println!();

        // Two invariants on real data rather than on a script: every region the
        // walks produced is accounted for, and every interesting region was
        // either read, refused, or left for a budget.
        assert_eq!(
            summary.regions_seen,
            summary.regions_interesting + summary.skipped.total(),
            "every region must be either interesting or passed over: {summary:?}"
        );
        assert_eq!(
            summary.regions_interesting,
            summary.regions_read + summary.regions_refused + summary.regions_over_budget,
            "every interesting region must be read, refused or deferred: {summary:?}"
        );
        assert!(
            summary.processes_examined > 0,
            "this process must be scannable"
        );

        // The decision is what makes the scan affordable. Measured on the
        // machine this was written on, explorer.exe had around 4,500 committed
        // regions and 22 of them were interesting — so a predicate that flagged
        // a third of a real process's memory would be a predicate that made a
        // memory scan cost what a disk scan costs. The bound is deliberately
        // loose: this is a check that the predicate has not stopped
        // discriminating, not a claim about any particular machine.
        assert!(
            summary.regions_interesting * 4 < summary.regions_seen,
            "the predicate flagged {} of {} regions, which is not a decision: {summary:?}",
            summary.regions_interesting,
            summary.regions_seen
        );
        // Every process handed to the scanner is in exactly one of the three
        // states, on real data and not on a script.
        assert_eq!(summary.processes_seen, targets.len() as u64);
        assert_eq!(
            summary.processes_seen,
            summary.processes_examined + summary.processes_refused() + summary.processes_gone(),
            "every process must be examined, refused or gone: {summary:?}"
        );
    }

    #[test]
    #[ignore = "reads the running system"]
    fn census_of_the_whole_machine() {
        // The whole-machine numbers in this crate's doc comments come from here:
        // how much of what is running a memory scan can actually look at, and
        // what the rest of it costs. This is the only test that calls
        // `scan_running_processes`, so it is also the only check that the
        // enumeration and the scan agree about which processes exist.
        let engine = quiet_engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let report = scanner.scan_running_processes().expect("the process list");
        let summary = report.summary();

        println!("\n=== whole-machine memory scan census ===");
        println!(
            "  {} processes listed: {} examined, {} refused, {} gone",
            summary.processes_seen,
            summary.processes_examined,
            summary.processes_refused(),
            summary.processes_gone(),
        );
        println!(
            "  refusals: {} denied, {} unreadable",
            summary.refused_denied, summary.refused_unreadable,
        );
        println!(
            "  regions: {} seen, {} interesting, {} read, {} refused, {} over budget, {} unknown",
            summary.regions_seen,
            summary.regions_interesting,
            summary.regions_read,
            summary.regions_refused,
            summary.regions_over_budget,
            summary.regions_unknown,
        );
        println!(
            "  {} bytes read, {} bytes in regions that were not read, {} findings",
            summary.bytes_read, summary.bytes_unread, summary.findings,
        );
        println!(
            "  passed over: {} reserved/free, {} too small, {} guarded, {} unreadable, \
             {} not executable, {} file-backed",
            summary.skipped.not_committed,
            summary.skipped.too_small,
            summary.skipped.guard,
            summary.skipped.not_readable,
            summary.skipped.not_executable,
            summary.skipped.backed_by_file,
        );
        println!(
            "  {} walk(s) stopped short; complete: {}",
            summary.walks_incomplete,
            summary.is_complete(),
        );
        println!();

        // The arithmetic that has to hold whatever the machine looks like: every
        // listed process is accounted for, every region is either interesting or
        // passed over, and every interesting region was read, refused or left
        // for a budget. On a machine where some process is always protected, the
        // first of these is exactly the claim that a memory scan is partial and
        // knows it.
        assert!(summary.processes_seen > 0, "the machine has processes");
        assert_eq!(
            summary.processes_seen,
            summary.processes_examined + summary.processes_refused() + summary.processes_gone(),
            "every process must be examined, refused or gone: {summary:?}"
        );
        assert_eq!(
            summary.regions_seen,
            summary.regions_interesting + summary.skipped.total(),
            "every region must be either interesting or passed over: {summary:?}"
        );
        assert_eq!(
            summary.regions_interesting,
            summary.regions_read + summary.regions_refused + summary.regions_over_budget,
            "every interesting region must be read, refused or deferred: {summary:?}"
        );
        assert!(
            summary.processes_examined > 0,
            "a memory scan that could open nothing is not a scan: {summary:?}"
        );
        // The scan is allowed to be partial — that is the point of the report —
        // but it is not allowed to be partial silently: an incomplete census has
        // to have at least one sentence saying why.
        assert_eq!(summary.is_complete(), summary.gaps().is_empty());
        if !summary.is_complete() {
            for gap in summary.gaps() {
                println!("  not examined: {gap}");
            }
        }
    }
}
