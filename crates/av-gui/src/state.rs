//! What the window knows.
//!
//! # Why this is separate from the drawing, and testable without a window
//!
//! A scan takes minutes on a real disk. The state a window is in while that
//! happens — how far along, what it is looking at, whether the user has asked
//! it to stop, what it found when it finished — is the part of the interface
//! that has *behaviour* in it, and behaviour is what breaks. None of it needs a
//! window to exercise: [`ScanState`] is an enum, [`Progress`] is arithmetic
//! over plain numbers, and [`ScanHandle`] is a handful of atomics a test can
//! drive from a single thread with no window and no scanning.
//!
//! The drawing code above this reads these values and puts rectangles around
//! them. A bug in the drawing is a bug you can see; a bug in here is a progress
//! bar that says 100% at 90% and a user who stops waiting.
//!
//! # Cancellation is the engine's protocol, not one invented here
//!
//! There is no cancellation token in `av-scan` and this crate does not add one.
//! What the engine offers is [`av_core::ScanOptions::stop_on_first`], the
//! `cancelled` field on [`av_core::ScanReport`], and an implicit contract that
//! the *caller* drives the per-file loop and can stop driving it. That is
//! exactly what the console does: `av-cli`'s scan driver holds an `AtomicBool`,
//! checks it before opening each file, and sets `report.cancelled` when it
//! stops early. [`ScanHandle::request_stop`] is that same flag, so a stop
//! requested from the window and a stop requested from the console are the same
//! stop, and a scan stops between files rather than inside one.
//!
//! The consequence is worth stating plainly, because it is visible to the user:
//! stopping is not instant. A scan of one enormous archive finishes that
//! archive before it stops, because the check happens before a file is opened
//! and not inside one. So the Stop button puts the window into a state that
//! says a stop has been asked for and is still landing, rather than a state
//! that says the scan is over — see [`ScanState::cancelled_note`]. A button
//! that claimed to have stopped something it had not stopped would be the
//! window telling the user their scan had ended while their disk was still
//! being read.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use av_core::{AvConfig, ScanReport, Severity};
// Reached only from the tests below, through `use super::*`, so a build
// without them would be carrying an import nothing reads.
#[cfg(test)]
use av_core::Verdict;
use av_quarantine::QuarantineEntry;

use crate::format::{count_of, human_bytes, human_count, human_duration, percentage, shorten_path};

/// `count` per second over `elapsed`, or `None` if that is not yet a rate.
///
/// A free function rather than a method because both the scan's count and the
/// walk's count are rates over the same clock, and the two callers should not
/// be able to drift apart in when they consider a rate meaningful.
///
/// The window exists because dividing by a very small duration produces a very
/// large number that is not information: two files in the first millisecond is
/// not "2,000 files per second", it is two files and a clock that has barely
/// moved.
fn rate_of(count: u64, elapsed: Duration) -> Option<f64> {
    if elapsed < Progress::MIN_RATE_WINDOW || count == 0 {
        return None;
    }
    Some(count as f64 / elapsed.as_secs_f64())
}

/// How far along a running scan is, as a value.
///
/// Plain data with no clock and no atomics in it, so the arithmetic below can
/// be tested with a total, a count and an elapsed time that a test chooses —
/// including the ones a real scan produces only at its edges: nothing done yet,
/// everything done, and a duration of zero.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    /// Files finished with, successfully or not.
    pub files_done: u64,
    /// Files the walk found, or `0` while the walk is still running and the
    /// total is not yet known.
    pub files_total: u64,
    /// Files the walk has found so far, while it is still walking.
    ///
    /// The walk is a phase of its own and on a large tree it is not a short
    /// one: enumerating a system drive is tens of seconds of filesystem
    /// latency before a single byte is examined. A window that showed nothing
    /// moving for that long would look hung, so the count of files found is
    /// published separately from the count of files scanned.
    pub files_found: u64,
    /// Whether the walk is still running.
    pub walking: bool,
    /// Bytes of the files the walk has found so far.
    ///
    /// A second byte count rather than a reuse of `bytes_done`, because the two
    /// are counts of different things and only one of them exists at a time.
    /// `bytes_done` is bytes *read*, which nothing has been during the walk; a
    /// line that printed it while walking was printing a number that is zero by
    /// construction, every time, however many files the walk had found.
    pub bytes_found: u64,
    /// Bytes examined so far.
    pub bytes_done: u64,
    /// Files that produced a verdict worth reporting.
    pub findings: u64,
    /// The file being looked at, as a display string.
    pub current: String,
    /// How long the scan has been running.
    pub elapsed: Duration,
}

impl Progress {
    /// The shortest elapsed time a rate is computed from.
    ///
    /// A rate divided by the first millisecond of a scan reports forty thousand
    /// files a second, because the first file was in the cache and the
    /// denominator had not started yet. Nothing is more likely to make a user
    /// disbelieve the rest of the screen than a number that is obviously
    /// nonsense, so below this the rate is simply not offered.
    pub const MIN_RATE_WINDOW: Duration = Duration::from_secs(1);

    /// How far along, when the total is known.
    pub fn fraction(&self) -> Option<f32> {
        crate::format::fraction(self.files_done, self.files_total)
    }

    /// How far along, as a whole number, when the total is known.
    pub fn percent(&self) -> Option<u8> {
        percentage(self.files_done, self.files_total)
    }

    /// Files per second, when enough time has passed for the number to mean
    /// anything.
    pub fn rate(&self) -> Option<u64> {
        let rate = self.rate_f64()?;
        // A rate above `u64::MAX` is not a rate; it is a duration of zero
        // surviving the window check on a coarse clock.
        Some(rate.min(u64::MAX as f64) as u64)
    }

    /// Files the walk is finding per second.
    ///
    /// The same arithmetic over the walk's count rather than the scan's, for
    /// the phase where the scan has not started. Without it the walk is the one
    /// phase of the whole operation with no movement on screen at all.
    pub fn walk_rate(&self) -> Option<u64> {
        let rate = rate_of(self.files_found, self.elapsed)?;
        Some(rate.min(u64::MAX as f64) as u64)
    }

    /// The rate as a float, for the estimate below.
    fn rate_f64(&self) -> Option<f64> {
        rate_of(self.files_done, self.elapsed)
    }

    /// A straight-line estimate of the time left.
    ///
    /// `None` when the total is not known, when nothing has finished, or when
    /// the scan is done — an estimate of zero seconds is not an estimate.
    ///
    /// This is a straight line and says so: a scan does not proceed at a
    /// constant rate, because a directory of text files and a directory of
    /// multi-gigabyte archives cost wildly different amounts per file. The
    /// number is worth showing because it is right about the order of magnitude,
    /// and it is drawn as an estimate rather than as a countdown.
    pub fn remaining(&self) -> Option<Duration> {
        if self.files_total == 0 || self.files_done >= self.files_total {
            return None;
        }
        let rate = self.rate_f64()?;
        if rate <= 0.0 {
            return None;
        }
        let left = (self.files_total - self.files_done) as f64 / rate;
        // A clock that jumps, or a first file that took an hour, can make this
        // absurd. Capped at a day: a scan that claims to need a week has an
        // estimate problem, not a week of work.
        Some(Duration::from_secs_f64(left.min(86_400.0)))
    }

    /// The line drawn under the progress bar.
    ///
    /// The same shape as the console's progress line — fields separated by two
    /// spaces, counts in the same format — because a user who has watched one
    /// and then the other should not have to read it twice.
    ///
    /// Fields that have nothing to say are left out rather than printed empty:
    /// before the walk has finished there is no total, and a line reading
    /// `412 of 0 files` is a line reporting a bug that is not there.
    ///
    /// While the walk is still running the line says so and counts what the
    /// walk has found, because that is the only number that exists yet. It is
    /// not dressed up as progress through the scan: the two phases are named
    /// differently on purpose, so that a slow disk does not look like a slow
    /// scan of a known amount of work.
    ///
    /// The size on that line is the size of the files found, which is what the
    /// walk knows, and not a byte count of anything read — no file has been
    /// opened yet, and the line said `0 B` for every walk it ever drew.
    pub fn line(&self) -> String {
        let mut parts = Vec::with_capacity(5);
        if self.walking {
            parts.push(format!(
                "looking for files… {} found so far",
                human_count(self.files_found)
            ));
            if let Some(rate) = self.walk_rate() {
                parts.push(format!("{}/s", human_count(rate)));
            }
            parts.push(human_bytes(self.bytes_found));
            if !self.current.is_empty() {
                parts.push(shorten_path(&self.current, 56));
            }
            return parts.join("  ");
        }
        match self.percent() {
            Some(percent) => parts.push(format!(
                "{} of {} files ({percent}%)",
                human_count(self.files_done),
                human_count(self.files_total)
            )),
            None => parts.push(format!("{} files so far", human_count(self.files_done))),
        }
        if let Some(rate) = self.rate() {
            parts.push(format!("{}/s", human_count(rate)));
        }
        if let Some(remaining) = self.remaining() {
            parts.push(format!("about {} left", human_duration(remaining)));
        }
        parts.push(if self.findings == 0 {
            "no findings".to_owned()
        } else {
            count_of(self.findings, "finding")
        });
        parts.push(human_bytes(self.bytes_done));
        if !self.current.is_empty() {
            parts.push(shorten_path(&self.current, 56));
        }
        parts.join("  ")
    }
}

/// The state a running scan publishes to whoever is watching it.
///
/// Every field is an atomic or a short-lived lock, because the scan thread
/// writes them and the drawing thread reads them on every frame. The lock is
/// only ever taken for the current path, and only for as long as it takes to
/// copy a string: a scan that took a lock on the scanning path for every file
/// would be measurably slower than one that does not.
#[derive(Debug)]
struct Shared {
    files_done: AtomicU64,
    files_total: AtomicU64,
    files_found: AtomicU64,
    walking: AtomicBool,
    bytes_found: AtomicU64,
    bytes_done: AtomicU64,
    findings: AtomicU64,
    current: parking_lot::Mutex<String>,
    stop: AtomicBool,
    started: Instant,
}

/// The scan thread's end of the shared progress.
///
/// Cloned and moved onto the worker; the window keeps its own clone. Dropping
/// both ends does not stop anything — the flag is read by the driver, which is
/// the only thing that can act on it.
#[derive(Debug, Clone)]
pub struct ScanHandle(Arc<Shared>);

impl ScanHandle {
    /// A handle with no work recorded and its clock started.
    pub fn new() -> Self {
        Self(Arc::new(Shared {
            files_done: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            files_found: AtomicU64::new(0),
            walking: AtomicBool::new(false),
            bytes_found: AtomicU64::new(0),
            bytes_done: AtomicU64::new(0),
            findings: AtomicU64::new(0),
            current: parking_lot::Mutex::new(String::new()),
            stop: AtomicBool::new(false),
            started: Instant::now(),
        }))
    }

    /// Record that the walk has started.
    ///
    /// While this is set the window shows the walk's own count rather than a
    /// percentage, because there is nothing to be a percentage *of* yet.
    pub fn begin_walk(&self) {
        self.0.walking.store(true, Ordering::Relaxed);
    }

    /// Record one file the walk has found, and how large it is.
    ///
    /// Cheap on purpose: the walk touches every directory entry on the disk, so
    /// this is two relaxed increments and nothing else, with no allocation and
    /// no lock.
    ///
    /// The size comes from the directory listing that produced the entry, so it
    /// costs the walk nothing to pass on — and it is the only thing that can be
    /// said about bytes during the walk, because none of them has been read.
    pub fn file_found(&self, bytes: u64) {
        self.0.files_found.fetch_add(1, Ordering::Relaxed);
        self.0.bytes_found.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record that the walk has finished and the scan is starting.
    ///
    /// Sets the total and clears the walking flag in that order, so that a
    /// window reading the pair can never see a total without seeing that the
    /// walk is over. It is one frame of a progress bar either way, but it is
    /// the difference between a bar that jumps and a bar that starts full.
    pub fn end_walk(&self, total: u64) {
        self.0.files_total.store(total, Ordering::Relaxed);
        self.0.walking.store(false, Ordering::Relaxed);
    }

    /// Record one file, whether or not it produced anything.
    pub fn file_done(&self, path: &str, bytes: u64) {
        self.0.files_done.fetch_add(1, Ordering::Relaxed);
        self.0.bytes_done.fetch_add(bytes, Ordering::Relaxed);
        // A path is a `String` allocation, so this is the one write that costs
        // something. It is skipped once a stop has been asked for, because by
        // then the only thing the user is watching for is the stop landing.
        if !self.stop_requested() {
            let mut current = self.0.current.lock();
            current.clear();
            current.push_str(path);
        }
    }

    /// Record one file that produced a verdict worth reporting.
    pub fn found(&self) {
        self.0.findings.fetch_add(1, Ordering::Relaxed);
    }

    /// Ask the scan to stop.
    ///
    /// The driver checks this before opening each file — the engine's own
    /// stopping protocol, the one the console uses. See the module
    /// documentation for what that does and does not guarantee.
    pub fn request_stop(&self) {
        self.0.stop.store(true, Ordering::Relaxed);
    }

    /// Whether a stop has been asked for.
    pub fn stop_requested(&self) -> bool {
        self.0.stop.load(Ordering::Relaxed)
    }

    /// What the scan has reached.
    pub fn snapshot(&self) -> Progress {
        self.snapshot_at(Instant::now())
    }

    /// What the scan had reached at a given moment.
    ///
    /// Split out from [`ScanHandle::snapshot`] so that the elapsed time — and
    /// therefore the rate and the estimate derived from it — is something a
    /// test chooses rather than something it waits for.
    fn snapshot_at(&self, now: Instant) -> Progress {
        Progress {
            files_done: self.0.files_done.load(Ordering::Relaxed),
            files_total: self.0.files_total.load(Ordering::Relaxed),
            files_found: self.0.files_found.load(Ordering::Relaxed),
            walking: self.0.walking.load(Ordering::Relaxed),
            bytes_found: self.0.bytes_found.load(Ordering::Relaxed),
            bytes_done: self.0.bytes_done.load(Ordering::Relaxed),
            findings: self.0.findings.load(Ordering::Relaxed),
            current: self.0.current.lock().clone(),
            elapsed: now.saturating_duration_since(self.0.started),
        }
    }
}

impl Default for ScanHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Which of the four screens the Scan tab is showing.
///
/// A separate enum from [`ScanState`] because the drawing code matches on the
/// shape of the screen much more often than on the data in it, and a match on
/// four unit variants with no fields is a match the compiler can check for
/// exhaustiveness at the one place a screen is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing has been scanned since the window opened.
    Idle,
    /// A scan is running on its own thread.
    Running,
    /// A scan finished. Whether it finished early or completely is on the
    /// report.
    Finished,
    /// A scan could not be started, or stopped with an error.
    Failed,
}

/// What the Scan tab is showing.
#[derive(Debug, Default)]
pub enum ScanState {
    /// Nothing has been scanned yet.
    #[default]
    Idle,
    /// A scan is running. The handle is how far along it is and how to stop it.
    Running(ScanHandle),
    /// A scan finished. The report is the answer, and it is kept whether the
    /// scan completed or was stopped early.
    Finished(Box<ScanReport>),
    /// A scan could not be run at all: no rule database, a target that does not
    /// exist, a walk that failed. Distinct from a file the scanner could not
    /// read, which is a finding on a report rather than a failure of the scan.
    Failed {
        /// What went wrong, in a sentence fit to put on screen.
        message: String,
    },
}

impl ScanState {
    /// Which screen to draw.
    pub fn phase(&self) -> Phase {
        match self {
            ScanState::Idle => Phase::Idle,
            ScanState::Running(_) => Phase::Running,
            ScanState::Finished(_) => Phase::Finished,
            ScanState::Failed { .. } => Phase::Failed,
        }
    }

    /// Whether a scan is running.
    pub fn is_running(&self) -> bool {
        matches!(self, ScanState::Running(_))
    }

    /// Whether a new scan can be started from here.
    ///
    /// Anything but running. Starting a second scan over the first is the one
    /// thing that would make the progress display meaningless, and there is no
    /// state where it is the right thing to do — the first scan would still be
    /// holding the disk.
    pub fn can_start(&self) -> bool {
        !self.is_running()
    }

    /// How far along a running scan is.
    pub fn progress(&self) -> Option<Progress> {
        match self {
            ScanState::Running(handle) => Some(handle.snapshot()),
            _ => None,
        }
    }

    /// The handle to a running scan, for a Stop button.
    pub fn handle(&self) -> Option<&ScanHandle> {
        match self {
            ScanState::Running(handle) => Some(handle),
            _ => None,
        }
    }

    /// The report of a finished scan, or of a running one that streams.
    pub fn report(&self) -> Option<&ScanReport> {
        match self {
            ScanState::Finished(report) => Some(report),
            _ => None,
        }
    }

    /// Record that the scan finished.
    pub fn finish(&mut self, report: ScanReport) {
        *self = ScanState::Finished(Box::new(report));
    }

    /// Record that the scan could not be run.
    pub fn fail(&mut self, message: impl Into<String>) {
        *self = ScanState::Failed {
            message: message.into(),
        };
    }

    /// The line at the top of the Scan tab.
    ///
    /// One place per phase, so that the sentence and the screen cannot disagree
    /// — a Failed state that still said "ready" is the kind of thing that
    /// happens when the text is chosen next to the button rather than here.
    pub fn summary(&self) -> String {
        match self {
            ScanState::Idle => "Nothing has been scanned yet.".to_owned(),
            ScanState::Running(handle) => handle.snapshot().line(),
            ScanState::Finished(report) => crate::format::scan_summary(report),
            ScanState::Failed { message } => {
                format!("The scan could not be run: {message}")
            }
        }
    }

    /// The sentence to draw when a finished scan was stopped early.
    ///
    /// `None` for every other state, including a finished scan that ran to the
    /// end. A cancelled scan's report is a real report of the part that was
    /// looked at, and the one thing a reader must not do is take it for the
    /// whole answer.
    pub fn cancelled_note(&self) -> Option<&'static str> {
        match self {
            ScanState::Finished(report) if report.cancelled => Some(
                "You stopped this scan, so these findings are what was looked at before you did \
                 — not the whole target.",
            ),
            ScanState::Running(handle) if handle.stop_requested() => {
                Some("Stopping after the file being scanned finishes.")
            }
            _ => None,
        }
    }
}

/// The Settings tab's edits, before they are saved.
///
/// Holds two copies of the configuration so that Cancel can put back what was
/// there without re-reading the file — the file may not be readable, and a user
/// who opened Settings and pressed Cancel must get their settings back whether
/// or not the disk is cooperating.
///
/// Nothing here writes anything. Saving is a separate act that goes through
/// [`av_core::AvConfig::validate`] first, so an edited configuration that would
/// be refused on load cannot be written by this window and then refused the
/// next time it starts.
#[derive(Debug, Clone)]
pub struct SettingsDraft {
    original: AvConfig,
    edited: AvConfig,
}

impl SettingsDraft {
    /// A draft of a configuration, with no edits yet.
    pub fn new(original: AvConfig) -> Self {
        Self {
            edited: original.clone(),
            original,
        }
    }

    /// The configuration as it is being edited.
    pub fn edited(&self) -> &AvConfig {
        &self.edited
    }

    /// The configuration as it is being edited, mutably.
    pub fn edited_mut(&mut self) -> &mut AvConfig {
        &mut self.edited
    }

    /// Record an exclusion that has already been written to the file.
    ///
    /// The Quarantine tab can add one — see `GuiApp::allow_here` — without the
    /// user ever opening Settings, and this is how the draft is told. It goes
    /// into **both** copies, and both are needed:
    ///
    /// * Leaving `original` alone would make the draft read as dirty by exactly
    ///   that one line, so the Settings tab would offer to save a change nobody
    ///   made.
    /// * Leaving `edited` alone is the worse one: the next Save would write the
    ///   configuration from before this call, and the exclusion — already saved
    ///   once — would be gone from the file.
    ///
    /// Edits already in the draft are preserved, because this adds a line to
    /// both sides of the comparison rather than replacing either.
    pub fn note_exclusion(&mut self, path: &std::path::Path) {
        for config in [&mut self.edited, &mut self.original] {
            if !config.general.exclusions.iter().any(|held| held == path) {
                config.general.exclusions.push(path.to_path_buf());
            }
        }
    }

    /// Whether anything has been changed.
    pub fn is_dirty(&self) -> bool {
        self.edited != self.original
    }

    /// Throw the edits away.
    pub fn revert(&mut self) {
        self.edited = self.original.clone();
    }

    /// Accept the edits as the new baseline, after they have been saved.
    pub fn committed(&mut self) {
        self.original = self.edited.clone();
    }

    /// Whether the edited configuration is one the engine would accept.
    ///
    /// The engine's own validation, not a second copy of it: the window must
    /// refuse exactly what the loader refuses, and a window with a slightly
    /// different idea of a valid threshold is a window that writes a file that
    /// stops the product from starting.
    pub fn validate(&self) -> Result<(), String> {
        self.edited.validate().map_err(|error| error.to_string())
    }
}

/// How a quarantine listing is ordered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VaultSort {
    /// Most recently taken first. The default, because the thing a user is
    /// looking for is nearly always the thing that just happened.
    #[default]
    Newest,
    /// File name, A to Z.
    Name,
    /// Largest first.
    Size,
    /// Worst verdict first, matching the console's listing.
    Worst,
}

impl VaultSort {
    /// The name shown in the sort control.
    pub const fn label(self) -> &'static str {
        match self {
            VaultSort::Newest => "Newest",
            VaultSort::Name => "Name",
            VaultSort::Size => "Size",
            VaultSort::Worst => "Worst",
        }
    }

    /// Every order, in the order the control offers them.
    pub const ALL: [VaultSort; 4] = [
        VaultSort::Newest,
        VaultSort::Name,
        VaultSort::Size,
        VaultSort::Worst,
    ];
}

/// How the quarantine tab is narrowed and ordered.
///
/// The same shape as [`crate::filter::Filter`] and deliberately not the same
/// type: a vault entry and a scan finding share a verdict and a path and
/// nothing else, and one filter type that had to work for both would be a
/// filter with half its fields meaningless half the time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultView {
    /// Show only entries whose file name or original path contains this,
    /// ignoring case.
    pub query: String,
    /// How to order what is left.
    pub sort: VaultSort,
}

impl VaultView {
    /// Whether this view is hiding anything.
    pub fn is_active(&self) -> bool {
        !self.query.trim().is_empty() || self.sort != VaultSort::Newest
    }

    /// Put the view back to showing everything, in the default order.
    ///
    /// Both halves, not just the query: a user who clicked Clear and still saw
    /// a filtered list would have been told the control did something it did
    /// not do.
    pub fn clear(&mut self) {
        self.query.clear();
        self.sort = VaultSort::Newest;
    }

    /// Whether one entry passes.
    pub fn matches(&self, entry: &QuarantineEntry) -> bool {
        crate::filter::path_matches(&entry.file_name, &self.query)
            || crate::filter::path_matches(&entry.original_path.to_string_lossy(), &self.query)
    }

    /// Apply this view to the vault's entries.
    pub fn apply<'a>(&self, entries: &'a [QuarantineEntry]) -> Vec<&'a QuarantineEntry> {
        let mut shown: Vec<&QuarantineEntry> =
            entries.iter().filter(|entry| self.matches(entry)).collect();
        shown.sort_by(|a, b| {
            let by_name = || a.file_name.to_lowercase().cmp(&b.file_name.to_lowercase());
            match self.sort {
                VaultSort::Newest => b.quarantined_at.cmp(&a.quarantined_at).then_with(by_name),
                VaultSort::Name => by_name(),
                VaultSort::Size => b.size.cmp(&a.size).then_with(by_name),
                VaultSort::Worst => severity_rank(b.severity)
                    .cmp(&severity_rank(a.severity))
                    .then_with(|| b.quarantined_at.cmp(&a.quarantined_at))
                    .then_with(by_name),
            }
        });
        shown
    }
}

/// How bad a severity is, for ordering. Never sorted on directly — a severity
/// is a property of a finding, and only this listing ever needs to rank one.
const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{Digests, ScanStats, ScanTarget, VerdictThresholds};
    use av_quarantine::{EntrySource, QuarantineContext, QuarantineId};

    fn report() -> ScanReport {
        let mut report = ScanReport::new(ScanTarget::Directory("C:\\scan".into()));
        report.stats = ScanStats {
            files_scanned: 10,
            ..ScanStats::default()
        };
        report
    }

    fn progress(done: u64, total: u64, elapsed: Duration) -> Progress {
        Progress {
            files_done: done,
            files_total: total,
            files_found: 0,
            walking: false,
            bytes_found: 0,
            bytes_done: 0,
            findings: 0,
            current: String::new(),
            elapsed,
        }
    }

    /// A progress value from the walk phase, where the found count and the size
    /// of what was found are the only two numbers that exist.
    fn walking_progress(found: u64, bytes: u64, elapsed: Duration) -> Progress {
        Progress {
            walking: true,
            files_found: found,
            bytes_found: bytes,
            ..progress(0, 0, elapsed)
        }
    }

    fn entry(name: &str, severity: Severity, size: u64, taken: i64) -> QuarantineEntry {
        let context = QuarantineContext {
            severity,
            verdict: Verdict::Malicious,
            ..QuarantineContext::default()
        };
        let mut entry = QuarantineEntry::new(
            QuarantineId::from_bytes([name.len() as u8; 16]),
            format!(r"C:\Users\me\Downloads\{name}"),
            size,
            Digests::default(),
            &context,
        );
        entry.quarantined_at = chrono::DateTime::from_timestamp(taken, 0).unwrap_or_default();
        entry.source = EntrySource::Scan;
        entry
    }

    // -- the phase machine ---------------------------------------------------

    /// The state the window puts itself in when it starts a scan: a running
    /// state holding the scanning thread's own handle.
    ///
    /// Built here rather than through a constructor on [`ScanState`], because
    /// the handle belongs to the job the window has just started — it comes out
    /// of `ScanJob::start` and the window adopts it, which is the only way the
    /// Stop button and the scanning thread can be looking at one flag. There is
    /// therefore no way for [`ScanState`] itself to mint one.
    fn running() -> (ScanState, ScanHandle) {
        let handle = ScanHandle::new();
        (ScanState::Running(handle.clone()), handle)
    }

    #[test]
    fn a_window_opens_idle_and_can_start() {
        let state = ScanState::default();
        assert_eq!(state.phase(), Phase::Idle);
        assert!(!state.is_running());
        assert!(state.can_start());
        assert!(state.report().is_none());
        assert!(state.progress().is_none());
    }

    #[test]
    fn a_running_scan_offers_its_handle_and_refuses_a_second_start() {
        let (state, handle) = running();
        assert_eq!(state.phase(), Phase::Running);
        assert!(state.is_running());
        assert!(!state.can_start(), "a second scan is refused");
        assert_eq!(state.handle().map(ScanHandle::stop_requested), Some(false));

        // The window's handle and the worker's handle are the same flag.
        handle.request_stop();
        assert!(state.handle().expect("still running").stop_requested());
    }

    #[test]
    fn a_finished_scan_keeps_its_report_and_can_be_started_again() {
        let (mut state, _handle) = running();
        state.finish(report());
        assert_eq!(state.phase(), Phase::Finished);
        assert!(state.can_start());
        assert_eq!(state.report().map(|r| r.stats.files_scanned), Some(10));
        assert!(state.progress().is_none());
        assert!(state.handle().is_none());
    }

    #[test]
    fn a_scan_that_could_not_run_says_why_and_can_be_retried() {
        let mut state = ScanState::default();
        state.fail("no rule database was found");
        assert_eq!(state.phase(), Phase::Failed);
        assert!(state.can_start());
        assert!(state.report().is_none());
        assert!(state.summary().contains("no rule database was found"));
        // And a scan can still be started from a failure, which is the point of
        // the state existing rather than the window refusing to go on.
        assert!(state.can_start());
    }

    #[test]
    fn a_cancelled_scan_is_a_finished_scan_that_says_it_was_cancelled() {
        // Not a phase of its own. The report of a stopped scan is still a
        // report, and throwing it away because the user stopped it would lose
        // everything that had already been found.
        let (mut state, handle) = running();
        assert_eq!(state.cancelled_note(), None);

        handle.request_stop();
        assert!(state
            .cancelled_note()
            .is_some_and(|note| note.contains("Stopping")));

        let mut stopped = report();
        stopped.cancelled = true;
        stopped.stats.files_scanned = 4;
        state.finish(stopped);
        assert_eq!(state.phase(), Phase::Finished);
        let note = state.cancelled_note().expect("a stopped scan says so");
        assert!(note.contains("not the whole target"), "{note}");
        assert!(state.summary().starts_with("Stopped early:"));
    }

    #[test]
    fn a_finished_scan_that_ran_to_the_end_has_no_cancellation_note() {
        let (mut state, _handle) = running();
        state.finish(report());
        assert!(state.cancelled_note().is_none());
        assert!(!state.summary().starts_with("Stopped early:"));
    }

    // -- the shared handle ---------------------------------------------------

    #[test]
    fn the_handle_counts_what_the_scan_thread_records() {
        let handle = ScanHandle::new();
        handle.end_walk(3);
        handle.file_done(r"C:\a.exe", 100);
        handle.found();
        handle.file_done(r"C:\b.exe", 200);

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.files_done, 2);
        assert_eq!(snapshot.files_total, 3);
        assert_eq!(snapshot.bytes_done, 300);
        assert_eq!(snapshot.findings, 1);
        assert_eq!(snapshot.current, r"C:\b.exe");
    }

    #[test]
    fn a_fresh_handle_has_nothing_in_it_and_has_not_been_stopped() {
        let snapshot = ScanHandle::default().snapshot();
        assert_eq!(snapshot.files_done, 0);
        assert_eq!(snapshot.files_total, 0);
        assert_eq!(snapshot.bytes_done, 0);
        assert_eq!(snapshot.findings, 0);
        assert!(snapshot.current.is_empty());
        assert!(!ScanHandle::default().stop_requested());
    }

    #[test]
    fn the_current_path_stops_being_updated_once_a_stop_is_asked_for() {
        // By the time a stop has been requested the only thing the user is
        // watching for is the stop landing, and the path is the one write on
        // the scanning path that allocates.
        let handle = ScanHandle::new();
        handle.file_done(r"C:\a.exe", 1);
        handle.request_stop();
        handle.file_done(r"C:\b.exe", 1);
        assert_eq!(handle.snapshot().current, r"C:\a.exe");
        assert_eq!(handle.snapshot().files_done, 2, "the count still advances");
    }

    #[test]
    fn the_elapsed_time_is_the_handles_own_clock() {
        let handle = ScanHandle::new();
        let later = Instant::now() + Duration::from_secs(30);
        let snapshot = handle.snapshot_at(later);
        assert!(snapshot.elapsed >= Duration::from_secs(30));
        assert!(snapshot.elapsed < Duration::from_secs(31));
    }

    #[test]
    fn two_handles_from_one_scan_read_the_same_counters() {
        // What makes the worker and the window able to hold one each.
        let worker = ScanHandle::new();
        let window = worker.clone();
        worker.end_walk(1);
        worker.file_done("a", 7);
        let snapshot = window.snapshot();
        assert_eq!(snapshot.files_done, 1);
        assert_eq!(snapshot.bytes_done, 7);
        assert!(!window.stop_requested());
        worker.request_stop();
        assert!(window.stop_requested());
    }

    // -- progress arithmetic -------------------------------------------------

    #[test]
    fn a_total_of_zero_is_not_a_division_and_not_a_percentage() {
        let unknown = progress(7, 0, Duration::from_secs(5));
        assert_eq!(unknown.fraction(), None);
        assert_eq!(unknown.percent(), None);
        assert_eq!(unknown.remaining(), None);
        let line = unknown.line();
        assert!(line.contains("7 files so far"), "{line}");
        assert!(!line.contains('%'), "{line}");
        assert!(!line.contains("of 0"), "{line}");
    }

    #[test]
    fn a_zero_duration_produces_no_rate_and_no_estimate() {
        // The state of a scan in its first frame. It must not print a rate
        // derived from a division by zero, and it must not print "inf/s".
        let just_started = progress(1, 100, Duration::ZERO);
        assert_eq!(just_started.rate(), None);
        assert_eq!(just_started.remaining(), None);
        let line = just_started.line();
        assert!(!line.contains("/s"), "{line}");
        assert!(!line.contains("left"), "{line}");
        assert!(!line.contains("inf"), "{line}");
        assert!(!line.contains("NaN"), "{line}");
    }

    #[test]
    fn a_rate_is_withheld_until_there_is_enough_time_to_measure_one() {
        let too_soon = progress(10, 100, Duration::from_millis(999));
        assert_eq!(too_soon.rate(), None);
        let measurable = progress(10, 100, Duration::from_secs(2));
        assert_eq!(measurable.rate(), Some(5));
        // No files done yet is also not a rate, whatever the clock says.
        assert_eq!(progress(0, 100, Duration::from_secs(60)).rate(), None);
    }

    #[test]
    fn the_estimate_is_a_straight_line_and_is_not_offered_when_there_is_none() {
        let half = progress(50, 100, Duration::from_secs(10));
        assert_eq!(half.remaining(), Some(Duration::from_secs(10)));
        // Done is not an estimate of zero seconds.
        let done = progress(100, 100, Duration::from_secs(20));
        assert_eq!(done.remaining(), None);
        assert_eq!(done.percent(), Some(100));
        // Past the end is not a negative estimate.
        assert_eq!(
            progress(120, 100, Duration::from_secs(20)).remaining(),
            None
        );
    }

    #[test]
    fn an_estimate_longer_than_a_day_is_capped_rather_than_believed() {
        // One file in an hour, with a million to go, is an arithmetic answer
        // and not a useful one.
        let slow = progress(1, 1_000_000, Duration::from_secs(3_600));
        assert_eq!(slow.remaining(), Some(Duration::from_secs(86_400)));
    }

    #[test]
    fn a_progress_line_says_the_four_things_a_user_wants() {
        let p = Progress {
            files_done: 412,
            files_total: 1_204,
            bytes_done: 3_400_000_000,
            findings: 2,
            current: r"C:\Users\me\Downloads\a.exe".to_owned(),
            elapsed: Duration::from_secs(10),
            ..progress(0, 0, Duration::ZERO)
        };
        let line = p.line();
        assert!(line.contains("412 of 1,204 files (34%)"), "{line}");
        assert!(line.contains("3.4 GB"), "{line}");
        assert!(line.contains("2 findings"), "{line}");
        assert!(line.contains("a.exe"), "{line}");
        // And nothing that reports a state it is not in.
        assert!(!line.contains("no findings"), "{line}");
    }

    #[test]
    fn the_walk_phase_reports_what_the_walk_has_found_and_not_a_percentage() {
        // Before the walk ends there is no total, so there can be no
        // percentage; what there is, is a number going up.
        let walking = walking_progress(12_304, 3_400_000_000, Duration::from_secs(10));
        assert_eq!(walking.percent(), None);
        assert_eq!(walking.rate(), None, "the scan has not started");
        assert_eq!(walking.walk_rate(), Some(1_230));
        let line = walking.line();
        assert!(line.contains("looking for files…"), "{line}");
        assert!(line.contains("12,304 found so far"), "{line}");
        assert!(line.contains("1,230/s"), "{line}");
        assert!(!line.contains('%'), "{line}");
        assert!(!line.contains("no findings"), "{line}");
    }

    #[test]
    fn the_walk_line_shows_the_size_of_what_it_found_and_not_the_bytes_it_read() {
        // Nothing has been read during the walk, so `bytes_done` is zero for
        // every walk that has ever run — and the line printed `bytes_done`, so
        // every walk that ever ran drew `0 B` beside a count of thousands of
        // files. A user read that as a scan that had found nothing, and they
        // were reading it correctly: the number was not a count of anything.
        let walking = walking_progress(3, 3_400_000_000, Duration::from_secs(10));
        assert_eq!(walking.bytes_done, 0, "no file has been opened yet");
        let line = walking.line();
        assert!(line.contains("3.4 GB"), "{line}");
        assert!(!line.contains("0 B"), "{line}");
    }

    #[test]
    fn the_walk_count_survives_the_change_over_to_the_scan() {
        // The handover between the two phases, which is where a progress bar
        // either starts correctly or jumps: the total is set and the walking
        // flag is cleared in one step, and the found count is left alone
        // because the walk really did find that many.
        let handle = ScanHandle::new();
        handle.begin_walk();
        handle.file_found(100);
        handle.file_found(200);
        handle.file_found(300);
        assert!(handle.snapshot().walking);
        assert_eq!(handle.snapshot().files_found, 3);
        assert_eq!(handle.snapshot().bytes_found, 600);

        handle.end_walk(3);
        let after = handle.snapshot();
        assert!(!after.walking);
        assert_eq!(after.files_total, 3);
        assert_eq!(after.files_found, 3);
        // The walk's byte count is a fact about the tree, not about reading, so
        // it is left standing across the handover exactly as the count is.
        assert_eq!(after.bytes_found, 600);
        assert_eq!(after.bytes_done, 0, "the scan has not read anything yet");
        assert_eq!(after.percent(), Some(0));
        assert!(
            after.line().contains("0 of 3 files (0%)"),
            "{}",
            after.line()
        );
    }

    #[test]
    fn a_progress_line_with_nothing_found_says_so_in_words() {
        let p = Progress {
            findings: 0,
            ..progress(1, 2, Duration::from_secs(2))
        };
        assert!(p.line().contains("no findings"), "{}", p.line());
    }

    #[test]
    fn one_finding_is_not_one_findings() {
        let p = Progress {
            findings: 1,
            ..progress(1, 2, Duration::from_secs(2))
        };
        assert!(p.line().contains("1 finding"), "{}", p.line());
    }

    #[test]
    fn a_long_path_in_the_progress_line_is_shortened_from_the_front() {
        // The progress line shares a row with the numbers, so an unbounded path
        // would push them off the edge of the window.
        let p = Progress {
            current: r"C:\Users\me\Projects\a\very\deep\tree\that\goes\on\and\on\file.exe"
                .to_owned(),
            ..progress(1, 2, Duration::from_secs(2))
        };
        let line = p.line();
        assert!(line.contains('…'), "{line}");
        assert!(line.ends_with("file.exe"), "{line}");
    }

    // -- settings ------------------------------------------------------------

    #[test]
    fn a_draft_starts_clean_and_knows_when_it_is_not() {
        let mut draft = SettingsDraft::new(AvConfig::default());
        assert!(!draft.is_dirty());
        draft.edited_mut().scanning.recursive = false;
        assert!(draft.is_dirty());
        assert!(
            draft.original.scanning.recursive,
            "the baseline is untouched"
        );
    }

    #[test]
    fn reverting_puts_back_what_was_there() {
        let mut draft = SettingsDraft::new(AvConfig::default());
        draft.edited_mut().scanning.threads = 99;
        draft.revert();
        assert!(!draft.is_dirty());
        assert_eq!(draft.edited().scanning.threads, 0);
    }

    #[test]
    fn committing_makes_the_edits_the_new_baseline() {
        let mut draft = SettingsDraft::new(AvConfig::default());
        draft.edited_mut().scanning.threads = 8;
        assert!(draft.is_dirty());
        draft.committed();
        assert!(!draft.is_dirty());
        assert_eq!(draft.original.scanning.threads, 8);
    }

    #[test]
    fn validation_is_the_engines_own_and_refuses_what_the_loader_refuses() {
        // The window must refuse exactly what `AvConfig::validate` refuses: a
        // configuration this window wrote and the loader then rejected would
        // stop the product from starting.
        let mut draft = SettingsDraft::new(AvConfig::default());
        assert!(draft.validate().is_ok());

        let thresholds = VerdictThresholds {
            suspicious: 200,
            malicious: 100,
        };
        draft.edited_mut().scanning.thresholds = thresholds;
        let error = draft
            .validate()
            .expect_err("inverted thresholds are refused");
        assert!(error.contains("strictly less"), "{error}");
        // And the engine agrees, which is the point of calling it rather than
        // reimplementing it.
        assert!(draft.edited().validate().is_err());

        draft.edited_mut().scanning.archive_depth = 17;
        assert!(draft.validate().is_err());
        draft.edited_mut().scanning.archive_depth = 16;
        draft.edited_mut().scanning.thresholds = VerdictThresholds::default();
        assert!(draft.validate().is_ok());
    }

    // -- the vault listing ---------------------------------------------------

    #[test]
    fn the_vault_is_newest_first_by_default() {
        let entries = vec![
            entry("old.exe", Severity::Low, 10, 1_000),
            entry("new.exe", Severity::Critical, 10, 3_000),
            entry("mid.exe", Severity::High, 10, 2_000),
        ];
        let shown = VaultView::default().apply(&entries);
        let names: Vec<&str> = shown.iter().map(|e| e.file_name.as_str()).collect();
        assert_eq!(names, vec!["new.exe", "mid.exe", "old.exe"]);
        assert!(!VaultView::default().is_active());
    }

    #[test]
    fn the_vault_can_be_ordered_by_name_size_and_severity() {
        let entries = vec![
            entry("b.exe", Severity::Low, 300, 1_000),
            entry("a.exe", Severity::Critical, 100, 3_000),
            entry("c.exe", Severity::High, 200, 2_000),
        ];
        let names = |sort| -> Vec<String> {
            VaultView {
                sort,
                ..VaultView::default()
            }
            .apply(&entries)
            .iter()
            .map(|e| e.file_name.clone())
            .collect()
        };
        assert_eq!(names(VaultSort::Name), vec!["a.exe", "b.exe", "c.exe"]);
        assert_eq!(names(VaultSort::Size), vec!["b.exe", "c.exe", "a.exe"]);
        assert_eq!(names(VaultSort::Worst), vec!["a.exe", "c.exe", "b.exe"]);
    }

    #[test]
    fn the_vault_search_matches_the_name_or_the_place_it_came_from() {
        let entries = vec![
            entry("invoice.exe", Severity::High, 10, 1_000),
            entry("photo.jpg", Severity::Low, 10, 2_000),
        ];
        let by_name = VaultView {
            query: "INVOICE".into(),
            ..VaultView::default()
        };
        assert_eq!(by_name.apply(&entries).len(), 1);
        // The path is the same for both in this fixture, so a query on it
        // matches both — which is the useful behaviour: a user searching for a
        // directory wants everything taken out of it.
        let by_path = VaultView {
            query: "downloads".into(),
            ..VaultView::default()
        };
        assert_eq!(by_path.apply(&entries).len(), 2);
        assert!(by_path.is_active());
        let nothing = VaultView {
            query: "no-such-file".into(),
            ..VaultView::default()
        };
        assert!(nothing.apply(&entries).is_empty());
    }

    #[test]
    fn every_vault_order_has_a_label_and_a_fixed_set() {
        assert_eq!(VaultSort::ALL.len(), 4);
        for sort in VaultSort::ALL {
            assert!(!sort.label().is_empty());
        }
    }

    #[test]
    fn an_entry_severity_is_ranked_from_info_to_critical() {
        assert_eq!(severity_rank(Severity::Info), 0);
        assert_eq!(severity_rank(Severity::Critical), 4);
        assert!(severity_rank(Severity::High) > severity_rank(Severity::Medium));
    }

    #[test]
    fn a_report_with_no_detections_still_produces_a_summary_line() {
        // The state the Scan tab is in immediately after a clean scan.
        let (mut state, _handle) = running();
        state.finish(report());
        let summary = state.summary();
        assert!(summary.contains("Scanned 10 files"), "{summary}");
        assert!(summary.contains("nothing was found"), "{summary}");
    }
}
