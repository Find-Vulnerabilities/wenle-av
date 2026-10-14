//! The scanning loop: events go in, findings come out.
//!
//! # The shape
//!
//! One thread per watched root reads the kernel's notification buffer and sends
//! [`WatchEvent`]s down a channel (see [`crate::watch`]). This module is the
//! consumer: it receives those events, decides which of them name a file worth
//! scanning, waits for the writes to stop, scans, and reports. It is a second
//! thread and not the same one, because a scan takes milliseconds to seconds and
//! a watch thread that stopped reading its buffer for that long would overflow
//! it — which is the failure mode the re-scan path exists to clean up after.
//!
//! # The loop, and why it is not a blocking `recv`
//!
//! A debounced scan is due at a particular instant, and a thread blocked in
//! `recv` on an empty channel would not wake for it. The loop therefore selects
//! between "an event arrived" and "the earliest deadline has passed", with the
//! wait capped at [`POLL_MS`] so a stop request is noticed within a quarter of a
//! second rather than at the next event.
//!
//! # One scan at a time, deliberately
//!
//! Scans run on this one thread, in deadline order. The alternative — a pool of
//! `worker_threads` — was not taken, for reasons about what a realtime scanner
//! is for rather than about effort. A scan is the most processor-hungry thing
//! the product does and it runs while the user is working, so a pool sized to
//! the core count would take the machine for the duration of a `%TEMP%` storm.
//! And the work is bounded at both ends already: the debounce window collapses a
//! burst into one scan per path, and a tree walk stops at [`RESCAN_FILE_LIMIT`].
//! The queue this thread has to drain is small by construction rather than by
//! luck. What a caller who configured `worker_threads` should know is that it
//! changes nothing here, which is why [`WatchPlan::unhonoured`] says so.
//!
//! # What happens when the kernel says it dropped events
//!
//! [`WatchEvent::Lost`] is turned into a walk of the affected tree: every file
//! under it, up to the limit, scanned, and the findings reported as a
//! [`Rescan`]. That is the documented response to an overflow, and it is why
//! [`WatchEvent`] makes the case impossible to ignore — the alternative, a log
//! line and a hole, is a silent gap in a protection the product claims to be
//! running. The same walk covers a directory that arrives whole, because a
//! directory move reports one event for the directory and nothing for what is
//! inside it.
//!
//! # What a caller can tell from the statistics
//!
//! [`ServiceStats`] counts what happened and not only what was found: how many
//! events arrived, how many were absorbed by the window, how many scans that
//! saved, how many files could not be read, how many batches the kernel dropped.
//! A watcher with thousands of events and no scans has an exclusion set doing
//! its job. A watcher with thousands of unreadable files is watching a directory
//! it should not be.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{select, Receiver, Sender};

use av_core::config::RealtimeConfig;
use av_core::scan::{FileScanReport, ScanOptions};
use av_core::AvPaths;
use av_quarantine::{EntrySource, QuarantineContext, QuarantinePolicy, QuarantineVault};
use av_scan::ScanEngine;

use crate::debounce::{effective_window, Debouncer};
use crate::error::{RealtimeError, Result};
use crate::filter::{is_reportable, is_scan_candidate, ExclusionSet};
use crate::finding::{disposition, Disposition, Finding, Phase};
use crate::notify::{Change, FileAction};
use crate::plan::{WatchPlan, RESCAN_FILE_LIMIT};
use crate::watch::{DirectoryWatch, Lost, WatchEvent, POLL_MS};

/// Which component this crate files its quarantines under.
///
/// [`EntrySource::Realtime`] because that is the word the product and the
/// configuration use for this subsystem, and the vault's list groups by it. It
/// is *not* a claim that anything was blocked — see [`Phase::observed`], which
/// is what turns this name plus [`RealtimeService::BLOCKS_NOTHING`] into the
/// honest [`Phase::AfterTheFact`].
const SOURCE: EntrySource = EntrySource::Realtime;

/// What the service reports.
#[derive(Debug)]
pub enum RealtimeEvent {
    /// A file that appeared was found to be a detection.
    Detected(Finding),
    /// The kernel dropped events for a tree, and the tree has been re-scanned.
    ///
    /// The findings are carried here rather than sent as separate
    /// [`RealtimeEvent::Detected`] events, because the caller has to be able to
    /// tell "we caught this as it arrived" from "we found this afterwards in the
    /// catch-up walk". The second means there was a window in which nothing was
    /// watched, and a report that merged the two would hide it.
    Rescanned(Rescan),
    /// A root is no longer being watched.
    ///
    /// The coverage the caller believes it has is now smaller than it believes.
    WatchFailed {
        /// The root that is no longer watched.
        root: PathBuf,
        /// Why the watch ended.
        error: RealtimeError,
    },
}

/// The result of making up for lost events.
#[derive(Debug)]
pub struct Rescan {
    /// The tree that was walked.
    pub root: PathBuf,
    /// Why the walk was needed.
    pub because: Lost,
    /// How many files were examined.
    pub files: usize,
    /// Directories the walk could not list.
    ///
    /// A hole in the walk, and a second reason the catch-up is not a clean bill
    /// of health: a subdirectory whose permissions or lock state refused the
    /// enumeration was not examined, and neither was anything under it.
    pub unreadable: usize,
    /// True when the walk stopped at [`RESCAN_FILE_LIMIT`] with files still
    /// unexamined.
    ///
    /// A caller that shows this must show it as "the catch-up scan was
    /// incomplete", never as "the catch-up scan found nothing else".
    pub truncated: bool,
    /// What the walk found.
    pub findings: Vec<Finding>,
}

/// Running totals for one session of watching.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceStats {
    /// Events the kernel reported, one per record, before any filtering.
    pub events: u64,
    /// Events dropped because the path is in the exclusion set.
    pub excluded: u64,
    /// Events that named a file worth scanning, and started a wait.
    pub waits_started: u64,
    /// Events that arrived while a wait for the same path was running, and so
    /// cost nothing.
    ///
    /// This is the number that says what the debounce window bought: each of
    /// these would have been a scan of a file that was still being written.
    pub events_coalesced: u64,
    /// Deletes seen in a watched tree.
    ///
    /// Counted although a delete is never a scan candidate, because a burst of
    /// them across one tree is what an encrypting ransomware looks like from the
    /// outside, and this is the only component that can see it.
    pub deletes: u64,
    /// Files actually scanned.
    pub files_scanned: u64,
    /// Paths that were due and had already gone when their turn came: a file
    /// written and deleted inside the window. Nothing to scan and nothing to
    /// report.
    pub vanished: u64,
    /// Files the engine could not read. Counted rather than ignored, because
    /// this is the number that says how much of the tree was really examined.
    pub unreadable: u64,
    /// Files taken into the vault.
    pub quarantined: u64,
    /// Bytes taken into the vault.
    pub quarantined_bytes: u64,
    /// Files the engine called a detection and the vault would not take.
    pub quarantine_failed: u64,
    /// Tree walks caused by lost events.
    pub rescans: u64,
    /// Roots whose watch ended.
    pub watch_failures: u64,
    /// Events seen per watched root, so a machine with one busy tree can be told
    /// from a busy machine.
    pub per_root: BTreeMap<PathBuf, u64>,
}

impl ServiceStats {
    /// How many scans the debounce window avoided.
    ///
    /// Not events minus scans: a burst of ten writes to one path is nine
    /// coalesced events and one scan, and this is the nine.
    pub fn scans_avoided(&self) -> u64 {
        self.events_coalesced
    }

    /// True when every file the engine was asked about was read.
    pub fn read_everything(&self) -> bool {
        self.unreadable == 0
    }

    /// Fold another set of totals into this one.
    pub fn merge(&mut self, other: &ServiceStats) {
        self.events += other.events;
        self.excluded += other.excluded;
        self.waits_started += other.waits_started;
        self.events_coalesced += other.events_coalesced;
        self.deletes += other.deletes;
        self.files_scanned += other.files_scanned;
        self.vanished += other.vanished;
        self.unreadable += other.unreadable;
        self.quarantined += other.quarantined;
        self.quarantined_bytes += other.quarantined_bytes;
        self.quarantine_failed += other.quarantine_failed;
        self.rescans += other.rescans;
        self.watch_failures += other.watch_failures;
        for (root, count) in &other.per_root {
            *self.per_root.entry(root.clone()).or_default() += count;
        }
    }
}

/// A running realtime watcher.
///
/// Owning the whole thing behind one `start` keeps the two threads' lifetimes
/// tied together: a watch whose events nobody reads would fill its channel and
/// then block, and a scanner with no watch would sit in `recv` until the channel
/// disconnected. Neither can happen to a caller that holds one of these.
///
/// [`RealtimeService::stop`] is the clean end. Dropping the value stops the
/// threads without waiting for them, which is right at process exit and wrong
/// anywhere else — the scanner's statistics are lost with it.
///
/// That claim is the `Drop` below and was false before it existed: neither
/// thread's stop flag was set by dropping, so the scanner stayed in its select
/// loop and the per-root watch threads stayed alive, all of them holding their
/// own `Arc` clone of a flag nobody had set. See [`DirectoryWatch`] for the same
/// defect on the watch side, where the documentation had made the same promise.
#[derive(Debug)]
pub struct RealtimeService {
    /// What the scanner sends.
    events: Receiver<RealtimeEvent>,
    /// Set by `stop`; both threads read it.
    stop: Arc<AtomicBool>,
    /// The scanner.
    worker: Option<std::thread::JoinHandle<()>>,
    /// The statistics the scanner sends as it ends.
    totals: Receiver<ServiceStats>,
    /// The watches. Stopped first in `stop`, so no event can arrive for a
    /// scanner that is on its way out.
    watch: Option<DirectoryWatch>,
    /// The plan this service was started with, including what it could not do.
    plan: WatchPlan,
}

impl Drop for RealtimeService {
    /// Stop both halves without waiting for either.
    ///
    /// The flag is what the scanner's loop tests at the top of every pass, and
    /// it is the only thing that ends it once its event channel has a live sender
    /// left in the watch — so it is set first and unconditionally. Dropping the
    /// watch then sets the watch's own flag through its `Drop`, which ends the
    /// per-root threads within [`crate::watch::POLL_MS`]; taking it out of the
    /// `Option` first is what keeps this from depending on field order, which a
    /// `Drop` implementation has no business depending on.
    ///
    /// The scanner is *not* joined, which is the documented difference from
    /// [`RealtimeService::stop`]: the statistics channel is left unread and the
    /// totals are lost. That is the right trade at process exit, where joining
    /// would only delay it, and the wrong one anywhere the numbers matter.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        drop(self.watch.take());
    }
}

impl RealtimeService {
    /// The one thing this crate cannot do, stated where it is used.
    ///
    /// A user-mode watcher cannot refuse a write, so every finding it produces
    /// is [`Phase::AfterTheFact`]. The phase is derived from this flag and not
    /// hardcoded, so that the day a kernel driver feeds this same code the one
    /// value that has to change is findable by its name.
    pub const BLOCKS_NOTHING: bool = false;

    /// Build a plan and start watching it.
    ///
    /// The engine is shared (`Arc`) because it holds the compiled rule database,
    /// which is large and read-only; a copy per watched root would be a copy of
    /// the whole signature set.
    ///
    /// The vault is opened here and moved into the scanner thread. It is the
    /// same vault the rest of the product uses, and that is the point: a file
    /// this watcher takes has to appear in the user's quarantine list, and a
    /// second vault beside the real one would be a quarantine nobody can find.
    ///
    /// A disabled plan produces a running service with no watched roots rather
    /// than an error. `enabled = false` is a legitimate configuration, and a
    /// caller that treats it as a failure reports a broken installation to a
    /// user who turned the feature off deliberately. [`RealtimeService::plan`]
    /// says which of the two it is; [`RealtimeService::is_watching`] answers it
    /// in one word.
    ///
    /// # It does not scan what is already there
    ///
    /// `start` arms the watches and returns; the files already in `Downloads`
    /// when it is called are not examined, and none of them is reported. This is
    /// not an omission to be tidied up later, it is the division of labour the
    /// two halves of the product are built on. A watch reports what happens
    /// after it is armed — that is all `ReadDirectoryChangesW` can do, and
    /// `crate::watch` documents the measurement — so the existing tree is the
    /// full scanner's job, and the pair is what covers both directions. A
    /// caller that starts this service and reports the user as fully protected
    /// without having scanned the watched trees has claimed coverage that the
    /// watch, by construction, does not provide.
    pub fn start(
        config: &RealtimeConfig,
        paths: &AvPaths,
        engine: Arc<ScanEngine>,
        policy: QuarantinePolicy,
    ) -> Result<Self> {
        let plan = WatchPlan::from_config(config, paths);
        let exclusions = ExclusionSet::for_paths(paths);
        let window = effective_window(config.debounce_ms);
        let options = scan_options();
        let acts = acts_on_detections(config);

        // Opened before the watches start, so a vault that cannot be opened
        // fails the whole call. A watcher that scans and then cannot take what
        // it found is worse than no watcher: the user is told about a malicious
        // file which is then left where it is.
        let vault =
            QuarantineVault::open(paths.quarantine_dir.clone(), policy).map_err(|source| {
                RealtimeError::Vault {
                    root: paths.quarantine_dir.clone(),
                    source,
                }
            })?;

        let watch = DirectoryWatch::start(&plan)?;
        let (out_tx, events) = crossbeam_channel::unbounded();
        let (totals_tx, totals) = crossbeam_channel::bounded(1);
        let stop = Arc::new(AtomicBool::new(false));

        let worker = std::thread::Builder::new()
            .name("av-realtime-scanner".to_string())
            .spawn({
                let plan = plan.clone();
                let stop = Arc::clone(&stop);
                let watch_events = watch.events().clone();
                move || {
                    let mut vault = vault;
                    let scanner = Scanner {
                        engine: &engine,
                        vault: &mut vault,
                        exclusions: &exclusions,
                        options: &options,
                        acts_on_detections: acts,
                    };
                    let stats = run(&plan, scanner, &watch_events, &out_tx, &stop, window);
                    // The receiver is gone only when `stop` has already given up
                    // on this thread, and there is nothing to do about it then.
                    let _ = totals_tx.send(stats);
                }
            })
            .map_err(|source| RealtimeError::WorkerSpawn { source })?;

        Ok(Self {
            events,
            stop,
            worker: Some(worker),
            totals,
            watch: Some(watch),
            plan,
        })
    }

    /// The stream of findings.
    ///
    /// Disconnects when the scanner ends, which happens on `stop` or when every
    /// watch has failed.
    pub fn events(&self) -> &Receiver<RealtimeEvent> {
        &self.events
    }

    /// The plan being run, including the roots that were skipped and the
    /// settings this crate cannot honour.
    pub fn plan(&self) -> &WatchPlan {
        &self.plan
    }

    /// True when at least one directory is actually being watched.
    pub fn is_watching(&self) -> bool {
        self.watch.is_some() && !self.plan.roots.is_empty()
    }

    /// Stop watching, join the scanner, and return what it did.
    ///
    /// The order matters. The watches stop first, so no new event can arrive for
    /// a scanner on its way out. The scanner then finishes the paths already due
    /// and exits when its channel disconnects, and only then is it joined, so
    /// the totals are complete. A path still inside its debounce window when
    /// this is called is *not* scanned: the caller asked the watcher to stop, and
    /// a shutdown that first walked `%TEMP%` would not be a shutdown. Everything
    /// already scanned reaches [`RealtimeService::events`] before the totals
    /// reach this caller, because the events are sent as they happen.
    ///
    /// [`RealtimeError::WorkerLost`] means the scanner died without reporting —
    /// a panic inside a scan, most likely — and the totals are then unknown
    /// rather than zero. That is why this returns a `Result` and not a
    /// [`ServiceStats`] that would read as "it did nothing".
    pub fn stop(mut self) -> Result<ServiceStats> {
        if let Some(watch) = self.watch.take() {
            watch.stop();
        }
        self.stop.store(true, Ordering::SeqCst);
        let joined = self.worker.take().map(|worker| worker.join());
        match joined {
            Some(Err(_)) => Err(RealtimeError::WorkerLost),
            _ => self
                .totals
                .try_recv()
                .map_err(|_| RealtimeError::WorkerLost),
        }
    }
}

/// The scanner's half of the service, bundled so the loop can hold a mutable
/// vault and an immutable engine without threading six parameters through every
/// call.
struct Scanner<'a> {
    engine: &'a ScanEngine,
    vault: &'a mut QuarantineVault,
    exclusions: &'a ExclusionSet,
    options: &'a ScanOptions,
    /// Whether a confirmed detection is acted on. See [`crate::finding::disposition`].
    acts_on_detections: bool,
}

impl Scanner<'_> {
    /// Scan one file and decide what to do about it.
    ///
    /// `action` is the event that led here, or `None` for a file found by a tree
    /// walk.
    ///
    /// Returns `None` for everything not worth telling a user about: a clean
    /// file, a file already gone, a file that could not be read (counted in the
    /// statistics instead), and a path inside the exclusion set.
    fn file(
        &mut self,
        path: &Path,
        action: Option<FileAction>,
        stats: &mut ServiceStats,
    ) -> Option<Finding> {
        if self.exclusions.excludes(path) {
            stats.excluded += 1;
            return None;
        }

        // Nothing is held open across the scan: `scan_file` does its own read,
        // and a watcher that kept a handle on every file it looked at would lock
        // the files of the program it is watching.
        if !path.is_file() {
            // Gone between the event and the deadline — a temporary file, a
            // build artefact — or a reparse point this crate does not follow.
            stats.vanished += 1;
            return None;
        }

        let report = self.engine.scan_file(path, self.options);
        stats.files_scanned += 1;

        match disposition(report.verdict(), self.acts_on_detections) {
            Disposition::Ignore => None,
            Disposition::Count => {
                stats.unreadable += 1;
                None
            }
            Disposition::Report => Some(self.finding(&report, action)),
            Disposition::Quarantine => Some(self.quarantine(&report, path, action, stats)),
        }
    }

    /// Describe a report, without taking the file.
    fn finding(&self, report: &FileScanReport, action: Option<FileAction>) -> Finding {
        Finding::from_report(
            report,
            Phase::observed(SOURCE, RealtimeService::BLOCKS_NOTHING),
            action,
        )
    }

    /// Take a reported file into the vault, and describe what happened.
    ///
    /// A vault that refuses does not turn a detection into a success: the file is
    /// still at its path and still malicious, so the finding comes back with the
    /// reason attached for the caller to show.
    fn quarantine(
        &mut self,
        report: &FileScanReport,
        path: &Path,
        action: Option<FileAction>,
        stats: &mut ServiceStats,
    ) -> Finding {
        let finding = self.finding(report, action);
        // The note is what lets a user sort a vault list by "why": an entry the
        // watcher took at three in the morning should say so, and say which kind
        // of event brought it in.
        let context = QuarantineContext::from_report(report, SOURCE).with_note(format!(
            "found by the user-mode watcher on {} after the file appeared; not blocked",
            action.map_or("a re-scan", FileAction::as_str)
        ));
        match self.vault.quarantine_file(path, &context) {
            Ok(entry) => {
                stats.quarantined += 1;
                stats.quarantined_bytes += entry.size;
                finding.with_quarantine(entry.id)
            }
            Err(error) => {
                stats.quarantine_failed += 1;
                log::warn!(
                    "the detection at {} could not be quarantined: {error}",
                    path.display()
                );
                finding.with_quarantine_error(error.to_string())
            }
        }
    }

    /// Walk a tree and scan every file in it, up to `limit`.
    ///
    /// One routine for two jobs that are the same job: catching up after the
    /// kernel dropped events, and looking inside a directory that arrived whole
    /// because something moved it into a watched tree.
    fn tree(&mut self, root: &Path, limit: usize, stats: &mut ServiceStats) -> TreeOutcome {
        let mut outcome = TreeOutcome::default();
        // `follow_links(false)` is the default and is written out anyway: a
        // junction into a profile directory would turn one walk into a walk of
        // everything, and a junction into a parent into an endless one.
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                // A directory that cannot be listed is a hole in the walk,
                // counted and stepped over: one unreadable subdirectory must not
                // cost the rest of the tree.
                Err(error) => {
                    log::debug!("the walk of {} could not descend: {error}", root.display());
                    outcome.unreadable_entries += 1;
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            if self.exclusions.excludes(entry.path()) {
                continue;
            }
            if outcome.files >= limit {
                outcome.truncated = true;
                break;
            }
            outcome.files += 1;
            if let Some(finding) = self.file(entry.path(), None, stats) {
                outcome.findings.push(finding);
            }
        }
        outcome
    }
}

/// What one tree walk produced.
#[derive(Debug, Default)]
struct TreeOutcome {
    /// Files scanned.
    files: usize,
    /// True when the walk stopped at its limit.
    truncated: bool,
    /// Directories that could not be listed.
    unreadable_entries: usize,
    /// Detections.
    findings: Vec<Finding>,
}

/// The scanning loop.
///
/// Ends when the stop flag is set, or when every watch has ended, the channel has
/// disconnected, and no path is still waiting on a window.
fn run(
    plan: &WatchPlan,
    mut scanner: Scanner<'_>,
    events: &Receiver<WatchEvent>,
    out: &Sender<RealtimeEvent>,
    stop: &AtomicBool,
    window: Duration,
) -> ServiceStats {
    let mut debouncer = Debouncer::new(window);
    let mut stats = ServiceStats::default();
    let mut disconnected = false;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if disconnected && debouncer.pending_len() == 0 {
            // No watches left and nothing waiting: there is no future event and
            // no pending deadline, so waiting again would wait forever.
            break;
        }

        // Wait for an event, never longer than the next deadline or the poll
        // interval. An unbounded `recv` would sleep through both.
        let wait = match debouncer.next_deadline() {
            Some(deadline) => deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(u64::from(POLL_MS))),
            None => Duration::from_millis(u64::from(POLL_MS)),
        };

        select! {
            recv(events) -> message => match message {
                Ok(event) => handle(event, plan, &mut debouncer, &mut stats, out, &mut scanner),
                // Every watch has ended. The paths still inside their window are
                // scanned below before the loop ends, which is the difference
                // between a watcher that shuts down and one that drops work.
                Err(_) => disconnected = true,
            },
            // Nothing arrived; the deadlines below are what this wake-up is for.
            default(wait) => {}
        }

        for path in debouncer.due(Instant::now()) {
            scan_due(&path, &mut scanner, &mut stats, out);
        }
    }

    stats
}

/// Act on one event from a watch thread.
fn handle(
    event: WatchEvent,
    plan: &WatchPlan,
    debouncer: &mut Debouncer,
    stats: &mut ServiceStats,
    out: &Sender<RealtimeEvent>,
    scanner: &mut Scanner<'_>,
) {
    match event {
        WatchEvent::Changed { root, changes } => {
            *stats.per_root.entry(root).or_default() += changes.len() as u64;
            let now = Instant::now();
            for change in changes {
                observe(&change, plan, debouncer, stats, now);
            }
        }
        WatchEvent::Lost { root, because } => {
            // The documented response to a dropped batch: walk the tree. See the
            // module documentation for why this is not a log line.
            stats.rescans += 1;
            let outcome = scanner.tree(&root, RESCAN_FILE_LIMIT, stats);
            let _ = out.send(RealtimeEvent::Rescanned(Rescan {
                root,
                because,
                files: outcome.files,
                unreadable: outcome.unreadable_entries,
                truncated: outcome.truncated,
                findings: outcome.findings,
            }));
        }
        WatchEvent::Failed { root, error } => {
            stats.watch_failures += 1;
            let _ = out.send(RealtimeEvent::WatchFailed { root, error });
        }
    }
}

/// Decide what one change means for the debouncer and the statistics.
///
/// Split out from [`handle`] so the decision is one function with one input
/// rather than a nest of conditions inside a loop inside a `match`, and so it can
/// be tested without a filesystem.
fn observe(
    change: &Change,
    plan: &WatchPlan,
    debouncer: &mut Debouncer,
    stats: &mut ServiceStats,
    now: Instant,
) {
    if !is_reportable(change.action) {
        // An action code this build does not know: not evidence that a file
        // appeared, and not worth guessing about.
        return;
    }
    stats.events += 1;

    if !is_scan_candidate(change.action, plan.scan_on_write) {
        if change.action == FileAction::Removed {
            stats.deletes += 1;
        }
        return;
    }

    if debouncer.observe(&change.path, now) {
        stats.waits_started += 1;
    } else {
        // The same path, inside a window that is already running. This is the
        // event the debounce exists to absorb, and counting them is what says
        // what it saved.
        stats.events_coalesced += 1;
    }
}

/// Scan one path whose writes have stopped.
///
/// A path that is a directory is walked rather than skipped: a directory moved
/// into a watched tree produces one event naming the directory and none at all
/// for the files inside it.
fn scan_due(
    path: &Path,
    scanner: &mut Scanner<'_>,
    stats: &mut ServiceStats,
    out: &Sender<RealtimeEvent>,
) {
    if path.is_dir() {
        let outcome = scanner.tree(path, RESCAN_FILE_LIMIT, stats);
        for finding in outcome.findings {
            let _ = out.send(RealtimeEvent::Detected(finding));
        }
        return;
    }
    if let Some(finding) = scanner.file(path, None, stats) {
        let _ = out.send(RealtimeEvent::Detected(finding));
    }
}

/// The scan options a realtime scan runs with.
///
/// [`ScanOptions::realtime`] exactly, with nothing adjusted. It is already the
/// low-cost profile — no archive expansion, no heuristics, not recursive, a five
/// second per-file budget — and this crate exists to run that profile on files
/// as they appear, not to change what a scan is. The things a watcher genuinely
/// has to bound are bounded elsewhere: how much work is queued, by the debounce
/// window, and how much of a tree a catch-up walk covers, by
/// [`RESCAN_FILE_LIMIT`].
fn scan_options() -> ScanOptions {
    ScanOptions::realtime()
}

/// Whether this installation acts on a confirmed detection.
///
/// The configuration's `block_on_detect`, and nothing else. It is what
/// [`Disposition::Quarantine`] turns on, and the word is translated honestly on
/// the way: taking a file away is not blocking it, because the file had a life
/// before it was found, and [`RealtimeService::BLOCKS_NOTHING`] is what the
/// report says about that.
fn acts_on_detections(config: &RealtimeConfig) -> bool {
    config.block_on_detect
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::ExclusionSet;

    /// A plan with no roots, built by hand so these tests do not resolve real
    /// profile directories or touch a filesystem.
    fn plan(scan_on_write: bool) -> WatchPlan {
        WatchPlan {
            roots: Vec::new(),
            exclusions: ExclusionSet::default(),
            scan_on_write,
            window: Duration::from_millis(200),
            skipped: Vec::new(),
            unhonoured: Vec::new(),
            disabled_by: None,
        }
    }

    fn change(path: &str, action: FileAction) -> Change {
        Change {
            action,
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn a_new_file_starts_exactly_one_wait_and_the_rest_of_the_burst_costs_nothing() {
        // The debounce decision at the layer that makes it, rather than through
        // the debouncer's own API: the statistics a caller reads have to agree
        // with what the scanner actually did.
        let mut debouncer = Debouncer::new(Duration::from_millis(200));
        let mut stats = ServiceStats::default();
        let plan = plan(false);
        let now = Instant::now();

        observe(
            &change(r"C:\Temp\a.exe", FileAction::Added),
            &plan,
            &mut debouncer,
            &mut stats,
            now,
        );
        for i in 0..9 {
            observe(
                &change(r"C:\Temp\a.exe", FileAction::Modified),
                &plan,
                &mut debouncer,
                &mut stats,
                now + Duration::from_millis(i * 10),
            );
        }

        assert_eq!(stats.events, 10);
        assert_eq!(stats.waits_started, 1, "one file, one wait");
        // Nine modifications with `scan_on_write` off are not coalesced: they
        // are not candidates at all, which is a different thing and must not be
        // reported as a saving the window made.
        assert_eq!(stats.events_coalesced, 0);
        assert_eq!(debouncer.pending_len(), 1);
    }

    #[test]
    fn a_write_inside_a_running_window_is_counted_as_a_scan_the_window_saved() {
        let mut debouncer = Debouncer::new(Duration::from_millis(200));
        let mut stats = ServiceStats::default();
        let plan = plan(true);
        let now = Instant::now();

        observe(
            &change(r"C:\Temp\a.exe", FileAction::Added),
            &plan,
            &mut debouncer,
            &mut stats,
            now,
        );
        observe(
            &change(r"C:\Temp\a.exe", FileAction::Modified),
            &plan,
            &mut debouncer,
            &mut stats,
            now + Duration::from_millis(50),
        );

        assert_eq!(stats.waits_started, 1);
        assert_eq!(stats.events_coalesced, 1);
        assert_eq!(stats.scans_avoided(), 1);
    }

    #[test]
    fn a_delete_is_counted_and_never_waited_for() {
        // A delete leaves nothing to scan, so it must not start a wait — and it
        // must not be dropped silently either, because it is the only signal the
        // watcher gets about a file being removed from under it.
        let mut debouncer = Debouncer::new(Duration::from_millis(200));
        let mut stats = ServiceStats::default();
        let plan = plan(true);
        let now = Instant::now();

        observe(
            &change(r"C:\Temp\a.exe", FileAction::Removed),
            &plan,
            &mut debouncer,
            &mut stats,
            now,
        );
        observe(
            &change(r"C:\Temp\a.exe", FileAction::RenamedOldName),
            &plan,
            &mut debouncer,
            &mut stats,
            now,
        );

        assert_eq!(stats.deletes, 1);
        assert_eq!(stats.waits_started, 0);
        assert_eq!(stats.events_coalesced, 0);
        assert_eq!(debouncer.pending_len(), 0);
    }

    #[test]
    fn a_rename_into_a_watched_tree_is_waited_for_because_the_file_just_arrived() {
        let mut debouncer = Debouncer::new(Duration::from_millis(200));
        let mut stats = ServiceStats::default();
        let plan = plan(false);
        observe(
            &change(r"C:\Temp\dropper.exe", FileAction::RenamedNewName),
            &plan,
            &mut debouncer,
            &mut stats,
            Instant::now(),
        );
        assert_eq!(stats.waits_started, 1);
    }

    #[test]
    fn an_action_code_this_build_does_not_know_is_not_counted_as_an_event() {
        // `Unknown` is filtered before it can reach the counters. Counting it as
        // an event and then not acting on it would make the statistics claim
        // traffic the scanner never considered.
        let mut debouncer = Debouncer::new(Duration::from_millis(200));
        let mut stats = ServiceStats::default();
        let plan = plan(true);
        observe(
            &change(r"C:\Temp\a.exe", FileAction::Unknown(99)),
            &plan,
            &mut debouncer,
            &mut stats,
            Instant::now(),
        );
        assert_eq!(stats.events, 0);
        assert_eq!(debouncer.pending_len(), 0);
    }

    #[test]
    fn an_excluded_path_is_dropped_before_it_can_start_a_wait() {
        // The storm guard's decision, at the layer where it is actually
        // applied. A vault write that reached the debouncer would be a scan, and
        // a scan is a write to the vault.
        let exclusions = ExclusionSet::new([PathBuf::from(r"C:\ProgramData\WenleAV\quarantine")]);
        assert!(exclusions.excludes(Path::new(r"C:\ProgramData\WenleAV\quarantine\items\ab.qtn")));
        assert!(!exclusions.excludes(Path::new(r"C:\Users\me\Downloads\a.exe")));
    }

    #[test]
    fn totals_add_up_across_roots() {
        let mut total = ServiceStats {
            per_root: BTreeMap::from([(PathBuf::from(r"C:\Temp"), 3)]),
            ..ServiceStats::default()
        };
        let other = ServiceStats {
            events: 5,
            per_root: BTreeMap::from([
                (PathBuf::from(r"C:\Temp"), 2),
                (PathBuf::from(r"D:\Downloads"), 7),
            ]),
            ..ServiceStats::default()
        };
        total.merge(&other);

        assert_eq!(total.events, 5);
        assert_eq!(total.per_root.get(Path::new(r"C:\Temp")), Some(&5));
        assert_eq!(total.per_root.get(Path::new(r"D:\Downloads")), Some(&7));
    }

    #[test]
    fn a_realtime_scan_is_the_fast_profile_and_nothing_else() {
        // Asserted rather than assumed: no archive expansion, no heuristics and
        // not recursive is what keeps a scan of a file that has just been
        // written cheap enough to run on a user's machine.
        let options = scan_options();
        assert!(!options.archives);
        assert!(!options.heuristics);
        assert!(!options.recursive);
        assert!(!options.memory);
        // And the per-file budget is bounded, so one slow file cannot hold the
        // single scanner thread for an unbounded time.
        assert_eq!(options.per_file_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn acting_on_a_detection_is_the_configurations_decision_and_nothing_else() {
        let mut config = RealtimeConfig {
            block_on_detect: true,
            ..RealtimeConfig::default()
        };
        assert!(acts_on_detections(&config));
        config.block_on_detect = false;
        assert!(!acts_on_detections(&config));
    }

    #[test]
    fn a_service_that_blocks_nothing_never_reports_pre_execution() {
        // The constant exists to be checked, not just documented. The assertion
        // is in a `const` block so that it is a compile error and not a test
        // failure if someone ever sets it to `true`: a watcher that blocks
        // nothing claiming otherwise is a claim no test run should be the first
        // to notice.
        const { assert!(!RealtimeService::BLOCKS_NOTHING) };
        assert_eq!(
            Phase::observed(SOURCE, RealtimeService::BLOCKS_NOTHING),
            Phase::AfterTheFact
        );
        assert_eq!(SOURCE, EntrySource::Realtime);
    }

    // -- the test that touches a real filesystem --------------------------
    //
    // Everything above tests a decision. This one tests the assembly: a real
    // directory watched, a real file written, a real scan, a real vault on disk,
    // and the report that comes back out. It is the only place the honest-phase
    // claim is checked end to end, which is why it goes through the vault rather
    // than asserting on a hand-built report.

    #[cfg(windows)]
    mod filesystem {
        use super::*;
        use crate::testing::same_path;

        /// One rule, high severity, firing on a marker string.
        ///
        /// `high` and not `medium` on purpose: the score ladder in `av-core`
        /// makes one high detection reach `Malicious` on its own, so the test
        /// exercises the quarantine path without needing two rules to agree.
        const RULES: &str = r#"
rule realtime_marker {
    meta:
        severity = "high"
        description = "A marker used by the av-realtime end-to-end test."
    strings:
        $marker = "WENLE-REALTIME-E2E-MARKER"
    condition:
        $marker
}
"#;

        const MARKER: &[u8] = b"MZ....WENLE-REALTIME-E2E-MARKER....";

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_file_written_into_a_watched_tree_is_found_taken_and_reported_honestly() {
            let temp = tempfile::tempdir().expect("a temp directory");
            let watched = temp.path().join("watched");
            let install = temp.path().join("install");
            let data = temp.path().join("data");
            for directory in [&watched, &install, &data] {
                std::fs::create_dir_all(directory).expect("a directory for the test");
            }

            let (database, report) = av_rules::database::RuleDatabase::compile(RULES);
            assert!(
                report.refusals.is_empty(),
                "the rule this test is built on was refused"
            );
            let engine = Arc::new(ScanEngine::new(database));
            let paths = AvPaths::with_data_dir(&install, &data);
            let config = RealtimeConfig {
                watched_paths: vec![watched.clone()],
                // The floor turns this into a real window; see `debounce`.
                debounce_ms: 50,
                block_on_detect: true,
                ..RealtimeConfig::default()
            };

            let service =
                RealtimeService::start(&config, &paths, engine, QuarantinePolicy::default())
                    .expect("the service starts");
            assert!(
                service.is_watching(),
                "nothing was watched: {:?}",
                service.plan().skipped
            );

            let dropper = watched.join("dropper.exe");
            std::fs::write(&dropper, MARKER).expect("the file is written");

            // Wait for the finding. The timeout is generous because this is the
            // one test that spans the whole path, and a machine under a build
            // load can take a while to schedule the scanner thread.
            let deadline = Instant::now() + Duration::from_secs(60);
            let finding = loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match service.events().recv_timeout(left) {
                    Ok(RealtimeEvent::Detected(finding)) if same_path(&finding.path, &dropper) => {
                        break finding
                    }
                    // Another file under the tree, or a catch-up walk: not what
                    // this test is about.
                    Ok(RealtimeEvent::Detected(_)) | Ok(RealtimeEvent::Rescanned(_)) => continue,
                    Ok(RealtimeEvent::WatchFailed { root, error }) => {
                        panic!("the watch on {} failed: {error}", root.display())
                    }
                    Err(error) => panic!("nothing was detected within sixty seconds: {error}"),
                }
            };

            // What was found, and what the caller is allowed to say about it.
            assert_eq!(finding.verdict, av_core::Verdict::Malicious);
            assert_eq!(
                finding.phase,
                Phase::AfterTheFact,
                "a watcher that cannot block reported a block"
            );
            assert!(!finding.phase.claims_a_block());
            let message = finding.message();
            assert!(message.contains("after it appeared"), "{message}");
            assert!(!message.contains("was blocked"), "{message}");
            // And it went through the vault, filed under this crate's own name.
            assert!(finding.is_contained(), "{message}");
            assert!(finding.quarantine_error.is_none());
            let id = finding.quarantined.expect("an identifier");
            assert!(
                !dropper.exists(),
                "the file was reported as taken and is still on disk"
            );

            let stats = service.stop().expect("the totals");
            assert!(stats.files_scanned >= 1, "{stats:?}");
            assert_eq!(stats.quarantined, 1, "{stats:?}");
            assert!(stats.quarantined_bytes >= MARKER.len() as u64, "{stats:?}");

            // The vault is the product's vault, not a private one: the entry is
            // in it, under this crate's source, with the honest note.
            let vault = QuarantineVault::open(data.join("quarantine"), QuarantinePolicy::default())
                .expect("the vault reopens");
            let entry = vault.get(id).expect("the entry is in the vault");
            assert_eq!(entry.source, EntrySource::Realtime);
            assert_eq!(entry.verdict, av_core::Verdict::Malicious);
            assert!(
                entry
                    .note
                    .as_deref()
                    .is_some_and(|note| note.contains("not blocked")),
                "the vault note claims more than the watcher did: {:?}",
                entry.note
            );
            assert!(
                same_path(&entry.original_path, &dropper),
                "the vault recorded {:?}",
                entry.original_path
            );
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_clean_file_written_into_a_watched_tree_is_scanned_and_not_reported() {
            // The other half of the differential. A watcher that reported every
            // file would pass the test above and be useless; this is the
            // assertion that the report means something.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watched = temp.path().join("watched");
            let data = temp.path().join("data");
            std::fs::create_dir_all(&watched).expect("the watched directory");
            std::fs::create_dir_all(&data).expect("the data directory");

            let (database, report) = av_rules::database::RuleDatabase::compile(RULES);
            assert!(report.refusals.is_empty(), "the rule was refused");
            let config = RealtimeConfig {
                watched_paths: vec![watched.clone()],
                debounce_ms: 50,
                ..RealtimeConfig::default()
            };
            let service = RealtimeService::start(
                &config,
                &AvPaths::with_data_dir(temp.path().join("install"), &data),
                Arc::new(ScanEngine::new(database)),
                QuarantinePolicy::default(),
            )
            .expect("the service starts");

            let ordinary = watched.join("notes.txt");
            std::fs::write(&ordinary, b"an ordinary file with nothing in it").expect("the write");

            // A detection is what must *not* happen here, so there is no event
            // to wait for: the loop drains the channel for a bounded interval
            // and fails on anything that arrives. The interval is the debounce
            // window plus generous slack for the machine, and what makes it
            // meaningful is the assertion after `stop` — `files_scanned` is the
            // proof the file was examined at all, so this cannot pass by the
            // watcher having done nothing.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let left = deadline.saturating_duration_since(Instant::now());
                match service.events().recv_timeout(left) {
                    Ok(RealtimeEvent::Detected(finding)) => {
                        panic!("a clean file was reported as a detection: {finding:?}")
                    }
                    Ok(RealtimeEvent::WatchFailed { root, error }) => {
                        panic!("the watch on {} failed: {error}", root.display())
                    }
                    Ok(_) => {}
                    // The interval elapsed with nothing reported.
                    Err(_) => break,
                }
            }

            let stats = service.stop().expect("the totals");
            assert!(stats.files_scanned >= 1, "{stats:?}");
            assert_eq!(stats.quarantined, 0, "{stats:?}");
            assert_eq!(stats.quarantine_failed, 0, "{stats:?}");
            assert!(ordinary.exists(), "a clean file was taken");
        }
    }
}
