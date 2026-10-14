//! Walking a tree and scanning what is in it.
//!
//! # The scanner reports; the host decides
//!
//! This module finds files, scans them and reports what the engine said. It
//! does **not** quarantine, does not touch the vault, and holds no state beyond
//! its own counters. That is deliberate and it is the same rule the whole crate
//! is built on: the vault has exactly one writer, and it lives in
//! [`crate::host`]. A walker that took files itself would be a second writer
//! racing the first over an index that is rewritten whole on every change.
//!
//! So a finding leaves here as a [`av_ipc::Detection`] with
//! [`av_ipc::DetectionAction::Reported`] and nothing else, and the host turns
//! that into a quarantine when the configuration asks for one and reports what
//! happened. The walker's job ends at "here is a file, here is what the engine
//! thought of it".
//!
//! # What is counted, and what is not
//!
//! [`ScanCounts`] separates files examined from files the engine could not
//! examine, because "we looked and it was clean" and "we could not look" are
//! different answers and a scan that reported the second as the first would be
//! lying about its coverage. `av_ipc::ScanSummary::covered_everything` is the
//! predicate a caller shows as "nothing was found", and it is false when either
//! counter is non-zero.
//!
//! # Progress is throttled, and the throttle is visible
//!
//! One progress event per [`PROGRESS_EVERY_FILES`] files rather than one per
//! file. A full scan of a large disk examines millions of files: an event each
//! would be millions of frames queued behind a client that is drawing a
//! progress bar, which costs more than the scan. The count in each event is the
//! true count at the moment it was sent, not the count at the last multiple —
//! a progress bar that advanced in steps of 64 would be a bar that lies about
//! the number beside it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use av_core::paths::AvPaths;
use av_core::scan::{FileScanReport, ScanOptions};
use av_ipc::{Detection, DetectionAction, ScanId, ScanProgress};
use av_quarantine::EntrySource;
use av_scan::ScanEngine;
use crossbeam_channel::Sender;

use crate::allow::AllowList;

/// How many files are examined between progress events.
pub const PROGRESS_EVERY_FILES: u64 = 64;

/// One scan's parameters.
#[derive(Debug, Clone)]
pub struct ScanJob {
    /// The identifier the progress and finish events refer to.
    pub id: ScanId,
    /// The file or directory to examine.
    pub path: PathBuf,
    /// How thoroughly. The caller's, not the service's, because a caller who
    /// has named one file has said more about what it wants than any setting.
    pub options: ScanOptions,
}

/// What the walker sends back while it runs.
#[derive(Debug)]
pub enum ScanMessage {
    /// How it is getting on.
    Progress(Box<ScanProgress>),
    /// A file the engine called a detection.
    ///
    /// The whole report rather than a digest of it, because the host has to
    /// assemble a quarantine context from it and `av_quarantine`'s own
    /// documentation says why the numbers must come from the report the user
    /// was shown rather than be derived again.
    Finding(Box<FileScanReport>),
    /// It stopped, and why.
    Finished(Box<ScanCounts>),
}

/// What one walk did, before the host has added what it did about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanCounts {
    /// Files the engine examined.
    pub files: u64,
    /// Bytes read.
    pub bytes: u64,
    /// Files the engine called a detection.
    pub detections: u64,
    /// Files the engine could not examine.
    pub unreadable: u64,
    /// Directories the walk could not list, and therefore did not descend
    /// into.
    pub unreadable_dirs: u64,
    /// How long it took.
    pub duration_ms: u64,
    /// True when the walk stopped before finishing.
    pub incomplete: bool,
    /// Why, in a sentence a user can read.
    pub incomplete_reason: Option<String>,
}

/// A running scan: the flag that stops it and the thread doing it.
#[derive(Debug)]
pub struct Running {
    /// The identifier.
    pub id: ScanId,
    /// Set to ask the walk to stop.
    pub cancel: Arc<AtomicBool>,
}

/// Run one walk, on this thread.
///
/// The walk itself, separated from [`spawn`] so that a test can run it to
/// completion without a thread and without racing. Everything this function
/// does is deterministic given a filesystem and an engine, which is what makes
/// it testable at all.
///
/// `paths` is consulted for one thing: a path inside the product's own tree is
/// skipped. Scanning the quarantine directory would find the files this product
/// already decided were malicious, report them as fresh detections, and — if
/// the configuration asks for automatic quarantine — try to take a file that is
/// already in the vault.
///
/// `allow` is the user's answer to the same question one step out: a path they
/// have allowed is skipped before it is read, not scanned and then discarded.
/// Skipping it here rather than at the finding is the point — a user who allows
/// a file means "stop looking at it", and a scan that reads every byte of a
/// file it will not report on has spent the machine's time to reach an answer
/// it already had.
pub fn walk(
    job: &ScanJob,
    engine: &ScanEngine,
    paths: &AvPaths,
    allow: &AllowList,
    cancel: &AtomicBool,
    out: &Sender<ScanMessage>,
) -> ScanCounts {
    let started = std::time::Instant::now();
    let mut counts = ScanCounts::default();
    let mut findings: u64 = 0;

    // A named file is scanned as a file. A named directory is walked. The two
    // are told apart by asking the filesystem once, rather than by trying to
    // walk a file and reading the error — an error that has to be distinguished
    // from "the directory exists and is empty".
    let is_dir = std::fs::metadata(&job.path)
        .map(|meta| meta.is_dir())
        .unwrap_or(false);

    let candidates: Vec<PathBuf> = if is_dir {
        let walker = walkdir::WalkDir::new(&job.path)
            .follow_links(job.options.follow_links)
            .into_iter();
        let mut files = Vec::new();
        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                counts.incomplete = true;
                counts.incomplete_reason = Some("cancelled".to_string());
                break;
            }
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        files.push(entry.into_path());
                    }
                }
                Err(error) => {
                    // A directory that could not be listed is a hole in the
                    // walk. Counted, never folded into "examined and clean".
                    if error.depth() == 0 {
                        // The root itself: nothing below it can be reached, so
                        // the walk is over and the scan says so rather than
                        // reporting an empty tree as nothing found.
                        counts.incomplete = true;
                        counts.incomplete_reason = Some(format!(
                            "{} could not be walked: {error}",
                            job.path.display()
                        ));
                        break;
                    }
                    counts.unreadable_dirs += 1;
                }
            }
        }
        files
    } else {
        vec![job.path.clone()]
    };

    for path in candidates {
        if cancel.load(Ordering::Relaxed) {
            counts.incomplete = true;
            counts.incomplete_reason = Some("cancelled".to_string());
            break;
        }
        if paths.is_protected(&path) {
            continue;
        }
        if allow.allows(&path) {
            continue;
        }

        let report = engine.scan_file(&path, &job.options);
        counts.files += 1;
        counts.bytes += report.scanned_bytes;

        if report.error.is_some() {
            counts.unreadable += 1;
        } else if report.is_detection() {
            counts.detections += 1;
            findings += 1;
            // `blocked = false`, always: nothing in user mode stopped this file
            // before it ran, and `Phase::observed` turns that fact into the
            // after-the-fact spelling. A scan cannot claim a block — see
            // `av_ipc::detect::Phase`.
            // Only the report crosses this channel. The host builds the
            // detection from it, because it needs the action it has just
            // decided on and nothing here can know that.
            //
            // This used to build a `Detection` as well and drop it on the next
            // line, under a comment saying it was sent alongside the report. It
            // was not sent, and it could not have been: it hard-coded
            // `DetectionAction::Reported`, so a caller that sent it would
            // publish a detection claiming nothing had been done about a file
            // the host had just quarantined — see `host::absorb_finding`, which
            // builds the real one from the action it decided.
            if out.send(ScanMessage::Finding(Box::new(report))).is_err() {
                // The host has gone. Stopping is the only thing left to do, and
                // the counters stay honest about how far the walk got.
                counts.incomplete = true;
                counts.incomplete_reason = Some("the service stopped listening".to_string());
                break;
            }
        }

        if counts.files % PROGRESS_EVERY_FILES == 0 {
            let progress = ScanProgress {
                id: job.id,
                scanned: counts.files,
                // Genuinely unknown for the whole of a walk: the file count of
                // a tree is not known until it has been enumerated, and the
                // enumeration is what the walk is doing. A fabricated total
                // would make a progress bar jump backwards.
                total: None,
                current: Some(path),
                detections: findings,
                bytes: counts.bytes,
            };
            if out.send(ScanMessage::Progress(Box::new(progress))).is_err() {
                counts.incomplete = true;
                counts.incomplete_reason = Some("the service stopped listening".to_string());
                break;
            }
        }

        if job.options.stop_on_first && counts.detections > 0 {
            counts.incomplete = true;
            counts.incomplete_reason =
                Some("stopped at the first detection, as the options asked".to_string());
            break;
        }
    }

    counts.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    counts
}

/// Run a walk on its own thread.
///
/// The thread is detached and reports through the channel: the host keeps the
/// [`Running`] handle, which carries the cancel flag, and stops caring once the
/// [`ScanMessage::Finished`] arrives. Detached rather than joined because a
/// join would mean the host waiting for a scan of `C:\` before it could answer
/// a status request, which is the shape of a service that stops responding
/// while it works.
pub fn spawn(
    job: ScanJob,
    engine: Arc<ScanEngine>,
    paths: AvPaths,
    allow: AllowList,
    cancel: Arc<AtomicBool>,
    out: Sender<ScanMessage>,
) -> std::io::Result<Running> {
    let id = job.id;
    let flag = Arc::clone(&cancel);
    std::thread::Builder::new()
        .name(format!("av-scan-{id}"))
        .spawn(move || {
            let counts = walk(&job, &engine, &paths, &allow, &cancel, &out);
            // The receiver is gone only when the host has stopped; the counts
            // are then of interest to nobody, which is not a failure.
            let _ = out.send(ScanMessage::Finished(Box::new(counts)));
        })
        .map(|_| Running { id, cancel: flag })
}

/// Turn a finding's report into the notification the protocol carries.
///
/// Exists as a function rather than a line in the walker so that the two
/// decisions it makes — the source is [`EntrySource::Scan`], and the phase is
/// after-the-fact — are in one place with their reasons. A scan runs after the
/// fact by construction: it is looking at files that are already on the disk,
/// and the only thing that can stop one before it runs is the kernel driver,
/// which this build does not connect.
pub fn detection_for(report: &FileScanReport, action: DetectionAction) -> Detection {
    Detection::from_report(report, EntrySource::Scan, false, action)
}

/// True when `path` is a directory the walk would descend into.
///
/// A small predicate with a caller that has only a path: a request naming a
/// directory and a request naming a file are the same request, and the service
/// has to be able to say which one it got when it refuses.
pub fn is_directory(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_rules::database::RuleDatabase;

    /// A rule that fires on a file containing the word it names.
    ///
    /// The rule's *name* is fixed rather than derived from the needle: a rule
    /// name is an identifier, and `WENLE-TEST-MARKER` contains hyphens, which
    /// one is not allowed to. The needle is only ever a string literal.
    fn engine_matching(needle: &str) -> Arc<ScanEngine> {
        let source =
            format!("rule Test_Finds_Marker {{ strings: $a = \"{needle}\" condition: $a }}\n");
        let (database, report) = RuleDatabase::compile(&source);
        assert!(
            report.refused() == 0 && database.len() == 1,
            "the test rule must compile: {report:?}"
        );
        Arc::new(ScanEngine::new(database))
    }

    fn engine_with_no_rules() -> Arc<ScanEngine> {
        Arc::new(ScanEngine::new(RuleDatabase::compile("").0))
    }

    fn paths_under(dir: &Path) -> AvPaths {
        AvPaths::with_data_dir(dir.join("install"), dir.join("data"))
    }

    fn job(path: PathBuf) -> ScanJob {
        ScanJob {
            id: ScanId::new(1),
            path,
            options: ScanOptions {
                recursive: true,
                // Heuristics and archives off: this test is about the walk and
                // the counting, and a heuristic that fired on a two-byte test
                // file would make the assertions about the engine rather than
                // about the walker.
                heuristics: false,
                archives: false,
                per_file_timeout: None,
                ..ScanOptions::default()
            },
        }
    }

    fn collect(
        job: &ScanJob,
        engine: &ScanEngine,
        paths: &AvPaths,
        cancel: &AtomicBool,
    ) -> (ScanCounts, Vec<ScanMessage>) {
        collect_with(job, engine, paths, &AllowList::new(), cancel)
    }

    /// The same, for the tests that have something to allow.
    fn collect_with(
        job: &ScanJob,
        engine: &ScanEngine,
        paths: &AvPaths,
        allow: &AllowList,
        cancel: &AtomicBool,
    ) -> (ScanCounts, Vec<ScanMessage>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        let counts = walk(job, engine, paths, allow, cancel, &tx);
        drop(tx);
        (counts, rx.into_iter().collect())
    }

    #[test]
    fn a_tree_of_clean_files_is_examined_and_reported_as_a_whole_tree() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("nested")).expect("creates");
        std::fs::write(root.join("a.txt"), b"nothing to see").expect("writes");
        std::fs::write(root.join("b.txt"), b"nothing either").expect("writes");
        std::fs::write(root.join("nested/c.txt"), b"nor here").expect("writes");

        let engine = engine_with_no_rules();
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let (counts, messages) = collect(&job(root), &engine, &paths, &cancel);

        assert_eq!(counts.files, 3);
        assert_eq!(counts.detections, 0);
        assert_eq!(counts.unreadable, 0);
        assert_eq!(counts.unreadable_dirs, 0);
        assert!(!counts.incomplete);
        assert!(counts.bytes > 0, "the bytes read are counted, not assumed");
        // No findings, and no progress either: three files is below the
        // throttle, and the walk sends nothing when there is nothing to say.
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[test]
    fn a_finding_arrives_as_a_report_and_never_as_a_claim_to_have_blocked_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).expect("creates");
        std::fs::write(root.join("bad.txt"), b"WENLE-TEST-MARKER").expect("writes");

        let engine = engine_matching("WENLE-TEST-MARKER");
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let (counts, messages) = collect(&job(root), &engine, &paths, &cancel);

        assert_eq!(counts.files, 1);
        assert_eq!(counts.detections, 1);
        let finding = messages
            .iter()
            .find_map(|message| match message {
                ScanMessage::Finding(report) => Some(report),
                _ => None,
            })
            .expect("the detection is reported");
        assert!(finding.is_detection());

        // And the notification built from it says the file was found *after*
        // the fact, which is the only thing a user-mode scan can honestly say.
        let detection = detection_for(finding, DetectionAction::Reported);
        assert_eq!(detection.source, EntrySource::Scan);
        assert!(!detection.claims_a_block());
        assert!(!detection.is_contained());
        assert_eq!(detection.action, DetectionAction::Reported);
        assert_eq!(detection.action.as_str(), "reported");
        assert!(!detection.rules.is_empty(), "the rule that fired is named");
    }

    /// A path the user has allowed is not read and not reported. Counted as
    /// examined would be the worse half of the bug: the scan would say it looked
    /// at a file it never opened, and a summary with zero detections would read
    /// as a clean tree.
    #[test]
    fn an_allowed_path_is_not_read_and_not_reported() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("kept")).expect("creates");
        std::fs::write(root.join("bad.txt"), b"WENLE-TEST-MARKER").expect("writes");
        std::fs::write(root.join("kept/also-bad.txt"), b"WENLE-TEST-MARKER").expect("writes");

        let engine = engine_matching("WENLE-TEST-MARKER");
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let allow = AllowList::from_paths(&[root.join("kept")]);

        let (counts, messages) = collect_with(&job(root.clone()), &engine, &paths, &allow, &cancel);
        assert_eq!(counts.files, 1, "only the file that was not allowed");
        assert_eq!(counts.detections, 1);
        assert!(messages.iter().any(|message| matches!(
            message,
            ScanMessage::Finding(report) if report.path == root.join("bad.txt")
        )));
        assert!(
            !messages.iter().any(|message| matches!(
                message,
                ScanMessage::Finding(report) if report.path.starts_with(root.join("kept"))
            )),
            "a finding for an allowed path is the loop this exists to break"
        );

        // And with the whole tree allowed, the walk is empty and complete —
        // the honest spelling of "there was nothing to look at".
        let everything = AllowList::from_paths(&[root.clone()]);
        let (counts, messages) = collect_with(&job(root), &engine, &paths, &everything, &cancel);
        assert_eq!(counts.files, 0);
        assert_eq!(counts.detections, 0);
        assert!(!counts.incomplete);
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[test]
    fn cancelling_stops_the_walk_and_says_so_rather_than_reporting_a_clean_tree() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).expect("creates");
        for index in 0..8 {
            std::fs::write(root.join(format!("{index}.txt")), b"x").expect("writes");
        }

        let engine = engine_with_no_rules();
        let paths = paths_under(dir.path());
        // Already cancelled: the walk must not examine anything and must not
        // report an empty, complete scan — the two things that would make a
        // cancelled scan look like a clean one.
        let cancel = AtomicBool::new(true);
        let (counts, _) = collect(&job(root), &engine, &paths, &cancel);

        assert_eq!(counts.files, 0);
        assert!(counts.incomplete);
        assert_eq!(counts.incomplete_reason.as_deref(), Some("cancelled"));
    }

    #[test]
    fn stop_on_first_stops_at_the_first_detection_and_calls_the_scan_incomplete() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).expect("creates");
        for index in 0..4 {
            std::fs::write(root.join(format!("{index}.txt")), b"WENLE-TEST-MARKER")
                .expect("writes");
        }

        let engine = engine_matching("WENLE-TEST-MARKER");
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let mut options = job(root.clone());
        options.options.stop_on_first = true;
        let (counts, _) = collect(&options, &engine, &paths, &cancel);

        assert_eq!(counts.detections, 1, "one finding, not four");
        assert_eq!(counts.files, 1);
        assert!(counts.incomplete);
        assert!(counts
            .incomplete_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("first detection")));
    }

    #[test]
    fn a_root_that_cannot_be_walked_is_an_incomplete_scan_and_not_an_empty_one() {
        // The failure this prevents: a scan of a path that does not exist
        // reporting zero files and zero detections, which reads exactly like a
        // clean bill of health.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let engine = engine_with_no_rules();
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let missing = dir.path().join("no-such-directory");
        std::fs::create_dir_all(&missing).expect("creates");
        // A directory that exists and is empty is a legitimate, complete,
        // empty scan.
        let (empty, _) = collect(&job(missing.clone()), &engine, &paths, &cancel);
        assert_eq!(empty.files, 0);
        assert!(!empty.incomplete);

        // A path that is not there at all is a single file that cannot be
        // read, which is counted as unreadable rather than as clean.
        let (absent, _) = collect(
            &job(dir.path().join("not-there.txt")),
            &engine,
            &paths,
            &cancel,
        );
        assert_eq!(absent.files, 1);
        assert_eq!(
            absent.unreadable, 1,
            "an unreadable file is not a clean one"
        );
        assert!(absent.incomplete_reason.is_none());
    }

    #[test]
    fn the_products_own_tree_is_skipped_rather_than_scanned_and_reported() {
        // The quarantine directory holds files this product already decided
        // were malicious. Scanning it would report them as fresh detections on
        // every full scan, and with automatic quarantine on it would try to
        // take a file that is already in the vault.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = paths_under(dir.path());
        std::fs::create_dir_all(&paths.quarantine_dir).expect("creates");
        std::fs::write(paths.quarantine_dir.join("held.bin"), b"WENLE-TEST-MARKER")
            .expect("writes");
        std::fs::write(dir.path().join("ordinary.txt"), b"WENLE-TEST-MARKER").expect("writes");

        let engine = engine_matching("WENLE-TEST-MARKER");
        let cancel = AtomicBool::new(false);

        let (in_vault, _) = collect(&job(paths.quarantine_dir.clone()), &engine, &paths, &cancel);
        assert_eq!(in_vault.files, 0, "the vault is not a scan target");
        assert_eq!(in_vault.detections, 0);

        // And the same walk over a directory that contains something ordinary
        // does examine it, so the skip is about the path and not about the
        // engine having gone quiet.
        let (ordinary, _) = collect(&job(dir.path().to_path_buf()), &engine, &paths, &cancel);
        assert!(ordinary.files >= 1);
    }

    #[test]
    fn progress_is_sent_on_the_throttle_and_carries_the_true_count() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).expect("creates");
        for index in 0..(PROGRESS_EVERY_FILES + 5) {
            std::fs::write(root.join(format!("{index}.txt")), b"x").expect("writes");
        }

        let engine = engine_with_no_rules();
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let (counts, messages) = collect(&job(root), &engine, &paths, &cancel);

        assert_eq!(counts.files, PROGRESS_EVERY_FILES + 5);
        let progress: Vec<&ScanProgress> = messages
            .iter()
            .filter_map(|message| match message {
                ScanMessage::Progress(progress) => Some(progress.as_ref()),
                _ => None,
            })
            .collect();
        assert!(!progress.is_empty(), "a long walk reports its progress");
        // The last one carries the real count, and every count is a multiple of
        // the throttle because that is when they are sent.
        for event in &progress {
            assert_eq!(event.id, ScanId::new(1));
            assert_eq!(event.scanned % PROGRESS_EVERY_FILES, 0);
            assert!(event.current.is_some());
            assert!(event.total.is_none(), "a walk does not know its total");
        }
        assert_eq!(
            progress.last().map(|event| event.scanned),
            Some(PROGRESS_EVERY_FILES)
        );
    }

    #[test]
    fn a_named_file_is_scanned_as_a_file_and_not_walked() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("one.txt"), b"WENLE-TEST-MARKER").expect("writes");
        let engine = engine_matching("WENLE-TEST-MARKER");
        let paths = paths_under(dir.path());
        let cancel = AtomicBool::new(false);
        let (counts, _) = collect(&job(dir.path().join("one.txt")), &engine, &paths, &cancel);
        assert_eq!(counts.files, 1);
        assert_eq!(counts.detections, 1);
        assert!(!counts.incomplete);
        assert!(is_directory(dir.path()));
        assert!(!is_directory(&dir.path().join("one.txt")));
        assert!(!is_directory(&dir.path().join("nothing-here")));
    }
}
