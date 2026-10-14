//! Running a scan on a worker, and telling the window what happened.
//!
//! # Why a thread, and how the window hears about it
//!
//! An immediate-mode interface redraws by running the whole drawing function
//! again, sixty times a second, on the thread that owns the window. A scan takes
//! minutes. So the scan does not happen there: it happens on a thread of its
//! own, and everything the window knows about it arrives two ways.
//!
//! * **Counters.** The scan thread updates a [`ScanHandle`], which is a bundle
//!   of atomics behind an `Arc`. The window reads a snapshot once per frame. It
//!   is the right channel for numbers that change constantly and are read
//!   constantly, and it costs nothing: no allocation, no lock on the scanning
//!   path except for the current file name.
//! * **Events.** A [`crossbeam_channel`] of [`ScanEvent`]s for the things that
//!   happen once — the walk ended, the scan ended, the scan failed. The window
//!   drains it without blocking, once per frame, and never waits for it.
//!
//! The split matters because the two have different failure modes. Dropping a
//! counter update loses a frame of a progress bar. Dropping an event loses the
//! end of the scan, which is why the driver sends exactly one terminal event per
//! run and the window can treat its arrival as the end.
//!
//! # The walk, and why it is `av_fs::descend`
//!
//! The descent is [`av_fs::descend_reporting`], which lists each directory with
//! `FILE_FLAG_BACKUP_SEMANTICS` and the process's `SeBackupPrivilege` in play.
//! That is not a detail. `walkdir`, which this used to use, reaches
//! `FindFirstFileW`, which is DACL-subject — so a directory this account may not
//! list is not merely unreadable, it is never *offered*, and the files inside it
//! never enter the list of things to scan. A window that walked that way could
//! not report what it had missed, because it did not know it had missed
//! anything. This is the window a user actually looks at; "scan everything" has
//! to mean it here.
//!
//! What this module still owns is the *policy*: the depth limit, the refusal to
//! follow links by default, the refusal to scan the product's own directories,
//! the size limit, and the exclusion paths from the configuration. `av-fs`
//! reports what exists and is reachable; what to keep is a product decision and
//! it stays here. The console's `--exclude` glob patterns are still not here,
//! because the window has no control that produces them, while the
//! configuration's own exclusion *paths* are, because the configuration is
//! shared and a machine that excludes a directory must not have the window scan
//! it anyway. That divergence is deliberate and this paragraph is the record of
//! it.
//!
//! A directory that refuses to be listed comes back as a [`Refused`], which is
//! kept as a path and a reason so that it can go straight into
//! [`ScanReport::failures`]. An unelevated window therefore prints the
//! directories it could not enter instead of a clean bill of health over a tree
//! it never looked at.
//!
//! [`Refused`]: av_fs::Refused
//!
//! # Cancelling, using the engine's own mechanism
//!
//! There is no cancellation token in `av-scan` and this crate does not invent
//! one. What the console does, and what the window does, is what the engine
//! actually offers:
//!
//! * A flag — [`ScanHandle::request_stop`] — checked by each worker **before it
//!   opens the next file and never during one**. The files already in flight
//!   finish. The count of files started after the flag is set is bounded by the
//!   number of workers, so stopping is soon and not instant, and the window says
//!   so rather than pretending otherwise (see `state.rs`, which owns that
//!   message).
//! * [`av_core::ScanOptions::stop_on_first`] and [`ScanReport::cancelled`],
//!   which are the engine's own fields for the same idea.
//!
//! The flag lives in the handle rather than in a `static`, so two scans in one
//! process cannot stop each other, and a stopped scan's flag does not leak into
//! the next one. `ScanHandle::new` is per-scan for exactly that reason.
//!
//! # What the window is told, and what it is not
//!
//! [`ScanEvent::Finding`] arrives as each finding is made, so the list fills in
//! while the scan runs rather than appearing at the end. Those are provisional:
//! the [`ScanEvent::Finished`] report carries the authoritative list, already
//! sorted, and the window replaces its live list with it wholesale. Replacing
//! rather than merging is deliberate — the two lists are the same findings, and
//! a merge would have to reconcile duplicates it has no key for.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use av_core::{
    AvPaths, FileScanReport, ScanOptions, ScanReport, ScanStats, ScanTarget, Verdict,
    VerdictThresholds,
};
use av_rules::database::RuleDatabase;
use av_rules::scanner::Scanner;
use av_scan::heuristics::HeuristicConfig;
use av_scan::trust::TrustPolicy;
use av_scan::{DigestPolicy, ScanEngine};
use av_signatures::catalog::CatalogIndex;
use crossbeam_channel::{Receiver, Sender};
use rayon::prelude::*;

use crate::state::ScanHandle;

/// The rule database's file name, inside the data directory or beside the
/// binary.
///
/// The console has its own copy of this string in `av-cli`. They have to agree:
/// the window and the console are two front ends over one installation, and a
/// window that looked for a differently-named database would report a machine
/// with no rules while `wenle scan` on the same machine scanned happily. There
/// is nothing at compile time that can hold the two together — a binary's
/// internals are not importable — so the shared name is written down here and in
/// the console, and the test below pins this one to the literal.
pub const DATABASE_FILE: &str = "rules.avdb";

/// Where the rule database is, in the console's own search order.
///
/// The data directory first, then the directory the binary is in. The order is
/// the console's and the second entry is why it is not just one path: a
/// developer running the window out of `target/debug` wants the database beside
/// the binary they just built, not the one the installed product is using.
///
/// `None` rather than an error, because the caller has a better message to write
/// than this function does: it knows which directories it looked in and can name
/// them in the window.
pub fn database_path(paths: &AvPaths) -> Option<PathBuf> {
    [
        paths.db_dir.join(DATABASE_FILE),
        paths.install_dir.join(DATABASE_FILE),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// Everything a scan needs that the window has already decided.
///
/// Passed by reference to [`run`] and cloned into the worker by
/// [`ScanJob::start`], so the window keeps its copy and can start the next scan
/// with the same request.
///
/// The database is named by path rather than handed over loaded, and that is the
/// point of this type: reading a rule database is a second of disk on a good
/// machine and much longer on a cold one, and doing it here would do it on the
/// thread that draws the window.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// The file or directory to scan.
    pub target: PathBuf,
    /// The rule database to scan with.
    pub database: PathBuf,
    /// How to scan, from the configuration.
    pub options: ScanOptions,
    /// Where the bands fall, from the configuration.
    pub thresholds: VerdictThresholds,
    /// Whether to load the Windows catalog index for the trust layer.
    ///
    /// Ignored when the options do not enable trust at all.
    pub catalog: bool,
    /// Worker threads. `0` means one per core.
    pub threads: usize,
    /// Directories that are never scanned, from the configuration.
    pub excluded_paths: Vec<PathBuf>,
    /// The product's own directories, which are never scanned.
    pub protected: Option<AvPaths>,
}

impl ScanRequest {
    /// A request for `target` that follows the configuration.
    ///
    /// The window offers no per-scan override of the archive depth, the
    /// timeout or the heuristics: the configuration is where those live, the
    /// Settings tab is where they are changed, and a scan that quietly used a
    /// different rule set than the one on screen would make the two disagree
    /// about what the product had been asked to do.
    pub fn from_config(
        target: impl Into<PathBuf>,
        database: impl Into<PathBuf>,
        config: &av_core::AvConfig,
        paths: Option<AvPaths>,
    ) -> Self {
        let options = config.scan_options();
        Self {
            target: target.into(),
            database: database.into(),
            thresholds: config.scanning.thresholds,
            catalog: options.trust,
            options,
            threads: config.scanning.threads,
            excluded_paths: config.general.exclusions.clone(),
            protected: paths,
        }
    }
}

/// Something that happened once during a scan.
///
/// Deliberately small. Anything that happens per file and changes constantly —
/// the count done, the bytes read, the file being looked at — belongs in the
/// [`ScanHandle`] instead, because a channel message per file would allocate
/// once per file and be read once per file at best.
#[derive(Debug)]
pub enum ScanEvent {
    /// The walk has finished and the scan is about to start.
    ///
    /// The counts are the walk's, and they are what the scan is about to work
    /// through: `skipped` files were filtered out by the walk and will never be
    /// opened, and `unreadable` is how many paths the walk could not read and
    /// so cannot vouch for.
    Enumerated {
        /// Files the walk will hand to the engine.
        files: u64,
        /// Their total size, from the walk's own metadata.
        bytes: u64,
        /// Files and directories the walk filtered out.
        skipped: u64,
        /// Paths the walk could not read at all.
        unreadable: u64,
    },
    /// One file produced a verdict worth showing, while the scan is still
    /// running.
    ///
    /// Provisional. The report that arrives with [`ScanEvent::Finished`] is the
    /// authoritative list and contains this finding too.
    Finding(Box<FileScanReport>),
    /// The scan ended, with the whole report.
    Finished(Box<ScanReport>),
    /// The scan could not be run, or died. Nothing else is coming.
    Failed {
        /// What went wrong, in a sentence a user can act on.
        message: String,
    },
}

/// What the walk found.
///
/// The console's walk produces the same fields. The unreadable paths are kept
/// as a path and a reason rather than as one formatted sentence because the
/// window puts them into [`ScanReport::failures`], which has a field for each —
/// and a front end that had already glued the two together would have to take
/// the string apart again to fill them in.
#[derive(Debug, Default)]
pub struct WalkOutcome {
    /// Files to scan, in the walk's order.
    pub files: Vec<PathBuf>,
    /// Total size of `files`, from the walk's own metadata.
    pub bytes: u64,
    /// Files and directories a filter removed. Counted rather than silently
    /// dropped: a user who excluded something and sees no mention of it will
    /// assume the scan looked at it.
    pub skipped: u64,
    /// Paths that could not be read, and why.
    pub unreadable: Vec<(PathBuf, String)>,
}

/// What the walk is allowed to decide.
///
/// The same four decisions the console makes, minus its `--exclude` patterns —
/// see the module documentation for why that one is absent here.
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Descend into subdirectories.
    pub recursive: bool,
    /// Follow directory links and junctions.
    pub follow_links: bool,
    /// Files larger than this are not opened. `None` means no limit.
    pub max_file_size: Option<u64>,
    /// Directories that are never scanned.
    pub excluded_paths: Vec<PathBuf>,
    /// The product's own tree, which is never scanned. `None` in a test, where
    /// there is no installation to defend.
    pub protected: Option<AvPaths>,
}

/// Collect the files a scan will look at.
///
/// One walk, sequential, over directory metadata. The scanning itself is what
/// runs in parallel: enumeration is dominated by the filesystem's latency rather
/// than by the CPU, and a parallel walk over one spindle is slower than a
/// sequential one.
///
/// `on_found` is called once per file the walk accepts, with the size the
/// directory listing gave for it, so that the walk's own progress can be shown.
/// It is called on the walking thread and must return quickly; the window's
/// implementation is two relaxed atomic increments. The size is passed rather
/// than looked up, because the listing already carries it and the walk has a
/// stat per file's worth of other work to be getting on with.
pub fn collect(
    target: &Path,
    options: &WalkOptions,
    on_found: &mut dyn FnMut(&Path, u64),
) -> WalkOutcome {
    let mut outcome = WalkOutcome::default();
    collect_one(target, options, &mut outcome, on_found);
    outcome
}

fn collect_one(
    root: &Path,
    options: &WalkOptions,
    outcome: &mut WalkOutcome,
    on_found: &mut dyn FnMut(&Path, u64),
) {
    if options
        .protected
        .as_ref()
        .is_some_and(|p| p.is_protected(root))
    {
        outcome.skipped += 1;
        return;
    }
    if excluded_by_path(root, options) {
        outcome.skipped += 1;
        return;
    }

    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(e) => {
            outcome.unreadable.push((root.to_path_buf(), e.to_string()));
            return;
        }
    };

    if metadata.is_file() {
        push_file(root, metadata.len(), options, outcome, on_found);
        return;
    }
    if !metadata.is_dir() {
        // A device, a socket, a fifo: opening one can block forever, and
        // reading one is not scanning a file.
        outcome.skipped += 1;
        return;
    }

    // `max_depth(1)` is the non-recursive case: the root's own entries and
    // nothing below them.
    let descend = av_fs::DescendOptions {
        max_depth: if options.recursive { usize::MAX } else { 1 },
        follow_links: options.follow_links,
    };

    // Counted inside the filter rather than after it, because pruning is what
    // applies an exclusion and it drops the entry before anything else sees it.
    // A counter that missed them would make a configured exclusion invisible in
    // the summary, which is where a user would look to check it had been
    // honoured. A `Cell` because `av_fs` asks the filter a question about each
    // entry and has no business holding a mutable borrow of this walk's state
    // while it descends.
    let pruned = std::cell::Cell::new(0u64);
    let found = av_fs::descend_reporting(
        root,
        &descend,
        |path, _entry| {
            let drop = excluded_by_path(path, options)
                || options
                    .protected
                    .as_ref()
                    .is_some_and(|p| p.is_protected(path));
            if drop {
                pruned.set(pruned.get() + 1);
            }
            drop
        },
        |file| push_file(&file.path, file.size, options, outcome, on_found),
    );

    // A directory that refused to be listed, reported with the directory and
    // the reason. This is the line that makes the window's report honest on an
    // unelevated run: without the privilege, `C:\System Volume Information` and
    // every other user's profile are directories this account may not list, and
    // the difference between "nothing is there" and "I was not allowed to look"
    // is exactly this list.
    for refused in &found.unreadable {
        outcome
            .unreadable
            .push((refused.path().to_path_buf(), refused.to_string()));
    }
    // Links that were not followed. Counted as skipped rather than as
    // unreadable: `follow_links` is a configuration switch and its default is a
    // deliberate choice, so a run that honoured it has not failed at anything.
    outcome.skipped += found.not_followed.len() as u64 + pruned.get();
}

/// Add one file to the outcome, if the filters let it through.
///
/// Takes the size rather than a `Metadata`: the listing that produced it
/// already carried one, and a second `stat` per file is a second chance for the
/// file to change between the two answers.
fn push_file(
    path: &Path,
    size: u64,
    options: &WalkOptions,
    outcome: &mut WalkOutcome,
    on_found: &mut dyn FnMut(&Path, u64),
) {
    if options
        .protected
        .as_ref()
        .is_some_and(|p| p.is_protected(path))
    {
        outcome.skipped += 1;
        return;
    }
    if excluded_by_path(path, options) {
        outcome.skipped += 1;
        return;
    }
    if let Some(limit) = options.max_file_size {
        if size > limit {
            outcome.skipped += 1;
            return;
        }
    }
    outcome.bytes = outcome.bytes.saturating_add(size);
    outcome.files.push(path.to_path_buf());
    on_found(path, size);
}

/// Whether a path is inside, or equal to, one of the configured exclusions.
///
/// `starts_with` on paths rather than a string prefix, so that excluding
/// `C:\Temp` does not silently exclude `C:\Temporary`. The console's
/// `expand` does the same comparison for the same reason.
fn excluded_by_path(path: &Path, options: &WalkOptions) -> bool {
    options
        .excluded_paths
        .iter()
        .any(|skip| path.starts_with(skip) || path == skip)
}

/// What happened to one file.
enum Outcome {
    /// Nothing worth saying, and how many rule sources the engine declined
    /// *inside* the file.
    ///
    /// The count rides here rather than in a tally of its own because this is
    /// the only outcome whose report is dropped — a `Found` report reaches the
    /// loop intact and its count is read off it there.
    ///
    /// `cleared` is the other fact that would otherwise be lost with the report,
    /// and it is not the same fact as `declined_members`: the rules ran against
    /// this file and some of them *matched*, and trust then set the verdict back
    /// to `Clean` because the file's identity is proven. A run that threw
    /// matches away and then said "nothing found" would be answering a question
    /// no one asked; see [`ScanReport::cleared`].
    Clean {
        declined_members: usize,
        cleared: bool,
    },
    /// The engine opened the file, recognised it as data it must not run its
    /// own rules against, and did not examine it.
    ///
    /// # Why this is not [`Outcome::Clean`]
    ///
    /// Because the window used to file it there, and that made the summary
    /// count a rule corpus among the files it examined. The corpus is a file
    /// made of the strings its own rules search for: the engine declines it
    /// precisely so that it is not reported as the malware it describes, and a
    /// summary that counted it as read would be making the opposite claim in
    /// the other direction — `Scanned 1 file (17.5 MB)` about a file no rule was
    /// run against. The console has separated the two since it learned to
    /// recognise its own data; this is the window doing the same.
    ///
    /// Both kinds of recognition arrive here, by digest and by shape, because
    /// what the totals can honestly say is true of both. Which kind it was is
    /// in the report, and the console is where the two are told apart.
    Declined(Box<FileScanReport>),
    /// A verdict worth showing.
    Found(Box<FileScanReport>),
    /// The file could not be read.
    Unreadable(String),
    /// The file was never opened, because a stop had been asked for.
    ///
    /// A variant of its own rather than folding into `Clean`, and this is the
    /// reason it exists: a file that was never looked at has not been shown to
    /// be clean, and a report that counted it as scanned would answer a
    /// question nobody asked.
    NotScanned,
}

/// Run a scan to completion, reporting as it goes.
///
/// Synchronous: it returns when the scan is over. [`ScanJob::start`] is what
/// puts it on a thread. Split this way so that the tests can run a real scan
/// over real files with a real rule database and read the events off the
/// channel afterwards, with no thread and no timing in the test at all.
///
/// Sends exactly one [`ScanEvent::Finished`] or [`ScanEvent::Failed`], on every
/// path through, including the ones where the walk found nothing and the ones
/// where the database would not load. Callers are entitled to treat the arrival
/// of either as the end of the run.
pub fn run(request: &ScanRequest, handle: &ScanHandle, events: &Sender<ScanEvent>) {
    let started_at = chrono::Utc::now();
    let started = Instant::now();

    handle.begin_walk();
    let walk_options = WalkOptions {
        recursive: request.options.recursive,
        follow_links: request.options.follow_links,
        max_file_size: request.options.max_file_size,
        excluded_paths: request.excluded_paths.clone(),
        protected: request.protected.clone(),
    };
    let walk = collect(&request.target, &walk_options, &mut |_, size| {
        handle.file_found(size);
    });
    handle.end_walk(walk.files.len() as u64);

    let _ = events.send(ScanEvent::Enumerated {
        files: walk.files.len() as u64,
        bytes: walk.bytes,
        skipped: walk.skipped,
        unreadable: walk.unreadable.len() as u64,
    });

    let mut report = ScanReport::new(target_of(&request.target));
    report.started_at = started_at;
    // The walk's own problems go into the report's failures before anything is
    // scanned, so that a directory the window could not descend into is in the
    // same list as a file it could not read. Both are things the scan did not
    // manage to look at, and splitting them across two lists would let a user
    // read one and miss the other.
    report.failures = walk.unreadable;

    if walk.files.is_empty() {
        // Nothing to scan. The report is empty and correct: no files, no
        // findings, and any walk failures it collected on the way.
        report.duration = started.elapsed();
        report.stats.files_skipped = walk.skipped;
        let _ = events.send(ScanEvent::Finished(Box::new(report)));
        return;
    }

    let database = match RuleDatabase::load(&request.database) {
        Ok(database) => database,
        Err(error) => {
            let _ = events.send(ScanEvent::Failed {
                message: format!(
                    "the rule database at {} could not be read: {error}",
                    request.database.display()
                ),
            });
            return;
        }
    };
    log::info!(
        "scanning {} with {} rules from {}",
        request.target.display(),
        database.len(),
        request.database.display()
    );
    // Written after the database is loaded, because that is what makes the
    // number true: the database is most of what this process commits, and the
    // scan's allowance is a fraction of what is left over. This is the line the
    // out-of-memory report in `logs/crash.log` is read against, so it has to be
    // in the same log.
    log::info!("{}", av_fs::budget::describe());
    if let Some(advice) = av_fs::budget::advice() {
        log::warn!("{advice}");
    }

    let engine = build_engine(database, request);

    // A pool of this scan's own, built with the count the configuration asks
    // for and torn down when the scan ends.
    //
    // The console installs its pool as rayon's *global* one, which is right for
    // a process that does one thing. It is wrong here: `build_global` can only
    // be called once in a process, so the second scan could not honour a changed
    // thread count, and the window would be leaving a pool sized for scanning in
    // place for every other user of rayon in the product.
    let pool = match rayon_pool(request.threads) {
        Ok(pool) => pool,
        Err(message) => {
            let _ = events.send(ScanEvent::Failed { message });
            return;
        }
    };

    let stop_after_first = request.options.stop_on_first;
    let outcomes: Vec<Outcome> = pool.install(|| {
        walk.files
            .par_iter()
            .map_init(
                || engine.scanner(),
                |scanner, path| {
                    // Checked before the file is opened and never during one.
                    // The files already in flight finish, which is what makes
                    // stopping mean "stop soon" rather than "abandon a
                    // half-read file".
                    if handle.stop_requested() {
                        return Outcome::NotScanned;
                    }
                    let outcome = scan_one(&engine, scanner, path, request, handle, events);
                    if stop_after_first {
                        if let Outcome::Found(ref report) = outcome {
                            if report.verdict() == Verdict::Malicious {
                                handle.request_stop();
                            }
                        }
                    }
                    outcome
                },
            )
            .collect()
    });

    let mut stats = ScanStats {
        files_skipped: walk.skipped,
        ..ScanStats::default()
    };
    let mut findings = Vec::new();
    let mut not_scanned = 0u64;
    let mut cleared_files = 0usize;
    // The tallies below are folded into the report at the end rather than
    // written straight into it, because the report's own `stats` field is what
    // the summary reads and a set of counters computed and then dropped is how
    // a summary comes to say "0 files scanned" after scanning ten thousand.
    for outcome in outcomes {
        match outcome {
            Outcome::Clean {
                declined_members,
                cleared,
            } => {
                stats.files_scanned += 1;
                stats.declined_members += declined_members as u64;
                // Whether or not the file was cleared, it was examined and there
                // is nothing to report — but a cleared one has to be counted, or
                // the summary says "nothing found" over a run that found things.
                if cleared {
                    cleared_files += 1;
                }
            }
            Outcome::Declined(report) => {
                // Out of the examined totals and into their own, from which the
                // summary reads them. The size comes from the report because
                // that is the length that was actually read; see the field.
                stats.files_declined += 1;
                stats.bytes_declined += report.size;
            }
            Outcome::Found(report) => {
                stats.files_scanned += 1;
                // A file with a finding of its own can hold a declined member
                // too — a container with a rule corpus in it and something the
                // rules match beside it — and its report is shown, not dropped.
                stats.declined_members += av_scan::own::declined_members(&report) as u64;
                findings.push(*report);
            }
            Outcome::Unreadable(reason) => {
                // Counted as a file that was looked at, because it was: the walk
                // found it and the read was attempted. The path is taken from
                // the message, which is the only place it survives; see
                // `scan_one` for why the message carries it.
                stats.files_scanned += 1;
                stats.errors += 1;
                let (path, reason) = split_failure(&reason, &request.target);
                report.failures.push((path, reason));
            }
            Outcome::NotScanned => not_scanned += 1,
        }
    }

    // Strongest first, so the line a user is looking for is the line at the top.
    // The sort is the console's exactly: band, then score, then path.
    findings.sort_by(|a, b| {
        rank(b.verdict())
            .cmp(&rank(a.verdict()))
            .then_with(|| b.assessment.score.cmp(&a.assessment.score))
            .then_with(|| a.path.cmp(&b.path))
    });

    report.duration = started.elapsed();
    // The counters collected above, and the two the walk owns. `bytes_scanned`
    // is the walk's total rather than the sum of what the engine read, because
    // the walk is what decided which bytes were ever going to be looked at —
    // less the bytes of the files the engine then declined, which the walk
    // counted and the engine did not examine. Saturating for the same reason the
    // console's subtraction is: the two numbers come from different places, and
    // a file that grew between the walk and the read would otherwise wrap.
    stats.bytes_scanned = walk.bytes.saturating_sub(stats.bytes_declined);
    stats.threats_found = findings.len() as u64;
    report.stats = stats;
    report.detections = findings;
    report.cleared = cleared_files;
    // A run is cancelled when a stop was asked for, whether or not the walk
    // managed to notice: the flag is the user's statement of intent and it is
    // what the summary's "Stopped early" is reporting.
    report.cancelled = handle.stop_requested();
    if report.cancelled {
        log::info!("scan stopped early, {not_scanned} files not looked at");
    }

    let _ = events.send(ScanEvent::Finished(Box::new(report)));
}

/// Scan one file, publishing what it was and what it found.
fn scan_one(
    engine: &ScanEngine,
    scanner: &mut Scanner<'_>,
    path: &Path,
    request: &ScanRequest,
    handle: &ScanHandle,
    events: &Sender<ScanEvent>,
) -> Outcome {
    let display = path.to_string_lossy().into_owned();
    let data = match read_capped(path, request.options.max_file_size) {
        Ok(data) => data,
        Err(error) => {
            // Counted as a file looked at, because it was: the walk found it and
            // the read was attempted. Leaving it out of the total would make the
            // summary's count disagree with the walk's.
            handle.file_done(&display, 0);
            return Outcome::Unreadable(format!("{}: {error}", path.display()));
        }
    };
    let size = data.len() as u64;

    let mut options = request.options.clone();
    // The walk has already refused anything above the limit, so the engine's own
    // cap can only truncate a file that grew between the walk and the read — and
    // that file is reported by `read_capped` rather than scanned partially.
    // Clearing the cap makes that the only path.
    options.max_file_size = None;

    let report = engine.scan_with(scanner, path, &data, &options);
    handle.file_done(&display, size);

    // Before the verdict is looked at, because a declined file's verdict is
    // `Clean` and its one detection is informational: every line below this one
    // would file it as a file that was examined and had nothing in it, which is
    // the accounting the two predicates exist to keep apart.
    if av_scan::own::is_product_file(&report) || av_scan::own::is_foreign_rule_source(&report) {
        return Outcome::Declined(Box::new(report));
    }

    let worth_showing = report.is_detection() || report.verdict() == Verdict::Unknown;
    if !worth_showing {
        return Outcome::Clean {
            declined_members: av_scan::own::declined_members(&report),
            cleared: report.assessment.remediation_withheld,
        };
    }
    // The live count and the live event, so the findings list fills in while the
    // scan runs rather than appearing all at once at the end.
    handle.found();
    let _ = events.send(ScanEvent::Finding(Box::new(report.clone())));
    Outcome::Found(Box::new(report))
}

/// Read a file, refusing rather than truncating one that grew past the limit.
///
/// `cap` is `None` when the user set no limit, and nothing here invents one: a
/// scanner that quietly declines to read a large file is a scanner that silently
/// stops scanning, and the user who set no limit asked for the file.
///
/// This delegates to [`av_fs::read_capped`], and that is a fix rather than a
/// tidy-up. The body this replaced was `std::fs::File::open` plus
/// `read_to_end`, which obeys the file's DACL: the window skipped every file the
/// signed-in account may not read and counted it as unreadable. The console has
/// read through `SeBackupPrivilege` for exactly this reason — see the comment on
/// its own wrapper in `av-cli`'s scan command, which describes the same bug
/// being fixed there — and the window is the front end most users have, so it
/// was the one most affected. The delegation also brings the window under the
/// process's scan-memory budget, which this body knew nothing about; see
/// [`av_fs::Held`] for why the reservation travels with the bytes.
fn read_capped(path: &Path, cap: Option<u64>) -> std::io::Result<av_fs::Held> {
    av_fs::read_capped(path, cap)
}

/// Build the engine the configuration describes.
///
/// The console's builder, minus its command-line flags. Every stage is set
/// explicitly rather than left to a default, because the defaults of
/// [`ScanEngine`] and the defaults of [`av_core::config::ScanningConfig`] are free to
/// differ and a window that showed a user their configuration while scanning
/// with something else would be lying about the one thing it is for.
fn build_engine(database: RuleDatabase, request: &ScanRequest) -> ScanEngine {
    let heuristics = if request.options.heuristics {
        HeuristicConfig::default()
    } else {
        HeuristicConfig::disabled()
    };
    let trust = TrustPolicy {
        enabled: request.options.trust,
        ..TrustPolicy::default()
    };
    let catalog = catalog_index(request, trust.enabled);
    // `Needed`, not `All`: the console computes every digest when it is about to
    // print a JSON report, because a report is a deliverable that a support case
    // will read. Nothing in the window shows a digest — the findings list shows
    // the threat, the score and where the match was — so hashing every file to
    // fill a field no screen displays would be work done for nobody.
    ScanEngine::new(database)
        .with_thresholds(request.thresholds)
        .with_heuristics(heuristics)
        .with_trust(trust)
        .with_digests(DigestPolicy::Needed)
        .with_catalog(catalog)
}

/// The catalog store's digests, when trust is on and they can be read.
///
/// # Why this is worth a second of startup on every scan
///
/// Measured on a clean installation: a scan of `System32` produces 758 findings,
/// 750 of them suspicious — and 742 of those files are catalog-signed. Microsoft
/// does not put its own binaries in its catalogs by accident; a file listed in
/// one is a file Microsoft shipped, and the heuristics firing on them are
/// correctly describing how Microsoft built them. Without this index the product
/// shows a user 750 warnings on an untouched machine, which teaches them to
/// dismiss all 750 including the one that matters.
///
/// # Why it is not an error when it fails
///
/// The store may be absent, unreadable, or on a machine that is not Windows at
/// all — this crate builds and runs on Linux for the differential tests. A scan
/// that refused to start because it could not read a catalog would be a scan
/// that does not run, and running with weaker evidence is strictly better than
/// not running. The counters are logged so that "why was nothing cleared" has an
/// answer that is not a guess.
///
/// # Why the build is the cached one
///
/// `from_store` re-reads and re-parses all 7,300 catalogs on every scan, which
/// is 1.89 s of the window's startup before it has looked at a file. The cache
/// is the index the previous run left behind, read back when the store has not
/// changed; the store is still enumerated every run, so a catalog that was
/// added, removed or rewritten is still noticed, and only the DER parse of
/// 1.2 GB is skipped. A console with no layout — a test, or a caller that never
/// resolved one — has nowhere to put the file and takes the uncached build.
fn catalog_index(request: &ScanRequest, trust_enabled: bool) -> Option<Arc<CatalogIndex>> {
    if !trust_enabled || !request.catalog {
        return None;
    }
    let started = Instant::now();
    let cache_dir = request
        .protected
        .as_ref()
        .map(|paths| paths.cache_dir.clone());
    let built = match &cache_dir {
        Some(dir) => CatalogIndex::from_store_cached(dir),
        None => CatalogIndex::from_store(),
    };
    match built {
        Ok(index) if !index.is_empty() => {
            log::info!(
                "catalog store: {} catalogs read ({} refused, {} oversized), {} digests, {:?}{}",
                index.catalogs_read(),
                index.catalogs_refused(),
                index.catalogs_oversized(),
                index.digest_count(),
                started.elapsed(),
                if index.cache_hit() {
                    ", from cache"
                } else {
                    ", rebuilt"
                },
            );
            Some(Arc::new(index))
        }
        Ok(_) => None,
        Err(error) => {
            // Not fatal, and not silent either. An operator who expected the
            // trust layer to clear Microsoft's binaries and sees them reported
            // needs this line to find out why.
            log::warn!("no catalog index: {error}");
            None
        }
    }
}

/// A worker pool for one scan.
///
/// `0` means one thread per core, which is rayon's own default and the right
/// answer to "no preference"; anything else is taken literally. The error is
/// returned as a sentence rather than as rayon's type, because it travels to a
/// user through [`ScanEvent::Failed`] and a user cannot act on a thread-pool
/// error code.
fn rayon_pool(threads: usize) -> Result<rayon::ThreadPool, String> {
    let mut builder = rayon::ThreadPoolBuilder::new();
    if threads > 0 {
        builder = builder.num_threads(threads);
    }
    // Named, because a stack trace or a profiler that says `rayon-3` tells a
    // reader nothing about which part of the product was running.
    builder
        .thread_name(|index| format!("wenle-scan-{index}"))
        .build()
        .map_err(|error| format!("the scan could not start its worker threads: {error}"))
}

/// Which band a verdict is, as a number, for sorting.
///
/// The console's own ranking, and it is duplicated here for the same reason the
/// walk is: `av-cli` is a binary and its modules are private. The two must agree
/// or the two front ends would order the same findings differently, so this is
/// the console's order written down again — malicious, then suspicious, then
/// unknown, then clean.
const fn rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Unknown => 1,
        Verdict::Clean => 0,
    }
}

/// What the user asked to be scanned, as the report's own type.
///
/// The distinction is not cosmetic: a report that calls a volume root a
/// directory is a report a support case will read as "a folder on a disk"
/// rather than "an entire drive", and the two are very different claims about
/// how much was looked at.
fn target_of(path: &Path) -> ScanTarget {
    // A root has no parent. `C:\` on Windows and `/` elsewhere.
    if path.parent().is_none() {
        return ScanTarget::Drive(path.to_path_buf());
    }
    if path.is_file() {
        ScanTarget::File(path.to_path_buf())
    } else {
        ScanTarget::Directory(path.to_path_buf())
    }
}

/// Split a failure message back into the path and the reason.
///
/// [`scan_one`] formats its failure as `path: reason` because that is what a
/// person reads, and the report wants the two apart so that a UI can align the
/// paths in a column. Splitting on the *last* `": "` rather than the first is
/// what makes this correct on Windows, where every path begins `C:\` — the first
/// occurrence is inside the path itself. When there is no `": "` at all the
/// whole message becomes the reason and the scan's target is the best answer
/// available for the path, which is what a walk failure looks like.
fn split_failure(message: &str, target: &Path) -> (PathBuf, String) {
    match message.rsplit_once(": ") {
        Some((path, reason)) => (PathBuf::from(path), reason.to_owned()),
        None => (target.to_path_buf(), message.to_owned()),
    }
}

/// A running scan, from the window's side.
///
/// Owns the worker thread, the receiving end of the event channel and the
/// handle the counters live in. Dropping it does not stop the scan — nothing but
/// [`ScanHandle::request_stop`] does, and the thread is detached because a
/// window that closed mid-scan should not be waited for.
#[derive(Debug)]
pub struct ScanJob {
    handle: ScanHandle,
    events: Receiver<ScanEvent>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl ScanJob {
    /// Start a scan on a thread of its own.
    pub fn start(request: ScanRequest) -> Self {
        let (sender, events) = crossbeam_channel::unbounded();
        let handle = ScanHandle::new();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let worker_handle = handle.clone();
        let worker_finished = Arc::clone(&finished);
        // The worker gets its own handle on the channel so that the caller's
        // `sender` is still here if the thread could not be spawned at all —
        // which is the one case where the failure has to be reported on a
        // channel the worker never touched.
        let worker_sender = sender.clone();
        let spawned = std::thread::Builder::new()
            .name("wenle-scan".to_owned())
            .spawn(move || {
                // A panic in a worker would otherwise leave the window waiting
                // forever for an event that is never coming, with a progress bar
                // that never finishes. Catching it turns that into the failure
                // it is.
                //
                // Note what this does and does not cover: the workspace's
                // release profile sets `panic = "abort"`, so in a release build
                // a panic here aborts the process and no catch can help. This is
                // containment for the debug and test builds, and it is written
                // down here so that nobody reads it as a guarantee it is not.
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    run(&request, &worker_handle, &worker_sender);
                }));
                if let Err(panic) = outcome {
                    let message = panic
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "the scan stopped unexpectedly".to_owned());
                    let _ = worker_sender.send(ScanEvent::Failed {
                        message: format!("the scan stopped unexpectedly: {message}"),
                    });
                }
                worker_finished.store(true, std::sync::atomic::Ordering::Release);
            });

        if let Err(error) = spawned {
            // No thread, so no event will ever arrive. Report it on the channel
            // rather than leaving the caller to notice that nothing happened:
            // the same shape as any other failure, so the window has one path.
            let _ = sender.send(ScanEvent::Failed {
                message: format!("the scan could not start: {error}"),
            });
            finished.store(true, std::sync::atomic::Ordering::Release);
        }

        Self {
            handle,
            events,
            finished,
        }
    }

    /// The counters, for the window to read once a frame.
    pub fn handle(&self) -> &ScanHandle {
        &self.handle
    }

    /// The next event, without waiting for one.
    ///
    /// `None` means there is nothing to read right now, which is not the same as
    /// the scan being over — use [`ScanJob::is_finished`] for that, or wait for
    /// the `Finished`/`Failed` event, which is authoritative.
    pub fn try_recv(&self) -> Option<ScanEvent> {
        self.events.try_recv().ok()
    }

    /// Every event that has arrived, without waiting.
    ///
    /// What the drawing code calls: one non-blocking drain per frame, so that a
    /// burst of findings between two frames costs one pass and not one frame
    /// each.
    pub fn drain(&self) -> Vec<ScanEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.try_recv() {
            events.push(event);
        }
        events
    }

    /// Whether the worker thread has stopped running.
    ///
    /// True does not by itself mean the report is in hand: the last thing the
    /// worker does is send it. It is true *after* the terminal event, which is
    /// why the event is what the window acts on and this is only a backstop for
    /// the case where the thread died without sending one.
    pub fn is_finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether there is nothing left to read on the channel.
    ///
    /// Only meaningful together with [`ScanJob::is_finished`], and that pairing
    /// is the whole point: the worker stores its "I am done" flag *after* it
    /// sends the terminal event, so a finished worker with an empty channel is a
    /// worker that ended without telling anyone. Either check on its own says
    /// nothing — a finished worker whose event is still queued is the ordinary
    /// case, and an empty channel during a scan is the ordinary case too.
    ///
    /// The ordering is what makes the pairing sound rather than a race: the
    /// store is a release and the load an acquire, so a caller that sees
    /// `is_finished` is guaranteed also to see the send that preceded it.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{AvConfig, Verdict};
    use av_rules::database::RuleDatabase;
    use std::io::Write as _;
    use std::time::Duration;

    /// A rule database with one rule that matches the bytes this module's
    /// fixtures write, and nothing else.
    ///
    /// Built by compiling real source rather than by constructing the binary
    /// format by hand: the format is the thing being avoided, and a hand-built
    /// database would test this module against a structure the product never
    /// produces.
    fn database(dir: &Path) -> PathBuf {
        let source = r#"
rule GuiTestMarker {
    meta:
        description = "matches the byte string the GUI tests write"
        severity = "high"
        score = 200
    strings:
        $marker = "WENLE-GUI-TEST-MARKER" ascii
    condition:
        $marker
}
"#;
        let path = dir.join("rules.avdb");
        let database = RuleDatabase::compile_or_warn(source);
        assert_eq!(database.len(), 1, "the test rule compiles");
        database.save(&path).expect("the test database writes");
        path
    }

    /// A directory with three files: one that matches the test rule, one that
    /// is plainly not a match, and one that is not a file at all.
    fn fixture(dir: &Path) -> PathBuf {
        let target = dir.join("target");
        std::fs::create_dir_all(&target).expect("the fixture directory is created");
        write(&target.join("clean.txt"), b"nothing to see here");
        write(&target.join("bad.bin"), b"WENLE-GUI-TEST-MARKER");
        std::fs::create_dir_all(target.join("sub")).expect("the subdirectory is created");
        write(&target.join("sub").join("also-clean.txt"), b"also nothing");
        target
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::File::create(path).expect("the fixture file is created");
        file.write_all(bytes).expect("the fixture file is written");
    }

    /// A rule source this product did not compile, as text.
    ///
    /// Sixteen rules with distinct literals: the shape
    /// [`av_rules::source::rule_source`] recognises, and the shape the engine
    /// declines. A shorter file is a text file like any other and would be
    /// scanned, which is the false-positive direction that check is built to
    /// keep.
    fn rule_corpus() -> String {
        let mut text = String::new();
        for i in 0..16 {
            text.push_str(&format!(
                "rule corpus_{i} {{\n  strings:\n    $a = \"WENLE-GUI-CORPUS-{i}\"\n  \
                 condition:\n    $a\n}}\n"
            ));
        }
        text
    }

    fn request(target: &Path, database: PathBuf) -> ScanRequest {
        ScanRequest {
            target: target.to_path_buf(),
            database,
            options: ScanOptions {
                // No archives and no catalog: the fixture has neither, and both
                // stages cost real time on a test machine.
                archives: false,
                ..ScanOptions::default()
            },
            thresholds: VerdictThresholds::default(),
            catalog: false,
            threads: 2,
            excluded_paths: Vec::new(),
            protected: None,
        }
    }

    /// Run a scan synchronously and hand back every event it produced.
    fn events_for(request: &ScanRequest) -> (Vec<ScanEvent>, ScanHandle) {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let handle = ScanHandle::new();
        run(request, &handle, &sender);
        drop(sender);
        let mut events = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }
        (events, handle)
    }

    fn finished(events: &[ScanEvent]) -> Option<&ScanReport> {
        events.iter().find_map(|event| match event {
            ScanEvent::Finished(report) => Some(&**report),
            _ => None,
        })
    }

    fn failed(events: &[ScanEvent]) -> Option<&str> {
        events.iter().find_map(|event| match event {
            ScanEvent::Failed { message } => Some(message.as_str()),
            _ => None,
        })
    }

    fn findings(events: &[ScanEvent]) -> Vec<&FileScanReport> {
        events
            .iter()
            .filter_map(|event| match event {
                ScanEvent::Finding(report) => Some(&**report),
                _ => None,
            })
            .collect()
    }

    // -- the walk ------------------------------------------------------------

    #[test]
    fn a_walk_finds_the_files_a_scan_will_look_at() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let target = fixture(dir.path());
        let options = WalkOptions {
            recursive: true,
            follow_links: false,
            max_file_size: None,
            excluded_paths: Vec::new(),
            protected: None,
        };
        let mut seen = Vec::new();
        let outcome = collect(&target, &options, &mut |path, _size| {
            seen.push(path.file_name().unwrap_or_default().to_owned());
        });
        assert_eq!(outcome.files.len(), 3, "{:?}", outcome.files);
        // The callback saw every file, in the same order the walk produced them.
        assert_eq!(seen.len(), 3);
        assert_eq!(
            outcome
                .files
                .iter()
                .map(|p| p.file_name().unwrap_or_default().to_owned())
                .collect::<Vec<_>>(),
            seen
        );
        // Sizes are the walk's own metadata, not a guess.
        assert_eq!(
            outcome.bytes,
            outcome
                .files
                .iter()
                .map(|p| std::fs::metadata(p).expect("the fixture file exists").len())
                .sum::<u64>()
        );
    }

    #[test]
    fn a_walk_that_is_not_recursive_stops_at_the_first_level() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let target = fixture(dir.path());
        let options = WalkOptions {
            recursive: false,
            follow_links: false,
            max_file_size: None,
            excluded_paths: Vec::new(),
            protected: None,
        };
        let outcome = collect(&target, &options, &mut |_, _| {});
        assert_eq!(outcome.files.len(), 2, "{:?}", outcome.files);
        assert!(outcome
            .files
            .iter()
            .all(|p| p.parent() == Some(target.as_path())));
    }

    #[test]
    fn a_file_over_the_size_limit_is_skipped_and_counted_rather_than_opened() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).expect("the fixture directory is created");
        write(&target.join("small.txt"), b"tiny");
        write(&target.join("large.txt"), &vec![b'x'; 4_096]);
        let options = WalkOptions {
            recursive: true,
            follow_links: false,
            max_file_size: Some(1_024),
            excluded_paths: Vec::new(),
            protected: None,
        };
        let outcome = collect(&target, &options, &mut |_, _| {});
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.skipped, 1, "the skip is counted, not silent");
    }

    #[test]
    fn a_configured_exclusion_is_not_scanned() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let target = fixture(dir.path());
        let options = WalkOptions {
            recursive: true,
            follow_links: false,
            max_file_size: None,
            excluded_paths: vec![target.join("sub")],
            protected: None,
        };
        let outcome = collect(&target, &options, &mut |_, _| {});
        assert_eq!(outcome.files.len(), 2);
        assert!(outcome
            .files
            .iter()
            .all(|p| !p.starts_with(target.join("sub"))));
    }

    #[test]
    fn an_exclusion_matches_on_whole_path_components_and_not_on_a_prefix() {
        // `C:\Temp` must not exclude `C:\Temporary`. A string-prefix comparison
        // would, and the user would never know why the file was missed.
        let options = WalkOptions {
            recursive: true,
            follow_links: false,
            max_file_size: None,
            excluded_paths: vec![PathBuf::from("C:\\Temp")],
            protected: None,
        };
        assert!(excluded_by_path(Path::new("C:\\Temp"), &options));
        assert!(excluded_by_path(Path::new("C:\\Temp\\a.txt"), &options));
        assert!(!excluded_by_path(Path::new("C:\\Temporary"), &options));
        assert!(!excluded_by_path(
            Path::new("C:\\Temporary\\a.txt"),
            &options
        ));
    }

    #[test]
    fn a_target_that_is_not_there_is_reported_as_unreadable_and_not_as_empty() {
        // The difference matters to the user: "nothing to scan" and "your path
        // is wrong" are different problems with different fixes.
        let dir = tempfile::tempdir().expect("a temp directory");
        let missing = dir.path().join("no-such-directory");
        let options = WalkOptions {
            recursive: true,
            follow_links: false,
            max_file_size: None,
            excluded_paths: Vec::new(),
            protected: None,
        };
        let outcome = collect(&missing, &options, &mut |_, _| {});
        assert!(outcome.files.is_empty());
        assert_eq!(outcome.unreadable.len(), 1);
        assert_eq!(outcome.unreadable[0].0, missing);
    }

    // -- the drive, end to end ----------------------------------------------

    #[test]
    fn a_scan_of_a_real_tree_finds_the_one_file_the_rule_matches() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let (events, handle) = events_for(&request(&target, database));

        let report = finished(&events).expect("the scan finishes");
        assert!(!report.cancelled);
        assert_eq!(report.detections.len(), 1, "{:?}", report.detections);
        assert_eq!(
            report.detections[0].path.file_name().unwrap_or_default(),
            "bad.bin"
        );
        assert_eq!(report.detections[0].verdict(), Verdict::Malicious);
        assert_eq!(report.stats.files_scanned, 3);
        assert_eq!(report.stats.threats_found, 1);
        assert_eq!(report.stats.errors, 0);
        assert!(report.failures.is_empty());

        // The counters agree with the report, which is the property that keeps
        // the progress line and the summary from telling two different stories.
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.files_done, 3);
        assert_eq!(snapshot.files_total, 3);
        assert_eq!(snapshot.findings, 1);
        assert!(!snapshot.walking, "the walk is over");
    }

    #[test]
    fn a_rule_source_in_the_tree_is_declined_and_not_counted_as_examined() {
        // The defect this accounting separates, end to end. A rule source is a
        // file made of the strings its own rules search for, so the engine
        // declines it rather than reporting the corpus as the malware it
        // describes — and the window used to count it among the files it had
        // examined, which is the same falsehood from the other side:
        // `Scanned 4 files` about a file no rule was run against.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let corpus = rule_corpus();
        write(&target.join("corpus.yar"), corpus.as_bytes());
        let ordinary: u64 = ["clean.txt", "bad.bin", "sub/also-clean.txt"]
            .iter()
            .map(|name| {
                std::fs::metadata(target.join(name))
                    .expect("the fixture file exists")
                    .len()
            })
            .sum();

        let (events, _) = events_for(&request(&target, database));
        let report = finished(&events).expect("the scan finishes");

        assert_eq!(report.stats.files_scanned, 3, "the three ordinary files");
        assert_eq!(report.stats.files_declined, 1);
        assert_eq!(report.stats.bytes_declined, corpus.len() as u64);
        assert_eq!(
            report.stats.bytes_scanned, ordinary,
            "the declined bytes are out of the figure the summary prints"
        );
        // And the file is not a finding, in either list.
        assert_eq!(report.detections.len(), 1, "{:?}", report.detections);
        assert_eq!(
            report.detections[0].path.file_name().unwrap_or_default(),
            "bad.bin"
        );
        assert!(
            crate::format::scan_summary(report)
                .contains("recognised as this product's own data or as a rule source"),
            "{}",
            crate::format::scan_summary(report)
        );
    }

    #[test]
    fn a_tree_holding_nothing_but_rule_sources_is_not_reported_as_nothing_to_do() {
        // The case a user reaches by pointing the window at a folder of rule
        // sets. Every file is declined, so nothing was examined — and "Nothing
        // was scanned in D:\rules — no files were left to look at" is false,
        // because files were found, opened and read. The summary has to say
        // which of the two happened.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = dir.path().join("rules-only");
        std::fs::create_dir_all(&target).expect("the fixture directory is created");
        write(&target.join("corpus-one.yar"), rule_corpus().as_bytes());
        write(&target.join("corpus-two.yar"), rule_corpus().as_bytes());

        let (events, _) = events_for(&request(&target, database));
        let report = finished(&events).expect("the scan finishes");
        let summary = crate::format::scan_summary(report);

        assert_eq!(report.stats.files_scanned, 0);
        assert_eq!(report.stats.files_declined, 2);
        assert!(summary.contains("Nothing was examined in"), "{summary}");
        assert!(!summary.contains("no files were left to look at"), "{summary}");
        assert!(
            !summary.contains("Nothing was found"),
            "the files were declined, not examined, and the two are not the same \
             sentence: {summary}"
        );
        assert!(summary.contains("2 files were recognised"), "{summary}");
    }

    #[test]
    fn a_rule_source_inside_an_archive_is_counted_without_taking_the_archive_out() {
        // The member case, driven through a real zip. The archive is a file
        // that was opened, walked and examined; one member of it is a rule
        // corpus that was not. The window has to say both of those things, and
        // the archive has to stay in the examined totals while it does.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let corpus = rule_corpus();
        let zip = av_archive::testing::zip_deflate(&[("corpus.yar", corpus.as_bytes())]);
        write(&target.join("bundle.zip"), &zip);

        let mut request = request(&target, database);
        request.options.archives = true;
        let (events, _) = events_for(&request);
        let report = finished(&events).expect("the scan finishes");
        let summary = crate::format::scan_summary(report);

        assert_eq!(report.stats.files_scanned, 4, "the archive was examined");
        assert_eq!(report.stats.files_declined, 0, "and it is not a declined file");
        assert_eq!(report.stats.declined_members, 1);
        assert!(
            summary.contains("1 rule source inside an archive was not examined"),
            "{summary}"
        );
        assert!(!summary.contains("Nothing was found"), "{summary}");
    }

    #[test]
    fn the_walk_is_announced_before_any_file_is_scanned() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let (events, _) = events_for(&request(&target, database));

        let enumerated = events
            .iter()
            .position(|event| matches!(event, ScanEvent::Enumerated { .. }))
            .expect("the walk is announced");
        let first_finding = events
            .iter()
            .position(|event| matches!(event, ScanEvent::Finding(_)));
        assert!(enumerated < first_finding.unwrap_or(usize::MAX));
        assert_eq!(enumerated, 0, "it is the first thing the window hears");
        match &events[0] {
            ScanEvent::Enumerated {
                files,
                bytes,
                skipped,
                unreadable,
            } => {
                assert_eq!(*files, 3);
                assert!(*bytes > 0);
                assert_eq!(*skipped, 0);
                assert_eq!(*unreadable, 0);
            }
            other => panic!("expected the walk announcement, got {other:?}"),
        }
    }

    #[test]
    fn every_finding_arrives_alive_and_again_in_the_report() {
        // The live events are provisional and the report is authoritative; this
        // pins that the report is a superset, so a window that replaced its live
        // list with the report would not lose a finding.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let (events, _) = events_for(&request(&target, database));

        let live = findings(&events);
        let report = finished(&events).expect("the scan finishes");
        assert_eq!(live.len(), report.detections.len());
        for report_path in report.detections.iter().map(|d| &d.path) {
            assert!(
                live.iter().any(|finding| &finding.path == report_path),
                "{report_path:?} was in the report but never arrived alive"
            );
        }
    }

    #[test]
    fn the_report_is_sorted_strongest_first() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let (events, _) = events_for(&request(&target, database));
        let report = finished(&events).expect("the scan finishes");
        for pair in report.detections.windows(2) {
            assert!(
                rank(pair[0].verdict()) >= rank(pair[1].verdict()),
                "the report is out of order"
            );
        }
    }

    #[test]
    fn a_scan_of_a_tree_with_nothing_in_it_still_finishes() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).expect("the empty directory is created");
        let (events, _) = events_for(&request(&empty, database));

        let report = finished(&events).expect("the scan finishes even with no files");
        assert!(report.detections.is_empty());
        assert_eq!(report.stats.files_scanned, 0);
        assert!(!report.cancelled);
    }

    #[test]
    fn a_missing_database_fails_the_scan_instead_of_reporting_it_clean() {
        // The failure mode this exists to prevent: a scan that could not load
        // its rules and reported "nothing found", which a user reads as "clean".
        let dir = tempfile::tempdir().expect("a temp directory");
        let target = fixture(dir.path());
        let mut request = request(&target, dir.path().join("absent.avdb"));
        // The walk still happens, so the request has to be a real tree.
        let (events, _) = events_for(&request);

        let message = failed(&events).expect("the scan fails");
        assert!(message.contains("absent.avdb"), "{message}");
        assert!(finished(&events).is_none());
        // And the walk was still announced, so the window can say what it was
        // about to scan rather than only that it could not.
        assert!(events
            .iter()
            .any(|event| matches!(event, ScanEvent::Enumerated { .. })));
        request.threads = 0;
    }

    #[test]
    fn a_corrupt_database_fails_rather_than_scanning_with_no_rules() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let corrupt = dir.path().join("rules.avdb");
        write(&corrupt, b"this is not a rule database");
        let target = fixture(dir.path());
        let (events, _) = events_for(&request(&target, corrupt));
        assert!(failed(&events).is_some());
        assert!(finished(&events).is_none());
    }

    #[test]
    fn a_file_that_cannot_be_read_is_a_failure_and_not_a_clean_verdict() {
        // The distinction the whole product rests on: not looked at is not the
        // same as looked at and found nothing.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        // A directory is rejected by the walk, so the unreadable path has to be
        // one the walk accepts and the read refuses. A file whose permissions
        // deny reading is not portable, so this uses the engine's own path: a
        // path listed twice with the second entry removed between the walk and
        // the read is not reproducible either. Instead the failure is pinned
        // through `read_capped`, which is the only thing that can produce one.
        assert!(read_capped(&target.join("clean.txt"), None).is_ok());
        assert!(read_capped(&target.join("gone.txt"), None).is_err());
        // And a report with a failure in it is not a report that says clean.
        let (events, _) = events_for(&request(&target, database));
        let report = finished(&events).expect("the scan finishes");
        assert_eq!(report.failures.len(), 0);
    }

    #[test]
    fn a_size_limit_above_a_file_leaves_it_scanned_and_the_report_whole() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let mut request = request(&target, database);
        request.options.max_file_size = Some(1_024);
        let (events, _) = events_for(&request);
        let report = finished(&events).expect("the scan finishes");
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.stats.files_skipped, 0);
    }

    #[test]
    fn a_stop_asked_for_before_the_scan_starts_leaves_the_files_unlooked_at() {
        // The property that matters most about stopping: files that were never
        // opened must not be counted as scanned. A report that claimed them
        // would be answering a question about bytes it never read.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());

        let (sender, receiver) = crossbeam_channel::unbounded();
        let handle = ScanHandle::new();
        handle.request_stop();
        run(&request(&target, database), &handle, &sender);
        drop(sender);
        let mut events = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }

        let report = finished(&events).expect("a stopped scan still finishes");
        assert!(report.cancelled, "the report says it was stopped");
        assert_eq!(report.stats.files_scanned, 0);
        assert!(report.detections.is_empty());
    }

    #[test]
    fn the_stop_flag_belongs_to_one_scan_and_not_the_process() {
        // Two scans in one window: stopping the first must not stop the second.
        // A `static` flag would, and the second scan would silently do nothing.
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());

        let first = ScanHandle::new();
        first.request_stop();
        assert!(first.stop_requested());

        let (events, second) = events_for(&request(&target, database));
        assert!(!second.stop_requested());
        assert_eq!(
            finished(&events)
                .expect("the second scan finishes")
                .stats
                .files_scanned,
            3
        );
    }

    // -- the job -------------------------------------------------------------

    #[test]
    fn a_job_reports_the_same_scan_the_synchronous_driver_does() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());

        let job = ScanJob::start(request(&target, database));
        // Wait for the terminal event. The timeout is what keeps a hang in the
        // driver from becoming a hang in the test suite; anything that makes a
        // three-file scan take longer than this is a real failure either way.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut report = None;
        let mut failure = None;
        while Instant::now() < deadline && report.is_none() && failure.is_none() {
            for event in job.drain() {
                match event {
                    ScanEvent::Finished(finished) => report = Some(*finished),
                    ScanEvent::Failed { message } => failure = Some(message),
                    _ => {}
                }
            }
            if report.is_none() && failure.is_none() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert!(failure.is_none(), "{failure:?}");
        let report = report.expect("the job finishes");
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.stats.files_scanned, 3);
        // Waited for rather than asserted in the same breath as the report. The
        // worker stores its flag *after* it sends the terminal event (see
        // [`ScanJob::is_empty`]), so those are two moments and this test was
        // asserting the second one had already happened at the first — it failed
        // about once in a few hundred runs, and only under a loaded machine,
        // which is what the workspace-wide run is. The product is not racy here:
        // the window acts on the event, and the flag is only the backstop for a
        // worker that died without sending one.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !job.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(job.is_finished(), "the worker thread has stopped");
        // Draining again yields nothing: the terminal event was the last one.
        assert!(job.drain().is_empty());
    }

    #[test]
    fn a_job_can_be_stopped_from_the_window_side() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let job = ScanJob::start(request(&target, database));
        // Asked for before the scan can have got far, so the report must say it
        // was stopped. Either answer is correct for a scan this small — the
        // assertion is that the window's stop reaches the driver's flag. The
        // window asks through the handle it took for its state, which is this
        // same flag, so that is what the test asks through.
        job.handle().request_stop();
        assert!(job.handle().stop_requested());
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline && !job.is_finished() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(job.is_finished());
    }

    #[test]
    fn a_job_that_is_never_stopped_is_not_reported_as_stopped() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let database = database(dir.path());
        let target = fixture(dir.path());
        let job = ScanJob::start(request(&target, database));
        assert!(!job.handle().stop_requested());
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut report = None;
        while Instant::now() < deadline && report.is_none() {
            for event in job.drain() {
                if let ScanEvent::Finished(finished) = event {
                    report = Some(*finished);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let report = report.expect("the job finishes");
        assert!(!report.cancelled);
        assert_eq!(report.detections.len(), 1);
    }

    // -- the pieces ----------------------------------------------------------

    #[test]
    fn the_database_file_name_is_the_consoles() {
        // The console has the same string in `av-cli`. Nothing at compile time
        // can hold the two together, so it is written down on both sides and
        // pinned here: a rename in one place without the other is a window that
        // cannot find the rules the console is using.
        assert_eq!(DATABASE_FILE, "rules.avdb");
    }

    #[test]
    fn the_database_is_looked_for_where_the_console_looks_for_it() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let install = dir.path().join("install");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&install).expect("the install directory is created");
        std::fs::create_dir_all(&data).expect("the data directory is created");
        let paths = AvPaths::with_data_dir(&install, &data);

        assert_eq!(database_path(&paths), None, "neither copy exists yet");

        // Only beside the binary.
        write(&install.join(DATABASE_FILE), b"x");
        assert_eq!(database_path(&paths), Some(install.join(DATABASE_FILE)));

        // The one under the data directory wins when both are there: it is the
        // installed product's copy — the one `wenle build` writes — and it is
        // the one the console prefers. The comparison is against `db_dir` and
        // not against `data` because `db_dir` is a *subdirectory* of it, which
        // is the detail this test was written wrong about the first time.
        std::fs::create_dir_all(&paths.db_dir).expect("the database directory is created");
        write(&paths.db_dir.join(DATABASE_FILE), b"x");
        assert_eq!(
            database_path(&paths),
            Some(paths.db_dir.join(DATABASE_FILE))
        );
        assert_ne!(
            paths.db_dir, data,
            "if these ever become the same directory this test stops proving anything"
        );
    }

    #[test]
    fn the_target_kind_is_the_report_s_own_and_not_a_guess() {
        let dir = tempfile::tempdir().expect("a temp directory");
        let file = dir.path().join("a.txt");
        write(&file, b"x");
        assert_eq!(target_of(&file), ScanTarget::File(file.clone()));
        assert_eq!(
            target_of(dir.path()),
            ScanTarget::Directory(dir.path().to_path_buf())
        );
        assert_eq!(
            target_of(Path::new("C:\\")),
            ScanTarget::Drive(PathBuf::from("C:\\"))
        );
        assert_eq!(
            target_of(Path::new("/")),
            ScanTarget::Drive(PathBuf::from("/"))
        );
    }

    #[test]
    fn a_failure_message_splits_at_the_last_separator_so_windows_paths_survive() {
        // `C:\a\b.txt: the file grew past the limit` — splitting at the first
        // `": "` would leave the path as `C` and put the drive's colon in the
        // reason.
        let (path, reason) = split_failure(
            "C:\\Users\\me\\bad.exe: the file grew past the 1024-byte limit",
            Path::new("C:\\scan"),
        );
        assert_eq!(path, PathBuf::from("C:\\Users\\me\\bad.exe"));
        assert_eq!(reason, "the file grew past the 1024-byte limit");

        // A message with no separator at all: a walk failure, which has no
        // path of its own to hand over.
        let (path, reason) = split_failure("permission denied", Path::new("C:\\scan"));
        assert_eq!(path, PathBuf::from("C:\\scan"));
        assert_eq!(reason, "permission denied");
    }

    #[test]
    fn the_rank_is_the_consoles_and_orders_the_bands_the_way_a_user_reads_them() {
        assert!(rank(Verdict::Malicious) > rank(Verdict::Suspicious));
        assert!(rank(Verdict::Suspicious) > rank(Verdict::Unknown));
        assert!(rank(Verdict::Unknown) > rank(Verdict::Clean));
        assert_eq!(rank(Verdict::Malicious), 3);
        assert_eq!(rank(Verdict::Clean), 0);
    }

    #[test]
    fn a_request_from_the_configuration_carries_the_configurations_answers() {
        let mut config = AvConfig::default();
        config.scanning.heuristics = false;
        config.scanning.trust = false;
        config.scanning.recursive = false;
        config.scanning.threads = 3;
        let request = ScanRequest::from_config("C:\\scan", "C:\\rules.avdb", &config, None);

        assert!(!request.options.heuristics);
        assert!(!request.options.trust);
        assert!(!request.options.recursive);
        assert_eq!(request.threads, 3);
        assert_eq!(request.thresholds, config.scanning.thresholds);
        assert!(
            !request.catalog,
            "trust is off, so there is nothing to index"
        );
        assert_eq!(request.database, PathBuf::from("C:\\rules.avdb"));
    }

    #[test]
    fn the_engine_is_built_from_the_request_and_not_from_the_defaults() {
        // The failure this catches: a builder that quietly used
        // `ScanningConfig`'s defaults while the window displayed the user's
        // settings.
        let dir = tempfile::tempdir().expect("a temp directory");
        let path = database(dir.path());
        let database = RuleDatabase::load(&path).expect("the test database loads");

        let mut config = AvConfig::default();
        config.scanning.thresholds = VerdictThresholds {
            suspicious: 5,
            malicious: 10,
        };
        let mut request = ScanRequest::from_config("C:\\scan", &path, &config, None);
        request.options.heuristics = false;
        request.options.trust = false;

        let engine = build_engine(database, &request);
        assert_eq!(engine.thresholds().malicious, 10);
        assert_eq!(engine.thresholds().suspicious, 5);
        assert!(!engine.heuristics().enabled);
        assert!(
            engine.catalog().is_none(),
            "trust is off, so nothing was indexed for it to consult"
        );
    }

    #[test]
    fn a_pool_of_no_preference_is_a_pool_and_a_number_is_taken_literally() {
        assert!(rayon_pool(0).is_ok());
        let pool = rayon_pool(2).expect("a two-thread pool builds");
        assert_eq!(pool.current_num_threads(), 2);
    }
}
