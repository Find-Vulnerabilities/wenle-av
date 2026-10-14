//! Watching processes as they start, and acting on what is inside them.
//!
//! # What this is for
//!
//! A minifilter sees files. It does not see a program that was already on the
//! disk before the filter was attached, and it does not see code that arrives in
//! a running process as *data* — a mapped file, a written page — rather than as
//! an image the loader opens. The first is covered by reading the *running
//! process*: the driver reports a process creation, this module walks that
//! process's memory with the same engine that scans files, and a finding is
//! handed to [`crate::host`], which is the only thing in this process that may
//! write to the vault.
//!
//! # Why every process is walked twice
//!
//! The notification this module is driven by arrives at process *creation* —
//! `PsSetCreateProcessNotifyRoutineEx` is called before the new process's first
//! instruction runs — so a walk that started then would see an address space
//! holding nothing but the image's own sections and `ntdll`. Sections of the
//! image are backed by a file and are skipped by `av_memory`'s predicate on
//! purpose, so the first walk finds nothing worth reading in the ordinary case:
//! whatever a program maps for itself is mapped *after* it starts.
//!
//! **This was measured, and the measurement is what the second walk is for.** A
//! process that maps a conviction-worthy file and then sleeps was run in the
//! test VM nine times on 2026-10-10 and 2026-10-11. Four of those runs were
//! convicted, and every one of those four walked an address space of 88 to 96
//! regions; the five that found nothing walked 37 to 41, which is a process that
//! has not finished starting. The walk and the program were in a race, and the
//! program won it about half the time. A scan that convicts on a coin toss is
//! not a security control, so a process this module examined and found clean is
//! walked **once more** after [`SETTLEMENT`] has passed — long enough for a
//! program to have done what it does at startup, short enough that the process
//! is still the one that was reported.
//!
//! What the second walk is not: it is not a watch. A program that injects
//! something into another process minutes after that process started is not seen
//! by either pass, and `wenle memory --pid` is the way to ask about a process
//! that is already running. That is the price of walking on an event; a
//! periodic whole-machine walk is what would cover the rest, and it is not
//! implemented.
//!
//! # Why this is not on the control thread
//!
//! [`crate::host::Host`] is a single-threaded control plane: it serves a client,
//! answers a driver decision and drains its channels between requests. A memory
//! walk is seconds of reading another process, and running one there would delay
//! every status query and — worse — every driver decision that arrived while it
//! ran. So this is a thread of its own with its own queue, following
//! `av_realtime::RealtimeService`'s shape: a bounded channel in, a channel of
//! outcomes out, a stop flag, and a `Drop` that ends it.
//!
//! # The four things that bound it
//!
//! Process starts arrive in bursts — starting a browser is dozens of them, a
//! build is hundreds — so nothing here may be unbounded:
//!
//! * the queue is bounded at [`MAX_PENDING_STARTS`], and a start that arrives
//!   when it is full is **dropped and counted**, never queued. Back-pressure was
//!   rejected: the producer is the driver's event stream, and a service that made
//!   the driver wait would be trading a missed scan for a missed file decision,
//!   which is the wrong trade in a security product.
//! * the list of processes waiting for their second walk is bounded at
//!   [`MAX_PENDING_SETTLEMENTS`] for the same reason, and a second walk that does
//!   not fit is dropped and logged. Nothing else is kept about a start: an entry
//!   leaves the list when it is walked, so what bounds it is the arrival rate
//!   over [`SETTLEMENT`] rather than the number of processes on the machine.
//! * each walk has a wall-clock [`SCAN_DEADLINE`], because a process that
//!   allocates as fast as it is read can stay under every byte budget and never
//!   finish.
//! * one process is walked at a time, because a walk is kernel-call bound and a
//!   second thread would contend for the same machine rather than overlap work.
//!   This is the reason `av_memory::MemoryScanner::scan_processes` is sequential
//!   too, and the reason a burst is shed by the queue instead of run in parallel.
//!
//! # What it deliberately does not do
//!
//! **It does not quarantine.** The vault's index is rewritten whole on every
//! change and has exactly one writer — [`crate::host::Host`] — which is the same
//! rule `av_realtime` follows with `block_on_detect = false`. A second writer
//! would silently discard the first one's entries, and the entries it discarded
//! would be the quarantines.
//!
//! **It does not decide policy.** Every question about a *file* is answered by
//! [`crate::memory::rule_on`], the same function the on-demand scan uses, so the
//! bar for taking a file found through memory cannot differ between the two
//! paths. What this module adds is the one judgement the on-demand path has no
//! use for — whether to stop the process — and that is `stop_if_justified`,
//! which is a pure function of what was found and what the user has allowed.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use av_core::paths::AvPaths;
use av_core::scan::ScanOptions;
use av_ipc::MemoryCoverage;
use av_memory::{MemoryFinding, MemoryScanConfig, ProcessRef, ProcessScan};
use av_scan::ScanEngine;

use crate::allow::AllowList;
use crate::engine;
use crate::memory;
use crate::terminate::{self, ProcessToken, Stopped};

/// How many process starts may be waiting to be examined.
///
/// A start that arrives with this many already waiting is dropped and counted.
/// See this module's documentation for why back-pressure is not the answer.
pub const MAX_PENDING_STARTS: usize = 32;

/// How long one process may be walked before the walk stops where it is.
///
/// Five seconds, which is far more than a walk of an ordinary process has been
/// measured to need — a whole-machine walk reads 54 to 77 MB across every
/// openable process — and far less than a client waiting on the control thread
/// would tolerate. A walk that runs out of time still reports every finding it
/// made before it did: `av_memory::ProcessOutcome::deadline_reached` records
/// that the address space was not seen in full rather than calling the process
/// clean.
pub const SCAN_DEADLINE: Duration = Duration::from_secs(5);

/// How long a process is given to finish starting before it is walked again.
///
/// The number is not a threshold anything is judged by — it is the answer to
/// "when is a program's startup over", and it is deliberately generous compared
/// with what a program takes to reach a `MapViewOfFile` of its own. The measured
/// runs behind it are in this module's documentation; the sample that motivated
/// it wrote its file and mapped it within a few milliseconds of its first
/// instruction, and lost the race anyway.
pub const SETTLEMENT: Duration = Duration::from_secs(2);

/// How many processes may be waiting for their second walk.
///
/// An entry leaves this list after [`SETTLEMENT`], so a burst that fills the
/// start queue cannot also fill this one: what it holds is roughly the starts of
/// the last two seconds. A second walk that does not fit is dropped and logged
/// rather than queued, for the reason [`MAX_PENDING_STARTS`] gives.
pub const MAX_PENDING_SETTLEMENTS: usize = 64;

/// How long the worker waits for a start before it looks at the stop flag.
const POLL: Duration = Duration::from_millis(100);

/// Which walk over one process this is.
///
/// The two are told apart because they count differently, not because they
/// judge differently: a process that was skipped or refused is a fact about the
/// *start*, and counting it twice would make the shutdown line say this service
/// declined to examine processes it never saw. A finding is a finding on either
/// pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// The walk the process's creation asked for.
    First,
    /// The walk [`SETTLEMENT`] later, for a process the first walk found clean.
    Second,
}

/// One process creation, as the driver reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    /// The new process's identifier.
    pub pid: u32,
    /// The image it was started from, when the driver had a name for it.
    ///
    /// Used for the two cheap refusals — the product's own tree, and a path the
    /// user has allowed — before a handle is opened at all. It is *not* what the
    /// process is identified by: [`av_memory::identify`] asks the kernel for a
    /// process's own image path, and the two can differ for a process that
    /// replaced its own image after starting.
    pub path: Option<PathBuf>,
}

/// One finding, and the ruling on the file behind it.
///
/// The two travel together because the host needs both and can produce neither:
/// the finding names the process and the address, and the ruling is what is acted
/// on. The ruling carries the file's own scan report, which is what the vault
/// records.
#[derive(Debug, Clone)]
pub struct Judged {
    /// What matched in memory.
    pub finding: MemoryFinding,
    /// What was decided about the file the bytes came from.
    pub ruling: memory::Ruling,
}

/// One process the worker examined, and everything the host needs to act on it.
#[derive(Debug)]
pub struct Watched {
    /// The process's identifier.
    pub pid: u32,
    /// The process, as a sentence.
    pub process: String,
    /// When it was identified — taken **before** the walk, so that this names
    /// the process whose memory was read rather than whatever holds the
    /// identifier now.
    pub token: ProcessToken,
    /// How much of the address space was read.
    pub coverage: MemoryCoverage,
    /// True when the walk reached the end of the address space.
    pub walk_complete: bool,
    /// True when the walk stopped because its deadline passed, as opposed to
    /// having reached the region cap. The two stop reasons get different
    /// sentences — see `av_memory::ProcessOutcome`.
    pub deadline_reached: bool,
    /// Set when the process was not examined at all, with the reason.
    pub refused: Option<String>,
    /// What each finding turned out to be. Empty for a clean process.
    pub findings: Vec<Judged>,
    /// What happened about stopping it, including nothing.
    pub stopped: Stopped,
}

impl Watched {
    /// True when the process is gone because this worker stopped it.
    ///
    /// Forwarded from [`Stopped::happened`] because it is the value
    /// `av_ipc::Detection::terminated` is set from, and a caller that reached
    /// for the field directly would have to know which variant counts.
    pub const fn terminated(&self) -> bool {
        self.stopped.happened()
    }

    /// A process that was never examined, for a reason worth a sentence.
    fn not_examined(pid: u32, process: String, token: ProcessToken, why: String) -> Self {
        Self {
            pid,
            process,
            token,
            coverage: MemoryCoverage::default(),
            walk_complete: false,
            deadline_reached: false,
            refused: Some(why),
            findings: Vec::new(),
            stopped: Stopped::NotAttempted {
                why: "the process was not examined, so nothing was decided about it".to_string(),
            },
        }
    }
}

/// Counters the worker keeps so that what it skipped is visible.
///
/// Atomics rather than a channel, because a counter is read while the thread
/// runs and a reader must not be able to block the worker. Every one of these is
/// a *fact about coverage*, which is why they exist: a security product that
/// silently declined to examine a hundred processes is indistinguishable from one
/// that examined them and found nothing.
#[derive(Debug, Default)]
struct Counters {
    starts: AtomicU64,
    dropped: AtomicU64,
    skipped_own: AtomicU64,
    skipped_allowed: AtomicU64,
    skipped_idle: AtomicU64,
    refused: AtomicU64,
    examined: AtomicU64,
    walked_again: AtomicU64,
    settlement_dropped: AtomicU64,
    findings: AtomicU64,
    stopped: AtomicU64,
}

/// What the worker has done, as of the moment it was read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessWatchStats {
    /// Process creations offered to the worker.
    pub starts: u64,
    /// Starts dropped because the queue was full.
    pub dropped: u64,
    /// Starts skipped because the process is this service or inside its tree.
    pub skipped_own: u64,
    /// Starts skipped because the user has allowed that path.
    pub skipped_allowed: u64,
    /// Starts skipped because the identifier was the idle process's.
    pub skipped_idle: u64,
    /// Processes that could not be opened or walked.
    pub refused: u64,
    /// Processes whose memory was walked.
    pub examined: u64,
    /// Processes walked a second time, [`SETTLEMENT`] after they started.
    ///
    /// `examined - walked_again` is the number of processes whose second walk
    /// did not happen, and that number is **two different facts**: the process
    /// had ended in between, which is the ordinary case and is fine — a program
    /// that is gone cannot hold injected code — or it was still running and the
    /// list of processes waiting for a second walk was full. Only the second is a
    /// gap in coverage, and it is [`Self::settlement_dropped`], which is what a
    /// reader should act on. The subtraction is not the number to look at.
    pub walked_again: u64,
    /// Processes that were examined once and never a second time because the
    /// list of processes waiting for their second walk was full.
    ///
    /// This is the coverage gap the second walk exists to close, so it is
    /// disclosed rather than only counted — the same shape as [`Self::dropped`],
    /// and for the same reason: a machine busy enough to fill this is exactly the
    /// machine whose process list a user would want to trust. A burst that fills
    /// it is a build, an installer or a script that spawns hundreds of
    /// processes, and what it costs is that those processes were read once, at
    /// creation, when the walk is the race this module's documentation describes.
    pub settlement_dropped: u64,
    /// Findings across every process examined.
    pub findings: u64,
    /// Processes this worker terminated.
    pub stopped: u64,
}

impl ProcessWatchStats {
    /// One sentence for a log line.
    pub fn describe(&self) -> String {
        format!(
            "{} start(s): {} examined, {} walked again after {}s, {} refused, {} skipped, {} \
             dropped, {} finding(s), {} process(es) stopped",
            self.starts,
            self.examined,
            self.walked_again,
            SETTLEMENT.as_secs(),
            self.refused,
            self.skipped_own + self.skipped_allowed + self.skipped_idle,
            self.dropped,
            self.findings,
            self.stopped
        )
    }
}

/// How a process's memory is examined.
///
/// A seam rather than a direct call, because the policy this module implements —
/// what to skip, what to decide, whether to stop — is worth testing without a
/// process to walk, and a test that had to plant a real injected page in a real
/// process could only state its assertions on the machines where that worked.
/// The real implementation is [`RealScanner`].
pub(crate) trait ProcessScanner: Send + Sync + 'static {
    /// Walk one process and judge what is in it.
    fn examine(&self, process: &ProcessRef, deadline: Duration) -> ProcessScan;
}

/// The scanner this service runs: `av-memory` over the shared engine.
struct RealScanner {
    engine: Arc<ScanEngine>,
}

impl ProcessScanner for RealScanner {
    #[cfg(windows)]
    fn examine(&self, process: &ProcessRef, deadline: Duration) -> ProcessScan {
        let mut source = match av_memory::Win32Source::open(process.clone()) {
            Ok(source) => source,
            Err(error) => {
                return ProcessScan::Refused {
                    process: process.clone(),
                    reason: av_memory::RefusalReason::from_error(&error),
                }
            }
        };
        // The deadline is the only difference from the options a client-asked
        // scan uses, and it is the documented reason a process-start scan has
        // one at all. Everything else is `av_memory`'s default, so that a byte
        // read here is judged by the same scanner a whole-machine memory scan
        // would use.
        let scanner = av_memory::MemoryScanner::new(
            &self.engine,
            MemoryScanConfig {
                deadline: Some(deadline),
                ..MemoryScanConfig::default()
            },
        );
        scanner.scan_process(&mut source)
    }

    #[cfg(not(windows))]
    fn examine(&self, process: &ProcessRef, _deadline: Duration) -> ProcessScan {
        ProcessScan::Refused {
            process: process.clone(),
            reason: av_memory::RefusalReason::RegionsUnavailable {
                code: 0,
                message: "this build has no way to read another process's memory".to_string(),
            },
        }
    }
}

/// What the worker needs that does not change, or changes through an `Arc`.
struct Context {
    engine: Arc<ScanEngine>,
    paths: AvPaths,
    /// A clone of the host's list, which shares its storage — so a path the user
    /// allows while a walk is in flight is honoured by that walk.
    allow: AllowList,
    /// The options a *file* examination uses, which is the configuration in
    /// force. The memory read itself uses `av_memory`'s defaults, as the
    /// on-demand path does.
    options: ScanOptions,
    /// How long a process is given before it is walked a second time.
    ///
    /// A field rather than [`SETTLEMENT`] itself so that a test can say when the
    /// second walk happens instead of waiting for it. A test that is not about
    /// the second walk passes a value long enough that it never arrives, which
    /// is what keeps every other test in this module stating the same thing it
    /// stated before there was a second walk.
    settlement: Duration,
    /// The process this service is.
    ///
    /// Skipped unconditionally, and the reason is not the one that first suggests
    /// itself. The tempting argument is that this process holds the compiled rule
    /// database, so every rule's own pattern text is in its memory and a walk of
    /// it would match rules against the rulebook containing them. **That argument
    /// is wrong, and it was measured wrong**: `wenle memory` sweeping this
    /// machine found nothing in its own process either, because the predicate
    /// only reads regions that are *executable and* private or writable, and the
    /// database is mapped read-only. Nothing here depends on that staying true,
    /// though — a change to the predicate or to how the database is mapped could
    /// make it false, and a skip that rests on a coincidence is not a skip.
    ///
    /// The reason it is skipped is simpler and does not depend on any of that: a
    /// finding about *this* process is never a fact about the machine. It can
    /// only be about our own binary or our own data — and every action this
    /// product takes on a finding is to quarantine the file behind it or
    /// terminate the process holding it, so acting on one would be this service
    /// quarantining itself or killing itself. What it would buy is nothing: the
    /// same bytes are examined as a file at start-up and whenever the database is
    /// loaded, by the path that is meant to judge them.
    own_pid: u32,
    /// Whether a process may be terminated. An atomic because the setting can be
    /// changed while the worker runs, and a worker holding the value it started
    /// with would go on killing processes after the user turned that off.
    terminating: Arc<AtomicBool>,
    scanner: Arc<dyn ProcessScanner>,
}

/// A running process watcher.
#[derive(Debug)]
pub struct ProcessWatch {
    starts: crossbeam_channel::Sender<Start>,
    outcomes: crossbeam_channel::Receiver<Watched>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    counters: Arc<Counters>,
    terminating: Arc<AtomicBool>,
}

impl Drop for ProcessWatch {
    /// Stop the thread without waiting for it.
    ///
    /// The flag is what the worker's receive loop tests; it is set here as well
    /// as in [`ProcessWatch::stop`] so that dropping the last handle cannot leave
    /// a thread walking processes for the life of the process. The walk itself is
    /// not interruptible — it is a sequence of kernel reads — so an exit can be
    /// delayed by up to [`SCAN_DEADLINE`], which is the deadline's other purpose.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl ProcessWatch {
    /// Start watching.
    ///
    /// Takes the engine, the paths and the allow list the host already owns. The
    /// vault is deliberately not among them — see this module's documentation.
    pub fn start(
        engine: Arc<ScanEngine>,
        paths: AvPaths,
        allow: AllowList,
        options: ScanOptions,
        terminating: bool,
    ) -> Result<Self, ProcessWatchError> {
        let scanner = Arc::new(RealScanner {
            engine: Arc::clone(&engine),
        });
        Self::run_over(Context {
            engine,
            paths,
            allow,
            options,
            settlement: SETTLEMENT,
            own_pid: std::process::id(),
            terminating: Arc::new(AtomicBool::new(terminating)),
            scanner,
        })
    }

    /// Start over a context a test built.
    ///
    /// The one entry point, so that the thread, the channels and the counters are
    /// the same in a test as in a service — the only thing a test changes is how
    /// a process's memory is read.
    #[cfg(test)]
    fn start_with(context: Context) -> Result<Self, ProcessWatchError> {
        Self::run_over(context)
    }

    /// Start over a scanner some other test module supplies.
    ///
    /// The service's own tests need the whole chain — a driver event, the worker,
    /// the host and the vault — to be exercised in one go, and they cannot use
    /// [`ProcessWatch::start_with`] because [`Context`] is private to this
    /// module. Everything but the scanner is what [`ProcessWatch::start`] builds,
    /// including `own_pid`, so a host test gets the real process's identifier
    /// rather than a stand-in.
    #[cfg(test)]
    pub(crate) fn start_with_scanner(
        engine: Arc<ScanEngine>,
        paths: AvPaths,
        allow: AllowList,
        options: ScanOptions,
        terminating: bool,
        scanner: Arc<dyn ProcessScanner>,
    ) -> Result<Self, ProcessWatchError> {
        Self::run_over(Context {
            engine,
            paths,
            allow,
            options,
            settlement: SETTLEMENT,
            own_pid: std::process::id(),
            terminating: Arc::new(AtomicBool::new(terminating)),
            scanner,
        })
    }

    fn run_over(context: Context) -> Result<Self, ProcessWatchError> {
        let (starts, queue) = crossbeam_channel::bounded(MAX_PENDING_STARTS);
        let (out, outcomes) = crossbeam_channel::unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let terminating = Arc::clone(&context.terminating);

        let worker = std::thread::Builder::new()
            .name("av-process-watch".to_string())
            .spawn({
                let stop = Arc::clone(&stop);
                let counters = Arc::clone(&counters);
                move || run(&context, &queue, &out, &stop, &counters)
            })
            .map_err(|source| ProcessWatchError::WorkerSpawn { source })?;

        Ok(Self {
            starts,
            outcomes,
            stop,
            worker: Some(worker),
            counters,
            terminating,
        })
    }

    /// Tell the worker about a process that has started.
    ///
    /// Returns false when the queue was full and the start was dropped, which the
    /// caller does not have to act on — it is counted either way — but which a
    /// test asserts on.
    #[must_use]
    pub fn note_start(&self, start: Start) -> bool {
        self.counters.starts.fetch_add(1, Ordering::Relaxed);
        match self.starts.try_send(start) {
            Ok(()) => true,
            // Both failures are a start that will not be examined, and both are
            // counted as one. They are different facts — a full queue is this
            // service being behind, and a disconnected one is the worker having
            // ended — but neither is something a caller can act on, and the
            // worker's own log line says which happened when it ends.
            Err(_) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// The processes that have been examined, oldest first.
    pub fn outcomes(&self) -> &crossbeam_channel::Receiver<Watched> {
        &self.outcomes
    }

    /// What the worker has done so far.
    pub fn stats(&self) -> ProcessWatchStats {
        ProcessWatchStats {
            starts: self.counters.starts.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            skipped_own: self.counters.skipped_own.load(Ordering::Relaxed),
            skipped_allowed: self.counters.skipped_allowed.load(Ordering::Relaxed),
            skipped_idle: self.counters.skipped_idle.load(Ordering::Relaxed),
            refused: self.counters.refused.load(Ordering::Relaxed),
            examined: self.counters.examined.load(Ordering::Relaxed),
            walked_again: self.counters.walked_again.load(Ordering::Relaxed),
            settlement_dropped: self.counters.settlement_dropped.load(Ordering::Relaxed),
            findings: self.counters.findings.load(Ordering::Relaxed),
            stopped: self.counters.stopped.load(Ordering::Relaxed),
        }
    }

    /// Whether a process may be terminated, from now on.
    ///
    /// Called when the configuration changes. Read by the worker at the moment
    /// it decides, so a change is in force before the next process start is
    /// decided on rather than at the next restart.
    pub fn set_terminating(&self, terminating: bool) {
        self.terminating.store(terminating, Ordering::SeqCst);
    }

    /// True when the worker will terminate a process whose file convicted.
    pub fn is_terminating(&self) -> bool {
        self.terminating.load(Ordering::SeqCst)
    }

    /// Stop the worker and wait for it.
    ///
    /// Returns false when the thread did not end cleanly, which in practice
    /// means it panicked. The counters are readable either way, and are read
    /// before this is called.
    pub fn stop(mut self) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        match self.worker.take() {
            Some(worker) => worker.join().is_ok(),
            None => true,
        }
    }
}

/// A watcher that could not be started.
#[derive(Debug, thiserror::Error)]
pub enum ProcessWatchError {
    /// The operating system would not create the thread.
    #[error("the process watcher's thread could not be started: {source}")]
    WorkerSpawn {
        /// What the operating system said.
        source: std::io::Error,
    },
}

/// The worker's loop.
fn run(
    context: &Context,
    queue: &crossbeam_channel::Receiver<Start>,
    out: &crossbeam_channel::Sender<Watched>,
    stop: &AtomicBool,
    counters: &Counters,
) {
    // The processes waiting for their second walk, in the order they are due.
    // Starts arrive in time order and every one is given the same delay, so the
    // order they are pushed in is the order they come due in and the front of
    // the queue is always the next one to walk.
    let mut settling: VecDeque<(Instant, Start)> = VecDeque::new();

    while !stop.load(Ordering::SeqCst) {
        // Never sleep past a second walk that is due, and never longer than the
        // poll: the stop flag is the other reason this thread wants to wake.
        let wait = settling
            .front()
            .map(|(due, _)| due.saturating_duration_since(Instant::now()))
            .unwrap_or(POLL)
            .min(POLL);

        match queue.recv_timeout(wait) {
            Ok(start) => {
                let watched = examine(context, &start, counters, Pass::First);
                // The second walk is for a process this one found nothing in, and
                // only for one that was read at all: a process that had already
                // ended, or that this service never examines, has nothing to say
                // the second time either — and a finding here has already been
                // acted on, so walking it again could only produce the same
                // finding twice.
                let again = watched.refused.is_none() && watched.findings.is_empty();
                // A closed receiver means the host has gone and there is nobody
                // to tell. The loop keeps draining rather than ending, because
                // the queue must not fill behind a host that is coming back.
                let _ = out.send(watched);
                if again {
                    if settling.len() < MAX_PENDING_SETTLEMENTS {
                        settling.push_back((Instant::now() + context.settlement, start));
                    } else {
                        // Counted, and disclosed from the count rather than from
                        // this line: a `debug!` in a log whose level is fixed is
                        // not a readout, which is the mistake this module has
                        // made before with the empty-findings arm in `host.rs`.
                        counters.settlement_dropped.fetch_add(1, Ordering::Relaxed);
                        log::debug!(
                            "the second walk of pid {} was dropped: {} processes are already \
                             waiting for theirs",
                            start.pid,
                            settling.len()
                        );
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }

        while settling
            .front()
            .is_some_and(|(due, _)| *due <= Instant::now())
        {
            let Some((_, start)) = settling.pop_front() else {
                break;
            };
            let watched = examine(context, &start, counters, Pass::Second);
            let _ = out.send(watched);
        }
    }
}

/// Examine one process and act on what is in it.
fn examine(context: &Context, start: &Start, counters: &Counters, pass: Pass) -> Watched {
    let first = pass == Pass::First;

    // The idle process has no address space to read, and asking for it costs a
    // syscall that always fails.
    if start.pid == 0 {
        if first {
            counters.skipped_idle.fetch_add(1, Ordering::Relaxed);
        }
        return Watched::not_examined(
            0,
            "the idle process".to_string(),
            ProcessToken::of(0),
            "process 0 is the idle process and has no address space".to_string(),
        );
    }

    // This service, by its identifier rather than by its path. The path check
    // below covers the installed case; this covers the one it does not — a build
    // run out of a target directory — and what it prevents is a finding whose
    // only possible subject is this product itself: see `Context::own_pid`.
    if start.pid == context.own_pid {
        if first {
            counters.skipped_own.fetch_add(1, Ordering::Relaxed);
        }
        return Watched::not_examined(
            start.pid,
            "this service".to_string(),
            ProcessToken::of(start.pid),
            "the process is the service itself, and a finding about it could only be about the \
             product, which would mean the product quarantining or killing itself"
                .to_string(),
        );
    }

    // The product's own tree, before a handle is opened. The vault's contents
    // live under the data directory, and they are files this product already
    // decided were malicious — a memory scan of a process that has one mapped
    // would otherwise quarantine the vault's own item.
    if let Some(path) = &start.path {
        if engine::is_own_tree(&context.paths, path) {
            if first {
                counters.skipped_own.fetch_add(1, Ordering::Relaxed);
            }
            return Watched::not_examined(
                start.pid,
                path.display().to_string(),
                ProcessToken::of(start.pid),
                format!(
                    "{} is inside the product's own directory, which is never examined from here",
                    path.display()
                ),
            );
        }
        if context.allow.allows(path) {
            if first {
                counters.skipped_allowed.fetch_add(1, Ordering::Relaxed);
            }
            return Watched::not_examined(
                start.pid,
                path.display().to_string(),
                ProcessToken::of(start.pid),
                format!("{} is allowed by the user's own decision", path.display()),
            );
        }
    }

    // Identified before the walk, never after: a process that exits while being
    // read and whose identifier is then reused must leave this naming the process
    // that *was* read. `crate::terminate` is what acts on that, from this token.
    let token = ProcessToken::of(start.pid);
    let process = av_memory::identify(start.pid);
    let described = process.describe();

    let outcome = match context.scanner.examine(&process, SCAN_DEADLINE) {
        ProcessScan::Refused { reason, .. } => {
            // A second walk is only ever asked for a process the first one read,
            // so a refusal here means the process ended in between. It is not
            // counted as a refusal — that counter is about a *start* this service
            // could not examine, and this one it did — but it is said, because
            // the alternative is a shutdown line reading "5 examined, 4 walked
            // again" with nothing anywhere naming the fifth.
            if !first {
                return Watched::not_examined(
                    start.pid,
                    described,
                    token,
                    format!(
                        "the process had ended before this walk, which is the second one, {}s \
                         after it started",
                        SETTLEMENT.as_secs()
                    ),
                );
            }
            counters.refused.fetch_add(1, Ordering::Relaxed);
            return Watched::not_examined(start.pid, described, token, reason.describe());
        }
        ProcessScan::Examined(outcome) => outcome,
    };
    if first {
        counters.examined.fetch_add(1, Ordering::Relaxed);
    } else {
        counters.walked_again.fetch_add(1, Ordering::Relaxed);
    }

    let mut findings = Vec::with_capacity(outcome.findings.len());
    for finding in &outcome.findings {
        let ruling = memory::rule_on(
            &finding.origin,
            &context.paths,
            &context.engine,
            &context.options,
        );
        findings.push(Judged {
            finding: finding.clone(),
            ruling,
        });
    }
    counters
        .findings
        .fetch_add(findings.len() as u64, Ordering::Relaxed);

    let stopped = stop_if_justified(context, start, &token, &findings);
    if stopped.happened() {
        counters.stopped.fetch_add(1, Ordering::Relaxed);
    }

    Watched {
        pid: start.pid,
        process: described,
        token,
        coverage: memory::coverage_of(&outcome),
        walk_complete: outcome.walk_complete,
        deadline_reached: outcome.deadline_reached,
        refused: None,
        findings,
        stopped,
    }
}

/// Stop the process, if anything justifies it and the user has not said not to.
///
/// # The bar
///
/// A memory match is not a reason to kill a process, and this function is where
/// that is enforced. What it requires is a finding whose *file* — examined in its
/// own right, by the same engine and the same thresholds that would have judged
/// it had the file walker reached it first — cleared the bar to be taken into the
/// vault. That is the condition under which this product has already decided a
/// file is malicious, and it is the only condition under which it will kill the
/// program running it.
///
/// A finding in a region no file backs is *not* such a condition, and that is the
/// hard half of this decision: [`memory::Left::NoFile`] is a real detection — the
/// shape of injected code — and it produces no [`memory::Action::Take`], so a
/// process whose only finding is injected code is reported and not stopped. That
/// is deliberate and it is the honest limit of what this build can prove: a
/// region written into a process by something else says nothing about which
/// program put it there, and terminating the process on that evidence alone would
/// be terminating the victim.
///
/// # The refusals
///
/// Each of these would otherwise be a process killed over a detection nobody
/// would stand behind:
///
/// * the configuration does not terminate processes;
/// * the process's own image is on the user's allow list — a user who allowed a
///   program meant to keep it, and killing it would be the exact opposite;
/// * the finding's file is on the allow list, which is the same decision
///   [`crate::host::Host::quarantine`]'s own backstop makes at the moment of
///   taking.
///
/// Nothing here re-asks whether the process is still the one that was scanned.
/// That is [`terminate::stop`]'s to answer, from the token, and it answers it
/// from the handle it terminates through.
fn stop_if_justified(
    context: &Context,
    start: &Start,
    token: &ProcessToken,
    findings: &[Judged],
) -> Stopped {
    if !context.terminating.load(Ordering::SeqCst) {
        return Stopped::NotAttempted {
            why: "realtime.terminate_malicious_process is off".to_string(),
        };
    }

    if let Some(image) = start.path.as_deref() {
        if context.allow.allows(image) {
            return Stopped::NotAttempted {
                why: format!("{} is allowed by the user's own decision", image.display()),
            };
        }
    }

    // Every file a finding points at that was malicious enough to be taken. The
    // two ways this can come up empty are *different facts* — nothing convicted,
    // or everything that convicted is allowed — and they are reported apart,
    // because a reader who saw the wrong one would go looking in the wrong
    // place. Collapsing them into a single `find_map` with the allow check in the
    // guard does exactly that, which is how this was first written.
    let taken: Vec<&PathBuf> = findings
        .iter()
        .filter_map(|judged| match &judged.ruling.action {
            memory::Action::Take { file } => Some(file),
            memory::Action::Leave { .. } => None,
        })
        .collect();
    if taken.is_empty() {
        return Stopped::NotAttempted {
            why: "no finding's own file was malicious enough to act on".to_string(),
        };
    }
    let Some(file) = taken.iter().copied().find(|file| !context.allow.allows(file)) else {
        return Stopped::NotAttempted {
            why: format!(
                "{} is allowed by the user's own decision, and it is the only file any finding \
                 points at",
                taken[0].display()
            ),
        };
    };

    log::warn!(
        "the process {} (pid {}) holds code from {} and is being stopped",
        start
            .path
            .as_deref()
            .map(Path::display)
            .map(|path| path.to_string())
            .unwrap_or_else(|| "whose image could not be named".to_string()),
        start.pid,
        file.display()
    );
    terminate::stop(token)
}

/// A scanner a test states the answer for.
///
/// Public to the crate so that `crate::host`'s tests can drive the whole chain —
/// a driver event, the worker, the host and the vault — with a memory answer
/// they chose, rather than walking whatever happens to be resident on the machine
/// running the suite.
#[cfg(test)]
pub(crate) mod testing {
    use super::{ProcessScanner, ProcessRef, ProcessScan};
    use std::time::Duration;

    /// A scanner that answers the same way for every process.
    ///
    /// The answer is handed the deadline as well as the process, because the
    /// deadline is the one thing the worker passes that a test cannot see from
    /// the outside — there is no field on `Watched` for it.
    pub(crate) struct FixedScanner {
        answer: Box<dyn Fn(&ProcessRef, Duration) -> ProcessScan + Send + Sync>,
    }

    impl FixedScanner {
        /// A scanner that answers `answer` for every process it is asked about.
        pub(crate) fn new(
            answer: impl Fn(&ProcessRef, Duration) -> ProcessScan + Send + Sync + 'static,
        ) -> Self {
            Self {
                answer: Box::new(answer),
            }
        }
    }

    impl ProcessScanner for FixedScanner {
        fn examine(&self, process: &ProcessRef, deadline: Duration) -> ProcessScan {
            (self.answer)(process, deadline)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use av_core::scan::FileScanReport;
    use av_core::Verdict;
    use av_memory::{Interest, Origin, ProcessOutcome, Protection, RegionKind};
    use av_rules::database::RuleDatabase;

    /// The bytes the test rule looks for.
    ///
    /// Benign on purpose: a fixture that carried a real malware idiom would be
    /// quarantined by the machine's own antivirus, which then refuses to build
    /// the test binary at all.
    const MARKER: &str = "WENLE-PROCESS-WATCH-MARKER";

    /// An engine with one rule, which fires on a file containing [`MARKER`].
    ///
    /// The severity is stated rather than left out, and that is not decoration:
    /// a rule with no severity scores as `Medium`, which is 60, which is the
    /// yellow band — and the yellow band never acts. The whole point of these
    /// tests is the bar, so the fixture has to be over it.
    fn engine() -> Arc<ScanEngine> {
        let source = format!(
            "rule Test_Finds_Marker {{\n  meta:\n    severity = \"critical\"\n  \
             strings:\n    $a = \"{MARKER}\"\n  condition:\n    $a\n}}\n"
        );
        let (database, report) = RuleDatabase::compile(&source);
        assert!(
            report.refused() == 0 && database.len() == 1,
            "the test rule must compile: {report:?}"
        );
        Arc::new(ScanEngine::new(database))
    }

    /// Options under which the verdict is the rule's and nothing else's.
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

    /// Paths under a temporary directory, so the own-tree check has something
    /// real to answer about.
    fn layout(dir: &tempfile::TempDir) -> AvPaths {
        AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"))
    }

    /// A finding attributed to `pid`, with whatever origin a test wants.
    fn finding(pid: u32, origin: Origin, verdict: Verdict) -> MemoryFinding {
        MemoryFinding {
            process: ProcessRef::new(pid, Some(PathBuf::from(r"C:\x\subject.exe"))),
            base: 0x0040_1000,
            region_size: 0x1000,
            bytes_read: 0x1000,
            truncated: false,
            interest: Interest::UnbackedCode,
            // `PAGE_EXECUTE_READWRITE`, which is what an injected page looks
            // like and what the predicate reads as worth examining.
            protection: Protection::from_raw(0x40),
            kind: RegionKind::Private,
            origin,
            verdict,
            score: 1_000,
            detections: Vec::new(),
        }
    }

    /// A scan outcome that reports `findings` for `pid`.
    fn outcome(pid: u32, findings: Vec<MemoryFinding>) -> ProcessScan {
        let mut outcome = ProcessOutcome::new(ProcessRef::new(pid, None));
        outcome.findings = findings;
        outcome.regions_seen = 4;
        outcome.regions_read = 1;
        outcome.bytes_read = 0x1000;
        ProcessScan::Examined(Box::new(outcome))
    }

    /// What a scanner was asked about, so a test can assert on the asks.
    #[derive(Default)]
    struct Asked {
        examined: Mutex<Vec<u32>>,
        deadlines: Mutex<Vec<Duration>>,
    }

    /// A watcher over a scanner that reports `findings` for any process.
    ///
    /// The second walk is put out of reach rather than switched off, because
    /// there is no switch: a process this watcher examined and found clean is
    /// walked again, and that is the whole of the change. Every test that is not
    /// *about* the second walk would otherwise read a second outcome for its one
    /// start and fail on the count of answers — so they all ask for a settlement
    /// longer than the suite runs and never see it. [`HOUR`] is that value, and
    /// [`a_clean_process_is_walked_a_second_time`] is the test that states the
    /// other half.
    fn watching(
        dir: &tempfile::TempDir,
        allow: AllowList,
        terminating: bool,
        scanner: Arc<dyn ProcessScanner>,
    ) -> ProcessWatch {
        watching_after(dir, allow, terminating, scanner, HOUR)
    }

    /// An hour, as the tests use it: longer than they run, so "never" is exact.
    const HOUR: Duration = Duration::from_secs(3600);

    /// A watcher whose second walk is due `settlement` after a start.
    fn watching_after(
        dir: &tempfile::TempDir,
        allow: AllowList,
        terminating: bool,
        scanner: Arc<dyn ProcessScanner>,
        settlement: Duration,
    ) -> ProcessWatch {
        ProcessWatch::start_with(Context {
            engine: engine(),
            paths: layout(dir),
            allow,
            options: options(),
            settlement,
            // A pid no test uses, so the "this service" skip never fires by
            // accident. The skip itself is asserted with `own_pid` directly.
            own_pid: 0xFFFF_FFF0,
            terminating: Arc::new(AtomicBool::new(terminating)),
            scanner,
        })
        .expect("the watcher's thread starts")
    }

    /// A scanner that finds `original` in every process it is asked about.
    fn constant(original: Origin) -> Arc<dyn ProcessScanner> {
        Arc::new(testing::FixedScanner::new(move |process, _deadline| {
                let pid = process.pid;
                outcome(pid, vec![finding(pid, original.clone(), Verdict::Malicious)])
            }))
    }

    /// Ask the watcher about one process and wait for the answer.
    fn watch_one(watch: &ProcessWatch, start: Start) -> Watched {
        assert!(watch.note_start(start), "the queue took the start");
        watch
            .outcomes()
            .recv_timeout(Duration::from_secs(10))
            .expect("the worker answers")
    }

    /// A file on disk that the test rule convicts.
    fn convicting_file(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("prefix {MARKER} suffix")).expect("the file is writable");
        path
    }

    #[test]
    fn a_process_holding_a_file_the_engine_convicts_is_terminated() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(&watch, Start { pid: 4242, path: None });
        assert_eq!(watched.pid, 4242);
        assert_eq!(watched.findings.len(), 1);
        assert!(
            watched.findings[0].ruling.action.is_take(),
            "the file is malicious in its own right, so the ruling must be to take it: {:?}",
            watched.findings[0].ruling.action
        );
        // There is no process 4242 on any machine, so the termination is refused
        // rather than performed — and it is a *refusal*, which is the point: the
        // worker tried, because every condition it is allowed to consider was
        // met. A process that really existed would have gone.
        assert!(
            !matches!(watched.stopped, Stopped::NotAttempted { .. }),
            "every condition for stopping was met: {:?}",
            watched.stopped
        );
        assert!(
            !watched.terminated(),
            "no process was terminated, so nothing may claim one was"
        );
        assert_eq!(watch.stats().stopped, 0);
        assert_eq!(watch.stats().examined, 1);
        assert_eq!(watch.stats().findings, 1);
        assert!(watch.stop(), "the worker ends cleanly");
    }

    #[test]
    fn a_process_holding_a_file_that_is_not_malicious_is_left_running() {
        // The guard that matters most: a match in memory whose file turns out to
        // be ordinary must not cost the user a running program.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("ordinary.dll");
        std::fs::write(&file, b"nothing of interest here").expect("the file is writable");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(&watch, Start { pid: 4243, path: None });
        assert_eq!(watched.findings.len(), 1);
        assert!(!watched.findings[0].ruling.action.is_take());
        match &watched.stopped {
            Stopped::NotAttempted { why } => {
                assert!(why.contains("malicious enough"), "{why}");
            }
            other => panic!("the process must be left alone, got {other:?}"),
        }
        assert!(watch.stop());
    }

    #[test]
    fn injected_code_is_reported_and_the_process_is_not_killed_for_it() {
        // The hard half of the bar, stated as a test. A region no file backs is
        // a real detection and it is *not* grounds for terminating the process:
        // it says nothing about which program wrote those bytes, so the process
        // could be the victim. This test is what stops a later change from
        // making "the scan found something" into "kill it".
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::Nothing),
        );

        let watched = watch_one(&watch, Start { pid: 4244, path: None });
        assert_eq!(watched.findings.len(), 1);
        match &watched.findings[0].ruling.action {
            memory::Action::Leave { file, why } => {
                assert!(file.is_none());
                assert_eq!(*why, memory::Left::NoFile);
            }
            other => panic!("nothing on disk backs these bytes, so nothing is taken: {other:?}"),
        }
        assert!(matches!(
            watched.stopped,
            Stopped::NotAttempted { .. }
        ));
        assert!(!watched.terminated());
        assert!(watch.stop());
    }

    #[test]
    fn with_termination_off_a_conviction_is_still_ruled_on_and_nothing_is_stopped() {
        // The ruling is the same either way — the file is taken into the vault
        // by the host regardless — and only the stopping changes.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            false,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(&watch, Start { pid: 4245, path: None });
        assert!(watched.findings[0].ruling.action.is_take());
        match &watched.stopped {
            Stopped::NotAttempted { why } => {
                assert!(why.contains("terminate_malicious_process"), "{why}");
            }
            other => panic!("termination is off, got {other:?}"),
        }
        assert!(watch.stop());
    }

    #[test]
    fn the_setting_can_be_turned_on_and_off_while_the_worker_runs() {
        // The worker is a thread and the configuration is not: a change made
        // through the window has to reach a decision that has not been made yet.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            false,
            constant(Origin::File { path: file.clone() }),
        );

        assert!(!watch.is_terminating());
        watch.set_terminating(true);
        assert!(watch.is_terminating());
        let watched = watch_one(&watch, Start { pid: 4246, path: None });
        assert!(
            !matches!(watched.stopped, Stopped::NotAttempted { .. }),
            "the setting was on by the time the decision was made: {:?}",
            watched.stopped
        );

        watch.set_terminating(false);
        let watched = watch_one(&watch, Start { pid: 4247, path: None });
        assert!(matches!(
            watched.stopped,
            Stopped::NotAttempted { .. }
        ));
        assert!(watch.stop());
    }

    #[test]
    fn a_file_the_user_allowed_is_not_grounds_for_stopping_the_process() {
        // The allow list is asked *before* the termination — which is the whole
        // reason this check is in this function rather than in the host. The
        // host's backstop would refuse the quarantine, but by then a process
        // that no longer exists could not be argued about.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "allowed.exe");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[file.clone()]),
            true,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(&watch, Start { pid: 4248, path: None });
        // The ruling is still a take — `memory::rule_on` is not told about the
        // allow list, and the vault's own backstop is what stops the file being
        // written. What the allow list changes here is the termination.
        assert!(watched.findings[0].ruling.action.is_take());
        match &watched.stopped {
            Stopped::NotAttempted { why } => {
                assert!(why.contains("allowed"), "{why}");
            }
            other => panic!("an allowed file is not grounds for killing: {other:?}"),
        }
        assert!(watch.stop());
    }

    #[test]
    fn a_process_running_an_allowed_image_is_left_alone() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let allowed = dir.path().join("game.exe");
        std::fs::write(&allowed, b"a program the user trusts").expect("the file is writable");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[allowed.clone()]),
            true,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(
            &watch,
            Start {
                pid: 4249,
                path: Some(allowed.clone()),
            },
        );
        assert!(watched.refused.is_some(), "an allowed image is not examined");
        assert!(watched.findings.is_empty());
        assert_eq!(watch.stats().skipped_allowed, 1);
        assert_eq!(watch.stats().examined, 0);
        assert!(watch.stop());
    }

    #[test]
    fn a_process_inside_the_products_own_tree_is_never_examined() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = layout(&dir);
        // A file inside the vault: the product already decided it was malicious,
        // and a memory scan of a process holding it must not decide again.
        let inside = paths.quarantine_dir.join("items").join("payload.bin");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::Nothing),
        );

        let watched = watch_one(
            &watch,
            Start {
                pid: 4250,
                path: Some(inside.clone()),
            },
        );
        match &watched.refused {
            Some(why) => assert!(why.contains("product's own directory"), "{why}"),
            None => panic!("the vault's own tree must be refused"),
        }
        assert_eq!(watch.stats().skipped_own, 1);
        assert!(watch.stop());
    }

    #[test]
    fn the_idle_process_is_refused_without_a_syscall() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::Nothing),
        );
        let watched = watch_one(&watch, Start { pid: 0, path: None });
        match &watched.refused {
            Some(why) => assert!(why.contains("idle"), "{why}"),
            None => panic!("process 0 must be refused"),
        }
        assert_eq!(watch.stats().skipped_idle, 1);
        assert_eq!(watch.stats().examined, 0);
        assert!(watch.stop());
    }

    #[test]
    fn a_process_that_cannot_be_read_is_refused_and_counted() {
        // The measured fact this records: on the machine this was written on,
        // 151 to 155 of 270 to 296 processes could not be opened. A refusal is
        // the ordinary case, not a fault, and it must be counted rather than
        // reported as a process that held nothing.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            Arc::new(testing::FixedScanner::new(|process, _deadline| ProcessScan::Refused {
                    process: process.clone(),
                    reason: av_memory::RefusalReason::AccessDenied {
                        code: 5,
                        message: "Access is denied.".to_string(),
                    },
                })),
        );

        let watched = watch_one(&watch, Start { pid: 4251, path: None });
        match &watched.refused {
            Some(why) => assert!(why.contains("denied"), "{why}"),
            None => panic!("the process was not examined, and the answer must say so"),
        }
        assert!(watched.findings.is_empty());
        assert_eq!(watch.stats().refused, 1);
        assert_eq!(watch.stats().examined, 0);
        assert!(watch.stop());
    }

    #[test]
    fn the_service_never_examines_itself() {
        // Not tidiness: the only finding a walk of this process could produce is
        // one about the product itself, and both of the actions this product
        // takes on a finding would then land on the product — the file behind it
        // is one of ours, and so is the process holding it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let asked = Arc::new(Asked::default());
        let seen = Arc::clone(&asked);
        let watch = ProcessWatch::start_with(Context {
            engine: engine(),
            paths: layout(&dir),
            allow: AllowList::from_paths(&[]),
            options: options(),
            settlement: HOUR,
            own_pid: 7,
            terminating: Arc::new(AtomicBool::new(true)),
            scanner: Arc::new(testing::FixedScanner::new(move |process, _deadline| {
                    seen.examined.lock().expect("the lock").push(process.pid);
                    ProcessScan::Refused {
                        process: process.clone(),
                        reason: av_memory::RefusalReason::Gone,
                    }
                })),
        })
        .expect("the watcher's thread starts");

        let watched = watch_one(&watch, Start { pid: 7, path: None });
        match &watched.refused {
            Some(why) => assert!(why.contains("service itself"), "{why}"),
            None => panic!("the service must not examine itself"),
        }
        assert!(
            asked.examined.lock().expect("the lock").is_empty(),
            "the scanner must never be asked about this process"
        );
        assert_eq!(watch.stats().skipped_own, 1);
        assert!(watch.stop());
    }

    #[test]
    fn a_burst_that_overflows_the_queue_is_dropped_and_counted() {
        // Process starts arrive in bursts — a build is hundreds of them — and a
        // queue that grew without end would be the service's own denial of
        // service. Dropping is the answer and counting is what makes the drop
        // honest rather than silent.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let asked = Arc::new(Asked::default());
        let seen = Arc::clone(&asked);
        let watch = ProcessWatch::start_with(Context {
            engine: engine(),
            paths: layout(&dir),
            allow: AllowList::from_paths(&[]),
            options: options(),
            settlement: HOUR,
            own_pid: 0xFFFF_FFF0,
            terminating: Arc::new(AtomicBool::new(false)),
            scanner: Arc::new(testing::FixedScanner::new(move |process, _deadline| {
                    // Slow enough that the queue behind it fills while the
                    // worker is inside one call. Real walks take seconds; this
                    // takes long enough to be reproducible.
                    seen.examined.lock().expect("the lock").push(process.pid);
                    std::thread::sleep(Duration::from_millis(30));
                    ProcessScan::Refused {
                        process: process.clone(),
                        reason: av_memory::RefusalReason::Gone,
                    }
                })),
        })
        .expect("the watcher's thread starts");

        let mut accepted = 0usize;
        for pid in 1_000..1_000 + (MAX_PENDING_STARTS as u32 * 3) {
            if watch.note_start(Start { pid, path: None }) {
                accepted += 1;
            }
        }
        assert!(
            accepted < MAX_PENDING_STARTS as usize * 3,
            "the queue cannot have taken every start in a burst three times its size"
        );
        let stats = watch.stats();
        assert_eq!(stats.dropped as usize, MAX_PENDING_STARTS as usize * 3 - accepted);
        assert_eq!(stats.starts as usize, accepted + stats.dropped as usize);
        assert!(watch.stop());
    }

    #[test]
    fn every_counter_is_reported_and_the_sentence_names_them() {
        let stats = ProcessWatchStats {
            starts: 10,
            dropped: 1,
            skipped_own: 2,
            skipped_allowed: 3,
            skipped_idle: 1,
            refused: 2,
            examined: 4,
            walked_again: 3,
            settlement_dropped: 0,
            findings: 5,
            stopped: 1,
        };
        let text = stats.describe();
        assert!(text.contains("10 start(s)"), "{text}");
        assert!(text.contains("4 examined"), "{text}");
        assert!(
            text.contains("3 walked again after 2s"),
            "the second walks are counted in the same sentence, and the delay is \
             part of the number because a reader cannot otherwise tell what it \
             means: {text}"
        );
        assert!(text.contains("2 refused"), "{text}");
        assert!(text.contains("1 dropped"), "{text}");
        assert!(text.contains("5 finding(s)"), "{text}");
        assert!(text.contains("1 process(es) stopped"), "{text}");
        // The three skips are reported as their sum, which is the number a
        // reader acts on. The parts are readable from `stats`, not from the
        // sentence, so this asserts the sum and not the parts.
        assert_eq!(stats.skipped_own + stats.skipped_allowed + stats.skipped_idle, 6);
        assert!(text.contains("6 skipped"), "{text}");
        assert_eq!(ProcessWatchStats::default().starts, 0);
    }

    #[test]
    fn a_walk_that_ran_out_of_time_says_which_of_the_two_reasons_it_was() {
        // The two stop reasons send a reader to different places — one is the
        // process's address space, the other is this service's own clock — so
        // the value the host logs them from has to carry the difference.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let deadlines = Arc::new(Asked::default());
        let seen = Arc::clone(&deadlines);
        let watch = ProcessWatch::start_with(Context {
            engine: engine(),
            paths: layout(&dir),
            allow: AllowList::from_paths(&[]),
            options: options(),
            settlement: HOUR,
            own_pid: 0xFFFF_FFF0,
            terminating: Arc::new(AtomicBool::new(false)),
            scanner: Arc::new(testing::FixedScanner::new(move |process, deadline| {
                    seen.deadlines.lock().expect("the lock").push(deadline);
                    let mut outcome = ProcessOutcome::new(process.clone());
                    outcome.walk_complete = false;
                    outcome.deadline_reached = true;
                    outcome.regions_seen = 3;
                    ProcessScan::Examined(Box::new(outcome))
                })),
        })
        .expect("the watcher's thread starts");

        let watched = watch_one(&watch, Start { pid: 4252, path: None });
        assert!(!watched.walk_complete);
        assert!(watched.deadline_reached);
        assert_eq!(watched.coverage.regions_walked, 3);
        assert!(watched.findings.is_empty());
        assert_eq!(watch.stats().examined, 1);
        // The deadline really was handed to the walk, and it is the documented
        // one. A walk with no deadline is the bug this asserts against: a
        // process that allocates as fast as it is read never reaches a byte
        // budget, so the wall clock is the only bound that can end it.
        assert_eq!(
            deadlines.deadlines.lock().expect("the lock").as_slice(),
            &[SCAN_DEADLINE]
        );
        assert!(watch.stop());
    }

    #[test]
    fn a_clean_process_is_walked_a_second_time_and_the_second_walk_is_counted_apart() {
        // The measurement this exists for: a walk started at process *creation*
        // reads an address space that has not finished being built — its own
        // sections are skipped by design and whatever it maps for itself is
        // mapped after its first instruction runs — so the walk and the program
        // are in a race, and the program won it about half the time. The second
        // walk is what stops that being a coin toss. It is counted apart from
        // `examined` so that the shutdown line cannot be read as this service
        // having examined twice as many processes as started.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let asked = Arc::new(Asked::default());
        let seen = Arc::clone(&asked);
        let watch = watching_after(
            &dir,
            AllowList::from_paths(&[]),
            false,
            Arc::new(testing::FixedScanner::new(move |process, _deadline| {
                seen.examined.lock().expect("the lock").push(process.pid);
                outcome(process.pid, Vec::new())
            })),
            Duration::ZERO,
        );

        let first = watch_one(&watch, Start { pid: 4321, path: None });
        let second = watch
            .outcomes()
            .recv_timeout(Duration::from_secs(10))
            .expect("a process the first walk found nothing in is walked again");

        assert_eq!(first.pid, 4321);
        assert_eq!(second.pid, first.pid, "the second walk is the same process");
        assert!(first.refused.is_none() && second.refused.is_none());
        assert_eq!(
            asked.examined.lock().expect("the lock").as_slice(),
            &[4321, 4321],
            "the process must really have been read twice"
        );
        let stats = watch.stats();
        assert_eq!(stats.examined, 1, "one process was examined, not two walks");
        assert_eq!(stats.walked_again, 1);
        assert!(watch.stop());
    }

    #[test]
    fn a_process_the_first_walk_convicted_is_not_walked_again() {
        // The other half of the schedule's condition, and the one that would be
        // an endless source of the same finding if it were wrong: a process whose
        // first walk convicted it has already been acted on — its file is in the
        // vault, or it has been terminated — so a second walk could only produce
        // the same finding again, which on a terminated process is a second
        // termination attempt on the way out.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let watch = watching_after(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::File { path: file }),
            Duration::ZERO,
        );

        let watched = watch_one(&watch, Start { pid: 4322, path: None });
        assert_eq!(watched.findings.len(), 1);
        assert!(
            watch
                .outcomes()
                .recv_timeout(Duration::from_millis(500))
                .is_err(),
            "a process that already convicted must not be walked a second time"
        );
        let stats = watch.stats();
        assert_eq!(stats.examined, 1);
        assert_eq!(stats.walked_again, 0);
        assert_eq!(stats.findings, 1, "the finding is counted once, not once per walk");
        assert!(watch.stop());
    }

    #[test]
    fn a_burst_that_fills_the_second_walk_list_is_counted() {
        // The second walk is scheduled, not guaranteed: a process waiting for one
        // occupies a slot for `SETTLEMENT`, so a burst that spawns processes
        // faster than two seconds' worth is read once at creation — which is the
        // race the second walk exists to close. That is a gap in coverage and the
        // counter is what makes it visible, so this asserts the counter is really
        // raised rather than that the code mentions it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        // `HOUR` so that nothing ever comes due: the list only ever grows, which
        // is what makes the arithmetic exact instead of a race of its own.
        let watch = watching_after(
            &dir,
            AllowList::from_paths(&[]),
            false,
            Arc::new(testing::FixedScanner::new(|process, _deadline| {
                outcome(process.pid, Vec::new())
            })),
            HOUR,
        );

        // The start queue is `MAX_PENDING_STARTS` deep, so a start that does not
        // fit is retried rather than dropped — a drop would be a *different*
        // counter, and this test is about the list behind the worker.
        let mut pid = 5_000u32;
        let mut sent = 0usize;
        while sent < MAX_PENDING_SETTLEMENTS + 8 {
            if watch.note_start(Start { pid, path: None }) {
                pid += 1;
                sent += 1;
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        while watch.stats().examined < sent as u64 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stats = watch.stats();
        assert_eq!(stats.examined, sent as u64, "every start must have been walked");
        assert_eq!(stats.walked_again, 0, "no second walk can have come due");
        assert_eq!(
            stats.settlement_dropped,
            (sent - MAX_PENDING_SETTLEMENTS) as u64,
            "a process examined while the list was full gets no second walk, and that is the \
             number a reader has to be able to see"
        );
        assert!(watch.stop());
    }

    #[test]
    fn a_ruling_carries_the_files_own_report_and_not_the_memory_matchs() {
        // What the vault records is the file's scan, which is why the ruling has
        // to bring it back out of the decision. A `Take` with no report would be
        // a ruling the host could not act on.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            false,
            constant(Origin::File { path: file.clone() }),
        );

        let watched = watch_one(&watch, Start { pid: 4253, path: None });
        let ruling = &watched.findings[0].ruling;
        let report: &FileScanReport = ruling
            .report
            .as_ref()
            .expect("a take is only ever ruled on a verdict, and a verdict comes with its report");
        assert_eq!(report.path, file);
        assert_eq!(report.verdict(), Verdict::Malicious);
        assert!(watch.stop());
    }

    #[test]
    fn a_real_process_holding_a_convicting_file_really_ends() {
        // The end of the whole path, against a process that exists. Everything
        // above this is a policy test over a made-up identifier; this one is the
        // one that can fail for a reason outside this process's control — the
        // handle, the creation time, the termination — and it is the only one
        // that can tell a working termination from a plausible-looking one.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = convicting_file(&dir, "dropped.exe");
        let mut child = crate::terminate::doomed::ChildGuard::new();
        let pid = child.pid();
        assert!(child.is_running(), "the child is running before the call");

        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::File { path: file.clone() }),
        );
        let watched = watch_one(
            &watch,
            Start {
                pid,
                path: Some(PathBuf::from(r"C:\somewhere\subject.exe")),
            },
        );

        assert_eq!(
            watched.stopped,
            Stopped::Terminated,
            "the process was not stopped: {}",
            watched.stopped.describe()
        );
        assert!(watched.terminated());
        assert_eq!(watch.stats().stopped, 1);
        assert_eq!(watch.stats().examined, 1);
        // `TerminateProcess` starts a teardown and returns, so the process
        // object is not necessarily signalled by the time it does. This is the
        // assertion that reads the operating system rather than our own report.
        assert!(
            child.wait_for_exit(),
            "the process was reported as terminated and is still running"
        );
        assert!(watch.stop());
    }

    #[test]
    fn a_real_process_is_left_running_when_the_file_behind_the_finding_is_ordinary() {
        // The mirror of the test above, and the one that matters more: the same
        // real process, the same real termination path, and a file that is not
        // malicious. It must still be running afterwards — read from the
        // operating system, not from the worker's own account of itself.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("ordinary.dll");
        std::fs::write(&file, b"nothing of interest here").expect("the file is writable");
        let mut child = crate::terminate::doomed::ChildGuard::new();

        let watch = watching(
            &dir,
            AllowList::from_paths(&[]),
            true,
            constant(Origin::File { path: file.clone() }),
        );
        let watched = watch_one(
            &watch,
            Start {
                pid: child.pid(),
                path: Some(PathBuf::from(r"C:\somewhere\subject.exe")),
            },
        );

        assert!(!watched.terminated());
        assert!(matches!(watched.stopped, Stopped::NotAttempted { .. }));
        assert_eq!(watch.stats().stopped, 0);
        assert!(
            child.is_running(),
            "a file that is not malicious must not cost the user a running program"
        );
        assert!(watch.stop());
    }

    #[test]
    fn a_watcher_that_cannot_start_its_thread_says_so() {
        // The error is the only one this module has, and it is returned rather
        // than panicked so that the host can log it and run without process
        // watching — the file side of the product still works.
        let error = ProcessWatchError::WorkerSpawn {
            source: std::io::Error::other("no more threads"),
        };
        let text = error.to_string();
        assert!(text.contains("process watcher"), "{text}");
        assert!(text.contains("no more threads"), "{text}");
    }
}
