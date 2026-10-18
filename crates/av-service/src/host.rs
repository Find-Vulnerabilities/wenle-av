//! The service's state, and the one place a decision about it is made.
//!
//! # One owner, and why that is a correctness property
//!
//! [`Host`] holds the vault, the watcher, the engine and the scan counter, and
//! nothing else in this process holds any of them. That is not tidiness:
//! `av_quarantine::QuarantineVault` keeps its index in memory and rewrites the
//! whole file on every change, so two live vaults over one directory each
//! silently discard the other's entries — the losing entry is gone from the
//! list and its blob is on disk with nothing pointing at it. The control loop
//! is therefore single-threaded, and every request is handled on it.
//!
//! # The two things the watcher is not allowed to do
//!
//! `av_realtime::RealtimeService::start` opens its *own* vault, and it does so
//! before it arms a single watch. Two live vaults is the one thing that must
//! not happen, so:
//!
//! * The configuration handed to it has `block_on_detect` forced to `false`,
//!   which is what `av_realtime::service::acts_on_detections` reads to decide
//!   whether the scanner takes anything. With it off, the watcher scans,
//!   reports, and writes nothing.
//! * The [`Host`] performs the quarantine for a realtime finding itself, with
//!   the vault it already owns.
//!
//! The vault `av_realtime` opens is still opened — it has to be, the API takes
//! a policy and not an optional vault — but with `acts_on_detections` false it
//! is never written to, and `QuarantineVault::open` only reads the index.
//! Merely opening it is harmless; writing through it is what is not.
//!
//! The second-order effect is that `realtime.block_on_detect` is not honoured,
//! and `crate::config::handled_elsewhere` says so rather than leaving a user to
//! find out. The file is taken into the vault *after* the scan that found it,
//! and the detection's phase says so: [`av_ipc::Phase::observed`] is given
//! `false` for `blocked`, so the notification says "found after it appeared"
//! and never "was blocked before it could run".
//!
//! # What a request may not do
//!
//! [`Host::handle`] matches [`av_ipc::Request`] exhaustively with no wildcard
//! arm, so a request added to the protocol stops this build. The refusals are
//! the interesting half and each one is a sentence a user can act on: a second
//! concurrent scan, a path inside the product's own tree, and a path that is
//! not there. All three are computed by [`scan_refusal`], which takes no
//! `&self` — a decision that can be made without the service is a decision a
//! test can make without the service.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use crossbeam_channel::{Receiver, TryRecvError};

use av_core::config::{AvConfig, RealtimeConfig};
use av_core::paths::AvPaths;
use av_core::scan::{FileScanReport, ScanOptions};
use av_core::Verdict;
use av_ipc::{
    BufferScan, Detection, DetectionAction, DriverEventAction, DriverPresence, DriverSubject, Event,
    MemoryReport, MissedWindow, Phase, QuarantineChange, QuarantineListing, RealtimeState, Reply,
    Request, ScanCancel, ScanFinished, ScanId, ScanStart, ScanSummary, ServiceState,
    SettingDisclosure, StatusReport, TamperState,
};
use av_memory::{MemoryFinding, ProcessRef};
use av_quarantine::{
    EntrySource, QuarantineContext, QuarantineError, QuarantineId, QuarantinePolicy,
    QuarantineVault, RestoreOptions,
};
use av_driver_proto::wire::{ConfigMessage, CONFIG_PROTECT_HANDLES};
use av_realtime::{DisabledBy, RealtimeEvent, RealtimeService, WatchPlan};

use crate::allow::AllowList;
use crate::config::{self, LoadedConfig};
use crate::driver;
use crate::engine::{self, Engine};
use crate::error::ServiceError;
use crate::filter_port;
use crate::memory;
use crate::process_watch::{Convictions, ProcessWatch, Start, Watched};
use crate::scan::{self, Running, ScanCounts, ScanJob, ScanMessage};
use crate::selfprotect::{self, SelfProtection};
use crate::tamper::Tamper;

/// How many vault entries a `QuarantineList` may return at most.
///
/// A cap and not a page size, because the protocol has no cursor: a reply that
/// was cut short has to be able to say how many it left out, and a caller that
/// wants the rest asks with a smaller `limit` of its own. 500 entries is a list
/// a window can scroll without a virtualising widget.
pub const QUARANTINE_LIST_CAP: usize = 500;

/// How many detections a [`ScanSummary`] carries.
///
/// A full scan of a large disk produces thousands, and `results` is a `Vec` in
/// a single frame. `detections` is the true count whatever this is, and
/// `results_omitted` says how many were not listed — so a caller can never read
/// a truncated list as a complete one.
pub const SCAN_RESULT_CAP: usize = 200;

/// How many scan messages are absorbed per control-loop pass.
///
/// The walker's channel is unbounded and a fast walk over a large tree can
/// queue faster than one pass drains. Bounding the pass is what keeps the
/// control loop answering status requests while a scan runs; the rest stay
/// queued for the next pass, which happens every few milliseconds.
pub const SCAN_DRAIN_CAP: usize = 256;

/// How many watcher events are absorbed per control-loop pass.
///
/// Same reason as [`SCAN_DRAIN_CAP`], and a lower number because the watcher's
/// queue is fed by the machine rather than by our own walker and a burst means
/// something is happening that the loop should get back to promptly.
pub const REALTIME_DRAIN_CAP: usize = 64;

/// How many driver events are absorbed per control-loop pass.
///
/// The lowest of the three caps, because this channel carries the least and the
/// least urgent: the driver's own status picture, and the two connection
/// transitions a service start produces. A burst here means the driver is
/// reporting something unusual, and the loop should get back to answering
/// clients rather than drain it in one pass.
pub const DRIVER_DRAIN_CAP: usize = 32;

/// How many finished process walks are absorbed per control-loop pass.
///
/// The same reason as the three above, and the smallest because this is the
/// slowest producer of the four: the worker walks one process at a time and a
/// walk takes seconds, so a batch of more than a handful means several processes
/// finished while the loop was busy — and the loop should get back to answering
/// clients rather than act on all of them in one pass. Since 2026-10-11 a
/// process can produce **two** outcomes — the walk its start asked for, and the
/// second one [`SETTLEMENT`] later — so a full batch can be as few as eight
/// processes. What this number bounds is the rate, and the rate is what the
/// paragraph above is about, so the number did not change.
///
/// [`SETTLEMENT`]: crate::process_watch::SETTLEMENT
pub const PROCESS_DRAIN_CAP: usize = 16;

/// Why a request to scan PID 0 is refused before anything is opened.
///
/// PID 0 is the idle process — the kernel's own accounting of the processor
/// doing nothing — and it has no user-mode address space to walk, no image, and
/// no thread that could be running code to find. Windows answers an attempt to
/// open it with the same "no such process" error it uses for a PID that was
/// never allocated, so without this check the caller would be told the process
/// does not exist, which is false and would send someone looking for a bug in
/// the process list. The sentence says what is actually the matter.
pub const IDLE_PROCESS: &str =
    "PID 0 is the idle process: it has no address space to scan and no image to name";

/// A file this run has taken into the vault, and what tells it apart from a
/// different file that later appears at the same path.
///
/// The entry identifier alone is not enough to answer "is this the same file
/// the driver refused a second ago": a path is a name, and a name can be
/// reused. `identity` is the original's size and last-write time as they were
/// the moment before it was taken, and it is compared with the same two
/// numbers read again — see [`Host::quarantine`].
#[derive(Debug, Clone, Copy)]
struct Taken {
    /// The entry holding the bytes.
    id: QuarantineId,
    /// The original's size and modification time at the moment of taking, or
    /// `None` when it could not be read before the vault moved it.
    identity: Option<FileIdentity>,
}

/// What tells one file from another at the same path, without reading either.
///
/// Two numbers rather than a digest: this is asked on a path the driver has
/// already refused once, and re-reading a file the scanner has just read in
/// order to hash it again would be the only cost in the path. The weakness is
/// stated rather than hidden — a file whose size *and* modification time are
/// both set back to the previous file's is read as the same file, and a
/// filesystem that reports no modification time never matches.
type FileIdentity = (u64, Option<std::time::SystemTime>);

/// The size and last-write time of whatever is at `path`, or `None` when
/// nothing is (or it cannot be asked).
fn file_identity(path: &Path) -> Option<FileIdentity> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()))
}

/// The service's state.
#[derive(Debug)]
pub struct Host {
    /// The layout every path is derived from.
    paths: AvPaths,
    /// When the process started, for the uptime in [`Host::status`].
    started: Instant,
    /// The configuration in force, and where it was read from.
    loaded: LoadedConfig,
    /// The engine, the database and the catalog index.
    engine: Engine,
    /// The paths the user has allowed, shared with the filter-port thread.
    ///
    /// Held here because this is the thread that hears the user: a decision
    /// arrives over the control pipe, is carried out against the vault, and the
    /// allow it implies is recorded here. The filter-port thread holds a handle
    /// to the same set and consults it before it scans anything, which is what
    /// makes the button take effect on the next launch rather than at restart.
    /// It holds `general.exclusions` as well, and [`Host::apply_live`] re-seeds
    /// that half on every accepted `ConfigSet`, so the file and the button are
    /// one answer rather than two that agree only at startup.
    allow: AllowList,
    /// The one vault. See this module's documentation.
    vault: QuarantineVault,
    /// The path of every file this process has taken, the entry that holds it,
    /// and what the file looked like when it was taken. Bounded by the number
    /// of quarantines in one run, which is small.
    ///
    /// It exists for one case: the driver asks about the same execution twice —
    /// its `CREATE` pre-operation and its acquire-for-section pre-operation —
    /// so a convicted file produces two detections a moment apart. See
    /// [`Host::quarantine`] for the two shapes that takes, and why the second
    /// of them is the one that used to leave two entries for one file.
    taken: HashMap<PathBuf, Taken>,
    /// The image files this run's engine has convicted, shared with the process
    /// worker.
    ///
    /// The worker needs it because the two halves of acting on a malicious
    /// program are split across two threads: this one takes the *file*, and the
    /// worker stops the *process* — and until 2026-10-18 the worker could only
    /// see memory findings, so a file convicted here was quarantined while the
    /// program it came from kept running. See
    /// [`crate::process_watch::Convictions`] for the measurement.
    ///
    /// Written in one place, [`Host::drain_driver`], from the detection the
    /// filter port built for a file it refused.
    convictions: Convictions,
    /// The watcher, when it is running.
    realtime: Option<RealtimeService>,
    /// The process watcher, when it is running.
    ///
    /// A thread of its own rather than work on the control loop, for the reason
    /// `crate::process_watch`'s documentation gives: a memory walk is seconds of
    /// reading another process, and running one here would delay every status
    /// query and every driver decision that arrived while it ran.
    ///
    /// It is started and stopped with the watcher, because the two are armed by
    /// the same switch and fed by the same driver. It holds no vault: it reports
    /// what it found and [`Host::absorb_memory`] does the taking, which is what
    /// keeps the vault's one writer a fact rather than a convention.
    process_watch: Option<ProcessWatch>,
    /// What the watcher is doing, as last observed.
    ///
    /// Cached rather than asked for on every status request, because the
    /// honest answer includes whether the roots were armed, and that is decided
    /// when the watcher starts. A cached value that was filled in from the
    /// plan is not a guess about the watcher — it is the watcher's own report
    /// of what it armed.
    realtime_state: RealtimeState,
    /// The scan in flight, when there is one.
    scan: Option<Running>,
    /// The walker's channel.
    scan_out: Receiver<ScanMessage>,
    /// What the driver's filter port has reported since the last drain, when a
    /// client is running. Created by [`Host::start_driver_port`] along with the
    /// client that feeds it, so that a host with no client has no channel and no
    /// sender kept alive for nobody to send on.
    driver_out: Option<Receiver<Event>>,
    /// The filter-port client, when one is running. See
    /// [`Host::start_driver_port`].
    filter_port: Option<filter_port::Client>,
    /// Whether the filter port was connected at the last drain.
    ///
    /// Recorded rather than derived, because the connection is the only
    /// evidence this service ever gets that the driver is *running* rather than
    /// merely loadable, and it arrives as an event rather than as a question
    /// anybody can ask. See [`Host::driver_status`].
    driver_connected: bool,
    /// What the driver said `PsSetCreateProcessNotifyRoutineEx` answered, in
    /// the same drain.
    ///
    /// `None` until the driver reports, and the report arrives once per
    /// connection — the driver queues it from its own connect callback. An
    /// `NTSTATUS`, so `Some(0)` is the one value that means process-start
    /// notifications are registered.
    process_notify: Option<i32>,
    /// What the driver said `ObRegisterCallbacks` answered, in the same drain.
    ///
    /// The second of the two registrations the driver reports when the service
    /// connects, and separate from [`Self::process_notify`] because the two are
    /// different mechanisms with different failure modes: process-start
    /// notifications feed the memory monitor, and the object callbacks are what
    /// stops another process from terminating this product. A single field
    /// holding "the last `NTSTATUS` the driver sent" would let one registration's
    /// failure be overwritten by the other's success, and would then say
    /// "registered" about the one that had failed.
    object_callbacks: Option<i32>,
    /// What the driver answered the configuration this service sent it.
    ///
    /// The third of the three statuses a connection produces, and the only one
    /// that is about a **question this service asked** rather than about
    /// something the driver did on its own. `Some(0)` means the driver applied
    /// the configuration — the object callbacks it was told to enable and the
    /// write gate it was told to arm over the install directory. See
    /// [`Host::driver_configuration`] for what is asked for and
    /// [`crate::filter_port::configure`] for how the answer gets here.
    configuration_reply: Option<i32>,
    /// Detections from the running scan, oldest first.
    scan_results: Vec<Detection>,
    /// How many detections the running scan has produced, including those not
    /// kept in `scan_results`.
    scan_detections: u64,
    /// How many the running scan took into the vault.
    scan_quarantined: u64,
    /// How many the vault refused.
    scan_quarantine_failed: u64,
    /// How many detections were not kept because of [`SCAN_RESULT_CAP`].
    scan_omitted: usize,
    /// Files the running scan has examined, as of its last progress message.
    running_scanned: u64,
    /// Files examined by scans that have finished.
    finished_files: u64,
    /// The next scan identifier.
    next_scan: u64,
    /// Where the process is in its life.
    state: ServiceState,
    /// What start-up self-protection did, when this host was the product's.
    ///
    /// `None` for a host a test built with [`Host::open_with`], and that is the
    /// honest value rather than a placeholder: no test process has had its own
    /// process DACL rewritten or its installer's recovery policy touched, and a
    /// field that claimed otherwise would be a report about a run that never
    /// happened. [`Host::open`] is the only thing that fills it.
    self_protection: Option<SelfProtection>,
    /// The tamper checker, when it is running.
    ///
    /// A thread of its own for the reason `crate::tamper`'s documentation gives,
    /// and a *cell* rather than a channel for the reason it gives too: a tamper
    /// finding is a fact about the machine with nothing for this loop to do about
    /// it, so [`Host::status`] reads the worker's last answer instead of draining
    /// a queue that would only ever be read by a connected client.
    tamper: Option<Tamper>,
    /// What to say when there is no tamper checker.
    ///
    /// The two reasons are different facts — the configuration turned it off, and
    /// the layout is one this product refuses to harden — so the sentence is kept
    /// rather than rebuilt. See [`Host::start_tamper`].
    tamper_state: TamperState,
}

impl Host {
    /// Open the vault, load the rules, and stop there.
    ///
    /// The watcher is *not* started here even when the configuration asks for
    /// it, and the reason is the one that already keeps the driver port out of
    /// [`Host::open_with`]: this function is also what a test builds, and the
    /// default watch plan is built from *this machine's* Desktop, Downloads,
    /// Documents, temporary directory and removable drives — so starting it here
    /// would have `cargo test` reading a developer's home directory.
    ///
    /// [`crate::control::serve`] is where it happens instead, which is the one
    /// path both real entry points — the service and `--console` — go through.
    /// [`Host::start_realtime`] is the call, and it honours the configuration
    /// rather than overriding it.
    ///
    /// A missing or unreadable rule database is not an error; see
    /// [`crate::engine`]. A vault that cannot be opened *is* an error, because
    /// a service that cannot take a malicious file has to say so at startup
    /// rather than at the moment it matters.
    pub fn open(paths: AvPaths, loaded: LoadedConfig) -> Result<Self, ServiceError> {
        // First, before the rule database is read and before anything is opened
        // in the product's own directories: this is the step that closes the
        // process's DACL, and every later step is one an attacker would rather
        // it did not reach. See `crate::selfprotect` — including why a cargo
        // build tree is skipped entirely, which is the reason a developer's
        // `--console` run is not hardened.
        let self_protection = selfprotect::apply(&paths);
        let engine = engine::load(&paths, &loaded.config.scanning);
        let mut host = Self::open_with(paths, loaded, engine)?;
        host.self_protection = Some(self_protection);
        // Last, and on a thread of its own: the first thing the checker does is
        // the expensive manifest pass, which hashes every product file, and doing
        // that here would delay startup by the same tens of megabytes of reading
        // the engine has just done. See `crate::tamper` for the two passes, and
        // for why the cheap one is what `protection.tamper_resistance` turns on.
        host.start_tamper();

        // Started here and not in `open_with`, and the split is the same one
        // `crate::control::serve` and `crate::control::serve_on` make: a test
        // builds its host with `open_with`, and a test that connected to the
        // product's filter port on a machine where the product is installed
        // would take the driver's client slot from the service that is supposed
        // to have it. What it costs is that this line is exercised only by a
        // service start, which is the honest description of it.
        host.start_driver_port(av_driver_proto::PORT_NAME);
        Ok(host)
    }

    /// Open over an engine the caller has already built.
    ///
    /// Separated from [`Host::open`] for the reason [`crate::engine::load_with`]
    /// exists: building the engine is the one expensive step in startup, and a
    /// test that has to read this machine's whole catalog store — 1.2 s and
    /// 1.2 GB of reads — to ask what happens when a scan of a temporary
    /// directory finds one file is a test nobody runs twice. It also means a
    /// test can inject a rule database without writing one to disk.
    pub fn open_with(
        paths: AvPaths,
        loaded: LoadedConfig,
        engine: Engine,
    ) -> Result<Self, ServiceError> {
        let policy = QuarantinePolicy::from(&loaded.config.quarantine);
        let vault =
            QuarantineVault::open(paths.quarantine_dir.clone(), policy).map_err(|source| {
                ServiceError::Vault {
                    path: paths.quarantine_dir.clone(),
                    message: source.to_string(),
                }
            })?;
        // A channel with no sender: `try_recv` reports `Disconnected` and the
        // drain loop treats that as "no scan", which is the truth. Keeping a
        // sender alive would leave the drain loop seeing `Empty` for a scan
        // that does not exist.
        let (no_scan, scan_out) = crossbeam_channel::unbounded::<ScanMessage>();
        drop(no_scan);
        // Built from the configuration *before* `loaded` is moved into the
        // struct, and that is the only reason it is a statement here rather
        // than a field initialiser like the rest. What it must not become is a
        // set that is rebuilt when the configuration changes: this is the
        // startup seed, and everything added afterwards comes from the user.
        let allow = AllowList::from_paths(&loaded.config.general.exclusions);
        Ok(Self {
            paths,
            started: Instant::now(),
            loaded,
            engine,
            allow,
            vault,
            taken: HashMap::new(),
            convictions: Convictions::new(),
            realtime: None,
            process_watch: None,
            realtime_state: RealtimeState::off(NO_WATCHER_YET),
            scan: None,
            scan_out,
            driver_out: None,
            filter_port: None,
            driver_connected: false,
            process_notify: None,
            object_callbacks: None,
            configuration_reply: None,
            scan_results: Vec::new(),
            scan_detections: 0,
            scan_quarantined: 0,
            scan_quarantine_failed: 0,
            scan_omitted: 0,
            running_scanned: 0,
            finished_files: 0,
            next_scan: 0,
            state: ServiceState::Starting,
            self_protection: None,
            tamper: None,
            tamper_state: TamperState::off(false, NO_TAMPER_YET),
        })
    }

    /// What start-up self-protection did, or `None` for a host a test built.
    ///
    /// The answer is *what was applied at startup* and not *what is true now*.
    /// The second question is `crate::selfprotect::measure`'s, and it is a
    /// different function because the two answers come apart: a directory
    /// recreated by an installer inherits its parent's permissions, and the
    /// service's own start-up would not notice.
    pub fn self_protection(&self) -> Option<&SelfProtection> {
        self.self_protection.as_ref()
    }

    /// Start the tamper checker, if the configuration asks for one.
    ///
    /// # What turns it on, and what turns it off anyway
    ///
    /// `protection.tamper_resistance`, under `protection.enabled`, and the two
    /// refusals are different facts that are reported differently:
    ///
    /// * **The configuration does not ask for it.** [`TamperState::off`] with
    ///   `enabled: false`, which is a user who turned this off.
    /// * **The layout is a cargo build tree.** `enabled: true` and a reason,
    ///   which is *the user asked for this and this product will not do it
    ///   here* — the same refusal [`crate::selfprotect`] makes at start-up and
    ///   `wenle protect apply` makes at the command line, taken from the same
    ///   `av_guard` function so the three cannot disagree. Re-applying an
    ///   installation's permissions inside `target/<profile>` would lock the
    ///   build that produced this binary.
    ///
    /// # What it is given
    ///
    /// The paths and the service name, and nothing else: the checker has no
    /// vault handle, no engine and no channel to this loop, because it takes
    /// nothing and decides nothing. See [`crate::tamper`].
    ///
    /// A thread that will not start is a state rather than only a log line,
    /// unlike [`Host::start_process_watch`]'s: the user asked for tamper
    /// resistance and is not getting it, and that belongs in the answer to
    /// `wenle service status` rather than in a file nobody opens.
    fn start_tamper(&mut self) {
        let protection = &self.loaded.config.protection;
        if !protection.enabled || !protection.tamper_resistance {
            self.tamper_state = TamperState::off(false, NO_TAMPER_ASKED_FOR);
            return;
        }
        if let Some(reason) = selfprotect::skip_reason(&self.paths) {
            log::info!("tamper resistance is not being checked: {reason}");
            self.tamper_state = TamperState::off(true, reason);
            return;
        }
        match Tamper::start(self.paths.clone(), selfprotect::service_name()) {
            Ok(tamper) => {
                log::info!(
                    "tamper resistance is running: this process's access list and the product's \
                     directories are re-read every {}s and put back when they are found undone, \
                     and the product's own files are compared against the manifest at startup \
                     and every {}h",
                    crate::tamper::CHEAP_INTERVAL.as_secs(),
                    crate::tamper::EXPENSIVE_INTERVAL.as_secs() / 3600
                );
                self.tamper_state = tamper.state();
                self.tamper = Some(tamper);
            }
            Err(error) => {
                log::error!("tamper resistance could not be started: {error}");
                self.tamper_state = TamperState::off(true, error.to_string());
            }
        }
    }

    /// Stop the tamper checker.
    fn stop_tamper(&mut self) {
        let Some(tamper) = self.tamper.take() else {
            return;
        };
        // The state is read before the join, so that the counters of the run
        // that has just ended are the ones a later status reports rather than
        // the zeroes `TamperState::off` would put there. `crate::tamper`'s own
        // documentation says why the state survives the thread.
        self.tamper_state = tamper.state();
        if !tamper.stop() {
            log::warn!("the tamper checker's thread did not end cleanly");
        }
        self.tamper_state.checking = false;
        self.tamper_state.disabled_by = Some("the service is stopping".to_string());
    }

    /// What the tamper checker is doing, as last observed.
    ///
    /// Read from the worker's cell rather than from [`Self::tamper_state`] when
    /// there is a worker, for the same reason [`Host::realtime_with_process_watch`]
    /// reads the process watcher's counters instead of caching them: the number
    /// this reports is a number about *right now*.
    fn tamper_state(&self) -> TamperState {
        match &self.tamper {
            Some(tamper) => tamper.state(),
            None => self.tamper_state.clone(),
        }
    }

    /// What the service is and what it is doing.
    ///
    /// [`crate::driver::check`] opens the driver's control device on every
    /// call. That is deliberate: a cached "loaded" would be a stale claim about
    /// a protection, and the call itself is a `CreateFileW` against a device
    /// that is either there or is not. What that call *cannot* answer is
    /// composed onto it by `Host::driver_status`.
    pub fn status(&self) -> StatusReport {
        StatusReport {
            state: self.state,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started.elapsed().as_secs(),
            driver: self.driver_status(),
            database: self.engine.database.clone(),
            realtime: self.realtime_with_process_watch(),
            quarantine_items: self.vault.entries().len(),
            scans_running: usize::from(self.scan.is_some()),
            files_examined: self.finished_files + self.running_scanned,
            tamper: self.tamper_state(),
        }
    }

    /// The watcher's state, with what the process watcher has had to drop.
    ///
    /// # Why the counters are read here rather than cached
    ///
    /// `realtime_state` is written when the watcher starts, changes or stops;
    /// the process watcher's counters move with every process the driver reports.
    /// Caching them would mean a status that was stale by however long it had
    /// been since the last lifecycle change, and the number this reports is a
    /// number about *right now* — how much of what the user asked for is not
    /// being examined.
    ///
    /// # Why a dropped start is a disclosure
    ///
    /// [`av_ipc::RealtimeState::disclosures`] is documented as "settings the
    /// watcher stores and does not honour", and this list already carries entries
    /// that are not settings at all — a configured root that could not be watched
    /// is one, and it is there because the two are the same fact to a user: *I
    /// asked for coverage and I have less*. A process start that was dropped
    /// because the queue was full is exactly that fact, and it is keyed to
    /// `realtime.scan_on_process_start` because that is the setting the user
    /// turned on and is not fully getting.
    ///
    /// Nothing is disclosed when nothing was dropped, so a machine that is
    /// keeping up reports no gap — which is what makes the disclosure mean
    /// something when it appears.
    fn realtime_with_process_watch(&self) -> RealtimeState {
        let mut state = self.realtime_state.clone();
        let Some(watch) = self.process_watch.as_ref() else {
            return state;
        };
        let stats = watch.stats();
        if stats.dropped > 0 {
            state.disclosures.push(SettingDisclosure::new(
                "realtime.scan_on_process_start",
                format!(
                    "{} process start(s) were not examined because the watcher was still walking \
                     an earlier one and its queue was full; {} examined so far",
                    stats.dropped, stats.examined
                ),
            ));
        }
        // The second walk is the one that closes the race between a walk and the
        // program being walked, and a process that never got it was read once, at
        // creation, when there was nothing in its address space yet. That is a
        // gap in coverage even though the process *was* examined, so it is said
        // in the same place and the same shape as the drop above — the sentence
        // that would otherwise be true and useless is "N examined, 0 dropped".
        if stats.settlement_dropped > 0 {
            state.disclosures.push(SettingDisclosure::new(
                "realtime.scan_on_process_start",
                format!(
                    "{} process(es) were examined once and not looked at a second time, because \
                     that many were already waiting for their second walk; a process read only at \
                     creation has not finished starting",
                    stats.settlement_dropped
                ),
            ));
        }
        state
    }

    /// What to say about the driver, from the two things this service knows.
    ///
    /// # Why the control-device answer is not the whole answer
    ///
    /// [`crate::driver::check`] asks whether `\\.\WenleAvFilter` can be opened,
    /// and **this build's driver creates no control device**: `IoCreateDevice`
    /// and `IoCreateSymbolicLink` occur nowhere in `av-driver`, which registers
    /// a minifilter and a communication port and nothing else. So that call
    /// answers `Absent` on every machine, including one where the filter is
    /// loaded and enforcing. Its sentence no longer claims otherwise — but a
    /// report that said only that would be a report saying "not loaded" about a
    /// driver that is running, which is the same class of false statement the
    /// process-notification report below exists to prevent.
    ///
    /// # What the connection proves
    ///
    /// The filter port exists only if the driver ran `FltCreateCommunicationPort`
    /// inside `DriverEntry`, after `FltRegisterFilter` succeeded. A service that
    /// is connected to it therefore knows something stronger than "the device
    /// could be opened": it knows the driver is loaded *and running callbacks*.
    /// That is what makes `Loaded` the right answer here, and why it is taken
    /// from the connection rather than from the device.
    ///
    /// When there is no connection this says so instead of repeating the
    /// device's sentence, because the two facts it has are "no device to ask"
    /// and "no port connected", and neither of them is the claim "the driver is
    /// not loaded".
    fn driver_status(&self) -> av_ipc::DriverStatus {
        let mut status = driver::check();
        if self.driver_connected {
            status.presence = DriverPresence::Loaded;
            status.detail = "the service is connected to the driver's filter port, which the \
                             driver cannot have created without having loaded"
                .to_string();
            status.device = Some(crate::driver::CONTROL_DEVICE.to_string());
        } else {
            status.detail = "the service is not connected to the driver's filter port, so no \
                             decision is being asked of the driver and none of its events are \
                             arriving; whether it is loaded is not something this service can \
                             say from here"
                .to_string();
        }
        if let Some(code) = self.process_notify {
            status.detail = format!("{}; {}", status.detail, describe_process_notify(code));
        }
        if let Some(code) = self.object_callbacks {
            status.detail = format!("{}; {}", status.detail, describe_object_callbacks(code));
        }
        if let Some(code) = self.configuration_reply {
            status.detail = format!("{}; {}", status.detail, describe_configuration(code));
        }
        status
    }

    /// Where the process is in its life, reporting the change when there is one.
    ///
    /// Returns an event only on a real transition, so a caller driving this
    /// from the SCM's notifications does not have to compare states itself.
    pub fn set_state(&mut self, state: ServiceState) -> Option<Event> {
        if self.state == state {
            return None;
        }
        self.state = state;
        Some(Event::StatusChanged(self.status()))
    }

    /// The state, without building a whole report.
    pub const fn state(&self) -> ServiceState {
        self.state
    }

    /// Everything worth saying about the rules that loaded.
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The configuration in force.
    pub const fn loaded(&self) -> &LoadedConfig {
        &self.loaded
    }

    /// Where everything lives.
    pub const fn paths(&self) -> &AvPaths {
        &self.paths
    }

    /// Handle one request.
    ///
    /// Exhaustive over [`av_ipc::Request`] with no wildcard arm: a request
    /// added to the protocol stops this build rather than being dropped
    /// silently, which is the failure the protocol's own documentation names.
    /// The events returned alongside the reply are the ones the request itself
    /// produced — a scan that was refused produces none, a `ConfigSet` that
    /// changed the watcher produces a status — and the caller sends them after
    /// the reply.
    pub fn handle(&mut self, request: &Request) -> (Reply, Vec<Event>) {
        match request {
            Request::Status => (Reply::Status(self.status()), Vec::new()),
            Request::ScanPath { path, options } => self.start_scan(path, options),
            Request::CancelScan { id } => (Reply::ScanCancelled(self.cancel_scan(*id)), Vec::new()),
            Request::ScanProcess { pid } => self.scan_process(*pid),
            Request::ScanBuffer { name, data } => self.scan_buffer(name, data),
            Request::QuarantineList { limit } => (
                Reply::QuarantineList(self.quarantine_list(*limit)),
                Vec::new(),
            ),
            Request::QuarantineRestore { id } => {
                (Reply::QuarantineChange(self.restore(*id)), Vec::new())
            }
            Request::QuarantineDelete { id } => {
                (Reply::QuarantineChange(self.delete(*id)), Vec::new())
            }
            Request::QuarantineAllow { id, permanent } => (
                Reply::QuarantineChange(self.allow(*id, *permanent)),
                Vec::new(),
            ),
            Request::ConfigGet => (
                Reply::Config(Box::new(config::report(&self.loaded))),
                Vec::new(),
            ),
            Request::ConfigSet { config } => self.set_config(config),
            Request::RealtimeSet { enabled } => {
                (Reply::Realtime(self.set_realtime(*enabled)), Vec::new())
            }
        }
    }

    /// Everything the machine has told the service since the last call.
    ///
    /// Called between requests by the control loop, which is what makes a
    /// single-threaded control plane able to serve a scan of `C:\` and a
    /// watcher at the same time: nothing here blocks, and a scan that has
    /// produced more than [`SCAN_DRAIN_CAP`] messages leaves the rest queued.
    pub fn drain(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        self.drain_driver(&mut out);
        self.drain_scan(&mut out);
        self.drain_realtime(&mut out);
        // Last, and in the pass after the driver's events were routed into it:
        // the worker is a thread of its own and walks a process for seconds, so
        // an outcome absorbed here was produced by a start seen in an earlier
        // pass. The order matters only in that the routing must have happened
        // first for there to be anything to absorb.
        self.drain_processes(&mut out);
        out
    }

    /// Stop the scan, stop the watcher, and say so.
    ///
    /// The scan is asked to cancel rather than joined: a walk of `C:\` can take
    /// minutes, and a service that waited for it would hold up the SCM's
    /// `STOP_PENDING` past its own timeout. The walker's thread checks the flag
    /// per file, so it stops within one file.
    ///
    /// Idempotent, because it is called from both [`Host`]'s own `Drop` and
    /// every explicit shutdown path, and a second call must not be a second
    /// warning about a watcher that is already gone.
    pub fn shut_down(&mut self) {
        if let Some(running) = self.scan.take() {
            running.cancel.store(true, Ordering::SeqCst);
        }
        self.stop_realtime("the service is stopping");
        // Once more, and not only for the reason `stop_realtime` gives: that
        // path stops the process watcher as part of stopping the watcher, and
        // this makes the shutdown itself idempotent — a second `shut_down` with
        // no watcher running must not be a second join.
        self.stop_process_watch();
        // Joined rather than abandoned, unlike the scan above and the filter-port
        // client below, and the reason is that it can be: the checker sleeps in
        // [`crate::tamper::POLL`] steps and checks its flag between them, so the
        // longest this waits is a quarter of a second. An expensive pass in
        // flight is the exception, and it is bounded by the product's own size.
        self.stop_tamper();
        if let Some(mut client) = self.filter_port.take() {
            // Asked and not waited for: the client's thread may be inside a
            // receive, which nothing in user mode can interrupt — see
            // [`crate::filter_port`]. The driver answers for itself as soon as
            // the connection goes, with the same allow it uses for a service
            // that never answered.
            client.stop();
            log::info!("the driver's decision port has been given up");
        }
        self.driver_out = None;
        self.state = ServiceState::Stopped;
    }

    /// What this service asks the driver to do for the product, in one message.
    ///
    /// # The two things it asks for, and which key asks for each
    ///
    /// * [`CONFIG_PROTECT_HANDLES`] — from `protection.self_protection`, under
    ///   `protection.enabled`. The driver removes the access rights that let
    ///   another process terminate, suspend or write into this product.
    /// * [`CONFIG_GATE_WRITES`] — from `protection.protect_own_files` together
    ///   with `driver.kernel_self_protection`, which is the driver's own half of
    ///   the same question and has to be on as well. The driver refuses writes
    ///   to this product's own files without asking anyone.
    ///
    /// # The directory, and why it is the install directory alone
    ///
    /// The gate matches a file *directly inside* the directory it is armed with,
    /// against the six names this product ships — see
    /// [`av_driver_proto::protect::is_protected_file`]. That directory is the
    /// install directory, and the rule database the loader actually reads lives
    /// somewhere else (`db_dir`) on every installation measured. **So the live
    /// rule database is not behind this gate**, and the reason is the same
    /// reason the gate is narrow at all: `wenle build` writes `db_dir/rules.avdb`
    /// in place, and a gate armed there would refuse the product's own rule
    /// compilation. That is a named gap rather than an oversight, and it is what
    /// `protection.protect_own_files` is disclosed as not covering.
    ///
    /// # Why a cargo build tree disarms the gate
    ///
    /// On a build tree `install_dir` is `target/<profile>`, which is the
    /// directory cargo writes into. Arming the gate there would refuse cargo's
    /// own writes to `wenle.exe`, `wenle-av-service.exe` and the rest, and every
    /// later build would fail with an access denial until the driver was
    /// restarted without the gate. Measured rather than feared: it is the same
    /// refusal `wenle protect apply` already documents at
    /// [`av_core::paths::cargo_build_tree`], and the check is that same
    /// function so the two cannot disagree.
    fn driver_configuration(&self) -> ConfigMessage {
        let protection = &self.loaded.config.protection;
        let mut flags = 0;
        if protection.enabled && protection.self_protection {
            flags |= CONFIG_PROTECT_HANDLES;
        }
        let mut message = ConfigMessage::new(flags);
        if !protection.enabled
            || !protection.protect_own_files
            || !self.loaded.config.driver.kernel_self_protection
        {
            return message;
        }
        if av_core::paths::cargo_build_tree(&self.paths.install_dir).is_some() {
            log::info!(
                "the install directory {} is inside a cargo build tree, so the driver is not \
                 being asked to refuse writes to it: cargo has to be able to write there",
                self.paths.install_dir.display()
            );
            return message;
        }
        // `encode_wide` rather than `to_string_lossy`: the driver compares
        // UTF-16 code units against a UTF-16 path, and a lossy conversion would
        // silently change the characters of a directory whose name is not valid
        // Unicode — which would arm the gate on a path that is not this one.
        let units: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(
            self.paths.install_dir.as_os_str(),
        )
        .collect();
        match message.arm_gate(&units) {
            Ok(()) => message,
            // Refused rather than truncated, which `set_dir`'s own
            // documentation explains: a truncated directory is a different
            // directory. It is not silently dropped either — the message goes
            // without the gate, and the log says why.
            Err(error) => {
                log::warn!(
                    "the install directory {} is {} code units and does not fit the {} the driver's \
                     configuration message carries, so the driver is not being asked to refuse \
                     writes to this product's files",
                    self.paths.install_dir.display(),
                    error.needed,
                    error.capacity
                );
                message
            }
        }
    }

    /// Start the client that answers the driver's decision port.
    ///
    /// Called by [`Host::open`] and not by [`Host::open_with`], because a test
    /// builds its host with `open_with` and a test that connected to the
    /// product's filter port on a machine where the product is installed would
    /// take the driver's client slot from the service that is supposed to have
    /// it. The name is a parameter for the same reason
    /// [`crate::control::serve_on`]'s is, and [`Host::open`] passes the
    /// protocol's constant.
    ///
    /// Returns whether the thread was started — **not** whether the driver was
    /// reached. That is a question only time answers, because the driver may be
    /// loaded long after the service, and the answer arrives as
    /// [`Event::Driver`] when the connection comes and goes. A `false` here
    /// means there is no thread at all, which on this platform means a machine
    /// out of handles or out of memory, and the service carries on either way:
    /// the driver allows what it cannot get an answer for.
    pub fn start_driver_port(&mut self, port_name: &str) -> bool {
        if let Some(client) = &self.filter_port {
            // Already asked for. Starting a second client over the same port
            // would be a second answer to one question, and the one the driver
            // keeps is whichever connected last.
            return client.is_running();
        }
        let (sender, receiver) = crossbeam_channel::unbounded::<Event>();
        let client = filter_port::start_on(
            Arc::clone(&self.engine.engine),
            sender,
            port_name,
            self.allow.clone(),
            self.paths.clone(),
            self.driver_configuration(),
        );
        let started = client.is_running();
        self.filter_port = Some(client);
        self.driver_out = Some(receiver);
        started
    }

    /// Start the watcher if the configuration asks for it and it is not already
    /// running, and report the state the machine is in either way.
    ///
    /// # Why the plan is asked and the configuration is not
    ///
    /// `realtime.enabled` is only one of three ways for nothing to be watched;
    /// `realtime.filesystem_fallback` and every configured root that is excluded
    /// or absent are the others. Which one applies is [`WatchPlan`]'s to decide —
    /// it is the single owner of the question "what will be watched" — and
    /// turning its answer into a sentence is [`realtime_state_of`]'s. Asking the
    /// configuration here would be a second opinion about the same question, and
    /// the copy that disagrees is the one that quietly stops watching.
    ///
    /// # Why `self.realtime` is left `None` when there is nothing to watch
    ///
    /// Load-bearing rather than tidiness: both other callers use `is_some()` as
    /// the question "is the watcher running". `Host::set_realtime` reads it to
    /// decide whether turning protection on has anything to do, and
    /// `Host::apply_live` compares it against `realtime.enabled`. A service
    /// built over a plan with no roots would answer `true` to both — so turning
    /// realtime on would be a no-op for the life of the process, which is the
    /// exact failure this function exists to prevent.
    pub fn start_realtime(&mut self) -> RealtimeState {
        if self.realtime.is_some() {
            return self.realtime_state.clone();
        }
        // Armed before the plan is consulted, and deliberately: process watching
        // does not come from the filesystem at all. It is the *driver* that
        // reports a process starting, so a machine whose configured roots are
        // all absent still has process monitoring — and returning early below on
        // `plan.roots.is_empty()` would otherwise silently leave it off while the
        // configuration says protection is on.
        self.start_process_watch();
        let config = self.watcher_config(self.loaded.config.realtime.enabled);
        let plan = WatchPlan::from_config(&config, &self.paths);
        if plan.roots.is_empty() {
            // Not started, and the state says *why* rather than saying that
            // nothing has started it yet — which is a different fact, and the
            // one `Host::open_with` reports before anything has asked.
            self.realtime_state = realtime_state_of(&config, &plan);
            return self.realtime_state.clone();
        }
        self.realtime_state = self.spawn_realtime(&config);
        self.realtime_state.clone()
    }

    /// The watcher's configuration as the service will run it.
    ///
    /// The one place where `block_on_detect` is forced off — see this module's
    /// documentation — so there is one place to look when the question is "why
    /// did the watcher not take that file". With it off the watcher scans and
    /// reports and writes nothing, and [`Host`] performs the vault write with
    /// the vault it owns.
    ///
    /// `enabled` is a parameter because [`Request::RealtimeSet`] overrides it
    /// for this run only: a user pausing protection from a notification area is
    /// not editing a configuration file, so the file is not written.
    fn watcher_config(&self, enabled: bool) -> RealtimeConfig {
        RealtimeConfig {
            enabled,
            block_on_detect: false,
            ..self.loaded.config.realtime.clone()
        }
    }

    /// Let go of a running watcher, keeping the state it is reported in.
    ///
    /// [`Host::stop_realtime`] answers "the user turned this off" and so
    /// publishes [`RealtimeState::off`]. This is for the callers whose state is
    /// already more specific than one sentence — a root-by-root record of what
    /// stopped, and why — and who only need the service gone so that a later
    /// [`Host::set_realtime`] can build a new one. Every restart path asks
    /// `self.realtime.is_none()`, so a watcher left here with nothing to watch is
    /// protection that can never be turned back on.
    ///
    /// Safe to call from inside [`Host::drain_realtime`], which
    /// [`Host::watcher_ended`] does: the event channel is unbounded —
    /// `av_realtime` builds it with `crossbeam_channel::unbounded` — so the
    /// worker thread cannot be parked in a send that this join would wait on.
    fn disarm_realtime(&mut self) {
        self.stop_process_watch();
        if let Some(service) = self.realtime.take() {
            match service.stop() {
                Ok(stats) => log::info!(
                    "the filesystem watcher stopped after {} events and {} scans",
                    stats.events,
                    stats.files_scanned
                ),
                Err(error) => log::warn!("the filesystem watcher did not stop cleanly: {error}"),
            }
        }
    }

    /// Stop the watcher, reporting what it did while it ran.
    fn stop_realtime(&mut self, reason: &str) {
        self.disarm_realtime();
        self.realtime_state = RealtimeState::off(reason);
    }

    /// Build and arm the watcher, turning either outcome into a state.
    fn spawn_realtime(&mut self, config: &RealtimeConfig) -> RealtimeState {
        let policy = QuarantinePolicy::from(&self.loaded.config.quarantine);
        match RealtimeService::start(config, &self.paths, Arc::clone(&self.engine.engine), policy) {
            Ok(service) => {
                let state = realtime_state_of(config, service.plan());
                self.realtime = Some(service);
                state
            }
            Err(error) => {
                // Not defaulted to "off and fine": the configuration asked for
                // a watcher and there is not one, and that is the state the
                // user is actually in.
                log::error!("the filesystem watcher could not be started: {error}");
                RealtimeState {
                    enabled: config.enabled,
                    watching: false,
                    roots: Vec::new(),
                    disabled_by: Some(format!("the watcher could not be started: {error}")),
                    disclosures: Vec::new(),
                    lost_roots: Vec::new(),
                    missed: None,
                }
            }
        }
    }

    /// Build and arm the process watcher, if it is not already running.
    ///
    /// # Why it is separate from the filesystem watcher
    ///
    /// Different mechanism, different source. The filesystem watcher exists
    /// while `realtime.enabled` and has roots to arm; this exists while the
    /// *driver* is connected and reporting process creations. They are started
    /// together because one switch means protection, and they stay separate
    /// values because either can be running without the other.
    ///
    /// # What it is given, and what it is not
    ///
    /// A clone of the allow list, which shares its storage — see
    /// [`crate::allow`] — so a path the user allows while a walk is in flight is
    /// honoured by that walk. The paths, the engine, and the scan options the
    /// configuration in force produces. **Deliberately not the vault**: the
    /// worker must not be a second writer of it, and [`Host::absorb_memory`] is
    /// where a file is taken.
    ///
    /// A thread that will not start is logged and left as "no watcher". There is
    /// no state field for it: the honest place for that fact is the log, and a
    /// machine that cannot create a thread has larger problems than this setting.
    fn start_process_watch(&mut self) {
        if self.process_watch.is_some() {
            return;
        }
        let options = engine::options_from(&self.loaded.config.scanning);
        let terminating = self.loaded.config.realtime.terminate_malicious_process;
        match ProcessWatch::start(
            Arc::clone(&self.engine.engine),
            self.paths.clone(),
            self.allow.clone(),
            options,
            terminating,
            self.convictions.clone(),
        ) {
            Ok(watch) => {
                log::info!(
                    "the process watcher is running; a convicted process will{} be terminated",
                    if terminating { "" } else { " not" }
                );
                self.process_watch = Some(watch);
            }
            Err(error) => log::error!("the process watcher could not be started: {error}"),
        }
    }

    /// Let go of the process watcher, reporting what it did while it ran.
    ///
    /// The counters are read before the thread is joined, and the join is
    /// bounded by the walk in flight: the worker checks its stop flag between
    /// processes and not inside one, so a shutdown can wait up to
    /// [`crate::process_watch::SCAN_DEADLINE`] for a walk to end. That is the
    /// deadline's other purpose — see the module.
    fn stop_process_watch(&mut self) {
        let Some(watch) = self.process_watch.take() else {
            return;
        };
        let stats = watch.stats();
        log::info!("the process watcher stopped: {}", stats.describe());
        if !watch.stop() {
            log::warn!("the process watcher's thread did not end cleanly");
        }
    }

    /// Turn the watcher on or off, and report what it is doing.
    ///
    /// The reply is the *state*, not the request echoed back. A caller that
    /// asked for `true` on a machine with no watchable directory gets
    /// `watching: false` with a reason, which is the answer it needs; a caller
    /// told `true` because that is what it asked for would believe it is
    /// protected.
    fn set_realtime(&mut self, enabled: bool) -> RealtimeState {
        if enabled {
            if self.realtime.is_none() {
                // `true` forced, whatever the file says, and for this run only:
                // the file is not written, so the next start reads the file
                // again. That is the difference between a pause and a policy.
                let config = self.watcher_config(true);
                self.realtime_state = self.spawn_realtime(&config);
            }
        } else {
            self.stop_realtime("realtime was turned off by request");
        }
        self.realtime_state.clone()
    }

    /// Whether a scan may start, or the sentence explaining why not.
    fn start_scan(&mut self, path: &Path, options: &ScanOptions) -> (Reply, Vec<Event>) {
        if let Some(reason) = scan_refusal(path, &self.paths, self.scan.is_some()) {
            return (
                Reply::ScanStarted(ScanStart::Refused {
                    path: path.to_path_buf(),
                    reason,
                }),
                Vec::new(),
            );
        }
        self.next_scan = self.next_scan.saturating_add(1);
        let id = ScanId::new(self.next_scan);
        let mut options = options.clone();
        if options.memory {
            // The caller asked a *file scan* to sweep memory, which is not a
            // thing a file scan does here. Refusing the whole scan would be
            // worse than running it without — the files would go unexamined over
            // an option that is not about them — so the scan runs and the caller
            // is told through `crate::config::unhonoured`, which lists
            // `scanning.memory`, and through this log line. What the caller
            // probably wants is [`Host::scan_process`], which is the same sweep
            // asked for as its own request.
            log::warn!(
                "a file scan asked for memory scanning; this build does it as a process scan, \
                 not as a step of a file scan, so this scan will not sweep memory"
            );
            options.memory = false;
        }
        let job = ScanJob {
            id,
            path: path.to_path_buf(),
            options,
        };
        let (out, scan_out) = crossbeam_channel::unbounded();
        let cancel = Arc::new(AtomicBool::new(false));
        match scan::spawn(
            job,
            Arc::clone(&self.engine.engine),
            self.paths.clone(),
            self.allow.clone(),
            Arc::clone(&cancel),
            out,
        ) {
            Ok(running) => {
                self.scan = Some(running);
                self.scan_out = scan_out;
                self.scan_results.clear();
                self.scan_detections = 0;
                self.scan_quarantined = 0;
                self.scan_quarantine_failed = 0;
                self.scan_omitted = 0;
                self.running_scanned = 0;
                (
                    Reply::ScanStarted(ScanStart::Started {
                        id,
                        path: path.to_path_buf(),
                    }),
                    Vec::new(),
                )
            }
            Err(error) => (
                Reply::ScanStarted(ScanStart::Refused {
                    path: path.to_path_buf(),
                    reason: format!("the scan thread could not be started: {error}"),
                }),
                Vec::new(),
            ),
        }
    }

    /// Ask the running scan to stop.
    fn cancel_scan(&mut self, id: ScanId) -> ScanCancel {
        match &self.scan {
            Some(running) if running.id == id => {
                running.cancel.store(true, Ordering::SeqCst);
                ScanCancel::Requested { id }
            }
            // A cancel that arrives after the scan finished is answered with
            // `Unknown` rather than `Requested`. `Requested` would be a claim
            // that something was cancelled, and by then the summary event has
            // already gone out.
            _ => ScanCancel::Unknown { id },
        }
    }

    /// What the vault holds, newest first.
    fn quarantine_list(&self, limit: Option<u32>) -> QuarantineListing {
        let asked = limit.map_or(QUARANTINE_LIST_CAP, |n| n as usize);
        // Clamped rather than refused: a caller asking for a million entries is
        // asking for more than one frame can carry, and the reply says how many
        // it left out either way.
        let cap = asked.min(QUARANTINE_LIST_CAP);
        let total = self.vault.entries().len();
        let mut entries = self.vault.entries().to_vec();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.quarantined_at));
        let omitted = total.saturating_sub(cap);
        entries.truncate(cap);
        QuarantineListing {
            entries,
            total,
            omitted,
        }
    }

    /// Put an item back where it came from.
    fn restore(&mut self, id: QuarantineId) -> QuarantineChange {
        // To the original path, and never overwriting: a restore that silently
        // replaced whatever is at that path now would destroy a file the user
        // never asked us to touch. `RestoreOptions::to_original` is the
        // conservative choice and the vault's own default for the overwrite
        // flag is the one that refuses.
        match self.vault.restore(id, &RestoreOptions::to_original()) {
            Ok(path) => QuarantineChange::Restored { id, path },
            Err(error) => QuarantineChange::Failed {
                id,
                reason: error.to_string(),
            },
        }
    }

    /// Put an item back and stop the product taking it again.
    ///
    /// # The order is the design
    ///
    /// Restore first, and allow only if it worked. The other order would let a
    /// user switch a rule off for a path whose bytes are still in the vault:
    /// the exclusion would suppress the detection of a file that is not there,
    /// so the user would have paid a rule for nothing. It also makes the
    /// failure legible — a restore that refuses leaves nothing half-done.
    ///
    /// The live set is updated whether or not the configuration is, because the
    /// two are answers to different questions: the set is what this run of the
    /// service honours, and the file is what the next run reads. A failed write
    /// is reported in [`QuarantineChange::Allowed::lasting`] rather than as a
    /// failure, because the file really is back and really is allowed — what is
    /// missing is that it stays that way.
    fn allow(&mut self, id: QuarantineId, permanent: bool) -> QuarantineChange {
        // The same conservative options as a plain restore: to the original
        // path, and never overwriting whatever is there now.
        let path = match self.vault.restore(id, &RestoreOptions::to_original()) {
            Ok(path) => path,
            Err(error) => {
                return QuarantineChange::Failed {
                    id,
                    reason: error.to_string(),
                }
            }
        };
        // Added even when the path came out of the configuration to begin with,
        // because `insert` says whether it was new and a duplicate changes
        // nothing.
        self.allow.insert(&path);
        let lasting = permanent && self.remember_exclusion(&path);
        QuarantineChange::Allowed { id, path, lasting }
    }

    /// Add `path` to `general.exclusions` in force and write it to the file.
    ///
    /// Answers whether the file was written. The in-force copy is updated only
    /// on success, so a failed write leaves the service reporting the
    /// configuration it actually has rather than one it wished it had — the
    /// same rule [`Self::set_config`] follows.
    ///
    /// **The file is read back before it is written**, and the re-read is the
    /// point rather than an incidental detail. This file has two writers: this
    /// service, and the window, which writes it whole when the user presses
    /// *Save* in its Settings tab and does not tell the service it did.
    /// Appending to the copy this process loaded at start-up would write that
    /// older document over the file, silently undoing every setting the user had
    /// saved since — the exclusion they just asked for would be in the file and
    /// the rest of their settings would not, and nothing would say so, because
    /// the service's idea of the configuration never contained them.
    ///
    /// So what is written is the file as it is *now*, plus the one line. Only
    /// `general.exclusions` is copied back into the in-force configuration: it
    /// is the only field this call changed, and the only one of them that is
    /// applied live (`AllowList::set_configured` through [`Self::apply_live`]).
    /// Adopting the whole re-read document instead would have the service claim
    /// it is running with settings it decided at start-up and has not
    /// re-applied.
    ///
    /// Nothing here re-applies the configuration. The exclusion is already in
    /// force through [`Self::allow`]'s `AllowList`, and running the full live
    /// application for a one-line change would restart things that have nothing
    /// to do with it.
    fn remember_exclusion(&mut self, path: &Path) -> bool {
        let mut config = config::load(&self.paths).config;
        if !config.general.exclusions.iter().any(|held| held == path) {
            config.general.exclusions.push(path.to_path_buf());
        }
        match config::save(&self.loaded.path, &config) {
            Ok(()) => {
                self.loaded.config.general.exclusions = config.general.exclusions;
                true
            }
            Err(error) => {
                log::warn!(
                    "the path {} was allowed for this run, but the exclusion could not be \
                     written to {}: {error}",
                    path.display(),
                    self.loaded.path.display()
                );
                false
            }
        }
    }

    /// Destroy an item's bytes and keep its record.
    fn delete(&mut self, id: QuarantineId) -> QuarantineChange {
        match self.vault.delete(id) {
            Ok(_entry) => QuarantineChange::Deleted { id },
            Err(error) => QuarantineChange::Failed {
                id,
                reason: error.to_string(),
            },
        }
    }

    /// Write a configuration, then report what of it is in force.
    fn set_config(&mut self, config: &AvConfig) -> (Reply, Vec<Event>) {
        if let Err(error) = config::save(&self.loaded.path, config) {
            // The report carries the file that is *in force* — the old one —
            // with the failure attached. Reporting the new document as if it
            // had been written would be the exact lie this reply exists to
            // prevent.
            let mut report = config::report(&self.loaded);
            report.load_error = Some(format!("the configuration was not written: {error}"));
            return (Reply::Config(Box::new(report)), Vec::new());
        }
        let previous = self.loaded.config.clone();
        self.loaded = config::load(&self.paths);
        self.apply_live(&previous)
    }

    /// Apply the settings that take effect without a restart.
    ///
    /// Everything else is in [`crate::config::needs_restart`], which reaches the
    /// caller through the report this function's reply carries. The list of
    /// what is applied here is deliberately short and is asserted against the
    /// disclosure tables by a test: a setting applied live that is also
    /// disclosed as needing a restart tells the user a restart is required when
    /// it is not, and a setting disclosed as honoured that nothing applies is
    /// worse.
    fn apply_live(&mut self, previous: &AvConfig) -> (Reply, Vec<Event>) {
        let mut events = Vec::new();
        self.vault
            .set_policy(QuarantinePolicy::from(&self.loaded.config.quarantine));
        // Replaced rather than added to, so an entry the user has just taken out
        // of the file starts being scanned again before this reply is written.
        // The session's allows are untouched — see `crate::allow` — which is why
        // this is a call on the list rather than a new one built from the file.
        self.allow
            .set_configured(&self.loaded.config.general.exclusions);

        // Pushed rather than re-read when the worker next decides, because the
        // worker is a thread: a settings change the user has just saved must not
        // need a process start to take effect, and it must not take effect *after*
        // a process start that was already in flight. `realtime.terminate_malicious_process`
        // is not in `crate::config::needs_restart`, so this line is what makes
        // that true.
        if let Some(watch) = self.process_watch.as_ref() {
            watch.set_terminating(self.loaded.config.realtime.terminate_malicious_process);
        }

        let wanted = self.loaded.config.realtime.enabled;
        let running = self.realtime.is_some();
        if wanted != running {
            if wanted {
                self.start_realtime();
            } else {
                self.stop_realtime("realtime.enabled is off");
            }
            events.push(Event::StatusChanged(self.status()));
        } else if running
            && previous.realtime.watched_paths != self.loaded.config.realtime.watched_paths
        {
            // The plan is built from the configuration when the watcher starts,
            // which is what `crate::config::needs_restart` says about these two
            // keys. The watcher keeps the roots it armed; the status is re-sent
            // so a client can see that the answer has changed even though the
            // watcher has not.
            events.push(Event::StatusChanged(self.status()));
        }

        (
            Reply::Config(Box::new(config::report(&self.loaded))),
            events,
        )
    }

    /// Absorb what the driver's filter port has reported.
    ///
    /// Both channel states mean the same thing here and both are ordinary: no
    /// message yet, and no client at all. `Empty` is a driver that is idle — it
    /// sends a status on a timer rather than per file — and `Disconnected` is a
    /// service that never started a client, or one whose client has stopped.
    /// Neither is a fault to report; the connection's own coming and going
    /// arrives *as* an event on this channel rather than as its end.
    ///
    /// # Why a block is quarantined here and not in the filter port
    ///
    /// The filter port is a thread with no vault, no configuration and no
    /// `&mut Host`, and the reply has to go back to the driver inside the
    /// driver's own timeout regardless. So the port reports the block as a
    /// [`Detection`] and this — the control loop, which owns the one thing that
    /// writes to the vault — decides what to do with the file. Both facts the
    /// decision needs are already in the detection: the verdict the engine
    /// reached, and [`EntrySource::Driver`] saying it was the kernel that
    /// stopped the file rather than the watcher that noticed it afterwards.
    ///
    /// Nothing is quarantined unless [`should_take`] says so, which is the same
    /// predicate every other path uses and the same one
    /// [`Host::quarantine`] re-checks against `auto_quarantine`. A block with
    /// `auto_quarantine` off therefore still happens — the program does not run
    /// — and the notification says the file was refused, which is true, rather
    /// than claiming a vault entry that was never written.
    fn drain_driver(&mut self, out: &mut Vec<Event>) {
        let Some(events) = self.driver_out.as_ref() else {
            return;
        };
        // Drained into a local first so the borrow of `self.driver_out` ends
        // before anything below needs `&mut self`. `quarantine` is `&mut self`
        // and this is the only reason for the intermediate vector.
        let mut batch = Vec::new();
        while batch.len() < DRIVER_DRAIN_CAP {
            match events.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        for event in batch {
            // Two kinds of `DriverEvent` arrive on this channel and they are
            // told apart by where they were made, not by what they say.
            // `av-service`'s own connection events are built by
            // `filter_port::connection_event`, which always fills
            // `driver_state` with what it concluded; every event that came off
            // the port has been through `driver::translate`, which always
            // leaves it `None` because an `EventMessage` carries no status.
            // Both facts are documented where they are produced.
            if let Event::Driver(reported) = &event {
                if reported.driver_state.is_some() {
                    // The service's own note about the connection, recorded
                    // rather than passed on unread: it is what
                    // `Host::driver_status` reports as the driver's presence,
                    // and it is the *only* thing in this process that knows
                    // whether the driver is running.
                    self.driver_connected = reported.detail != 0;
                } else if reported.action == DriverEventAction::StateChanged {
                    // The driver's own reports, queued from its connect
                    // callback. `detail` is an `NTSTATUS` in both cases and the
                    // *subject* is what says which one — two registrations, two
                    // statuses, and `av-driver`'s `defer_driver_state_event` is
                    // where they are queued.
                    //
                    // Split by subject rather than stored in one slot because
                    // the two say different things about different mechanisms,
                    // and a single slot would report whichever arrived last as
                    // if it were the state of both.
                    //
                    // The remaining subjects are named rather than folded into a
                    // wildcard, so a `DriverSubject` added later stops this build
                    // instead of quietly becoming a status nothing records. They
                    // record nothing because a `StateChanged` event names a
                    // registration, and these are the only two the driver makes.
                    match reported.subject {
                        DriverSubject::Driver => {
                            self.process_notify = Some(reported.detail as i32);
                        }
                        DriverSubject::Protection => {
                            self.object_callbacks = Some(reported.detail as i32);
                        }
                        DriverSubject::Configuration => {
                            self.configuration_reply = Some(reported.detail as i32);
                        }
                        DriverSubject::File
                        | DriverSubject::Process
                        | DriverSubject::Image
                        | DriverSubject::Unrecognised { .. } => {}
                    }
                    // Consumed rather than forwarded. Nothing in the product
                    // renders a bare driver event, so publishing it would be a
                    // message no window shows; the fact it carries is reported
                    // by `Host::status`, which is where a user looks.
                    continue;
                } else if reported.action == DriverEventAction::ExecutionBlocked {
                    // The driver failed the creation itself, before the program
                    // got to run. This is the one event in the product that
                    // means a process did **not** start, and until 2026-10-18
                    // the driver never sent it.
                    //
                    // Logged here rather than routed to the watcher, because
                    // there is no process to watch: the pid in the event was
                    // refused and never existed. The line is the measurement —
                    // it is how the next run tells "the section refusal was
                    // honoured" from "it was not, and the veto caught it" from
                    // "neither worked".
                    match &reported.path {
                        Some(path) => log::warn!(
                            "{} (pid {}) was refused before it ran: the engine had just refused that image at the section gate",
                            path.display(),
                            reported.process_id
                        ),
                        None => log::warn!(
                            "a process (pid {}) was refused before it ran: the engine had just refused its image at the section gate",
                            reported.process_id
                        ),
                    }
                    continue;
                } else if reported.action == DriverEventAction::ProcessStarted {
                    // Routed rather than published, and the same reason applies
                    // as above: a bare driver event is a message no front end
                    // shows. What a client *is* told is the detection, if the
                    // walk finds anything — which arrives when the worker
                    // finishes, not here.
                    //
                    // `process_id` is the new process, not the parent: the
                    // driver takes it from `PS_CREATE_NOTIFY_INFO`'s own
                    // process identifier. `path` is its image, translated from
                    // the device path on the driver's worker.
                    self.note_process_start(reported.process_id, reported.path.clone());
                    continue;
                }
            }
            match event {
                Event::Detection(mut detection)
                    if detection.source == EntrySource::Driver
                        && should_take(detection.verdict) =>
                {
                    // Recorded *before* the quarantine and whether or not it
                    // succeeds, because the two answers differ: the vault can
                    // refuse to hold a file — it is gone, it is open, the disk
                    // is full — and none of that makes the process running it
                    // less malicious. What the worker consults is the engine's
                    // verdict, not the take.
                    self.convictions
                        .record(&detection.path, detection.verdict);
                    detection.action = self.quarantine(
                        &detection.path,
                        context_for_detection(&detection),
                    );
                    out.push(Event::Detection(detection));
                }
                other => out.push(other),
            }
        }
    }

    /// Hand a process that has just started to the worker, if it is wanted.
    ///
    /// # Why the configuration is read here
    ///
    /// `realtime.scan_on_process_start` is not in [`crate::config::needs_restart`],
    /// so it is a setting that takes effect without a restart — and this is
    /// where that is true. Reading it when the worker started would make turning
    /// it off apply at the next service start, which is not what the disclosure
    /// table promises.
    ///
    /// # Why a start with no worker is dropped rather than queued
    ///
    /// The driver reports process creations for as long as it is loaded, which
    /// is longer than the watcher runs: protection can be paused from the
    /// window, and the driver does not know that. Holding starts for a worker
    /// that is not there would mean a pause produces a burst of walks the moment
    /// protection is turned back on, examining processes that started while the
    /// user had said not to. The driver's own queue is the one that buffers, and
    /// it is bounded; what is dropped here is dropped for a reason and is
    /// counted by the driver's own drop counter.
    fn note_process_start(&mut self, pid: u32, path: Option<PathBuf>) {
        if !self.loaded.config.realtime.scan_on_process_start {
            return;
        }
        let Some(watch) = self.process_watch.as_ref() else {
            log::trace!("process {pid} started with no memory watcher running");
            return;
        };
        if !watch.note_start(Start { pid, path }) {
            // Counted by the worker and reported by `Host::status`'s watcher
            // counters; logged here at a level that does not fill a log when a
            // build starts four hundred processes.
            log::debug!("the process watcher's queue was full and process {pid} was not examined");
        }
    }

    /// Absorb what the process watcher has finished with.
    ///
    /// The other half of the split [`crate::process_watch`] documents: the worker
    /// reads memory and decides, and this — the control loop, which owns the one
    /// thing that writes to the vault — does the taking and tells the client.
    ///
    /// A refused process and a clean one both produce nothing: a refusal is
    /// counted by the worker, and an empty finding list has no detection to
    /// report. Neither is a fault, and neither is silence about something that
    /// happened to the machine's state.
    fn drain_processes(&mut self, out: &mut Vec<Event>) {
        // Drained into a local first so the borrow of `self.process_watch` ends
        // before `absorb_memory` needs `&mut self` — the same shape, and the
        // same reason, as `drain_driver`'s.
        let mut batch = Vec::new();
        if let Some(watch) = self.process_watch.as_ref() {
            while batch.len() < PROCESS_DRAIN_CAP {
                match watch.outcomes().try_recv() {
                    Ok(watched) => batch.push(watched),
                    Err(_) => break,
                }
            }
        }
        for watched in batch {
            self.absorb_memory(watched, out);
        }
    }

    /// Act on one examined process.
    ///
    /// The quarantine goes through [`Host::carry_out_ruling`], which is the same
    /// path a client-requested process scan uses — so the same ruling produces
    /// the same vault entry with the same note whichever way it was reached.
    ///
    /// [`Watched::refused`] and an empty finding list are both logged and then
    /// dropped. Nothing is published for either, and the difference between them
    /// survives in the worker's counters rather than in the event stream: a
    /// process nobody could read is a gap in coverage, and a client asking "what
    /// has this service been doing" gets that from `Host::status`.
    fn absorb_memory(&mut self, watched: Watched, out: &mut Vec<Event>) {
        if let Some(why) = &watched.refused {
            log::debug!("{} was not examined: {why}", watched.process);
            return;
        }

        // Before the early return for a clean process, because the stop this
        // reads is about the *image* and a process stopped for its image has no
        // findings at all. The quarantine of a running executable cannot delete
        // it — Windows keeps an image that is mapped — so the vault queues the
        // deletion, and stopping the process is the moment the queue can be
        // finished. Without this the file stayed on disk, runnable, until
        // somebody ran `wenle quarantine maintain`.
        if watched.terminated() {
            if let Some(image) = watched.image.as_deref() {
                self.finish_removal(image);
            }
        }

        if watched.findings.is_empty() {
            log::trace!(
                "{} was examined and held nothing that matched; stopped: {}",
                watched.process,
                watched.stopped.describe()
            );
            return;
        }

        // Read once, before the loop: the termination happened or it did not, and
        // it is a fact about the process rather than about any one finding. Every
        // detection this process produces carries the same answer, which is what
        // makes "the process this was found in was stopped" readable from a
        // single detection a client is looking at.
        let terminated = watched.terminated();
        for judged in &watched.findings {
            let action = self.carry_out_ruling(&judged.ruling, &judged.finding.container());
            out.push(Event::Detection(memory::detection_for(
                &judged.finding,
                action,
                terminated,
            )));
        }

        if !watched.walk_complete {
            // Said out loud because the alternative reads as "this process held
            // nothing else", which is a claim about an address space that was
            // not seen in full. The two stop reasons are named separately for
            // the reason `av_memory::ProcessOutcome` keeps the flags apart: one
            // says the process has an enormous address space and the other says
            // this service ran out of time, and they send a reader to different
            // places.
            log::warn!(
                "{} was not walked to the end ({}); what the walk did not reach was not examined",
                watched.process,
                if watched.deadline_reached {
                    "it ran out of time"
                } else {
                    "the region cap was reached"
                }
            );
        }
    }

    /// Absorb what the walker has sent.
    fn drain_scan(&mut self, out: &mut Vec<Event>) {
        let mut absorbed = 0usize;
        while absorbed < SCAN_DRAIN_CAP {
            match self.scan_out.try_recv() {
                Ok(message) => {
                    absorbed += 1;
                    self.absorb_scan(message, out);
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    // The walker's thread is gone and no `Finished` arrived:
                    // either it panicked or the send failed. A client waiting
                    // for the end of a scan has to be told, and the honest
                    // thing to tell it is that the scan stopped without
                    // reporting — not silence, and not a summary of zeroes
                    // that reads like a clean tree.
                    if let Some(running) = self.scan.take() {
                        self.finish_scan(
                            running.id,
                            ScanCounts {
                                incomplete: true,
                                incomplete_reason: Some(
                                    "the scan ended without reporting its results".to_string(),
                                ),
                                ..ScanCounts::default()
                            },
                            out,
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Take one message from the walker.
    fn absorb_scan(&mut self, message: ScanMessage, out: &mut Vec<Event>) {
        match message {
            ScanMessage::Progress(progress) => {
                self.running_scanned = progress.scanned;
                out.push(Event::ScanProgress(*progress));
            }
            ScanMessage::Finding(report) => self.absorb_finding(&report, out),
            ScanMessage::Finished(counts) => {
                // `self.scan` is cleared even if the walker somehow reports a
                // finish for a scan that is not the current one: leaving it set
                // would refuse every later scan for the life of the process.
                let id = match self.scan.take() {
                    Some(running) => running.id,
                    None => return,
                };
                self.finish_scan(id, *counts, out);
            }
        }
    }

    /// Decide what to do about one finding from the walker, and say so.
    fn absorb_finding(&mut self, report: &FileScanReport, out: &mut Vec<Event>) {
        self.scan_detections = self.scan_detections.saturating_add(1);
        let action = self.act_on_report(report);
        match action {
            DetectionAction::Quarantined { .. } => {
                self.scan_quarantined = self.scan_quarantined.saturating_add(1)
            }
            DetectionAction::QuarantineFailed { .. } => {
                self.scan_quarantine_failed = self.scan_quarantine_failed.saturating_add(1)
            }
            DetectionAction::Reported => {}
        }
        let detection = scan::detection_for(report, action);
        if self.scan_results.len() < SCAN_RESULT_CAP {
            self.scan_results.push(detection.clone());
        } else {
            self.scan_omitted = self.scan_omitted.saturating_add(1);
        }
        out.push(Event::Detection(detection));
    }

    /// Take a detection into the vault, if the configuration says to.
    ///
    /// The verdict check is a full `match` rather than `matches!` or an
    /// inequality, so that a variant added to [`Verdict`] stops this build
    /// instead of silently landing on the "do not act" side. See
    /// [`should_take`].
    fn act_on_report(&mut self, report: &FileScanReport) -> DetectionAction {
        if !should_take(report.verdict()) {
            return DetectionAction::Reported;
        }
        self.quarantine(
            &report.path,
            QuarantineContext::from_report(report, EntrySource::Scan),
        )
    }

    /// Whether the user has allowed `path`, and nothing should be done about it.
    ///
    /// One function so that every path that could take a file asks the question
    /// in the same place: the driver's gate asks [`crate::filter_port`]'s copy of
    /// this list before it scans, the watcher's findings ask here, and the
    /// service's own walk asks it before it reads the file. [`Self::quarantine`]
    /// asks it once more, at the moment of taking, so that a decision made before
    /// the user's *Allow* does not take a file the user has just put back. Four
    /// call sites and one answer, which is the only way "allow this file" can mean
    /// one thing.
    fn allowed(&self, path: &Path) -> bool {
        self.allow.allows(path)
    }

    /// Write one file into the vault, or say why not.
    ///
    /// # The same file, asked about twice
    ///
    /// The driver has two gates on one execution: its `IRP_MJ_CREATE`
    /// pre-operation sees the open that asked for `FILE_EXECUTE`, and its
    /// acquire-for-section pre-operation sees the mapping that follows. A file
    /// the engine convicts is refused at both, so the port reports two
    /// detections for it — measured in the test VM at 11:24:33 and 11:24:34 on
    /// 2026-10-01, both for the same path and the same path tag.
    ///
    /// The first reaches this function and takes the file. What the second one
    /// finds depends on whether the vault could remove the original, and the
    /// two shapes are different failures of the same overwrite:
    ///
    /// * **The original is gone.** The vault — quite correctly — refuses a path
    ///   that is not there, and what that failure is *not* is
    ///   [`DetectionAction::QuarantineFailed`], whose whole meaning is "the
    ///   file is still on disk". A missing source is looked up in
    ///   [`Host::taken`] and answers with the entry this run already made.
    /// * **The original is still there**, because whoever was about to run it
    ///   held it open and the deletion was deferred
    ///   ([`Host::win_the_removal_race`] is what retries it). The vault has a
    ///   file to take, so it takes it — and one file ends up with **two**
    ///   entries holding the same bytes. Measured in the guest on 2026-10-13:
    ///   `plant-payload.bin`, two entries (`b437adee`, `f7eaecb7`) both unable
    ///   to delete the original, against one for `plant2.bin`, where the retry
    ///   won the race and the second refusal therefore took the first shape.
    ///
    /// So the entry is looked up *before* the vault is asked, and the file on
    /// disk is compared with the one that was taken — same size, same
    /// modification time ([`FileIdentity`]). A path the driver refused twice
    /// while the original sat there unchanged is one file and one entry; a path
    /// where something *new* has been written since is a new file and gets its
    /// own, because answering with the old entry would report bytes as held
    /// that are not the bytes now on disk.
    ///
    /// A path this run has *not* taken, that is nonetheless gone, is still a
    /// failure and still an error: something other than this service removed
    /// the file, and no vault entry describes where it went.
    fn quarantine(&mut self, path: &Path, context: QuarantineContext) -> DetectionAction {
        if !self.loaded.config.quarantine.auto_quarantine {
            return DetectionAction::Reported;
        }
        // The backstop, and the fourth place [`Self::allowed`] is asked. The
        // three earlier ones are how a file is *not examined*: the driver's gate
        // asks before it scans, the watcher asks when a finding arrives, and the
        // walk asks before it reads. Those three happen before the decision and
        // this one happens at it, which is what makes "allow this file" hold for
        // a decision that was already in flight — the case that matters is the
        // user pressing *Allow* on a file in the vault while the driver, which
        // decided a moment earlier, still has that detection on its way here. The
        // file really is back on disk by then, so the vault would take it a second
        // time and the list would show the item the user had just cleared.
        //
        // A take is not undone and the finding is not hidden: the answer is
        // [`DetectionAction::Reported`], the same one `auto_quarantine = false`
        // gives, because the honest statement is that the file was examined and
        // this product is not acting on it.
        if self.allowed(path) {
            log::debug!(
                "{} was convicted but is allowed by the user's own decision; it is reported and \
                 not taken",
                path.display()
            );
            return DetectionAction::Reported;
        }
        // Read once, before the vault may move the file: what is recorded is
        // what the original looked like when it was taken, and what is compared
        // is what is at that path now.
        let identity = file_identity(path);
        if let Some(taken) = self.taken.get(path).copied() {
            if identity.is_some() && identity == taken.identity {
                Self::already_taken(path, taken.id, "the original is still there, unchanged");
                // The second refusal is often the one that arrives after the
                // process holding the file has been stopped — measured in the
                // guest on 2026-10-13, `host:1903 ... was deleted on a retry` —
                // so a deletion the first take had to defer is worth retrying
                // rather than leaving to `wenle quarantine maintain`.
                if context.remove_original && self.removal_is_pending(path) {
                    self.win_the_removal_race(path);
                }
                return DetectionAction::Quarantined { id: taken.id };
            }
        }
        match self.vault.quarantine_file(path, &context) {
            Ok(entry) => {
                self.taken.insert(
                    path.to_path_buf(),
                    Taken {
                        id: entry.id,
                        identity,
                    },
                );
                if context.remove_original && !entry.original_removed {
                    self.win_the_removal_race(path);
                }
                DetectionAction::Quarantined { id: entry.id }
            }
            Err(error) => {
                if let Some(id) = self.taken_earlier(path, &error) {
                    return DetectionAction::Quarantined { id };
                }
                // The file is still on disk. That is the fact this variant
                // exists to carry, and it is why the count of failures is a
                // separate number in the summary rather than a log line.
                log::error!("{} could not be quarantined: {error}", path.display());
                DetectionAction::QuarantineFailed {
                    reason: error.to_string(),
                }
            }
        }
    }

    /// The one sentence both routes to "this run already holds this file" say.
    ///
    /// `because` is the half that differs, and it is the half a reader needs:
    /// whether the original is still on disk unchanged (and was not taken
    /// again) or is gone entirely.
    fn already_taken(path: &Path, id: QuarantineId, because: &str) {
        log::info!(
            "{} was already taken into the vault by this run, as item {id}; the second refusal of \
             the same file has nothing left to quarantine ({because})",
            path.display()
        );
    }

    /// The entry that holds `path`, when this run is what took it and the only
    /// thing that went wrong is that the original is no longer there.
    ///
    /// The error is inspected rather than the filesystem: `NotFound` from the
    /// vault's own metadata call is the fact being asked about, and a second
    /// `exists` check here would be a race against whatever removed the file.
    fn taken_earlier(&self, path: &Path, error: &QuarantineError) -> Option<QuarantineId> {
        let missing = matches!(
            error,
            QuarantineError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
        );
        if !missing {
            return None;
        }
        let id = self.taken.get(path)?.id;
        Self::already_taken(path, id, "the original is gone");
        Some(id)
    }

    /// How long to keep trying when the vault could not delete the original.
    ///
    /// The file is held open by whoever was about to run it: the driver refuses
    /// the section while that process still holds the handle it opened to ask,
    /// so `DeleteFileW` — which asks for `DELETE` — loses a race measured in
    /// milliseconds. These four waits absorb that. They cost nothing when the
    /// delete succeeds first time (the common case), which is what keeps the
    /// budget in [`av_quarantine`]'s `max_removal_attempts` from being spent by
    /// the 100 ms control tick.
    const REMOVAL_RETRY_DELAYS: [Duration; 4] = [
        Duration::from_millis(50),
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_millis(400),
    ];

    /// Finish the deletion the vault had to defer.
    ///
    /// `store` leaves the original in place when `DeleteFileW` fails, queues it,
    /// and still returns `Ok` — so without this the file is reported as
    /// quarantined while it is still on disk holding a toast's worth of
    /// confidence, and nothing in the service ever retries it (the pending
    /// queue is swept only by `wenle quarantine maintain`).
    ///
    /// Each pass runs the same sweep the CLI runs — the only thing that can
    /// clear the queue — and stops as soon as this path is out of it. A handle
    /// that outlives 750 ms is not a race but a file someone is using, so it is
    /// left queued rather than retried harder here.
    fn win_the_removal_race(&mut self, path: &Path) {
        for delay in Self::REMOVAL_RETRY_DELAYS {
            std::thread::sleep(delay);
            match self.vault.retry_pending_removals() {
                Ok(sweep) => {
                    if !self.removal_is_pending(path) {
                        if sweep.abandoned > 0 {
                            log::warn!(
                                "gave up on deleting {} after too many attempts; it is still on \
                                 disk",
                                path.display()
                            );
                        } else {
                            log::info!(
                                "{} was deleted on a retry: the first attempt lost a race with \
                                 the handle of the process that opened it to run it",
                                path.display()
                            );
                        }
                        return;
                    }
                }
                Err(error) => {
                    log::warn!("the retry of {}'s deletion failed: {error}", path.display());
                    return;
                }
            }
        }
        log::warn!(
            "{} is still held open; its deletion stays queued and `wenle quarantine maintain` \
             will retry it",
            path.display()
        );
    }

    /// Whether the vault still owes a deletion of `path`.
    fn removal_is_pending(&self, path: &Path) -> bool {
        self.vault.pending_removals().iter().any(|p| p.path == path)
    }

    /// Finish the deletion of an image whose process has just been stopped.
    ///
    /// This is the one case [`Host::win_the_removal_race`] cannot cover: it
    /// waits 750 ms for a handle to be released, and the handle in question
    /// belongs to a process that is *running*, so it is released when that
    /// process ends and not before. Measured in the guest on 2026-10-18: a
    /// sample convicted at its section and quarantined had its bytes in the
    /// vault while the executable stayed where it was, which is why the same
    /// file could be started six times by hand.
    ///
    /// One sweep, no waiting: by the time this runs `TerminateProcess` has
    /// returned and the mapping is going away. A sweep that still fails is left
    /// queued for the next attempt rather than retried here — the caller this
    /// would block is the control loop.
    fn finish_removal(&mut self, image: &Path) {
        if !self.removal_is_pending(image) {
            return;
        }
        match self.vault.retry_pending_removals() {
            Ok(sweep) => {
                if !image.is_file() {
                    log::info!(
                        "{} was deleted now that the process running it has been stopped",
                        image.display()
                    );
                } else if sweep.abandoned > 0 {
                    log::warn!(
                        "{} is still on disk and its deletion has been given up on after too \
                         many attempts; what is left is the vault's copy and a file that can \
                         still be started",
                        image.display()
                    );
                } else {
                    log::warn!(
                        "{} is still on disk after its process was stopped; the deletion stays \
                         queued",
                        image.display()
                    );
                }
            }
            Err(error) => log::warn!(
                "the deletion of {} could not be retried now that its process has been \
                 stopped: {error}",
                image.display()
            ),
        }
    }

    /// Scan one process's memory, act on what its findings point at, and say
    /// what happened.
    ///
    /// # The chain, and where each link is
    ///
    /// A finding is attributed to `process:address`;
    /// [`av_memory::provenance::mapped_file_name`] says which file the bytes
    /// came from, if any; [`crate::memory`] decides what may be done about
    /// that file; and this is what carries the decision out through
    /// [`Host::quarantine`] — the same choke point a file the walker found goes
    /// through. There is deliberately no second way into the vault.
    ///
    /// # What this cannot do, stated here rather than discovered later
    ///
    /// * **It does not stop anything.** By the time this runs the process is
    ///   running, and a match in its memory is a fact about a program that has
    ///   already started. [`Phase::observed`] is given `false` for `blocked` and
    ///   so every detection from here is reported as after-the-fact. Stopping a
    ///   process *before* it runs is the kernel's job and needs an image-load
    ///   callback this build does not install — see the module documentation.
    /// * **It does not terminate the process.** See [`crate::memory`] for why,
    ///   and for what is done instead: the file, when there is one.
    /// * **It cannot see every process.** Measured on this machine, over half of
    ///   everything running refuses `PROCESS_VM_READ`; those come back as a
    ///   refusal carrying the reason, and a refusal is never a clean scan.
    ///
    /// # The cost, and why it is paid on the control loop
    ///
    /// This is synchronous: the loop that serves requests is busy for the
    /// duration, so a status request during a process scan is answered late
    /// rather than immediately. That is a deliberate trade. One process is
    /// bounded by [`av_memory::MemoryScanConfig`]'s byte budget for a process —
    /// a quarter of a gigabyte, and measured at tens of megabytes on this
    /// machine — and the alternative is a second scan pipeline with its own
    /// thread, channel, cancellation flag and progress events, none of which
    /// this needs yet. A client sees a slower answer, never a wrong one.
    /// Scan bytes that no file on disk contains. See [`Request::ScanBuffer`].
    ///
    /// # Why this does not quarantine, and why it notifies anyway
    ///
    /// [`Host::act_on_report`] is deliberately not called. Every other path that
    /// turns a report into a detection funnels through it and it moves the file
    /// into the vault — but these bytes came out of a host's memory and there
    /// may be no file at all to move. What the caller gets is a verdict with a
    /// reason attached; the caller is an AMSI provider sitting inside somebody
    /// else's process, and it is the thing that decides what to do.
    ///
    /// A notification is published regardless, because the alternative is a
    /// script silently not running with nothing telling the user why. Its source
    /// is [`EntrySource::Amsi`], and `blocked` is [`should_take`] of the verdict
    /// rather than a constant — the two have to be the same answer as the one
    /// the provider gives AMSI, or the corner says "stopped" about a script that
    /// the provider answered `NotDetected` for and the host therefore ran.
    ///
    /// That distinction is the yellow band. A `Suspicious` script is reported,
    /// because the user should know, and is not blocked, because this product's
    /// policy is that the middle band warns and never acts — so the notification
    /// for one is published as after-the-fact, which is the truth: it ran.
    ///
    /// # The name is a label, and is used as one
    ///
    /// It becomes a [`Path`] for exactly one purpose: the engine classifies a
    /// target partly by its extension, so a name that ends in `.ps1` is worth
    /// more to the classification than one that says nothing. Nothing here opens
    /// it, and the name never leaves this function as anything but a string in a
    /// report — see [`Request::ScanBuffer`] for why it is not trusted.
    fn scan_buffer(&mut self, name: &str, data: &[u8]) -> (Reply, Vec<Event>) {
        let options = engine::options_from(&self.loaded.config.scanning);
        let report = self
            .engine
            .engine
            .scan_bytes(Path::new(name), data, &options);

        let mut events = Vec::new();
        if report.is_detection() {
            let detection = Detection::from_report(
                &report,
                EntrySource::Amsi,
                should_take(report.verdict()),
                DetectionAction::Reported,
            );
            events.push(Event::Detection(detection));
        }

        let assessment = &report.assessment;
        // The same list `Detection::from_report` builds, by the same rule: a
        // detection with an empty identifier is carried under its readable name,
        // and a second spelling here is a second answer to "which rule fired".
        let rules: Vec<String> = assessment
            .detections
            .iter()
            .map(|detection| {
                if detection.rule_id.is_empty() {
                    detection.display_name()
                } else {
                    detection.rule_id.clone()
                }
            })
            .collect();

        // Written before the reply is built and after the rules are, so that
        // what is logged and what is answered are the same conviction — see
        // [`amsi_conviction_line`] for why this path needs a record at all.
        if report.is_detection() {
            log::warn!(
                "{}",
                amsi_conviction_line(name, report.verdict(), assessment.score, &rules)
            );
        }

        let summary = match &report.error {
            Some(error) => format!("{name} was not examined: {error}"),
            None if report.is_detection() => format!(
                "{name} matched {} rule(s) and was judged {}",
                rules.len(),
                report.verdict().as_str()
            ),
            None => format!("nothing found in {name}"),
        };

        let scan = BufferScan {
            name: name.to_owned(),
            verdict: report.verdict(),
            score: assessment.score,
            severity: assessment.max_severity(),
            rules,
            summary,
            error: report.error.clone(),
            size: report.scanned_bytes,
            duration_ms: u64::try_from(report.duration.as_millis()).unwrap_or(u64::MAX),
        };
        (Reply::BufferScan(Box::new(scan)), events)
    }

    fn scan_process(&mut self, pid: u32) -> (Reply, Vec<Event>) {
        let mut events = Vec::new();
        let report = self.memory_report(pid, &mut events);
        (Reply::MemoryScan(Box::new(report)), events)
    }

    /// The body of [`Host::scan_process`], collecting detection events as it
    /// goes.
    ///
    /// Split out so that the reply is built in exactly one place: a refusal
    /// takes four different routes out of here and every one of them has to
    /// produce a report that says so, which is what this shape makes hard to get
    /// wrong.
    #[cfg(windows)]
    fn memory_report(&mut self, pid: u32, events: &mut Vec<Event>) -> MemoryReport {
        if pid == 0 {
            return memory::refused_report(&ProcessRef::anonymous(pid), IDLE_PROCESS.into());
        }
        let process = av_memory::identify(pid);
        let mut source = match av_memory::Win32Source::open(process.clone()) {
            Ok(source) => source,
            // A handle that will not open is the same class of refusal as a walk
            // that will not run, and it gets the same shape of sentence. The
            // process was not examined and the report says so rather than
            // carrying an empty finding list a client could read as "clean".
            Err(error) => return memory::refused_report(&process, error.to_string()),
        };
        let scanner = av_memory::MemoryScanner::new(
            &self.engine.engine,
            av_memory::MemoryScanConfig::default(),
        );
        let outcome = match scanner.scan_process(&mut source) {
            av_memory::ProcessScan::Refused { reason, .. } => {
                return memory::refused_report(&process, reason.describe());
            }
            av_memory::ProcessScan::Examined(outcome) => outcome,
        };

        let options = engine::options_from(&self.loaded.config.scanning);
        let mut outcomes = Vec::with_capacity(outcome.findings.len());
        let mut detections = Vec::with_capacity(outcome.findings.len());
        for finding in &outcome.findings {
            let outcome = self.act_on_memory_finding(finding, &options);
            // `false`: this path is a scan somebody asked for, and a scan does
            // not kill anything. The process-start path is the one that can,
            // and it is the only caller that passes `true`.
            detections.push(memory::detection_for(
                finding,
                outcome.action.clone(),
                false,
            ));
            outcomes.push(outcome);
        }
        let tallies = memory::tally(outcomes.iter().map(|outcome| &outcome.decision));
        for detection in &detections {
            events.push(Event::Detection(detection.clone()));
        }

        MemoryReport {
            pid: process.pid,
            process: process.describe(),
            findings: detections,
            coverage: memory::coverage_of(&outcome),
            walk_complete: outcome.walk_complete,
            refused: None,
            files_taken: tallies.taken,
            files_left: tallies.left,
            without_a_file: tallies.without_a_file,
            at: Utc::now(),
        }
    }

    /// The same refusal on a platform this build cannot scan memory on.
    ///
    /// A separate definition rather than a `cfg` inside the body, because there
    /// is no part of the real one that is meaningful here: no handle, no walk,
    /// no findings. The report is a refusal, which is the honest answer, and the
    /// reason names the platform rather than the process.
    #[cfg(not(windows))]
    fn memory_report(&mut self, pid: u32, _events: &mut Vec<Event>) -> MemoryReport {
        memory::refused_report(
            &ProcessRef::anonymous(pid),
            "this build has no way to read another process's memory on this platform".to_string(),
        )
    }

    /// Decide about one memory finding and carry the decision out.
    ///
    /// Every question of *policy* is answered by [`crate::memory::rule_on`],
    /// which is pure and tested without a vault. This function supplies the one
    /// thing that function cannot have — the vault — and is not allowed to have
    /// an opinion of its own about anything else.
    ///
    /// The file's scan comes back inside the ruling rather than being stashed by
    /// a closure written here, which is what lets the vault record the numbers
    /// the *file's* scan reached. Those are the numbers the user is shown, and a
    /// second derivation from the memory finding's assessment would be a second
    /// answer.
    fn act_on_memory_finding(
        &mut self,
        finding: &MemoryFinding,
        options: &ScanOptions,
    ) -> memory::Outcome {
        let ruling = memory::rule_on(&finding.origin, &self.paths, &self.engine.engine, options);
        let action = self.carry_out_ruling(&ruling, &finding.container());
        memory::Outcome {
            decision: ruling.action,
            action,
        }
    }

    /// Do what a ruling says: take the file, or leave it and say why.
    ///
    /// `container` is the `process:address` string the finding was attributed
    /// to, and it is what the vault's note carries. Without it the record says a
    /// file was malicious and nothing about why anyone looked at it — the note is
    /// the only thing that makes a vault entry traceable back to the process it
    /// was found in.
    ///
    /// One implementation for both callers that act on memory findings — a scan
    /// a client asked for, and a process this service watched start — because the
    /// two must not differ in what they do about the same ruling. The logging
    /// lives here for the same reason: a file left because its image is gone from
    /// under a mapped region is worth the same warning whichever path found it.
    fn carry_out_ruling(&mut self, ruling: &memory::Ruling, container: &str) -> DetectionAction {
        match &ruling.action {
            memory::Action::Take { file } => match &ruling.report {
                Some(report) => {
                    let context = QuarantineContext::from_report(report, EntrySource::Memory)
                        .with_note(format!("found in the memory of {container}"));
                    self.quarantine(file, context)
                }
                // Unreachable: a take is only ever ruled on a verdict, and a
                // verdict only ever comes back with the report it came from.
                // Written as a failure rather than an `expect`, because a
                // service that panicked here would take the whole machine's
                // protection down over a state that leaves the file on disk.
                None => {
                    log::error!(
                        "{} was ruled fit to quarantine with no scan report behind the ruling",
                        file.display()
                    );
                    DetectionAction::QuarantineFailed {
                        reason: "the file's own scan report was lost before it could be taken"
                            .to_string(),
                    }
                }
            },
            memory::Action::Leave { .. } => {
                // Logged rather than silent, and at a level that says whether
                // anyone should look: a file that is gone from under a mapped
                // image is worth noticing, and a file that merely scanned
                // ordinary is not.
                match &ruling.action {
                    memory::Action::Leave {
                        why: memory::Left::Gone,
                        ..
                    } => log::warn!(
                        "{} backs bytes that matched in memory and is no longer on disk",
                        ruling.action.file().unwrap_or(Path::new("?")).display()
                    ),
                    memory::Action::Leave {
                        why: memory::Left::OwnTree,
                        ..
                    } => log::warn!(
                        "a memory finding points into the product's own tree, which is never acted \
                         on from here: {}",
                        ruling.action.file().unwrap_or(Path::new("?")).display()
                    ),
                    _ => log::info!("{}", ruling.action.describe()),
                }
                DetectionAction::Reported
            }
        }
    }

    /// Turn a finished walk into the event that ends a client's scan.
    fn finish_scan(&mut self, id: ScanId, counts: ScanCounts, out: &mut Vec<Event>) {
        // Oldest first while it ran, so reversing gives newest first, which is
        // what `ScanSummary::results` documents.
        let mut results = std::mem::take(&mut self.scan_results);
        results.reverse();
        let summary = ScanSummary {
            files: counts.files,
            bytes: counts.bytes,
            detections: self.scan_detections,
            quarantined: self.scan_quarantined,
            quarantine_failed: self.scan_quarantine_failed,
            unreadable: counts.unreadable,
            unreadable_dirs: counts.unreadable_dirs,
            duration_ms: counts.duration_ms,
            incomplete: counts.incomplete,
            incomplete_reason: counts.incomplete_reason,
            results,
            results_omitted: self.scan_omitted,
            at: Utc::now(),
        };
        self.finished_files = self.finished_files.saturating_add(counts.files);
        self.running_scanned = 0;
        self.scan_detections = 0;
        self.scan_quarantined = 0;
        self.scan_quarantine_failed = 0;
        self.scan_omitted = 0;
        out.push(Event::ScanFinished(ScanFinished { id, summary }));
    }

    /// Absorb what the watcher has reported.
    fn drain_realtime(&mut self, out: &mut Vec<Event>) {
        // Collected first, then handled: the events borrow the service, and
        // handling one may need `&mut self` to write the vault. The disconnect is
        // carried out the same way and for the same reason.
        let mut collected = Vec::new();
        let mut ended = false;
        if let Some(service) = &self.realtime {
            while collected.len() < REALTIME_DRAIN_CAP {
                match service.events().try_recv() {
                    Ok(event) => collected.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        // Not the stopping path: `stop_realtime` takes the
                        // service before this function can see it, so the only
                        // way to reach this arm is that the watcher died on its
                        // own. `av_realtime` names the two ways — "on `stop` or
                        // when every watch has failed" — and neither is silent.
                        //
                        // `drain_scan` is the precedent, and the cost of getting
                        // this wrong is higher here than it is there. A scan that
                        // ends early ends, and the client is told; a watcher that
                        // dies leaves the machine without real-time protection
                        // for the rest of the process's life, and a `status()`
                        // that went on answering `watching: true` with roots
                        // nobody was watching would be the product telling its
                        // user they are protected. That is the failure this arm
                        // and `watcher_ended` exist to make impossible.
                        ended = true;
                        break;
                    }
                }
            }
        }
        for event in collected {
            self.absorb_realtime(event, out);
        }
        if ended {
            self.watcher_ended();
            out.push(Event::StatusChanged(self.status()));
        }
    }

    /// Record that the watcher stopped by itself, and leave it restartable.
    ///
    /// The two facts a client needs are that nothing is watched any more and
    /// *why*, and both come out of taking the service away: `status` reads
    /// [`RealtimeState`], and every path that restarts the watcher —
    /// [`Host::set_realtime`], [`Host::start_realtime`] through
    /// [`Host::apply_live`] — asks whether `self.realtime` is `None`. Leaving the
    /// dead service in place would answer "still running" to all of them, which
    /// is how a watcher that died becomes a watcher that can never be brought
    /// back.
    ///
    /// Deliberately not [`Host::stop_realtime`] with a different sentence: that
    /// function's reason argument would be a lie here — nothing asked for this —
    /// and the stop it performs is on a service that has already finished.
    fn watcher_ended(&mut self) {
        const REASON: &str = "the filesystem watcher stopped on its own: every watched root \
                              failed, or its scanner ended without reporting. Nothing is being \
                              watched.";
        log::error!("{REASON}");
        self.disarm_realtime();
        // Only if the state still claims coverage. When every root has already
        // failed its way out, that state names each directory that stopped and
        // why, and overwriting it with this one sentence would replace a
        // per-root record with a summary of itself. `watching: false` with a
        // live service is otherwise unreachable — `spawn_realtime` only stores
        // one when the plan had roots.
        if self.realtime_state.watching {
            self.realtime_state = RealtimeState::off(REASON);
        }
    }

    /// Take one watcher event.
    ///
    /// Exhaustive over [`av_realtime::RealtimeEvent`], because all three
    /// variants mean something a client has to be told and a wildcard arm would
    /// be the one that dropped the important one.
    fn absorb_realtime(&mut self, event: RealtimeEvent, out: &mut Vec<Event>) {
        match event {
            RealtimeEvent::Detected(finding) => {
                if self.allowed(&finding.path) {
                    return;
                }
                let action = match already_decided(&finding) {
                    Some(action) => action,
                    None if should_take(finding.verdict) => {
                        self.quarantine(&finding.path, context_for_finding(&finding))
                    }
                    None => DetectionAction::Reported,
                };
                out.push(Event::Detection(detection_for_finding(&finding, action)));
            }
            // A catch-up walk after the kernel dropped events. Each finding is
            // reported as a detection, and the walk itself is recorded in the
            // status, because the fact a client most needs is that there was a
            // window in which nothing was watched. Sent as one event rather than
            // as a detection per finding plus a footnote, so the "we missed a
            // window" fact cannot be dropped by a client that handles detections
            // and ignores the rest — and recorded in `missed` rather than only
            // logged, because a status change whose payload is unchanged tells
            // the client nothing and a log file is not where a user finds out
            // their protection had a hole in it.
            RealtimeEvent::Rescanned(rescan) => {
                log::warn!(
                    "{} was re-scanned after lost events: {} ({} files, {} unreadable, \
                     truncated: {})",
                    rescan.root.display(),
                    rescan.because,
                    rescan.files,
                    rescan.unreadable,
                    rescan.truncated
                );
                self.realtime_state.missed_window(MissedWindow {
                    root: rescan.root.clone(),
                    because: rescan.because.to_string(),
                    files: rescan.files as u64,
                    unreadable: rescan.unreadable as u64,
                    truncated: rescan.truncated,
                    findings: rescan.findings.len(),
                });
                for finding in &rescan.findings {
                    if self.allowed(&finding.path) {
                        continue;
                    }
                    let action = match already_decided(finding) {
                        Some(action) => action,
                        None if should_take(finding.verdict) => {
                            self.quarantine(&finding.path, context_for_finding(finding))
                        }
                        None => DetectionAction::Reported,
                    };
                    out.push(Event::Detection(detection_for_finding(finding, action)));
                }
                out.push(Event::StatusChanged(self.status()));
            }
            RealtimeEvent::WatchFailed { root, error } => {
                // The coverage the user believes they have is now smaller than
                // they believe. That is a status change and not a log line — and
                // it has to be a change: `status` clones `realtime_state`, which
                // was fixed when the watcher started, so publishing it unchanged
                // would report the previous state under a new name and leave the
                // stopped root listed as watched. `root_lost` is what moves it.
                log::error!("{} is no longer watched: {error}", root.display());
                let still_watching = self.realtime_state.root_lost(&root, error.to_string());
                if !still_watching {
                    // The service is still running and has nothing to watch. Left
                    // there it answers "already running" to every restart path —
                    // the failure `Host::start_realtime` documents — so it is let
                    // go and the next request builds a new one. The state is kept
                    // as `root_lost` left it rather than replaced with `off`:
                    // which directory stopped, and why, is what the user needs,
                    // and `off` would collapse it to one sentence.
                    self.disarm_realtime();
                }
                out.push(Event::StatusChanged(self.status()));
            }
        }
    }
}

/// The last resort, and not the clean end.
///
/// [`Host::shut_down`] is how a caller says goodbye: it stops the watcher and
/// tells the client. This exists for the paths where a caller *cannot* — an
/// error returning out of [`crate::control::serve`], a panic unwinding, the
/// `--console` path returning early — because a dropped host would otherwise
/// leave a watcher thread holding a directory handle and a scan thread walking
/// a disk in a process that is about to exit. Doing it twice is harmless.
impl Drop for Host {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// What a watcher error message says when no watcher has been started yet.
const NO_WATCHER_YET: &str = "the filesystem watcher has not been started";

/// What the tamper state says on a host nothing has asked to check.
///
/// The state a test's host reports, and the state [`Host::open`] reports for the
/// moment between `open_with` and `start_tamper`. It is not "the machine is
/// clean" — see [`TamperState`], whose whole design is that the answer a report
/// falls back to is never the reassuring one.
const NO_TAMPER_YET: &str = "the tamper checker has not been started";

/// What it says when the configuration does not ask for tamper resistance.
///
/// A different fact from [`NO_TAMPER_YET`] and worded as the user's own setting
/// rather than as something missing: `protection.tamper_resistance` is off, so
/// nothing is being watched, and a sentence about a service that has not started
/// something it was never asked to start would send somebody looking for a bug.
const NO_TAMPER_ASKED_FOR: &str =
    "protection.tamper_resistance is off in the configuration, so the product's own protection \
     is not being re-checked while the service runs";

/// One sentence for what the driver said about process-start notifications.
///
/// `code` is the `NTSTATUS` `PsSetCreateProcessNotifyRoutineEx` returned.
/// `STATUS_SUCCESS` is the only value that means registered, and **the failure
/// case is the one that has to be loud**: a driver whose process notifications
/// never registered reports nothing when a program starts, and a report that
/// said nothing there would read exactly like a machine where nothing starts —
/// which is why this says "not registered" and prints the code rather than
/// saying "disabled" or staying silent.
///
/// The code is printed rather than resolved to a name because resolving it
/// would mean a table of `NTSTATUS` values in this binary that has to be kept
/// right, and the number is what a reader looks up.
fn describe_process_notify(code: i32) -> String {
    if code == 0 {
        "the driver reports that process-start notifications are registered".to_string()
    } else {
        format!(
            "the driver reports that process-start notifications are NOT registered \
             (PsSetCreateProcessNotifyRoutineEx returned 0x{:08X}), so a program starting is not \
             being reported to this service and its memory is not being examined",
            code as u32
        )
    }
}

/// One sentence for what the driver said about its object callbacks.
///
/// `code` is the `NTSTATUS` `ObRegisterCallbacks` returned, reported by the
/// driver with [`av_ipc::DriverSubject::Protection`] because it is a
/// registration made to defend this product rather than something the driver
/// observed happening.
///
/// # Why this sentence is separate from [`describe_process_notify`]'s
///
/// The two are different mechanisms and a reader who was told only one of them
/// had failed would look at the wrong half of the driver. Process-start
/// notifications are how a starting program's memory gets examined; the object
/// callbacks are how another process is stopped from terminating this one. A
/// machine can have either without the other, and this build has had exactly
/// that: process-start notifications have been registered for several rounds
/// while `ObRegisterCallbacks` did not appear in the driver at all.
///
/// The failure case is the loud one for the same reason it is in
/// [`describe_process_notify`]: an unregistered callback removes nothing and
/// reports nothing, so silence here would read as "nothing tried to touch us".
fn describe_object_callbacks(code: i32) -> String {
    if code == 0 {
        "the driver reports that its object callbacks are registered, so the access rights that \
         would let another process terminate or write into this product are being removed"
            .to_string()
    } else {
        format!(
            "the driver reports that its object callbacks are NOT registered \
             (ObRegisterCallbacks returned 0x{:08X}), so another process's request to terminate \
             or write into this product is not being stripped of those rights",
            code as u32
        )
    }
}

/// One sentence for what the driver answered the configuration message.
///
/// `code` is the `NTSTATUS` the driver returned from its port message callback,
/// reported with [`DriverSubject::Configuration`] by the filter-port thread that
/// sent it — see [`crate::filter_port::configure`].
///
/// # Why the success sentence names what was asked for, not "success"
///
/// The configuration has two independent halves and the driver answers with one
/// code for the pair, so `STATUS_SUCCESS` is a claim that both were applied
/// *from the driver's side* — its `ObRegisterCallbacks` registration and its
/// write gate over the directory it was given. What it does **not** say is that
/// the write gate covers the rule database the loader actually reads, because it
/// does not, and that gap is named where the directory is chosen
/// ([`Host::driver_configuration`]) and in the disclosure
/// `protection.protect_own_files` carries. A sentence here that said only "the
/// driver accepted the configuration" would let a reader assume the whole of
/// that key was in force.
///
/// The failure case is the loud one, for the reason it is in
/// [`describe_process_notify`]: a driver that refused this message is defending
/// nothing, and a status that stayed silent would be indistinguishable from one
/// where the message was never sent.
fn describe_configuration(code: i32) -> String {
    if code == 0 {
        "the driver applied the configuration this service sent it, so the kernel's own defence of \
         this product is armed and does not depend on this service answering"
            .to_string()
    } else {
        format!(
            "the driver REFUSED the configuration this service sent it with 0x{:08X}, so its \
             protection of this product is not armed: another process's requests against it are \
             not being stripped of the rights to terminate or write into it, and writes to this \
             product's own files are not being refused in the kernel",
            code as u32
        )
    }
}

/// Whether a detection should be taken into the vault.
///
/// The policy itself is [`Verdict::blocks`], and this function exists only to
/// keep the name the vault's callers know it by. It used to hold a second copy
/// of the match, which was harmless right up until an AMSI provider needed the
/// same answer from inside another process — see that method's documentation
/// for what the duplicate would have cost.
pub const fn should_take(verdict: Verdict) -> bool {
    verdict.blocks()
}

/// The one line a script block this product convicted leaves behind.
///
/// # Why this path needs a record of its own
///
/// Every other way something is convicted ends at a vault entry, and the
/// product's entire user-facing surface for a block is built on those entries:
/// the window's list, the corner notification, `wenle quarantine list`. The AMSI
/// path deliberately takes nothing — there is no file to take — so none of that
/// appears, and the event it produces is published on the *provider's* own
/// connection, which is inside somebody else's process. That provider logs the
/// event at debug and drops it, and a host like `powershell.exe` has no logger
/// installed at all.
///
/// The result, before this function existed: a script this product refused left
/// no trace anywhere a person could look, and "the provider examined it and
/// convicted it" could not be told apart from "the provider never ran at all".
/// The check that the provider works is unanswerable in that state, and so is
/// "why did my script not run".
///
/// # Why it is a function and not a `log::warn!` at the call site
///
/// The shape of this line is a contract with somebody reading the service log —
/// the only place it can be read — so it is a pure function of its arguments and
/// is asserted on, the same way [`crate::main`]'s log format is. A call site
/// that could spell the line differently from the one the check greps for is the
/// failure this prevents, and it is the failure a test can catch.
///
/// The rules are named rather than counted. A conviction a user cannot attribute
/// to a rule is a conviction they cannot argue with, and "score 100" alone gives
/// them nothing to look up.
///
/// It says what was *done* with the verdict in the host's own terms, because the
/// two bands lead to different outcomes a reader has to be able to tell apart: a
/// `Suspicious` script is one this product reports and runs anyway, and a line
/// that read as a block would be this product claiming an action its policy says
/// it must not take.
fn amsi_conviction_line(name: &str, verdict: Verdict, score: u16, rules: &[String]) -> String {
    // A detection whose rules all had neither an identifier nor a readable name
    // is not reachable through `Detection::from_report`'s own rule, but a line
    // reading "from " with nothing after it would be a line a person cannot act
    // on, so the empty case says so rather than being left blank.
    let attribution = if rules.is_empty() {
        "(no rule named it)".to_string()
    } else {
        rules.join(", ")
    };
    format!(
        "an AMSI host asked about {name}: {} with score {}, from {attribution}{}",
        verdict.as_str(),
        score,
        if should_take(verdict) {
            " — the host was told to refuse it"
        } else {
            " — the host was told to run it"
        }
    )
}

/// Whether a scan of `path` must be refused, and why.
///
/// Takes the three facts it needs rather than `&self`, so that every refusal is
/// testable without a service, a thread or a filesystem — the property that
/// makes the sentences here worth trusting.
pub fn scan_refusal(path: &Path, paths: &AvPaths, busy: bool) -> Option<String> {
    if busy {
        return Some(
            "a scan is already running; cancel it before starting another, because two scans at \
             once each run at half speed and neither reports the whole truth"
                .to_string(),
        );
    }
    // Checked before existence, and the order matters: the product's own
    // vault and data directories may not have been created yet, and "that
    // directory does not exist" is a much less useful answer than "that is the
    // vault". The reason a path is refused should be the reason that matters.
    if engine::is_own_tree(paths, path) {
        return Some(format!(
            "{} is inside the product's own directory; scanning it would report the quarantine \
             vault's own contents as fresh detections",
            path.display()
        ));
    }
    if !path.exists() {
        return Some(format!("{} does not exist", path.display()));
    }
    None
}

/// The watcher's picture, from its configuration and the plan it built.
///
/// `disabled_by` is spelled out by hand because
/// [`av_realtime::DisabledBy`] has no `Display` — and it should not have one:
/// the sentence belongs to the component that knows what the user asked for,
/// and this is that component.
pub fn realtime_state_of(config: &RealtimeConfig, plan: &WatchPlan) -> RealtimeState {
    let mut disclosures: Vec<SettingDisclosure> = plan
        .unhonoured
        .iter()
        .map(|entry| SettingDisclosure::new(entry.setting, entry.reason))
        .collect();
    // A configured root that is not being watched is the same class of fact as
    // an unhonoured setting — the user asked for coverage and has less — so it
    // goes in the same list, naming the path in the reason.
    for skipped in &plan.skipped {
        disclosures.push(SettingDisclosure::new(
            "realtime.watched_paths",
            format!(
                "{} is not watched: {}",
                skipped.path.display(),
                skipped.reason.describe()
            ),
        ));
    }
    RealtimeState {
        enabled: config.enabled,
        watching: !plan.roots.is_empty(),
        roots: plan.roots.clone(),
        disabled_by: plan.disabled_by.map(disabled_by_text),
        disclosures,
        // Empty by construction: this builds the state a watcher *starts* in, and
        // nothing has stopped or been missed yet. Both are filled in later by the
        // drain, from the events that say so.
        lost_roots: Vec::new(),
        missed: None,
    }
}

/// Why nothing is watched, in a sentence.
///
/// Exhaustive over [`DisabledBy`]: a new reason stops this build, because the
/// alternative is a user being shown no reason at all for having no protection.
fn disabled_by_text(reason: DisabledBy) -> String {
    match reason {
        DisabledBy::NotEnabled => {
            "realtime.enabled is off, so nothing is being watched".to_string()
        }
        DisabledBy::FallbackTurnedOff => "realtime.filesystem_fallback is off, and the kernel \
             minifilter is not connected by this build, so nothing is watching the filesystem"
            .to_string(),
    }
}

/// What the vault already decided about a watcher finding, if it decided.
///
/// `av_realtime` takes a file itself when `block_on_detect` is honoured, and
/// reports the entry it made or the reason it could not. This service forces
/// that off, so both fields are empty in practice — but a build that stopped
/// forcing it off would otherwise quarantine the same file twice, and the
/// second write is the one that loses the first entry's record.
pub fn already_decided(finding: &av_realtime::Finding) -> Option<DetectionAction> {
    if let Some(id) = finding.quarantined {
        return Some(DetectionAction::Quarantined { id });
    }
    finding
        .quarantine_error
        .as_ref()
        .map(|reason| DetectionAction::QuarantineFailed {
            reason: reason.clone(),
        })
}

/// The vault context for a watcher finding.
///
/// Built by hand because a [`FileScanReport`] does not survive the watcher —
/// `av_realtime` consumes it and keeps the [`av_realtime::Finding`] — so
/// `QuarantineContext::from_report` is not available. Every field that *is*
/// carried over is copied from the finding rather than re-derived, for the
/// reason that function gives: those are the numbers the user was shown.
///
/// The note is not decoration. It is the record of *how* the file was taken,
/// which is the one thing the vault entry cannot work out for itself: this
/// watcher takes a file after the scan that found it, having blocked nothing.
pub fn context_for_finding(finding: &av_realtime::Finding) -> QuarantineContext {
    QuarantineContext {
        threat: finding.threat.clone(),
        detection: finding.detection.clone(),
        severity: finding.severity,
        verdict: finding.verdict,
        source: EntrySource::Realtime,
        note: Some(
            "taken by the filesystem watcher after the scan that found it; the file was not \
             stopped before it appeared"
                .to_string(),
        ),
        remove_original: true,
    }
}

/// The vault record for a file the kernel driver refused.
///
/// The context is built from the [`Detection`] rather than from a
/// [`FileScanReport`], for the reason [`context_for_finding`] gives and one
/// more: the report belongs to the filter port's thread, which has already
/// replied to the driver and moved on by the time this runs. The detection is
/// what crossed the channel, and it carries the same copied — not recomputed —
/// verdict, severity and threat.
///
/// [`detection`](QuarantineContext::detection) is the first rule identifier,
/// which is what [`QuarantineContext::from_report`] takes as well; the whole
/// list is in the detection and stays there.
///
/// The note is the record of how the file was taken, and **it is two sentences
/// rather than one since 2026-10-15**, because a driver detection now arrives
/// from two gates that took the file in opposite ways.
///
/// A refusal is the strongest of the three sources: the driver stopped the
/// open, so the program never began to run, and the vault write lands on a file
/// no process has a handle to. A conviction from the gate that only reports is
/// the **weakest** source in the product — nothing was stopped and the program
/// did run; all that made the file takeable is that the engine convicted it
/// while the kernel was asking. Writing the stronger sentence for both would
/// put "no process was allowed to execute it" on a vault record for a file that
/// executed, and the quarantine list is the only place that difference is
/// recorded for a user reading it a week later.
pub fn context_for_detection(detection: &Detection) -> QuarantineContext {
    let note = if detection.claims_a_block() {
        "the kernel driver refused this file before it ran and the service took it afterwards; \
         no process was allowed to execute it"
    } else {
        "the kernel driver convicted this file while it was being opened and the service took it \
         afterwards; the open was allowed, so a process may have run it"
    };
    QuarantineContext {
        threat: detection.threat.clone(),
        detection: detection.rules.first().cloned(),
        severity: detection.severity,
        verdict: detection.verdict,
        source: EntrySource::Driver,
        note: Some(note.to_string()),
        remove_original: true,
    }
}

/// The notification a watcher finding turns into.
///
/// The phase is [`Phase::observed`] of the source and `false`, and not the
/// finding's own phase field, because the derivation is the protocol's and
/// doing it once here is what stops two components disagreeing. A test asserts
/// the two agree.
///
/// The score is [`av_core::Severity::default_score`], which is the score a
/// finding of that severity alone carries. It is used because
/// [`av_realtime::Finding`] does not carry the engine's accumulated score —
/// the report it was built from is consumed inside the watcher — and reporting
/// a zero would render "0" beside a file the engine called malicious.
/// `av_realtime`'s own code reaches for the same function for the same reason
/// when it has no score of its own.
pub fn detection_for_finding(finding: &av_realtime::Finding, action: DetectionAction) -> Detection {
    Detection {
        path: finding.path.clone(),
        file_name: file_name_of(&finding.path),
        verdict: finding.verdict,
        score: finding.severity.default_score(),
        severity: finding.severity,
        threat: finding.threat.clone(),
        rules: finding.detection.iter().cloned().collect(),
        action,
        source: EntrySource::Realtime,
        size: finding.size,
        at: Utc::now(),
        // The watcher reports files. There is no process in the story, and so
        // no process this could have terminated.
        in_process: None,
        terminated: false,
        phase: Phase::observed(EntrySource::Realtime, false),
    }
}

/// The file name component of a path, or the whole path when there is not one.
///
/// The same fallback `av-quarantine` and `av-ipc` use. A name that came out
/// empty would render a blank line where a file name belongs.
///
/// `pub(crate)` rather than private, which it was when the only caller was the
/// watcher's conversion: a memory finding needs the same fallback, and now that
/// both are in this crate a fourth copy of four lines is a fourth place the rule
/// can drift. The two copies that remain are in crates this one cannot see.
pub(crate) fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use av_core::config::AvConfig;
    use av_core::Severity;
    use av_ipc::MemoryCoverage;
    use av_rules::database::RuleDatabase;

    use crate::process_watch::Judged;
    use crate::terminate::{ProcessToken, Stopped};

    /// A layout in a temporary directory, with a database the tests can fill.
    fn layout(dir: &tempfile::TempDir) -> AvPaths {
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        std::fs::create_dir_all(&paths.db_dir).expect("the database directory");
        paths
    }

    /// A host over a temporary directory, with no rules.
    ///
    /// Built with [`Host::open_with`] and an engine whose catalog index is
    /// `None`, which is the whole reason that constructor exists: the
    /// production [`Host::open`] would read this machine's entire catalog store
    /// for every test in this module.
    fn host(dir: &tempfile::TempDir) -> Host {
        let paths = layout(dir);
        let loaded = config::load(&paths);
        let engine = engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            crate::engine::CatalogStatus::default(),
        );
        Host::open_with(paths, loaded, engine).expect("the vault opens in a temporary directory")
    }

    /// A host whose whole watch plan is one directory this test owns.
    ///
    /// `watched_paths` is set rather than left to the default, and that is the
    /// point of the helper. The default plan is `av-realtime`'s
    /// `standard_paths()` — the Desktop, Downloads, Documents, temporary
    /// directory and removable drives of whichever account runs the test — so a
    /// test that armed it would have the scanner read a developer's home
    /// directory, and it would pass whether or not the code under it worked.
    /// Everything else is `config::load`'s answer.
    fn host_watching(dir: &tempfile::TempDir, watched: &Path) -> Host {
        let mut host = host(dir);
        // Asserted rather than assumed. "The configuration asks for realtime" is
        // only a meaningful question about `start_realtime` while the default is
        // yes, and a default quietly changed to `false` would make the test below
        // fail for a reason that has nothing to do with the code it tests.
        assert!(
            host.loaded.config.realtime.enabled,
            "the default must ask for realtime, or this helper is asking the wrong question"
        );
        assert!(
            host.loaded.config.realtime.filesystem_fallback,
            "the default must let the userspace watcher be the mechanism"
        );
        host.loaded.config.realtime.watched_paths = vec![watched.to_path_buf()];
        host
    }

    /// A host whose engine holds one rule matching `needle`, declared with
    /// whatever `severity` the caller names — `None` for a rule that declares
    /// none — and written to the data directory so the startup search finds it.
    ///
    /// The severity is a parameter rather than a constant because the *band* it
    /// produces is the thing under test in several places. One High indicator
    /// scores 100 and reaches `Verdict::Malicious`; a rule with no severity at
    /// all lands in the yellow band, where the product reports and never acts.
    /// A fixture that could only build the first would leave "the warning band
    /// does not act" untestable at this level, which is the half of the policy
    /// that is easy to get wrong.
    fn host_with_rule(dir: &tempfile::TempDir, needle: &str, severity: Option<&str>) -> Host {
        let paths = layout(dir);
        let meta = match severity {
            Some(severity) => format!("  meta:\n    severity = \"{severity}\"\n"),
            // Omitted rather than emitted empty: a `meta:` block with nothing
            // under it is a shape no rule in the corpus has, and a fixture that
            // invented one would be testing the parser's tolerance rather than
            // the band.
            None => String::new(),
        };
        let source = format!(
            "rule Test_Finds_Marker {{\n{meta}  strings:\n    $a = \"{needle}\"\n  condition:\n    \
             $a\n}}\n"
        );
        let database = RuleDatabase::compile(&source).0;
        assert_eq!(database.len(), 1, "the rule must compile");
        database
            .save(paths.db_dir.join(crate::engine::DATABASE_FILE))
            .expect("the database is written");
        let loaded = config::load(&paths);
        let engine = engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            crate::engine::CatalogStatus::default(),
        );
        assert!(
            engine.database.is_some(),
            "the rule database must have been found: {:?}",
            engine.load_error
        );
        Host::open_with(paths, loaded, engine).expect("the vault opens in a temporary directory")
    }

    /// A host whose engine holds one High rule matching `needle`.
    ///
    /// `severity = "high"` on purpose: one High indicator scores 100, which
    /// reaches `Verdict::Malicious`, and only a confirmed verdict is acted on.
    /// A rule with no severity lands in the yellow band, where the product warns
    /// and never acts — which is what the test that asserts nothing was taken is
    /// checking, so the severity has to be the one that *would* be acted on for
    /// that test to mean anything. Callers that want the other band ask for it
    /// with [`host_with_rule`] directly.
    fn host_matching(dir: &tempfile::TempDir, needle: &str) -> Host {
        host_with_rule(dir, needle, Some("high"))
    }

    /// A finding, built by hand so this module does not need a watcher.
    fn finding(path: PathBuf, verdict: Verdict, severity: Severity) -> av_realtime::Finding {
        av_realtime::Finding {
            path,
            phase: av_realtime::Phase::AfterTheFact,
            verdict,
            severity,
            threat: None,
            detection: Some("Test_Finds_Marker".to_string()),
            size: 12,
            action: None,
            quarantined: None,
            quarantine_error: None,
        }
    }

    #[test]
    fn a_fresh_host_reports_itself_honestly() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        assert_eq!(host.state(), ServiceState::Starting);

        let status = host.status();
        assert_eq!(status.state, ServiceState::Starting);
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.scans_running, 0);
        assert_eq!(status.files_examined, 0);
        assert_eq!(status.quarantine_items, 0);
        // No rules were written, so the report has to say so rather than being
        // empty in a way that reads as "there are no threats".
        assert!(status.database.is_none());
        assert!(host.engine().load_error.is_some());

        // And the transition is reported once and only once.
        let event = host.set_state(ServiceState::Running).expect("a change");
        assert!(matches!(event, Event::StatusChanged(_)));
        assert!(host.set_state(ServiceState::Running).is_none());
        assert_eq!(host.status().state, ServiceState::Running);
    }

    #[test]
    fn every_refusal_has_a_sentence_a_user_can_act_on() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = layout(&dir);

        // A scan already running.
        let busy = scan_refusal(Path::new("C:\\Windows"), &paths, true).expect("refused");
        assert!(
            busy.contains("already running"),
            "unexpected message: {busy}"
        );

        // A path that is not there. Outside the product's own tree, or the
        // own-tree reason is the one that fires — which is the ordering the
        // next assertion pins.
        let missing =
            scan_refusal(&dir.path().join("nothing-here"), &paths, false).expect("refused");
        assert!(
            missing.contains("does not exist"),
            "unexpected message: {missing}"
        );

        // The product's own tree, which is the one that matters: scanning it
        // would find the vault's contents and report them as new detections.
        // The vault directory does not exist yet here, and the own-tree reason
        // is still the one given — a user who typed the wrong path needs to
        // know *why* it is wrong, not that it is empty.
        let own = scan_refusal(&paths.quarantine_dir, &paths, false).expect("refused");
        assert!(
            own.contains("product's own directory"),
            "unexpected message: {own}"
        );
        assert!(
            !paths.quarantine_dir.exists(),
            "the reason is prior to existence"
        );

        // And an ordinary directory is not refused at all. The temporary
        // root's parent, not `paths.data_dir` — the data directory is itself
        // the product's own tree and is correctly refused.
        assert!(dir.path().is_dir());
        assert!(scan_refusal(dir.path(), &paths, false).is_none());
        assert!(scan_refusal(&paths.data_dir, &paths, false).is_some());
    }

    #[test]
    fn a_second_scan_is_refused_rather_than_queued() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        // Set the flag the same way a running scan would, without a thread: the
        // refusal is a decision about state and not about a thread existing.
        host.scan = Some(Running {
            id: ScanId::new(1),
            cancel: Arc::new(AtomicBool::new(false)),
        });
        let (reply, events) = host.handle(&Request::ScanPath {
            path: host.paths().data_dir.clone(),
            options: ScanOptions::default(),
        });
        match reply {
            Reply::ScanStarted(ScanStart::Refused { reason, .. }) => {
                assert!(reason.contains("already running"), "unexpected: {reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(events.is_empty(), "a refusal produces no events");
    }

    #[test]
    fn a_cancel_with_no_scan_of_that_name_is_unknown() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        let (reply, _) = host.handle(&Request::CancelScan { id: ScanId::new(7) });
        assert_eq!(
            reply,
            Reply::ScanCancelled(ScanCancel::Unknown { id: ScanId::new(7) })
        );
    }

    #[test]
    fn the_quarantine_list_is_newest_first_and_says_what_it_left_out() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        // Written through the host's own vault so the listing is reading the
        // state the service actually holds.
        for name in ["first.bin", "second.bin", "third.bin"] {
            let path = dir.path().join(name);
            std::fs::write(&path, name.as_bytes()).expect("writes");
            let context = QuarantineContext {
                source: EntrySource::Manual,
                ..QuarantineContext::default()
            };
            host.vault
                .quarantine_file(&path, &context)
                .expect("the vault takes it");
        }

        let (reply, _) = host.handle(&Request::QuarantineList { limit: None });
        let listing = match reply {
            Reply::QuarantineList(listing) => listing,
            other => panic!("expected a listing, got {other:?}"),
        };
        assert_eq!(listing.total, 3);
        assert_eq!(listing.entries.len(), 3);
        assert_eq!(listing.omitted, 0);
        assert!(!listing.is_truncated());
        // Newest first, so the last one written is the first one listed.
        assert_eq!(listing.entries[0].file_name, "third.bin");
        assert_eq!(listing.entries[2].file_name, "first.bin");

        // And a limit smaller than the vault reports the shortfall rather than
        // quietly returning less.
        let (reply, _) = host.handle(&Request::QuarantineList { limit: Some(1) });
        match reply {
            Reply::QuarantineList(listing) => {
                assert_eq!(listing.entries.len(), 1);
                assert_eq!(listing.total, 3);
                assert_eq!(listing.omitted, 2);
                assert!(listing.is_truncated());
            }
            other => panic!("expected a listing, got {other:?}"),
        }

        // A limit larger than the cap is clamped to the cap, not honoured.
        let (reply, _) = host.handle(&Request::QuarantineList {
            limit: Some(u32::MAX),
        });
        match reply {
            Reply::QuarantineList(listing) => assert_eq!(listing.entries.len(), 3),
            other => panic!("expected a listing, got {other:?}"),
        }
    }

    #[test]
    fn a_restore_or_delete_of_something_that_is_not_there_fails_with_a_reason() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        let absent = QuarantineId::new();
        for reply in [
            host.handle(&Request::QuarantineRestore { id: absent }).0,
            host.handle(&Request::QuarantineDelete { id: absent }).0,
        ] {
            match reply {
                Reply::QuarantineChange(QuarantineChange::Failed { id, reason }) => {
                    assert_eq!(id, absent);
                    assert!(!reason.is_empty(), "a failure has to say why");
                }
                other => panic!("expected a failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn config_set_writes_the_file_and_reports_what_will_wait_for_a_restart() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        let mut wanted = AvConfig::default();
        wanted.scanning.thresholds.malicious = 175;
        wanted.quarantine.auto_quarantine = true;

        let (reply, _) = host.handle(&Request::ConfigSet {
            config: Box::new(wanted.clone()),
        });
        let report = match reply {
            Reply::Config(report) => report,
            other => panic!("expected a configuration report, got {other:?}"),
        };
        assert!(report.load_error.is_none(), "{:?}", report.load_error);
        assert_eq!(report.config.scanning.thresholds.malicious, 175);
        // The threshold is applied at startup, so the report has to say so.
        assert!(
            report
                .unhonoured
                .iter()
                .any(|entry| entry.setting == "scanning.thresholds"),
            "a setting that waits for a restart must be disclosed"
        );
        // And it is really on disk, and really re-read.
        assert_eq!(host.loaded().config.scanning.thresholds.malicious, 175);
        let reread = AvConfig::load_or_default(&host.paths().config_file).expect("it parses");
        assert!(reread.quarantine.auto_quarantine);
    }

    #[test]
    fn a_configuration_that_cannot_be_written_is_reported_against_the_file_in_force() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        // A directory where the file should be: the write fails, and the reply
        // must not claim the new document is in force.
        std::fs::create_dir_all(&host.paths().config_file).expect("creates the obstruction");
        let mut wanted = AvConfig::default();
        wanted.scanning.thresholds.malicious = 199;

        let (reply, events) = host.handle(&Request::ConfigSet {
            config: Box::new(wanted),
        });
        assert!(events.is_empty());
        match reply {
            Reply::Config(report) => {
                let error = report.load_error.expect("the failure is reported");
                assert!(error.contains("not written"), "unexpected message: {error}");
                // The configuration in force is still the old one.
                assert_ne!(report.config.scanning.thresholds.malicious, 199);
            }
            other => panic!("expected a configuration report, got {other:?}"),
        }
    }

    #[test]
    fn turning_realtime_off_reports_a_state_and_not_an_echo() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        // Nothing was started, so turning it off is answered with the state it
        // is actually in: not watching, with a reason.
        let (reply, _) = host.handle(&Request::RealtimeSet { enabled: false });
        match reply {
            Reply::Realtime(state) => {
                assert!(!state.enabled);
                assert!(!state.watching);
                assert!(state.disabled_by.is_some());
                assert!(state.roots.is_empty());
            }
            other => panic!("expected a realtime state, got {other:?}"),
        }
        // And asking for `true` through a configuration with `enabled = false`
        // is still answered with the truth rather than the request. The
        // watcher is not started here, so this asserts the reply shape only:
        // `set_realtime` reads the state back out of the service, and a service
        // that started would be reported as `watching: true`.
        assert!(!host.loaded().config.realtime.enabled || host.realtime.is_none());
    }

    #[test]
    fn a_disabled_configuration_explains_itself() {
        let config = RealtimeConfig {
            enabled: false,
            ..RealtimeConfig::default()
        };
        let state = realtime_state_of(&config, &WatchPlan::disabled(DisabledBy::NotEnabled));
        assert!(!state.enabled);
        assert!(!state.watching);
        let reason = state.disabled_by.expect("a reason");
        assert!(reason.contains("realtime.enabled"), "unexpected: {reason}");

        // The other reason is a different sentence, because it is a different
        // problem: the user turned off the one mechanism that could have been
        // watching.
        let fallback = realtime_state_of(
            &RealtimeConfig::default(),
            &WatchPlan::disabled(DisabledBy::FallbackTurnedOff),
        );
        let reason = fallback.disabled_by.expect("a reason");
        assert!(
            reason.contains("filesystem_fallback"),
            "unexpected: {reason}"
        );
        assert_ne!(reason, disabled_by_text(DisabledBy::NotEnabled));
    }

    #[test]
    fn starting_realtime_arms_a_watcher_over_the_configured_root() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);

        let state = host.start_realtime();

        assert!(state.enabled, "the configuration asks for it");
        assert!(
            state.watching,
            "a watcher over a directory that exists must be watching: {state:?}"
        );
        assert_eq!(state.roots, vec![watched]);
        assert!(
            state.disabled_by.is_none(),
            "nothing is disabled: {state:?}"
        );
        // Held, and that is what makes it stoppable: `stop_realtime` reads this
        // field, so a watcher nobody holds is a watcher nobody can stop.
        assert!(host.realtime.is_some(), "the service must be held");

        // Idempotent, and it reports the *state* rather than a second watcher:
        // the early return is what keeps a second call from arming the same
        // roots twice, which would scan every file twice.
        let again = host.start_realtime();
        assert_eq!(again.roots, state.roots);
    }

    /// A root that stops has to leave the watched list, be recorded, and leave
    /// the watcher startable again.
    ///
    /// The third is the one a naive fix misses. Reporting `watching: false` is
    /// the visible half, but `set_realtime` and `apply_live` both ask
    /// `self.realtime.is_none()` to decide whether there is anything to do, so a
    /// service left running with no roots answers "already running" for the life
    /// of the process — protection that is off and cannot be turned back on.
    ///
    /// Driven by handing `absorb_realtime` the event a failing watch sends,
    /// which is what the drain does with it. The event is reached through the
    /// real path rather than a stand-in, so this fails if the arm is removed.
    #[test]
    fn a_root_that_stops_is_reported_and_leaves_the_watcher_startable() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);
        let armed = host.start_realtime();
        assert!(
            armed.watching,
            "the watcher has to be armed for this test to mean anything: {armed:?}"
        );

        let mut out = Vec::new();
        host.absorb_realtime(
            RealtimeEvent::WatchFailed {
                root: watched.clone(),
                error: av_realtime::RealtimeError::Win32 {
                    call: "ReadDirectoryChangesW",
                    code: 1,
                    message: "the test says so".to_string(),
                },
            },
            &mut out,
        );

        let realtime = host.status().realtime;
        assert!(
            !realtime.watching,
            "the only root stopped, so nothing may be reported as watched: {realtime:?}"
        );
        assert!(
            realtime.roots.is_empty(),
            "the stopped root has to leave the watched list: {:?}",
            realtime.roots
        );
        assert_eq!(
            realtime.lost_roots.len(),
            1,
            "the root that stopped has to be recorded: {realtime:?}"
        );
        assert_eq!(realtime.lost_roots[0].root, watched);
        assert!(
            realtime.lost_roots[0].reason.contains("ReadDirectoryChangesW"),
            "the reason has to be the watcher's, not a summary: {:?}",
            realtime.lost_roots[0]
        );
        assert!(
            realtime.disabled_by.is_some(),
            "a client asking why nothing is watched must be told: {realtime:?}"
        );
        assert!(
            realtime.enabled,
            "the watcher stopped; nobody turned it off: {realtime:?}"
        );
        assert!(
            host.realtime.is_none(),
            "a watcher with nothing to watch must not be left in place: every restart path asks this"
        );
        assert!(
            matches!(out.as_slice(), [Event::StatusChanged(_)]),
            "the fact has to arrive as a status change, and the one that carries it: {out:?}"
        );

        let restarted = host.start_realtime();
        assert!(
            restarted.watching,
            "the watcher has to be startable again: {restarted:?}"
        );
    }

    /// A catch-up walk after lost events is recorded in the status, not only in
    /// the log.
    ///
    /// A `StatusChanged` whose payload is unchanged tells a client nothing, and
    /// the log file is not where a user finds out their protection had a hole in
    /// it. The findings the walk produced are sent separately, as detections.
    #[test]
    fn a_catch_up_walk_after_lost_events_is_recorded_in_the_status() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);
        host.start_realtime();

        let mut out = Vec::new();
        host.absorb_realtime(
            RealtimeEvent::Rescanned(av_realtime::Rescan {
                root: watched.clone(),
                because: av_realtime::Lost::BufferOverflow,
                files: 214,
                unreadable: 3,
                truncated: true,
                findings: Vec::new(),
            }),
            &mut out,
        );

        let realtime = host.status().realtime;
        assert!(
            realtime.watching,
            "a catch-up walk does not stop the watch: {realtime:?}"
        );
        let missed = realtime
            .missed
            .as_ref()
            .unwrap_or_else(|| panic!("the window in which nothing was watched has to be reported: {realtime:?}"));
        assert_eq!(missed.root, watched);
        assert_eq!(missed.files, 214);
        assert_eq!(missed.unreadable, 3);
        assert!(
            missed.truncated,
            "a walk that stopped early must not read as a walk that covered everything"
        );
        assert!(
            missed.because.contains("buffer"),
            "the reason has to say what kind of loss it was: {missed:?}"
        );
        assert!(
            matches!(out.as_slice(), [Event::StatusChanged(_)]),
            "the walk itself is reported as a status change: {out:?}"
        );
    }

    /// The failure this test exists for is one step removed from the code it
    /// calls, which is why it asserts on `set_realtime` rather than on
    /// `start_realtime` alone.
    ///
    /// A `start_realtime` that built a watcher over an empty plan would leave
    /// `self.realtime` as `Some` — a service watching nothing, held as though it
    /// were watching something. `set_realtime` reads exactly that field to decide
    /// whether turning protection on has anything to do, so the consequence would
    /// be that `realtime.enabled = false` in the configuration made turning
    /// realtime on a permanent no-op: the user asks for protection, the request
    /// is accepted, and nothing is ever watched.
    #[test]
    fn a_configuration_that_asks_for_nothing_leaves_the_watcher_startable() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);
        host.loaded.config.realtime.enabled = false;

        let off = host.start_realtime();
        assert!(!off.enabled);
        assert!(!off.watching);
        assert!(off.roots.is_empty());
        let reason = off.disabled_by.expect("a reason for having no protection");
        assert!(
            reason.contains("realtime.enabled is off"),
            "the reason must name the setting the user set: {reason}"
        );
        assert!(
            host.realtime.is_none(),
            "nothing was armed, so nothing may be held — see this test's doc comment"
        );

        // The other half of the same question, and the one that fails if the
        // field above is `Some`: a request to turn protection on has to work.
        let on = host.set_realtime(true);
        assert!(
            on.watching,
            "turning realtime on after a configuration that had it off must arm the watcher: {on:?}"
        );
        assert_eq!(on.roots, vec![watched]);
    }

    /// The second reason a plan can have no roots, and a different sentence for
    /// the user — so it is asserted separately rather than folded into the test
    /// above, where a shared assertion would pass while one of the two reasons
    /// was reported as the other.
    #[test]
    fn the_fallback_being_off_leaves_the_watcher_startable() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);
        // `enabled` stays true: this is the configuration that hands the job to
        // the kernel minifilter rather than turning protection off.
        host.loaded.config.realtime.filesystem_fallback = false;

        let state = host.start_realtime();
        assert!(state.enabled, "realtime is still asked for");
        assert!(!state.watching);
        let reason = state.disabled_by.expect("a reason for having no watcher");
        assert!(
            reason.contains("filesystem_fallback"),
            "the reason must name the setting, and not the other one: {reason}"
        );
        assert!(
            host.realtime.is_none(),
            "the userspace watcher was not asked for, so none may be held"
        );
    }

    /// A watcher that dies has to stop being reported as protection, and has to
    /// be startable again — the second half is the one a naive fix misses.
    ///
    /// The detection half of this is not exercised here: reaching
    /// `drain_realtime`'s `Disconnected` arm needs a watcher that genuinely
    /// failed, which means either deleting a watched root under a live
    /// `ReadDirectoryChangesW` (timing-dependent, and a flaky test is worse than
    /// no test) or a seam in the service that does not otherwise exist. What is
    /// tested is what the arm does, which is what decides whether the machine
    /// ends up protected again.
    #[test]
    fn a_watcher_that_ended_is_reported_as_gone_and_can_be_started_again() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_watching(&dir, &watched);
        assert!(host.start_realtime().watching, "armed to begin with");

        host.watcher_ended();

        // Gone, and said so, rather than still claimed.
        assert!(
            host.realtime.is_none(),
            "the dead service must not be left in place: every restart path asks this"
        );
        let status = host.status();
        assert!(
            !status.realtime.watching,
            "a watcher that ended must not be reported as watching: {:?}",
            status.realtime
        );
        assert!(status.realtime.roots.is_empty());
        let reason = status
            .realtime
            .disabled_by
            .expect("a reason for having no protection");
        assert!(
            reason.contains("stopped on its own"),
            "the reason must not read as a stop somebody asked for: {reason}"
        );

        // And startable again, which is the half that a fix leaving the field
        // set would silently break.
        let again = host.set_realtime(true);
        assert!(
            again.watching,
            "realtime must be startable after the watcher ended: {again:?}"
        );
        assert_eq!(again.roots, vec![watched]);
    }

    #[test]
    fn only_a_confirmed_verdict_is_acted_on() {
        assert!(should_take(Verdict::Malicious));
        // The yellow band warns and never acts.
        assert!(!should_take(Verdict::Suspicious));
        // An unreadable file is not evidence of anything, and treating it as
        // grounds for removal would delete files because a lock was held.
        assert!(!should_take(Verdict::Unknown));
        assert!(!should_take(Verdict::Clean));
    }

    #[test]
    fn a_watcher_finding_never_claims_a_block() {
        let path = PathBuf::from("C:\\Users\\x\\Downloads\\payload.exe");
        let detection = detection_for_finding(
            &finding(path.clone(), Verdict::Malicious, Severity::High),
            DetectionAction::Reported,
        );
        assert_eq!(detection.path, path);
        assert_eq!(detection.file_name, "payload.exe");
        assert!(!detection.claims_a_block());
        assert_eq!(detection.phase.as_str(), "after-the-fact");
        assert_eq!(detection.source, EntrySource::Realtime);
        // The score is the severity's own, because the finding carries no
        // accumulated one and a zero beside a malicious file is a lie of a
        // different kind.
        assert_eq!(detection.score, Severity::High.default_score());
        assert!(detection.score > 0);
        assert_eq!(detection.rules, vec!["Test_Finds_Marker".to_string()]);
    }

    #[test]
    fn the_two_derivations_of_a_phase_agree() {
        // `av-ipc` derives the phase from the source and whether anything was
        // stopped; `av-realtime` derives it from the same two facts its own
        // way. If they ever disagree, one of the two is claiming a block that
        // did not happen, and this test is where that is caught.
        let theirs = av_realtime::Phase::observed(EntrySource::Realtime, false);
        let ours = Phase::observed(EntrySource::Realtime, false);
        assert_eq!(theirs.as_str(), ours.as_str());
        assert!(!theirs.claims_a_block());
        assert!(!ours.claims_a_block());

        // And the derivation is not vacuous: a source that *is* pre-execution
        // classed and did block lands on the other word.
        let blocked = Phase::observed(EntrySource::Driver, true);
        assert!(blocked.claims_a_block());
        assert_eq!(blocked.as_str(), "pre-execution");
        // While the same source that blocked nothing does not.
        assert!(!Phase::observed(EntrySource::Driver, false).claims_a_block());
    }

    #[test]
    fn a_finding_the_watcher_already_acted_on_is_not_acted_on_twice() {
        let mut decided = finding(
            PathBuf::from("C:\\x\\payload.exe"),
            Verdict::Malicious,
            Severity::High,
        );
        assert!(already_decided(&decided).is_none());

        let id = QuarantineId::new();
        decided.quarantined = Some(id);
        assert_eq!(
            already_decided(&decided),
            Some(DetectionAction::Quarantined { id })
        );

        // A failure is carried through too: re-attempting the quarantine would
        // lose the reason the first one gave.
        decided.quarantined = None;
        decided.quarantine_error = Some("the vault is full".to_string());
        match already_decided(&decided) {
            Some(DetectionAction::QuarantineFailed { reason }) => {
                assert_eq!(reason, "the vault is full")
            }
            other => panic!("expected the watcher's own failure, got {other:?}"),
        }
    }

    #[test]
    fn the_context_for_a_finding_says_how_the_file_was_taken() {
        let context = context_for_finding(&finding(
            PathBuf::from("C:\\x\\payload.exe"),
            Verdict::Malicious,
            Severity::Critical,
        ));
        assert_eq!(context.source, EntrySource::Realtime);
        assert_eq!(context.verdict, Verdict::Malicious);
        assert_eq!(context.severity, Severity::Critical);
        assert_eq!(context.detection.as_deref(), Some("Test_Finds_Marker"));
        assert!(context.remove_original);
        let note = context.note.expect("a note");
        assert!(
            note.contains("not") && note.contains("stopped"),
            "the note has to record that nothing was blocked: {note}"
        );
    }

    #[test]
    fn draining_with_nothing_running_yields_nothing() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        assert!(host.drain().is_empty());
        assert!(host.drain().is_empty());
    }

    #[test]
    fn a_console_host_never_takes_the_drivers_port_from_the_service_that_owns_it() {
        // The fault: a test, or any other console run of the service, connects
        // to the port the *installed* service is connected to. The driver keeps
        // one client, so the machine's real service would be left holding a port
        // that answers nothing while a process that exits in a second holds the
        // connection — protection off on a machine somebody is using, and no
        // error anywhere. `Host::open_with` exists for exactly this and this is
        // the test that fails if someone makes it start the client too.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        assert!(
            host.filter_port.is_none(),
            "a host built with `open_with` connected to the driver's port"
        );
        assert!(host.driver_out.is_none());
        assert!(host.drain().is_empty());
        // And the real entry point is the one that asks: `Host::open` is not
        // called here, so what this asserts is only the split — `open` calls
        // `start_driver_port`, and the wiring of that call is in `open`, not in
        // the constructor both paths share.
    }

    #[test]
    fn an_event_the_driver_port_produced_reaches_a_client_through_drain() {
        // The fault: the client's channel exists and nothing reads it. Every
        // connection transition the driver's port observes would be produced,
        // queued and never delivered, so a user interface would show a machine
        // that is protected for as long as the process runs and would have no
        // way to see the moment it stopped being. The event is built by
        // `filter_port`'s own constructor rather than by hand, so this test
        // breaks if that function is renamed or changed rather than agreeing
        // with a copy of it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        let (sender, receiver) = crossbeam_channel::unbounded::<Event>();
        host.driver_out = Some(receiver);

        let connected = crate::filter_port::connection_event(true, r"\WenleAvFilterPort");
        sender.send(Event::Driver(connected.clone())).expect("queued");

        let drained = host.drain();
        match drained.as_slice() {
            [Event::Driver(event)] => {
                assert_eq!(event.action, av_ipc::DriverEventAction::StateChanged);
                assert_eq!(event.subject, av_ipc::DriverSubject::Driver);
                assert_eq!(event.detail, 1, "connected is the nonzero detail");
                let state = event.driver_state.as_ref().expect("a state");
                assert_eq!(state.presence, av_ipc::DriverPresence::Loaded);
                assert!(state.detail.contains("connected"));
            }
            other => panic!("expected the connection event, got {other:?}"),
        }
        assert!(
            host.drain().is_empty(),
            "`drain` took the event twice: it is a drain, not a buffer"
        );

        // The other direction, which is the one a user notices: the same
        // constructor called with `false` says the machine is deciding nothing.
        let lost = crate::filter_port::connection_event(false, r"\WenleAvFilterPort");
        sender.send(Event::Driver(lost)).expect("queued");
        let drained = host.drain();
        match drained.as_slice() {
            [Event::Driver(event)] => {
                assert_eq!(event.detail, 0);
                let state = event.driver_state.as_ref().expect("a state");
                assert_eq!(
                    state.presence,
                    av_ipc::DriverPresence::Unknown,
                    "a lost connection is not proof the driver is gone"
                );
            }
            other => panic!("expected the disconnection event, got {other:?}"),
        }
    }

    #[test]
    fn the_configuration_sent_to_the_driver_follows_the_settings_that_ask_for_it() {
        // What this pins is the mapping between a user's configuration and the
        // one message the driver is armed with. Every case here is a way to ask
        // for *less* protection, and each of them has to actually reduce what is
        // sent — a mapping that only ever set both bits would look right in the
        // default case and be wrong in all four of the others.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);

        // The default: both defences, over the install directory.
        let sent = host.driver_configuration();
        assert!(sent.protect_handles(), "self-protection is on by default");
        assert!(sent.gate_writes(), "protecting our own files is on by default");
        let expected: Vec<u16> = host
            .paths()
            .install_dir
            .to_string_lossy()
            .encode_utf16()
            .collect();
        assert_eq!(sent.dir(), expected.as_slice());

        // `protection.enabled` is the master switch, and off must mean off.
        host.loaded.config.protection.enabled = false;
        let off = host.driver_configuration();
        assert!(!off.protect_handles(), "the master switch did not reach it");
        assert!(!off.gate_writes(), "the master switch did not reach it");
        host.loaded.config.protection.enabled = true;

        // The driver's own half of the file question. Turning it off leaves the
        // handle callbacks alone: they are a different mechanism.
        host.loaded.config.driver.kernel_self_protection = false;
        let no_gate = host.driver_configuration();
        assert!(no_gate.protect_handles());
        assert!(
            !no_gate.gate_writes(),
            "`driver.kernel_self_protection` is off and the gate was armed anyway"
        );
        host.loaded.config.driver.kernel_self_protection = true;

        // And the other way round.
        host.loaded.config.protection.self_protection = false;
        let no_handles = host.driver_configuration();
        assert!(!no_handles.protect_handles());
        assert!(
            no_handles.gate_writes(),
            "turning off one protection turned off the other"
        );
        host.loaded.config.protection.self_protection = true;

        host.loaded.config.protection.protect_own_files = false;
        assert!(!host.driver_configuration().gate_writes());
    }

    #[test]
    fn a_build_tree_is_never_asked_to_refuse_writes_to_itself() {
        // The one layout where the write gate would break the machine it runs
        // on. On a build tree `install_dir` is the directory cargo writes into,
        // so arming the gate there would refuse cargo's own writes to
        // `wenle.exe` — and every later build would fail with an access denial
        // until the driver was reloaded. Measured in `wenle protect apply`, which
        // refuses the same tree for the same reason; the check is shared so the
        // two cannot disagree.
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").expect("a workspace root");
        let paths = AvPaths::with_data_dir(
            dir.path().join("target").join("debug"),
            dir.path().join("data"),
        );
        std::fs::create_dir_all(&paths.db_dir).expect("the database directory");
        let loaded = config::load(&paths);
        let engine = engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            crate::engine::CatalogStatus::default(),
        );
        let host = Host::open_with(paths, loaded, engine).expect("the vault opens");

        let sent = host.driver_configuration();
        assert!(
            !sent.gate_writes(),
            "the driver would have been armed against the directory cargo builds into"
        );
        assert!(
            sent.protect_handles(),
            "the handle callbacks are not a build-tree hazard and must still be asked for"
        );

        // The same directory with no `Cargo.toml` above it is not a build tree,
        // and the gate is armed — so the assertion above is about the workspace
        // and not about a directory merely being called `target`.
        std::fs::remove_file(dir.path().join("Cargo.toml")).expect("removed");
        assert!(host.driver_configuration().gate_writes());
    }

    #[test]
    fn a_configuration_the_driver_refused_is_reported_as_a_refusal() {
        // The status sentence, both directions. A driver that would not take the
        // configuration is defending nothing, and its answer must not read like
        // the one where the message was never sent — which is exactly what an
        // unreported refusal would look like.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        assert!(
            !host
                .status()
                .driver
                .detail
                .contains("applied the configuration"),
            "nothing has been sent, so nothing may be reported as applied"
        );

        const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Configuration,
                STATUS_INVALID_PARAMETER,
            )))
            .expect("queued");
        assert!(host.drain().is_empty(), "consumed, not published");
        let detail = host.status().driver.detail;
        assert!(
            detail.contains("REFUSED the configuration"),
            "the driver would not arm itself and the status does not say so: {detail}"
        );
        assert!(detail.contains("0xC000000D"), "{detail}");

        // The other value through the same path, so the sentence is not
        // unconditional.
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Configuration,
                0,
            )))
            .expect("queued");
        let _ = host.drain();
        let detail = host.status().driver.detail;
        assert!(detail.contains("applied the configuration"), "{detail}");
        assert!(!detail.contains("REFUSED"), "{detail}");
    }

    /// A driver event built the way `driver::translate` builds one.
    ///
    /// The two fields that are load-bearing are copied from that function
    /// deliberately: `driver_state` is `None`, because an `EventMessage` carries
    /// no status and `None` is what tells an event that came off the port apart
    /// from the service's own connection note (which always fills it), and the
    /// `sequence` is the driver's rather than zero.
    fn driver_report(
        action: DriverEventAction,
        subject: av_ipc::DriverSubject,
        detail: u32,
    ) -> av_ipc::DriverEvent {
        av_ipc::DriverEvent {
            sequence: 3,
            timestamp_100ns: 133_000_000_000_000_000,
            action,
            subject,
            path: None,
            process_id: 0,
            thread_id: 0,
            detail,
            driver_state: None,
        }
    }

    #[test]
    fn a_driver_that_could_not_register_process_notifications_says_so_in_the_status() {
        // The fault this test exists for: `PsSetCreateProcessNotifyRoutineEx`
        // fails, and nothing anywhere says so. Programs would start and be
        // reported by nobody, and a machine with no process notifications looks
        // exactly like a machine where nothing starts — the silence *is* the
        // problem. The driver sends the raw `NTSTATUS` once, when the service
        // connects, and this is where it is read.
        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);

        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Driver,
                STATUS_ACCESS_DENIED,
            )))
            .expect("queued");

        assert!(
            host.drain().is_empty(),
            "a bare driver state report is consumed rather than published: nothing in the product \
             renders one, and `Host::status` is where the fact it carries is read"
        );

        let detail = host.status().driver.detail;
        assert!(
            detail.contains("NOT registered"),
            "the driver could not register process notifications and the status does not say so: \
             {detail}"
        );
        assert!(
            detail.contains("0xC0000022"),
            "the exact NTSTATUS is the thing a reader looks up, and it is missing: {detail}"
        );

        // The other value, through the same path, so that this test cannot pass
        // by the sentence being unconditional.
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Driver,
                0,
            )))
            .expect("queued");
        let _ = host.drain();
        let detail = host.status().driver.detail;
        assert!(detail.contains("are registered"), "{detail}");
        assert!(!detail.contains("NOT registered"), "{detail}");
    }

    #[test]
    fn the_two_registrations_the_driver_reports_are_reported_separately() {
        // The defect this test exists for, stated as the defect: the driver
        // queues two `NTSTATUS` values at connect — one for
        // `PsSetCreateProcessNotifyRoutineEx`, one for `ObRegisterCallbacks` —
        // and the service stored whichever arrived in a single
        // `process_notify` slot. They would have overwritten each other, and
        // the surviving one would have been reported as the state of both
        // mechanisms. A machine whose object callbacks had failed would have
        // read as fully protected because process notifications succeeded.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);

        const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
        // The order matters and is the driver's: process notifications first,
        // then protection. The failing one is deliberately second, so a
        // single-slot implementation ends up claiming success.
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Driver,
                0,
            )))
            .expect("queued");
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Protection,
                STATUS_ACCESS_DENIED,
            )))
            .expect("queued");
        assert!(host.drain().is_empty(), "both are consumed, not published");

        let detail = host.status().driver.detail;
        assert!(
            detail.contains("process-start notifications are registered"),
            "the registration that succeeded is not reported: {detail}"
        );
        assert!(
            detail.contains("object callbacks are NOT registered"),
            "the registration that failed was overwritten by the one that succeeded, or is not \
             reported at all: {detail}"
        );
        assert!(
            detail.contains("0xC0000022"),
            "the exact NTSTATUS is what a reader looks up: {detail}"
        );
        // And the succeeded one must not be *denied* by the sentence about the
        // other mechanism, which is what a shared slot would produce in the
        // opposite order.
        assert!(
            !detail.contains("process-start notifications are NOT registered"),
            "a failure of the object callbacks was reported as a failure of process-start \
             notifications: {detail}"
        );

        // The other order, so the test cannot pass by the two sentences being
        // independent of which status they were handed.
        let (mut host, sender) = host_with_driver_channel(&dir);
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Protection,
                0,
            )))
            .expect("queued");
        sender
            .send(Event::Driver(driver_report(
                DriverEventAction::StateChanged,
                av_ipc::DriverSubject::Driver,
                STATUS_ACCESS_DENIED,
            )))
            .expect("queued");
        let _ = host.drain();
        let detail = host.status().driver.detail;
        assert!(
            detail.contains("object callbacks are registered"),
            "{detail}"
        );
        assert!(
            detail.contains("process-start notifications are NOT registered"),
            "{detail}"
        );
    }

    #[test]
    fn the_connection_to_the_port_is_what_makes_the_driver_count_as_loaded() {
        // `driver::check` opens `\\.\WenleAvFilter`, and this build's driver
        // creates no control device at all, so that call answers "absent" on a
        // machine where the filter is loaded and enforcing. Reporting that
        // answer by itself would be a false statement about a running driver.
        // The connection is the stronger fact — the port exists only because
        // `DriverEntry` ran `FltRegisterFilter` and then created it — so the
        // status is composed from the two and this test pins the composition.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        let device = crate::driver::check();

        let before = host.status().driver;
        assert_eq!(
            before.presence, device.presence,
            "with nothing connected the device's own answer is the answer"
        );
        assert!(
            before.detail.contains("not connected"),
            "and the sentence has to say which fact produced it: {}",
            before.detail
        );
        assert!(
            !before.detail.contains("is not loaded"),
            "having no connection is not evidence that the driver is not loaded: {}",
            before.detail
        );

        sender
            .send(Event::Driver(crate::filter_port::connection_event(
                true,
                r"\WenleAvFilterPort",
            )))
            .expect("queued");
        let _ = host.drain();

        let connected = host.status().driver;
        assert_eq!(
            connected.presence,
            DriverPresence::Loaded,
            "the service is connected to the driver's port and the status does not say the driver \
             is loaded"
        );
        assert!(
            connected.detail.contains("connected"),
            "the sentence has to say what was measured: {}",
            connected.detail
        );

        // And it goes back the other way: a dropped connection must not leave a
        // stale "loaded" standing, which is a machine that is unprotected
        // reporting itself as protected.
        sender
            .send(Event::Driver(crate::filter_port::connection_event(
                false,
                r"\WenleAvFilterPort",
            )))
            .expect("queued");
        let _ = host.drain();
        let lost = host.status().driver;
        assert_eq!(lost.presence, device.presence);
        assert!(lost.detail.contains("not connected"), "{}", lost.detail);
    }

    #[test]
    fn a_registered_process_notification_reads_as_registered_and_a_failure_does_not() {
        // The two sentences, on their own, because the status test above can
        // only see them through a composed string. The property being pinned is
        // that a failure never reads like an absence of activity: what a reader
        // must not be able to conclude from the failure case is "no program has
        // started".
        let ok = describe_process_notify(0);
        assert!(ok.contains("registered"), "{ok}");
        assert!(!ok.contains("NOT registered"), "{ok}");

        let failed = describe_process_notify(0xC000_0022u32 as i32);
        assert!(failed.contains("NOT registered"), "{failed}");
        assert!(failed.contains("0xC0000022"), "{failed}");
        assert!(
            failed.contains("not being reported"),
            "a failure has to say what it costs: {failed}"
        );
    }

    /// A driver's detection, as `filter_port` builds one.
    ///
    /// Built here rather than through [`Detection::from_report`] because there
    /// is no [`FileScanReport`] in this story: the report belonged to the filter
    /// port's thread and was dropped when it replied to the driver. The fields
    /// are the ones that crossed the channel.
    ///
    /// `blocked` is a parameter rather than `true`, because the port has built
    /// two kinds of driver detection since 2026-10-15: one from the section
    /// gate, which refuses, and one from the create gate, which cannot and
    /// reports instead. [`driver_detection`] is the first of those.
    fn driver_detection_with(path: PathBuf, verdict: Verdict, blocked: bool) -> Detection {
        Detection {
            file_name: file_name_of(&path),
            path,
            verdict,
            score: 100,
            severity: Severity::High,
            threat: None,
            rules: vec!["Test_Finds_Marker".to_string()],
            action: DetectionAction::Reported,
            source: EntrySource::Driver,
            size: 4096,
            at: Utc::now(),
            in_process: None,
            terminated: false,
            phase: Phase::observed(EntrySource::Driver, blocked),
        }
    }

    /// The driver's refusal, which is what nearly every caller of the helper
    /// above means.
    fn driver_detection(path: PathBuf, verdict: Verdict) -> Detection {
        driver_detection_with(path, verdict, true)
    }

    /// A host whose driver channel this test feeds by hand.
    fn host_with_driver_channel(dir: &tempfile::TempDir) -> (Host, crossbeam_channel::Sender<Event>) {
        let mut host = host(dir);
        let (sender, receiver) = crossbeam_channel::unbounded::<Event>();
        host.driver_out = Some(receiver);
        (host, sender)
    }

    #[test]
    fn the_context_for_a_drivers_block_says_the_file_never_ran() {
        // The three sources write three different notes, and they have to: the
        // vault entry is the only place the difference between "we stopped it"
        // and "we found it afterwards" is recorded, and a user reading the
        // quarantine list a week later has nothing else to go on.
        let context = context_for_detection(&driver_detection(
            PathBuf::from("C:\\Samples\\payload.exe"),
            Verdict::Malicious,
        ));
        assert_eq!(context.source, EntrySource::Driver);
        assert_eq!(context.verdict, Verdict::Malicious);
        assert_eq!(context.severity, Severity::High);
        assert_eq!(context.detection.as_deref(), Some("Test_Finds_Marker"));
        assert!(context.remove_original);
        let note = context.note.expect("a note");
        assert!(
            note.contains("refused") && note.contains("before it ran"),
            "the note has to record that the program never started: {note}"
        );
    }

    #[test]
    fn the_context_for_a_create_gate_conviction_says_the_program_may_have_run() {
        // The other driver detection, and the one that arrived on 2026-10-15:
        // the create gate cannot refuse, so it reports a conviction while the
        // file is allowed to open. The vault note is the only thing that
        // separates this from a refusal a week later, and the two sentences
        // have to be *opposite* rather than merely different — "no process was
        // allowed to execute it" is a claim this case cannot make.
        let refused = context_for_detection(&driver_detection_with(
            PathBuf::from("C:\\Samples\\payload.exe"),
            Verdict::Malicious,
            true,
        ));
        let reported = context_for_detection(&driver_detection_with(
            PathBuf::from("C:\\Samples\\payload.exe"),
            Verdict::Malicious,
            false,
        ));
        let refused = refused.note.expect("a note");
        let reported = reported.note.expect("a note");
        assert_ne!(
            refused, reported,
            "the two driver sources took the file in opposite ways, so one sentence cannot \
             describe both"
        );
        assert!(
            reported.contains("allowed"),
            "the note has to say the open was not refused: {reported}"
        );
        assert!(
            !reported.contains("no process was allowed"),
            "the program was allowed to run; this cannot be claimed of it: {reported}"
        );
        // The note is a record of *how* the file was taken, so it has to name
        // the mechanism rather than only deny the stronger claim.
        assert!(reported.contains("convicted"), "{reported}");
    }

    #[test]
    fn a_block_the_driver_reported_is_quarantined_by_the_service() {
        // The chain that makes the notification possible at all. The driver
        // refuses the file inside its own timeout and can do nothing else; the
        // filter port has no vault; so the block arrives here as a detection and
        // this — the control loop — takes the file through the one function that
        // writes to the vault. Without this the block happens and the user is
        // told nothing, which is indistinguishable from a program that would not
        // start.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"the engine would have to convict this, but a test cannot").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");

        match host.drain().as_slice() {
            [Event::Detection(detection)] => {
                match &detection.action {
                    DetectionAction::Quarantined { id } => {
                        // The vault really holds it, which is what the
                        // notification will say.
                        assert!(host.vault.get(*id).is_ok());
                    }
                    other => panic!("a file the driver refused was not taken: {other:?}"),
                }
                assert_eq!(detection.source, EntrySource::Driver);
                assert!(
                    detection.claims_a_block(),
                    "a refusal reported as after-the-fact would tell the user the program ran"
                );
            }
            other => panic!("expected the detection, got {other:?}"),
        }
        assert!(
            !target.is_file(),
            "the file the driver refused is still on disk"
        );
    }

    #[test]
    fn the_second_refusal_of_a_file_this_run_already_took_is_not_an_error() {
        // Measured in the test VM on 2026-10-01 at 11:24:33 and 11:24:34, twice
        // for the same path and the same path tag. The driver has two gates
        // that ask about the same execution — its `IRP_MJ_CREATE`
        // pre-operation and its acquire-for-section pre-operation — so one
        // convicted file produces two detections a moment apart. The first
        // takes the file and removes the original; the second arrives to find
        // nothing there, and used to be logged as `could not be quarantined:
        // read the size of failed ... os error 2`. That reads as a second
        // failure, and the guest console was read that way.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"asked about twice, taken once").expect("written");
        for _ in 0..2 {
            sender
                .send(Event::Detection(driver_detection(
                    target.clone(),
                    Verdict::Malicious,
                )))
                .expect("queued");
        }

        let mut ids = Vec::new();
        for event in host.drain() {
            match event {
                Event::Detection(detection) => match &detection.action {
                    DetectionAction::Quarantined { id } => ids.push(*id),
                    other => panic!("a refusal of a convicted file was not taken: {other:?}"),
                },
                other => panic!("expected detections, got {other:?}"),
            }
        }

        assert_eq!(ids.len(), 2, "both refusals have to be reported");
        assert_eq!(
            ids[0], ids[1],
            "the second refusal names the entry the first one made, rather than \
             inventing a second entry for a file that is already in the vault"
        );
        assert_eq!(
            host.vault.entries().len(),
            1,
            "one file was taken, so the vault holds one entry"
        );
        assert!(
            !target.is_file(),
            "the original is gone, which is what the second refusal found"
        );
    }

    #[test]
    fn a_file_the_driver_refused_is_remembered_as_a_reason_to_stop_its_process() {
        // The wiring, and the one that was missing until 2026-10-18: taking the
        // file and stopping the program are done by different threads, and this
        // is where the first tells the second. Without it the file is in the
        // vault and the process runs — measured in the guest on 2026-10-18, with
        // WannaCry.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"convicted by the driver's gate").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        host.drain();

        assert_eq!(
            host.convictions.verdict_for(&target),
            Some(Verdict::Malicious),
            "the process worker has no way to learn what the driver's gate convicted"
        );
    }

    #[test]
    fn a_conviction_is_remembered_even_when_the_vault_declines_to_take_the_file() {
        // The distinction this pins: what the worker acts on is
        // the *engine's verdict*, not the vault's success. A machine whose
        // vault is full or whose file is locked still has a malicious program
        // running, and `auto_quarantine = false` is the user saying "report it,
        // do not take it" — not "let it run".
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = false;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"convicted by the driver's gate").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        host.drain();

        assert_eq!(
            host.convictions.verdict_for(&target),
            Some(Verdict::Malicious),
            "the verdict is the reason to stop the process, and the vault's answer is a \
             different question"
        );
        assert!(
            target.is_file(),
            "the file was reported and not taken, which is what the setting asked for"
        );
    }

    #[test]
    fn a_file_this_run_took_but_could_not_delete_is_not_taken_a_second_time() {
        // Measured in the guest on 2026-10-13, Round C acceptance B: one
        // payload, mapped executable and writable by a process that held it
        // open with `FILE_SHARE_READ`, produced **two** vault entries
        // (`b437adee`, `f7eaecb7`) for the same 4.1 KB, both of which said the
        // original could not be deleted. The section-gate refusal takes the
        // file and the memory conviction takes the file it is attributed to;
        // the second of them found the original still there, and the vault —
        // which is right to take a file that is in front of it — made a second
        // entry for it.
        //
        // Two entries for one file is not two copies of anything: the list
        // shows the user the same file twice, clearing one leaves the other,
        // and the count of what this product holds is wrong twice over. So
        // `taken` answers *before* the vault is asked, and the identity of the
        // file on disk is what makes that answer safe.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("plant-payload.bin");
        std::fs::write(&target, b"the bytes a loader mapped").expect("written");

        // `FILE_SHARE_READ` alone: anyone may read it, nobody may delete it.
        // This is what the process that mapped the file holds, and it is what
        // forces the vault to leave the original in place.
        use std::os::windows::fs::OpenOptionsExt;

        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&target)
            .expect("the loader's handle");

        for _ in 0..2 {
            sender
                .send(Event::Detection(driver_detection(
                    target.clone(),
                    Verdict::Malicious,
                )))
                .expect("queued");
        }

        let mut ids = Vec::new();
        for event in host.drain() {
            match event {
                Event::Detection(detection) => match &detection.action {
                    DetectionAction::Quarantined { id } => ids.push(*id),
                    other => panic!("a refusal of a convicted file was not taken: {other:?}"),
                },
                other => panic!("expected detections, got {other:?}"),
            }
        }

        assert_eq!(ids.len(), 2, "both refusals have to be reported");
        assert_eq!(
            ids[0], ids[1],
            "the second refusal made a second entry for a file this run was already holding"
        );
        assert_eq!(
            host.vault.entries().len(),
            1,
            "one file was taken, so the vault holds one entry"
        );
        assert!(
            target.is_file(),
            "the original has to still be there: this is the shape where the deletion could not \
             be done, and a test where it could would not reach the code under test"
        );
        assert_eq!(
            host.vault.pending_removals().len(),
            1,
            "the deletion the vault had to defer is still owed, and `wenle quarantine maintain` \
             is what will finish it"
        );

        drop(held);
    }

    #[test]
    fn a_new_file_at_a_path_this_run_already_took_gets_its_own_entry() {
        // The other half of the rule, and the reason it is not simply "this
        // path has been seen": a path is a name, and a name can be reused. A
        // dropper that writes a second payload over the first would otherwise
        // be answered with the entry holding the *old* bytes — a list entry
        // saying the file is held while the new one sits on disk unheld.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.bin");
        std::fs::write(&target, b"the first payload").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        let first = match host.drain().as_slice() {
            [Event::Detection(detection)] => match &detection.action {
                DetectionAction::Quarantined { id } => *id,
                other => panic!("a file the driver refused was not taken: {other:?}"),
            },
            other => panic!("expected one detection, got {other:?}"),
        };
        assert!(!target.is_file(), "the first payload was taken");

        // Different bytes, and a different length, written at the same path by
        // whatever wrote the first one.
        std::fs::write(&target, b"the second payload, which is longer").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        let second = match host.drain().as_slice() {
            [Event::Detection(detection)] => match &detection.action {
                DetectionAction::Quarantined { id } => *id,
                other => panic!("the second file was not taken: {other:?}"),
            },
            other => panic!("expected one detection, got {other:?}"),
        };

        assert_ne!(
            first, second,
            "the second file was answered with the entry holding the first one's bytes"
        );
        assert_eq!(
            host.vault.entries().len(),
            2,
            "two files were taken, so the vault holds two entries"
        );
    }

    #[test]
    fn a_file_the_user_allowed_is_put_back_and_not_taken_again() {
        // The whole of what the user asked for on 2026-10-09, as one story: a
        // detection takes the file, the user presses *Allow permanently*, and the
        // product never takes that file again. Without this the feature is a
        // loop — restore, re-detect, restore — and the user's only way out would
        // be to switch the product off.
        //
        // The second detection is fed through the *driver* channel, which is the
        // path that has no allow check of its own: its gate decided before the
        // allow existed, and the detection was already on its way. That is the
        // race the check in `quarantine` is for, and a test that went through the
        // watcher instead would be testing a path that never had the hole.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"convicted, put back, and then left alone").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");

        let id = match host.drain().as_slice() {
            [Event::Detection(detection)] => match &detection.action {
                DetectionAction::Quarantined { id } => *id,
                other => panic!("a file the driver refused was not taken: {other:?}"),
            },
            other => panic!("expected one detection, got {other:?}"),
        };
        assert!(!target.is_file(), "the file was taken");

        // The decision the user makes in the window, reaching the service
        // through `Request::QuarantineAllow { permanent: true }`.
        match host.allow(id, true) {
            QuarantineChange::Allowed {
                id: allowed,
                path,
                lasting,
            } => {
                assert_eq!(allowed, id);
                assert_eq!(path, target);
                assert!(
                    lasting,
                    "a permanent allow has to reach the configuration, or the user is told the \
                     file is safe and finds it gone again after a restart"
                );
            }
            other => panic!("the file was not put back: {other:?}"),
        }
        assert!(target.is_file(), "the user asked for the file to be back");

        // And the configuration on disk, not only the copy in memory: this is
        // what makes the allow outlive the service.
        let written = AvConfig::load_or_default(&host.loaded.path).expect("the configuration reads");
        assert!(
            written.general.exclusions.contains(&target),
            "the exclusion was not written: {:?}",
            written.general.exclusions
        );

        // The detection that was already in flight.
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        match host.drain().as_slice() {
            [Event::Detection(detection)] => {
                assert!(
                    matches!(detection.action, DetectionAction::Reported),
                    "a file the user allowed was taken a second time: {:?}",
                    detection.action
                );
            }
            other => panic!("expected one detection, got {other:?}"),
        }
        assert!(
            target.is_file(),
            "the user allowed this file and it left the disk anyway"
        );
        assert!(
            host.vault.entries().iter().all(|entry| entry.id == id),
            "the second detection made a second vault entry"
        );
    }

    #[test]
    fn an_allow_keeps_the_settings_another_writer_saved_meanwhile() {
        // The `config.toml` two-writer defect, in the direction that loses the
        // user's data without saying anything. The window writes this file whole
        // when the user presses *Save* in its Settings tab and does not tell the
        // service; the service's copy is therefore as old as its own last write.
        // Appending the exclusion to *that* copy writes the document from before
        // the Save — so pressing *Allow permanently* would silently undo the
        // settings the user had just saved, and only the exclusion would survive.
        //
        // The sequence is the user's own: change a setting, save, then allow a
        // file. Nothing exotic is needed to reach it.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let threads_at_start = host.loaded.config.scanning.threads;
        let mut saved_by_the_window = host.loaded.config.clone();
        saved_by_the_window.scanning.threads = threads_at_start + 7;
        saved_by_the_window
            .save(&host.loaded.path)
            .expect("what the window writes when Save is pressed");
        assert_ne!(
            host.loaded.config.scanning.threads,
            saved_by_the_window.scanning.threads,
            "the test is only meaningful while the service's copy is the older one"
        );

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"taken, so that there is something to allow").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        let id = match host.drain().as_slice() {
            [Event::Detection(detection)] => match &detection.action {
                DetectionAction::Quarantined { id } => *id,
                other => panic!("the file was not taken: {other:?}"),
            },
            other => panic!("expected one detection, got {other:?}"),
        };

        match host.allow(id, true) {
            QuarantineChange::Allowed { lasting, .. } => {
                assert!(lasting, "the exclusion did not reach the file");
            }
            other => panic!("the file was not allowed: {other:?}"),
        }

        let written = AvConfig::load_or_default(&host.loaded.path).expect("the configuration reads");
        assert!(
            written.general.exclusions.contains(&target),
            "the exclusion the user asked for is not in the file: {:?}",
            written.general.exclusions
        );
        assert_eq!(
            written.scanning.threads, saved_by_the_window.scanning.threads,
            "allowing a file wrote away a setting the user had saved, and nothing said so"
        );
    }

    #[test]
    fn a_quarantine_whose_delete_loses_a_race_is_retried_until_it_wins() {
        // Measured in the test VM on 2026-10-02 18:07:22, with the create gate
        // no longer refusing: `quarantined C:\Samples\block-test.exe but could
        // not delete it yet: 存取被拒。 (os error 5)`. The file was held open by
        // the process that had just opened it to run it — the driver refuses
        // the *section*, which is later than the open — so `DeleteFileW`, which
        // asks for DELETE, lost a race measured in milliseconds. Deleting it by
        // hand five seconds later worked, which is what says "race" and not
        // "lock".
        //
        // The handle here is held open on purpose, so the first attempt is
        // *forced* to fail: the file cannot be deleted while it is open, and
        // the only way it can be gone by the end of `drain` is a retry. The
        // vault's own events are what say which of the two happened, rather
        // than the test inferring it from the outcome.
        //
        // The holder is released by the test, not by a fixed sleep. A sleep
        // races the rest of the test: under load `drain` can reach its first
        // `DeleteFileW` *after* the sleep expires, which leaves the file free
        // and turns this into a test that proves nothing (observed once on
        // 2026-10-09, during a full-suite run). The listener below is on the
        // calling thread inside the vault, so it can hand the release over
        // while `drain` is still running — the one moment at which "the first
        // delete failed" is a fact rather than a hope.
        use std::os::windows::fs::OpenOptionsExt;
        use av_quarantine::events::QuarantineEvent;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"opened by whoever was about to run it").expect("written");

        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let recorder = std::sync::Arc::clone(&seen);
        let (release, may_close) = crossbeam_channel::bounded::<()>(1);
        host.vault.subscribe(std::sync::Arc::new(move |event: &QuarantineEvent| {
            let label = match event {
                QuarantineEvent::RemovalDeferred { .. } => "deferred",
                QuarantineEvent::RemovalCompleted { .. } => "completed",
                _ => return,
            };
            recorder.lock().expect("the recorder").push(label.to_owned());
            if label == "deferred" {
                // Unbounded in practice — the buffer is one — and the listener
                // must never block, because it runs inside `drain`.
                let _ = release.try_send(());
            }
        }));

        // `FILE_SHARE_READ` alone: anyone may read it, nobody may delete it.
        // Sharing nothing but read is what a loader's own open looks like from
        // our side of the delete.
        let (opened, is_open) = crossbeam_channel::bounded::<()>(1);
        let held = target.clone();
        let holder = std::thread::spawn(move || {
            let handle = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0x0000_0001)
                .open(&held)
                .expect("the test's handle");
            opened.send(()).expect("the handle is open");
            // The timeout is a liveness floor, not a delay: the release is
            // expected to arrive within the retry budget, and if the first
            // delete somehow succeeded there is nothing to wait for, so the
            // test fails on its own assertion instead of hanging here.
            let _ = may_close.recv_timeout(std::time::Duration::from_secs(10));
            drop(handle);
        });
        is_open.recv().expect("the file is open before the detection");

        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");

        match host.drain().as_slice() {
            [Event::Detection(detection)] => match &detection.action {
                DetectionAction::Quarantined { id } => {
                    assert!(host.vault.get(*id).is_ok(), "the bytes have to be held");
                }
                other => panic!("a file the driver refused was not taken: {other:?}"),
            },
            other => panic!("expected the detection, got {other:?}"),
        }
        holder.join().expect("the holder");

        let order = seen.lock().expect("the recorder").clone();
        assert_eq!(
            order,
            vec!["deferred".to_owned(), "completed".to_owned()],
            "the first delete has to have failed and a later one to have finished it — \
             `completed` alone would mean the handle never blocked anything and this test \
             proves nothing"
        );
        assert!(
            !target.is_file(),
            "the delete was forced to fail once, so this only passes if it was retried"
        );
        assert!(
            host.vault.pending_removals().is_empty(),
            "a successful retry has to clear the queue it was queued into"
        );
    }

    #[test]
    fn a_file_held_past_the_retry_window_is_left_queued_and_not_abandoned() {
        // The other half, and the reason the retry is bounded rather than run
        // from the 100 ms control tick: `max_removal_attempts` is 10, and a
        // tick that swept the queue would spend all ten in a second and then
        // *abandon* a file that was merely held a moment longer — clearing its
        // queue entry, so nothing would ever delete it again. Four attempts
        // over 750 ms fit inside the budget with room to spare.
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"held for longer than the window").expect("written");
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&target)
            .expect("the test's handle");

        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        let events = host.drain();

        assert!(
            matches!(
                events.as_slice(),
                [Event::Detection(d)] if matches!(d.action, DetectionAction::Quarantined { .. })
            ),
            "the vault really does hold the bytes, so the report is not a lie: {events:?}"
        );
        assert!(target.is_file(), "a handle held past the window keeps the file");

        let pending = host.vault.pending_removals();
        assert_eq!(pending.len(), 1, "the deletion has to stay queued");
        assert!(
            pending[0].attempts >= 2,
            "the retries have to have run and failed: {} attempt(s)",
            pending[0].attempts
        );
        assert!(
            pending[0].attempts <= 5,
            "four attempts are affordable; {} of a budget of 10 is not",
            pending[0].attempts
        );

        // And what a reboot or `wenle quarantine maintain` does, done here: the
        // queue is the recovery path, so releasing the handle has to finish it.
        drop(handle);
        host.win_the_removal_race(&target);
        assert!(!target.is_file(), "the queued deletion still has to work");
        assert!(host.vault.pending_removals().is_empty());
    }

    #[test]
    fn the_original_is_deleted_once_the_process_that_was_holding_it_is_stopped() {
        // Measured in the guest on 2026-10-18: the sample was convicted at its
        // section, the vault took its bytes — and the executable stayed exactly
        // where it was, which is why it could be started six times by hand.
        // Deleting a *running* image cannot work, and the only sweep of the
        // queue the vault keeps is `wenle quarantine maintain`. Stopping the
        // process is the moment the deletion becomes possible, and this is that
        // moment being used.
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"the process is running this").expect("written");
        // The handle a running image holds: read access, no share-delete.
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&target)
            .expect("the test's handle");

        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");
        let events = host.drain();
        assert!(
            matches!(
                events.as_slice(),
                [Event::Detection(d)] if matches!(d.action, DetectionAction::Quarantined { .. })
            ),
            "the premise is a file the vault took: {events:?}"
        );
        assert!(
            target.is_file(),
            "the premise is a deletion that could not happen yet, so this test needs the handle"
        );
        assert_eq!(host.vault.pending_removals().len(), 1);

        // The process ends — which is what the worker's stop does — and the
        // report of it arrives at the control thread.
        drop(handle);
        let mut report = watched(std::process::id(), Vec::new(), Stopped::Terminated);
        report.image = Some(target.clone());
        let mut out = Vec::new();
        host.absorb_memory(report, &mut out);

        assert!(
            !target.is_file(),
            "the deletion stayed queued after the process holding the file was stopped"
        );
        assert!(
            host.vault.pending_removals().is_empty(),
            "a successful retry has to clear the queue it was queued into"
        );
    }

    #[test]
    fn a_block_is_only_reported_when_the_configuration_says_not_to_act() {
        // `auto_quarantine` off has to mean that *nothing* is taken — including a
        // file the kernel stopped, which is the one case where a product might be
        // tempted to help. The block still happens, because blocking is the
        // driver's decision and not the vault's; what does not happen is the
        // vault write.
        //
        // The switch is set here rather than relied on. It used to be the shipped
        // default and this test used to read it, which made the test a claim
        // about the configuration rather than about the behaviour; the default is
        // now the other way (a detection is taken unless told otherwise), and a
        // test of "off" has to say "off" itself.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = false;

        let target = dir.path().join("payload.exe");
        std::fs::write(&target, b"left alone on purpose").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Malicious,
            )))
            .expect("queued");

        match host.drain().as_slice() {
            [Event::Detection(detection)] => {
                assert_eq!(detection.action, DetectionAction::Reported);
                // Still the truth about what happened: the driver did refuse it.
                assert!(detection.claims_a_block());
            }
            other => panic!("expected the detection, got {other:?}"),
        }
        assert!(
            target.is_file(),
            "with auto_quarantine off nothing may take a file"
        );
    }

    #[test]
    fn a_driver_detection_the_product_would_not_act_on_is_only_passed_through() {
        // The yellow band, arriving down the driver's channel. A verdict that
        // does not justify removal does not justify it here either, and the
        // verdict comes from the detection rather than from anything the driver
        // said — the driver only ever refuses what the engine called malicious,
        // and this is the check that keeps that from being load-bearing.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (mut host, sender) = host_with_driver_channel(&dir);
        host.loaded.config.quarantine.auto_quarantine = true;

        let target = dir.path().join("maybe.exe");
        std::fs::write(&target, b"a heuristic's opinion").expect("written");
        sender
            .send(Event::Detection(driver_detection(
                target.clone(),
                Verdict::Suspicious,
            )))
            .expect("queued");

        match host.drain().as_slice() {
            [Event::Detection(detection)] => {
                assert_eq!(detection.verdict, Verdict::Suspicious);
                assert_eq!(detection.action, DetectionAction::Reported);
            }
            other => panic!("expected the detection, got {other:?}"),
        }
        assert!(
            target.is_file(),
            "a suspicion is not grounds for removal, and the driver's channel is no exception"
        );
    }

    #[test]
    fn shutting_down_gives_the_drivers_port_up_and_leaves_nothing_queued() {
        // The fault: a client that outlives the service's shutdown. The driver
        // would keep a connection to a process that is going away, hold image
        // loads open against it, and get no answer until its own timeout — so
        // the last thing the service does is make the machine briefly slow to
        // open files. The port name is one that does not exist on any machine:
        // this must not reach a real driver even if the product is installed.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        let started = host.start_driver_port(r"\WenleAvNoSuchPortForATest");
        assert_eq!(
            started,
            cfg!(windows),
            "a build with the filter manager starts a thread; a build without it says so"
        );
        assert!(host.filter_port.is_some());
        assert!(host.driver_out.is_some());

        // Asking twice is not two clients. The driver keeps whichever connected
        // last, so a second one would leave the first holding a connection that
        // is no longer the driver's and a channel nobody drains.
        let again = host.start_driver_port(r"\WenleAvNoSuchPortForATest");
        assert_eq!(again, started);
        assert!(host.filter_port.is_some());

        host.shut_down();
        assert!(
            host.filter_port.is_none(),
            "the client outlived the shutdown"
        );
        assert!(host.driver_out.is_none());
        assert!(host.drain().is_empty());
        // Idempotent, because `Drop` calls it after the explicit paths do.
        host.shut_down();
        assert!(host.drain().is_empty());
    }

    #[test]
    fn a_scan_runs_to_a_summary_the_host_assembled() {
        // The whole chain in one test, without a service: the walker's thread,
        // the message pump, the summary and the counter. The files are in a
        // temporary directory and the rule matches one of them.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_matching(&dir, "WENLE-SCAN-MARKER");
        // Report-only, so that this test is about the summary chain and not
        // about the switch. The taken case is
        // `automatic_quarantine_takes_the_file_out_of_the_tree`, which sets the
        // same field the other way; this one names the switch rather than
        // reading whatever the default happens to be, which is what it used to
        // do and what would have made it a claim about the configuration.
        host.loaded.config.quarantine.auto_quarantine = false;
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("creates");
        std::fs::write(tree.join("clean.txt"), b"nothing to see").expect("writes");
        std::fs::write(tree.join("bad.bin"), b"WENLE-SCAN-MARKER").expect("writes");

        let (reply, _) = host.handle(&Request::ScanPath {
            path: tree.clone(),
            options: ScanOptions::default(),
        });
        let id = match reply {
            Reply::ScanStarted(ScanStart::Started { id, .. }) => id,
            other => panic!("expected a started scan, got {other:?}"),
        };
        assert_eq!(host.status().scans_running, 1);

        let events = run_to_finish(&mut host);
        let summary = events
            .iter()
            .find_map(|event| match event {
                Event::ScanFinished(finished) if finished.id == id => Some(&finished.summary),
                _ => None,
            })
            .expect("a scan that started finishes");

        assert_eq!(summary.files, 2, "both files were examined");
        assert_eq!(summary.detections, 1);
        assert_eq!(summary.results.len(), 1);
        assert_eq!(summary.results[0].file_name, "bad.bin");
        assert!(!summary.results[0].claims_a_block());
        // The verdict is the one that *would* be acted on if the configuration
        // asked for it. Without this the test would pass just as well on a
        // verdict the product is supposed to ignore, and would prove nothing
        // about the switch it is named for.
        assert_eq!(summary.results[0].verdict, Verdict::Malicious);
        assert!(should_take(summary.results[0].verdict));
        // `auto_quarantine` was turned off above, so the file was reported and
        // left where it was — and the summary says so rather than implying it
        // was handled.
        assert_eq!(summary.quarantined, 0);
        assert_eq!(summary.quarantine_failed, 0);
        assert_eq!(summary.results[0].action, DetectionAction::Reported);
        assert!(tree.join("bad.bin").is_file(), "the file is still there");

        // The scan is over and the counters agree.
        assert_eq!(host.status().scans_running, 0);
        assert_eq!(host.status().files_examined, 2);
        assert_eq!(host.status().quarantine_items, 0);
    }

    #[test]
    fn automatic_quarantine_takes_the_file_out_of_the_tree() {
        // The same chain with `quarantine.auto_quarantine` on: this is the one
        // test that proves the service acts, rather than only reporting, and
        // that it acts through the vault it owns.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_matching(&dir, "WENLE-SCAN-MARKER");
        host.loaded.config.quarantine.auto_quarantine = true;
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("creates");
        let bad = tree.join("bad.bin");
        std::fs::write(&bad, b"WENLE-SCAN-MARKER").expect("writes");

        let (reply, _) = host.handle(&Request::ScanPath {
            path: tree.clone(),
            options: ScanOptions::default(),
        });
        assert!(matches!(
            reply,
            Reply::ScanStarted(ScanStart::Started { .. })
        ));
        let events = run_to_finish(&mut host);
        let summary = events
            .iter()
            .find_map(|event| match event {
                Event::ScanFinished(finished) => Some(&finished.summary),
                _ => None,
            })
            .expect("a summary");
        assert_eq!(summary.detections, 1);
        assert_eq!(summary.quarantined, 1);
        assert_eq!(summary.quarantine_failed, 0);
        match &summary.results[0].action {
            DetectionAction::Quarantined { id } => {
                // The vault really holds it, under the identifier the
                // notification carried.
                assert!(host.vault.get(*id).is_ok());
            }
            other => panic!("expected a quarantine, got {other:?}"),
        }
        assert!(!bad.is_file(), "the original is gone");
        assert_eq!(host.status().quarantine_items, 1);
    }

    #[test]
    fn a_file_the_watcher_finds_is_taken_without_being_asked() {
        // The flow the product is for, on the default configuration and through
        // the real watcher rather than a hand-fed event: a file appears in a
        // watched directory, the engine convicts it, and it leaves the tree.
        //
        // The default is asserted rather than set. Round B (2026-10-09) made
        // `quarantine.auto_quarantine` true by default, which is the whole of
        // "detection puts the file in the vault"; a test that set the field
        // itself would go on passing after the default was put back, and the
        // default is what every machine that has never written a configuration
        // file actually gets.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_matching(&dir, "WENLE-SCAN-MARKER");
        assert!(
            host.loaded.config.quarantine.auto_quarantine,
            "a detected file has to be taken without the user asking; this is the default Round B \
             set, and turning it back off makes the product report and do nothing"
        );
        let plan = host.loaded.config.realtime.clone();
        assert!(
            plan.enabled && plan.filesystem_fallback,
            "the userspace watcher is the mechanism this test drives: {plan:?}"
        );
        host.loaded.config.realtime.watched_paths = vec![watched.clone()];
        let armed = host.start_realtime();
        assert!(
            armed.watching,
            "the watcher has to be armed for this test to mean anything: {armed:?}"
        );

        let bad = watched.join("dropped.bin");
        std::fs::write(&bad, b"WENLE-SCAN-MARKER").expect("writes");

        // Bounded, because the watcher is another thread and a test that waited
        // forever on a bug would hang the suite instead of failing it.
        match wait_for(&mut host, &bad, Duration::from_secs(10))
            .expect("the watcher never reported the file it was watching for")
        {
            DetectionAction::Quarantined { id } => {
                assert!(host.vault.get(id).is_ok(), "the vault does not hold it");
            }
            other => panic!("a convicted file was not taken: {other:?}"),
        }
        assert!(!bad.is_file(), "the file is still in the tree");
        assert_eq!(host.status().quarantine_items, 1);
    }

    #[test]
    fn the_watcher_leaves_alone_a_file_the_user_allowed() {
        // The other half of the same story, through the same real watcher: the
        // user presses *Allow* on what was just taken, the file comes back, and
        // the watcher stops seeing it. Without this the two halves of the
        // product disagree — the window says the file is allowed and the watcher
        // takes it again the moment it is written.
        //
        // The allow here is the session one (`permanent: false`), which is the
        // harder of the two for this path: it lives only in the running
        // service's `AllowList`, so it is the answer a *running* watcher has to
        // consult rather than something a restart would pick up.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let watched = dir.path().join("watched");
        std::fs::create_dir_all(&watched).expect("the watched directory");
        let mut host = host_matching(&dir, "WENLE-SCAN-MARKER");
        host.loaded.config.realtime.watched_paths = vec![watched.clone()];
        assert!(host.start_realtime().watching, "the watcher is armed");

        let allowed = watched.join("allowed.bin");
        std::fs::write(&allowed, b"WENLE-SCAN-MARKER").expect("writes");
        let id = match wait_for(&mut host, &allowed, Duration::from_secs(10)) {
            Some(DetectionAction::Quarantined { id }) => id,
            other => panic!("the file was not taken to begin with: {other:?}"),
        };

        match host.allow(id, false) {
            QuarantineChange::Allowed { path, lasting, .. } => {
                assert_eq!(path, allowed, "the wrong file was put back");
                assert!(
                    !lasting,
                    "a session allow must not reach the configuration: the window's *Allow for \
                     now* button would otherwise be permanent"
                );
            }
            other => panic!("the file was not put back: {other:?}"),
        }
        assert!(allowed.is_file(), "the user asked for it back");
        // Written again, which is the event that took it the first time.
        std::fs::write(&allowed, b"WENLE-SCAN-MARKER").expect("writes");

        // A second file, convicted by the same rule, planted after the allow.
        // This is what keeps the assertion below from passing for the wrong
        // reason: if the watcher had stopped working — or were not armed at all
        // — this file would stay put too, and "the allowed file was left alone"
        // would be true of a service that had stopped watching.
        let other = watched.join("other.bin");
        std::fs::write(&other, b"WENLE-SCAN-MARKER").expect("writes");
        match wait_for(&mut host, &other, Duration::from_secs(10)) {
            Some(DetectionAction::Quarantined { .. }) => {}
            other => panic!("the watcher is not convicting anything any more: {other:?}"),
        }

        assert!(
            allowed.is_file(),
            "a file the user allowed was taken again by the watcher"
        );
        assert_eq!(
            host.status().quarantine_items,
            2,
            "one item for the file that was taken, one for the second file — and none for the \
             file the user allowed"
        );
    }

    /// Drain until `path` is reported, or the deadline passes.
    ///
    /// The action, not the whole detection: every caller here is asking what was
    /// *done* about the file. `None` means no detection for that path arrived,
    /// which for an allowed path is the correct answer and is why this returns
    /// an `Option` rather than panicking.
    fn wait_for(
        host: &mut Host,
        path: &Path,
        within: Duration,
    ) -> Option<DetectionAction> {
        let deadline = Instant::now() + within;
        loop {
            for event in host.drain() {
                if let Event::Detection(detection) = event {
                    if detection.path == path {
                        return Some(detection.action);
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Drive the host until a scan finishes, or give up.
    ///
    /// A bounded loop rather than a join: the walker is detached on purpose,
    /// and a test that waited forever on a bug would hang the suite instead of
    /// failing it.
    fn run_to_finish(host: &mut Host) -> Vec<Event> {
        let mut collected = Vec::new();
        for _ in 0..2_000 {
            collected.extend(host.drain());
            if collected
                .iter()
                .any(|event| matches!(event, Event::ScanFinished(_)))
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        collected
    }

    /// A host with a process watcher armed over a real engine.
    ///
    /// The real watcher rather than a stand-in, and no processes are fed to it:
    /// what these tests are about is the host's half — when the watcher exists,
    /// what the setting gates, and what the host does with a `Watched` it is
    /// handed. The walking itself is tested in `crate::process_watch`.
    fn host_watching_processes(dir: &tempfile::TempDir, marker: &str) -> Host {
        let mut host = host_matching(dir, marker);
        host.start_process_watch();
        assert!(
            host.process_watch.is_some(),
            "the watcher has to exist for these tests to mean anything"
        );
        host
    }

    /// A process outcome, built by hand.
    ///
    /// The worker's answer without the worker: everything the host reads from it
    /// is here, and none of it requires a process to walk. That is what makes
    /// these tests deterministic — a real walk reads whatever happens to be
    /// resident and takes seconds.
    fn watched(pid: u32, findings: Vec<(MemoryFinding, memory::Ruling)>, stopped: Stopped) -> Watched {
        Watched {
            pid,
            process: format!("test-subject.exe ({pid})"),
            token: ProcessToken::of(pid),
            coverage: MemoryCoverage {
                regions_walked: 12,
                regions_examined: 3,
                bytes_read: 0x3000,
                regions_unreadable: 0,
                regions_over_budget: 0,
            },
            walk_complete: true,
            deadline_reached: false,
            refused: None,
            findings: findings
                .into_iter()
                .map(|(finding, ruling)| Judged { finding, ruling })
                .collect(),
            stopped,
            image: None,
        }
    }

    /// A finding attributed to `pid`, whose bytes came from `file`.
    ///
    /// Hand-built for the reason the module documentation gives: `av_memory`'s
    /// test source is not reachable from this crate, and every field of a
    /// [`MemoryFinding`] is public precisely so that a caller can state one. The
    /// shape is `av_memory`'s own file-origin fixture: a private, readable,
    /// writable and executable page — the shape of code copied into a process
    /// from somewhere — whose provenance the source named a file for. That last
    /// part is what the finding is *about*: the file is the thing worth dealing
    /// with, because terminating the process ends the incident only until the
    /// file runs again.
    fn memory_finding(pid: u32, file: &Path) -> MemoryFinding {
        MemoryFinding {
            process: av_memory::ProcessRef::new(pid, Some(PathBuf::from(r"C:\x\subject.exe"))),
            base: 0x0040_1000,
            region_size: 0x1000,
            bytes_read: 0x1000,
            truncated: false,
            interest: av_memory::Interest::UnbackedCode,
            protection: av_memory::Protection::from_raw(0x40),
            kind: av_memory::RegionKind::Private,
            origin: av_memory::Origin::File {
                path: file.to_path_buf(),
            },
            verdict: Verdict::Malicious,
            score: 100,
            detections: Vec::new(),
        }
    }

    #[test]
    fn what_a_watched_process_held_is_taken_and_reported_as_memory() {
        // The end of the path C2 exists for: the worker walks a process, and the
        // *host* — the only writer of the vault — takes the file and publishes a
        // detection. The source is `Memory` and not the driver's: nobody refused
        // this file, it was found inside a running program, and a record that
        // said otherwise would claim an interception that never happened.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");
        host.loaded.config.quarantine.auto_quarantine = true;

        let file = dir.path().join("dropped.bin");
        std::fs::write(&file, b"WENLE-PROCESS-MARKER").expect("writes");
        let ruling = ruling_for(&host, &file);
        assert!(
            ruling.action.is_take(),
            "the fixture has to convict for this test to mean anything: {:?}",
            ruling.action
        );

        let mut out = Vec::new();
        host.absorb_memory(
            watched(
                4242,
                vec![(memory_finding(4242, &file), ruling)],
                Stopped::Terminated,
            ),
            &mut out,
        );

        match out.as_slice() {
            [Event::Detection(detection)] => {
                assert_eq!(detection.path, file);
                assert_eq!(detection.source, EntrySource::Memory);
                assert!(
                    detection.terminated,
                    "the process was stopped, and the record has to say so"
                );
                assert!(
                    !detection.claims_a_block(),
                    "a process that was already running was not blocked; claiming it was is the \
                     one thing the memory source is not allowed to say"
                );
                match &detection.action {
                    DetectionAction::Quarantined { id } => {
                        assert!(host.vault.get(*id).is_ok(), "the vault does not hold it");
                    }
                    other => panic!("a convicted file was not taken: {other:?}"),
                }
            }
            other => panic!("expected exactly one detection, got {other:?}"),
        }
        assert!(!file.is_file(), "the file is still on disk");
        assert_eq!(host.status().quarantine_items, 1);
    }

    #[test]
    fn a_process_that_held_nothing_publishes_nothing() {
        // Silence about a process that held nothing is the correct answer, and it
        // has to be silence rather than an empty detection: a client that saw one
        // would have something to display about a process that is entirely
        // ordinary.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");
        let mut out = Vec::new();
        host.absorb_memory(
            watched(4243, Vec::new(), Stopped::NotAttempted {
                why: "realtime.terminate_malicious_process is off".to_string(),
            }),
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(host.status().quarantine_items, 0);
    }

    #[test]
    fn a_process_that_was_never_examined_publishes_nothing() {
        // A refusal is a gap in coverage and it is counted by the worker; what it
        // must not become is a detection, because there was no finding to report.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");
        let mut refusal = watched(4244, Vec::new(), Stopped::NotAttempted {
            why: "the process was not examined".to_string(),
        });
        refusal.refused = Some("Access is denied.".to_string());
        refusal.walk_complete = false;

        let mut out = Vec::new();
        host.absorb_memory(refusal, &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(host.status().quarantine_items, 0);
    }

    #[test]
    fn a_process_left_running_is_reported_without_claiming_it_was_stopped() {
        // The flag is a fact about the process, not about the file, and it is
        // read once for every finding the process produced. A record that said
        // "terminated" on a run where termination was off would be the most
        // damaging kind of wrong: the user would believe a threat had been
        // stopped.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");
        host.loaded.config.quarantine.auto_quarantine = true;

        let file = dir.path().join("dropped.bin");
        std::fs::write(&file, b"WENLE-PROCESS-MARKER").expect("writes");
        let ruling = ruling_for(&host, &file);

        let mut out = Vec::new();
        host.absorb_memory(
            watched(
                4245,
                vec![(memory_finding(4245, &file), ruling)],
                Stopped::NotAttempted {
                    why: "realtime.terminate_malicious_process is off".to_string(),
                },
            ),
            &mut out,
        );

        match out.as_slice() {
            [Event::Detection(detection)] => {
                assert!(!detection.terminated, "no process was stopped");
                assert!(
                    matches!(detection.action, DetectionAction::Quarantined { .. }),
                    "the file is still taken regardless of what happened to the process: {:?}",
                    detection.action
                );
            }
            other => panic!("expected exactly one detection, got {other:?}"),
        }
        assert!(!file.is_file());
    }

    #[test]
    fn the_setting_is_what_decides_whether_a_start_reaches_the_worker() {
        // `realtime.scan_on_process_start` is read at routing time, because it is
        // not in `needs_restart`: a change made from the window has to take
        // effect on the next process that starts rather than at the next restart.
        // The idle process is used as the subject so that nothing is walked and
        // the answer is only about the gate.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");

        host.loaded.config.realtime.scan_on_process_start = false;
        host.note_process_start(0, None);
        assert_eq!(
            host.process_watch.as_ref().expect("the watcher").stats().starts,
            0,
            "a start must not reach the worker while the setting is off"
        );

        host.loaded.config.realtime.scan_on_process_start = true;
        host.note_process_start(0, None);
        assert_eq!(
            host.process_watch.as_ref().expect("the watcher").stats().starts,
            1,
            "the start has to be offered to the worker once the setting is on"
        );
        // And the worker really did receive it: the idle process is skipped by
        // identifier, before anything is opened.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if host
                .process_watch
                .as_ref()
                .expect("the watcher")
                .stats()
                .skipped_idle
                == 1
            {
                break;
            }
            assert!(Instant::now() < deadline, "the worker never saw the start");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_start_with_no_watcher_is_dropped_rather_than_held() {
        // The driver reports process creations whether or not the watcher is
        // running — protection can be paused from the window and the driver does
        // not know that. Holding them would mean a pause produces a burst of
        // walks the moment protection is turned back on, examining processes that
        // started while the user had said not to.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        assert!(host.process_watch.is_none());
        assert!(host.loaded.config.realtime.scan_on_process_start);
        // Nothing to assert on the counters — there is no watcher to count — so
        // what this asserts is that the call is not a panic and does not conjure
        // one. The dropped count that makes this honest is the driver's own.
        host.note_process_start(4246, None);
        assert!(host.process_watch.is_none());
    }

    #[test]
    fn the_watcher_exists_while_realtime_does_and_not_after() {
        // The lifecycle, and the one thing it would be easy to get wrong: the
        // process watcher's source is the *driver*, not the filesystem, so
        // `start_realtime` must arm it even on a machine with no watchable
        // directory. A plan with no roots returns early from the filesystem half,
        // and the process half must not be inside that return.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        host.loaded.config.realtime.watched_paths = Vec::new();
        assert!(host.process_watch.is_none());

        let _ = host.start_realtime();
        assert!(
            host.process_watch.is_some(),
            "a plan with no filesystem roots still has to arm the process watcher"
        );

        host.disarm_realtime();
        assert!(
            host.process_watch.is_none(),
            "the watcher's thread does not outlive the protection it belonged to"
        );
    }

    #[test]
    fn changing_the_setting_reaches_a_watcher_that_is_already_running() {
        // `realtime.terminate_malicious_process` is not in `needs_restart`, so
        // the disclosure table promises it takes effect live. A worker holding
        // the value it was started with would go on killing processes after the
        // user turned that off — which is the worst possible way for a setting to
        // be ignored.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host(&dir);
        host.loaded.config.realtime.scan_on_process_start = false;
        host.loaded.config.realtime.terminate_malicious_process = false;
        host.start_process_watch();
        let watch = host.process_watch.as_ref().expect("the watcher");
        assert!(
            !watch.is_terminating(),
            "the watcher starts with the configuration's answer"
        );

        let previous = host.loaded.config.clone();
        host.loaded.config.realtime.terminate_malicious_process = true;
        host.apply_live(&previous);
        assert!(
            host.process_watch
                .as_ref()
                .expect("the watcher")
                .is_terminating(),
            "a change made while the service runs has to reach the running worker"
        );
    }

    /// A host whose process watcher walks processes with an answer a test chose.
    ///
    /// The whole chain is real except the memory: the driver's channel, the
    /// routing, the worker's thread, its queue and its counters, and this host's
    /// vault. What a test supplies is what the walk of a process found — which is
    /// the one thing it cannot stage, because planting an injected page in a real
    /// process is not something a test suite can promise on every machine.
    fn host_with_process_scanner(
        dir: &tempfile::TempDir,
        marker: &str,
        scanner: Arc<dyn crate::process_watch::ProcessScanner>,
    ) -> (Host, crossbeam_channel::Sender<Event>) {
        let mut host = host_matching(dir, marker);
        let watch = ProcessWatch::start_with_scanner(
            Arc::clone(&host.engine.engine),
            host.paths.clone(),
            host.allow.clone(),
            engine::options_from(&host.loaded.config.scanning),
            true,
            host.convictions.clone(),
            scanner,
        )
        .expect("the watcher's thread starts");
        host.process_watch = Some(watch);
        let (sender, receiver) = crossbeam_channel::unbounded::<Event>();
        host.driver_out = Some(receiver);
        (host, sender)
    }

    /// A process-creation event, as the driver's own would be routed in.
    ///
    /// `driver_state` is `None`, which is what [`crate::driver::translate`]
    /// always leaves it as and what tells this apart from the port's own
    /// connection events.
    fn process_started_event(pid: u32, path: Option<PathBuf>) -> Event {
        Event::Driver(av_ipc::DriverEvent {
            sequence: 1,
            timestamp_100ns: 0,
            action: DriverEventAction::ProcessStarted,
            subject: av_ipc::DriverSubject::Process,
            path,
            process_id: pid,
            thread_id: 0,
            detail: 0,
            driver_state: None,
        })
    }

    /// Drain until a detection for `path` arrives, or the deadline passes.
    fn wait_for_detection(host: &mut Host, path: &Path, within: Duration) -> Option<Detection> {
        let deadline = Instant::now() + within;
        loop {
            for event in host.drain() {
                if let Event::Detection(detection) = event {
                    if detection.path == path {
                        return Some(detection);
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_process_the_driver_reported_starting_is_walked_and_its_file_is_taken() {
        // The whole of C2 in one test, with only the driver itself and the
        // memory read replaced: a process-creation event goes into the driver's
        // channel, the host routes it to the watcher, the worker walks it on its
        // own thread, the host — and only the host — takes the file, and a client
        // is told. A break anywhere in that chain leaves the file on disk and
        // this test failing.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("dropped.bin");
        std::fs::write(&file, b"WENLE-PROCESS-MARKER").expect("writes");

        let (mut host, sender) = host_with_process_scanner(
            &dir,
            "WENLE-PROCESS-MARKER",
            Arc::new(crate::process_watch::testing::FixedScanner::new({
                let file = file.clone();
                move |process, _deadline| {
                    let mut outcome =
                        av_memory::ProcessOutcome::new(process.clone());
                    outcome.findings = vec![memory_finding(process.pid, &file)];
                    outcome.regions_seen = 4;
                    outcome.regions_read = 1;
                    outcome.bytes_read = 0x1000;
                    av_memory::ProcessScan::Examined(Box::new(outcome))
                }
            })),
        );
        host.loaded.config.quarantine.auto_quarantine = true;
        assert!(host.loaded.config.realtime.scan_on_process_start);

        // A process the worker has never heard of terminating, so nothing is
        // killed: this test is about the file, and `crate::process_watch` tests
        // the termination against a process that exists.
        sender
            .send(process_started_event(0xFFFF_FF00, None))
            .expect("queued");

        let detection = wait_for_detection(&mut host, &file, Duration::from_secs(10))
            .expect("the process start never produced a detection");
        assert_eq!(detection.source, EntrySource::Memory);
        assert!(
            !detection.claims_a_block(),
            "the process had already started; nothing was blocked"
        );
        match &detection.action {
            DetectionAction::Quarantined { id } => {
                assert!(host.vault.get(*id).is_ok(), "the vault does not hold it");
            }
            other => panic!("a convicted file was not taken: {other:?}"),
        }
        assert!(!file.is_file(), "the file is still on disk");
        assert_eq!(host.status().quarantine_items, 1);

        let stats = host.process_watch.as_ref().expect("the watcher").stats();
        assert_eq!(stats.examined, 1);
        assert_eq!(stats.findings, 1);
    }

    #[test]
    fn a_start_the_worker_could_not_keep_up_with_is_disclosed_and_not_hidden() {
        // The queue is bounded, so a burst — a build, a browser starting — has to
        // shed starts. Shedding them silently would be a coverage gap the user
        // could not see, which is the one kind of gap this product must never
        // have; the count reaches the status through the same list a root that
        // could not be watched does.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let slow = Arc::new(crate::process_watch::testing::FixedScanner::new(
            |process, _deadline| {
                // Long enough that the queue behind it fills while the worker is
                // inside this one call.
                std::thread::sleep(Duration::from_millis(50));
                av_memory::ProcessScan::Refused {
                    process: process.clone(),
                    reason: av_memory::RefusalReason::Gone,
                }
            },
        ));
        let (mut host, _sender) = host_with_process_scanner(&dir, "WENLE-PROCESS-MARKER", slow);

        for pid in 1_000..1_000 + (crate::process_watch::MAX_PENDING_STARTS as u32 * 3) {
            host.note_process_start(pid, None);
        }
        let stats = host.process_watch.as_ref().expect("the watcher").stats();
        assert!(
            stats.dropped > 0,
            "a burst three times the queue's size must have shed something: {stats:?}"
        );

        let status = host.status();
        let disclosed = status
            .realtime
            .disclosures
            .iter()
            .find(|entry| entry.setting == "realtime.scan_on_process_start");
        match disclosed {
            Some(entry) => {
                assert!(
                    entry.reason.contains(&stats.dropped.to_string()),
                    "the disclosure has to carry the count it is about: {}",
                    entry.reason
                );
            }
            None => panic!(
                "{} dropped start(s) and the status says nothing: {:?}",
                stats.dropped, status.realtime.disclosures
            ),
        }
    }

    #[test]
    fn a_watcher_that_dropped_nothing_discloses_nothing() {
        // The other half: a machine keeping up reports no gap, which is what
        // makes the disclosure above mean something when it appears.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let host = host_watching_processes(&dir, "WENLE-PROCESS-MARKER");
        assert!(host.process_watch.as_ref().expect("the watcher").stats().dropped == 0);
        assert!(
            !host
                .status()
                .realtime
                .disclosures
                .iter()
                .any(|entry| entry.setting == "realtime.scan_on_process_start"),
            "nothing was dropped, so there is no gap to report"
        );
    }

    /// The ruling the engine reaches for `file`, on this host's configuration.
    ///
    /// Run rather than constructed, so that the fixture cannot state a ruling the
    /// engine would not reach: a hand-built `Take` whose report said something
    /// else would test the host against a decision no machine would ever make.
    fn ruling_for(host: &Host, file: &Path) -> memory::Ruling {
        let options = engine::options_from(&host.loaded.config.scanning);
        memory::rule_on(
            &av_memory::Origin::File {
                path: file.to_path_buf(),
            },
            &host.paths,
            &host.engine.engine,
            &options,
        )
    }

    // ---- the AMSI path's receiving end ------------------------------------
    //
    // `Host::scan_buffer` is what `av-amsi`'s provider reaches over the control
    // pipe when a script host is about to run a block of script. It is the only
    // scan in this service that acts on bytes with no file behind them, and the
    // three properties below are what make it safe to put that answer inside
    // somebody else's process:
    //
    //   * a conviction is reported and nothing is taken — there is no file,
    //   * the warning band is reported and *not* claimed as a block, because
    //     the notification and the verdict the provider returns have to be the
    //     same answer or the corner says "stopped" about a script that ran,
    //   * a clean buffer produces no event at all.
    //
    // Before these, nothing in the workspace had ever sent a
    // [`Request::ScanBuffer`]: every `av-amsi` test runs against a machine with
    // no service, which is the opposite case.

    #[test]
    fn a_convicted_script_block_is_reported_to_the_host_and_nothing_is_taken() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_matching(&dir, "WENLE-SCRIPT-MARKER");

        let script = b"Write-Host 'WENLE-SCRIPT-MARKER'";
        let (reply, events) = host.handle(&Request::ScanBuffer {
            name: "Script Block".to_string(),
            data: script.to_vec(),
        });

        let scan = match reply {
            Reply::BufferScan(scan) => scan,
            other => panic!("expected a buffer scan, got {other:?}"),
        };
        assert_eq!(scan.verdict, Verdict::Malicious, "{scan:?}");
        assert_eq!(scan.rules, vec!["Test_Finds_Marker".to_string()]);
        assert_eq!(scan.score, 100, "one High indicator is the whole score");
        // The name is a label and comes back as one. Nothing opened it.
        assert_eq!(scan.name, "Script Block");
        assert_eq!(scan.size, script.len() as u64);
        assert!(scan.error.is_none(), "{scan:?}");

        let [Event::Detection(detection)] = events.as_slice() else {
            panic!("expected exactly one detection, got {events:?}");
        };
        assert_eq!(detection.source, EntrySource::Amsi);
        assert_eq!(detection.verdict, Verdict::Malicious);
        // The provider is what refuses the script, so the *claim* is a block.
        assert!(detection.phase.claims_a_block(), "{detection:?}");
        // The action is not. This product moved no file, because there is no
        // file — a `Quarantined` here would name an entry the vault does not
        // have.
        assert!(
            matches!(detection.action, DetectionAction::Reported),
            "{detection:?}"
        );
        // And it is not a memory finding either: no process is in this story.
        assert!(detection.in_process.is_none(), "{detection:?}");
        assert!(!detection.terminated, "{detection:?}");

        // The vault was not touched. This is the property the method's own
        // documentation states, and the one a future "let us just quarantine
        // it" change would break without any other assertion noticing.
        let (reply, _) = host.handle(&Request::QuarantineList { limit: None });
        match reply {
            Reply::QuarantineList(listing) => assert_eq!(listing.total, 0),
            other => panic!("expected a listing, got {other:?}"),
        }
    }

    #[test]
    fn a_script_in_the_warning_band_is_reported_and_not_claimed_as_a_block() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        // No severity at all: the yellow band, where this product warns and
        // never acts. The whole point of the test is the disagreement that
        // would otherwise be possible between the notification and the answer.
        let mut host = host_with_rule(&dir, "WENLE-SCRIPT-MARKER", None);

        let (reply, events) = host.handle(&Request::ScanBuffer {
            name: "Script Block".to_string(),
            data: b"Write-Host 'WENLE-SCRIPT-MARKER'".to_vec(),
        });

        let scan = match reply {
            Reply::BufferScan(scan) => scan,
            other => panic!("expected a buffer scan, got {other:?}"),
        };
        // The band is asserted rather than assumed. If a later change made a
        // severity-less rule convict, this test would be measuring the wrong
        // thing and should say so here rather than three assertions later.
        assert_eq!(scan.verdict, Verdict::Suspicious, "{scan:?}");

        let [Event::Detection(detection)] = events.as_slice() else {
            panic!("expected exactly one detection, got {events:?}");
        };
        assert_eq!(detection.source, EntrySource::Amsi);
        // The user is told, because a script matching a rule is worth knowing
        // about...
        assert!(matches!(detection.action, DetectionAction::Reported), "{detection:?}");
        // ...and the record does not claim a block, because there was none: the
        // provider answered `NotDetected` for these bytes and the host ran them.
        assert!(!detection.phase.claims_a_block(), "{detection:?}");
        assert!(!detection.verdict.blocks(), "the band must not act");
    }

    #[test]
    fn clean_script_bytes_produce_no_event_at_all() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut host = host_matching(&dir, "WENLE-SCRIPT-MARKER");

        let (reply, events) = host.handle(&Request::ScanBuffer {
            name: "Script Block".to_string(),
            data: b"Get-ChildItem -Path C:\\".to_vec(),
        });

        match reply {
            Reply::BufferScan(scan) => {
                assert_eq!(scan.verdict, Verdict::Clean, "{scan:?}");
                assert!(scan.rules.is_empty(), "{scan:?}");
            }
            other => panic!("expected a buffer scan, got {other:?}"),
        }
        // Nothing was found, so nothing is published. This is the arm that
        // keeps every benign script block on the machine from producing a
        // notification.
        assert!(events.is_empty(), "{events:?}");
    }

    /// The line a convicted script block leaves in the service log.
    ///
    /// That line is not a convenience: it is the *only* record this product
    /// keeps of an AMSI conviction, because this path takes no file and so
    /// produces no vault entry for the window, the corner or `wenle quarantine
    /// list` to show. The check that the provider works reads this line out of
    /// `logs\service.log`, so its shape is a contract and not prose.
    ///
    /// Asserted by fragment rather than by whole string: what the check depends
    /// on is that the name, the verdict, the score and the firing rule are all
    /// present and that the two bands can be told apart. The exact punctuation
    /// is nobody's business, and a test that pinned it would fail on a wording
    /// change that broke nothing.
    #[test]
    fn the_line_a_convicted_script_leaves_names_the_rule_and_the_outcome() {
        let rules = vec!["TRELLIX_ARC_Malw_Eicar".to_string()];
        let refused = amsi_conviction_line("Script Block", Verdict::Malicious, 100, &rules);
        for fragment in [
            "Script Block",
            "malicious",
            "100",
            "TRELLIX_ARC_Malw_Eicar",
        ] {
            assert!(refused.contains(fragment), "{refused}");
        }
        assert!(refused.contains("refuse it"), "{refused}");

        // The other band. It must not read as a block: the middle band is where
        // this product warns and never acts, and the provider answers
        // `NotDetected` for it, so the host runs the script. A log line saying
        // otherwise would be the product claiming an action it did not take.
        let waved_through = amsi_conviction_line("Script Block", Verdict::Suspicious, 40, &rules);
        assert!(waved_through.contains("run it"), "{waved_through}");
        assert!(!waved_through.contains("refuse"), "{waved_through}");

        // A detection no rule can be named for still says something a person can
        // act on, rather than leaving a sentence ending in "from ".
        let anonymous = amsi_conviction_line("Script Block", Verdict::Malicious, 100, &[]);
        assert!(anonymous.contains("no rule named it"), "{anonymous}");
    }
}
