//! The service executable.
//!
//! # Four modes, and why the command line is parsed by hand
//!
//! The SCM runs this file with no arguments and expects it to become a service.
//! A person runs it with one of three flags and expects it to answer. There are
//! three flags and one absence, so the parser is fifteen lines and an
//! exhaustive match on `Mode`. A `clap` dependency would be a build-time and
//! review-surface cost for three flags, and the decisions worth testing (which
//! flag means which mode, and what happens when two are given) are tested here
//! without a parser generator in the way.
//!
//! | argument | what happens |
//! |---|---|
//! | *(none)* | [`scm::run`]: the real service, under the SCM |
//! | `--console` | the same machine, in the foreground, without the SCM |
//! | `--check` | read the configuration and the rule database, print what was found, exit |
//! | `--version`, `--help` | print, exit |
//!
//! # Why `--console` exists
//!
//! Because the service cannot be installed here: `sc create` needs
//! administrator rights and a machine nobody is using. Without a foreground
//! mode, the only way to run this code is on a machine that has given it
//! `LocalSystem` and a registry entry, which is to say never in this workspace.
//! With it, the whole machine (the vault, the scanner, the watcher, the control
//! pipe) can be exercised by a person who typed one word, and a
//! developer's build is not worse than a user's installation.
//!
//! What it does *not* do is pretend to be a service. There is no control
//! handler, so there is no stop flag to set, so `Ctrl-C` ends the process
//! rather than asking it to stop. Nothing is lost by that: the vault rewrites
//! its index on every change, so there is no in-memory state a kill discards,
//! and the single-instance lock is a file handle the kernel closes when the
//! process ends. A console control handler would need the `Win32_System_Console`
//! feature, and pulling a new feature into the `windows` crate recompiles it
//! for every crate in this workspace, which is a real cost paid by five other
//! people's builds for a debug convenience.
//!
//! # Why the log is a file
//!
//! A service has no console. `Stdio` is not connected, so anything written to
//! it goes nowhere at all, and a service that logs to nowhere is a service that
//! cannot be debugged: the SCM's only visible output is an exit code.
//! `%ProgramData%\WenleAV\logs\service.log` is where a person can look. In
//! `--console` mode the same lines are mirrored to stderr, because there a
//! person *is* watching, and looking at a file to see what just happened is
//! absurd.
//!
//! The event log would be the Windows-native answer, and it is not taken:
//! `ReportEventW` needs the `Win32_System_EventLog` feature and a registered
//! event source in the registry, which is installed by the same
//! administrator-only step this build cannot perform. A file in the product's
//! own directory works on every machine, installed or not.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use av_core::paths::AvPaths;
use av_ipc::DriverStatus;
use av_service::engine::Engine;
use av_service::{config, control, driver, engine, scm, single, ServiceError};

/// The system allocator, with a report written when it refuses a request.
///
/// A service that dies of an out-of-memory abort looks, from the SCM and from
/// the user, exactly like a service that was stopped — no error, no exit
/// reason, no log line. This writes one first. See [`av_core::alloc`].
#[global_allocator]
static ALLOCATOR: av_core::alloc::Reporting = av_core::alloc::Reporting;

/// The run did what it was asked.
const EXIT_OK: u8 = 0;

/// The run failed. What failed is in the log.
const EXIT_FAILED: u8 = 1;

/// The command line has no meaning: an unknown flag, or two modes at once.
const EXIT_USAGE: u8 = 2;

/// Another instance of this service already holds the lock.
///
/// Distinct from [`EXIT_FAILED`] because it is not a failure: the guard is
/// doing its job, the running service is serving the user, and a script that
/// started this one should be able to tell "already protected" from "would not
/// start".
const EXIT_ALREADY_RUNNING: u8 = 3;

/// What the command line asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Run under the Service Control Manager.
    Service,
    /// Run the same machine in the foreground.
    Console,
    /// Report what this installation has, then exit.
    Check,
    /// Print the version.
    Version,
    /// Print the usage.
    Help,
}

/// The usage text, which is also the only documentation a user gets.
const USAGE: &str = "\
wenle-av-service - the Wenle AV background service

USAGE:
    wenle-av-service                 run as a Windows service (the SCM starts it this way)
    wenle-av-service --console       run in the foreground, without the SCM
    wenle-av-service --check         report the configuration, the driver and the rule database
    wenle-av-service --version       print the version
    wenle-av-service --help          print this

Running with no arguments outside the Service Control Manager fails with
error 1063, which is what it means: this is a service, and only the SCM knows
how to start one. Use --console to run it by hand.";

/// Read the mode out of the arguments.
///
/// Two modes at once is an error rather than a precedence rule. `--check
/// --console` has no meaning — one prints and exits, the other runs forever —
/// and picking a winner would be this function inventing a meaning for
/// something the user did not say.
fn parse(args: &[String]) -> Result<Mode, String> {
    let mut mode: Option<Mode> = None;
    for arg in args {
        let wanted = match arg.as_str() {
            "--console" => Mode::Console,
            "--check" => Mode::Check,
            "--version" | "-V" => Mode::Version,
            "--help" | "-h" => Mode::Help,
            other => return Err(format!("`{other}` is not an argument this program takes")),
        };
        mode = match (mode, wanted) {
            // Help is the one exception, and only because it is the one a user
            // reaches for when they have already got something else wrong:
            // `--console --help` asking what `--console` means should answer.
            // Both orderings of that are one arm, because a user who typed two
            // things and meant the second is the same user either way — and
            // `--help --console` is somebody who typed an extra flag while
            // looking at the usage text, which is not worth an error.
            (_, Mode::Help) | (Some(Mode::Help), _) => Some(Mode::Help),
            (Some(previous), _) => {
                return Err(format!(
                    "{} and {arg} cannot both be given",
                    name_of(previous)
                ))
            }
            (None, _) => Some(wanted),
        };
    }
    Ok(mode.unwrap_or(Mode::Service))
}

/// A mode's flag, for an error message about it.
const fn name_of(mode: Mode) -> &'static str {
    match mode {
        Mode::Service => "the default",
        Mode::Console => "--console",
        Mode::Check => "--check",
        Mode::Version => "--version",
        Mode::Help => "--help",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();

    let mode = match parse(&args) {
        Ok(mode) => mode,
        Err(message) => {
            // These three modes exist to talk to a person, who has a console.
            // The service mode writes nothing to stdout at all — see this
            // module's documentation on where its log goes.
            eprintln!("wenle-av-service: {message}");
            eprintln!();
            eprintln!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let outcome = match mode {
        Mode::Help => {
            println!("{USAGE}");
            Ok(EXIT_OK)
        }
        Mode::Version => {
            println!("wenle-av-service {}", env!("CARGO_PKG_VERSION"));
            Ok(EXIT_OK)
        }
        Mode::Service => run_service(),
        Mode::Console => run_console(),
        Mode::Check => run_check(),
    };

    match outcome {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            // Logged and printed, because the two audiences are different: the
            // log survives the process, and stderr is what the person who just
            // typed the command is looking at.
            log::error!("{error}");
            eprintln!("wenle-av-service: {error}");
            ExitCode::from(exit_code_for(&error))
        }
    }
}

/// The exit code a failure deserves.
fn exit_code_for(error: &ServiceError) -> u8 {
    if matches!(error, ServiceError::AlreadyRunning { .. }) {
        EXIT_ALREADY_RUNNING
    } else {
        EXIT_FAILED
    }
}

/// Where everything lives, for the executable that is running.
///
/// Also the one place the allocation-failure log is armed, because it is the
/// one place every mode passes through *after* the directories exist. A service
/// has no console and the SCM's only visible output is an exit code, so a scan
/// that exhausts memory and aborts would otherwise leave nothing at all behind
/// — the process would simply stop being there.
fn paths_for_this_exe() -> Result<AvPaths, ServiceError> {
    let paths =
        AvPaths::for_current_exe().map_err(|error| ServiceError::Other(error.to_string()))?;
    paths
        .ensure_dirs()
        .map_err(|error| ServiceError::Other(error.to_string()))?;
    // Reported and not fatal, for the reason `start_logging` gives below: a
    // service that would not run because it could not open a diagnostic file
    // leaves the machine unprotected to protect a diagnostic.
    if let Err(error) = av_core::set_crash_log(paths.log_dir.join("crash.log")) {
        eprintln!("wenle-av-service: no crash log: {error}");
    }
    Ok(paths)
}

/// Start the log, and say so on stderr when there is one to say it on.
///
/// A failure here is reported and not fatal. The reasoning is
/// [`av_service::engine`]'s, one layer down: a service that refused to start
/// because it could not open a log file would leave the machine unprotected in
/// order to protect a diagnostic, which is the wrong way round.
fn start_logging(paths: &AvPaths, mirror_stderr: bool) {
    if let Err(error) = logging::init(&paths.log_dir, mirror_stderr) {
        // `mirror_stderr` is exactly the "is anybody listening" question here.
        if mirror_stderr {
            eprintln!(
                "wenle-av-service: the log at {} could not be opened: {error}",
                paths.log_dir.display()
            );
        }
    }
}

/// Run under the Service Control Manager.
///
/// The order matters, and each step is placed against the one it could damage:
/// the log is opened first, so that a second instance's refusal is written
/// *somewhere* rather than only to a console the SCM never gave it; the guard
/// next, so that a second instance exits before it touches the vault — and, in
/// the same step, before it can rotate the owner's log out from under it, which
/// is `logging::rotate` and the reason that is not part of opening the log; the
/// configuration third, so that a mistyped key is reported through
/// [`config::report`] rather than silently defaulted; the SCM last, because
/// entering it is the point of no return.
fn run_service() -> Result<u8, ServiceError> {
    let paths = paths_for_this_exe()?;
    start_logging(&paths, false);
    let _guard = single::InstanceGuard::acquire(&paths.data_dir)?;
    // Only now: see the order note above, and `logging::rotate`.
    logging::rotate(&paths.log_dir);
    let loaded = config::load(&paths);
    announce(&loaded);

    match scm::run(paths, loaded) {
        Ok(()) => Ok(EXIT_OK),
        Err(error) if scm::not_started_by_the_scm(&error) => Err(ServiceError::Usage(
            "this program is a service, and only the Service Control Manager can start one. \
             To run it by hand, use --console."
                .to_string(),
        )),
        Err(error) => Err(error),
    }
}

/// Run the same machine in the foreground.
fn run_console() -> Result<u8, ServiceError> {
    let paths = paths_for_this_exe()?;
    start_logging(&paths, true);
    let _guard = single::InstanceGuard::acquire(&paths.data_dir)?;
    // After the guard, for the reason `run_service`'s own note gives: this is
    // the process that would otherwise rotate a running service's log away.
    logging::rotate(&paths.log_dir);
    let loaded = config::load(&paths);
    announce(&loaded);

    let host = av_service::host::Host::open(paths, loaded)?;
    log::info!("running in the foreground; Ctrl-C ends the process");

    // Nothing ever sets this, and that is the documented consequence of
    // running without a control handler: see this module's documentation.
    let stop = AtomicBool::new(false);
    let mut host = control::serve(host, &stop)?;
    host.shut_down();
    Ok(EXIT_OK)
}

/// Report the configuration and everything this build does not do with it.
///
/// The lists are the point. A service that started quietly with a `config.toml`
/// full of keys nothing reads would be a service whose user believes in
/// protections that are not there.
fn announce(loaded: &config::LoadedConfig) {
    if let Some(error) = &loaded.load_error {
        log::error!(
            "{} was not usable, so the built-in defaults are in force: {error}",
            loaded.path.display()
        );
    } else {
        log::info!("configuration read from {}", loaded.path.display());
    }
    let report = config::report(loaded);
    // The two lists `report` folds together are not the same fact, and at
    // start-up they are nearly opposite: the keys that wait for a restart are
    // the ones this process is about to read — `Host::open` is the next call —
    // and announcing those as "not acted on" told a user their engine settings
    // were ignored in the same breath as the engine being built from them.
    // Eleven of them, under a warning, on every start-up, measured 2026-10-10.
    let (ignored, read_here) = config::start_up(&report);
    for setting in ignored {
        log::warn!(
            "{} is stored and not acted on: {}",
            setting.setting,
            setting.reason
        );
    }
    for setting in read_here {
        log::debug!(
            "{} is read at start-up, and this is the start-up that reads it: {}",
            setting.setting,
            setting.reason
        );
    }
    for setting in &report.handled_elsewhere {
        log::info!(
            "{} is handled by something other than this service: {}",
            setting.setting,
            setting.reason
        );
    }
}

/// What a `--check` found, and whether the installation can detect anything.
#[derive(Debug)]
struct CheckOutcome {
    /// What to print.
    text: String,
    /// False when this installation can detect nothing at all.
    healthy: bool,
}

/// Report the configuration, the driver and the rule database.
///
/// The catalog index is built, which [`av_service::engine::build_catalog`]
/// documents as 1.2 GB of reads through the cache directory the layout names.
/// Reading the store is the right trade here: `--check` is a diagnostic a person
/// typed, its whole purpose is to say whether the trust layer has evidence, and
/// a version of it that skipped the store to be fast would answer "no catalogs"
/// about a store it never read — which is exactly the confusion
/// [`av_service::engine::CatalogStatus::is_empty`] exists to avoid. Reading it
/// *through the cache* is the other half, and it is why this is fast enough to
/// be worth typing.
fn run_check() -> Result<u8, ServiceError> {
    let paths =
        AvPaths::for_current_exe().map_err(|error| ServiceError::Other(error.to_string()))?;
    let loaded = config::load(&paths);
    let status = driver::check();
    let engine = engine::load(&paths, &loaded.config.scanning);

    let outcome = check_report(&paths, &loaded, &status, &engine);
    println!("{}", outcome.text);
    if outcome.healthy {
        Ok(EXIT_OK)
    } else {
        Ok(EXIT_FAILED)
    }
}

/// Build the `--check` text.
///
/// Takes everything it reports as an argument, so that it can be tested on a
/// temporary layout with a rule database that is or is not there — and so that
/// no test has to read this machine's real configuration, driver or catalogs to
/// assert what the report says.
fn check_report(
    paths: &AvPaths,
    loaded: &config::LoadedConfig,
    status: &DriverStatus,
    engine: &Engine,
) -> CheckOutcome {
    let mut text = String::new();
    text.push_str("wenle-av-service --check\n\n");

    text.push_str("where things are\n");
    text.push_str(&format!("  install   {}\n", paths.install_dir.display()));
    text.push_str(&format!("  data      {}\n", paths.data_dir.display()));
    text.push_str(&format!("  vault     {}\n", paths.quarantine_dir.display()));

    text.push_str("\nconfiguration\n");
    text.push_str(&format!("  file      {}\n", loaded.path.display()));
    match &loaded.load_error {
        Some(error) => text.push_str(&format!(
            "  result    NOT READ, defaults are in force: {error}\n"
        )),
        None => text.push_str("  result    read\n"),
    }
    let report = config::report(loaded);
    // "not in force" rather than "not acted on", and the wording matters more
    // since 2026-10-09: `ConfigReport::unhonoured` is two lists folded into one
    // — settings nothing reads, and settings that are read once at startup and
    // not when they change — so the sentence here has to cover both. Each entry
    // says which it is; the heading only has to stop claiming the first.
    text.push_str(&format!(
        "  stored and not in force: {}\n",
        report.unhonoured.len()
    ));
    for setting in &report.unhonoured {
        text.push_str(&format!("    {} — {}\n", setting.setting, setting.reason));
    }
    text.push_str(&format!(
        "  handled by something other than this service: {}\n",
        report.handled_elsewhere.len()
    ));
    for setting in &report.handled_elsewhere {
        text.push_str(&format!("    {} — {}\n", setting.setting, setting.reason));
    }

    text.push_str("\nself protection\n");
    // Read back off the machine rather than reported from what start-up did,
    // and the difference is the point of `selfprotect::measure`: a `--check`
    // run is very often a *different process* from the service, so what the
    // service applied at its own start is a fact about the service and not
    // about the object this process is looking at. Measured is the only answer
    // that is true for the machine.
    for line in av_service::selfprotect::measure(paths) {
        text.push_str(&format!("  {line}\n"));
    }

    text.push_str("\nkernel driver\n");
    text.push_str(&format!("  presence  {:?}\n", status.presence));
    text.push_str(&format!("  detail    {}\n", status.detail));
    if let Some(device) = &status.device {
        text.push_str(&format!("  device    {device}\n"));
    }

    text.push_str("\nrule database\n");
    match &engine.database {
        Some(database) => {
            text.push_str(&format!("  file      {}\n", database.path.display()));
            text.push_str(&format!("  rules     {}\n", database.rules));
            text.push_str(&format!("  format    {}\n", database.format_version));
            text.push_str(&format!("  bytes     {}\n", database.bytes));
        }
        None => text.push_str("  none loaded\n"),
    }
    if let Some(error) = &engine.load_error {
        text.push_str(&format!("  problem   {error}\n"));
    }
    text.push_str(&format!("  catalogs  {}\n", engine.catalog.describe()));

    // The verdict, and the only part of this report a script should read: an
    // installation with no rules detects nothing, and saying "clean" about it
    // would be saying "clean" about a machine nothing looked at.
    let healthy = engine.load_error.is_none();
    text.push('\n');
    if healthy {
        text.push_str("this installation can scan.\n");
    } else {
        text.push_str(
            "this installation CANNOT DETECT ANYTHING: no rule database was loaded. \
             Every scan it runs will report every file as clean.\n",
        );
    }

    CheckOutcome { text, healthy }
}

/// Where the service's log goes, and how it is written.
///
/// A module of the binary rather than of the library, because the library is
/// the machine and this is the process: nothing in [`av_service`] should be
/// able to reach the log file, and a library that installed a global logger as
/// a side effect of being linked would be a library that decides for its
/// callers.
mod logging {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    /// The log file inside the layout's `log_dir`.
    pub const LOG_FILE_NAME: &str = "service.log";

    /// The name the previous log is kept under when a new one starts.
    pub const ROTATED_FILE_NAME: &str = "service.log.old";

    /// The size at which the log is rolled over.
    ///
    /// 4 MiB, which is months of ordinary operation — a service logs a line per
    /// request, not per file. The check happens once per start rather than per
    /// write, so a service that runs for a year is a service whose log grew for
    /// a year; unbounded growth in `%ProgramData%` is a disk-space bug, and a
    /// rotation that ran on every write would be a `stat` per log line.
    pub const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

    /// The logger, and where it writes.
    ///
    /// One file behind a mutex: the service logs from the control thread and
    /// from whatever threads the watcher and the scanner own, and interleaved
    /// half-lines are worse than no log at all. The lock is held for the length
    /// of one write and never across a call that could block on anything else.
    struct Logger {
        /// The file, opened for append.
        file: Mutex<std::fs::File>,
        /// Whether to also write to stderr.
        mirror_stderr: bool,
    }

    /// The logger this process installed, so that [`rotate`] can move its
    /// handle to the fresh file.
    ///
    /// Set once, by [`init`]. A second `init` in one process cannot win
    /// `log::set_logger` and does not replace this either: the first logger is
    /// the one that is writing, and it is the one rotation has to move.
    static LOGGER: OnceLock<&'static Logger> = OnceLock::new();

    impl Logger {
        /// Point this logger at the file it should be writing to now.
        ///
        /// Needed because an append handle follows its file through a rename:
        /// after [`roll_over`] the handle this process holds is still the one
        /// for the *rotated* file, so without this the instance that rotated
        /// writes its whole life into `service.log.old` and the live log is
        /// never created. That is exactly what was measured in the guest on
        /// 2026-10-13 — the file a grep found the run's lines in was the `.old`
        /// one, and `service.log` held two lines from before the rotation.
        fn reopen(&self, path: &Path) {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => {
                    if let Ok(mut held) = self.file.lock() {
                        *held = file;
                    }
                }
                // The old handle still works, so logging continues into the
                // rotated file rather than stopping. Saying so through that
                // handle is the only place left to say it.
                Err(error) => log::warn!(
                    "the log could not be reopened at {} after the rotation: {error}; lines keep \
                     going into {ROTATED_FILE_NAME}",
                    path.display()
                ),
            }
        }
    }

    impl log::Log for Logger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Debug
        }

        fn log(&self, record: &log::Record) {
            if !self.enabled(record.metadata()) {
                return;
            }
            let line = format_line(
                record.level(),
                record.target(),
                &record.args().to_string(),
                &timestamp(),
                record.line(),
            );
            if let Ok(mut file) = self.file.lock() {
                // A failed write to a log is not worth stopping a service for,
                // and there is nowhere to report it that is not the log.
                let _ = writeln!(file, "{line}");
            }
            if self.mirror_stderr {
                let _ = writeln!(std::io::stderr(), "{line}");
            }
        }

        fn flush(&self) {
            if let Ok(mut file) = self.file.lock() {
                let _ = file.flush();
            }
        }
    }

    /// Start logging into `log_dir`.
    ///
    /// Returns the reason it could not, rather than failing the process: see
    /// [`super::start_logging`].
    ///
    /// Rotation is deliberately *not* part of this, and [`rotate`] is the step
    /// that does it — see that function for why the two are separate and why the
    /// order between them and the instance guard matters.
    pub fn init(log_dir: &Path, mirror_stderr: bool) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(log_dir)?;
        let path = log_dir.join(LOG_FILE_NAME);

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let logger = Logger {
            file: Mutex::new(file),
            mirror_stderr,
        };
        // `log::set_logger` wants a `'static` reference and `log`'s
        // boxed-logger helper is behind a feature this workspace does not
        // enable, so the box is leaked. That is the same allocation
        // `set_boxed_logger` would have leaked on success — a logger lives as
        // long as the process, and this is the only call that makes one. On the
        // failure path the leak is one `Logger` in a process that is already
        // not going to log anything.
        let logger: &'static Logger = Box::leak(Box::new(logger));
        // A logger that is already installed belongs to an earlier call in this
        // process; the first one wins. Not an error: the alternative is a
        // second copy of every line, or none.
        if log::set_logger(logger).is_ok() {
            // Debug, because the control loop's per-request line is the one a
            // support conversation actually needs.
            log::set_max_level(log::LevelFilter::Debug);
        }
        // Remembered so [`rotate`] can move this handle. Set even when
        // `set_logger` refused it: what rotation has to move is the handle this
        // process opened, and that is this one either way.
        let _ = LOGGER.set(logger);
        Ok(())
    }

    /// Move an oversized log aside, once this process owns the installation.
    ///
    /// # Why this is not part of opening the log
    ///
    /// Rotation is the one step in startup that damages a process that is
    /// *already running*. The rename takes the live log away from the instance
    /// that owns it: that instance's open handle follows the file to its new
    /// name, so it keeps appending to `service.log.old` while `service.log`
    /// becomes a fresh, empty file belonging to the process that is about to
    /// exit. A support call then reads `service.log` and finds one line — and
    /// the next rotation overwrites the file the real history went to.
    ///
    /// So it happens after [`crate::single::InstanceGuard::acquire`], which is
    /// the point at which "this process owns the installation" is known. A
    /// process that fails the guard never rotates, so the owner's log is left
    /// alone. The cost is that opening the log still happens first, which is
    /// deliberate: it is what puts a second instance's refusal *into* the
    /// product's log rather than only on a console the SCM never gave it.
    ///
    /// # And the process that rotates has to move its own handle
    ///
    /// The rename takes this process's log away from it: an append handle
    /// follows its file to the new name. Which is why rotation does not end at
    /// [`roll_over`] — the logger this process installed is reopened on the
    /// fresh `service.log`, so what it writes from here on is where a support
    /// call looks. The mismatch this prevents is not hypothetical: on
    /// 2026-10-13 the live log in the guest **did not exist**, and the whole of
    /// the run's history was in `service.log.old`.
    ///
    /// That the ordering above is still needed, even with the reopen, is the
    /// other process's business: reopening moves *our* handle, and nothing here
    /// can move a handle an instance that is already running owns. The guard is
    /// what keeps that instance's log from being renamed out from under it.
    pub fn rotate(log_dir: &Path) {
        rotate_with(LOGGER.get().copied(), log_dir);
    }

    /// [`rotate`], with the logger passed in rather than read from [`LOGGER`].
    ///
    /// The seam that makes the reopen testable: the real entry point has one
    /// process-global logger and `log::set_logger` can be called once per
    /// process, so a test that went through [`init`] would be a test that
    /// hijacks the logger of every other test in this binary.
    fn rotate_with(logger: Option<&Logger>, log_dir: &Path) {
        let path = log_dir.join(LOG_FILE_NAME);
        if roll_over(&path, log_dir) {
            if let Some(logger) = logger {
                logger.reopen(&path);
            }
        }
    }

    /// Move an oversized log aside, so the next one starts empty.
    ///
    /// A rename and not a delete: the previous run's end is often the only
    /// record of why the service stopped. If the rename fails — a file held
    /// open by a viewer, most likely — the log simply keeps growing, which is
    /// the failure this function is least bad at. `true` means the name is free
    /// again and the caller has a handle to move.
    ///
    /// [`rotate_with`] is the only caller outside this module's tests.
    fn roll_over(path: &Path, log_dir: &Path) -> bool {
        let too_big = std::fs::metadata(path)
            .map(|metadata| metadata.len() >= MAX_LOG_BYTES)
            .unwrap_or(false);
        if too_big {
            return std::fs::rename(path, log_dir.join(ROTATED_FILE_NAME)).is_ok();
        }
        false
    }

    /// One line of log, without the newline.
    ///
    /// The timestamp is passed in rather than read here, so that the format is a
    /// pure function of its arguments and can be asserted on. Local time and not
    /// UTC: this file is read by somebody sitting at the machine, comparing it
    /// with something that happened a minute ago.
    pub fn format_line(
        level: log::Level,
        target: &str,
        message: &str,
        timestamp: &str,
        line: Option<u32>,
    ) -> String {
        match line {
            Some(line) => format!("{timestamp} [{level}] {target}:{line} {message}"),
            None => format!("{timestamp} [{level}] {target} {message}"),
        }
    }

    /// Now, as a person's clock shows it.
    fn timestamp() -> String {
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_line_says_when_what_and_where() {
            let line = format_line(
                log::Level::Warn,
                "av_service::host",
                "the vault could not be written",
                "2026-09-20 11:02:03",
                Some(412),
            );
            assert!(line.contains("2026-09-20 11:02:03"), "{line}");
            assert!(line.contains("[WARN]"), "{line}");
            assert!(line.contains("av_service::host:412"), "{line}");
            assert!(line.ends_with("the vault could not be written"), "{line}");
            assert!(!line.contains('\n'), "a line with a newline is two lines");

            // A record with no line number — anything logged from a macro that
            // does not carry one — does not grow a dangling colon.
            let without = format_line(log::Level::Info, "av_service", "started", "t", None);
            assert!(without.contains("av_service started"), "{without}");
            assert!(!without.contains(':'), "{without}");
        }

        #[test]
        fn every_level_is_visibly_different() {
            // A log where `error` and `info` render alike is a log a person
            // skims past the line that matters in.
            let render = |level| format_line(level, "t", "m", "s", None);
            let levels = [
                log::Level::Error,
                log::Level::Warn,
                log::Level::Info,
                log::Level::Debug,
                log::Level::Trace,
            ];
            let mut seen: Vec<String> = levels.iter().map(|level| render(*level)).collect();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), levels.len());
        }

        #[test]
        fn an_oversized_log_is_moved_aside_and_a_fresh_one_starts() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(LOG_FILE_NAME);

            // Under the limit: left exactly where it is, because the common
            // case must not lose the log that is being appended to.
            std::fs::write(&path, b"small").unwrap();
            roll_over(&path, dir.path());
            assert!(path.exists());
            assert!(!dir.path().join(ROTATED_FILE_NAME).exists());

            // Over the limit: moved aside, and the name is free again.
            let big = vec![b'x'; MAX_LOG_BYTES as usize];
            std::fs::write(&path, &big).unwrap();
            roll_over(&path, dir.path());
            assert!(!path.exists(), "the oversized log is still in the way");
            let rotated = dir.path().join(ROTATED_FILE_NAME);
            assert!(rotated.exists());
            assert_eq!(std::fs::metadata(&rotated).unwrap().len(), MAX_LOG_BYTES);

            // And a second roll-over replaces the previous one rather than
            // failing, so two runs in a row both leave a log to read.
            std::fs::write(&path, b"fresh").unwrap();
            std::fs::write(&path, &big).unwrap();
            roll_over(&path, dir.path());
            assert_eq!(std::fs::metadata(&rotated).unwrap().len(), MAX_LOG_BYTES);
        }

        /// The instance that rotated keeps writing into the live log.
        ///
        /// This is the defect the guest showed on 2026-10-13 in its plain form:
        /// `service.log` did not exist, and every line of the run was in the
        /// rotated name. The handle is built here the way [`init`] builds it and
        /// the write goes through [`log::Log::log`], so what is asserted is the
        /// real write path rather than the field behind it.
        #[test]
        fn the_instance_that_rotated_keeps_writing_into_the_live_log() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(LOG_FILE_NAME);
            std::fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();

            // The instance that owns the log, holding it open as `init` does.
            let logger = Logger {
                file: Mutex::new(OpenOptions::new().append(true).open(&path).unwrap()),
                mirror_stderr: false,
            };

            rotate_with(Some(&logger), dir.path());

            assert!(
                path.exists(),
                "the live log was not recreated, so the instance that rotated is about to write \
                 its whole life into {ROTATED_FILE_NAME}"
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                0,
                "the live log must start empty; the history is in {ROTATED_FILE_NAME}"
            );
            assert_eq!(
                std::fs::metadata(dir.path().join(ROTATED_FILE_NAME))
                    .unwrap()
                    .len(),
                MAX_LOG_BYTES
            );

            log::Log::log(
                &logger,
                &log::Record::builder()
                    .args(format_args!("the line a support call needs"))
                    .level(log::Level::Info)
                    .target("test")
                    .build(),
            );

            let live = std::fs::read_to_string(&path).unwrap();
            assert!(
                live.contains("the line a support call needs"),
                "the line this instance wrote did not reach the live log: {live:?}"
            );
            let rotated = std::fs::read_to_string(dir.path().join(ROTATED_FILE_NAME)).unwrap();
            assert!(
                !rotated.contains("the line a support call needs"),
                "the line went into the rotated file, which is the defect itself"
            );
        }

        /// The hazard [`rotate`]'s *ordering* exists to avoid, pinned as the
        /// platform fact it is.
        ///
        /// The reopen above moves our own handle and cannot move anybody else's,
        /// so an instance that rotates a log another process is writing still
        /// takes that process's history away from it. Two processes and an
        /// installed service are needed to exercise that end to end; what is
        /// pinned here is the property of `rename` that makes the guard-first
        /// ordering necessary, in front of whoever is tempted to drop it. The
        /// owner is a plain handle on purpose — a `Logger` that never reopens.
        #[test]
        fn another_process_rotating_the_log_takes_the_owners_lines_with_it() {
            use std::io::Write;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(LOG_FILE_NAME);
            std::fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
            // The instance that was running first, holding the log open.
            let mut owner = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();

            // Nothing is logging through this module in a test process, which is
            // exactly the "the rotator is not the owner" case.
            rotate_with(None, dir.path());

            assert!(!path.exists(), "rotation must free the live name");

            writeln!(owner, "the line a support call needs").unwrap();
            owner.flush().unwrap();

            assert!(
                !path.exists(),
                "the owner recreated the live log through its old handle"
            );
            let rotated = std::fs::read_to_string(dir.path().join(ROTATED_FILE_NAME)).unwrap();
            assert!(
                rotated.ends_with("the line a support call needs\n"),
                "the owner's line did not follow the rename, so this hazard does not exist and \
                 the ordering it justifies is not needed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::config::AvConfig;
    use av_service::engine::CatalogStatus;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_string()).collect()
    }

    #[test]
    fn no_arguments_means_the_service() {
        // The SCM starts this program with no arguments, so this is the one
        // mapping that must never change: anything else is a service that does
        // not start.
        assert_eq!(parse(&args(&[])), Ok(Mode::Service));
        assert_eq!(parse(&args(&["--console"])), Ok(Mode::Console));
        assert_eq!(parse(&args(&["--check"])), Ok(Mode::Check));
        assert_eq!(parse(&args(&["--version"])), Ok(Mode::Version));
        assert_eq!(parse(&args(&["-V"])), Ok(Mode::Version));
        assert_eq!(parse(&args(&["--help"])), Ok(Mode::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Mode::Help));
    }

    #[test]
    fn two_modes_at_once_is_an_error_naming_both() {
        // `--check --console` has no meaning — one prints and exits, the other
        // runs forever — and choosing a winner would be this program inventing
        // an instruction the user did not give.
        let error = parse(&args(&["--check", "--console"])).unwrap_err();
        assert!(error.contains("--check"), "{error}");
        assert!(error.contains("--console"), "{error}");
        // In either order, and the same for a pair that shares a flag name.
        assert!(parse(&args(&["--console", "--check"])).is_err());
        assert!(parse(&args(&["--console", "--console"])).is_err());
        assert!(parse(&args(&["--version", "--check"])).is_err());
    }

    #[test]
    fn help_is_the_one_that_does_not_conflict() {
        // A user who has got something else wrong types `--help` next, and
        // being told their command line is invalid instead of what the flags
        // mean is how a usage text goes unread.
        assert_eq!(parse(&args(&["--console", "--help"])), Ok(Mode::Help));
        assert_eq!(parse(&args(&["--help", "--console"])), Ok(Mode::Help));
        assert_eq!(parse(&args(&["--check", "-h"])), Ok(Mode::Help));
    }

    #[test]
    fn an_unknown_argument_is_refused_by_name() {
        // Named, so the user can see which word was wrong; refusing silently
        // and running as a service is the failure this prevents — a person who
        // typed `--consol` would get a program that hung waiting for the SCM.
        let error = parse(&args(&["--consol"])).unwrap_err();
        assert!(error.contains("--consol"), "{error}");
        assert!(parse(&args(&["console"])).is_err());
        assert!(parse(&args(&[""])).is_err());
        assert!(parse(&args(&["-c"])).is_err());
    }

    #[test]
    fn an_already_running_service_gets_its_own_exit_code() {
        // Not a failure: the guard is doing its job and the machine is
        // protected, which is what a script starting this needs to know.
        assert_eq!(
            exit_code_for(&ServiceError::AlreadyRunning {
                path: std::path::PathBuf::from(r"C:\ProgramData\WenleAV\service.lock")
            }),
            EXIT_ALREADY_RUNNING
        );
        assert_ne!(EXIT_ALREADY_RUNNING, EXIT_FAILED);
        assert_ne!(EXIT_ALREADY_RUNNING, EXIT_USAGE);
        assert_ne!(EXIT_OK, EXIT_FAILED);
        assert_eq!(
            exit_code_for(&ServiceError::Other("anything else".to_string())),
            EXIT_FAILED
        );
        assert_eq!(
            exit_code_for(&ServiceError::Config {
                path: std::path::PathBuf::from("config.toml"),
                message: "a key it does not know".to_string()
            }),
            EXIT_FAILED
        );
    }

    #[test]
    fn the_usage_text_mentions_every_mode_it_documents() {
        // A usage text that omits the flag the user needs is a usage text that
        // sends them to the source.
        for flag in ["--console", "--check", "--version", "--help"] {
            assert!(USAGE.contains(flag), "{flag} is not in the usage text");
        }
        // And it says what the no-argument case does, because that is the one a
        // person hits by accident and the one whose error message is a number.
        assert!(USAGE.contains("SCM"));
        assert!(USAGE.contains(scm::SERVICE_NAME) || USAGE.contains("service"));
    }

    #[test]
    fn the_report_says_when_an_installation_can_detect_nothing() {
        // The whole point of `--check`: an installation with no rule database
        // reports every file as clean, and a report that said "fine" about it
        // would be the most expensive kind of wrong answer.
        let dir = tempfile::tempdir().unwrap();
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        // Both directories are empty, so there is no database to find.
        let loaded = config::LoadedConfig {
            config: AvConfig::default(),
            load_error: None,
            path: paths.config_file.clone(),
        };
        let engine = av_service::engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            CatalogStatus::default(),
        );
        let outcome = check_report(
            &paths,
            &loaded,
            &DriverStatus::unknown("not looked for"),
            &engine,
        );

        assert!(!outcome.healthy);
        assert!(
            outcome.text.contains("CANNOT DETECT ANYTHING"),
            "{}",
            outcome.text
        );
        // And it says which of the several reasons it is, with the fix.
        assert!(
            outcome.text.contains("no rule database was found"),
            "{}",
            outcome.text
        );
        assert!(outcome.text.contains("wenle build"), "{}", outcome.text);
        // The paths it reports are the ones it was given, not this machine's.
        assert!(outcome.text.contains(&paths.data_dir.display().to_string()));
        assert!(outcome
            .text
            .contains(&paths.quarantine_dir.display().to_string()));
        // And the driver's answer is repeated rather than summarised into a
        // yes or no: "not looked for" is a third answer that has to survive.
        assert!(outcome.text.contains("not looked for"), "{}", outcome.text);
    }

    #[test]
    fn the_report_repeats_what_the_configuration_does_not_do() {
        // A user reading `--check` after editing `config.toml` is reading it to
        // find out whether what they wrote is in force. The two lists are the
        // answer to that, so they have to be in the text and not only in the
        // wire protocol.
        let dir = tempfile::tempdir().unwrap();
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        let loaded = config::LoadedConfig {
            config: AvConfig::default(),
            load_error: Some("unknown field `scannin`, expected `scanning`".to_string()),
            path: paths.config_file.clone(),
        };
        let engine = av_service::engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            CatalogStatus::default(),
        );
        let outcome = check_report(&paths, &loaded, &DriverStatus::unknown("checked"), &engine);

        assert!(outcome.text.contains("NOT READ"), "{}", outcome.text);
        assert!(outcome.text.contains("unknown field"), "{}", outcome.text);
        // Both disclosure lists are rendered, with their reasons.
        let report = config::report(&loaded);
        assert!(!report.unhonoured.is_empty());
        for setting in &report.unhonoured {
            assert!(outcome.text.contains(&setting.setting), "{}", outcome.text);
        }
        for setting in &report.handled_elsewhere {
            assert!(outcome.text.contains(&setting.setting), "{}", outcome.text);
        }
        // A configuration file that would not parse does not change the
        // verdict: the database is what decides whether anything is detected.
        assert!(outcome.text.contains("catalogs"), "{}", outcome.text);
    }
}
