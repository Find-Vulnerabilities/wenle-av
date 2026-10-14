//! `wenle service` — installing, removing, starting, stopping, and asking.
//!
//! # The five verbs, and why they are split the way they are
//!
//! Two things know about this product and they know different things. The
//! Service Control Manager knows whether the name is in its database and
//! whether a process is running under it; the service itself knows what it is
//! watching, what rules it loaded, and what it has quarantined. Only one of
//! those two can be asked by an ordinary user, and the gap between them is
//! where every confusing service problem lives — a service the SCM calls
//! `RUNNING` that answers nothing on the pipe, and a service answering on the
//! pipe that the SCM has never heard of, which is exactly what running
//! `wenle-av-service --console` by hand produces.
//!
//! So `status` asks **both** and reports them as two separate answers rather
//! than reconciling them into one word. A command that printed "running" would
//! have to choose which of the two to believe, and whichever it chose would be
//! wrong in one of those two cases.
//!
//! # Why the SCM work lives in `av-service`
//!
//! The name, the binary name, the account and the state mapping are all facts
//! about the service, and this tool is a caller of them. `av-service::install`
//! is where they are; this module is the part that decides what to print.
//!
//! # The one thing `--data-dir` does not reach
//!
//! Nothing here forwards it. The service derives `%ProgramData%\WenleAV` from
//! the path of *its own* executable, and no command line can move another
//! process's `%ProgramData%`. A user who installs with `--data-dir` and then
//! wonders why the service is reading the machine-wide configuration has been
//! misled by a flag that looked like it applied, so `service install` says so
//! in its own help text rather than leaving it to be discovered.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use av_ipc::{Client, Incoming, ManifestVerdict, Reply, Request, StatusReport, PIPE_NAME};
use av_service::install::{self, ScmState, StartOutcome, StopOutcome};
use av_service::pipe::PipeConnection;

use crate::cli::{Globals, ServiceCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;
use crate::progress::{human_bytes, human_count};

/// How long to wait for the service to answer a status request.
///
/// A timeout belongs to the caller and not to `av-ipc`, which says so: the
/// right value depends on what was asked, and a protocol crate that picked one
/// would be picking it for a quarantine listing and a cancel alike. This is the
/// caller, the question is one round trip on a local pipe, and five seconds is
/// three orders of magnitude more than that takes while still being short
/// enough that a person who typed the command does not think it has hung.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait between polls of a pipe that has nothing on it.
///
/// `Client::recv` is a question rather than a wait — the transport under it
/// answers "nothing has arrived" instead of blocking — so a caller that wants
/// to keep asking has to sleep, or it spins a core. Five milliseconds is the
/// same interval `av-service`'s transport polls at, and the cost of the whole
/// wait is one `PeekNamedPipe` two hundred times a second while nothing
/// happens.
const POLL: Duration = Duration::from_millis(5);

/// Run a `service` subcommand.
pub fn run(command: &ServiceCommand, globals: &Globals, context: &Context) -> Result<Exit> {
    match command {
        ServiceCommand::Install { binary } => install(binary.as_deref(), globals, context),
        ServiceCommand::Remove => remove(globals),
        ServiceCommand::Start => start(globals),
        ServiceCommand::Stop => stop(globals),
        ServiceCommand::Status { json } => status(*json, globals),
    }
}

/// Install the service.
///
/// The executable is checked before the SCM is asked to do anything. A service
/// whose `binPath` names a file that is not there installs perfectly well and
/// then fails at every boot, with the only explanation in an event log nobody
/// reads until the machine has been unprotected for a week — and this is the
/// one moment at which the mistake can be caught cheaply.
fn install(binary: Option<&Path>, globals: &Globals, context: &Context) -> Result<Exit> {
    let image = match binary {
        Some(path) => path.to_path_buf(),
        None => install::installed_binary(&context.paths.install_dir),
    };
    if !image.is_file() {
        return Err(anyhow!(
            "there is no service executable at {}.\n       \
             Build it with `cargo build -p av-service --release`, or point at one with \
             `--binary`.",
            image.display()
        ));
    }

    install::install(&image)?;

    output::heading("Service");
    println!(
        "  installed {} to run {}",
        install::SERVICE_NAME,
        console::style(install::image_path(&image)).cyan(),
    );
    println!("  it starts automatically when this machine boots");
    // Its recovery policy, set here because nothing else can. The service
    // cannot write its own — a service running as `LocalSystem` has
    // `SERVICE_QUERY_CONFIG` and not `SERVICE_CHANGE_CONFIG`, measured
    // 2026-10-10, and `av_service::selfprotect` documents the eight start-ups
    // that proved it — and this moment is both the one the policy belongs to
    // and the one at which this process is elevated by construction, since
    // `CreateServiceW` has just succeeded.
    //
    // A failure is reported and not fatal: the service is installed and works,
    // and failing here would send a caller to re-run a command that would then
    // say the name is already taken. `wenle protect apply` sets the same thing
    // and is the verb for repairing a machine that has one.
    match av_guard::service::configure_recovery(install::SERVICE_NAME) {
        Ok(recovery) => println!(
            "  it will be restarted if it fails: {}",
            recovery.describe()
        ),
        Err(detail) => output::warn(&detail),
    }
    // What the SCM says, rather than what was asked for. The two agree here on
    // every path that reaches this line, and the point of asking is that the
    // report is the machine's answer and not this command's intention.
    report(install::state()?, globals);
    Ok(Exit::Clean)
}

/// Remove the service.
fn remove(globals: &Globals) -> Result<Exit> {
    install::remove()?;
    output::heading("Service");
    println!("  {} was removed", install::SERVICE_NAME);
    let state = install::state()?;
    if state.is_installed() {
        // `DeleteService` marks the service for deletion and the name stays in
        // the SCM's database until the service has finished stopping, so this
        // is a real window and not a failure. Saying so is the difference
        // between a user waiting ten seconds and a user filing a bug.
        output::warn(&format!(
            "the SCM still reports it as {} — a service that was running is stopped and \
             unregistered first, so this clears on its own in a few seconds",
            state.as_str(),
        ));
    }
    let _ = globals;
    Ok(Exit::Clean)
}

/// Start the service.
fn start(globals: &Globals) -> Result<Exit> {
    let outcome = install::start()?;
    output::heading("Service");
    match outcome {
        StartOutcome::Started => println!("  {} was started", install::SERVICE_NAME),
        StartOutcome::AlreadyRunning => {
            println!("  {} was already running", install::SERVICE_NAME)
        }
    }
    report(install::state()?, globals);
    Ok(Exit::Clean)
}

/// Stop the service.
fn stop(globals: &Globals) -> Result<Exit> {
    let outcome = install::stop()?;
    output::heading("Service");
    match outcome {
        StopOutcome::StopRequested => println!(
            "  {} was asked to stop; it writes its quarantine index and closes its pipe \
             before it reports itself stopped",
            install::SERVICE_NAME,
        ),
        StopOutcome::NotRunning => {
            println!("  {} was not running", install::SERVICE_NAME)
        }
    }
    report(install::state()?, globals);
    Ok(Exit::Clean)
}

/// One line saying where the SCM has the service.
///
/// A line and not a heading, because it is a follow-up to whatever the caller
/// just did rather than an answer in its own right.
fn report(state: ScmState, globals: &Globals) {
    match state {
        ScmState::NotInstalled => println!("  the SCM does not know this name"),
        ScmState::Unrecognised(code) => {
            // Named rather than rounded: a state from a newer Windows is a
            // thing to report, and "stopped" would be a guess.
            println!("  the SCM reports a state this build does not know ({code})")
        }
        other => {
            println!("  the SCM reports it as {}", other.as_str());
            if globals.quiet {
                return;
            }
            hint(other);
        }
    }
}

/// What to do next, said only when there is something to do.
fn hint(state: ScmState) {
    match state {
        ScmState::Stopped if !state.is_running() => {
            println!("  start it with `wenle service start`");
        }
        ScmState::StartPending | ScmState::StopPending | ScmState::ContinuePending => {
            println!("  it is between states; ask again in a moment");
        }
        ScmState::Paused | ScmState::PausePending => println!(
            "  this service never accepts a pause, so something outside this product asked \
             for it"
        ),
        _ => {}
    }
}

/// Say what the SCM and the service each report.
///
/// Both, always, and neither reconciled into the other. See this module's
/// documentation for the two cases where they disagree and both are right.
fn status(json: bool, globals: &Globals) -> Result<Exit> {
    let scm = install::state()?;
    let asked = ask_the_service();

    if json {
        let pipe = match &asked {
            Ok(report) => serde_json::json!({
                "pipe": PIPE_NAME,
                "connected": true,
                "status": report,
            }),
            Err(error) => serde_json::json!({
                "pipe": PIPE_NAME,
                "connected": false,
                "error": format!("{error:#}"),
            }),
        };
        let document = serde_json::json!({
            "service_control_manager": {
                "name": install::SERVICE_NAME,
                "state": scm.as_str(),
                "installed": scm.is_installed(),
                "running": scm.is_running(),
            },
            "service": pipe,
        });
        println!("{document}");
        return Ok(exit_for(scm, &asked));
    }

    output::heading("Service control manager");
    println!("  name   {}", install::SERVICE_NAME);
    match scm {
        ScmState::NotInstalled => println!(
            "  state  not installed — nothing in the SCM answers to this name on this machine"
        ),
        ScmState::Unrecognised(code) => println!(
            "  state  a state this build does not know ({code}); this is a newer Windows than \
             this build, or something else is using the name"
        ),
        other => println!("  state  {}", other.as_str()),
    }
    if !globals.quiet {
        match scm {
            ScmState::NotInstalled => println!(
                "         install it with `wenle service install`, from an elevated prompt"
            ),
            ScmState::Stopped => println!("         start it with `wenle service start`"),
            _ => {}
        }
    }

    output::heading("Service");
    match &asked {
        Ok(report) => print_status(report, globals),
        Err(error) => {
            // Not printed through `output::error`, because whether this is a
            // fault depends on the answer above and this function's caller
            // decides that from the exit code. What is said here is only what
            // happened.
            println!("  nothing is answering on {PIPE_NAME}");
            println!("  {error:#}");
        }
    }

    Ok(exit_for(scm, &asked))
}

/// The exit code for the pair of answers.
///
/// The exit code answers a different question from the report above it. The
/// report answers *what is the state of this machine*, and every sentence in it
/// is true. The exit code answers *is anything protecting this machine*, and a
/// number cannot be explained, softened or read in context.
///
/// So a machine with nothing answering is a failure, however honestly the report
/// describes it. The person reading "not installed — install it with `wenle
/// service install`, from an elevated prompt" knows what to do; a monitoring
/// script sees only the number, and 0 would tell it that all is well on a
/// machine with no antivirus running. The precedent is `systemctl status`, which
/// exits 3 for a stopped unit and 4 for one that does not exist rather than 0,
/// for exactly this reason.
///
/// Two of the silent states stay clean on purpose:
///
/// * A service that *answers* is protecting the machine whatever the SCM
///   believes about it. `--console` runs one by hand with nothing installed,
///   which is what a developer sees all day, and it is a working product rather
///   than a broken one.
/// * [`ScmState::StartPending`] with nothing answering yet is a service on its
///   way up. It is the one silent state that is not a fault, and it lasts
///   seconds.
fn exit_for(scm: ScmState, asked: &Result<StatusReport>) -> Exit {
    match (scm, asked) {
        (_, Ok(_)) => Exit::Clean,
        (ScmState::StartPending, Err(_)) => Exit::Clean,
        _ => Exit::Failure,
    }
}

/// Ask the running service what it is doing.
///
/// Three ways this fails, and they read differently on purpose, because the
/// three send a person to three different places:
///
/// * **No pipe by this name.** `WaitNamedPipeW` returns at once and
///   `av-service::pipe` says so in those words — no service is running under
///   the name and none is installed. This is the ordinary answer on a machine
///   that has never had the service installed.
/// * **A pipe that will not take a client.** Instances exist and none accepted
///   one for five seconds, which is a service that is there and stuck, and the
///   message says that instead.
/// * **Permission denied.** The pipe is created with the default descriptor, so
///   this is a `CreateFileW` failure and reads as "could not be opened: Access
///   is denied. (os error 5)" — a principal this machine's own security does not
///   let reach the product's state.
///
/// None of the three is this function's to explain or to soften; each is
/// reported as what the operating system said, and the exit code is decided by
/// [`exit_for`] from the pair of answers rather than from any one of them.
fn ask_the_service() -> Result<StatusReport> {
    let connection = PipeConnection::connect_to(PIPE_NAME)?;
    let mut client = Client::new(connection);
    let id = client.send(Request::Status)?;
    let deadline = Instant::now() + REPLY_TIMEOUT;
    loop {
        for incoming in client.recv()? {
            // Events are read and dropped: this client asked one question and
            // the answer is what it came for. Draining them is not optional —
            // the session holds an event until it is read, and a client that
            // never read would let them accumulate to the frame cap.
            if let Incoming::Reply { id: got, reply } = incoming {
                if got != id {
                    continue;
                }
                return match reply {
                    Reply::Status(report) => Ok(report),
                    // Unreachable through `av-ipc`'s own correlation check,
                    // which refuses a reply whose kind does not answer the
                    // request. Written out rather than `unreachable!` so that a
                    // protocol bug is a sentence and not a panic in a tool a
                    // user is holding.
                    other => Err(anyhow!(
                        "the service answered a status request with a {} reply",
                        other.kind().as_str()
                    )),
                };
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "the service accepted the connection but said nothing within {}s",
                REPLY_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(POLL);
    }
}

/// One status report, as a person reads it.
fn print_status(report: &StatusReport, globals: &Globals) {
    println!("  connected to {PIPE_NAME}");
    println!("  state           {}", report.state.as_str());
    println!("  version         {}", report.version);
    println!("  uptime          {}", human_duration(report.uptime_secs));

    // The driver, with the reason for whatever it says. `unknown` is not
    // "absent" and the difference is the whole reason `DriverPresence` has
    // three values: a build that never looked must not be read as a machine
    // with no protection.
    match &report.driver.device {
        Some(device) => println!(
            "  driver          {} — {} ({device})",
            report.driver.presence.as_str(),
            report.driver.detail,
        ),
        None => println!(
            "  driver          {} — {}",
            report.driver.presence.as_str(),
            report.driver.detail,
        ),
    }

    match &report.database {
        Some(database) => println!(
            "  rules           {} from {} (format {}, {})",
            human_count(database.rules as u64),
            database.path.display(),
            database.format_version,
            human_bytes(database.bytes),
        ),
        // The state a client must never read as "nothing found": a service
        // with no rules has no ability to detect anything, and it is said in
        // those words rather than as a zero next to a rule count.
        None => output::warn(
            "no rule database is loaded, so this service cannot detect anything. Build one \
             with `wenle build` and restart the service.",
        ),
    }

    print_realtime(report);
    if !globals.quiet {
        for disclosure in &report.realtime.disclosures {
            output::warn(&disclosure_warning(disclosure));
        }
    }

    println!(
        "  quarantine      {} {}",
        human_count(report.quarantine_items as u64),
        if report.quarantine_items == 1 {
            "item"
        } else {
            "items"
        },
    );
    println!("  scans running   {}", report.scans_running);
    println!("  files examined  {}", human_count(report.files_examined));
    print_tamper(report);
}

/// What tamper resistance is doing, in two lines and then whatever it found.
///
/// # Why the findings are warnings and not fields
///
/// The first line is a statement about the product's own work — how many checks
/// have run and how many times protection was found undone and put back. The
/// second is a statement about the *files*, and the two are separate lines
/// because they answer separate questions: a machine where the process's access
/// list was re-applied is protected again, and one where `wenle.exe` no longer
/// matches the manifest is a machine where somebody has to decide something.
///
/// Anything unresolved goes through [`output::warn`], which is the same channel
/// every other "this is not what you asked for" line in this command uses. A
/// tamper finding printed as an ordinary field would sit at the same weight as
/// the uptime.
fn print_tamper(report: &StatusReport) {
    let tamper = &report.tamper;
    if !tamper.checking {
        match (&tamper.disabled_by, tamper.enabled) {
            (Some(reason), _) => println!("  tamper          off — {reason}"),
            // The contradiction `print_realtime` also reports: the
            // configuration asks for this and nothing is doing it.
            (None, true) => output::warn(
                "tamper resistance is enabled in the configuration and nothing is checking it, \
                 and the service gives no reason — this is a fault worth reporting",
            ),
            (None, false) => println!("  tamper          off"),
        }
        return;
    }

    println!(
        "  tamper          on, {} check{}, {} re-applied",
        human_count(tamper.passes),
        if tamper.passes == 1 { "" } else { "s" },
        human_count(tamper.reapplied),
    );
    match &tamper.manifest {
        ManifestVerdict::Clean { files } => println!(
            "                  the product's own files match the manifest ({} compared)",
            human_count(*files as u64)
        ),
        ManifestVerdict::Changed { differences } => output::warn(&format!(
            "{} of the product's own files no longer match the manifest taken for this \
             installation, and nothing has been repaired and the manifest has not been \
             rewritten — run `wenle protect verify` for the comparison in full",
            human_count(*differences as u64)
        )),
        // Not a warning, and said in its own words: every file the manifest
        // names matches, and these are files that are not the product's.
        ManifestVerdict::Unexpected { appeared } => println!(
            "                  every file the manifest names still matches; {} file{} that {} not \
             the product's {} in the directories they live in (`wenle protect verify` names them)",
            human_count(*appeared as u64),
            if *appeared == 1 { "" } else { "s" },
            if *appeared == 1 { "is" } else { "are" },
            if *appeared == 1 { "is" } else { "are" },
        ),
        ManifestVerdict::Absent => println!(
            "                  the product's own files are not compared against anything: no \
             manifest has been taken for this installation (`wenle protect manifest` records one)"
        ),
        ManifestVerdict::Unavailable(reason) => {
            output::warn(&format!("the product's own files could not be compared: {reason}"));
        }
        // Before the first expensive pass has finished, which is a moment and
        // not a state: it is said as such rather than left as a blank.
        ManifestVerdict::NotChecked => println!("                  the product's own files have not been compared yet"),
    }

    for sentence in &tamper.unresolved {
        output::warn(&format!("protection is not in place: {sentence}"));
    }
    for change in &tamper.changes {
        // The prefix is neutral because `Change::describe` says what kind of
        // change this is in its first word — `MISSING`, `CHANGED`, `UNEXPECTED`,
        // `APPEARED` — and a prefix that named one kind was printed over all
        // four. It read "a product file no longer matches the manifest:
        // UNEXPECTED: … is not one of the product's files" for a file that was
        // never the product's, which is a line contradicting itself.
        println!("                  {change}");
    }
}

/// What the watcher is doing, in one or two lines.
///
/// `enabled` and `watching` are printed together whenever they disagree,
/// because that disagreement is the only interesting thing about this section:
/// a configuration that asks for realtime protection and a watcher that armed
/// nothing is a user who has been told they are protected and is not.
fn print_realtime(report: &StatusReport) {
    let realtime = &report.realtime;
    if realtime.watching {
        println!(
            "  realtime        on, watching {} {}",
            realtime.roots.len(),
            if realtime.roots.len() == 1 {
                "directory"
            } else {
                "directories"
            },
        );
        for root in &realtime.roots {
            println!("                    {}", root.display());
        }
        return;
    }
    match (&realtime.disabled_by, realtime.enabled) {
        (Some(reason), _) => println!("  realtime        off — {reason}"),
        // Enabled and not watching, with nothing saying why. That is a state
        // the service should never produce and cannot explain away, so it is
        // reported as the contradiction it is rather than as one of the two.
        (None, true) => output::warn(
            "realtime protection is enabled in the configuration and no directory is being \
             watched, and the service gives no reason — this is a fault worth reporting",
        ),
        (None, false) => println!("  realtime        off"),
    }
}

/// One of the watcher's disclosures, as the warning line a person reads.
///
/// # Why the frame is not "is stored and not acted on"
///
/// It was until 2026-10-11, and in this command that frame claims something
/// `av-realtime`'s list cannot claim. The list is the *watcher's*: the settings
/// **the file watcher** does not honour, written by the component that does not
/// honour them. `is stored and not acted on` is `av-service`'s own frame for
/// [`av_ipc::ConfigReport::unhonoured`], where it means nothing in the build
/// acts on the setting — and the same words were printed here, over settings the
/// service does act on. `av-realtime`'s `WatchPlan::unhonoured` always carries
/// `realtime.scan_on_process_start` and `realtime.terminate_malicious_process`
/// when those two settings are true, which is the default, so this command
/// warned about both on every machine that ran it: measured in the VM on
/// 2026-10-11, and against the deployed binary, where `wenle config --check`
/// lists neither as unhonoured and
/// `av_service::config::the_process_side_of_realtime_is_no_longer_disclosed_as_missing`
/// exists to keep it that way. The watcher's own reason for both says so — "the
/// setting is acted on by the service, not by this watcher" — which is why the
/// honest frame keeps the reason and drops the claim over it.
///
/// The frame was self-contradicting in the other direction too. A process start
/// dropped because the worker's queue was full is disclosed under
/// `realtime.scan_on_process_start` with a reason counting the starts that were
/// missed; "is stored and not acted on" announced that the setting does nothing
/// in the same line as the number of times it had been acted on.
///
/// What is true of every entry this list can hold — the watcher's five settings,
/// a configured root it could not watch, a start it dropped — is that the
/// coverage the user asked for is not fully in place. Every reason in the list
/// is written to stand alone, so the frame only has to stop claiming more than
/// the list knows.
fn disclosure_warning(disclosure: &av_ipc::SettingDisclosure) -> String {
    format!(
        "{} is not fully in force: {}",
        disclosure.setting, disclosure.reason
    )
}

/// A duration in seconds, as something a person reads.
///
/// Seconds are what [`StatusReport::uptime_secs`] carries and "3725s" is not an
/// answer anybody can use. Two units at most: past a day the hours stop
/// mattering, and a service that has been up for three days is described by
/// "3d 4h" and not by "3d 4h 12m 9s".
fn human_duration(secs: u64) -> String {
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duration_reads_as_two_units_at_most() {
        assert_eq!(human_duration(0), "0s");
        assert_eq!(human_duration(9), "9s");
        assert_eq!(human_duration(60), "1m 00s");
        assert_eq!(human_duration(125), "2m 05s");
        assert_eq!(human_duration(3_600), "1h 0m");
        assert_eq!(human_duration(3_725), "1h 2m");
        assert_eq!(human_duration(86_400), "1d 0h");
        assert_eq!(human_duration(86_400 * 3 + 3_600 * 4 + 65), "3d 4h");
    }

    #[test]
    fn a_machine_with_nothing_answering_does_not_exit_clean() {
        // What the exit code is for: a script asking "is this machine
        // protected?" must be able to tell the answer from the number, because
        // the report's sentences are for a person. Every silent state is a
        // failure except the one that is a service on its way up.
        let silent: Result<StatusReport> = Err(anyhow!("nothing answered"));
        assert_eq!(exit_for(ScmState::Running, &silent), Exit::Failure);
        assert_eq!(exit_for(ScmState::Stopped, &silent), Exit::Failure);
        assert_eq!(exit_for(ScmState::NotInstalled, &silent), Exit::Failure);
        assert_eq!(exit_for(ScmState::StopPending, &silent), Exit::Failure);
        assert_eq!(exit_for(ScmState::Paused, &silent), Exit::Failure);

        // A service that answers is protecting the machine whatever the SCM
        // believes — including the developer's case, a service run by hand with
        // `--console` and nothing installed.
        let answered: Result<StatusReport> = Ok(sample());
        assert_eq!(exit_for(ScmState::Running, &answered), Exit::Clean);
        assert_eq!(exit_for(ScmState::Stopped, &answered), Exit::Clean);
        assert_eq!(exit_for(ScmState::NotInstalled, &answered), Exit::Clean);

        // A service that is still starting is not yet a broken one.
        assert_eq!(exit_for(ScmState::StartPending, &silent), Exit::Clean);
    }

    #[test]
    fn a_watcher_disclosure_does_not_claim_that_nothing_acts_on_it() {
        // `wenle service status` prints `av-realtime`'s list — the settings *the
        // file watcher* does not honour — and until 2026-10-11 it printed them
        // with `av-service`'s frame for a setting nothing in the build acts on.
        // On the deployed binary that day the command warned that
        // `realtime.scan_on_process_start` and
        // `realtime.terminate_malicious_process` were stored and not acted on,
        // and the service acts on both. The first half of this test is the other
        // surface saying so; the second half is the line this command prints.
        let reported = av_service::config::report(&av_service::config::load(
            &av_core::AvPaths::with_data_dir(
                std::path::PathBuf::from(r"C:\wenle"),
                std::path::PathBuf::from(r"C:\ProgramData\WenleAV"),
            ),
        ));
        for setting in [
            "realtime.scan_on_process_start",
            "realtime.terminate_malicious_process",
        ] {
            assert!(
                !reported
                    .unhonoured
                    .iter()
                    .any(|disclosure| disclosure.setting == setting),
                "{setting} is acted on by the service, so a warning saying that nothing acts on \
                 it is false in whichever command it is printed from"
            );
        }

        // The kinds this list can hold, each with the reason its own component
        // writes: a setting the watcher does not honour, a configured root it
        // could not watch, a start it dropped, and a process it examined once and
        // never looked at again. One frame has to be true of all four, which is
        // why it claims less than the old one did — the last two are a setting
        // the service acts on, disclosed because it fell behind.
        let entries = [
            av_ipc::SettingDisclosure::new(
                "realtime.scan_on_execute",
                "this crate watches the filesystem, and a filesystem does not say whether a file \
                 is about to be executed",
            ),
            av_ipc::SettingDisclosure::new(
                "realtime.watched_paths",
                r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup is \
                 not watched: it does not exist",
            ),
            av_ipc::SettingDisclosure::new(
                "realtime.scan_on_process_start",
                "3 process start(s) were not examined because the watcher was still walking an \
                 earlier one and its queue was full; 12 examined so far",
            ),
            av_ipc::SettingDisclosure::new(
                "realtime.scan_on_process_start",
                "7 process(es) were examined once and not looked at a second time, because that \
                 many were already waiting for their second walk; a process read only at creation \
                 has not finished starting",
            ),
        ];
        for entry in &entries {
            let line = disclosure_warning(entry);
            assert!(
                !line.contains("not acted on"),
                "an entry in this list can be a setting the service acts on, so the line must \
                 not say otherwise: {line}"
            );
            assert!(line.starts_with(&entry.setting), "{line}");
            assert!(line.ends_with(&entry.reason), "{line}");
        }
    }

    #[test]
    fn the_default_binary_is_the_service_beside_this_executable() {
        // The path rule, exercised on exactly the expression `install` above
        // uses to build the image path when no `--binary` is given. Written
        // through `installed_binary` rather than a local helper, because a
        // second function wrapping this one would be a function nothing in the
        // shipping binary calls — which is precisely what the compiler said
        // about the wrapper this replaces.
        let context = Context {
            paths: av_core::AvPaths::with_data_dir(
                std::path::PathBuf::from(r"C:\wenle"),
                std::path::PathBuf::from(r"C:\ProgramData\WenleAV"),
            ),
            config: av_core::AvConfig::default(),
        };
        assert_eq!(
            install::installed_binary(&context.paths.install_dir),
            std::path::PathBuf::from(r"C:\wenle\wenle-av-service.exe")
        );
    }

    /// A status report to make the exit-code test able to talk about one.
    fn sample() -> StatusReport {
        StatusReport {
            state: av_ipc::ServiceState::Running,
            version: "0.1.0".to_string(),
            uptime_secs: 12,
            driver: av_ipc::DriverStatus {
                presence: av_ipc::DriverPresence::Unknown,
                detail: "this build does not look".to_string(),
                device: None,
            },
            database: None,
            realtime: av_ipc::RealtimeState::off("realtime.enabled is false"),
            quarantine_items: 0,
            scans_running: 0,
            files_examined: 0,
            tamper: av_ipc::TamperState::off(false, "protection.tamper_resistance is false"),
        }
    }
}
