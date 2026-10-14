//! `wenle integrate` — putting this product into Windows itself.
//!
//! # Why this is a command rather than something an installer does silently
//!
//! Two reasons, and the second is the one that decided it.
//!
//! The first is that the product has no installer. A release is unpacked, and
//! the only thing that has ever put anything on a machine is a command a person
//! typed — see `wenle service install`, which is the same shape for the same
//! reason.
//!
//! The second is that this writes to `HKEY_LOCAL_MACHINE\Software\Classes` when
//! asked to, which is a place where a menu item can be registered for every
//! account on the machine. Something that does that as a side effect of being
//! unpacked is something a user cannot decline, cannot see, and cannot undo
//! without knowing where to look. A command that has to be typed can be declined
//! by not typing it, and the help text says what it will do before it does it.
//!
//! # What it is worth, said in the command rather than only in the crate
//!
//! The verbs are cosmetic. They add a right-click menu item and nothing else:
//! nothing here watches anything, nothing here runs at scan time, and a machine
//! with the verbs unregistered is exactly as protected as one with them
//! registered. That is why [`status`] and [`both`] exit 0 when nothing is
//! registered, where `wenle service status` exits 2 when nothing answers: a
//! machine with no service is unprotected, and a machine with no shell verb is
//! not. The exit code is a contract with a script, and 2 here would tell that
//! script a working machine was broken.
//!
//! **That rule is about the verbs, and [`driver_status`] is the exception to
//! it.** The shell verbs are cosmetic, the AMSI provider is a second opinion,
//! and the driver is neither: it is the only thing in the product that sees a
//! file operation before it happens. So `driver status` exits 2 when the machine
//! is not registered the way this build registers it, which is the code
//! `wenle protect status` uses for a machine that is not fully protected and
//! means the same thing here. `defender`, `amsi`, `notifications` and `startup`
//! `status` exit 0 for the reason the verbs do: they report what is registered,
//! and none of them is a comparison against what this build would write. A
//! machine with no startup entry is a machine where the user has not asked for
//! one, and a machine with no notification identifier still shows every
//! notification — see [`notifications_install`] for the measurement that says
//! so.
//!
//! # The scope, and why it is printed
//!
//! With neither `--user` nor `--machine`, the scope is the one this process can
//! actually write: machine when it is elevated, the current user otherwise. That
//! decision is printed on every `install` and `remove` that did not have it
//! named, because it is the difference between a menu item every account on the
//! machine sees and one only the caller does — and because a user who ran the
//! command from an unelevated prompt deserves to be told why they got the
//! smaller one rather than left to discover it from another account.

use anyhow::{anyhow, Result};
use av_core::AvError;
#[cfg(windows)]
use av_integration::amsi;
#[cfg(windows)]
use av_integration::defender::{self, DefenderStatus, Previous, Tamper};
use av_integration::driver::{self, DriverStatus};
use av_integration::Hive;
use av_integration::notifications::{self, NotificationStatus};
use av_integration::shell::{
    self, Location, Registration, Scope, ShellStatus, VerbStatus,
};
use av_integration::startup::{self, StartupStatus};

#[cfg(windows)]
use crate::cli::{AmsiCommand, DefenderCommand, DriverCommand};
use crate::cli::{Globals, IntegrateCommand, ScopeArgs, SessionCommand, ShellCommand};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;

/// `ERROR_ACCESS_DENIED`.
///
/// The one registry code this command has a second sentence for. See [`act`].
const ERROR_ACCESS_DENIED: u32 = 5;

/// Run an `integrate` subcommand.
pub fn run(command: &IntegrateCommand, globals: &Globals, _context: &Context) -> Result<Exit> {
    match command {
        IntegrateCommand::Shell(shell_args) => match &shell_args.command {
            ShellCommand::Install(args) => install(args, globals),
            ShellCommand::Remove(args) => remove(args, globals),
            ShellCommand::Status(args) => status(args, globals),
        },
        #[cfg(windows)]
        IntegrateCommand::Amsi(amsi_args) => match &amsi_args.command {
            AmsiCommand::Install => amsi_install(globals),
            AmsiCommand::Remove => amsi_remove(globals),
            AmsiCommand::Status => amsi_status(globals),
        },
        #[cfg(windows)]
        IntegrateCommand::Defender(defender_args) => match &defender_args.command {
            DefenderCommand::Status => defender_status(globals),
            DefenderCommand::Disable => defender_disable(globals),
            DefenderCommand::Restore => defender_restore(globals),
        },
        #[cfg(windows)]
        IntegrateCommand::Driver(driver_args) => match &driver_args.command {
            DriverCommand::Install => driver_install(globals),
            DriverCommand::Remove => driver_remove(globals),
            DriverCommand::Status => driver_status(globals),
        },
        IntegrateCommand::Notifications(notifications_args) => match &notifications_args.command {
            SessionCommand::Install => notifications_install(globals),
            SessionCommand::Remove => notifications_remove(globals),
            SessionCommand::Status => notifications_status(globals),
        },
        IntegrateCommand::Startup(startup_args) => match &startup_args.command {
            SessionCommand::Install => startup_install(globals),
            SessionCommand::Remove => startup_remove(globals),
            SessionCommand::Status => startup_status(globals),
        },
        // Both scopes, and the `--data-dir` this command ignores is deliberate:
        // what is registered is a fact about this machine's registry, and there
        // is no directory that moves it.
        IntegrateCommand::Status => both(globals),
    }
}

// -- the AMSI provider -------------------------------------------------------

/// Register the provider DLL for the whole machine.
///
/// The status printed afterwards is read back from the registry rather than
/// restated from what was just written, for the reason [`install`] gives about
/// the shell verbs: the two agree on every path that reaches this line, and the
/// point of reading is that a write which did not take — a policy that reverts
/// it, a key another account owns — shows up here rather than being reported as
/// success.
#[cfg(windows)]
fn amsi_install(globals: &Globals) -> Result<Exit> {
    let dll = amsi::install().map_err(amsi_failure)?;

    output::heading("AMSI provider");
    println!("  registered {}", console::style(dll.display()).cyan());
    let status = amsi::status().map_err(amsi_failure)?;
    print_amsi(&status, globals);
    if !status.is_complete() {
        // Not an error exit. The registration is in the registry and this is a
        // report of what it will do — which, on a machine where the DLL is not
        // where it was registered from, is nothing. That is worth a warning and
        // not worth telling a script the command failed: the keys this command
        // owns were written.
        output::warn(
            "the registration is in place but Windows would not load the provider from it. \
             The lines above say why.",
        );
    }
    Ok(Exit::Clean)
}

/// Take the registration out.
#[cfg(windows)]
fn amsi_remove(globals: &Globals) -> Result<Exit> {
    amsi::remove().map_err(amsi_failure)?;

    output::heading("AMSI provider");
    println!("  removed from {}", console::style("HKEY_LOCAL_MACHINE").cyan());
    let status = amsi::status().map_err(amsi_failure)?;
    if status.is_absent() {
        println!("  nothing is registered there");
    } else {
        // A `remove` that did not remove everything is a fact worth printing
        // rather than a failure to raise, and which keys survived is what the
        // user needs in order to finish the job.
        print_amsi(&status, globals);
    }
    Ok(Exit::Clean)
}

/// What is registered.
#[cfg(windows)]
fn amsi_status(globals: &Globals) -> Result<Exit> {
    let status = amsi::status().map_err(amsi_failure)?;
    print_amsi(&status, globals);
    Ok(Exit::Clean)
}

/// A registration failure, in the words the crate used.
///
/// No second sentence for `ERROR_ACCESS_DENIED`, unlike [`act`]: the crate
/// already refuses an unelevated machine-wide write *by name* before attempting
/// it, so a code 5 that gets this far came from an ACL rather than from
/// elevation — which no amount of elevating changes, and which therefore has no
/// remedy to offer.
#[cfg(windows)]
fn amsi_failure(error: amsi::AmsiError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// The AMSI registration, as a person reads it.
#[cfg(windows)]
fn print_amsi(status: &amsi::AmsiStatus, _globals: &Globals) {
    output::heading("AMSI provider — HKEY_LOCAL_MACHINE");
    // "keys this build writes", because the list below it is longer than this
    // count: `sites()` reports all four sites, and two of them are the 32-bit
    // view that a 64-bit build never writes and only reads. A bare "0 of 2" over
    // four lines reads as though two of them had been forgotten.
    println!(
        "  registered {} of {} keys this build writes",
        status.registered(),
        amsi::Site::NATIVE.len()
    );
    for entry in status.sites() {
        print_site(entry);
    }
    for problem in status.problems() {
        output::warn(&problem);
    }
    // The 32-bit view, when something registered it. Not a fault — a machine
    // with a 32-bit copy of the product is entitled to have entries there — but
    // this build cannot honour them, and a user who does not know they are
    // there would read "registered 2 of 2" as full coverage.
    let other = status.other_views();
    if !other.is_empty() {
        println!(
            "  {} {} the 32-bit view, which this 64-bit build does not write",
            console::style("note     ").yellow(),
            if other.len() == 1 { "entry in" } else { "entries in" },
        );
        for site in other {
            println!("                {}", site.key_path());
        }
        println!(
            "                scripts run by a 32-bit host are not examined by this provider"
        );
    }
}

/// One site's lines, with the DLL it names.
#[cfg(windows)]
fn print_site(entry: &amsi::SiteStatus) {
    let site = entry.site;
    match &entry.state {
        amsi::SiteState::Absent => {
            println!(
                "  {}  {}",
                console::style("absent    ").yellow(),
                site.describe()
            );
        }
        amsi::SiteState::Incomplete { detail } => {
            println!(
                "  {}  {}",
                console::style("broken    ").red().bold(),
                site.describe()
            );
            println!("              {detail}");
        }
        amsi::SiteState::Present(amsi::Detail::Provider) => {
            println!(
                "  {}  {}",
                console::style("registered").green(),
                site.describe()
            );
        }
        amsi::SiteState::Present(amsi::Detail::Client {
            dll,
            threading_model,
            on_disk,
            trusted,
        }) => {
            println!(
                "  {}  {}",
                console::style("registered").green(),
                site.describe()
            );
            // The path verbatim and never re-derived from this process, for the
            // reason `print_entry` gives about the shell verb's command line:
            // the question is what Windows will load, and the answer is a string
            // in the registry.
            println!("              dll       {}", console::style(dll.display()).cyan());
            println!(
                "              threading {}",
                threading_model.as_deref().unwrap_or("(not set)")
            );
            // Both flags, spelled out, because "registered" on its own is a
            // claim about a key and a user reads it as a claim about
            // protection.
            println!(
                "              file      {}",
                if *on_disk { "present" } else { "NOT THERE" }
            );
            println!(
                "              safe path {}",
                if *trusted { "yes" } else { "NO — writable by an ordinary user" }
            );
        }
    }
    println!(
        "              key       {}",
        console::style(site.key_path()).dim()
    );
}

// -- Windows Defender's real-time monitoring --------------------------------

/// What Defender's real-time monitoring is set to.
///
/// Read-only, and the one command in this group that needs no elevation. The
/// module reads nothing an ordinary user may not read, and the report says what
/// it is a report *about* rather than leaving a reader to take a number for a
/// measurement of protection.
#[cfg(windows)]
fn defender_status(globals: &Globals) -> Result<Exit> {
    let status = defender::status().map_err(defender_failure)?;
    print_defender(&status, globals);
    Ok(Exit::Clean)
}

/// Turn Defender's real-time monitoring off.
///
/// # The order of this function, and why it is the order
///
/// The status is read and printed *before* the change, because the two facts a
/// person needs in order to decide — what it is set to now, and whether
/// Defender's tamper protection is going to revert whatever is written — are
/// both facts about the machine as it is. Printing them afterwards would be
/// printing a description of a machine that no longer exists, and printing them
/// only on the failure path would mean a user who succeeded never saw what they
/// gave up.
///
/// Nothing here asks "are you sure". A command that has to be typed is already
/// deliberate, the same argument `wenle integrate` makes about not doing this
/// from an installer, and an interactive prompt would be a prompt no script and
/// no support session could get past.
///
/// # Why the elevation refusal comes after those two lines
///
/// [`defender::disable`] checks for elevation before it touches anything, so an
/// unelevated `disable` prints what it was about to do and then the refusal —
/// rather than refusing first. The order is deliberate: the report above it is a
/// read of this machine, which an unelevated process may make, and a user who is
/// about to be told to elevate has more use for "it is currently set to X, and
/// tamper protection will fight you" than for a bare refusal. The check itself
/// stays in the module, so that the rule about who may write is in one place
/// rather than in the module and in whichever command called it.
#[cfg(windows)]
fn defender_disable(globals: &Globals) -> Result<Exit> {
    let before = defender::status().map_err(defender_failure)?;

    output::heading("Windows Defender — real-time monitoring");
    println!(
        "  now          {}",
        console::style(before.monitoring().describe()).cyan()
    );
    println!("  giving up    {GIVING_UP}");
    // The one thing on this machine most likely to make the write do nothing,
    // said before the write rather than offered afterwards as an explanation for
    // a failure the user would have to work out on their own.
    if before.tamper().may_revert_writes() {
        output::warn(&format!(
            "Defender's tamper protection is {} on this machine, and it treats a change to this \
             setting as an attack: it may refuse the write, or revert it a moment after it lands, \
             and it logs the attempt (event 5013). Turn tamper protection off in Windows Security \
             first if you want this to take effect — this command does not turn it off for you, \
             and will not.",
            before.tamper().describe()
        ));
    }

    let previous = defender::disable().map_err(defender_failure)?;

    println!(
        "  wrote        {}",
        console::style(format!("{} = 1", defender::DISABLE_VALUE)).cyan()
    );
    println!("               {}", console::style(defender::POLICY_KEY).dim());
    println!("  recorded     {}", console::style(previous.describe()).cyan());
    println!(
        "               {}",
        console::style(format!("{}\\{}", defender::RECORD_KEY, defender::RECORD_VALUE)).dim()
    );
    // Said outright rather than left to be inferred from a success, because the
    // registry is the only thing this command can see and it is not the thing
    // the user cares about.
    println!();
    println!("  {HELD_OFF}");
    if !globals.quiet {
        println!(
            "  Run `wenle integrate defender status` again in a few seconds: a value that is \
             still there was one Defender accepted, and one that has gone was reverted. Put it \
             back with `wenle integrate defender restore`."
        );
    }
    Ok(Exit::Clean)
}

/// Put back the value that was there before [`defender_disable`] changed it.
#[cfg(windows)]
fn defender_restore(globals: &Globals) -> Result<Exit> {
    let previous = defender::restore().map_err(defender_failure)?;
    let status = defender::status().map_err(defender_failure)?;

    output::heading("Windows Defender — real-time monitoring");
    println!("  put back     {}", console::style(previous.describe()).cyan());
    // Which of the two shapes the undo took, spelled out: "the value was not
    // there" is a sentence a user can act on, and it is not the same action as
    // writing a number.
    match previous {
        Previous::Absent => println!(
            "               {} removed from {}",
            defender::DISABLE_VALUE,
            console::style(defender::POLICY_KEY).dim()
        ),
        Previous::Dword(value) => println!(
            "               {} = {value} in {}",
            defender::DISABLE_VALUE,
            console::style(defender::POLICY_KEY).dim()
        ),
    }
    println!("  record       cleared");
    print_defender(&status, globals);
    Ok(Exit::Clean)
}

/// What a user is giving up, in one sentence, printed before the change.
///
/// A constant rather than a literal inside the `println!` above so that the
/// sentence printed here, the one `disable`'s own help text promises, and the
/// one the module documentation argues for are the same sentence — and so that
/// changing what this product claims to take on is a change in one place.
#[cfg(windows)]
const GIVING_UP: &str = "Windows Defender's on-access scanning. While it is off, this product's \
                         real-time protection is the only thing examining files as they are \
                         written — and if it is not running, nothing is.";

/// What is true once the policy value is in the registry, and what is not.
#[cfg(windows)]
const HELD_OFF: &str = "The value is in the registry. Whether Defender honours it is not \
                        something this command can see — the registry holds settings, not \
                        running state — so this is not a claim that monitoring has stopped. \
                        Windows Security is where that is read.";

/// A failure from the Defender module, in the words the crate used.
///
/// No second sentence for `ERROR_ACCESS_DENIED`, unlike [`act`]: the module
/// refuses an unelevated write by name before attempting it, so a code 5 that
/// gets this far came from a key's own ACL — which on these keys is the ordinary
/// state rather than an accident, and which no amount of elevating changes.
#[cfg(windows)]
fn defender_failure(error: defender::DefenderError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// What Defender is set to, as a person reads it.
#[cfg(windows)]
fn print_defender(status: &DefenderStatus, _globals: &Globals) {
    output::heading("Windows Defender — settings");
    let monitoring = status.monitoring();
    println!(
        "  real-time    {}",
        if monitoring.is_off() {
            console::style(monitoring.describe()).yellow().bold().to_string()
        } else {
            console::style(monitoring.describe()).green().to_string()
        }
    );

    // Both keys, and both always printed even when neither is set. A report that
    // printed only the policy value would leave a user unable to tell "this
    // product has not touched it" from "something else set it", which is the
    // question they are here to answer.
    println!(
        "  policy       {}",
        describe_value(status.policy())
    );
    println!(
        "               {}",
        console::style(defender::POLICY_KEY).dim()
    );
    println!(
        "  defender     {}",
        describe_value(status.setting())
    );
    println!(
        "               {}",
        console::style(defender::SETTINGS_KEY).dim()
    );

    println!("  tamper       {}", describe_tamper(status.tamper()));
    println!("  passive      {}", describe_value(status.passive()));

    match status.record() {
        Some(previous) => {
            println!(
                "  record       {}",
                console::style(previous.describe()).cyan()
            );
            println!(
                "               {} = {}",
                console::style(defender::RECORD_VALUE).dim(),
                console::style(previous.encode()).dim()
            );
            println!(
                "               this product is holding the setting off; put it back with \
                 `wenle integrate defender restore`"
            );
        }
        None => println!("  record       none — this product has not changed anything here"),
    }

    // What the report is not. Printed every time rather than only when something
    // looks wrong, because the number above is exactly the kind of number a
    // reader assumes is a measurement.
    println!();
    println!("  {NOT_A_MEASUREMENT}");
}

/// The warning under every Defender report.
#[cfg(windows)]
const NOT_A_MEASUREMENT: &str = "These are settings, and the registry holds settings rather than \
                                 running state: nothing above says whether the Defender service \
                                 is running or honouring them. Windows Security is where that is \
                                 read, and this command does not replace it.";

/// A `REG_DWORD` setting, or the absence of one, as a person reads it.
///
/// The distinction is the point and is why this is not `unwrap_or(0)`: `0` and
/// "no value" are different registries, they are different answers to "has
/// anybody configured this", and every one of these settings reads as its
/// default when the value is absent.
#[cfg(windows)]
fn describe_value(value: Option<u32>) -> String {
    match value {
        Some(value) => console::style(value.to_string()).cyan().to_string(),
        None => console::style("(not set)").dim().to_string(),
    }
}

/// Tamper protection, with its consequence spelled out when it is in force.
#[cfg(windows)]
fn describe_tamper(tamper: Tamper) -> String {
    if tamper.may_revert_writes() {
        console::style(format!(
            "{} — a change made here may be refused or reverted",
            tamper.describe()
        ))
        .yellow()
        .bold()
        .to_string()
    } else {
        console::style(tamper.describe()).to_string()
    }
}

// -- the kernel driver -------------------------------------------------------

/// This product's service name, as `sc`, `fltmc` and the registry spell it.
///
/// Read from the crate that owns it rather than written here, so that the two
/// commands this file prints — `fltmc load` and `fltmc unload` — name the same
/// service the installer registered. A second spelling of it here would be a
/// command a user could type that fails with "the specified service does not
/// exist as an installed service", which reads as a broken install.
const FILTER_SERVICE: &str = av_driver_proto::DRIVER_SERVICE_NAME;

/// The command that starts a registered filter without waiting for a reboot.
///
/// Printed by `install`, because the difference between "registered" and
/// "running" is the whole difficulty of this subject and no command here can
/// close it: the loader starts a boot-start driver at boot, and nothing in user
/// mode can ask the SCM to start a filesystem filter — `fltmc` is the tool that
/// can, and it is not this program.
///
/// A function and not a constant, so that the service name is [`FILTER_SERVICE`]
/// and not a second copy of it. A `fltmc` line naming a service that does not
/// exist fails with "the specified service does not exist as an installed
/// service", which reads as a broken install rather than as a typo in this
/// file's help text.
#[cfg(windows)]
fn activate_now() -> String {
    format!("fltmc load {FILTER_SERVICE}")
}

/// The command that stops a loaded filter before the next boot. See
/// [`activate_now`].
#[cfg(windows)]
fn deactivate_now() -> String {
    format!("fltmc unload {FILTER_SERVICE}")
}

/// Install the kernel driver and register it as a service.
///
/// The status printed afterwards is read back from the registry rather than
/// restated from what was just written, for the reason [`amsi_install`] gives:
/// the two agree on every path that reaches the print, and the point of reading
/// is that a write which did not take shows up here rather than being reported as
/// success.
#[cfg(windows)]
fn driver_install(globals: &Globals) -> Result<Exit> {
    let source = driver::product_driver().map_err(driver_failure)?;
    let status = driver::install(&source).map_err(driver_failure)?;

    output::heading("Kernel driver");
    println!(
        "  installed {} from {}",
        console::style(av_driver_proto::DRIVER_FILE_NAME).cyan(),
        source.display()
    );
    print_driver(&status, globals);

    if !status.is_installed() {
        // An error exit here, unlike the AMSI case. That one warns because the
        // keys it owns were written and only the DLL was in the wrong place; this
        // one has just written a kernel service that the loader will refuse, and
        // a script that continued on it would be continuing on a machine that is
        // not protected.
        return Err(anyhow!(
            "the registration was written but does not read back as complete; the lines above say \
             what is missing"
        ));
    }

    println!();
    println!(
        "  {}  run {} to start it now, or reboot",
        console::style("note").dim(),
        console::style(activate_now()).cyan()
    );
    Ok(Exit::Clean)
}

/// Unregister the driver and delete its image.
#[cfg(windows)]
fn driver_remove(globals: &Globals) -> Result<Exit> {
    driver::remove().map_err(driver_failure)?;

    output::heading("Kernel driver");
    println!("  removed the service and its image");
    let status = driver::status().map_err(driver_failure)?;
    if status.is_installed() {
        // A `remove` that did not remove is a fact worth printing rather than a
        // failure to raise, and which value survived is what a user needs to
        // finish the job by hand.
        print_driver(&status, globals);
    } else {
        println!("  nothing is registered for {}", console::style(FILTER_SERVICE).cyan());
    }
    println!();
    // Printed unconditionally, because this command cannot tell whether the
    // filter is loaded and the answer is the same either way: if it is, the
    // sentence applies; if it is not, the command is harmless.
    println!(
        "  {}  a filter that is already loaded stays loaded until the machine restarts; {} \
         unloads it now",
        console::style("note").dim(),
        console::style(deactivate_now()).cyan()
    );
    Ok(Exit::Clean)
}

/// What is registered, and what this build would register.
#[cfg(windows)]
fn driver_status(globals: &Globals) -> Result<Exit> {
    let status = driver::status().map_err(driver_failure)?;
    print_driver(&status, globals);

    // The limits of what a registry read can answer, stated where the report
    // ends. A user who reads "installed" and concludes the driver is filtering
    // their disk has concluded something this command did not tell them.
    println!();
    println!(
        "  {}  this is the registration, not the running state. A driver whose service is \
         registered and whose file is present can still have been refused by the kernel when it \
         loaded, and only {} can answer that",
        console::style("note").dim(),
        console::style("fltmc filters").cyan()
    );

    if status.is_installed() {
        output::summary(&format!(
            "The kernel driver is registered and its image is on disk. Whether the kernel \
             accepted it is not something the registry records — {} answers that.",
            console::style("fltmc filters").cyan()
        ));
        return Ok(Exit::Clean);
    }
    // Non-zero, and the same code `wenle protect status` uses for the same
    // reason: this is not a report of what is registered, it is a comparison
    // against what this build would write, and the machine failing that
    // comparison is a machine running with less protection than the product
    // provides. The module documentation's rule that this command group exits 0
    // is about the shell verbs, which are cosmetic; see the `state` line this
    // prints and the note above it.
    output::summary(
        "This machine is not protected at the kernel level: the driver is not registered the way \
         this build registers it.",
    );
    Ok(Exit::Failure)
}

/// A driver failure, in the words the crate used.
///
/// No second sentence for `ERROR_ACCESS_DENIED`, for the reason
/// [`amsi_failure`] gives: the crate refuses an unelevated machine-wide write
/// *by name* before attempting it, so a code 5 reaching here came from an ACL
/// rather than from elevation, and elevating would not change it.
#[cfg(windows)]
fn driver_failure(error: driver::DriverError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// The registration, as a person reads it.
///
/// Prints the values the machine holds only when they are not what this build
/// would write, and prints the whole list when nothing is registered. A healthy
/// machine gets four lines; a broken one gets the value that is wrong, by full
/// key path, without anybody having to open a registry editor.
#[cfg(windows)]
fn print_driver(status: &DriverStatus, _globals: &Globals) {
    output::heading(&format!("Kernel driver — {}", status.image.display()));

    // "values" and not "values of the service key": the nine span the service
    // key, the `Instances` subkey and the instance subkey, and a user who reads
    // "the service key" and then goes looking in a registry editor will find
    // three of the nine. `status.values` is the whole registration, which is
    // what the count is of.
    let registered = status.values.len() - status.absent().len();
    println!(
        "  registered {} of {} values of the {FILTER_SERVICE} registration",
        registered,
        status.values.len()
    );
    println!(
        "  image      {}",
        if status.file_present {
            console::style("present").green().to_string()
        } else {
            console::style("missing").red().bold().to_string()
        }
    );

    if status.is_installed() {
        println!("  state      {}", console::style("installed").green().bold());
        return;
    }

    // One line per value that is not what this build writes, and *only* those:
    // `DriverStatus::problems` says the same nine things in sentences, and
    // printing both would double the length of a report whose whole value is
    // that the one wrong value is easy to find. The image is the exception —
    // it is a file and not a value, so `problems` is the only thing that
    // mentions it, and it is the failure that matters most.
    println!();
    for found in status.absent().into_iter().chain(status.differing()) {
        // The two are different problems and deserve different words: nothing is
        // registered at all, versus a registration that has drifted from what
        // this build writes. A user fixes the first by installing and the second
        // by working out who changed it.
        // Padded before it is styled, not after: the width of a styled object
        // is the width of its escape codes too, so `{tag:<7}` on the styled
        // value would line up only on a terminal with no colour.
        let label = if found.absent() { "unset" } else { "wrong" };
        let padded = format!("{label:<7}");
        let tag = if found.absent() {
            console::style(padded).yellow()
        } else {
            console::style(padded).red().bold()
        };
        println!("  {tag}  {}\\{}", found.key, found.name);
        // Indented to the key column, so the value that is wrong and the value
        // that should be there read as one block rather than two lines.
        match &found.actual {
            Some(actual) => println!(
                "           is {actual}, and this build writes {}",
                found.expected
            ),
            None => println!("           this build writes {}", found.expected),
        }
    }
    if !status.file_present {
        println!(
            "  {}  the driver image is not at {} — a registration naming a file that is not there \
             is one the loader accepts and then fails to find",
            console::style("error  ").red().bold(),
            status.image.display()
        );
    }
    println!();
    println!(
        "  state      {}",
        console::style("not installed").yellow().bold()
    );
}

// -- the two per-user registrations ------------------------------------------

/// Register the name and icon this product's notifications are attributed to.
///
/// Nothing here decides whether a notification is *shown* — that was measured,
/// and the answer is that an unregistered identifier posts successfully. So a
/// write that did not take is warned about and not raised, in the same spirit as
/// an incomplete shell-verb install: the machine is not less protected, the
/// notification still arrives, and only the name above it is wrong.
fn notifications_install(globals: &Globals) -> Result<Exit> {
    let status = notifications::install().map_err(notifications_failure)?;

    output::heading("Notifications");
    println!(
        "  registered {} as {}",
        console::style(av_core::APP_USER_MODEL_ID).cyan(),
        console::style(notifications::DISPLAY_NAME).cyan()
    );
    print_notifications(&status, globals);
    if !status.is_installed() {
        output::warn(
            "the key was written but does not read back as carrying a display name; the lines \
             above say what the machine holds",
        );
    }
    Ok(Exit::Clean)
}

/// Remove the registration.
///
/// One key, and the account's own notification switches are left alone: those
/// are Windows' record of what the user asked for, and deleting them would turn
/// a user's "notifications from this app: off" back on as a side effect of
/// unregistering a name.
fn notifications_remove(globals: &Globals) -> Result<Exit> {
    notifications::remove().map_err(notifications_failure)?;

    output::heading("Notifications");
    println!(
        "  removed {} from {}",
        console::style(av_core::APP_USER_MODEL_ID).cyan(),
        Hive::CurrentUser
    );
    let status = notifications::status().map_err(notifications_failure)?;
    if status.is_installed() {
        // A `remove` that did not remove is a fact worth printing rather than a
        // failure to raise: what survived is what a user needs to delete by
        // hand, and the list below names it.
        print_notifications(&status, globals);
    } else {
        println!("  nothing is registered there now");
    }
    Ok(Exit::Clean)
}

/// What is registered, read back from the registry.
fn notifications_status(globals: &Globals) -> Result<Exit> {
    let status = notifications::status().map_err(notifications_failure)?;
    print_notifications(&status, globals);
    println!();
    println!(
        "  {}  this is the name and the icon, not whether a notification is shown. A toast is \
         posted and displayed on a machine where nothing has ever been registered; without this \
         key it is attributed to the program that posted it instead of to {}",
        console::style("note").dim(),
        notifications::DISPLAY_NAME
    );
    Ok(Exit::Clean)
}

/// The registration, as a person reads it.
fn print_notifications(status: &NotificationStatus, _globals: &Globals) {
    output::heading(&format!(
        "Notifications — {}",
        notification_key_line()
    ));
    println!(
        "  name       {}",
        describe_text(status.display_name.as_deref())
    );
    println!("  icon       {}", describe_text(status.icon.as_deref()));
    println!(
        "  settings   {}",
        describe_notification_settings(status)
    );
    println!();
    let state = if status.is_installed() {
        console::style("registered").green().bold().to_string()
    } else {
        console::style("not registered").yellow().bold().to_string()
    };
    println!("  state      {state}");
}

/// The full path of the registration key, for a heading.
fn notification_key_line() -> String {
    format!("{}\\{}", Hive::CurrentUser, notifications::key_path())
}

/// A registry value the key may or may not carry.
///
/// `not set` rather than an empty column: a key that is there with its values
/// deleted is a shape a half-finished install leaves behind, and a blank line
/// beside `name` would read as a bug in the report rather than as the fact it
/// is. Named apart from [`describe_value`], which says the same thing about a
/// number in Defender's keys.
fn describe_text(value: Option<&str>) -> String {
    match value {
        Some(value) => value.to_owned(),
        None => console::style("not set").yellow().to_string(),
    }
}

/// What Windows says about this account's switches for these notifications.
///
/// The distinction that matters is between "Windows has no entry, because this
/// application has never posted" and "Windows has an entry saying the user
/// turned these off". They look the same in a boolean and they are not the same
/// fact: the first is a machine where nothing has been offered yet, and a report
/// that called it muted would tell a user they had switched something off.
fn describe_notification_settings(status: &NotificationStatus) -> String {
    match (status.settings_present, status.enabled) {
        (_, Some(false)) => console::style("switched off for this account")
            .yellow()
            .bold()
            .to_string(),
        (_, Some(true)) => "on".to_owned(),
        (true, None) => "an entry with no on/off value in it".to_owned(),
        (false, None) => {
            "no entry yet — Windows writes one the first time a notification is posted".to_owned()
        }
    }
}

// -- the per-user startup entry ----------------------------------------------

/// Register the entry that starts the window when this user signs in.
fn startup_install(globals: &Globals) -> Result<Exit> {
    let status = startup::install().map_err(startup_failure)?;

    output::heading("Startup");
    println!("  registered {} — the window starts in the notification area", console::style(startup::VALUE_NAME).cyan());
    print_startup(&status, globals);
    if !status.is_installed() {
        output::warn(
            "the value was written but does not read back; the lines above say what the machine \
             holds",
        );
    }
    Ok(Exit::Clean)
}

/// Remove the entry.
///
/// One *value*, never the key: `...\CurrentVersion\Run` is where every other
/// program that starts at sign-in keeps its own entry, and deleting the key
/// would take all of them with it. See [`av_integration::startup`].
fn startup_remove(globals: &Globals) -> Result<Exit> {
    startup::remove().map_err(startup_failure)?;

    output::heading("Startup");
    println!(
        "  removed the {} value from {} — no other program's startup entry was touched",
        console::style(startup::VALUE_NAME).cyan(),
        Hive::CurrentUser
    );
    let status = startup::status().map_err(startup_failure)?;
    if status.is_installed() {
        print_startup(&status, globals);
    } else {
        println!("  nothing is registered there now");
    }
    Ok(Exit::Clean)
}

/// What the machine holds, read back from the registry.
fn startup_status(globals: &Globals) -> Result<Exit> {
    let status = startup::status().map_err(startup_failure)?;
    print_startup(&status, globals);
    println!();
    // The two things a registry read cannot answer, said where the report ends.
    // The first is about the *user's* own switch and the second about Windows
    // itself, and both are the kind of thing a user would otherwise assume from
    // a line that says "registered".
    println!(
        "  {}  nothing here removes this entry except {} · Task Manager's Startup apps list is a \
         view of the same values, and switching it off there is a decision this product respects",
        console::style("note").dim(),
        console::style("wenle integrate startup remove").cyan()
    );
    Ok(Exit::Clean)
}

/// The startup entry, as a person reads it.
fn print_startup(status: &StartupStatus, _globals: &Globals) {
    output::heading(&format!(
        "Startup — {}\\{}",
        Hive::CurrentUser,
        startup::RUN_KEY
    ));
    println!(
        "  command    {}",
        describe_text(status.command.as_deref())
    );
    if status.is_stale() {
        // The failure a `Run` entry has that no other registration here has:
        // Windows ignores an entry whose program is not there, silently, so a
        // stale path is invisible from every direction except this one.
        println!();
        println!(
            "  {}  that is not the command line this build writes. A program that has been moved \
             or deleted leaves an entry Windows ignores without saying so; {} replaces it",
            console::style("note").dim(),
            console::style("wenle integrate startup install").cyan()
        );
    }
    println!();
    let state = if status.is_installed() {
        console::style("registered").green().bold().to_string()
    } else {
        console::style("not registered").yellow().bold().to_string()
    };
    println!("  state      {state}");
}

/// A notification-registration failure, in the words the crate used.
fn notifications_failure(error: notifications::NotificationError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// A startup-registration failure, in the words the crate used.
fn startup_failure(error: startup::StartupError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// Add the verbs to Explorer's menu.
fn install(args: &ScopeArgs, globals: &Globals) -> Result<Exit> {
    let scope = resolve(args, globals);
    act(scope, Action::Install)?;

    output::heading("Shell integration");
    println!("  registered for {}", scope.describe());
    println!("  hive       {}", scope.hive());
    // The report is what is in the registry now, read back, and not a restatement
    // of what was just written. The two agree on every path that reaches this
    // line, and the point of reading is that a failure to write — a key another
    // account owns, a policy that reverts it — shows up here rather than being
    // reported as success.
    let status = shell::status(scope).map_err(report_failure)?;
    print_scope(&status, globals);
    if !status.is_complete() {
        output::warn(
            "not every location registered. Explorer offers the verb for the ones that did; \
             run this command again to finish the rest.",
        );
    }
    Ok(Exit::Clean)
}

/// Take the verbs out of Explorer's menu.
fn remove(args: &ScopeArgs, globals: &Globals) -> Result<Exit> {
    let scope = resolve(args, globals);
    act(scope, Action::Remove)?;

    output::heading("Shell integration");
    println!("  removed from {}", scope.describe());
    println!("  hive       {}", scope.hive());
    let status = shell::status(scope).map_err(report_failure)?;
    if status.is_absent() {
        println!("  nothing is registered there");
    } else {
        // A `remove` that did not remove everything is a fact worth printing
        // rather than a failure to raise: the keys are gone for three of four
        // locations and the fourth is somebody else's to delete. The list below
        // says which.
        print_scope(&status, globals);
    }
    Ok(Exit::Clean)
}

/// What is registered in one scope.
fn status(args: &ScopeArgs, globals: &Globals) -> Result<Exit> {
    let scope = resolve(args, globals);
    let status = shell::status(scope).map_err(report_failure)?;
    print_scope(&status, globals);
    hint(&status, globals);
    Ok(Exit::Clean)
}

/// What is registered in both scopes.
///
/// The command somebody runs when they do not know which scope they registered
/// in, or whether they registered at all. One scope failing to read — which a
/// machine with an unusual policy can produce — does not stop the other from
/// being reported: half an answer to "what is registered here" is worth more than
/// no answer, and the half that failed says so in its own line.
fn both(globals: &Globals) -> Result<Exit> {
    let mut read = 0usize;
    for scope in [Scope::Machine, Scope::User] {
        match shell::status(scope) {
            Ok(status) => {
                read += 1;
                print_scope(&status, globals);
                hint(&status, globals);
            }
            Err(error) => {
                output::heading(&format!("Shell integration — {scope}"));
                println!("  this scope could not be read");
                println!("  {error}");
            }
        }
    }
    if read == 0 {
        return Err(anyhow!(
            "neither half of the registry could be read, so nothing can be said about what is \
             registered on this machine"
        ));
    }

    // And the two per-user registrations, which the scopes above say nothing
    // about: neither is an Explorer verb and neither has a machine half.
    // Reported here because this is the command somebody runs when they do not
    // know what is registered on this machine, and a report that omitted two of
    // the things this product registers would be a lie by omission.
    for read in [Report::Notifications, Report::Startup] {
        match read.status(globals) {
            Ok(()) => {}
            Err(error) => {
                output::heading(read.heading());
                println!("  this could not be read");
                println!("  {error}");
            }
        }
    }
    Ok(Exit::Clean)
}

/// The two per-user registrations, for the loop in [`both`].
///
/// An enum rather than two `match` blocks because they are reported the same
/// way — print it, or say why it could not be read — and because the failure of
/// one must not stop the other, which is the rule [`both`] already follows for
/// the two scopes.
#[derive(Debug, Clone, Copy)]
enum Report {
    /// See [`notifications_status`].
    Notifications,
    /// See [`startup_status`].
    Startup,
}

impl Report {
    /// The heading to print when the status could not be read.
    fn heading(self) -> &'static str {
        match self {
            Self::Notifications => "Notifications",
            Self::Startup => "Startup",
        }
    }

    /// Print what is registered.
    fn status(self, globals: &Globals) -> Result<()> {
        match self {
            Self::Notifications => {
                let status = notifications::status().map_err(notifications_failure)?;
                print_notifications(&status, globals);
                Ok(())
            }
            Self::Startup => {
                let status = startup::status().map_err(startup_failure)?;
                print_startup(&status, globals);
                Ok(())
            }
        }
    }
}

/// Which scope the caller asked for, or the one this process can write.
///
/// The default is printed when it is taken, and only then. A user who typed
/// `--user` knows what they asked for; a user who typed neither is about to learn
/// which one they got and why, and the "why" is the elevation of the process they
/// are sitting in front of.
fn resolve(args: &ScopeArgs, globals: &Globals) -> Scope {
    match args.scope() {
        Some(scope) => scope,
        None => {
            let scope = shell::default_scope();
            if !globals.quiet {
                let elevation = if shell::is_elevated() {
                    "elevated"
                } else {
                    "not elevated"
                };
                println!(
                    "No scope given, and this prompt is {elevation}, so {scope} was chosen — \
                     {}. Use --machine or --user to say which you meant.",
                    scope.describe()
                );
            }
            scope
        }
    }
}

/// One word for which of the two things is being done, so [`act`] can be one
/// function instead of two that differ in a verb.
#[derive(Debug, Clone, Copy)]
enum Action {
    Install,
    Remove,
}

/// Run one scope-level action, turning a refusal into something a user can act
/// on.
///
/// The conversion to [`AvError`] is what makes the second arm possible. The
/// crate's own error says which key and which call; what a user needs to know is
/// whether the remedy is to elevate, which [`shell::install`] has already decided
/// before attempting anything, or to stop trying — and only the numeric code
/// distinguishes the two after the fact. A code 5 here therefore means the write
/// was refused by the *machine's* permissions rather than by this process's
/// elevation, which no amount of elevating will change.
fn act(scope: Scope, action: Action) -> Result<()> {
    let outcome = match action {
        Action::Install => shell::install(scope),
        Action::Remove => shell::remove(scope),
    };
    match outcome.map_err(AvError::from) {
        Ok(()) => Ok(()),
        Err(AvError::Win32 {
            code: ERROR_ACCESS_DENIED,
            call,
        }) => Err(anyhow!(
            "{call} was refused: the registry key already exists and this account may not change \
             it. Delete it from an account that owns it, or register for this account only with \
             `--user`."
        )),
        Err(error) => Err(error.into()),
    }
}

/// Reading the registry failed, in the words the crate used.
///
/// Separate from [`act`] because a read has no elevation remedy to offer: a
/// status that cannot be read is either a machine with an unusual policy or a
/// bug, and both are reported as what happened rather than dressed up as a
/// suggestion.
fn report_failure(error: shell::ShellError) -> anyhow::Error {
    anyhow::Error::from(AvError::from(error))
}

/// One scope's registration, as a person reads it.
fn print_scope(status: &ShellStatus, _globals: &Globals) {
    output::heading(&format!("Explorer verbs — {}", status.scope()));
    println!("  hive       {}", status.scope().hive());
    println!("  for        {}", status.scope().describe());
    println!(
        "  registered {} of {}",
        status.registered(),
        Location::ALL.len()
    );
    for entry in status.entries() {
        print_entry(entry);
    }
}

/// One location's line, with the command line it will actually run.
fn print_entry(entry: &VerbStatus) {
    let location = entry.location;
    match &entry.registration {
        Registration::Absent => {
            println!(
                "  {}  {}",
                console::style("absent    ").yellow(),
                location.describe()
            );
        }
        Registration::Incomplete { detail } => {
            println!(
                "  {}  {}",
                console::style("broken    ").red().bold(),
                location.describe()
            );
            println!("              {detail}");
        }
        Registration::Present {
            command,
            menu_text,
            icon,
        } => {
            println!(
                "  {}  {}",
                console::style("registered").green(),
                location.describe()
            );
            println!(
                "                menu  {}",
                menu_text.as_deref().unwrap_or("(none)")
            );
            println!(
                "                icon  {}",
                icon.as_deref().unwrap_or("(none)")
            );
            // The command line verbatim, and never re-derived from this
            // process's own path. It was written by whichever version of the
            // product ran `install`, possibly from a different directory, and the
            // question being answered is what Explorer will run — which is a
            // string in the registry and not a string this build would produce.
            println!("                run   {}", console::style(command).cyan());
        }
    }
    println!(
        "                key   {}",
        console::style(location.key_path()).dim()
    );
}

/// What to do next, said only when there is something to do.
fn hint(status: &ShellStatus, globals: &Globals) {
    if globals.quiet || status.is_complete() {
        return;
    }
    println!(
        "  register it with `wenle integrate shell install --{}`",
        status.scope()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ScopeArgs;

    fn args(machine: bool, user: bool) -> ScopeArgs {
        ScopeArgs { machine, user }
    }

    #[test]
    fn a_scope_flag_is_the_scope_and_neither_flag_is_the_default() {
        // The three answers the command line can give, and the third is the one
        // that has to be told apart from "user": a caller who typed no flag has
        // not chosen the current user, they have declined to choose.
        assert_eq!(args(true, false).scope(), Some(Scope::Machine));
        assert_eq!(args(false, true).scope(), Some(Scope::User));
        assert_eq!(args(false, false).scope(), None);
    }

    #[test]
    fn a_scope_that_cannot_be_read_is_not_a_clean_answer() {
        // `both` refuses to report at all when neither half could be read, which
        // is the one case where "nothing is registered" and "I could not look"
        // must not be the same output. The check is on the shape of the return,
        // since the machine's own registry is not this test's to disturb.
        let read_nothing: Result<Exit> = Err(anyhow!(
            "neither half of the registry could be read, so nothing can be said about what is \
             registered on this machine"
        ));
        assert!(read_nothing.is_err());
    }
}
