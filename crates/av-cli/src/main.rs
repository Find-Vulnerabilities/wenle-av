//! The `wenle` command-line front end.
//!
//! # What this binary is for
//!
//! Six jobs, and it is worth being explicit about them because they are
//! different products sharing a name: it is the tool an administrator uses to
//! scan a machine or a share, the tool whoever is looking at a machine that is
//! misbehaving right now uses to examine what its processes are holding in
//! memory, the tool a rule author uses to build and inspect a rule database, the
//! tool whoever is setting the product up uses to install and steer the
//! background service, the tool that puts the product into Windows itself so
//! that Explorer offers it from a right-click, and the reference implementation
//! of the engine that the service and the graphical front end are written
//! against. When the two disagree about what a scan of a file concludes, this is
//! the one that is right, because it is the one with no state of its own.
//!
//! Only `service install`, `remove`, `start` and `stop`; `integrate shell
//! install` and `remove` against the machine's half of the registry; `integrate
//! amsi install` and `remove`; `integrate defender disable` and `restore`; and
//! `integrate driver install` and `remove` change the machine they are run on.
//! All of those need administrator rights and all of them are undone by the
//! command paired with them. Every other command here reads and reports.
//!
//! # Exit codes
//!
//! A script that runs a scanner needs to know what happened without parsing
//! English, so the codes are a contract:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Nothing to act on: every target was clean, suspicious only, or skipped |
//! | 1 | At least one target is malicious |
//! | 2 | The scan could not be completed: bad arguments, no rule database, unreadable target |
//! | 3 | Nothing malicious, but something suspicious. See `--fail-on-suspicious` |
//!
//! Three is not a failure: the middle band of the verdict model
//! means "tell the user, do not touch the file", and a script that treated it
//! as one would be reacting to something the engine explicitly declined to act
//! on. A caller that wants to be stricter asks for it.
//!
//! Two commands use the same codes for their own subject rather than for a
//! scan, and both leave 1 unused because neither has anything to call
//! malicious: `wenle config` exits 2 when `config.toml` exists and could not be
//! used, and `wenle protect verify` exits 3 when the product's own files have
//! changed.

// A test that unwraps is a test whose failure message is the assertion that
// failed, not the four lines of `match` that would otherwise be needed to say
// the same thing. The same allowance every other crate in the workspace makes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cli;
mod commands;
mod exit;
mod glob;
mod memory;
mod output;
mod progress;
mod walk;

use clap::Parser;

use crate::cli::{Args, Command, Globals};
use crate::exit::Exit;

/// The system allocator, with a report written when it refuses a request.
///
/// A scan that exhausts memory does not return an error and does not unwind:
/// Rust aborts, Windows records `0xc0000409` with no reason, and the user is
/// left with "it disappeared". This puts the size asked for and the commit left
/// on stderr and in `logs/crash.log` first. See [`av_core::alloc`].
#[global_allocator]
static ALLOCATOR: av_core::alloc::Reporting = av_core::alloc::Reporting;

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    init_logging(&args);
    let globals = Globals::of(&args);
    if globals.no_color {
        // `console` already honours `NO_COLOR` and whether the stream is a
        // terminal; this is the third way to say it and the only one the
        // program has to act on itself.
        console::set_colors_enabled(false);
    }

    // `wenle config` is answered here, before the layout is turned into a
    // context, because `Context::resolve` refuses a `config.toml` this build
    // cannot parse and reporting that refusal is one of the things this command
    // exists for. It takes the paths and not the configuration, and it is the
    // only command that does; see `commands::config`.
    if let Command::Config(config) = &args.command {
        return finish(commands::config::run(
            config,
            &globals,
            args.data_dir.as_deref(),
        ));
    }

    let context = match commands::Context::resolve(args.data_dir.as_deref()) {
        Ok(context) => context,
        Err(error) => return fail(&error),
    };

    // Armed as soon as the layout is known and before any command runs, because
    // the commands that exhaust memory are the ones that load the rule database
    // and then scan. A failure here is worth a warning and not a refusal: the
    // stderr copy still lands, and a product that will not scan because it
    // could not open a log file is worse than one that scans without a log.
    if let Err(error) = av_core::set_crash_log(context.paths.log_dir.join("crash.log")) {
        output::warn(&format!(
            "cannot write {}: {error}; an out-of-memory report will go to stderr only",
            context.paths.log_dir.join("crash.log").display()
        ));
    }

    let outcome = match &args.command {
        Command::Scan(scan) => commands::scan::run(scan, &globals, &context),
        Command::Memory(memory) => commands::memory::run(memory, &globals, &context),
        Command::Build(build) => commands::build::run(build, &globals, &context),
        Command::Db(db) => commands::db::run(&db.command, &globals, &context),
        Command::Quarantine(quarantine) => {
            commands::quarantine::run(quarantine, &globals, &context)
        }
        Command::Service(service) => commands::service::run(&service.command, &globals, &context),
        Command::Integrate(integrate) => commands::integrate::run(&integrate.command, &globals, &context),
        Command::Protect(protect) => commands::protect::run(&protect.command, &globals, &context),
        // Answered above, before the context exists. Listed here so that the
        // match stays exhaustive: a command added to the enum and forgotten
        // below is a compile error rather than a command that prints nothing.
        Command::Config(_) => unreachable!("`wenle config` is dispatched before the context"),
    };

    finish(outcome)
}

/// Turn a command's outcome into the process's exit code.
///
/// One place, because `wenle config` returns from `main` before the context is
/// built and the other eight return at the end: two copies of this match is two
/// places for the codes to disagree with the table in this crate's
/// documentation.
fn finish(outcome: anyhow::Result<Exit>) -> std::process::ExitCode {
    match outcome {
        Ok(exit) => std::process::ExitCode::from(exit as u8),
        Err(error) => fail(&error),
    }
}

/// Report an error the way every command reports one, and exit with the code
/// that says the program could not do its job rather than that it found
/// something.
fn fail(error: &anyhow::Error) -> std::process::ExitCode {
    // Printed as a chain, because the interesting part of "cannot read the rule
    // database" is usually the sentence after it.
    output::error(&format!("{error:#}"));
    std::process::ExitCode::from(Exit::Failure as u8)
}

/// Turn on logging when the environment asks for it.
///
/// `RUST_LOG` is the switch, as it is for every other Rust tool, and the
/// default is quiet: a scanner that prints log lines by default is a scanner
/// whose output a script cannot read.
fn init_logging(args: &Args) {
    let default = match args.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default.to_owned());
    // Failure here means the filter string is malformed, which is the user's
    // problem to see rather than a reason not to scan.
    if let Err(e) = env_logger::Builder::new()
        .parse_filters(&filter)
        .format_timestamp_secs()
        .try_init()
    {
        let _ = e;
    }
}
