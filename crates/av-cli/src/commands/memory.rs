//! `wenle memory`: examining running processes, and dealing with what it finds.
//!
//! # Why this is a command of its own
//!
//! Because it answers a question no file scan can, and because the question
//! comes up at moments when there is no directory to point at. `wenle scan
//! --memory <path>` sweeps memory as part of a file scan; this sweeps it
//! without walking anything. A user who has just watched something misbehave
//! wants `wenle memory --pid 4242`, not a scan of a directory chosen to satisfy
//! an argument parser.
//!
//! # What it does with what it finds
//!
//! A finding is attributed to a process and an address. What is *dealt with* is
//! the file the bytes came from, when there is one and when that file is
//! malicious in its own right — and the decision, and the reason for it, live in
//! [`av_service::memory`] rather than here, because the service makes the same
//! decision about the same findings and two implementations of a threshold are
//! two different thresholds. See [`crate::memory::Chain`] for the carrying out.
//!
//! # What it does not do, said here rather than discovered from a report
//!
//! It does not stop anything. By the time this runs the process is running, and
//! a match in its memory is a fact about a program that has already started.
//! Nothing here terminates a process either: what a finding is *about* is
//! evidence, and the answer to evidence in a running program is the file that
//! put it there, not the death of whatever happened to be holding it. Both of
//! those are stated in the output too, at the end, so that a user who reads a
//! clean report does not conclude that they are continuously protected.

use std::time::Instant;

use anyhow::Result;
use av_memory::MemoryScanConfig;

use crate::cli::{Globals, MemoryArgs};
use crate::commands::scan::build_engine;
use crate::commands::Context;
use crate::exit::Exit;
use crate::memory;
use crate::output;

/// Examine processes, act on what the findings point at, and report.
pub fn run(args: &MemoryArgs, globals: &Globals, context: &Context) -> Result<Exit> {
    let (database, path) = context.load_database(args.db.as_deref())?;
    let count = database.len();

    // The options are the configuration's, not a set of flags this command does
    // not have. A file examined because a memory finding pointed at it is
    // examined the way this machine is configured to examine files — including
    // the size ceiling and the trust rules — so that a file taken from here is
    // taken on the same evidence a scan would have taken it on. The engine is
    // built by the same function the file scan uses, for the same reason: two
    // engines would be two answers to what a file's verdict is.
    let options = context.config.scan_options();
    let engine = build_engine(database, context, &options, args.json, true);
    log::info!("loaded {count} rules from {}", path.display());

    let started = Instant::now();
    let report = match args.pid {
        Some(pid) => memory::scan_one(&engine, pid, MemoryScanConfig::default()),
        None => memory::scan_machine(&engine, MemoryScanConfig::default()),
    };
    let elapsed = started.elapsed();

    let mut chain = memory::Chain::build(&report, &engine, &context.paths, &options);
    if args.quarantine && chain.to_take() > 0 {
        // Opened only now, and only because there is something to put in it: a
        // vault that is opened for nothing creates a directory and, on a machine
        // that has never quarantined anything, a master key.
        let mut vault = context.open_vault(None)?;
        let taken = chain.carry_out(&mut vault);
        log::info!("{taken} file(s) taken into the vault because of a memory finding");
    }

    if args.json {
        let document = serde_json::json!({
            "tool": "wenle",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": { "path": path.display().to_string(), "count": count },
            "memory": memory::json(&report, elapsed, Some(&chain)),
        });
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        memory::print_section(&report, elapsed, globals.quiet, Some(&chain));
        if !globals.quiet {
            print_scope(args);
        }
    }

    Ok(Exit::from_verdicts(
        [report.verdict()],
        args.fail_on_suspicious,
    ))
}

/// What this command covered, and what it therefore cannot claim.
///
/// Printed after the section and suppressed by `--quiet`, which is exactly the
/// class of message `--quiet` means: the findings are the answer, and this is
/// the caveat that keeps the absence of findings from being read as an absence
/// of threats. It is written out on every run rather than only on an incomplete
/// one, because the sentence a user needs is not "this one was partial" but
/// "this kind of check is always a snapshot".
fn print_scope(args: &MemoryArgs) {
    let subject = match args.pid {
        Some(pid) => format!("process {pid}"),
        None => "every process this account can open".to_string(),
    };
    output::warn(&format!(
        "this examined the memory of {subject}, as it was while the scan ran. It is a snapshot: \
         it does not watch for anything starting, and nothing was stopped. Memory that could not \
         be read is counted above and is not a clean result."
    ));
}
