//! `wenle config` — the configuration in force, and what this build does with it.
//!
//! # The hole this fills
//!
//! `av-service` has always known which of `AvConfig`'s keys it acts on and which
//! it does not. That answer is assembled into an [`av_ipc::ConfigReport`] and
//! sent to whoever asks — and until now nobody could ask. It went out over the
//! control pipe to the graphical front end and to no command-line verb at all,
//! so the table existed, was maintained, and was readable only by a program that
//! renders none of it.
//!
//! The cost of that is specific and was paid twice. A key that reads as a
//! protection and does nothing — `driver.fail_closed` is the standing example —
//! is invisible to a user, and the disclosure table is the only thing that knows
//! it. And the table itself drifted: on 2026-10-10 all five `logging.*` entries
//! were found to be describing a product that does not exist, `logging.level`
//! among them promising that a restart would make it take effect when nothing
//! reads the key at all. A table nothing can read is a table nothing can catch.
//!
//! So this is the reader. It prints the two lists with their reasons, which is
//! the whole of what the service knows about the configuration and the user does
//! not.
//!
//! # Why the default is the values rather than the lists
//!
//! `--check` is a question about the configuration and the listing is the
//! configuration, so the listing is what the bare verb does. The two share a
//! header — the file, and whether it parsed — because a reader has to know which
//! of the two documents they are looking at before either answer means anything.
//!
//! # Why this is the one command that runs on an unparseable file
//!
//! Every other command stops at [`Context::resolve`], which refuses a
//! `config.toml` this build cannot read. That is right for them: a scan has to
//! know what the configuration asks for. It would be exactly wrong here. The
//! case this command exists for is a user who edited a key, saw no error, and
//! believes something is on — and the sharpest form of that is a file with a
//! typo in it, where nothing at all is in force and the product is running on
//! the defaults. [`av_service::config::load`] is the tolerant reader the service
//! itself uses, and it turns that into a fact to report.
//!
//! [`Context::resolve`]: super::Context::resolve

use std::path::Path;

use anyhow::Result;
use av_ipc::ConfigReport;
use av_service::config;

use crate::cli::{ConfigArgs, Globals};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;

/// Run `wenle config`.
pub fn run(args: &ConfigArgs, globals: &Globals, data_dir: Option<&Path>) -> Result<Exit> {
    // The layout, not the [`Context`]: `Context::resolve` reads the
    // configuration and refuses one it cannot parse, which is the single case
    // this command has to survive. See this module's documentation.
    let paths = Context::paths(data_dir)?;
    let report = config::report(&config::load(&paths));

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(exit_for(&report));
    }

    output::heading("Configuration");
    println!("  file  {}", paths.config_file.display());
    match &report.load_error {
        None if paths.config_file.is_file() => println!("  read  yes"),
        // Not an error and not a failure: this is the documented state of a
        // fresh installation, where the defaults are the configuration the user
        // has agreed to by not writing one.
        None => println!("  read  no file — the defaults below are in force"),
        Some(error) => {
            // The error goes on lines of its own rather than after the word.
            // A `toml` parse failure is several lines — the position, the line
            // of the file, a caret under it — and one whose first line was
            // appended to `read  NO —` would have its remaining lines printed
            // flush against the left margin, which reads as four separate
            // statements rather than one message.
            println!("  read  {}", console::style("NO").red().bold());
            for line in error.lines() {
                println!("        {line}");
            }
            println!("        nothing above describes that file: what is in force is the default");
            println!("        configuration, which is rarely what its author intended");
        }
    }

    if args.check {
        for line in disclosure_lines(&report) {
            println!("{line}");
        }
    } else {
        output::heading("In force");
        // Printed through `toml` and not reformatted by hand, so that what a
        // user reads here is byte-for-byte what `save` writes and can be pasted
        // back into the file. It is the whole document with the defaults filled
        // in, which is the difference between this and the file the user wrote.
        print!("{}", toml::to_string_pretty(&report.config)?);
        if !globals.quiet {
            println!("\n`wenle config --check` says which of these keys this build acts on.");
        }
    }

    Ok(exit_for(&report))
}

/// The exit code.
///
/// A file that exists and could not be used is the one failure this verb
/// reports, because it means what is running is not what its author wrote.
///
/// Not the unhonoured list. Every configuration this product ships with leaves
/// keys nothing acts on, so a check that failed on those would fail on a correct
/// installation, and a code that is always 2 is a code a script cannot branch on.
/// Which keys is a fact in the output, not in the exit status.
fn exit_for(report: &ConfigReport) -> Exit {
    if report.load_error.is_some() {
        Exit::Failure
    } else {
        Exit::Clean
    }
}

/// The two lists, as the lines a person reads.
///
/// Split from [`run`] so that the layout can be asserted without capturing a
/// process's standard output, which is the same split [`output::finding_lines`]
/// makes and for the same reason.
pub fn disclosure_lines(report: &ConfigReport) -> Vec<String> {
    let mut lines = Vec::new();

    // "Not in force as written" rather than the wire field's own description,
    // because the report's first list is two lists folded into one: settings
    // nothing reads, and settings this build reads at its next start. Both are
    // "not what you wrote, running now", and the reason is what tells them
    // apart — see `av_service::config::report`.
    lines.push(output::heading_line(&format!(
        "Not in force as written ({})",
        report.unhonoured.len()
    )));
    for disclosure in &report.unhonoured {
        lines.push(format!("  {}", console::style(&disclosure.setting).cyan()));
        lines.push(format!("      {}", disclosure.reason));
    }
    lines.push(String::new());
    lines.push(
        "        A reason that says \"restart\" is a setting this build does read, at its next"
            .to_string(),
    );
    lines.push("        start. The rest are not read by anything in this build.".to_string());

    lines.push(output::heading_line(&format!(
        "Acted on by another part of the product ({})",
        report.handled_elsewhere.len()
    )));
    for disclosure in &report.handled_elsewhere {
        lines.push(format!("  {}", console::style(&disclosure.setting).cyan()));
        lines.push(format!("      {}", disclosure.reason));
    }

    if report.unhonoured.is_empty() && report.handled_elsewhere.is_empty() {
        // Unreachable while the tables are non-empty, and written out anyway:
        // two headings with nothing under them read as a report that failed to
        // gather anything, which is the one thing this command must never look
        // like.
        lines.push(String::new());
        lines.push("  every key in this configuration is in force as written.".to_string());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_ipc::SettingDisclosure;

    fn report(load_error: Option<&str>) -> ConfigReport {
        ConfigReport {
            config: Box::new(av_core::AvConfig::default()),
            load_error: load_error.map(str::to_owned),
            unhonoured: vec![SettingDisclosure::new("driver.fail_closed", "a no-op")],
            handled_elsewhere: vec![SettingDisclosure::new("ui.window_width", "the window")],
        }
    }

    #[test]
    fn a_file_that_could_not_be_used_is_the_only_failure() {
        // The 2 is a contract with whatever script is running this: it has to
        // mean "the configuration you wrote is not the one running" and nothing
        // else. A key nothing acts on is a fact about the build and is true of
        // every installation, so it must not be able to produce this code — a
        // check that fails on a correct machine is a check nobody can use.
        assert_eq!(exit_for(&report(None)), Exit::Clean);
        assert_eq!(exit_for(&report(Some("unknown field `scann`"))), Exit::Failure);

        // And the clean case is not an accident of the fixture: the default
        // configuration really does leave keys unhonoured.
        let default = config::report(&config::load(&av_core::AvPaths::with_data_dir(
            std::env::temp_dir(),
            std::env::temp_dir(),
        )));
        assert!(!default.unhonoured.is_empty());
        assert_eq!(exit_for(&default), Exit::Clean);
    }

    #[test]
    fn both_lists_are_printed_with_their_reasons() {
        // The reason is the whole content of the answer. "This key does
        // nothing" without saying what is missing leaves a user with nothing to
        // do next, which is how the `logging.*` entries stayed wrong for as long
        // as they did.
        let text = disclosure_lines(&report(None)).join("\n");
        for fragment in [
            "Not in force as written",
            "driver.fail_closed",
            "a no-op",
            "Acted on by another part of the product",
            "ui.window_width",
            "the window",
        ] {
            assert!(text.contains(fragment), "{fragment} is missing from:\n{text}");
        }
        // The one thing the first heading cannot say on its own, because the
        // report folds the restart list into it.
        assert!(text.contains("restart"), "{text}");
    }

    #[test]
    fn the_counts_are_the_counts() {
        let mut small = report(None);
        small.unhonoured.push(SettingDisclosure::new("scanning.x", "y"));
        let text = disclosure_lines(&small).join("\n");
        assert!(text.contains("Not in force as written (2)"), "{text}");
        assert!(
            text.contains("Acted on by another part of the product (1)"),
            "{text}"
        );
    }

    #[test]
    fn the_check_flag_is_parsed_and_defaults_to_off() {
        // The listing is the default and `--check` is the widening, so a bare
        // `wenle config` must not silently be the check.
        let parsed = <crate::cli::Args as clap::Parser>::parse_from(["wenle", "config"]);
        let crate::cli::Command::Config(args) = parsed.command else {
            unreachable!("the fixture asks for the configuration")
        };
        assert!(!args.check, "a bare `wenle config` is the listing");
        assert!(!args.json);

        let parsed = <crate::cli::Args as clap::Parser>::parse_from(["wenle", "config", "--check"]);
        let crate::cli::Command::Config(args) = parsed.command else {
            unreachable!("the fixture asks for the configuration")
        };
        assert!(args.check, "--check asks for the disclosure table");
    }

    #[test]
    fn the_json_document_carries_more_than_the_check_prints() {
        // `--json` is the machine's copy of the whole report, so a script does
        // not have to know that `--check` exists. Pinned because the two
        // together are the shape most likely to be quietly narrowed to whatever
        // the human rendering happens to use.
        let text = serde_json::to_string_pretty(&report(Some("bad"))).expect("a document");
        for fragment in ["load_error", "unhonoured", "handled_elsewhere", "bad"] {
            assert!(text.contains(fragment), "{fragment} is missing from:\n{text}");
        }
    }
}
