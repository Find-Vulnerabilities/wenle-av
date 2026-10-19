//! `wenle build` — compile rule sources into a `.avdb` database.
//!
//! # The refusal report is the point
//!
//! This engine refuses a rule whose constructs it does not implement, names the
//! construct, and carries on with the rest. That decision has a cost — a rule
//! that is not in the database cannot detect anything — and this command is
//! where the cost is made visible instead of paid silently. `--report` prints
//! the refusals grouped by the capability that would fix them, most common
//! first, which is a work queue ordered by how much each entry buys.
//!
//! `--strict` is the release build's flag: it turns every refusal into a
//! failure. A release whose rule set is missing rules because someone renamed a
//! module member is a release that ships a smaller product than it says.
//!
//! # Sources are read, not linked
//!
//! Every source is concatenated into one buffer before compilation, in the
//! order the arguments were given. Order matters and is not sorted: rules are
//! evaluated in the order they appear, a rule may read another's verdict, and
//! the command-line order is the only order the user controls.
//!
//! # With no arguments, the product's own rules
//!
//! A release build is `wenle build` and nothing else, so the product has to
//! know where its own rules are. Two directories can hold them and a bare
//! `wenle build` reads the first of them that has any source in it:
//!
//! 1. `AvPaths::rules_dir` — `%ProgramData%\WenleAV\rules`, the *installed*
//!    rules. `core/` holds the rules written by hand in this language,
//!    `converted/` the ones imported from an upstream package. This is what an
//!    installation that has been given rules of its own builds from, so it wins
//!    whenever it holds anything.
//! 2. `AvPaths::shipped_rules_dir` — `rules/` beside the executable, the corpus
//!    that ships with the release. Nothing copies it into the data root, so
//!    without this fallback an unpacked release would answer a fresh machine
//!    with "no rule sources" while the rules sat next to the binary saying it.
//!
//! Naming sources explicitly still overrides both — the default exists so that
//! the shipped database is reproducible from what is on the machine, not so
//! that the path becomes unspellable. The build reads the *installed* sources
//! and writes the *installed* database in the ordinary case, so a release is
//! reproducible from what is installed rather than from a checkout that happens
//! to sit beside it.
//!
//! Which directory was read is printed, because "are the rules I can see the
//! rules it used?" is a question the output should answer rather than leave to
//! a bug report. And a machine with no rules anywhere is told which directories
//! were looked in and what was wrong with them — that they are not there, or
//! that they are there and empty — rather than being told it named no sources,
//! which is a fact about the command line and would be a lie about a command
//! line that named nothing on purpose.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use av_core::paths::AvPaths;
use av_rules::database::{CompileReport, RuleDatabase};

use crate::cli::{BuildArgs, Globals};
use crate::commands::{self, Context, DATABASE_FILE};
use crate::exit::Exit;
use crate::output;
use crate::progress::human_count;

/// Extensions a rule source may have.
///
/// `yar` and `yara` are accepted alongside this product's own `avrule` because a
/// corpus written for another engine is a corpus worth compiling rather than
/// rewriting, and the language is a superset of the one those files are in.
/// Which extension a file has changes nothing about how it is read — the list
/// exists so that walking a directory picks up sources and leaves everything
/// else alone.
const SOURCE_EXTENSIONS: [&str; 3] = ["avrule", "yar", "yara"];

/// Compile rule sources into a database.
pub fn run(args: &BuildArgs, globals: &Globals, context: &Context) -> Result<Exit> {
    // An empty argument list means "the product's own rules", not "nothing".
    // The distinction is the whole reason this is not an error at the argument
    // parser: `wenle build` is what a release runs, and a release that had to
    // name its own rule directory would be a release whose command line
    // somebody can get wrong in a way nothing checks.
    let mut read_from = None;
    let installed;
    let requested: &[PathBuf] = match args.sources.is_empty() {
        true => {
            let rules = product_rules(&context.paths)?;
            read_from = Some(rules.clone());
            installed = vec![rules];
            &installed
        }
        false => &args.sources,
    };

    let sources = collect_sources(requested)?;
    if sources.is_empty() {
        // Which of the two situations this is matters to whoever reads it: a
        // directory that does not exist is an installation that never
        // happened, and one that exists but holds no sources is an
        // installation whose rules were removed.
        let names: Vec<String> = requested
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        bail!(
            "no rule sources in {} — a rule source is a file ending in {}; the \
             release runs the precompiled database in assets/rules.avdb, and \
             this command is only needed when you add sources of your own",
            names.join(" or "),
            SOURCE_EXTENSIONS.join(", "),
        );
    }

    let mut combined = String::new();
    let mut bytes = 0u64;
    // Taken here, from the bytes on disk, because this is the only moment they
    // exist: the database that comes out of the compile is a compiled thing,
    // and the text it came from is gone by the time anything wants to ask
    // whether some file on the disk *is* one of these sources. See
    // [`av_rules::database::RuleSource`] for what that question is for.
    //
    // The digest is of the file's bytes, and `read_to_string` hands back
    // exactly those bytes for a UTF-8 source — a rule file that is not UTF-8
    // does not reach this line, because the read refuses it.
    let mut recorded = Vec::with_capacity(sources.len());
    for source in &sources {
        let text = std::fs::read_to_string(source)
            .with_context(|| format!("reading {}", source.display()))?;
        recorded.push(av_rules::database::RuleSource::of(
            source
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| source.display().to_string()),
            text.as_bytes(),
        ));
        bytes += text.len() as u64;
        log::debug!("{}: {} bytes", source.display(), text.len());
        // A separator, so that a file whose last line lacks a newline cannot
        // glue its closing brace to the next file's first rule.
        combined.push_str(&text);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }

    if !globals.quiet {
        output::heading("Compiling");
        println!(
            "  {} source file{}, {}",
            human_count(sources.len() as u64),
            if sources.len() == 1 { "" } else { "s" },
            crate::progress::human_bytes(bytes),
        );
        if let Some(dir) = &read_from {
            // Printed only when the sources were not named, because then they
            // came from a directory the user did not type and cannot guess:
            // two of them are searched, and which one answered is a fact about
            // this machine rather than about the command.
            println!("  from {}", dir.display());
        }
    }

    let (database, report) = RuleDatabase::compile(&combined);
    // Recorded before anything can write the database, so that the sources
    // travel with it and a scan on a machine that has never seen this checkout
    // still knows which files are its own corpus.
    let database = database.with_sources(recorded);
    print_report(&report, args, globals);

    if args.strict && report.refused() > 0 {
        output::error(&format!(
            "{} rule{} refused; --strict does not write a database that is missing rules",
            report.refused(),
            if report.refused() == 1 { "" } else { "s" },
        ));
        return Ok(Exit::Failure);
    }
    if database.is_empty() {
        output::error("every rule was refused; there is nothing to write");
        return Ok(Exit::Failure);
    }

    let path = match &args.output {
        Some(path) => path.clone(),
        None => {
            context.paths.ensure_dirs().ok();
            context.paths.db_dir.join(DATABASE_FILE)
        }
    };
    let image = database.to_bytes()?;
    commands::write_file(&path, &image)?;

    let stats = database.stats();
    if !globals.quiet {
        output::heading("Written");
        println!(
            "  {} rules  {}  {} strings  {} hashes",
            human_count(stats.rules as u64),
            crate::progress::human_bytes(image.len() as u64),
            human_count(stats.strings as u64),
            human_count(stats.hashes as u64),
        );
        println!("  {}", path.display());
    }

    if report.refused() > 0 {
        output::warn(&format!(
            "{} rule{} refused and not in the database; `--report` says by what",
            report.refused(),
            if report.refused() == 1 { "" } else { "s" },
        ));
    }
    Ok(Exit::Clean)
}

/// The product's own rule sources, and where they were found.
///
/// The two candidates are [`AvPaths::rules_dir`] — the installed rules, which
/// is where a user's own rules go — and [`AvPaths::shipped_rules_dir`], the
/// corpus that ships beside the executable. See the module documentation for
/// why both are searched and why the installed one wins.
///
/// A candidate that cannot supply rules is not an error here. It is one
/// candidate that did not answer, and the question is whether any did: the
/// failure is reported once, at the end, against all of them together, because
/// "this one is missing" is only interesting when nothing else was found.
fn product_rules(paths: &AvPaths) -> Result<PathBuf> {
    // Deduplicated, because the two coincide in a portable layout — the data
    // root is the install directory — and a message that named one path twice
    // would read as two directories that were both tried.
    let mut candidates = vec![paths.rules_dir.clone()];
    let shipped = paths.shipped_rules_dir();
    if shipped != paths.rules_dir {
        candidates.push(shipped);
    }

    for candidate in &candidates {
        let found = collect_sources(std::slice::from_ref(candidate)).unwrap_or_default();
        if !found.is_empty() {
            return Ok(candidate.clone());
        }
    }

    let named = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ");
    // Which of the two situations this is matters to whoever reads it: a
    // directory that does not exist is an installation that never happened, and
    // one that exists but holds no sources is an installation whose rules were
    // removed. Only the first is worth calling "not installed".
    if candidates.iter().all(|path| !path.is_dir()) {
        bail!(
            "no rules are installed — {named} does not exist; name a source \
             directory, or put rule sources there and run this again"
        );
    }
    bail!(
        "no rule sources in {named} — a rule source is a file ending in {}",
        SOURCE_EXTENSIONS.join(", "),
    );
}

/// Every source file named, directly or inside a named directory.
fn collect_sources(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for path in paths {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("{} does not exist", path.display()))?;
        if metadata.is_file() {
            out.push(path.clone());
            continue;
        }
        if !metadata.is_dir() {
            bail!("{} is neither a file nor a directory", path.display());
        }
        let walker = walkdir::WalkDir::new(path)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| !is_hidden(entry.path()));
        for entry in walker {
            let entry = entry.with_context(|| format!("walking {}", path.display()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            if has_source_extension(entry.path()) {
                out.push(entry.path().to_path_buf());
            }
        }
    }
    Ok(out)
}

/// Whether a path ends in one of the rule source extensions.
fn has_source_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            SOURCE_EXTENSIONS
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
        })
}

/// Whether an entry is a dot-directory or a dot-file, which is never a source.
///
/// Skipped so that a checkout's `.git` is not walked: the alternative is
/// reading every object file in it and reporting them all as malformed.
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.') && name != ".")
}

/// The compile report, as a person reads it.
fn print_report(report: &CompileReport, args: &BuildArgs, globals: &Globals) {
    if globals.quiet && !args.report {
        // `--quiet` silences the run's commentary, but `--report` is a request
        // for it: a user who typed both asked for the report and asked not to
        // be told the routine things around it.
        return;
    }
    output::heading("Sources");
    println!("  {} rules seen", human_count(report.rules_seen as u64));
    println!(
        "  {} chunks parsed",
        human_count(report.chunks_parsed as u64)
    );
    if report.parse_failures > 0 {
        println!(
            "  {} chunk{} could not be parsed at all",
            human_count(report.parse_failures as u64),
            if report.parse_failures == 1 { "" } else { "s" }
        );
    }
    if report.chunks_malformed > 0 {
        println!(
            "  {} chunk{} had unbalanced braces and were recovered",
            human_count(report.chunks_malformed as u64),
            if report.chunks_malformed == 1 {
                ""
            } else {
                "s"
            }
        );
    }

    if report.refusals.is_empty() {
        if args.report {
            println!("  no refusals");
        }
        return;
    }

    // Grouped by capability, which is the only grouping that suggests what to
    // do next. A list of ten thousand rule names is not a report.
    output::heading("Refused, by missing capability");
    for (feature, count) in report.by_feature() {
        println!("  {:>6}  {feature}", human_count(count as u64));
    }

    if !args.report {
        return;
    }
    output::heading("Refused rules");
    // Ten of them, because the report is for a person deciding what to do next
    // and the names are examples of the groupings above, not a work list.
    for refusal in report.refusals.iter().take(10) {
        println!(
            "  {}:{}  {}\n            {}",
            style_dim(&refusal.name),
            refusal.line,
            style_cyan(refusal.feature),
            refusal.reason
        );
    }
    if report.refusals.len() > 10 {
        println!(
            "  … and {} more",
            human_count((report.refusals.len() - 10) as u64)
        );
    }

    if !report.string_refusals.is_empty() {
        output::heading("Refused strings");
        println!(
            "  {} pattern{} refused; each removed one string from a rule that is otherwise \
             in the database",
            human_count(report.string_refusals.len() as u64),
            if report.string_refusals.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for (rule, slot, reason) in report.string_refusals.iter().take(10) {
            println!("  {rule}[{slot}]  {reason}");
        }
    }
}

fn style_dim(text: &str) -> String {
    console::style(text).dim().to_string()
}

fn style_cyan(text: &str) -> String {
    console::style(text).cyan().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::config::AvConfig;

    /// A context whose whole state lives in `dir`.
    fn context(dir: &Path) -> Context {
        let paths = av_core::paths::AvPaths::with_data_dir(dir.to_path_buf(), dir.to_path_buf());
        Context {
            paths,
            config: AvConfig::default(),
        }
    }

    fn build_args(sources: Vec<PathBuf>) -> BuildArgs {
        BuildArgs {
            sources,
            output: None,
            report: false,
            strict: false,
        }
    }

    /// The one rule source these tests compile, and the rule in it.
    const SOURCE: &str = "rule t { strings: $a = \"hello\" condition: $a }\n";

    #[test]
    fn no_arguments_compiles_the_installed_rules() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        std::fs::create_dir_all(&context.paths.rules_dir).unwrap();
        std::fs::write(context.paths.rules_dir.join("a.avrule"), SOURCE).unwrap();

        let exit = run(&build_args(Vec::new()), &Globals::default(), &context).unwrap();

        assert_eq!(exit, Exit::Clean);
        // Written to the installed location, not to the working directory: the
        // default is a release build, and a release build that wrote its
        // database somewhere else would be a release nobody could ship.
        let written = context.paths.db_dir.join(DATABASE_FILE);
        assert!(written.is_file(), "{} was not written", written.display());
        let database = RuleDatabase::from_bytes(&std::fs::read(&written).unwrap()).unwrap();
        assert_eq!(database.stats().rules, 1);
    }

    #[test]
    fn no_arguments_and_no_install_says_which_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        // Deliberately not created. `AvPaths::rules_dir` is `data_dir/rules`.
        assert!(!context.paths.rules_dir.exists());

        let error = run(&build_args(Vec::new()), &Globals::default(), &context)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains(&context.paths.rules_dir.display().to_string()),
            "the directory that is missing is the whole message: {error}"
        );
        assert!(error.contains("no rules are installed"), "{error}");
    }

    #[test]
    fn no_arguments_and_an_empty_install_is_a_different_answer() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        std::fs::create_dir_all(&context.paths.rules_dir).unwrap();

        let error = run(&build_args(Vec::new()), &Globals::default(), &context)
            .unwrap_err()
            .to_string();

        // A directory that is there and holds nothing is an installation whose
        // rules were removed, which is not the same failure as one that never
        // happened, and the two are worth telling apart.
        assert!(error.contains("no rule sources in"), "{error}");
        assert!(!error.contains("does not exist"), "{error}");
    }

    /// A context whose install and data roots differ.
    ///
    /// Which is what an ordinary installation has, and what the fallback from
    /// the installed rules to the shipped corpus is about. [`context`] makes
    /// the two the same directory, which is the portable layout — a real one,
    /// but not this one.
    fn split_context(install: &Path, data: &Path) -> Context {
        let paths =
            av_core::paths::AvPaths::with_data_dir(install.to_path_buf(), data.to_path_buf());
        Context {
            paths,
            config: AvConfig::default(),
        }
    }

    #[test]
    fn no_arguments_falls_back_to_the_corpus_beside_the_executable() {
        let install = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let context = split_context(install.path(), data.path());
        // The release as it is unpacked: the corpus is there, the data root is
        // an empty directory the product has never been installed into.
        let shipped = context.paths.shipped_rules_dir().join("converted");
        std::fs::create_dir_all(&shipped).unwrap();
        std::fs::write(shipped.join("corpus.yar"), SOURCE).unwrap();

        let exit = run(&build_args(Vec::new()), &Globals::default(), &context).unwrap();

        assert_eq!(exit, Exit::Clean);
        // The database still goes to the installed location. Reading the
        // shipped tree is what makes an unpacked release detect anything;
        // writing to it would make the database a file inside the release,
        // which the next unpack would replace.
        let written = context.paths.db_dir.join(DATABASE_FILE);
        let database = RuleDatabase::from_bytes(&std::fs::read(&written).unwrap()).unwrap();
        assert_eq!(database.stats().rules, 1);
        assert!(!context
            .paths
            .shipped_rules_dir()
            .join(DATABASE_FILE)
            .exists());
    }

    #[test]
    fn the_installed_rules_win_over_the_shipped_corpus() {
        let install = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let context = split_context(install.path(), data.path());
        let shipped = context.paths.shipped_rules_dir();
        std::fs::create_dir_all(&shipped).unwrap();
        std::fs::write(
            shipped.join("corpus.yar"),
            "rule a { strings: $a = \"x\" condition: $a }\n\
             rule b { strings: $b = \"y\" condition: $b }\n",
        )
        .unwrap();
        std::fs::create_dir_all(&context.paths.rules_dir).unwrap();
        std::fs::write(context.paths.rules_dir.join("mine.avrule"), SOURCE).unwrap();

        let exit = run(&build_args(Vec::new()), &Globals::default(), &context).unwrap();

        assert_eq!(exit, Exit::Clean);
        let written = context.paths.db_dir.join(DATABASE_FILE);
        let database = RuleDatabase::from_bytes(&std::fs::read(&written).unwrap()).unwrap();
        // One rule, not two: the installed directory answered and the corpus
        // was not read. An installation whose own rules were silently joined or
        // replaced by the shipped ones would be a product that cannot be
        // configured.
        assert_eq!(database.stats().rules, 1);
        assert!(database.rules().iter().any(|rule| rule.name == "t"));
    }

    #[test]
    fn neither_directory_having_sources_names_both() {
        let install = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let context = split_context(install.path(), data.path());
        // Both exist, both hold nothing: an installation that happened and lost
        // its rules, which is why the message does not say "does not exist".
        std::fs::create_dir_all(&context.paths.rules_dir).unwrap();
        std::fs::create_dir_all(context.paths.shipped_rules_dir()).unwrap();

        let error = run(&build_args(Vec::new()), &Globals::default(), &context)
            .unwrap_err()
            .to_string();

        assert!(error.contains("no rule sources in"), "{error}");
        assert!(
            error.contains(&context.paths.rules_dir.display().to_string()),
            "{error}"
        );
        assert!(
            error.contains(&context.paths.shipped_rules_dir().display().to_string()),
            "both directories that were tried belong in the message: {error}"
        );
        assert!(!error.contains("does not exist"), "{error}");
    }

    #[test]
    fn a_named_source_still_overrides_the_install() {
        let dir = tempfile::tempdir().unwrap();
        let context = context(dir.path());
        std::fs::create_dir_all(&context.paths.rules_dir).unwrap();
        // Both exist and hold a rule, and they are different rules, so which
        // one was compiled is visible in the database rather than inferred.
        std::fs::write(context.paths.rules_dir.join("installed.avrule"), SOURCE).unwrap();
        let named = dir.path().join("named.avrule");
        std::fs::write(
            &named,
            "rule t { strings: $a = \"hello\" condition: $a }\nrule u { strings: $b = \"x\" condition: $b }\n",
        )
        .unwrap();

        let exit = run(&build_args(vec![named]), &Globals::default(), &context).unwrap();

        assert_eq!(exit, Exit::Clean);
        let database = RuleDatabase::from_bytes(
            &std::fs::read(context.paths.db_dir.join(DATABASE_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(database.stats().rules, 2);
    }
}
