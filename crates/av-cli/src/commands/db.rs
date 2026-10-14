//! `wenle db` — inspect a rule database without scanning anything.
//!
//! # Why a database needs inspecting at all
//!
//! Because "which rules am I running" is the first question of every support
//! case and every false-positive report, and the answer is not visible from the
//! outside: a `.avdb` is one binary blob, the product may hold several, and the
//! one a scan used is whichever the search order found first. So a database can
//! be named — which is what makes this work on one someone emailed, and on a
//! developer's freshly built one rather than the installed one — and with none
//! named it resolves through `Context::database_path`, the same search the
//! scanner performs, so a bare `db info` answers for the database a bare `scan`
//! would really use. `db list` answers the follow-up: "and does it contain a
//! rule for *this*".

use std::cmp::Reverse;
use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use av_core::{Severity, ThreatCategory};
use av_rules::database::RuleDatabase;

use crate::cli::{DbCommand, Globals};
use crate::commands::Context;
use crate::exit::Exit;
use crate::output;
use crate::progress::human_count;

/// Run a `db` subcommand.
///
/// The database is resolved here, once, for both subcommands and before either
/// of them runs. `Context::database_path` is the same search the scanner does —
/// the data directory first, then beside the executable — so a bare `db info`
/// reports on the database a bare `scan` would actually use, rather than on a
/// second guess at where it might be. That matters more than it sounds: the
/// whole reason to inspect a database is to find out what the product is
/// running, and answering from a different file than the scanner reads would be
/// a confident wrong answer.
pub fn run(command: &DbCommand, globals: &Globals, context: &Context) -> Result<Exit> {
    match command {
        DbCommand::Info { file } => info(&context.database_path(file.as_deref())?, context),
        DbCommand::List {
            file,
            limit,
            category,
        } => list(
            &context.database_path(file.as_deref())?,
            *limit,
            category.as_deref(),
            globals,
        ),
    }
}

/// Summarise a database.
fn info(file: &std::path::Path, context: &Context) -> Result<Exit> {
    let database = load(file)?;
    let stats = database.stats();

    output::heading("Rule database");
    println!("  {}", file.display());
    let size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
    println!(
        "  {} on disk  {} rules",
        crate::progress::human_bytes(size),
        human_count(stats.rules as u64),
    );

    output::heading("Contents");
    println!("  {} patterns compiled", human_count(stats.strings as u64));
    println!(
        "  {} exact-match hashes in {} rules",
        human_count(stats.hashes as u64),
        human_count(stats.rules_with_hashes as u64),
    );
    // The count of rules that declare a severity is deliberately not printed.
    // It was informative while the engine gave every rule the same default and
    // the number told you how many rules had been thought about; now that
    // calibration derives a severity for every rule that carries an author's
    // score, the count is the rule count and says nothing. The distribution
    // that replaced it is below, under `By severity`.
    println!(
        "  {} rules are decisive on their own",
        human_count(stats.decisive_rules as u64),
    );
    if stats.private_rules > 0 {
        println!(
            "  {} private rules (usable by other rules, never reported)",
            human_count(stats.private_rules as u64)
        );
    }
    if stats.global_rules > 0 {
        println!(
            "  {} global rules (they gate whether the rest are evaluated)",
            human_count(stats.global_rules as u64)
        );
    }
    if stats.matcher_refusals > 0 {
        // Not an error at load time: the rule is present and its other strings
        // still match. It is a number worth seeing because it is the only trace
        // a refused *string* leaves, and the compile report that explained it is
        // long gone by the time someone asks.
        output::warn(&format!(
            "{} patterns were refused when this database was compiled and are not being \
             matched; recompile the sources with `wenle build --report` to see why",
            human_count(stats.matcher_refusals as u64),
        ));
    }

    scores(&database, context);
    categories(&database);
    Ok(Exit::Clean)
}

/// What the database's own scores say about the thresholds in force.
///
/// This is the table a person reads when a scan is too noisy or too quiet, and
/// it is here rather than in a document because the numbers depend on the rule
/// set and the configuration together: the same database against a stricter
/// configuration can have no rule at all that condemns a file on its own.
fn scores(database: &RuleDatabase, context: &Context) {
    let thresholds = &context.config.scanning.thresholds;
    let profile = database.profile(thresholds);
    if database.is_empty() {
        return;
    }
    let total = database.len();

    output::heading("By severity");
    for severity in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let count = profile.at(severity);
        if count == 0 {
            continue;
        }
        println!(
            "  {:>6}  {:>5.1}%  {}",
            human_count(count as u64),
            (count as f64) * 100.0 / total as f64,
            severity.as_str(),
        );
    }
    if profile.observations > 0 {
        // Called out separately because it is the one severity with a promise
        // attached, and a reader who has not written a rule will not know that.
        println!(
            "  {} of those score nothing and never reach a verdict on their own",
            human_count(profile.observations as u64),
        );
    }

    output::heading("By score");
    for (score, count) in &profile.by_score {
        println!(
            "  {:>6}  {:>5.1}%  score {score}",
            human_count(*count as u64),
            (*count as f64) * 100.0 / total as f64,
        );
    }

    output::heading("Against the thresholds in force");
    println!(
        "  suspicious at {}   malicious at {}",
        thresholds.suspicious, thresholds.malicious
    );
    // The two numbers this whole table exists for. Stated as a share of the
    // database, because "9,814 rules" says nothing until it is read next to how
    // many rules there are — and phrased as what one match does, because that
    // is the decision the number actually informs.
    println!(
        "  a single match by {} rules ({:.1}%) puts a file in the suspicious band",
        human_count(profile.alone_suspicious as u64),
        (profile.alone_suspicious as f64) * 100.0 / total as f64,
    );
    println!(
        "  a single match by {} rules ({:.1}%) puts it in the malicious band",
        human_count(profile.alone_malicious as u64),
        (profile.alone_malicious as f64) * 100.0 / total as f64,
    );
    if profile.alone_malicious_by_decree > 0 {
        // Named separately because these are the rules whose score does *not*
        // explain the line above, and a reader comparing the two counts would
        // otherwise find they do not add up.
        println!(
            "    {} of those are decisive: their author marked them as the answer on their \
             own, so the score is not what condemns the file",
            human_count(profile.alone_malicious_by_decree as u64),
        );
    }
    if profile.alone_malicious_open_to_argument > 0 {
        // The other route to a single-match conviction, and not the same claim:
        // a rating is the author saying "stop looking", and a reading is this
        // product's own opinion about the rule — its title, or the shape of its
        // condition. Only the rating survives a proven publisher, so a reader
        // looking at how much of the database convicts on its own is entitled to
        // know how much of that is this product's reading rather than an
        // author's rating.
        println!(
            "    {} of those convict on a *reading* of the rule rather than on its author's \
             rating — its title, or a condition nothing ordinary satisfies — so a file whose \
             publisher is proven answers them",
            human_count(profile.alone_malicious_open_to_argument as u64),
        );
    }
}

/// What the database can detect, by category.
fn categories(database: &RuleDatabase) {
    let mut counts: BTreeMap<ThreatCategory, usize> = BTreeMap::new();
    for rule in database.rules() {
        if let Some(category) = rule.metadata.category {
            *counts.entry(category).or_insert(0) += 1;
        }
    }
    if counts.is_empty() {
        return;
    }
    let mut rows: Vec<(ThreatCategory, usize)> = counts.into_iter().collect();
    rows.sort_by_key(|(_, count)| Reverse(*count));

    output::heading("By category");
    let total = database.len().max(1);
    for (category, count) in rows.iter().take(20) {
        // The share as well as the count: whether the database is mostly
        // ransomware rules or mostly adware rules is the thing a person is
        // actually asking when they read this table.
        let share = (*count as f64) * 100.0 / total as f64;
        println!(
            "  {:>6}  {:>5.1}%  {category}",
            human_count(*count as u64),
            share,
        );
    }
}

/// List rules.
fn list(
    file: &std::path::Path,
    limit: usize,
    category: Option<&str>,
    globals: &Globals,
) -> Result<Exit> {
    let database = load(file)?;
    let wanted = category.map(|name| name.to_ascii_lowercase());

    let mut shown = 0usize;
    let mut matching = 0usize;
    for rule in database.rules() {
        if let Some(wanted) = &wanted {
            // Against the category's tag, case-insensitively, so that
            // `--category Ransomware` and `--category ransomware` both work and
            // the user does not have to know which spelling is canonical.
            let matches = rule
                .metadata
                .category
                .is_some_and(|category| category.as_str().eq_ignore_ascii_case(wanted));
            if !matches {
                continue;
            }
        }
        matching += 1;
        if shown >= limit {
            continue;
        }
        shown += 1;
        print_rule(rule);
    }

    if globals.quiet {
        // The rules are the answer and the totals are commentary, so `--quiet`
        // drops the commentary and keeps the answer.
        return Ok(Exit::Clean);
    }
    output::heading("Listed");
    if matching == 0 {
        println!("  no rules matched");
    } else if matching > shown {
        println!(
            "  {} of {} rules shown; raise --limit to see the rest",
            human_count(shown as u64),
            human_count(matching as u64),
        );
    } else {
        println!("  {} rules", human_count(matching as u64));
    }
    Ok(Exit::Clean)
}

/// One rule, as one block.
fn print_rule(rule: &av_rules::database::CompiledRule) {
    let severity = rule.metadata.effective_severity();
    let tag = if rule.private {
        " (private)"
    } else if rule.global {
        " (global)"
    } else {
        ""
    };
    println!(
        "\n  {}  {}  {}{}",
        console::style(&rule.name).cyan(),
        console::style(severity.as_str()).bold(),
        console::style(format!("score {}", rule.metadata.score())).dim(),
        console::style(tag).dim(),
    );
    if let Some(description) = &rule.metadata.description {
        println!("    {description}");
    }
    let mut facts = Vec::new();
    if let Some(category) = rule.metadata.category {
        facts.push(format!("category {category}"));
    }
    if rule.metadata.decisive {
        facts.push("decisive".to_owned());
    }
    if !rule.metadata.hashes.is_empty() {
        facts.push(format!("{} hash(es)", rule.metadata.hashes.len()));
    }
    facts.push(format!("{} strings", rule.defs.len()));
    println!("    {}", console::style(facts.join("  ·  ")).dim());
}

/// Read a database, with the file named in any error.
///
/// A `.avdb` is a compiled artefact and carries no record of what was refused
/// while building it; the reasons belong to the sources, which is why `build
/// --report` exists. The one number that survives is the count of refused
/// patterns in [`av_rules::database::DatabaseStats`], and `db info` prints it.
fn load(file: &std::path::Path) -> Result<RuleDatabase> {
    RuleDatabase::load(file).with_context(|| format!("loading {}", file.display()))
}
