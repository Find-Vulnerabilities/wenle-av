//! Does the filtering change any verdict? Two scanners, one answer.
//!
//! Every filter in this engine is an optimization that trades a proof for time,
//! and each one can lose a detection if the proof is wrong: the atom is claimed
//! to be a window of the string, the trailer to be implied by any match, the
//! automaton to have seen every occurrence. The proofs are sound as written —
//! but a proof is only as good as its premises, and a false negative is the one
//! failure an antivirus cannot have. It reports a file as clean when it is not,
//! and nothing downstream will ever notice.
//!
//! So the conclusion is checked against the data instead. Each file is scanned
//! twice:
//!
//! - the ordinary way, with the prefilter choosing candidates, refuting strings
//!   and handing over witness offsets;
//! - by [`Scanner::unfiltered`], which believes every rule is a candidate and
//!   every string may be present, so nothing is decided by a filter.
//!
//! The two must agree on every reported match — the rule *and* where each of its
//! strings was found. Comparing only the rule would miss a string-level mistake
//! that did not change the verdict of that rule, and the string offsets are what
//! `at`, `in` and the `#` counts are computed from.
//!
//! ```text
//! cargo run --release --example verify_filters -- path/to/rules.yar [files...]
//! ```
//!
//! This is slow by construction and meant to be. The unfiltered pass searches
//! for every string of every rule, which is exactly the work the prefilter
//! exists to avoid — on a rule set of this size and a file of a megabyte it is
//! minutes, not milliseconds. Run it after any change to the prefilter, the
//! atoms or the matchers, on files small enough to finish: the verdicts it
//! compares are per file, so a handful of real binaries is a real test.
//!
//! Exit code is `FAILURE` if any file is reported differently, so this can be
//! run unattended.
//!
//! # Files to pass
//!
//! Anything already on the machine, and preferably both kinds:
//!
//! - **clean system binaries** — the false-negative direction. These are large,
//!   full of ASCII, and full of the library code that hundreds of rules are
//!   about, so they exercise every path in the prefilter. A filter that drops a
//!   real match shows up here as the unfiltered scanner finding something the
//!   filtered one did not.
//! - **known malware** — the same test from the other side, and the one that
//!   matters most in production. Any sample from a public corpus will do; the
//!   files are never executed, only read.

// A development tool whose job is to fail loudly on bad input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use av_rules::database::RuleDatabase;
use av_rules::matches::MatchSet;
use av_rules::scanner::Scanner;

/// Real binaries to check when none are named. Deliberately the small ones: the
/// unfiltered pass costs a search per string per rule, so its time is the
/// buffer size times sixty thousand, and a run that does not finish verifies
/// nothing.
const CANDIDATES: &[&str] = &[
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\kernel32.dll",
];

fn main() -> ExitCode {
    // Parsing and compiling a 17 MB rule set recurses over a deep expression
    // tree, so it gets the same bounded stack the other tools use.
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawning the worker thread");
    handle.join().unwrap_or(ExitCode::FAILURE)
}

/// One reported match, reduced to what must be identical between the two scans.
type Finding = (u32, MatchSet);

fn run() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: verify_filters <rules.yar> [files...]");
        return ExitCode::FAILURE;
    };
    let source = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let started = Instant::now();
    let (database, report) = RuleDatabase::compile(&source);
    println!(
        "{} rules compiled from {} seen ({} refused) in {:?}",
        database.len(),
        report.rules_seen,
        report.refused(),
        started.elapsed()
    );

    let files: Vec<PathBuf> = {
        let given: Vec<PathBuf> = args.map(PathBuf::from).collect();
        if given.is_empty() {
            CANDIDATES
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .collect()
        } else {
            given
        }
    };
    if files.is_empty() {
        eprintln!("no files to check; pass some as arguments");
        return ExitCode::FAILURE;
    }

    let mut filtered = Scanner::new(&database);
    let mut unfiltered = Scanner::unfiltered(&database);
    let mut disagreements = 0usize;
    let mut total_matched = 0usize;

    for file in &files {
        let Ok(data) = fs::read(file) else {
            println!("  {:<24} unreadable, skipped", short(file));
            continue;
        };
        let (agreed, matched) = compare(&database, &mut filtered, &mut unfiltered, &short(file), &data);
        disagreements += usize::from(!agreed);
        total_matched += matched;
    }

    // The real files are the right data, but on a clean machine they match
    // nothing, and two empty results agreeing proves very little. So the rule
    // set's own text is scanned as well: it contains the literal of every rule
    // in it, so most rules find themselves, the matchers run for real, and the
    // offsets they report are compared rather than assumed.
    for (name, slice) in source_slices(&source) {
        let (agreed, matched) = compare(&database, &mut filtered, &mut unfiltered, &name, slice);
        disagreements += usize::from(!agreed);
        total_matched += matched;
    }

    println!();
    if total_matched == 0 {
        println!(
            "nothing matched anywhere in this run, so the two scans were only \
             compared on empty results — this proves almost nothing"
        );
        return ExitCode::FAILURE;
    }
    if disagreements == 0 {
        println!("agreement everywhere; the filters changed no verdict");
        ExitCode::SUCCESS
    } else {
        println!(
            "{disagreements} checks disagree — a filter is unsound, and the \
             timings above are beside the point"
        );
        ExitCode::FAILURE
    }
}

/// Scan one buffer both ways and say whether they agreed, and how much matched.
fn compare(
    database: &RuleDatabase,
    filtered: &mut Scanner<'_>,
    unfiltered: &mut Scanner<'_>,
    name: &str,
    data: &[u8],
) -> (bool, usize) {
    let started = Instant::now();
    let fast = filtered.scan(data);
    let fast_time = started.elapsed();
    let started = Instant::now();
    let slow = unfiltered.scan(data);
    let slow_time = started.elapsed();

    let ours = findings(&fast);
    let theirs = findings(&slow);
    let same = ours == theirs;

    println!("\n  {name}  ({} bytes)", data.len());
    println!(
        "    filtered   {:>6} candidates, {:>5} evaluated, {:>4} matched  ({fast_time:?})",
        fast.candidates,
        fast.evaluated,
        ours.len()
    );
    println!(
        "    unfiltered {:>6} candidates, {:>5} evaluated, {:>4} matched  ({slow_time:?})",
        slow.candidates,
        slow.evaluated,
        theirs.len()
    );
    println!(
        "    the prefilter saved {:.1}x the time for the same answer",
        slow_time.as_secs_f64() / fast_time.as_secs_f64().max(f64::MIN_POSITIVE)
    );
    if fast.matcher_failures > 0 || slow.matcher_failures > 0 {
        println!(
            "    WARNING: a matcher gave up early ({} filtered, {} unfiltered) — \
             this result means nothing until that is fixed",
            fast.matcher_failures, slow.matcher_failures
        );
    }

    if same {
        println!(
            "    agree: {} reported matches, same rules and same offsets",
            ours.len()
        );
        return (true, ours.len());
    }

    // A difference is a bug in a filter, and which way it went says which one:
    // a rule the unfiltered scan found and the filtered one did not is a lost
    // detection and the serious case.
    for (rule, strings) in &theirs {
        if !ours.iter().any(|(r, _)| r == rule) {
            println!(
                "    MISSED  {} — the unfiltered scan matched it",
                rule_name(database, *rule)
            );
            println!("            with strings {strings:?}");
        }
    }
    for (rule, strings) in &ours {
        match theirs.iter().find(|(r, _)| r == rule) {
            None => println!(
                "    EXTRA   {} — only the filtered scan matched it",
                rule_name(database, *rule)
            ),
            Some((_, other)) if other != strings => {
                println!(
                    "    DIFFER  {} — same rule, different offsets",
                    rule_name(database, *rule)
                );
                describe_slots(strings, other);
            }
            Some(_) => {}
        }
    }
    (false, ours.len())
}

/// Which slots differ, and by how much.
///
/// Printing both match sets whole is hundreds of offsets and buries the answer.
/// What a person needs is which slot, how many matches each scan found, and one
/// offset that only one of them has — enough to go and look at the bytes.
fn describe_slots(filtered: &MatchSet, unfiltered: &MatchSet) {
    for slot in 0..filtered.string_count().max(unfiltered.string_count()) as u32 {
        let ours = filtered.matches(slot);
        let theirs = unfiltered.matches(slot);
        if ours == theirs {
            continue;
        }
        println!(
            "            slot {slot}: filtered {} matches, unfiltered {}",
            ours.len(),
            theirs.len()
        );
        let only = theirs
            .iter()
            .map(|m| m.offset)
            .find(|offset| !ours.iter().any(|m| m.offset == *offset));
        if let Some(offset) = only {
            println!("              the filtered scan missed the match at {offset}");
        }
        let extra = ours
            .iter()
            .map(|m| m.offset)
            .find(|offset| !theirs.iter().any(|m| m.offset == *offset));
        if let Some(offset) = extra {
            println!("              and reported one at {offset} that is not there");
        }
    }
}

/// Slices of the rule source, as buffers to scan.
///
/// The whole file would be better and is too slow to search unfiltered, so it
/// is taken in pieces from different places: one near the start, one from the
/// middle. The rule set is alphabetical, so a slice of it is a coherent family
/// of rules rather than a random sample, and two slices a rule set apart cover
/// two different families.
fn source_slices(source: &str) -> Vec<(String, &[u8])> {
    const SLICE: usize = 1 << 20;
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    for (name, start) in [("rules (first MiB)", 0usize), ("rules (middle MiB)", bytes.len() / 2)] {
        let start = start.min(bytes.len());
        let end = (start + SLICE).min(bytes.len());
        // Cut on a line boundary so the buffer is text rather than half a
        // literal: a torn string at the seam is noise, not a test.
        let end = match bytes[end..].iter().position(|b| *b == b'\n') {
            Some(offset) if end + offset < bytes.len() => end + offset,
            _ => end,
        };
        if end > start {
            out.push((name.to_string(), &bytes[start..end]));
        }
    }
    out
}

/// The reported matches of a scan, in a fixed order so the two can be compared.
///
/// Sorted by rule index because the two scans visit rules in different orders —
/// the filtered one in whatever order the prefilter selected them — and the
/// comparison is about the set, not the sequence.
fn findings(outcome: &av_rules::scanner::ScanOutcome) -> Vec<Finding> {
    let mut out: Vec<Finding> = outcome
        .reportable()
        .map(|m| (m.rule, m.strings.clone()))
        .collect();
    out.sort_by_key(|(rule, _)| *rule);
    out
}

fn rule_name(database: &RuleDatabase, rule: u32) -> String {
    database
        .rule(rule)
        .map_or_else(|| format!("#{rule}"), |r| r.name.clone())
}

/// The file name alone, so the column stays readable.
fn short(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
