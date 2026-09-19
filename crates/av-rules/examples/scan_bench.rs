//! Development tool: the whole pipeline, against real files.
//!
//! `compile_ruleset` reports what the compiler refused and how selective the
//! prefilter is. This reports what a scan actually costs — the number that
//! decides whether the engine is usable — by loading a real rule set, scanning
//! real binaries, and breaking the time down by stage.
//!
//! ```text
//! cargo run --release --example scan_bench -- path/to/rules.yar [more files...]
//! ```
//!
//! Any files given after the rule set are scanned. With none, it scans a few
//! system binaries, which is the right test data for an antivirus: real
//! executables are large, full of ASCII, full of the library code that a rule
//! set has hundreds of rules about, and — for a clean machine — full of nothing
//! that should be detected.
//!
//! # What to look at
//!
//! `rules selected` is the prefilter's selectivity: the fraction of the rule set
//! that survives to be evaluated. `strings refuted` against `strings searched`
//! is the second filter, and on a clean file the first should dwarf the second.
//! If `rules selected` is not a small percentage, nothing downstream matters,
//! because every rule reaches the interpreter on every file.

// A development tool whose job is to fail loudly on bad input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use av_rules::database::RuleDatabase;
use av_rules::scanner::Scanner;

/// Real binaries, in preference order. The first few that exist are used.
const CANDIDATES: &[&str] = &[
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\wininet.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\cmd.exe",
];

/// How many real binaries to scan. Enough to cover a few hundred megabytes of
/// the kind of data the product will actually meet, without the run taking
/// longer than the numbers are worth.
const BINARIES: usize = 6;

fn main() -> ExitCode {
    // Parsing and compiling a 17 MB rule set recurses over a deep expression
    // tree, so it gets the same bounded stack the other tools use.
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawning the worker thread");
    handle.join().unwrap_or(ExitCode::FAILURE)
}

fn run() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: scan_bench <rules.yar> [files...]");
        return ExitCode::FAILURE;
    };
    let source = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // -- compile ------------------------------------------------------------

    let started = Instant::now();
    let (database, report) = RuleDatabase::compile(&source);
    let compile_time = started.elapsed();

    println!("=== rule set ===");
    println!(
        "{:>7} rules seen, {} compiled ({:.2}%), {} refused",
        report.rules_seen,
        database.len(),
        percent(database.len(), report.rules_seen),
        report.refused()
    );
    println!("        compiled in {compile_time:?}");
    let stats = database.stats();
    println!(
        "{:>7} strings, {} unavailable to the matcher",
        stats.strings, stats.matcher_refusals
    );
    println!(
        "{:>7} private, {} global, {} decisive, {} carry hashes ({} hashes)",
        stats.private_rules, stats.global_rules, stats.decisive_rules,
        stats.rules_with_hashes, stats.hashes
    );
    let prefilter = database.prefilter().stats();
    println!(
        "{:>7} atoms, {} rules unfilterable ({:.2}%)",
        prefilter.atoms,
        prefilter.unfiltered_rules,
        percent(prefilter.unfiltered_rules, prefilter.rules)
    );

    // -- the database file ---------------------------------------------------

    let bytes = database.to_bytes().expect("serialising the database");
    println!("\n=== database ===");
    println!(
        "{:>7} bytes on disk ({:.2} bytes per rule)",
        bytes.len(),
        bytes.len() as f64 / database.len().max(1) as f64
    );
    let started = Instant::now();
    let reloaded = RuleDatabase::from_bytes(&bytes).expect("loading the database");
    let load_time = started.elapsed();
    println!(
        "{:>7} rules reloaded in {load_time:?} — {:.2}x the cost of compiling, \
         which is what a service pays once at startup",
        reloaded.len(),
        load_time.as_secs_f64() / compile_time.as_secs_f64()
    );

    let mut scanner = Scanner::new(&database);

    // -- synthetic buffers ---------------------------------------------------

    println!("\n=== synthetic buffers, 1 MiB ===");
    let zeros = vec![0u8; 1 << 20];
    let text: Vec<u8> = (0..1usize << 20)
        .map(|i| b"the quick brown fox jumps over the lazy dog. "[i % 45])
        .collect();
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let random: Vec<u8> = (0..1usize << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();

    for (name, buffer) in [
        ("zeros", &zeros),
        ("text", &text),
        ("random", &random),
    ] {
        let (best, outcome) = time_scan(&mut scanner, buffer);
        report_scan(name, buffer.len(), best, &outcome, database.len());
        if outcome.detected() {
            print_detections(&outcome, &database);
        }
    }

    // -- real binaries -------------------------------------------------------

    let files: Vec<PathBuf> = {
        let given: Vec<PathBuf> = args.map(PathBuf::from).collect();
        if given.is_empty() {
            CANDIDATES
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .take(BINARIES)
                .collect()
        } else {
            given
        }
    };

    if files.is_empty() {
        println!("\nno test binaries found; pass some as arguments");
        return ExitCode::SUCCESS;
    }

    println!("\n=== real binaries ===");
    let mut total_bytes = 0usize;
    let mut total_time = Duration::ZERO;
    let mut detections = 0usize;
    for file in &files {
        let Ok(data) = fs::read(file) else {
            println!("  {:<40} unreadable, skipped", short(file));
            continue;
        };
        let (best, outcome) = time_scan(&mut scanner, &data);
        report_scan(&short(file), data.len(), best, &outcome, database.len());
        if outcome.detected() {
            print_detections(&outcome, &database);
            detections += 1;
        }
        total_bytes += data.len();
        total_time += best;
    }

    if total_time > Duration::ZERO {
        let throughput = total_bytes as f64 / total_time.as_secs_f64() / 1e6;
        println!(
            "\n{:>7} bytes in {total_time:?} — {throughput:.0} MB/s across {} files",
            total_bytes,
            files.len()
        );
    }
    // On a clean machine this must be zero. A non-zero count here is the
    // measurement that matters most, and it is the reason to scan real binaries
    // rather than only synthetic buffers.
    println!("{detections} of {} files detected", files.len());

    ExitCode::SUCCESS
}

/// The best of several runs, to leave out the first pass's page faults.
fn time_scan(scanner: &mut Scanner<'_>, data: &[u8]) -> (Duration, av_rules::scanner::ScanOutcome) {
    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..3 {
        let started = Instant::now();
        let outcome = scanner.scan(data);
        best = best.min(started.elapsed());
        last = Some(outcome);
    }
    (best, last.expect("at least one run"))
}

fn report_scan(
    name: &str,
    len: usize,
    elapsed: Duration,
    outcome: &av_rules::scanner::ScanOutcome,
    rules: usize,
) {
    let throughput = len as f64 / elapsed.as_secs_f64() / 1e6;
    println!(
        "\n  {name}  ({len} bytes, {throughput:.0} MB/s, {elapsed:?})",
    );
    println!(
        "    {:>6} candidates ({:.2}% of the rule set), {} evaluated, {} matched",
        outcome.candidates,
        percent(outcome.candidates, rules),
        outcome.evaluated,
        outcome.matches.len()
    );
    let strings = outcome.strings_searched + outcome.strings_refuted;
    println!(
        "    {:>6} strings searched, {} refuted by atoms ({:.0}% avoided)",
        outcome.strings_searched,
        outcome.strings_refuted,
        percent(outcome.strings_refuted, strings)
    );
    if outcome.global_gate_failed {
        println!("    global gate failed — no rule was considered");
    }
    if outcome.vm_failures > 0 {
        println!("    WARNING: {} rules could not be evaluated", outcome.vm_failures);
    }
}

fn print_detections(outcome: &av_rules::scanner::ScanOutcome, database: &RuleDatabase) {
    for matched in outcome.reportable() {
        let Some(rule) = database.rule(matched.rule) else {
            continue;
        };
        let severity = rule.metadata.effective_severity();
        println!(
            "      DETECTED {} ({}, score {}, decisive {})",
            rule.name,
            severity.as_str(),
            rule.metadata.score(),
            rule.metadata.decisive
        );
    }
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

/// The file name alone, so the column stays readable.
fn short(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
