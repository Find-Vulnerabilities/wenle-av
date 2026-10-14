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
//! Four filters, in the order a file meets them, each reported so the next one
//! has something to be measured against:
//!
//! - **candidates** — the prefilter's selectivity, as a fraction of the rule
//!   set. This is the filter that matters most, because a rule that survives
//!   here reaches the interpreter.
//! - **strings refuted** against **strings searched and swept** — the per-string
//!   handover. On a clean file the refuted count should dwarf the rest.
//! - **strings swept** against **strings searched** — of the strings that were
//!   not refuted, how many the literal sweep answered from the one pass it makes
//!   over the buffer before any rule is looked at. Each of those is a search the
//!   scan did not run, which is the whole of what the sweep is for: without it
//!   the cost of a scan is `strings × file size`, and with it the per-string
//!   term is gone for every literal in the rule set.
//! - **strings located** against **strings searched** — of the strings still
//!   searched for, how many the prefilter's atom offsets placed without a pass
//!   over the buffer. This applies only when every occurrence of the string's
//!   atom was kept, and only to a string with one form, so a low number here is
//!   the honest answer about how much the shortcut buys on this file.
//!
//! Each scan also reports its split between the prefilter, the sweep, and
//! everything after them. They have different fixes and the aggregate timing
//! cannot tell them apart, so optimizing without the split is guessing.
//!
//! `matcher failures` is not a performance number. It counts strings the
//! matcher gave up on before finishing its search, which is a correctness
//! signal: a non-zero count means detections may have been missed, and it must
//! be read before any timing.

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
        stats.private_rules,
        stats.global_rules,
        stats.decisive_rules,
        stats.rules_with_hashes,
        stats.hashes
    );
    let prefilter = database.prefilter().stats();
    println!(
        "{:>7} atoms, {} rules unfilterable ({:.2}%)",
        prefilter.atoms,
        prefilter.unfiltered_rules,
        percent(prefilter.unfiltered_rules, prefilter.rules)
    );
    // How much of the rule set the condition analysis could say anything about.
    // This is the ceiling on both the conjunctive selection and the scanner's
    // early bail-out, and it is the number that decides whether either is worth
    // more work: a rule whose condition is `any of them` can never be made
    // selective by reasoning about its strings.
    println!(
        "{:>7} rules conjunctive ({:.2}%), demanding {} strings between them",
        prefilter.conjunctive_rules,
        percent(prefilter.conjunctive_rules, prefilter.rules),
        prefilter.required_strings
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

    for (name, buffer) in [("zeros", &zeros), ("text", &text), ("random", &random)] {
        let timing = time_scan(&mut scanner, &database, buffer);
        report_scan(name, buffer.len(), &timing, database.len());
        if timing.outcome.detected() {
            print_detections(&timing.outcome, &database);
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
        let timing = time_scan(&mut scanner, &database, &data);
        report_scan(&short(file), data.len(), &timing, database.len());
        if timing.outcome.detected() {
            print_detections(&timing.outcome, &database);
            detections += 1;
        }
        total_bytes += data.len();
        total_time += timing.scan;
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

/// What one scan cost, and what it did.
struct Timing {
    /// Best of three, to leave out the first pass's page faults.
    scan: Duration,
    /// The prefilter's own pass, measured by calling it the way the scanner
    /// does. Without this split the timings say the scan is dominated by "string
    /// searches", which is a guess: the automaton visits every atom match in the
    /// buffer, and on a large binary that is millions of them. Which part is the
    /// cost decides what to optimize next, so it is measured rather than reasoned
    /// about.
    prefilter: Duration,
    /// The literal sweep's own pass, measured the same way. It runs inside
    /// `scan`, so it is a part of `scan` rather than something beside it.
    sweep: Duration,
    /// Row entries the sweep recorded, before deduplication — one per string per
    /// occurrence. The half of the sweep's cost that is not the pass itself, and
    /// the number that says whether a short literal common in real files is
    /// making the pass expensive.
    swept_hits: usize,
    outcome: av_rules::scanner::ScanOutcome,
}

/// The best of several runs, to leave out the first pass's page faults.
fn time_scan(scanner: &mut Scanner<'_>, database: &RuleDatabase, data: &[u8]) -> Timing {
    let prefilter = {
        let mut scratch = database.prefilter().scratch();
        let mut out = Vec::new();
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let started = Instant::now();
            database
                .prefilter()
                .candidates(data, &mut scratch, &mut out);
            best = best.min(started.elapsed());
        }
        best
    };

    let (sweep, swept_hits) = {
        // The hit table is made once and reused, as the scanner reuses its own,
        // so what is measured is the pass and the rows it writes rather than the
        // allocation of a table sized for every string in the rule set.
        let mut hits = database.sweep().hits();
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let started = Instant::now();
            database.sweep().run(data, &mut hits);
            best = best.min(started.elapsed());
        }
        (best, hits.found())
    };

    let mut best = Duration::MAX;
    let mut last = None;
    for _ in 0..3 {
        let started = Instant::now();
        let outcome = scanner.scan(data);
        best = best.min(started.elapsed());
        last = Some(outcome);
    }
    Timing {
        scan: best,
        prefilter,
        sweep,
        swept_hits,
        outcome: last.expect("at least one run"),
    }
}

fn report_scan(name: &str, len: usize, timing: &Timing, rules: usize) {
    let Timing {
        scan: elapsed,
        prefilter,
        sweep,
        swept_hits,
        outcome,
    } = timing;
    let (elapsed, prefilter, sweep) = (*elapsed, *prefilter, *sweep);
    let throughput = len as f64 / elapsed.as_secs_f64() / 1e6;
    println!("\n  {name}  ({len} bytes, {throughput:.0} MB/s, {elapsed:?})",);
    println!(
        "    {prefilter:?} in the prefilter ({:.0}%), {sweep:?} in the sweep ({:.0}%), \
         {:?} after them",
        percent_f(prefilter, elapsed),
        percent_f(sweep, elapsed),
        elapsed.saturating_sub(prefilter + sweep)
    );
    println!(
        "    {:>6} candidates ({:.2}% of the rule set), {} evaluated, {} matched",
        outcome.candidates,
        percent(outcome.candidates, rules),
        outcome.evaluated,
        outcome.matches.len()
    );
    // The three ways a string can be settled without a search, plus the search,
    // so the column adds up to what a rule actually asked for.
    let strings = outcome.strings_searched + outcome.strings_refuted + outcome.strings_swept;
    println!(
        "    {:>6} strings searched, {} refuted by atoms, {} swept ({:.0}% avoided)",
        outcome.strings_searched,
        outcome.strings_refuted,
        outcome.strings_swept,
        percent(outcome.strings_refuted + outcome.strings_swept, strings)
    );
    println!(
        "    {:>6} sweep hits recorded before dedup, from one pass over the whole buffer",
        swept_hits
    );
    println!(
        "    {:>6} of those searched located by a unique atom ({:.0}%), {} searched the long way",
        outcome.strings_localized,
        percent(outcome.strings_localized, outcome.strings_searched),
        outcome.strings_searched - outcome.strings_localized
    );
    if outcome.global_gate_failed {
        println!("    global gate failed — no rule was considered");
    }
    // Not a performance number: the matcher reports giving up before its search
    // finished, and a scan that reports it may have missed a detection. Printed
    // whenever it is non-zero so a timing run cannot quietly hide it.
    if outcome.matcher_failures > 0 {
        println!(
            "    WARNING: {} strings were not searched to the end — detections may be missing",
            outcome.matcher_failures
        );
    }
    if outcome.vm_failures > 0 {
        println!(
            "    WARNING: {} rules could not be evaluated",
            outcome.vm_failures
        );
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

/// The same, for a duration measured against a duration.
fn percent_f(part: Duration, whole: Duration) -> f64 {
    if whole.is_zero() {
        0.0
    } else {
        part.as_secs_f64() * 100.0 / whole.as_secs_f64()
    }
}

/// The file name alone, so the column stays readable.
fn short(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
