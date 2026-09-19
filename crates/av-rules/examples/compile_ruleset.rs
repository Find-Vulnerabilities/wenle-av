//! Development tool: compile a third-party rule set and report what it refused.
//!
//! Parsing a rule set tells you the grammar is complete. Compiling one tells
//! you the *engine* is complete, which is a different and much larger question:
//! a rule can parse perfectly and still be undecidable by a compiler that has
//! no `pe` module. This tool is how the gap between the two gets measured
//! instead of guessed at — it compiles every rule, buckets the refusals by
//! [`av_rules::compiler::CompileError::feature`], and prints the result in the
//! order the work should be done.
//!
//! ```text
//! cargo run --release --example compile_ruleset -- path/to/rules.yar
//! ```
//!
//! Set `COMPILE_SHOW=20` to disassemble the first twenty rules that compile,
//! which is the quickest way to see whether the code generator is emitting what
//! you think it is.
//!
//! # Reading the output
//!
//! Compiling and refusing are both correct outcomes. A refused rule does not
//! enter the database, so it can never contribute a false positive; the cost is
//! one detection that does not fire, and the refusal is counted here. What
//! would *not* be correct is compiling a construct to something that nearly
//! means the same thing — so a low refusal count is only good news if the
//! refusals are the constructs you know about.

// An example is a program whose job is to fail loudly when given bad input, so
// the panic-family lints that guard the library do not apply here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

use av_rules::compiler::{compile_rule, CompileError};
use av_rules::prefilter::{Prefilter, RuleFilter, RuleStrings};
use av_rules::ruleset;

fn main() -> ExitCode {
    // The same bounded stack the parser tool uses. Compiling recurses over the
    // same tree the parser built, so whatever stack parses a rule set must also
    // compile one.
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawning the worker thread");
    handle.join().unwrap_or(ExitCode::FAILURE)
}

fn run() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: compile_ruleset <file.yar>");
        return ExitCode::FAILURE;
    };
    let source = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let split = ruleset::split_rule_chunks(&source);
    println!(
        "{} bytes, {} rule chunks, {} the splitter could not delimit",
        source.len(),
        split.chunks.len(),
        split.malformed
    );
    if split.unaccounted() > 0 {
        // Loud, because it means rules the parser never saw. Every count below
        // would be an undercount and nothing else in the pipeline would say so.
        println!(
            "WARNING: {} `rule` headers produced no chunk — the splitter dropped rules",
            split.unaccounted()
        );
    }

    let mut rules_seen = 0usize;
    let mut compiled = 0usize;
    let mut parse_failures = 0usize;
    let mut refusals: BTreeMap<&'static str, (usize, String)> = BTreeMap::new();
    let mut descriptors = 0usize;
    let mut instructions = 0usize;
    let mut constants = 0usize;
    // Every compiled rule's strings, in rule order, so the prefilter can be
    // built from the real rule set rather than from a guess about it — along
    // with what each condition requires, which is what decides whether the
    // rule-level filter is a conjunction or a disjunction.
    let mut filters: Vec<RuleFilter> = Vec::new();
    let mut rules_without_atoms = 0usize;
    let mut string_refusals: BTreeMap<&'static str, (usize, String)> = BTreeMap::new();

    let started = Instant::now();
    let show = env::var("COMPILE_SHOW")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut shown = 0usize;

    for chunk in &split.chunks {
        let file = match av_rules::parser::parse_file(chunk.text) {
            Ok(f) => f,
            Err(_) => {
                // Counted but not bucketed: this tool is about compilation, and
                // the parser's own tool already histograms syntax errors.
                parse_failures += 1;
                continue;
            }
        };

        for rule in &file.rules {
            rules_seen += 1;
            match compile_rule(rule) {
                Ok(program) => {
                    compiled += 1;
                    descriptors += program.string_count as usize;
                    instructions += program.code.len();
                    constants += program.constants.len();

                    // The strings are compiled here as the scanner will compile
                    // them once and keep. A string the matcher refuses
                    // contributes no atoms, so its rule ends up unfiltered
                    // rather than wrongly filtered — the safe direction.
                    let rule_atoms: RuleStrings = rule
                        .strings
                        .iter()
                        .enumerate()
                        .map(|(slot, def)| match av_rules::matcher::compile(def, slot as u32) {
                            Ok(compiled) => compiled.atoms(),
                            Err(e) => {
                                let entry = string_refusals
                                    .entry(e.feature.unwrap_or("invalid string"))
                                    .or_insert_with(|| (0, String::new()));
                                entry.0 += 1;
                                if entry.1.is_empty() {
                                    entry.1 = format!("{}: {}", rule.name, e.message);
                                }
                                av_rules::atoms::StringAtoms::none()
                            }
                        })
                        .collect();
                    if rule_atoms.iter().all(|atoms| atoms.is_empty()) {
                        rules_without_atoms += 1;
                    }
                    filters.push(RuleFilter {
                        strings: rule_atoms,
                        required: program.required_strings.clone(),
                    });

                    if shown < show {
                        shown += 1;
                        println!(
                            "\n--- {} (line {}) — {} strings, {} instructions, \
                             depth {} steps, stack {}",
                            rule.name,
                            chunk.line,
                            program.string_count,
                            program.code.len(),
                            program.max_steps,
                            program.max_stack
                        );
                        print!("{}", program.disassemble());
                    }
                }
                Err(e) => {
                    let entry = refusals
                        .entry(e.feature)
                        .or_insert_with(|| (0, String::new()));
                    entry.0 += 1;
                    if entry.1.is_empty() {
                        entry.1 = describe(rule, &e, chunk.line);
                    }
                }
            }
        }
    }

    let elapsed = started.elapsed();
    let percent = |part: usize| {
        if rules_seen == 0 {
            0.0
        } else {
            (part as f64) * 100.0 / (rules_seen as f64)
        }
    };

    println!("\n=== compilation ===");
    println!("{rules_seen:>7} rules seen");
    println!(
        "{compiled:>7} compiled ({:.2}%), {parse_failures} chunks failed to parse",
        percent(compiled)
    );
    // `.max(1)` rather than a guard: with nothing compiled there are no
    // averages to report, and zero is the honest-looking answer that keeps this
    // line from being a division by zero.
    let per_rule = compiled.max(1) as f64;
    println!(
        "{:>7.1} instructions per rule, {:.1} constants, {:.2} strings",
        instructions as f64 / per_rule,
        constants as f64 / per_rule,
        descriptors as f64 / per_rule
    );
    println!("compiled in {elapsed:?}");

    if !refusals.is_empty() {
        let refused: usize = refusals.values().map(|(n, _)| n).sum();
        println!(
            "\n=== refusals: {refused} rules ({:.2}%) ===",
            percent(refused)
        );
        let mut rows: Vec<_> = refusals.into_iter().collect();
        rows.sort_by_key(|(_, (count, _))| Reverse(*count));
        for (feature, (count, example)) in &rows {
            println!("\n{count:>6}  ({:.2}%)  {feature}\n        {example}", percent(*count));
        }
        println!("\n{} distinct features to implement", rows.len());
    }

    if !string_refusals.is_empty() {
        let refused: usize = string_refusals.values().map(|(n, _)| n).sum();
        println!("\n=== string refusals: {refused} strings ===");
        let mut rows: Vec<_> = string_refusals.into_iter().collect();
        rows.sort_by_key(|(_, (count, _))| Reverse(*count));
        for (feature, (count, example)) in &rows {
            println!("{count:>6}  {feature}\n        {example}");
        }
    }

    report_prefilter(&filters, rules_without_atoms);

    ExitCode::SUCCESS
}

/// Build the prefilter from the real rule set and say what it would do.
///
/// This is the number that decides whether the engine is usable. A prefilter
/// that selects most of the rule set on every file has bought nothing, and the
/// only way to know which way it went is to build one out of the rules that
/// actually ship and measure it against a buffer.
fn report_prefilter(filters: &[RuleFilter], rules_without_atoms: usize) {
    let started = Instant::now();
    let prefilter = Prefilter::build(filters);
    let stats = prefilter.stats();
    println!("\n=== prefilter ===");
    println!(
        "{:>7} rules, {rules_without_atoms} with no usable atom, built in {:?}",
        stats.rules,
        started.elapsed()
    );
    println!(
        "{:>7} distinct atoms ({:.1} per rule), {} case-insensitive",
        stats.atoms,
        stats.atoms as f64 / stats.rules.max(1) as f64,
        stats.case_insensitive_atoms
    );
    if stats.rules > 0 {
        println!(
            "{:>7} rules unfilterable ({:.2}%) — evaluated on every file",
            stats.unfiltered_rules,
            stats.unfiltered_rules as f64 * 100.0 / stats.rules as f64
        );
    }

    // How many rules the prefilter selects for buffers of each kind. Real
    // files are neither all-zero nor random, so the useful figure is the
    // middle one: text-like data is the hardest case for a signature engine,
    // because a rule set is full of ASCII strings and a file full of ASCII
    // will trip some of them no matter what.
    let mut scratch = prefilter.scratch();
    let mut out = Vec::new();
    let zeros = vec![0u8; 1 << 20];
    let text: Vec<u8> = (0..1usize << 20)
        .map(|i| b"the quick brown fox jumps over the lazy dog. "[i % 45])
        .collect();
    // A cheap deterministic pseudo-random buffer, so the run is reproducible.
    let mut state = 0x2545F491_4F6CDD1Du64;
    let random: Vec<u8> = (0..1usize << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();

    for (name, buffer) in [
        ("1 MiB of zeros", &zeros),
        ("1 MiB of text", &text),
        ("1 MiB random", &random),
    ] {
        // Timed over several runs and reported as the best, because the first
        // pass over a freshly allocated megabyte pays for the page faults and
        // says nothing about the automaton. The best run is the one closest to
        // the steady state the scanner will actually be in.
        let mut best = std::time::Duration::MAX;
        for _ in 0..5 {
            let started = Instant::now();
            prefilter.candidates(buffer, &mut scratch, &mut out);
            best = best.min(started.elapsed());
        }
        let selected = out.len();
        let percent = selected as f64 * 100.0 / stats.rules.max(1) as f64;
        let throughput = buffer.len() as f64 / best.as_secs_f64() / 1e6;
        println!(
            "{selected:>7} rules selected for {name} ({percent:.2}%) in \
             {best:?} ({throughput:.0} MB/s)"
        );
    }
}

/// One line naming the rule and one naming the construct at fault.
fn describe(rule: &av_rules::ast::Rule, e: &CompileError, line: usize) -> String {
    format!("{} (line {line}): {}", rule.name, e.message)
}
