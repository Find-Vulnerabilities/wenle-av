//! Development tool: parse a third-party rule set and report what failed.
//!
//! A single syntax error aborts a whole-file parse, which tells you almost
//! nothing about a 337,000-line rule set. This splits the text into individual
//! rules first, parses each one on its own, and prints a histogram of the
//! distinct failures — which is what actually drives the decision about what
//! the grammar still needs. It also counts the condition constructs the parsed
//! rules use, so the compiler can be built against real frequencies rather than
//! guesses.
//!
//! ```text
//! cargo run --release --example parse_ruleset -- path/to/rules.yar
//! ```
//!
//! Set `PARSE_WHOLE=1` to skip the split and parse the file as one unit, which
//! is what you want when investigating a single rule in isolation. Set
//! `PARSE_TRACE=1` to name each rule before parsing it — a stack overflow aborts
//! without unwinding, so the last name printed is the only clue about where it
//! happened.
//!
//! The split itself lives in `av_rules::ruleset`, shared with the compiler's
//! coverage tool, so that both agree on what one rule is.

// An example is a program whose job is to fail loudly when given bad input, so
// the panic-family lints that guard the library do not apply here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

use av_rules::ast::Expr;

fn main() -> ExitCode {
    // A bounded, deliberately ordinary stack. The parser limits nesting depth
    // and condition size, so a real rule set must fit in a stack of the size
    // the engine would actually run on — if it does not, the bounds are wrong
    // and this is where that shows up rather than in production. The earlier
    // half-gigabyte here was a workaround for unbounded recursion, and keeping
    // it would hide exactly the failure this tool exists to find.
    let handle = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawning the worker thread");
    handle.join().unwrap_or(ExitCode::FAILURE)
}

fn run() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: parse_ruleset <file.yar>");
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
    let whole = env::var_os("PARSE_WHOLE").is_some();
    let split = if whole {
        av_rules::ruleset::Split {
            chunks: vec![av_rules::ruleset::Chunk {
                line: 1,
                text: &source,
            }],
            headers: 1,
            malformed: 0,
        }
    } else {
        av_rules::ruleset::split_rule_chunks(&source)
    };
    let split_elapsed = started.elapsed();

    println!(
        "{} bytes, {} rule chunks, {} chunks the splitter could not delimit",
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
    let chunks = split.chunks;

    let mut parsed_chunks = 0usize;
    let mut rule_count = 0usize;
    let mut failures: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut constructs: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut modules: BTreeMap<String, usize> = BTreeMap::new();
    let mut parse_elapsed = std::time::Duration::ZERO;

    let trace = env::var_os("PARSE_TRACE").is_some();
    for chunk in &chunks {
        let (line, text) = (chunk.line, chunk.text);
        if trace {
            // A stack overflow aborts the process without unwinding, so the
            // only way to find the offending rule is to name it beforehand.
            eprintln!("parsing rule at line {line} ({} bytes)", text.len());
        }
        let t0 = Instant::now();
        let result = av_rules::parser::parse_file(text);
        parse_elapsed += t0.elapsed();

        match result {
            Ok(file) => {
                parsed_chunks += 1;
                rule_count += file.rules.len();
                for rule in &file.rules {
                    let mut found = BTreeSet::new();
                    walk(&rule.condition, &mut found, &mut modules);
                    for name in found {
                        *constructs.entry(name).or_default() += 1;
                    }
                }
            }
            Err(e) => {
                let entry = failures.entry(bucket(&e.message)).or_insert((0, String::new()));
                entry.0 += 1;
                if entry.1.is_empty() {
                    entry.1 = format!("line {line}: {e}");
                }
            }
        }
    }

    let failed = chunks.len().saturating_sub(parsed_chunks);
    println!("\nparsed {parsed_chunks} chunks containing {rule_count} rules");
    println!("failed {failed} chunks ({:.3}%)", percent(failed, chunks.len()));
    println!("split {split_elapsed:?}, parse {parse_elapsed:?}");

    if !failures.is_empty() {
        println!("\n=== failure histogram ===");
        let mut rows: Vec<_> = failures.into_iter().collect();
        rows.sort_by_key(|(_, (count, _))| Reverse(*count));
        for (message, (count, example)) in rows.iter().take(25) {
            println!("\n{count:>6}  {message}\n        {example}");
        }
        println!("\n{} distinct failure kinds", rows.len());
    }

    if !modules.is_empty() {
        println!("\n=== module references ===");
        let mut rows: Vec<_> = modules.into_iter().collect();
        rows.sort_by_key(|(_, count)| Reverse(*count));
        for (name, count) in rows {
            println!("{count:>7}  {name}");
        }
    }

    if !constructs.is_empty() {
        println!("\n=== condition constructs (rules using each) ===");
        let mut rows: Vec<_> = constructs.into_iter().collect();
        rows.sort_by_key(|(_, count)| Reverse(*count));
        for (name, count) in rows {
            println!("{count:>7}  {name}");
        }
    }

    ExitCode::SUCCESS
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (whole as f64)
    }
}

/// Collapse messages that differ only in the offending token, so the histogram
/// counts kinds of problem rather than kinds of character.
fn bucket(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut inside = false;
    for ch in message.chars() {
        match ch {
            '`' => {
                if !inside {
                    out.push_str("`_`");
                }
                inside = !inside;
            }
            _ if inside => {}
            _ => out.push(ch),
        }
    }
    out
}

/// Record which condition constructs a rule uses, once per rule.
fn walk(expr: &Expr, found: &mut BTreeSet<&'static str>, modules: &mut BTreeMap<String, usize>) {
    match expr {
        Expr::Bool(_) | Expr::Int(_) | Expr::Float(_) => {}
        Expr::Str(_) => {
            found.insert("string literal");
        }
        Expr::Regex { .. } => {
            found.insert("regex operand");
        }
        Expr::Filesize => {
            found.insert("filesize");
        }
        Expr::EntryPoint => {
            found.insert("entrypoint");
        }
        Expr::StringMatch(_) => {
            found.insert("$a");
        }
        Expr::StringAt(_, a) => {
            found.insert("$a at");
            walk(a, found, modules);
        }
        Expr::StringIn(_, a, b) => {
            found.insert("$a in");
            walk(a, found, modules);
            walk(b, found, modules);
        }
        Expr::StringCount(_) => {
            found.insert("#a");
        }
        Expr::StringOffset(_, i) => {
            found.insert("@a");
            if let Some(i) = i {
                walk(i, found, modules);
            }
        }
        Expr::StringLength(_, i) => {
            found.insert("!a");
            if let Some(i) = i {
                walk(i, found, modules);
            }
        }
        Expr::Of { quantifier, .. } | Expr::OfIn { quantifier, .. } => {
            found.insert("N of set");
            if let av_rules::ast::Quantifier::Count(e) = quantifier {
                found.insert("N of set given as a count");
                walk(e, found, modules);
            }
            if let Expr::OfIn { from, to, .. } = expr {
                found.insert("N of set in range");
                walk(from, found, modules);
                walk(to, found, modules);
            }
        }
        Expr::ForOf { body, .. } => {
            found.insert("for .. of");
            walk(body, found, modules);
        }
        Expr::ForIn {
            quantifier,
            from,
            to,
            body,
            ..
        } => {
            found.insert("for .. in range");
            if let av_rules::ast::Quantifier::Count(e) = quantifier {
                found.insert("for .. in with a count");
                walk(e, found, modules);
            }
            walk(from, found, modules);
            walk(to, found, modules);
            walk(body, found, modules);
        }
        Expr::ForEach {
            quantifier,
            iterable,
            body,
            ..
        } => {
            found.insert("for .. in array");
            if let av_rules::ast::Quantifier::Count(e) = quantifier {
                found.insert("for .. in with a count");
                walk(e, found, modules);
            }
            walk(iterable, found, modules);
            walk(body, found, modules);
        }
        Expr::ForOfPlaceholder => {
            found.insert("$ placeholder");
        }
        Expr::Variable(_) => {
            found.insert("loop variable");
        }
        Expr::Not(a) | Expr::Defined(a) | Expr::Negate(a) | Expr::BitNot(a) => {
            if matches!(expr, Expr::Defined(_)) {
                found.insert("defined");
            }
            walk(a, found, modules);
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            walk(a, found, modules);
            walk(b, found, modules);
        }
        Expr::Arithmetic { lhs, rhs, .. }
        | Expr::Bitwise { lhs, rhs, .. }
        | Expr::Compare { lhs, rhs, .. } => {
            if matches!(expr, Expr::Arithmetic { .. }) {
                found.insert("arithmetic");
            }
            if matches!(expr, Expr::Bitwise { .. }) {
                found.insert("bitwise");
            }
            if matches!(expr, Expr::Compare { .. }) {
                found.insert("comparison");
            }
            walk(lhs, found, modules);
            walk(rhs, found, modules);
        }
        Expr::StringOp { lhs, rhs, .. } => {
            found.insert("string operator");
            walk(lhs, found, modules);
            walk(rhs, found, modules);
        }
        Expr::Call { path, args } => {
            found.insert("function call");
            note_module(path, modules);
            for a in args {
                walk(a, found, modules);
            }
        }
        Expr::Field { path } => {
            found.insert("module field");
            note_module(path, modules);
        }
        Expr::Index { base, index } => {
            found.insert("index");
            walk(base, found, modules);
            walk(index, found, modules);
        }
    }
}

fn note_module(path: &av_rules::ast::MemberPath, modules: &mut BTreeMap<String, usize>) {
    *modules.entry(path.root.clone()).or_default() += 1;
}
