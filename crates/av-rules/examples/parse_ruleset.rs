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
//! # Why the split is line-based
//!
//! Tracking brace depth would need to know about regex literals, because
//! `/ab{2}/` contains a brace that is not a block delimiter. Every rule set in
//! practice writes one rule per block with the closing brace alone on a line,
//! so splitting on `rule`-header lines and `^}` lines is both simpler and more
//! reliable. The splitter verifies its own work: chunks that do not begin with
//! `rule` and end with `}` are counted and reported rather than parsed.

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
    let (chunks, malformed) = if env::var_os("PARSE_WHOLE").is_some() {
        (vec![(1usize, source.as_str())], 0usize)
    } else {
        split_rules(&source)
    };
    let split_elapsed = started.elapsed();

    println!(
        "{} bytes, {} rule chunks, {malformed} chunks the splitter could not delimit",
        source.len(),
        chunks.len()
    );

    let mut parsed_chunks = 0usize;
    let mut rule_count = 0usize;
    let mut failures: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut constructs: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut modules: BTreeMap<String, usize> = BTreeMap::new();
    let mut parse_elapsed = std::time::Duration::ZERO;

    let trace = env::var_os("PARSE_TRACE").is_some();
    for (line, text) in &chunks {
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

/// Split into `(starting line number, rule text)` pairs.
///
/// A hex string closes with a brace alone on a line — `        }` — which is
/// character-for-character what a rule's closing brace looks like. Taking that
/// for the end of the rule truncates it: the remaining strings and the whole
/// `condition:` block vanish, and the fragment that survives parses as a rule
/// that is simply missing its condition. So the splitter tracks whether it is
/// inside a hex block and only a brace outside one ends the rule.
fn split_rules(source: &str) -> (Vec<(usize, &str)>, usize) {
    let mut chunks = Vec::new();
    let mut malformed = 0usize;
    let mut start: Option<(usize, usize)> = None; // (line, byte offset)
    let mut in_hex = false;

    // `str::lines` yields subslices of `source`, so a line's distance from the
    // start of the source is just its pointer difference. That is how each
    // chunk gets a byte range without re-scanning for offsets.
    let base = source.as_ptr() as usize;

    for (index, line) in source.lines().enumerate() {
        let line_no = index.saturating_add(1);
        let line_offset = line.as_ptr() as usize - base;
        let trimmed = line.trim();

        if start.is_none() {
            if is_rule_header(line.trim_start()) {
                start = Some((line_no, line_offset));
            }
            continue;
        }

        if in_hex {
            if trimmed == "}" {
                in_hex = false;
            }
            continue;
        }

        // `$a = {` opens a hex block, and so does `$a = { 4D 5A` with the body
        // already begun. Hex bodies hold only hex digits, wildcards, brackets
        // and parentheses — never braces — so an unbalanced brace on a line
        // that names a string can only be the start of one.
        if trimmed.contains('$') && line.matches('{').count() > line.matches('}').count() {
            in_hex = true;
            continue;
        }

        if trimmed != "}" {
            continue;
        }

        let (from_line, offset) = start.take().expect("checked by `start.is_some()`");
        let text = &source[offset..line_offset + line.len()];
        // A rule without a `condition:` section is not a rule. Checking for one
        // turns any truncation this splitter still gets wrong into a counted
        // failure rather than a silently mis-parsed rule.
        if text.trim_start().contains("rule ") && text.trim_end().ends_with('}') && has_condition(text)
        {
            chunks.push((from_line, text));
        } else {
            malformed += 1;
        }
    }
    (chunks, malformed)
}

/// True when some line of the rule opens a `condition:` section.
fn has_condition(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        t.strip_prefix("condition").is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

/// True for `rule name : tags` and its `private`/`global` prefixes.
fn is_rule_header(trimmed: &str) -> bool {
    let mut rest = trimmed;
    loop {
        if let Some(r) = rest.strip_prefix("private") {
            rest = r.trim_start();
        } else if let Some(r) = rest.strip_prefix("global") {
            rest = r.trim_start();
        } else {
            break;
        }
    }
    let Some(rest) = rest.strip_prefix("rule") else {
        return false;
    };
    // The name must follow, so `rulex` is not a header.
    matches!(rest.chars().next(), Some(c) if c.is_whitespace())
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
