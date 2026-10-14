//! Where a loaded rule database's memory goes, counted field by field.
//!
//! This module exists because "the antivirus uses 350 MB" is not a fact anyone
//! can act on. It walks a loaded [`RuleDatabase`] and adds up the bytes each
//! part of it holds — the rule headers, the string definitions, the bytecode,
//! the compiled matchers and the regex parse trees beside them — so that the
//! total can be attributed to structures instead of to a hypothesis.
//!
//! # What it counts, and what it cannot
//!
//! Every number here is a **lower bound on what the allocator was asked for**,
//! not a measure of what the process holds: it counts `Vec` capacity and
//! `String` capacity where those are known, and it deliberately does not model
//! the allocator's own per-allocation overhead, which on this platform is
//! roughly sixteen bytes each and which the size-class histogram in
//! `tests/memory_probe.rs` supplies instead.
//!
//! One part is missing on purpose. A compiled `regex::bytes::Regex` keeps its
//! program behind a private box and exposes nothing that reports its size, so
//! the bytes it holds are *not* in this table. They are what remains when this
//! table is subtracted from the measured total, and that is the reading to take
//! from the two together rather than either one alone.
//!
//! # Why it is a feature
//!
//! It is off by default. Nothing in the product calls it, and it exists for the
//! same reason `tests/memory_probe.rs` does: to answer a question about memory
//! with a measurement. Build it with `--features memory-probe`.

use std::mem::size_of;

use crate::database::{CompiledRule, RuleDatabase, RuleMetadata};
use crate::matcher::{CompiledString, Kind};
use crate::program::{Const, Program};

/// Bytes held by each part of a database.
///
/// All of these are the heap the part owns, not the size of the value itself,
/// except where a name says otherwise. They are meant to be added up and
/// compared with a measured total.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Parts {
    /// The `Vec<CompiledRule>` itself: one fixed-size header per rule.
    pub rule_headers: usize,
    /// Rule names.
    pub names: usize,
    /// Rule tag lists.
    pub tags: usize,
    /// Metadata strings, which include every rule's description.
    pub metadata: usize,
    /// The string definitions (`CompiledRule::defs`).
    pub defs: usize,
    /// The hex token trees inside those definitions, which `defs` also counts
    /// as part of its own per-entry header.
    pub def_hex_tokens: usize,
    /// The literal bytes in text definitions.
    pub def_text: usize,
    /// The regex body and flag text in regex definitions.
    pub def_regex_text: usize,
    /// Rule bytecode.
    pub program_code: usize,
    /// Rule constants, including the byte strings they hold.
    pub program_constants: usize,
    /// The `Vec<CompiledString>` headers, one per string.
    pub matcher_headers: usize,
    /// String identifiers inside the compiled matchers.
    pub matcher_ids: usize,
    /// Literal bytes in compiled matchers, the `wide`, `xor` and `base64`
    /// expansions included.
    pub matcher_literal_bytes: usize,
    /// Hex token trees in compiled matchers. These are a second copy of the
    /// definitions' trees, because `Pattern::compile` clones them.
    pub matcher_hex_tokens: usize,
    /// Regex parse trees (`regex_syntax::hir::Hir`) kept beside the compiled
    /// regexes so the prefilter can ask which bytes a pattern requires.
    pub matcher_hir: usize,
    /// Source file names and digests.
    pub sources: usize,
}

impl Parts {
    /// Everything this table attributes, added up.
    pub fn total(&self) -> usize {
        self.rule_headers
            + self.names
            + self.tags
            + self.metadata
            + self.defs
            + self.def_hex_tokens
            + self.def_text
            + self.def_regex_text
            + self.program_code
            + self.program_constants
            + self.matcher_headers
            + self.matcher_ids
            + self.matcher_literal_bytes
            + self.matcher_hex_tokens
            + self.matcher_hir
            + self.sources
    }
}

/// How many of each kind of thing the database holds, so that a byte count can
/// be read per item as well as in total.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub rules: usize,
    pub strings: usize,
    pub literal_strings: usize,
    pub hex_strings: usize,
    pub regex_strings: usize,
    pub literal_forms: usize,
}

/// Load a database the way the product did before [`RegexCache`] existed: every
/// string compiles its own regular expression, however many wrote the same one.
///
/// The point is to make the size of the change a measurement rather than an
/// inference. Both loads run the same reader over the same bytes in the same
/// process, so the difference between them is the sharing and nothing else —
/// which is not true of comparing this run with a run recorded earlier.
///
/// Leaves the switch as it found it, so a later load in the same process shares
/// again.
pub fn load_without_sharing(
    path: &std::path::Path,
) -> Result<RuleDatabase, crate::database::DatabaseError> {
    let bytes = std::fs::read(path)?;
    crate::matcher::SHARING_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
    let loaded = RuleDatabase::from_bytes(&bytes);
    crate::matcher::SHARING_DISABLED.store(false, std::sync::atomic::Ordering::Relaxed);
    loaded
}

/// Rebuild every rule's compiled regex from the parse tree kept beside it.
///
/// A `regex::bytes::Regex` keeps its program behind a private box and reports
/// nothing about its size, so the only way to attribute those bytes is to build
/// the same regexes a second time and measure the allocation. The parse tree is
/// what `build_regex` was handed, so `hir.to_string()` is the same expression
/// the original was compiled from — the same compile, and therefore the same
/// program, within the slack of how a round-tripped expression prints.
///
/// The caller holds the result and measures; dropping it gives the number back.
pub fn rebuilt_regexes(db: &RuleDatabase) -> Vec<regex::bytes::Regex> {
    rebuilt_regexes_with(db, None)
}

/// The same, with the lazy DFA's size limit set, to see what that limit costs
/// in memory. `None` is the builder's own default.
pub fn rebuilt_regexes_with(
    db: &RuleDatabase,
    dfa_limit: Option<usize>,
) -> Vec<regex::bytes::Regex> {
    let mut out = Vec::new();
    for rule in db.probe_rules() {
        for matcher in rule.probe_matchers() {
            if let Kind::Regex { hir, .. } = matcher.probe_kind() {
                let mut builder = regex::bytes::RegexBuilder::new(&hir.to_string());
                builder.unicode(false);
                if let Some(limit) = dfa_limit {
                    builder.dfa_size_limit(limit);
                }
                if let Ok(regex) = builder.build() {
                    out.push(regex);
                }
            }
        }
    }
    out
}

/// Build `count` trivial regexes with the same builder the engine uses.
///
/// The point is to separate the engine's fixed per-regex cost from the cost of
/// the pattern itself: `abc0`, `abc1`, ... are as small as a regex gets, so
/// whatever they cost is overhead every regex pays before its own program is
/// counted. The caller measures the allocation.
pub fn trivial_regexes(count: usize) -> Vec<regex::bytes::Regex> {
    (0..count)
        .filter_map(|i| {
            regex::bytes::RegexBuilder::new(&format!("abc{i}"))
                .unicode(false)
                .build()
                .ok()
        })
        .collect()
}

/// The compiled regexes of the *distinct* expressions only, one per expression.
///
/// Comparing this with [`rebuilt_regexes`] is a cross-check on what sharing
/// compiled regexes saves: both are built the same way, so the difference is
/// the program bytes of the repeats.
///
/// It reads low against the real thing, and it is worth knowing why.
/// [`load_without_sharing`] is the direct measurement and it is the one to
/// quote; this is the estimate that agrees with it in direction. Two reasons
/// the estimate is the smaller of the two: it builds every pattern without the
/// case-insensitive and dot-matches-new-line flags the loader applies, and it
/// counts only the bytes asked of the allocator, not the allocator's own
/// per-allocation overhead — and a compiled program is not one allocation but
/// several hundred, so the repeats cost that overhead as well.
pub fn rebuilt_distinct_regexes(db: &RuleDatabase) -> Vec<regex::bytes::Regex> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rule in db.probe_rules() {
        for matcher in rule.probe_matchers() {
            if let Kind::Regex { hir, .. } = matcher.probe_kind() {
                let text = hir.to_string();
                if !seen.insert(text.clone()) {
                    continue;
                }
                if let Ok(regex) = regex::bytes::RegexBuilder::new(&text)
                    .unicode(false)
                    .build()
                {
                    out.push(regex);
                }
            }
        }
    }
    out
}

/// How many regex strings there are, and how many distinct expressions they
/// spell. Two rules that wrote the same expression get two compiled regexes,
/// which is worth knowing before deciding whether to compile them separately.
pub fn distinct_regex_bodies(db: &RuleDatabase) -> (usize, usize) {
    let mut bodies = std::collections::HashSet::new();
    let mut total = 0;
    for rule in db.probe_rules() {
        for matcher in rule.probe_matchers() {
            if let Kind::Regex { hir, .. } = matcher.probe_kind() {
                total += 1;
                bodies.insert(hir.to_string());
            }
        }
    }
    (total, bodies.len())
}

/// Count and measure everything in `db`.
pub fn parts(db: &RuleDatabase) -> (Parts, Counts) {
    let mut p = Parts::default();
    let mut c = Counts::default();

    let rules = db.probe_rules();
    c.rules = rules.len();
    p.rule_headers = rules.capacity() * size_of::<CompiledRule>();
    for rule in rules {
        measure_rule(rule, &mut p, &mut c);
    }

    let sources = db.probe_sources();
    p.sources = sources.capacity() * size_of::<crate::database::RuleSource>()
        + sources
            .iter()
            .map(|s| s.name.capacity() + s.sha256.capacity())
            .sum::<usize>();
    (p, c)
}

fn measure_rule(rule: &CompiledRule, p: &mut Parts, c: &mut Counts) {
    p.names += rule.name.capacity();
    p.tags += rule.tags.capacity() * size_of::<String>()
        + rule.tags.iter().map(|t| t.capacity()).sum::<usize>();
    p.metadata += metadata_bytes(&rule.metadata);

    p.defs += rule.defs.capacity() * size_of::<crate::ast::StringDef>();
    for def in &rule.defs {
        p.defs += def.id.capacity();
        match &def.value {
            crate::ast::StringValue::Text(bytes) => p.def_text += bytes.capacity(),
            crate::ast::StringValue::Hex(hex) => {
                p.def_hex_tokens += hex_tokens(&hex.tokens);
            }
            crate::ast::StringValue::Regex { body, flags } => {
                p.def_regex_text += body.capacity() + flags.capacity();
            }
            // Nothing to count: this is what a shed definition is. The `defs`
            // line above still counts the header and the identifier, which are
            // what is left.
            crate::ast::StringValue::Shed => {}
        }
    }

    let (code, constants) = program_bytes(&rule.program);
    p.program_code += code;
    p.program_constants += constants;

    let matchers = rule.probe_matchers();
    p.matcher_headers += matchers.capacity() * size_of::<CompiledString>();
    for matcher in matchers {
        c.strings += 1;
        p.matcher_ids += matcher.id.capacity();
        match matcher.probe_kind() {
            Kind::Literal(literals) => {
                c.literal_strings += 1;
                c.literal_forms += literals.len();
                p.matcher_literal_bytes += literals.capacity()
                    * size_of::<crate::matcher::text::Literal>()
                    + literals.iter().map(|l| l.bytes.capacity()).sum::<usize>();
            }
            Kind::Hex(pattern) => {
                c.hex_strings += 1;
                p.matcher_hex_tokens +=
                    hex_tokens(&pattern.tokens) + pattern.prefix.capacity();
            }
            Kind::Regex { hir, .. } => {
                c.regex_strings += 1;
                p.matcher_hir += hir_bytes(hir);
            }
        }
    }
}

fn metadata_bytes(meta: &RuleMetadata) -> usize {
    let mut n = 0;
    for text in [&meta.description, &meta.author, &meta.date, &meta.source, &meta.license, &meta.family, &meta.variant] {
        n += text.as_ref().map_or(0, |s| s.capacity());
    }
    n += meta.reference.capacity() * size_of::<String>()
        + meta.reference.iter().map(|s| s.capacity()).sum::<usize>();
    n += meta.hashes.capacity() * size_of::<String>()
        + meta.hashes.iter().map(|s| s.capacity()).sum::<usize>();
    for (key, value) in &meta.extra {
        n += key.capacity();
        if let crate::ast::MetaValue::Text(text) = value {
            n += text.capacity();
        }
    }
    n
}

fn program_bytes(program: &Program) -> (usize, usize) {
    let code = program.code.capacity() * size_of::<crate::program::Op>();
    let mut constants = program.constants.capacity() * size_of::<Const>();
    for constant in &program.constants {
        if let Const::Str(bytes) = constant {
            constants += bytes.len();
        }
    }
    constants += program.regexes.capacity() * size_of::<crate::program::RegexSpec>();
    constants += program.required_strings.capacity() * size_of::<u32>();
    (code, constants)
}

/// Bytes a hex token tree holds, its own entries included.
fn hex_tokens(tokens: &Vec<crate::ast::HexToken>) -> usize {
    let mut n = tokens.capacity() * size_of::<crate::ast::HexToken>();
    for token in tokens {
        match token {
            crate::ast::HexToken::Alternative(branches) | crate::ast::HexToken::Not(branches) => {
                n += branches.capacity() * size_of::<Vec<crate::ast::HexToken>>();
                for branch in branches {
                    n += hex_tokens(branch);
                }
            }
            _ => {}
        }
    }
    n
}

/// Bytes a regex parse tree holds. Each node is a `Hir`, whose children live in
/// `Vec`s of their own.
fn hir_bytes(hir: &regex_syntax::hir::Hir) -> usize {
    use regex_syntax::hir::HirKind;
    let mut n = size_of::<regex_syntax::hir::Hir>();
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(literal) => n += literal.0.len(),
        HirKind::Class(class) => {
            if let regex_syntax::hir::Class::Bytes(bytes) = class {
                n += bytes.ranges().len() * size_of::<regex_syntax::hir::ClassBytesRange>();
            }
        }
        HirKind::Repetition(repetition) => n += hir_bytes(&repetition.sub),
        HirKind::Capture(capture) => n += hir_bytes(&capture.sub),
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            n += children.capacity() * size_of::<regex_syntax::hir::Hir>();
            for child in children {
                n += hir_bytes(child);
            }
        }
    }
    n
}

