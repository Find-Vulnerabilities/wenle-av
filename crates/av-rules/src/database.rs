//! The compiled rule set: what the engine loads and the scanner runs.
//!
//! A [`RuleDatabase`] is every rule of a rule set in the form the scanner
//! needs — bytecode, matchers and a built prefilter — plus the metadata the
//! reporting layer turns into a [`Detection`](av_core::Detection).
//!
//! # What is stored, and what is rebuilt
//!
//! A database file holds the bytecode, the string *definitions*, and the
//! metadata. It does not hold the compiled matchers or the automaton, because
//! those are large, pointer-bearing structures that cannot be written to a file
//! and memmapped back. They are rebuilt on load.
//!
//! That is a deliberate trade and it is worth stating plainly, because the
//! module documentation in `lib.rs` says "memory-mappable" and this is the
//! honest version of it. Rebuilding costs the prefilter's construction — about
//! 170 ms for ten thousand rules, measured — and happens once when the service
//! starts, not once per file. Writing every automaton's transition tables to
//! disk so they could be mapped would save that startup cost and cost a great
//! deal of complexity in return; a service that starts once per boot is not
//! where the time is going.
//!
//! The effect that *does* matter is preserved: a scan does not parse or compile
//! anything. Parsing a 17 MB rule file takes seconds; loading this takes the
//! prefilter build and nothing else.
//!
//! # Versioning
//!
//! The file starts with a magic number and a format version. Both are checked
//! on load, because the alternative to refusing a stale database is
//! misinterpreting it — bytecode is not self-describing, so an old file read by
//! a new engine would produce instruction-level nonsense rather than an error.

use std::collections::BTreeMap;
use std::path::Path;

use av_core::{Platform, Severity, ThreatCategory, ThreatName};
use serde::{Deserialize, Serialize};

use crate::ast::{MetaValue, Rule, StringDef};
use crate::compiler::compile_rule;
use crate::matcher::{self, CompiledString, MatcherError};
use crate::prefilter::{Prefilter, RuleFilter, RuleStrings};
use crate::program::Program;
use crate::ruleset;

/// Identifies a database file. Chosen to be unlikely to appear at the start of
/// anything else, and readable in a hex dump.
pub const MAGIC: [u8; 8] = *b"WENLEAV\0";

/// Format version. Bump on any change to the layout of [`DatabaseImage`].
///
/// [`DatabaseImage`] is private, so the only way this can go unnoticed is a
/// serialised type changing underneath it — which is exactly what it is for.
pub const FORMAT_VERSION: u32 = 1;

/// Everything that can go wrong building or loading a rule set.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("rule database is truncated: {0} bytes is too short to hold a header")]
    Truncated(usize),
    #[error("not a rule database: expected magic {expected:?}, found {found:?}")]
    BadMagic {
        expected: [u8; 8],
        found: [u8; 8],
    },
    #[error(
        "rule database format version {found} cannot be read by this engine, which \
         writes version {supported}"
    )]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("rule database is corrupt: {0}")]
    Corrupt(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

impl From<bincode::Error> for DatabaseError {
    fn from(e: bincode::Error) -> Self {
        // A deserialisation failure is either a truncated file or one written
        // by something else. Both are "this is not a database I can use", and
        // the underlying message is the only thing that says which.
        DatabaseError::Corrupt(e.to_string())
    }
}

/// The scoring and naming metadata a rule carries.
///
/// This mirrors [`crate::ast::RuleMeta`] and adds the two derivations the
/// reporting layer would otherwise each have to make for itself: the score,
/// which must apply the `weight` override in one place or two callers will
/// disagree, and the structured threat name, built from the category, platform,
/// family and variant.
///
/// `severity` stays an `Option` here rather than being resolved at build time,
/// because a rule that declares nothing and a rule that declares `low` are
/// different claims and only [`RuleMetadata::effective_severity`] should
/// conflate them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Vec<String>,
    pub date: Option<String>,
    pub source: Option<String>,
    pub license: Option<String>,
    pub severity: Option<Severity>,
    pub category: Option<ThreatCategory>,
    pub platform: Option<Platform>,
    pub family: Option<String>,
    pub variant: Option<String>,
    /// Explicit score override, applied in place of the severity's default.
    pub weight: Option<u16>,
    /// No corroboration needed: this detection alone justifies a malicious
    /// verdict.
    pub decisive: bool,
    /// The author's own quality rating, as third-party rule sets carry it.
    pub quality: Option<u8>,
    /// Hashes of known samples, harvested into the exact-match blocklist.
    pub hashes: Vec<String>,
    /// Meta keys the engine does not model, preserved so an importer that
    /// re-exports a rule set does not silently discard an author's annotations.
    pub extra: BTreeMap<String, MetaValue>,
}

impl From<&crate::ast::RuleMeta> for RuleMetadata {
    fn from(meta: &crate::ast::RuleMeta) -> Self {
        Self {
            description: meta.description.clone(),
            author: meta.author.clone(),
            reference: meta.reference.clone(),
            date: meta.date.clone(),
            source: meta.source.clone(),
            license: meta.license.clone(),
            severity: meta.severity,
            category: meta.category,
            platform: meta.platform,
            family: meta.family.clone(),
            variant: meta.variant.clone(),
            weight: meta.weight,
            decisive: meta.decisive,
            quality: meta.quality,
            hashes: meta.hashes.clone(),
            extra: meta.extra.clone(),
        }
    }
}

impl RuleMetadata {
    /// The severity to treat this rule as having.
    ///
    /// A rule that declares none is [`Severity::Medium`] rather than
    /// [`Severity::Info`]. Info scores zero, so defaulting to it would make an
    /// undeclared rule silently inert — a rule that can never contribute to a
    /// verdict. Medium is the claim "this is worth 60 points", which is what an
    /// author who wrote a rule but no severity most likely meant, and it is
    /// visible: a rule that has to be corroborated is exactly what Medium
    /// produces.
    pub fn effective_severity(&self) -> Severity {
        self.severity.unwrap_or(Severity::Medium)
    }

    /// The score this rule contributes when it matches.
    pub fn score(&self) -> u16 {
        self.weight.unwrap_or_else(|| self.effective_severity().default_score())
    }

    /// The structured threat name, when the rule names a category.
    pub fn threat(&self) -> Option<ThreatName> {
        let category = self.category?;
        let mut threat = ThreatName::new(self.platform.unwrap_or(Platform::Win32), category);
        if let Some(family) = &self.family {
            threat = threat.with_family(family.clone());
        }
        if let Some(variant) = &self.variant {
            threat = threat.with_variant(variant.clone());
        }
        Some(threat)
    }

    /// The text to show a user for this rule.
    pub fn display_name(&self, rule_name: &str) -> String {
        match self.threat() {
            Some(threat) => threat.to_string(),
            None => rule_name.to_owned(),
        }
    }
}

/// One rule, ready to run.
///
/// Not `Clone`: the compiled matchers wrap a regex engine and an automaton,
/// and cloning a rule set to change one rule's metadata is not something
/// anything wants. A rule set is replaced whole when it is updated.
#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    /// `private rule` — evaluated, and its result is available to the scan, but
    /// never reported to the user.
    pub private: bool,
    /// `global rule` — must match for any other rule to be considered.
    pub global: bool,
    pub tags: Vec<String>,
    pub metadata: RuleMetadata,
    pub program: Program,
    /// The definitions, kept for two reasons: the database is rebuilt from them
    /// on load, and a report can name the string that matched.
    pub defs: Vec<StringDef>,
    /// The compiled matchers. Rebuilt on load, never serialised.
    matchers: Vec<CompiledString>,
}

impl CompiledRule {
    /// Wrap a compiled program and its definitions, building the matchers.
    ///
    /// A string the matcher refuses is left out of `matchers` but keeps its
    /// slot, so the bytecode's slot numbering is unaffected and the condition
    /// sees the string as never matching. That is the honest reading of a
    /// string the engine cannot search for, and it is what the prefilter
    /// already assumes: a refused string contributes no atoms, so its rule is
    /// evaluated every time and the missing match is what decides it.
    pub fn new(
        rule: &Rule,
        program: Program,
    ) -> (Self, Vec<(u32, MatcherError)>) {
        let mut matchers = Vec::with_capacity(rule.strings.len());
        let mut refusals = Vec::new();
        for (slot, def) in rule.strings.iter().enumerate() {
            let slot = slot as u32;
            match matcher::compile(def, slot) {
                Ok(compiled) => matchers.push(compiled),
                Err(e) => refusals.push((slot, e)),
            }
        }
        let compiled = Self {
            name: rule.name.clone(),
            private: rule.private,
            global: rule.global,
            tags: rule.tags.clone(),
            metadata: RuleMetadata::from(&rule.meta),
            program,
            defs: rule.strings.clone(),
            matchers,
        };
        (compiled, refusals)
    }

    /// The atoms of every string, indexed by slot.
    ///
    /// A slot whose string was refused comes back empty, which is what makes
    /// the rule unfilterable rather than wrongly filtered.
    pub fn string_atoms(&self) -> RuleStrings {
        (0..self.program.string_count)
            .map(|slot| {
                self.matchers
                    .iter()
                    .find(|m| m.slot == slot)
                    .map_or_else(crate::atoms::StringAtoms::none, CompiledString::atoms)
            })
            .collect()
    }

    /// The matcher for one slot, if the string could be compiled.
    pub fn matcher(&self, slot: u32) -> Option<&CompiledString> {
        self.matchers.iter().find(|m| m.slot == slot)
    }

    pub fn matchers(&self) -> &[CompiledString] {
        &self.matchers
    }

    /// The identifier of a string slot, e.g. `$a`, for a report.
    pub fn string_id(&self, slot: u32) -> Option<&str> {
        self.defs.get(slot as usize).map(|def| def.id.as_str())
    }
}

/// What a rule set was built from, for reporting and for the UI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub rules: usize,
    pub private_rules: usize,
    pub global_rules: usize,
    /// Rules that carry an exact-match hash in their metadata.
    pub rules_with_hashes: usize,
    pub hashes: usize,
    /// Rules that declare a severity.
    pub rules_with_severity: usize,
    /// Rules that are decisive on their own.
    pub decisive_rules: usize,
    pub strings: usize,
    pub matcher_refusals: usize,
}

/// Why one rule did not make it into the database.
#[derive(Debug, Clone)]
pub struct RuleRefusal {
    pub name: String,
    /// Source line of the rule, for the operator's sake rather than the
    /// machine's.
    pub line: usize,
    pub reason: String,
    /// The feature at fault, as the compiler names it. This is the field a work
    /// queue is built from: the same string for every rule blocked by the same
    /// missing capability.
    pub feature: &'static str,
}

/// The outcome of compiling a rule set: what got in, and what did not.
#[derive(Debug, Clone, Default)]
pub struct CompileReport {
    pub rules_seen: usize,
    pub chunks_parsed: usize,
    pub chunks_malformed: usize,
    pub parse_failures: usize,
    pub refusals: Vec<RuleRefusal>,
    /// String-level refusals, as `(rule, slot, reason)`. A string refusal does
    /// not remove the rule; it removes one pattern from it.
    pub string_refusals: Vec<(String, u32, String)>,
}

impl CompileReport {
    pub fn refused(&self) -> usize {
        self.refusals.len()
    }

    /// Refusals grouped by the capability that would fix them, most common
    /// first.
    ///
    /// This is the work queue: implementing the first entry buys the most
    /// rules.
    pub fn by_feature(&self) -> Vec<(&'static str, usize)> {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for refusal in &self.refusals {
            *counts.entry(refusal.feature).or_insert(0) += 1;
        }
        let mut rows: Vec<_> = counts.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        rows
    }
}

/// The compiled rule set.
#[derive(Debug)]
pub struct RuleDatabase {
    rules: Vec<CompiledRule>,
    prefilter: Prefilter,
    stats: DatabaseStats,
}

impl RuleDatabase {
    /// Build from rules that are already compiled.
    pub fn from_rules(rules: Vec<CompiledRule>) -> Self {
        let filters: Vec<RuleFilter> = rules
            .iter()
            .map(|rule| RuleFilter {
                strings: rule.string_atoms(),
                required: rule.program.required_strings.clone(),
            })
            .collect();
        let prefilter = Prefilter::build(&filters);
        let stats = summarise(&rules);
        Self {
            rules,
            prefilter,
            stats,
        }
    }

    /// Compile a rule set from source.
    ///
    /// Never fails as a whole. A rule that cannot be compiled is recorded in
    /// the report and left out, because the alternative — refusing the rule set
    /// — would mean one unsupported construct costs every other rule in the
    /// file their detection.
    pub fn compile(source: &str) -> (Self, CompileReport) {
        let split = ruleset::split_rule_chunks(source);
        let mut report = CompileReport {
            chunks_malformed: split.malformed,
            ..CompileReport::default()
        };
        let mut compiled: Vec<CompiledRule> = Vec::with_capacity(split.chunks.len());

        for chunk in &split.chunks {
            let file = match crate::parser::parse_file(chunk.text) {
                Ok(file) => {
                    report.chunks_parsed += 1;
                    file
                }
                Err(e) => {
                    report.parse_failures += 1;
                    // One parse failure can hide several rules, and the chunk is
                    // the unit the parser works in, so the refusal is recorded
                    // against the chunk rather than a rule name that may not
                    // have been reached.
                    report.refusals.push(RuleRefusal {
                        name: format!("<chunk at line {}>", chunk.line),
                        line: chunk.line,
                        reason: e.to_string(),
                        feature: "parse error",
                    });
                    continue;
                }
            };

            for rule in &file.rules {
                report.rules_seen += 1;
                match compile_rule(rule) {
                    Ok(program) => {
                        let (compiled_rule, refusals) = CompiledRule::new(rule, program);
                        for (slot, e) in refusals {
                            report
                                .string_refusals
                                .push((rule.name.clone(), slot, e.message.clone()));
                        }
                        compiled.push(compiled_rule);
                    }
                    Err(e) => report.refusals.push(RuleRefusal {
                        name: rule.name.clone(),
                        line: chunk.line,
                        reason: e.message.clone(),
                        feature: e.feature,
                    }),
                }
            }
        }

        report.string_refusals.shrink_to_fit();
        (Self::from_rules(compiled), report)
    }

    /// Compile a rule set from source, reporting only what could not be
    /// compiled. For callers that do not want the report.
    pub fn compile_or_warn(source: &str) -> Self {
        let (db, report) = Self::compile(source);
        if !report.refusals.is_empty() {
            log::warn!(
                "{} of {} rules were refused; the largest gap is {} rules blocked by `{}`",
                report.refused(),
                report.rules_seen,
                report.by_feature().first().map_or(0, |(_, n)| *n),
                report.by_feature().first().map_or("-", |(f, _)| f),
            );
        }
        db
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    pub fn rule(&self, index: u32) -> Option<&CompiledRule> {
        self.rules.get(index as usize)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn prefilter(&self) -> &Prefilter {
        &self.prefilter
    }

    pub fn stats(&self) -> &DatabaseStats {
        &self.stats
    }

    /// Every hash carried in rule metadata, paired with the rule that carries
    /// it.
    ///
    /// This is where the exact-match blocklist comes from: the rule set already
    /// names samples, so there is no second source of hashes to keep in step
    /// with it.
    pub fn hashes(&self) -> impl Iterator<Item = (&str, u32)> {
        self.rules.iter().enumerate().flat_map(|(index, rule)| {
            rule.metadata
                .hashes
                .iter()
                .map(move |hash| (hash.as_str(), index as u32))
        })
    }

    // -- persistence --------------------------------------------------------

    /// Serialise to the bytes of a `.avdb` file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DatabaseError> {
        let image = DatabaseImage {
            rules: self
                .rules
                .iter()
                .map(|rule| RuleImage {
                    name: rule.name.clone(),
                    private: rule.private,
                    global: rule.global,
                    tags: rule.tags.clone(),
                    metadata: rule.metadata.clone(),
                    program: rule.program.clone(),
                    defs: rule.defs.clone(),
                })
                .collect(),
        };

        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        // Length-prefixed rather than "the rest of the file" so that a
        // truncated file is caught by the reader instead of being silently
        // accepted as a shorter rule set.
        let body = bincode::serialize(&image)?;
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Rebuild from the bytes of a `.avdb` file.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DatabaseError> {
        const HEADER: usize = MAGIC.len() + 4 + 8;
        if bytes.len() < HEADER {
            return Err(DatabaseError::Truncated(bytes.len()));
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);
        if magic != MAGIC {
            return Err(DatabaseError::BadMagic {
                expected: MAGIC,
                found: magic,
            });
        }
        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != FORMAT_VERSION {
            return Err(DatabaseError::UnsupportedVersion {
                found: version,
                supported: FORMAT_VERSION,
            });
        }
        let mut length = [0u8; 8];
        length.copy_from_slice(&bytes[12..20]);
        let length = u64::from_le_bytes(length) as usize;
        let body = bytes
            .get(HEADER..HEADER + length)
            .ok_or(DatabaseError::Truncated(bytes.len()))?;

        let image: DatabaseImage = bincode::deserialize(body)?;
        let mut rules = Vec::with_capacity(image.rules.len());
        for rule in image.rules {
            // Rebuilt here rather than stored, which is the trade this module's
            // documentation is about.
            let mut matchers = Vec::with_capacity(rule.defs.len());
            for (slot, def) in rule.defs.iter().enumerate() {
                if let Ok(compiled) = matcher::compile(def, slot as u32) {
                    matchers.push(compiled);
                }
            }
            rules.push(CompiledRule {
                name: rule.name,
                private: rule.private,
                global: rule.global,
                tags: rule.tags,
                metadata: rule.metadata,
                program: rule.program,
                defs: rule.defs,
                matchers,
            });
        }
        Ok(Self::from_rules(rules))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DatabaseError> {
        std::fs::write(path, self.to_bytes()?)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        Self::from_bytes(&std::fs::read(path)?)
    }
}

/// The serialisable form of a rule set.
#[derive(Debug, Serialize, Deserialize)]
struct DatabaseImage {
    rules: Vec<RuleImage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleImage {
    name: String,
    private: bool,
    global: bool,
    tags: Vec<String>,
    metadata: RuleMetadata,
    program: Program,
    defs: Vec<StringDef>,
}

fn summarise(rules: &[CompiledRule]) -> DatabaseStats {
    let mut stats = DatabaseStats {
        rules: rules.len(),
        ..DatabaseStats::default()
    };
    for rule in rules {
        stats.private_rules += usize::from(rule.private);
        stats.global_rules += usize::from(rule.global);
        stats.strings += rule.defs.len();
        stats.matcher_refusals += rule.defs.len() - rule.matchers.len();
        stats.rules_with_severity += usize::from(rule.metadata.severity.is_some());
        stats.decisive_rules += usize::from(rule.metadata.decisive);
        if !rule.metadata.hashes.is_empty() {
            stats.rules_with_hashes += 1;
            stats.hashes += rule.metadata.hashes.len();
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"
rule alpha {
    meta:
        description = "first"
        severity = "high"
        category = "ransomware"
        family = "LockBit"
    strings:
        $a = "this is a needle"
    condition:
        $a
}

rule beta {
    meta:
        severity = "low"
    strings:
        $a = "another needle here"
    condition:
        $a
}
"#;

    fn database() -> RuleDatabase {
        let (db, report) = RuleDatabase::compile(SOURCE);
        assert_eq!(report.rules_seen, 2, "both rules should parse");
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        db
    }

    #[test]
    fn rules_compile_with_their_metadata() {
        let db = database();
        assert_eq!(db.len(), 2);
        let alpha = db.rule(0).unwrap();
        assert_eq!(alpha.name, "alpha");
        assert_eq!(alpha.metadata.severity, Some(Severity::High));
        assert_eq!(alpha.metadata.family.as_deref(), Some("LockBit"));
        assert_eq!(alpha.metadata.score(), 100);
        assert_eq!(
            alpha.metadata.threat().unwrap().to_string(),
            "Win32.Ransomware.LockBit"
        );
    }

    #[test]
    fn a_weight_overrides_the_severity_default() {
        let source = r#"
rule weighted {
    meta:
        severity = "low"
        weight = 5
    strings:
        $a = "a long enough string"
    condition:
        $a
}
"#;
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0);
        assert_eq!(db.rule(0).unwrap().metadata.score(), 5);
    }

    /// A rule that declares no severity is Medium, not Info. Info scores zero
    /// and would make the rule inert — a rule that can never contribute.
    #[test]
    fn an_undeclared_severity_is_medium_and_scores() {
        let source = r#"
rule undeclared {
    strings:
        $a = "a long enough string"
    condition:
        $a
}
"#;
        let (db, _) = RuleDatabase::compile(source);
        let rule = db.rule(0).unwrap();
        assert_eq!(rule.metadata.effective_severity(), Severity::Medium);
        assert_eq!(rule.metadata.score(), 60);
    }

    #[test]
    fn a_rule_with_no_category_has_no_threat_name() {
        let source = r#"
rule generic {
    strings:
        $a = "a long enough string"
    condition:
        $a
}
"#;
        let (db, _) = RuleDatabase::compile(source);
        assert_eq!(db.rule(0).unwrap().metadata.threat(), None);
        assert_eq!(db.rule(0).unwrap().metadata.display_name("generic"), "generic");
    }

    #[test]
    fn stats_count_what_the_database_holds() {
        let db = database();
        let stats = db.stats();
        assert_eq!(stats.rules, 2);
        assert_eq!(stats.strings, 2);
        assert_eq!(stats.matcher_refusals, 0);
        assert_eq!(stats.rules_with_severity, 2);
    }

    // -- a rule the compiler refuses ----------------------------------------

    #[test]
    fn a_refused_rule_does_not_take_the_others_with_it() {
        let source = r#"
rule good {
    strings:
        $a = "a long enough string"
    condition:
        $a
}

rule unsupported {
    strings:
        $a = "another long string"
    condition:
        pe.something_not_implemented
}

rule also_good {
    strings:
        $a = "a third long string"
    condition:
        $a
}
"#;
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.rules_seen, 3);
        assert_eq!(report.refused(), 1);
        assert_eq!(report.refusals[0].name, "unsupported");
        assert_eq!(db.len(), 2, "the other two still compile");
        assert_eq!(db.rule(0).unwrap().name, "good");
        assert_eq!(db.rule(1).unwrap().name, "also_good");
    }

    #[test]
    fn refusals_are_grouped_by_the_capability_that_would_fix_them() {
        let source = r#"
rule a {
    strings:
        $x = "a long enough string"
    condition:
        pe.missing_field
}
rule b {
    strings:
        $x = "another long string here"
    condition:
        pe.also_missing
}
"#;
        let (_, report) = RuleDatabase::compile(source);
        let rows = report.by_feature();
        assert_eq!(rows.len(), 1, "both blocked by the same thing");
        assert_eq!(rows[0].1, 2);
    }

    // -- persistence --------------------------------------------------------

    #[test]
    fn a_database_round_trips_through_bytes() {
        let db = database();
        let bytes = db.to_bytes().expect("serialising");
        let restored = RuleDatabase::from_bytes(&bytes).expect("deserialising");

        assert_eq!(restored.len(), db.len());
        assert_eq!(restored.stats(), db.stats());
        for (before, after) in db.rules().iter().zip(restored.rules()) {
            assert_eq!(before.name, after.name);
            assert_eq!(before.metadata, after.metadata);
            // The bytecode is what has to survive exactly; the matchers are
            // rebuilt, so comparing them is comparing the rebuild.
            assert_eq!(before.program.code, after.program.code);
            assert_eq!(before.program.constants.len(), after.program.constants.len());
            assert_eq!(before.defs, after.defs);
            assert_eq!(before.matchers().len(), after.matchers().len());
        }
    }

    /// The rebuilt matchers must actually find things, not merely exist. A
    /// round trip that produced empty matchers would pass every check above.
    #[test]
    fn a_restored_database_still_matches() {
        let db = database();
        let restored =
            RuleDatabase::from_bytes(&db.to_bytes().unwrap()).expect("deserialising");
        let rule = restored.rule(0).unwrap();
        let matcher = rule.matcher(0).expect("string 0 should have a matcher");
        let mut matches = crate::matches::MatchSet::with_capacity(1);
        assert!(matcher.find_all(b"prefix this is a needle suffix", &mut matches));
        assert_eq!(matches.count(0), 1);
    }

    #[test]
    fn a_file_that_is_not_a_database_is_refused() {
        let bytes = b"this is not a rule database, it is a text file";
        assert!(matches!(
            RuleDatabase::from_bytes(bytes),
            Err(DatabaseError::BadMagic { .. })
        ));
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_partially_read() {
        let db = database();
        let bytes = db.to_bytes().unwrap();
        // Past the header, so it is the length prefix that catches it.
        assert!(matches!(
            RuleDatabase::from_bytes(&bytes[..bytes.len() - 10]),
            Err(DatabaseError::Truncated(_))
        ));
        assert!(matches!(
            RuleDatabase::from_bytes(&bytes[..4]),
            Err(DatabaseError::Truncated(4))
        ));
    }

    /// A database from a future version has to be refused, not guessed at:
    /// bytecode is not self-describing, so misreading it produces
    /// instruction-level nonsense instead of an error.
    #[test]
    fn a_future_format_version_is_refused() {
        let db = database();
        let mut bytes = db.to_bytes().unwrap();
        let future = FORMAT_VERSION + 1;
        bytes[8..12].copy_from_slice(&future.to_le_bytes());
        match RuleDatabase::from_bytes(&bytes) {
            Err(DatabaseError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, future);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[test]
    fn saving_and_loading_a_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.avdb");
        database().save(&path).expect("saving");
        let loaded = RuleDatabase::load(&path).expect("loading");
        assert_eq!(loaded.len(), 2);
    }

    // -- hashes -------------------------------------------------------------

    #[test]
    fn hashes_are_harvested_from_metadata_with_their_rule() {
        let source = r#"
rule hashed {
    meta:
        hash = "d41d8cd98f00b204e9800998ecf8427e"
        hash = "0cc175b9c0f1b6a831c399e269772661"
    strings:
        $a = "a long enough string"
    condition:
        $a
}
"#;
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0);
        let hashes: Vec<_> = db.hashes().collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.iter().all(|(_, rule)| *rule == 0));
        assert_eq!(db.stats().rules_with_hashes, 1);
    }

    #[test]
    fn an_empty_source_compiles_to_an_empty_database() {
        let (db, report) = RuleDatabase::compile("");
        assert!(db.is_empty());
        assert_eq!(report.rules_seen, 0);
    }

    // -- the prefilter is built from the compiled rules ----------------------

    #[test]
    fn the_prefilter_is_built_from_the_compiled_rules() {
        let db = database();
        assert_eq!(db.prefilter().stats().rules, 2);
        assert!(db.prefilter().stats().atoms >= 2);
    }
}
