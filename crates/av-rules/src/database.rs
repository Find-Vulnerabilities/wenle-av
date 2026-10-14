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

use av_core::{Platform, Severity, ThreatCategory, ThreatName, VerdictThresholds};
use serde::{Deserialize, Serialize};

use crate::ast::{MetaValue, Rule, StringDef, StringValue};
use crate::compiler::CompileError;
use crate::matcher::{self, CompiledString, MatcherError, RegexCache};
use crate::prefilter::{Prefilter, RuleFilter, RuleStrings};
use crate::program::Program;
use crate::ruleset;
use crate::sweep::LiteralSweep;

/// Identifies a database file. Chosen to be unlikely to appear at the start of
/// anything else, and readable in a hex dump.
pub const MAGIC: [u8; 8] = *b"WENLEAV\0";

/// Bytes of a `.avdb` before the rule set itself: the magic, the format version
/// and the length of the body.
///
/// Public because reading it is the whole of [`RuleDatabase::check_file`], and a
/// caller that wants to reason about the cost of that call should be able to see
/// what it is.
pub const HEADER_LEN: usize = MAGIC.len() + 4 + 8;

/// Format version. Bump on any change to the layout of the serialised image.
///
/// That image is private, so the only way this can go unnoticed is a
/// serialised type changing underneath it — which is exactly what it is for.
///
/// Version 2 added `Op::ForBegin`, `Op::ForStep`, `Op::VarLoad` and
/// [`Program::var_slots`](crate::program::Program::var_slots); a version 1
/// reader would silently misread a looping rule as a sequence of ops it does
/// not have, which is worse than refusing the file.
///
/// Version 3 added `Op::PeField`, `Op::PeIndexed` and `Op::PeCall`. The same
/// argument applies with more force: those three carry a payload, so a version 2
/// reader would take the `PeField` discriminant for an opcode it does have and
/// then execute the member byte as the next instruction.
///
/// Version 4 added more members to `PeField`, `PeElement` and `PeFunc`, and
/// *removed* the four packed `PeField` version members. A version 3 reader would
/// not misread the bytecode — the opcodes are unchanged — but it would answer
/// the four members that used to sit at those discriminants with whatever now
/// occupies them, which is the silent wrong answer this constant exists to
/// refuse rather than the loud one it was built for.
///
/// Version 5 added the seven `PeElement` signature members and
/// `PeField::NumberOfSignatures`. The same argument as version 4: the opcodes
/// are unchanged, so a version 4 reader loads the image happily and then
/// answers `pe.signatures[i].serial` with whichever member now sits at that
/// discriminant — a certificate field silently read as a section field. That is
/// a rule matching the wrong files rather than a rule that fails to load.
///
/// Version 6 added `PeFunc::Imphash`, `PeFunc::Imports`, `PeFunc::ImportsSymbol`,
/// `PeFunc::Exports`, `PeField::NumberOfImports` and `PeField::NumberOfExports`.
/// Still no opcode changed, so a version 5 reader loads the image and then
/// answers `pe.imphash()` by calling whichever function now sits at that
/// discriminant — a membership test where a hash was asked for, which is a
/// `false` where the rule wanted a string and therefore a missed detection with
/// nothing in the scan to show for it.
///
/// The one thing that *did* change shape is the operand count of a `PeCall`:
/// `ImportsSymbol` pops two where every version 5 function popped at most one.
/// A version 5 reader handed one would read one operand and leave the other on
/// the stack, and from there every subsequent expression reads its operand from
/// the wrong slot. That misreads the rule rather than refusing it, which is the
/// failure this constant exists to prevent.
///
/// Version 7 added `Op::ModuleCall`, and with it the `hash` and `math` modules.
/// This one is the loud case rather than the quiet one: a version 6 reader has
/// no `ModuleCall`, so the byte lands on whatever opcode now follows and the
/// program it then executes is not the program that was compiled — most likely
/// falling off the end of a jump table and reporting a corrupt database, which
/// is the right thing for it to report. The version is bumped anyway, because
/// "most likely" is not a guarantee, and because `ModuleFunc` gained a payload
/// of `HashKind` whose discriminants a future reordering could move.
///
/// Version 8 added `Op::ForEachBegin`, for `for <var> in pe.resources`. The
/// loud case again — a version 7 reader has no such opcode — and bumped for the
/// same reason as version 7 despite that: the opcode takes a different number of
/// operands from the `ForBegin` that a reader without it would land on, so the
/// misreading is not a crash but a loop entered with the wrong bound off a stack
/// that is one value short. Version 8 also added the `PeField`, `PeElement` and
/// `PeFunc` members for the resource directory and the Rich signature, which is
/// the version 4 argument exactly: those discriminants are payload, and a
/// version 7 reader would answer one member with another.
///
/// Version 9 added `Op::RuleRef`, for a rule written in terms of another rule.
/// The loud case again: a version 8 reader has no such opcode, so the byte
/// lands on whatever follows it in the table and the payload — a rule index —
/// is executed as the next instruction. A corpus with no references between
/// its rules serialises identically under both versions, and the version is
/// bumped anyway, because a database that happens to be readable is not the
/// same thing as one that is correct to read.
///
/// Version 9 also changed what a stored rule has to carry. A rule now records
/// its **corpus position** — its index among every rule of the source, refusals
/// included — because that is the slot [`crate::program::Op::RuleRef`] names and the slot a
/// scan's result array is indexed by. It cannot be recomputed on load: the
/// image holds only the rules that survived, and a corpus position counted over
/// the survivors is off by one for every refusal before it. A rule reading
/// another rule's verdict from the wrong slot is a detection that fires on the
/// wrong file, which is the quiet kind of wrong this constant exists to refuse.
///
/// The rules are stored in *evaluation order* as well, so that a scan can walk
/// them from the front and read each answer out of the slot the rule before it
/// wrote. That is a property of the order they appear in rather than a field,
/// and it survives the round trip for free.
///
/// Version 10 added [`RuleSource`] and the `sources` list in the image: the
/// digests of the source files the rules were compiled from. This is the quiet
/// case, and the reason the version is bumped anyway is worth stating. A
/// version 9 reader would read the rule list and stop — bincode stops when the
/// fields it knows about are filled — so it would load the rules correctly and
/// silently have no record of where they came from. The rules would all work.
/// What would be lost is the answer to "is this file my own corpus?", and the
/// version 9 reader would give it wrong in the direction that matters: a
/// scanner with no record of its own sources reports them as malware, and
/// `av_scan::own` documents the measurement of exactly that. A reader that
/// cannot answer the question must not be the reader that answers it, which
/// means refusing the file.
/// Version 11 added [`RuleMetadata::score`], the confidence rating a
/// third-party rule set carries *in its own units*, as a field distinct from
/// [`RuleMetadata::weight`], this product's own point value. The two were one
/// field and both are serialised, so a version 10 reader would take the new
/// `score` for the `weight` beside it. This is the quiet case: the database
/// loads, every rule works, and the arithmetic underneath every verdict is a
/// different arithmetic from the one this build computes — which is exactly the
/// failure the split exists to end, so a reader that would reintroduce it must
/// refuse the file instead.
/// Version 12 added [`RuleMetadata::incontestable`], the flag that separates a
/// rule its author rated decisive from one this product convicts on a reading
/// of — its title, or a condition nothing ordinary satisfies. The
/// quintessential quiet case, and the worst of them: the field sits beside
/// [`RuleMetadata::quality`], which is an `Option<u8>` and therefore reads its
/// presence from a leading byte. A version 11 reader would take the new flag's
/// `1` for the tag of `Some`, take the next byte — the start of the hashes
/// list — for the value, and arrive at a `quality` of zero for **every rule in
/// the database**. Zero is below [`crate::calibrate::QUALITY_FLOOR`], so every
/// rule's weight would be halved, and the scan would run to completion, report
/// its findings, and be wrong by half about all of them. A reader that cannot
/// read a field must not be the reader that guesses at it, which is why this
/// refuses the file rather than trying.
pub const FORMAT_VERSION: u32 = 12;

/// Everything that can go wrong building or loading a rule set.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("rule database is truncated: {0} bytes is too short to hold a header")]
    Truncated(usize),
    #[error("not a rule database: expected magic {expected:?}, found {found:?}")]
    BadMagic { expected: [u8; 8], found: [u8; 8] },
    #[error(
        "rule database format version {found} cannot be read by this engine, which \
         writes version {supported}: the database was written by a different build of \
         this product. Rebuild it with this build (`wenle build`), or run the build \
         that wrote it"
    )]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("rule database is corrupt: {0}")]
    Corrupt(String),
    /// The machine has too little memory to hold the rules this file contains.
    ///
    /// # Why this is checked before the parse rather than survived during it
    ///
    /// Because a parse that runs out of memory does not return an error, it
    /// aborts the process. Rust allocates infallibly: the `Vec` and `String`
    /// growth inside a ten-thousand-rule parse hits
    /// [`handle_alloc_error`](std::alloc::handle_alloc_error) when the machine
    /// has nothing left to commit, and that function writes one line and calls
    /// `abort()`. An abort cannot be caught, so the front end dies with it.
    ///
    /// That is not hypothetical and the shape it takes is worth stating, because
    /// it is what a user reports: both front ends walk the tree *before* they
    /// load the database, on purpose — see [`RuleDatabase::check_file`] for that
    /// argument — so the abort lands after the walk. The scan appears to count
    /// the files and then exit by itself, with no message anywhere, because
    /// there is nothing left alive to print one — and the front end's own
    /// [`check_file`](RuleDatabase::check_file) call, which exists to move database
    /// failures *before* the walk, cannot help with this one: the file is
    /// perfectly readable, so the check passes and the abort waits for the walk
    /// to finish.
    ///
    /// Measured on this machine: `logs/crash.log` held a 4,193,376-byte request
    /// refused with 11,193,360 bytes of commit left, and the two 10,016- and
    /// 32,768-byte requests that followed it were the attempts to describe the
    /// first one.
    ///
    /// # Why the numbers are MiB and integers
    ///
    /// Integers because this value can be built on a machine that cannot
    /// allocate, and MiB because the three figures are hundreds of megabytes and
    /// a user comparing them should not have to count digits.
    #[error(
        "not enough memory to load the rule database: it is {file_mib} MiB on disk and needs \
         about {needed_mib} MiB in memory, and this machine has {free_mib} MiB left to commit. \
         The rules were not loaded, because loading them would have failed part-way through and \
         taken the process down with it. Close something, or give the machine more page file"
    )]
    OutOfMemory {
        /// The database file's size.
        file_mib: u64,
        /// What the parse is expected to need.
        needed_mib: u64,
        /// What the machine had left to commit.
        free_mib: u64,
    },
    /// Writing out a database whose string definitions have been discarded.
    ///
    /// Refused rather than written, because the file would be a valid database
    /// with no strings in it — a rule set that matches nothing, which is
    /// exactly the wrong thing to hand somebody who is relying on it. See
    /// [`StringValue::Shed`] for why the definitions go.
    #[error(
        "this rule database cannot be written back out: its string definitions were \
         discarded after loading, to save the memory of holding each one twice, and a \
         file written from it now would have no strings in it. Serialise a database \
         you have just compiled — `wenle build` writes one — rather than one you \
         have loaded"
    )]
    DefinitionsShed,
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

/// How much memory a loaded database occupies per byte of its file.
///
/// # Where the number comes from
///
/// Measured, not guessed: the shipped ten-thousand-rule database is 24.2 MiB on
/// disk, settles at 195 MB of live heap once loaded, and peaks at 379 MB while
/// being loaded — the last of which is the figure that matters here, because
/// what the parse has to survive is its own worst moment and not where it
/// stops. That is 15.7 times the file, and this rounds up to 20.
///
/// The measurement is from `crates/av-rules/tests/memory_probe.rs`, which
/// installs a counting allocator and prints that peak; it is the instrument to
/// re-run rather than the number to trust. Two changes on 2026-10-09 cut both
/// figures a long way — the compiled regular expressions are now shared between
/// the 852 strings that spell 497 distinct expressions, and the string
/// definitions are discarded once the matchers have been built from them (see
/// [`StringValue::Shed`]) — and before them the same probe read 296 MB settled
/// and 455 MB at the peak. `av-fs`'s budget module quotes this number, in prose,
/// as the resident the scan budget must leave room for.
///
/// # Why the factor is so large
///
/// Because almost none of a database is bytes. A file of 25 MB expands into
/// 10,764 rule structures, each holding a parsed condition tree, a list of
/// string patterns in several matching modes, and a metadata block with a dozen
/// optional `String`s — and each of those is a separate allocation with its own
/// header, not a slice of one buffer. The file's own bytes are the smallest part
/// of what loading it costs.
///
/// # Why it is charged even though the file is small
///
/// Because the file being small is what makes the abort surprising. A 25 MB file
/// looks affordable on a machine with 30 MB free, and the parse then asks for
/// twenty times that in increments, and the increment that fails is the one that
/// kills the process.
const MEMORY_PER_BYTE: u64 = 20;

/// How much commit the load must leave behind, beyond the rules themselves.
///
/// The same argument as `av-fs`'s read headroom, and the same size: the failure
/// path allocates — building this error, formatting it, and the front end
/// printing it — and a check that spends the last byte of commit cannot report
/// that it did.
const LOAD_HEADROOM: u64 = 64 * 1024 * 1024;

/// Refuse a database the machine cannot hold, before parsing it.
///
/// Answers [`DatabaseError::OutOfMemory`] when the parse is expected not to fit,
/// and `Ok` when it is expected to — including when the machine will not say how
/// much commit it has, because not knowing is not a reason to refuse to load a
/// rule set.
fn afford(file: u64) -> Result<(), DatabaseError> {
    afford_for(
        file,
        av_core::alloc::memory_status().map(|status| status.available_commit),
    )
}

/// The decision [`afford`] makes, for a known amount of free commit.
///
/// Split out so that it can be tested without a machine that happens to be
/// nearly full. The three numbers it turns on are the ones that were wrong, and
/// a test that could only run on an exhausted machine would never run.
fn afford_for(file: u64, free: Option<u64>) -> Result<(), DatabaseError> {
    const MIB: u64 = 1024 * 1024;
    let Some(free) = free else {
        // Not knowing is not a reason to refuse to load a rule set. A machine
        // that will not report its commit is a machine whose loads are no worse
        // than they were before this check existed.
        return Ok(());
    };
    let needed = file.saturating_mul(MEMORY_PER_BYTE);
    if needed.saturating_add(LOAD_HEADROOM) <= free {
        return Ok(());
    }
    Err(DatabaseError::OutOfMemory {
        file_mib: file / MIB,
        needed_mib: needed / MIB,
        free_mib: free / MIB,
    })
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
    /// The confidence rating a third-party rule set carries, in that set's own
    /// units. Kept beside [`RuleMetadata::weight`] rather than merged with it:
    /// this one is calibrated onto the engine's ladder by
    /// [`crate::calibrate::apply`], and the other is used as written. See
    /// [`crate::ast::RuleMeta::score`].
    pub score: Option<u16>,
    /// No corroboration needed: this detection alone justifies a malicious
    /// verdict.
    pub decisive: bool,
    /// Beyond argument as well as decisive: nothing may discount this rule's
    /// finding, cap it, or call a file clean because of it.
    ///
    /// False for a rule that convicts on a *reading* of it rather than on its
    /// author's rating — its name ([`crate::family`]) or the shape of its
    /// condition ([`crate::content`]). Those are two of the three routes to
    /// [`RuleMetadata::decisive`]; a reading can be wrong about the world, and
    /// the third route is the author's own confidence, which the file in front
    /// of us cannot argue with. See [`crate::calibrate::apply`], which is where
    /// the routes are told apart, and [`av_core::Detection::incontestable`] for
    /// why they are not one.
    pub incontestable: bool,
    /// The author's own quality rating, as third-party rule sets carry it.
    pub quality: Option<u8>,
    /// Hashes of known samples, harvested into the exact-match blocklist.
    pub hashes: Vec<String>,
    /// Meta keys the engine does not model, preserved so an importer that
    /// re-exports a rule set does not silently discard an author's annotations.
    pub extra: BTreeMap<String, MetaValue>,
}

impl RuleMetadata {
    /// Build the metadata a scan reads, with [`crate::calibrate`] applied.
    ///
    /// `tags` is the rule's whole tag list — the ones after the colon on the
    /// `rule` line and the ones in its `tags` metadata string — because
    /// calibration reads both and only the caller has both. Everything that
    /// builds a [`RuleMetadata`] goes through here, so that no route into the
    /// engine can skip the calibration and produce a rule set whose scores mean
    /// something different from the one next to it.
    ///
    /// The rule is passed whole, and deliberately so. Calibration reads three
    /// things that are not metadata: the rule's name ([`crate::family`]), and
    /// its strings and condition, which together say what it demands
    /// ([`crate::content`]). A `RuleMeta` alone supplies none of them, and the
    /// earlier signature that took one was a route into the engine that
    /// produced metadata calibrated by a different set of rules than every
    /// other route — the exact failure this constructor exists to prevent.
    /// Passing the [`crate::ast::Rule`] leaves no reading for a caller to
    /// supply wrongly, because a caller supplies none of them.
    ///
    /// `tags` is still separate because it is not the rule's own: it is the
    /// merged list of the tags on the `rule` line and the ones in its `tags`
    /// metadata string, and only the caller has both.
    pub fn calibrated(rule: &crate::ast::Rule, tags: &[String]) -> Self {
        let meta = &rule.meta;
        let mut built = Self {
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
            score: meta.score,
            decisive: meta.decisive,
            // A rule that states `decisive` in its own metadata is its author
            // staking the strongest claim the language can make, which is the
            // same kind of statement as a third-party set's own decisive
            // rating — see [`crate::calibrate::apply`]. Both are beyond
            // trust's reach; a claim read out of a rule's *name* or out of the
            // shape of its *condition* is not.
            incontestable: meta.decisive,
            quality: meta.quality,
            hashes: meta.hashes.clone(),
            extra: meta.extra.clone(),
        };
        let demand = crate::content::demand(&rule.strings, &rule.condition);
        crate::calibrate::apply(&mut built, tags, &rule.name, demand);
        built
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
    ///
    /// Read off [`RuleMetadata::weight`] rather than [`RuleMetadata::score`],
    /// because [`RuleMetadata::calibrated`] has already turned the author's own
    /// units into this engine's points and left the result there. A rule that
    /// states neither falls back to its severity's rung.
    pub fn score(&self) -> u16 {
        self.weight
            .unwrap_or_else(|| self.effective_severity().default_score())
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
    /// The rule's position in the corpus it was compiled with, counting the
    /// rules that were refused alongside it.
    ///
    /// This is the slot its verdict belongs in. `Op::RuleRef` names another
    /// rule by corpus position, so a scan keeps one boolean per corpus rule and
    /// a rule that reads another reads the same array the scanner writes. It is
    /// not the rule's position in [`RuleDatabase::rules`], because that list is
    /// missing whatever was refused, and a shift of one there would have one
    /// rule reading another rule's verdict — a false positive with no visible
    /// cause.
    pub corpus_index: u32,
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
    ///
    /// The first reason is spent by the time loading is over, and
    /// [`RuleDatabase::shed_definitions`] then empties the second down to the
    /// identifiers — see [`StringValue::Shed`]. A database that has just been
    /// compiled, or read back with [`RuleDatabase::from_bytes`], still holds
    /// them whole.
    pub defs: Vec<StringDef>,
    /// The compiled matchers. Rebuilt on load, never serialised.
    matchers: Vec<CompiledString>,
}

/// A rule's whole tag list: the ones after the colon on the `rule` line, then
/// the ones in its `tags` metadata string.
///
/// Both are the author labelling the rule, and nothing downstream should have
/// to know which syntax a particular corpus used. The rule line comes first,
/// which is the order a reader of the rule sees them in.
fn merged_tags(rule: &Rule) -> Vec<String> {
    let mut tags = rule.tags.clone();
    tags.extend(rule.meta.tags.iter().cloned());
    tags
}

impl CompiledRule {
    /// The compiled matchers, for the memory probe. See [`crate::probe`].
    #[cfg(feature = "memory-probe")]
    pub(crate) fn probe_matchers(&self) -> &Vec<CompiledString> {
        &self.matchers
    }

    /// Wrap a compiled program and its definitions, building the matchers.
    ///
    /// A string the matcher refuses is left out of `matchers` but keeps its
    /// slot, so the bytecode's slot numbering is unaffected and the condition
    /// sees the string as never matching. That is the honest reading of a
    /// string the engine cannot search for, and it is what the prefilter
    /// already assumes: a refused string contributes no atoms, so its rule is
    /// evaluated every time and the missing match is what decides it.
    ///
    /// `corpus_index` is the rule's position in the corpus it was compiled
    /// with, refusals included — see the field of the same name.
    ///
    /// `cache` is shared across every rule of one load, so that two rules which
    /// wrote the same regular expression share one compiled program. It is not
    /// `pub` because [`RegexCache`] is an implementation detail of loading a
    /// database; a caller with one string to compile wants
    /// [`crate::matcher::compile`].
    pub(crate) fn new(
        rule: &Rule,
        program: Program,
        corpus_index: u32,
        cache: &mut RegexCache,
    ) -> (Self, Vec<(u32, MatcherError)>) {
        let mut matchers = Vec::with_capacity(rule.strings.len());
        let mut refusals = Vec::new();
        for (slot, def) in rule.strings.iter().enumerate() {
            let slot = slot as u32;
            match matcher::compile_with(def, slot, cache) {
                Ok(compiled) => matchers.push(compiled),
                Err(e) => refusals.push((slot, e)),
            }
        }
        let tags = merged_tags(rule);
        let compiled = Self {
            name: rule.name.clone(),
            corpus_index,
            private: rule.private,
            global: rule.global,
            metadata: RuleMetadata::calibrated(rule, &tags),
            tags,
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
    ///
    /// This is the one thing a loaded database reads out of its definitions,
    /// and it is the reason [`RuleDatabase::shed_definitions`] keeps the
    /// identifiers and throws away everything else.
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

/// How a rule set's own scores are distributed, and what that means for the
/// thresholds in force.
///
/// # The one question this answers
///
/// *Can a single rule condemn a file?* A scanner whose every rule is worth more
/// than its malicious threshold reports everything it recognises as malicious
/// on the strength of one match; a scanner whose every rule is worth less can
/// never condemn anything at all, and both look identical from the outside —
/// both produce a report. The difference only shows up in the false-positive
/// rate, which is the most expensive thing to discover late, and the way to see
/// it early is to ask the database directly: count the rules whose score alone
/// clears each threshold.
///
/// The counts are of rules, not of scores, so `alone_malicious` is exactly the
/// number of rules that can put a clean file into the malicious band without
/// corroboration from anything else. A rule set of 10,764 rules in which a few
/// dozen can do that is a rule set with a working middle; one in which
/// thousands can is a rule set that is really a blacklist of single signatures
/// wearing a scoring engine's clothes.
///
/// # Why a decisive rule is counted here whatever it scores
///
/// Because the verdict does not read its score. [`Assessment::finalize`] returns
/// [`av_core::Verdict::Malicious`] the moment any detection is decisive, before any
/// addition happens — a rule its author marked decisive is one whose author is
/// asserting that the match is the answer, and adding up points on top of an
/// answer is arithmetic that can only get it wrong. So a rule can condemn a
/// file on one match at a score of 1, and a count that read only the scores
/// would report a smaller number than the truth, in the direction that looks
/// reassuring.
///
/// [`Assessment::finalize`]: av_core::Assessment::finalize
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleProfile {
    /// Rules per [`Severity`], indexed by the severity's position in the
    /// ladder: `[Info, Low, Medium, High, Critical]`.
    pub by_severity: [usize; 5],
    /// Rules per score, smallest first. Only the scores that occur.
    pub by_score: BTreeMap<u16, usize>,
    /// Rules that on their own put a file into the suspicious band or above.
    pub alone_suspicious: usize,
    /// Rules that on their own put a file into the malicious band: they are
    /// decisive, or their score clears `thresholds.malicious`.
    pub alone_malicious: usize,
    /// How many of the rules counted above are counted because they are
    /// decisive rather than because of their score. Reported so that a
    /// surprising `alone_malicious` can be attributed without re-deriving it.
    pub alone_malicious_by_decree: usize,
    /// How many of those convictions this product *read* out of the rule rather
    /// than taking from the author's own rating, and which are therefore open
    /// to argument by evidence about who published the file.
    ///
    /// A subset of [`Self::alone_malicious`] rather than of
    /// [`Self::alone_malicious_by_decree`]: reading a rule also raises its
    /// weight to the convicting rung, so those rules are counted by their score
    /// as well as by the decree. What the number answers is "how much of this
    /// database's convicting power is this product's opinion about the rules
    /// rather than an author's opinion about the samples".
    ///
    /// Two readings count here, and neither is the author's rating: a **name**
    /// that writes down a family and an instance of it, and a **condition**
    /// that cannot be satisfied by an ordinary string. Those rules still
    /// convict on their own; what they do not do is convict a file whose
    /// identity is proven, which is the trade `av_scan::trust` documents.
    /// Only the rating route — an author's 90-odd score at a decent quality —
    /// takes that answer away from the publisher.
    pub alone_malicious_open_to_argument: usize,
    /// Rules that score nothing: recorded on a match and never counted towards
    /// a verdict.
    pub observations: usize,
}

impl RuleProfile {
    /// The rules at one severity.
    pub fn at(&self, severity: Severity) -> usize {
        self.by_severity[severity_index(severity)]
    }
}

/// Where a severity sits in the ladder, for indexing [`RuleProfile`]'s array.
///
/// A free function rather than a method on [`Severity`], because the array is
/// this module's and the ordering it encodes is the derived `Ord` on the enum —
/// which is declaration order. Keeping the two in one place means a severity
/// added to the ladder shows up here as a `match` that no longer compiles,
/// rather than as a table with a row nothing ever writes.
fn severity_index(severity: Severity) -> usize {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
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
///
/// The rules are held in **evaluation order**: a rule that reads another rule's
/// verdict sits after it, so a scan can walk the list from the front and be sure
/// the answers are there. [`RuleDatabase::compile`] establishes that from the
/// corpus; see [`RuleDatabase::from_rules`] for what a caller assembling rules
/// by hand has to guarantee.
#[derive(Debug)]
pub struct RuleDatabase {
    rules: Vec<CompiledRule>,
    /// The number of slots a scan's result array needs: the highest
    /// `corpus_index` in the set, plus one.
    result_len: usize,
    prefilter: Prefilter,
    /// The literal automatons, built from the same rules and on the same terms
    /// as `prefilter`: a large structure that is rebuilt on load rather than
    /// serialised.
    sweep: LiteralSweep,
    stats: DatabaseStats,
    /// The source files this database was compiled from, with the digest of
    /// each one's bytes. Serialised with the image; see [`RuleSource`].
    sources: Vec<RuleSource>,
    /// The digest of the `.avdb` file these rules were read from, when they
    /// were read from one.
    ///
    /// Not serialised: it is a fact about the container, not about the rules,
    /// and a database assembled in memory has no file to describe. Set by
    /// [`RuleDatabase::from_bytes`], which is where the bytes are in hand.
    file_digest: Option<String>,
}

/// One rule source file a database was compiled from.
///
/// # Why the digest is recorded at all
///
/// A rule is a description of bytes to look for, written down in a file that
/// contains those bytes. So the corpus is a file that matches its own rules:
/// measured on the 10,764-rule source this product ships, scanning it produced
/// 43 detections and a `malicious` verdict on the product's own signature data.
/// A scanner that did that would be reporting itself, which is both wrong and —
/// because the file is on disk wherever the product was built or unpacked —
/// routine rather than exotic.
///
/// The fix is to know the file rather than to guess at it, and a path is the
/// wrong way to know it: the same source sits in a build tree, in the
/// installation, in a backup and in whatever directory somebody copied it to,
/// and every one of those is the same file. A digest is the same in all of
/// them. See `av_scan::own`, which is where the answer is used.
///
/// Recorded at build time because it cannot be recovered afterwards: the
/// database holds the compiled rules, and the text they were compiled from is
/// gone by then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSource {
    /// The name the file had when it was compiled. Carried for the report a
    /// user reads after a scan — "this is the file this product was built
    /// from" is a sentence that needs a name in it — and for nothing else: a
    /// file is recognised by its digest, never by its path.
    pub name: String,
    /// SHA-256 of the file's bytes, lowercase hex. See
    /// [`av_core::hash::HashKind`].
    pub sha256: String,
}

impl RuleSource {
    /// A source with its digest computed from `bytes`.
    pub fn of(name: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            name: name.into(),
            sha256: av_core::hash::HashKind::Sha256.digest(bytes),
        }
    }
}

impl RuleDatabase {
    /// Build from rules that are already compiled.
    ///
    /// `rules` must be in evaluation order — a rule that reads another must come
    /// after it — and each rule's `corpus_index` must be the slot its verdict
    /// belongs in, distinct from every other rule's. [`RuleDatabase::compile`]
    /// produces both. A caller whose rules do not reference each other can
    /// number them `0..n` and pass them in any order; the order then decides
    /// nothing but which rule is tried first.
    ///
    /// The result array is sized from the largest `corpus_index` present rather
    /// than from the corpus the rules came from, which is sound because a rule
    /// that reads a refused rule is refused with it: no rule that can run reads
    /// a slot past the end of this list.
    pub fn from_rules(rules: Vec<CompiledRule>) -> Self {
        let filters: Vec<RuleFilter> = rules
            .iter()
            .map(|rule| RuleFilter {
                strings: rule.string_atoms(),
                required: rule.program.required_strings.clone(),
            })
            .collect();
        let prefilter = Prefilter::build(&filters);
        // Built here rather than in `from_bytes`, because `from_bytes` builds
        // the matchers and then calls this: one place that knows how a database
        // turns into automatons, so a loaded database and a compiled one cannot
        // disagree about what the sweep answers.
        let sweep = LiteralSweep::build(&rules);
        let stats = summarise(&rules);
        let result_len = rules
            .iter()
            .map(|rule| rule.corpus_index as usize + 1)
            .max()
            .unwrap_or(0);
        Self {
            rules,
            result_len,
            prefilter,
            sweep,
            stats,
            sources: Vec::new(),
            file_digest: None,
        }
    }

    /// Record the source files this database was compiled from.
    ///
    /// A database compiled by [`RuleDatabase::compile`] alone does not know
    /// them, and this is what tells it. Called by the build command, which is
    /// the only place both the files and the compiled result are in hand.
    ///
    /// A database whose sources were never recorded behaves exactly as one
    /// compiled from a source whose digest nobody has: it recognises nothing as
    /// its own. That is the safe direction of the two — the cost is a scan that
    /// reports the corpus as malware, and the alternative is a scanner that
    /// vouches for a file it has no proof about.
    #[must_use]
    pub fn with_sources(mut self, sources: Vec<RuleSource>) -> Self {
        self.sources = sources;
        self
    }

    /// The source files this database was compiled from, when they were
    /// recorded.
    pub fn sources(&self) -> &[RuleSource] {
        &self.sources
    }

    /// The SHA-256 of the `.avdb` file these rules were read from.
    ///
    /// `None` for a database that was compiled in memory, which was never a
    /// file and therefore cannot be one.
    pub fn file_digest(&self) -> Option<&str> {
        self.file_digest.as_deref()
    }

    /// Compile a rule set from source.
    ///
    /// Never fails as a whole. A rule that cannot be compiled is recorded in
    /// the report and left out, because the alternative — refusing the rule set
    /// — would mean one unsupported construct costs every other rule in the
    /// file their detection.
    ///
    /// # Why every rule is read before any is compiled
    ///
    /// A rule may be written in terms of another rule, and the reference may
    /// point forward — to a rule in a later chunk of the same file. So no rule
    /// can be compiled until the whole source has been parsed, and the compile
    /// is a two-pass affair over the entire set rather than a loop over rules.
    /// The rules are held in memory between the passes; a rule set of ten
    /// thousand rules out of a seventeen-megabyte file costs a few tens of
    /// megabytes to hold, which is the price of resolving names across the set.
    ///
    /// # Why the order the rules come out in matters
    ///
    /// They come out in evaluation order, which is not source order: the corpus
    /// sorts them so that a rule runs after everything it names. A scan walks
    /// the list once and reads each verdict from the slot the rule before it
    /// wrote. See [`RuleDatabase::rules`].
    pub fn compile(source: &str) -> (Self, CompileReport) {
        let split = ruleset::split_rule_chunks(source);
        let mut report = CompileReport {
            chunks_malformed: split.malformed,
            ..CompileReport::default()
        };

        // Pass 1: parse every chunk and keep every rule. The parsed files are
        // kept alive beside their rules because a rule borrows the text it was
        // parsed from — `Rule` holds `&str` spans, not copies.
        // A rule the splitter announced but no chunk accounts for was never
        // offered to the parser, so nothing else in this report would mention
        // it. Reported as one refusal rather than a count, because the splitter
        // knows the file and the line but not which rule: `unaccounted` is a
        // number, and a number with no name is still better than silence.
        let unaccounted = split.unaccounted();
        if unaccounted > 0 {
            report.refusals.push(RuleRefusal {
                name: format!("<{unaccounted} rule(s) the splitter dropped>"),
                line: 0,
                reason: format!(
                    "{} rule headers were seen but {} chunks and {} malformed blocks \
                     account for them: the splitter could not find the end of a rule",
                    split.headers,
                    split.chunks.len(),
                    split.malformed
                ),
                feature: "split error",
            });
        }

        let mut files: Vec<(usize, crate::parser::ParsedFile)> =
            Vec::with_capacity(split.chunks.len());
        for chunk in &split.chunks {
            match crate::parser::parse_file(chunk.text) {
                Ok(file) => {
                    report.chunks_parsed += 1;
                    files.push((chunk.line, file));
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
                }
            }
        }

        // The corpus, flat, in source order. `Op::RuleRef` operands are
        // positions in *this* list, and so is a scan's result array; the two
        // have to be counted the same way, refusals included, or a rule reads
        // another rule's verdict.
        let rules: Vec<&Rule> = files
            .iter()
            .flat_map(|(_, file)| file.rules.iter())
            .collect();
        let lines: Vec<usize> = files
            .iter()
            .flat_map(|(line, file)| file.rules.iter().map(move |_| *line))
            .collect();
        report.rules_seen = rules.len();
        let corpus_len = rules.len();

        // Pass 2: compile every rule against every other, and order them.
        let corpus = crate::compiler::compile_corpus(rules.iter().copied());
        let order: Vec<u32> = corpus.order().to_vec();
        let compiled_count = corpus.compiled();
        // Split into the programs and the reasons there are not any, rather
        // than asking the corpus twice: the answers line up by index, and the
        // index is what the report needs.
        let mut programs: Vec<Option<Program>> = Vec::with_capacity(corpus_len);
        let mut errors: Vec<Option<CompileError>> = Vec::with_capacity(corpus_len);
        for outcome in corpus.into_rules() {
            match outcome {
                Ok(program) => {
                    programs.push(Some(program));
                    errors.push(None);
                }
                Err(e) => {
                    programs.push(None);
                    errors.push(Some(e));
                }
            }
        }

        // Pass 3: admit rules in evaluation order, propagating each refusal
        // forward. One pass is enough because the order guarantees a rule's
        // dependencies have already been decided by the time it is reached.
        let mut admitted = vec![false; corpus_len];
        let mut compiled: Vec<CompiledRule> = Vec::with_capacity(compiled_count);
        // One cache for the whole load, not one per rule: the expressions a
        // corpus repeats are repeated across rules, which is where the sharing
        // is. See `RegexCache`.
        let mut regex_cache = RegexCache::default();
        for &index in &order {
            let i = index as usize;
            let Some(program) = programs[i].take() else {
                // Did not compile. The corpus recorded why, and pass 4 below
                // copies that reason into the report.
                continue;
            };
            let rule = rules[i];

            // A global rule is the gate, and a scan runs the gate before
            // anything else — so a global rule that reads another rule has
            // nothing to read, whatever the order. Refused rather than
            // evaluated as `false`, which would close the gate on every file
            // and report the whole set as clean.
            if rule.global {
                if let Some(&dep) = program
                    .rule_refs()
                    .iter()
                    .find(|&&d| !rules[d as usize].global)
                {
                    report.refusals.push(RuleRefusal {
                        name: rule.name.clone(),
                        line: lines[i],
                        reason: format!(
                            "global rule `{}` reads `{}`, which is not global: the gate \
                             is evaluated before every other rule, so there would be \
                             nothing to read",
                            rule.name, rules[dep as usize].name
                        ),
                        feature: "rule dependency",
                    });
                    continue;
                }
            }

            // A rule that reads something this database did not admit reads a
            // slot no scan will ever write. `false` there turns `OTHER and $a`
            // into a detection that never fires and `not OTHER` into a
            // condition true of every file on the disk — the second being a
            // false positive manufactured out of a missing string.
            if let Some(&broken) = program.rule_refs().iter().find(|&&d| !admitted[d as usize]) {
                report.refusals.push(RuleRefusal {
                    name: rule.name.clone(),
                    line: lines[i],
                    reason: format!(
                        "`{}` reads `{}`, which was refused",
                        rule.name, rules[broken as usize].name
                    ),
                    feature: "rule dependency",
                });
                continue;
            }

            let (compiled_rule, string_refusals) =
                CompiledRule::new(rule, program, index, &mut regex_cache);
            for (slot, e) in &string_refusals {
                report
                    .string_refusals
                    .push((rule.name.clone(), *slot, e.message.clone()));
            }

            // A rule with a string the matcher cannot search for is **not**
            // admitted. It would otherwise be a rule whose condition reads a
            // slot that never matches, and that is unsound in both directions:
            // `$a and $b` with `$b` refused is a detection that never fires,
            // and `not $b` with `$b` refused is a condition that is true on
            // every file. Neither is what the rule's author wrote, and neither
            // is visible in a scan.
            //
            // The cost is a detection that does not fire, which the histogram
            // below names; the alternative is a verdict that is confidently
            // wrong about a file.
            let Some((slot, error)) = string_refusals.first() else {
                admitted[i] = true;
                compiled.push(compiled_rule);
                continue;
            };
            report.refusals.push(RuleRefusal {
                name: rule.name.clone(),
                line: lines[i],
                reason: format!(
                    "string {} (`{}`) cannot be searched: {}",
                    slot, rule.strings[*slot as usize].id, error.message
                ),
                feature: error.feature.unwrap_or("invalid string"),
            });
        }

        // Pass 4: the rules the corpus refused, reported alongside the ones the
        // database refused, so that one report covers the whole source. Reported
        // in corpus order rather than evaluation order, because a refused rule
        // was never placed in an order and the source is the only sequence it
        // has.
        for (i, error) in errors.into_iter().enumerate() {
            let Some(error) = error else { continue };
            report.refusals.push(RuleRefusal {
                name: rules[i].name.clone(),
                line: lines[i],
                reason: error.message,
                feature: error.feature,
            });
        }

        report.string_refusals.shrink_to_fit();
        let mut database = Self::from_rules(compiled);
        // The corpus counted rules the database may have dropped, and a rule
        // that names one of those was dropped with it, so this is never smaller
        // than the highest index a surviving rule reads.
        database.result_len = corpus_len.max(database.result_len);
        (database, report)
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

    /// The rules, in evaluation order.
    ///
    /// A rule that reads another rule's verdict appears after it, so a scan can
    /// walk this list from the front and read each answer out of the slot the
    /// earlier rule wrote. Source order is not preserved and is not meaningful
    /// here; a rule knows its own source position through its span, and the
    /// compile report is what is ordered by source.
    /// The source files this database was compiled from, for the memory probe.
    /// See [`crate::probe`].
    #[cfg(feature = "memory-probe")]
    pub(crate) fn probe_sources(&self) -> &Vec<RuleSource> {
        &self.sources
    }

    #[cfg(feature = "memory-probe")]
    pub(crate) fn probe_rules(&self) -> &Vec<CompiledRule> {
        &self.rules
    }

    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// The number of result slots one scan needs.
    ///
    /// One per corpus rule, refusals included, because `Op::RuleRef` names a
    /// rule by its position in the corpus. A scan allocates this once and
    /// writes each rule's verdict into `rules()[..].corpus_index` as it goes.
    pub fn result_len(&self) -> usize {
        self.result_len
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

    /// The literal automatons, for the scanner's per-buffer sweep.
    ///
    /// Shared by every scanning thread, which is why the hit table is not part
    /// of it: what a scan writes is per thread and per file, and lives in
    /// [`SweepHits`](crate::sweep::SweepHits).
    pub fn sweep(&self) -> &LiteralSweep {
        &self.sweep
    }

    pub fn stats(&self) -> &DatabaseStats {
        &self.stats
    }

    /// How this rule set's scores are distributed, against the thresholds in
    /// force. See [`RuleProfile`] for what the numbers mean and why they are
    /// worth looking at.
    ///
    /// Computed rather than stored, because it is a function of the thresholds
    /// as much as of the rules: the same database against a stricter
    /// configuration answers the "can one rule condemn a file" question
    /// differently, and a figure baked in at build time would be answering it
    /// about the configuration that built it.
    pub fn profile(&self, thresholds: &VerdictThresholds) -> RuleProfile {
        let mut profile = RuleProfile::default();
        for rule in &self.rules {
            let score = rule.metadata.score();
            let decisive = rule.metadata.decisive;
            profile.by_severity[severity_index(rule.metadata.effective_severity())] += 1;
            *profile.by_score.entry(score).or_insert(0) += 1;
            if score == 0 && !decisive {
                profile.observations += 1;
            }
            if decisive || score >= thresholds.suspicious {
                profile.alone_suspicious += 1;
            }
            if decisive || score >= thresholds.malicious {
                profile.alone_malicious += 1;
                if score < thresholds.malicious {
                    profile.alone_malicious_by_decree += 1;
                }
                if decisive && !rule.metadata.incontestable {
                    profile.alone_malicious_open_to_argument += 1;
                }
            }
        }
        profile
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
        // Checked before anything is built, so a refusal costs nothing and
        // cannot half-happen. Asked of the rules rather than kept as a flag on
        // the database: a flag and the definitions it describes can drift
        // apart, and this answer cannot.
        if self
            .rules
            .iter()
            .any(|rule| rule.defs.iter().any(|def| matches!(def.value, StringValue::Shed)))
        {
            return Err(DatabaseError::DefinitionsShed);
        }
        let image = DatabaseImage {
            rules: self
                .rules
                .iter()
                .map(|rule| RuleImage {
                    name: rule.name.clone(),
                    corpus_index: rule.corpus_index,
                    private: rule.private,
                    global: rule.global,
                    tags: rule.tags.clone(),
                    metadata: rule.metadata.clone(),
                    program: rule.program.clone(),
                    defs: rule.defs.clone(),
                })
                .collect(),
            sources: self.sources.clone(),
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
        let length = Self::check_header(bytes)?;
        const HEADER: usize = HEADER_LEN;
        let body = bytes
            .get(HEADER..HEADER + length)
            .ok_or(DatabaseError::Truncated(bytes.len()))?;

        let image: DatabaseImage = bincode::deserialize(body)?;
        let mut rules = Vec::with_capacity(image.rules.len());
        // One cache for the whole file, for the same reason `compile` uses one:
        // the expressions this corpus repeats are repeated across rules.
        let mut regex_cache = RegexCache::default();
        for rule in image.rules {
            // Rebuilt here rather than stored, which is the trade this module's
            // documentation is about.
            let mut matchers = Vec::with_capacity(rule.defs.len());
            for (slot, def) in rule.defs.iter().enumerate() {
                if let Ok(compiled) = matcher::compile_with(def, slot as u32, &mut regex_cache) {
                    matchers.push(compiled);
                }
            }
            rules.push(CompiledRule {
                name: rule.name,
                corpus_index: rule.corpus_index,
                private: rule.private,
                global: rule.global,
                tags: rule.tags,
                metadata: rule.metadata,
                program: rule.program,
                defs: rule.defs,
                matchers,
            });
        }
        // The digest of the file is taken here, from the bytes that were
        // handed in, rather than by `load` — so that the two ways in produce
        // the same answer and a caller who read the file itself still gets a
        // database that knows what it is. It is a digest of the whole file
        // including its header, which is what a copy of that file elsewhere on
        // disk has.
        Ok(Self::from_rules(rules)
            .with_identity(av_core::hash::HashKind::Sha256.digest(bytes), image.sources))
    }

    /// Attach what the image says about where these rules came from.
    fn with_identity(mut self, file_digest: String, sources: Vec<RuleSource>) -> Self {
        self.file_digest = Some(file_digest);
        self.sources = sources;
        self
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DatabaseError> {
        std::fs::write(path, self.to_bytes()?)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let file = std::fs::metadata(path)?.len();
        // Asked before the parse, for the reason [`DatabaseError::OutOfMemory`]
        // gives in full: the parse cannot report that it ran out of memory,
        // because the way it runs out is the process aborting. A refusal here
        // costs one `GlobalMemoryStatusEx` and turns a vanished scan into a
        // sentence naming three numbers the user can act on.
        afford(file)?;
        // The read below allocates the file's bytes infallibly too, which the
        // check above has already paid for: `MEMORY_PER_BYTE` covers the whole
        // resident footprint of a loaded database, of which the file's own bytes
        // are the smallest part.
        let mut database = Self::from_bytes(&std::fs::read(path)?)?;
        // Here rather than in `from_bytes`, and that is deliberate: `from_bytes`
        // is also the reader half of the write/read round trip, and a database
        // read back from its own bytes has to still hold the definitions it was
        // written from or the round trip would not close. Loading a file to
        // scan with is the case where they are dead weight.
        database.shed_definitions();
        Ok(database)
    }

    /// Drop the string definitions, keeping their identifiers.
    ///
    /// # Why
    ///
    /// A loaded database holds every string definition twice. Once as the
    /// author wrote it ([`CompiledRule::defs`], which is what a file is
    /// serialised from) and once inside the compiled matcher, which is what a
    /// scan reads. Only the second is needed to scan: the first is read after
    /// loading for exactly one thing, naming a matched string in a report, and
    /// that needs the identifier alone.
    ///
    /// Measured on the shipping corpus, with a counting allocator: of the
    /// 296 MB such a database used to occupy, 45.3 MB was the hex token trees
    /// stored a second time, plus under a megabyte of literal and regex text.
    /// Those trees are the whole of what is kept twice — a literal is stored
    /// twice too, but it is a pointer into the file's bytes rather than a
    /// rebuilding of them, so there is nothing to free.
    ///
    /// # What it costs
    ///
    /// The database can no longer be serialised, and
    /// [`Self::to_bytes`] refuses rather than writing a file with no strings in
    /// it. Nothing in the product does that with a loaded database: the writer
    /// is `wenle build`, which writes one it has just compiled.
    ///
    /// Idempotent, so calling it twice is not a mistake.
    pub fn shed_definitions(&mut self) {
        for rule in &mut self.rules {
            for def in &mut rule.defs {
                if !matches!(def.value, StringValue::Shed) {
                    // Only the value: the identifier is read by `string_id`, and
                    // the modifier list and source span describe a definition
                    // whose value is gone, so replacing them would be dressing
                    // up an absence rather than recording one.
                    def.value = StringValue::Shed;
                }
            }
        }
    }

    /// Check the first twenty bytes of a database file, without reading it.
    ///
    /// # Why a front end wants this before it starts work
    ///
    /// Because of what a scan does before it loads the database. Both front ends
    /// walk the tree first — deliberately, so that a mistyped path is reported
    /// in a second rather than after a 25 MB file has been parsed — and that
    /// ordering means every way the database can be unusable is discovered
    /// *after* the walk. On a folder of any size that is minutes of work
    /// followed by a message about a file the user never named, and the message
    /// arrives at the moment they stopped waiting for it.
    ///
    /// Measured on this machine: a build whose format version did not match the
    /// installed database refused every scan, and the user's own diagnosis of it
    /// was a guess about their folder's name, because a failure that arrives
    /// after a walk looks like it came from the walk.
    ///
    /// The check is magic, version and body length, which is everything that can
    /// be wrong with a database for a reason other than its contents. It is not
    /// a substitute for [`Self::load`] — a file that passes this can still be
    /// truncated or corrupt — and it is not a claim that the rules inside will
    /// work. It is a claim that this build is able to try.
    ///
    /// # And the memory, which is why this is the version that matters
    ///
    /// The same ordering argument applies to memory, and there it is the
    /// difference between a sentence and a vanished window. A database that
    /// cannot be held is a database whose parse will abort the process — see
    /// [`DatabaseError::OutOfMemory`] — and an abort cannot be reported by the
    /// code that discovers it. Asking here means the front end discovers it
    /// *before* the walk, which is where a user can still read the answer: the
    /// failure arrives in the same second as the click, naming three numbers,
    /// instead of after minutes of enumeration followed by the window closing on
    /// its own.
    ///
    /// Returns the length of the body the header declares, which is the one
    /// thing a caller cannot see for itself without doing the same arithmetic.
    pub fn check_file(path: impl AsRef<Path>) -> Result<usize, DatabaseError> {
        let path = path.as_ref();
        let file = std::fs::metadata(path)?.len();
        afford(file)?;
        let mut header = [0u8; HEADER_LEN];
        let mut file = std::fs::File::open(path)?;
        std::io::Read::read_exact(&mut file, &mut header).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                // A file too short to hold a header: the same answer the reader
                // gives for it, so that the early check and the real load cannot
                // disagree about whether a file is usable.
                DatabaseError::Truncated(HEADER_LEN)
            } else {
                DatabaseError::Io(e)
            }
        })?;
        Self::check_header(&header)
    }

    /// The header checks [`Self::from_bytes`] and [`Self::check_file`] share.
    ///
    /// One implementation rather than two: an early check that accepted a file
    /// the real load then refused would be worse than no early check, because
    /// the user would have been told the scan was starting.
    ///
    /// Returns the body length the header declares.
    fn check_header(bytes: &[u8]) -> Result<usize, DatabaseError> {
        if bytes.len() < HEADER_LEN {
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
        let declared = u64::from_le_bytes(length);
        // The length is checked rather than cast, because a header can declare
        // anything and this is the one field whose value decides an arithmetic
        // expression the reader then evaluates — `HEADER_LEN + length`, which on
        // a corrupt file claiming `u64::MAX` would overflow and panic in a debug
        // build. The cast would also silently truncate on a 32-bit target. A
        // length no slice could hold is corrupt by definition, so it is refused
        // here rather than passed on as a number that means something else.
        match usize::try_from(declared) {
            Ok(length) if HEADER_LEN.checked_add(length).is_some() => Ok(length),
            _ => Err(DatabaseError::Corrupt(format!(
                "the header declares a body of {declared} bytes, which no rule database can hold"
            ))),
        }
    }
}

/// The serialisable form of a rule set.
#[derive(Debug, Serialize, Deserialize)]
struct DatabaseImage {
    rules: Vec<RuleImage>,
    /// The source files the rules were compiled from. See [`RuleSource`] for
    /// why the image carries them, and note that a database built by a tool
    /// that did not record them carries an empty list rather than a guess.
    sources: Vec<RuleSource>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleImage {
    name: String,
    /// See [`CompiledRule::corpus_index`]. Stored rather than recomputed,
    /// because the corpus it counts includes rules this image does not contain
    /// and the position a rule holds cannot be recovered from its neighbours.
    corpus_index: u32,
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

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn the_shipped_database_is_refused_on_a_machine_that_cannot_hold_it() {
        // The measured case, as arithmetic. The shipped database is 25.3 MiB on
        // disk, it is 469 MB resident, and the machine in the crash log had
        // 11,193,360 bytes left to commit when the parse asked for another
        // 4,193,376. Every one of those requests "fits" in the free commit, and
        // the process aborted anyway, because the parse makes thousands of them.
        let refused = afford_for(26 * MIB, Some(11 * MIB));
        match refused {
            Err(DatabaseError::OutOfMemory {
                file_mib,
                needed_mib,
                free_mib,
            }) => {
                assert_eq!(file_mib, 26);
                // Twenty times the file, which is the point: the file is not
                // what has to fit.
                assert_eq!(needed_mib, 520);
                assert_eq!(free_mib, 11);
            }
            other => panic!("a 26 MiB database must be refused with 11 MiB free: {other:?}"),
        }
    }

    #[test]
    fn the_refusal_sentence_names_all_three_numbers() {
        let message = afford_for(26 * MIB, Some(11 * MIB))
            .expect_err("refused")
            .to_string();
        assert!(message.contains("26 MiB"), "{message}");
        assert!(message.contains("520 MiB"), "{message}");
        assert!(message.contains("11 MiB"), "{message}");
        // And what happened to the rules, because the reader's alternative
        // assumption is that they were loaded and found nothing.
        assert!(message.contains("were not loaded"), "{message}");
    }

    #[test]
    fn an_ordinary_database_loads_where_there_is_room() {
        // The direction that keeps the product working. 520 MiB needed plus the
        // headroom, against 2 GiB free.
        assert!(afford_for(26 * MIB, Some(2048 * MIB)).is_ok());
    }

    #[test]
    fn the_headroom_is_charged_beyond_the_rules_themselves() {
        let needed = 10 * MIB * MEMORY_PER_BYTE;
        let headroom = LOAD_HEADROOM;
        assert!(afford_for(10 * MIB, Some(needed + headroom)).is_ok());
        assert!(
            afford_for(10 * MIB, Some(needed + headroom - 1)).is_err(),
            "one byte short of the headroom is short of the headroom"
        );
    }

    #[test]
    fn a_machine_that_will_not_report_its_commit_refuses_to_load_nothing() {
        // Not knowing is a different fact from knowing there is no room.
        assert!(afford_for(26 * MIB, None).is_ok());
    }

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

    /// A database of four rules that between them exercise every branch of the
    /// profile: a plain one, one below the malicious threshold, one at or above
    /// it, one decisive with a score that would not reach it, and an
    /// observation.
    ///
    /// The fixture states `weight`, this product's own point value, because its
    /// assertions are about points. A third-party rule set states `score`, which
    /// is calibrated rather than read as points — see
    /// [`a_corpus_of_ordinary_rules_profiles_as_nothing_that_can_condemn_alone`]
    /// for that path.
    fn profile_database() -> RuleDatabase {
        let source = r#"
rule ordinary {
    meta:
        weight = 75
    condition:
        true
}

rule strong {
    meta:
        weight = 100
    condition:
        true
}

rule certain {
    meta:
        weight = 40
        decisive = true
    condition:
        true
}

rule observation {
    meta:
        weight = 90
        tags = "file, info"
    condition:
        true
}
"#;
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        assert_eq!(db.len(), 4);
        db
    }

    #[test]
    fn the_profile_separates_the_rules_that_condemn_from_the_rules_that_merely_warn() {
        let db = profile_database();
        let profile = db.profile(&VerdictThresholds::default());
        // `ordinary` and `strong` clear the suspicious threshold on their score
        // alone; `certain` is decisive, which counts whether or not it does.
        assert_eq!(profile.alone_suspicious, 3);
        // `strong` on its score, `certain` on being decisive. The observation
        // scores nothing and is in neither count.
        assert_eq!(profile.alone_malicious, 2);
        assert_eq!(profile.alone_malicious_by_decree, 1);
        assert_eq!(profile.observations, 1);
        // `certain` states `decisive` in its own metadata, which is its author
        // staking the strongest claim the language can make — so no conviction
        // here rests on anything this product read out of the rule.
        assert_eq!(profile.alone_malicious_open_to_argument, 0);
    }

    /// The other route to a single-match conviction, counted separately because
    /// it is a weaker claim: a rule this product decided was decisive still
    /// convicts alone, and a file whose publisher is proven answers it.
    #[test]
    fn the_profile_counts_the_convictions_this_product_read_rather_than_rated() {
        let source = r#"
rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1 {
    meta:
        score = 75
        quality = 85
    condition:
        true
}

rule rated_by_its_author {
    meta:
        score = 95
        quality = 90
    condition:
        true
}
"#;
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        let profile = db.profile(&VerdictThresholds::default());
        // Both convict alone, and neither is attributed to the decree: the
        // named rule was raised to the convicting rung and the rated one's own
        // band already reaches it, so in both cases the score explains the
        // conviction on its own. Which is why this count is a subset of
        // `alone_malicious` and not of `alone_malicious_by_decree`.
        assert_eq!(profile.alone_malicious, 2);
        assert_eq!(profile.alone_malicious_by_decree, 0);
        assert_eq!(
            profile.alone_malicious_open_to_argument, 1,
            "the named rule"
        );
        // And the distinction the count is *for*: the named rule is exactly the
        // one a proven publisher answers, and the rated one is not.
        assert!(!db.rules()[0].metadata.incontestable, "the named rule");
        assert!(db.rules()[1].metadata.incontestable, "the rated rule");
    }

    #[test]
    fn a_decisive_rule_condemns_a_file_its_score_would_not() {
        // The reason the profile cannot count scores alone. `certain` is worth
        // 40, which is under the malicious threshold of 100, and it still ends
        // the scan — so a profile that read only the scores would report one
        // fewer rule than there are.
        let db = profile_database();
        let certain = db
            .rules()
            .iter()
            .find(|rule| rule.name == "certain")
            .expect("the rule is in the database");
        assert_eq!(certain.metadata.score(), 40);
        assert!(certain.metadata.decisive);
    }

    #[test]
    fn the_profile_follows_the_thresholds_rather_than_the_rules() {
        // The same database answers differently under a stricter
        // configuration, which is why the profile is computed rather than
        // stored: a figure baked in at build time would be answering the
        // question about the configuration that built it.
        let db = profile_database();
        let strict = VerdictThresholds {
            suspicious: 80,
            malicious: 120,
        };
        let profile = db.profile(&strict);
        // Only `certain`, by decree: 75 and 100 are both under 120.
        assert_eq!(profile.alone_malicious, 1);
        assert_eq!(profile.alone_malicious_by_decree, 1);
        // `strong` at 100 is the only score at or above 80.
        assert_eq!(profile.alone_suspicious, 2);
    }

    #[test]
    fn the_profile_counts_every_rule_exactly_once_in_the_severity_table() {
        let db = profile_database();
        let profile = db.profile(&VerdictThresholds::default());
        let counted: usize = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
        .iter()
        .map(|severity| profile.at(*severity))
        .sum();
        assert_eq!(counted, db.len());
        // And the score table agrees, which is what makes `By score` and `By
        // severity` two views of one distribution rather than two numbers a
        // reader has to reconcile.
        let by_score: usize = profile.by_score.values().sum();
        assert_eq!(by_score, db.len());
    }

    #[test]
    fn a_rule_at_the_threshold_is_counted_and_one_below_it_is_not() {
        // Off-by-one here is the difference between a rule set that can condemn
        // a file and one that cannot, and the boundary is the threshold itself:
        // `Assessment::finalize` uses `>=`.
        let source = r#"
rule exactly {
    meta:
        weight = 100
    condition:
        true
}
"#;
        let (db, _) = RuleDatabase::compile(source);
        assert_eq!(db.profile(&VerdictThresholds::default()).alone_malicious, 1);
        assert_eq!(
            db.profile(&VerdictThresholds {
                suspicious: 30,
                malicious: 101,
            })
            .alone_malicious,
            0
        );
    }

    #[test]
    fn a_corpus_of_ordinary_rules_profiles_as_nothing_that_can_condemn_alone() {
        // The measurement behind the whole `weight`/`score` split, asserted
        // where it was felt rather than where it was written.
        //
        // 86% of the vendored corpus states `score = 75`. Read as points — which
        // is what one field for both spellings did — every one of those rules
        // was worth 75 against a conviction threshold of 100, so this profile
        // would report every rule as able to condemn a file alone, and two
        // ordinary patterns matching one file out of 10,764 would quarantine it.
        // That is the false-positive storm this test exists to keep from coming
        // back, and the number it guards is 0.
        let mut source = String::new();
        for index in 0..40 {
            source.push_str(&format!(
                "rule ordinary_{index} {{\n    meta:\n        score = 75\n        quality = 85\n    \
                 condition:\n        true\n}}\n\n"
            ));
        }
        let (db, report) = RuleDatabase::compile(&source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        assert_eq!(db.len(), 40);

        let profile = db.profile(&VerdictThresholds::default());
        assert_eq!(
            profile.alone_malicious, 0,
            "an ordinary corpus rule cannot condemn a file on its own"
        );
        assert_eq!(profile.alone_malicious_by_decree, 0);
        // They are not inert, though: forty of them together still warn, which
        // is the band that tells the user to look without acting.
        assert_eq!(profile.alone_suspicious, 40);

        // And the corpus's own confident band keeps the power to condemn, which
        // is the half of this that must not be traded away.
        let confident = format!(
            "{source}rule confident {{\n    meta:\n        score = 100\n        \
                                 quality = 90\n    condition:\n        true\n}}\n"
        );
        let (db, report) = RuleDatabase::compile(&confident);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        let profile = db.profile(&VerdictThresholds::default());
        assert_eq!(profile.alone_malicious, 1);
        // Counted by its score rather than by decree, and that is a property of
        // the banding rather than a coincidence: a corpus rule is decisive only
        // at `score >= 90`, and 90 bands to 100 — which *is* the default
        // convicting threshold. So a decisive corpus rule can never be one whose
        // score alone would not have condemned. `by_decree` is what a
        // hand-written `decisive = true` produces (see
        // [`the_profile_separates_the_rules_that_condemn_from_the_rules_that_merely_warn`]),
        // and under a conviction threshold above 150 the same corpus rules move
        // into it.
        assert_eq!(profile.alone_malicious_by_decree, 0);
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
        assert_eq!(
            db.rule(0).unwrap().metadata.display_name("generic"),
            "generic"
        );
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
            assert_eq!(
                before.program.constants.len(),
                after.program.constants.len()
            );
            assert_eq!(before.defs, after.defs);
            assert_eq!(before.matchers().len(), after.matchers().len());
        }
    }

    /// The rebuilt matchers must actually find things, not merely exist. A
    /// round trip that produced empty matchers would pass every check above.
    #[test]
    fn a_restored_database_still_matches() {
        let db = database();
        let restored = RuleDatabase::from_bytes(&db.to_bytes().unwrap()).expect("deserialising");
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

    // -- shedding the definitions -------------------------------------------

    /// A rule set with one of each kind of string, because the three are stored
    /// differently and only one of them is worth shedding. Text is a `Vec<u8>`
    /// inside the definition, and a hex pattern is a token tree inside it;
    /// the literal bytes a text string compiles to are *shared* with the
    /// definition, so shedding that one frees almost nothing — and the test
    /// exists partly to pin down that the shed pass does not confuse the two.
    const MIXED_SOURCE: &str = r#"
rule mixed {
    strings:
        $hex = { 4D 5A 90 00 ?? ?? [2-4] (41|42) }
        $re = /needle[-_][0-9]{4}/
        $text = "a plain string"
    condition:
        any of them
}
"#;

    fn mixed_database() -> RuleDatabase {
        let (db, report) = RuleDatabase::compile(MIXED_SOURCE);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        db
    }

    #[test]
    fn shedding_keeps_the_identifiers_and_the_slot_numbering() {
        let mut db = mixed_database();
        let before: Vec<(String, bool)> = db.rules()[0]
            .defs
            .iter()
            .map(|def| (def.id.clone(), matches!(def.value, StringValue::Shed)))
            .collect();
        assert_eq!(before.len(), 3);
        assert!(before.iter().all(|(_, shed)| !shed), "nothing is shed yet");

        db.shed_definitions();

        let after = &db.rules()[0].defs;
        assert_eq!(after.len(), 3, "a slot must not disappear");
        for (slot, (id, _)) in before.iter().enumerate() {
            assert_eq!(&after[slot].id, id);
            assert!(matches!(after[slot].value, StringValue::Shed));
            // The reader that needs them keeps working, which is the whole
            // reason the identifiers are not shed with the values.
            assert_eq!(db.rules()[0].string_id(slot as u32), Some(id.as_str()));
        }
    }

    /// The point of shedding is that it does not change what a scan finds, and
    /// the only way to know that is to scan. A shed database that stopped
    /// matching would still pass every structural check above.
    #[test]
    fn a_shed_database_still_matches_every_kind_of_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.avdb");
        let whole = mixed_database();
        whole.save(&path).expect("saving");
        let loaded = RuleDatabase::load(&path).expect("loading");
        assert!(
            matches!(loaded.rules()[0].defs[0].value, StringValue::Shed),
            "loading is what sheds, so this had better have shed"
        );

        // Spelled out byte by byte against the fixture above, because the two
        // have to agree for the test to mean anything: `4D 5A 90 00`, two bytes
        // for the `?? ??`, two for the `[2-4]`, then the `41` the alternative
        // ends on. The rest is what the regex and the text string look for.
        let mut data: Vec<u8> = vec![0x4D, 0x5A, 0x90, 0x00, 0x01, 0x02, 0x03, 0x04, 0x41];
        data.extend_from_slice(b" needle-0042 and a plain string");

        for (database, label) in [(&whole, "as compiled"), (&loaded, "as loaded")] {
            let rule = &database.rules()[0];
            for (slot, matcher) in rule.matchers().iter().enumerate() {
                let mut matches = crate::matches::MatchSet::with_capacity(3);
                assert!(
                    matcher.find_all(&data, &mut matches),
                    "{label}: matcher {slot} ran out of budget"
                );
                assert_eq!(
                    matches.count(matcher.slot),
                    1,
                    "{label}: matcher {slot} ({}) did not find its string",
                    rule.string_id(matcher.slot).unwrap_or("?")
                );
            }
        }
    }

    /// Writing a shed database back out is refused, and the refusal is the
    /// point: the bytes it would produce are a valid database with no strings
    /// in it, which is a rule set that matches nothing and reports every file
    /// as clean.
    #[test]
    fn a_shed_database_refuses_to_be_written_back_out() {
        let mut db = mixed_database();
        db.shed_definitions();
        assert!(matches!(db.to_bytes(), Err(DatabaseError::DefinitionsShed)));

        // And the same through `save`, so the refusal cannot be lost by a
        // caller that only ever writes to a path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shed.avdb");
        assert!(db.save(&path).is_err());
        assert!(!path.exists(), "a refused save must not leave a file behind");
    }

    /// Shedding is not the only thing that must not be reached through
    /// `from_bytes`: the reader half of the round trip has to keep the values,
    /// or an image would lose its strings the first time it was read back.
    #[test]
    fn reading_an_image_keeps_the_definitions_it_was_written_from() {
        let db = mixed_database();
        let restored =
            RuleDatabase::from_bytes(&db.to_bytes().unwrap()).expect("deserialising");
        assert!(restored.rules()[0]
            .defs
            .iter()
            .all(|def| !matches!(def.value, StringValue::Shed)));
        assert!(restored.to_bytes().is_ok(), "and it can be written again");
    }

    #[test]
    fn shedding_twice_is_not_a_mistake() {
        let mut db = mixed_database();
        db.shed_definitions();
        db.shed_definitions();
        assert!(db.rules()[0]
            .defs
            .iter()
            .all(|def| matches!(def.value, StringValue::Shed)));
        assert_eq!(db.rules()[0].defs.len(), 3);
    }

    // -- the early check ----------------------------------------------------

    #[test]
    fn a_file_this_build_wrote_passes_the_early_check() {
        // The check has to accept what the writer produces, or a front end that
        // probes before walking would refuse every scan it is meant to run.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.avdb");
        let database = database();
        database.save(&path).expect("saving");

        let body = RuleDatabase::check_file(&path).expect("a file this build wrote");
        let bytes = database.to_bytes().unwrap();
        assert_eq!(body, bytes.len() - HEADER_LEN);
    }

    /// The property the early check exists for: it answers what the real load
    /// would answer about the ways a database can be unusable that are visible
    /// in its header.
    #[test]
    fn the_early_check_and_the_real_load_refuse_the_same_header() {
        let db = database();
        let whole = db.to_bytes().unwrap();
        let dir = tempfile::tempdir().unwrap();

        let mut wrong_version = whole.clone();
        wrong_version[8..12].copy_from_slice(&(FORMAT_VERSION + 7).to_le_bytes());
        let mut wrong_magic = whole.clone();
        wrong_magic[..4].copy_from_slice(b"NOTA");
        let wrong_magic = wrong_magic;

        let cases: [(&str, &[u8]); 3] = [
            ("a future version", &wrong_version),
            ("a foreign file", &wrong_magic),
            (
                "a file too short to hold a header",
                &whole[..HEADER_LEN - 1],
            ),
        ];
        for (what, bytes) in cases {
            let path = dir.path().join("probe.avdb");
            std::fs::write(&path, bytes).unwrap();

            let early = RuleDatabase::check_file(&path);
            let real = RuleDatabase::from_bytes(bytes);
            assert!(early.is_err(), "{what}: the early check accepted it");
            assert!(real.is_err(), "{what}: the load accepted it");
            assert_eq!(
                std::mem::discriminant(&early.unwrap_err()),
                std::mem::discriminant(&real.unwrap_err()),
                "{what}: the early check and the load disagree about why"
            );
        }
    }

    /// And what it does *not* claim. A file whose header is sound but whose body
    /// was cut off passes the early check and fails to load, which is the honest
    /// limit of a twenty-byte probe: a front end that used it as a promise
    /// rather than as a filter would be reporting a scan that then failed.
    #[test]
    fn a_truncated_body_passes_the_early_check_and_fails_to_load() {
        let whole = database().to_bytes().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cut.avdb");
        std::fs::write(&path, &whole[..whole.len() - 10]).unwrap();

        assert!(RuleDatabase::check_file(&path).is_ok());
        assert!(matches!(
            RuleDatabase::load(&path),
            Err(DatabaseError::Truncated(_))
        ));
    }

    /// A path that is not there is reported as such. Both front ends probe a
    /// path that comes from a config file or a command line, so "the file the
    /// user named does not exist" is an ordinary answer and not a panic.
    #[test]
    fn a_missing_file_is_an_io_error_and_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.avdb");
        assert!(matches!(
            RuleDatabase::check_file(&path),
            Err(DatabaseError::Io(_))
        ));
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

    // -- rules written in terms of other rules -------------------------------

    /// A rule that names one defined *after* it.
    ///
    /// Forward is the interesting direction: it is what makes the compile a
    /// two-pass affair over the whole source, and it is how a corpus states a
    /// shared condition once and turns it on from thirty places.
    const FORWARD_REFERENCE: &str = r#"
rule USER {
    strings: $a = "needle"
    condition: HELPER and $a
}

private rule HELPER {
    condition: uint16(0) == 0x5a4d
}
"#;

    #[test]
    fn a_forward_reference_resolves_and_orders_the_rules() {
        let (db, report) = RuleDatabase::compile(FORWARD_REFERENCE);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        assert_eq!(db.len(), 2);
        // The helper is evaluated first although it is written second, because
        // the rule that reads it comes first in the source.
        assert_eq!(db.rules()[0].name, "HELPER");
        assert_eq!(db.rules()[1].name, "USER");
        // Corpus positions, which is what a reference carries and what a scan's
        // result array is indexed by — not positions in `rules()`.
        assert_eq!(db.rules()[0].corpus_index, 1);
        assert_eq!(db.rules()[1].corpus_index, 0);
        assert_eq!(db.result_len(), 2);
    }

    #[test]
    fn a_scan_runs_a_rule_through_the_rule_it_names() {
        use crate::scanner::Scanner;

        let (db, _) = RuleDatabase::compile(FORWARD_REFERENCE);
        let mut scanner = Scanner::new(&db);

        // An `MZ` buffer: the helper holds, and the string is there.
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(b"..needle..");
        let outcome = scanner.scan(&data);
        let names: Vec<&str> = outcome
            .reportable()
            .map(|m| db.rule(m.rule).unwrap().name.as_str())
            .collect();
        assert_eq!(names, ["USER"], "{outcome:?}");

        // The same buffer without the string: the reference resolved to true,
        // and the rule is still false because of its own half.
        let outcome = scanner.scan(b"MZ....");
        assert_eq!(outcome.reportable().count(), 0, "{outcome:?}");

        // A buffer with the string but no `MZ`: the helper is false, and the
        // rule cannot fire on the string alone. This is the case a broken
        // reference would get wrong in the loud direction.
        let outcome = scanner.scan(b"..needle..");
        assert_eq!(outcome.reportable().count(), 0, "{outcome:?}");
    }

    #[test]
    fn a_rule_that_reads_a_rule_that_was_refused_is_refused_too() {
        // `HELPER` cannot compile, so `USER` has no verdict to read. Reading a
        // `false` there would be a rule that never fires, and reading it under
        // `not` would be a rule that fires on every file — so neither is
        // offered.
        let (db, report) = RuleDatabase::compile(
            r#"
rule USER {
    strings: $a = "x"
    condition: HELPER and $a
}

private rule HELPER {
    strings: $a = "x"
    condition: pe.signatures[0].verified
}
"#,
        );
        assert!(db.is_empty(), "{:?}", db.rules());
        let dependency: Vec<&RuleRefusal> = report
            .refusals
            .iter()
            .filter(|r| r.feature == "rule dependency")
            .collect();
        assert_eq!(dependency.len(), 1, "{:?}", report.refusals);
        assert_eq!(dependency[0].name, "USER");
        assert!(
            dependency[0].reason.contains("HELPER"),
            "{}",
            dependency[0].reason
        );
        // The reason the helper could not be used is reported as its own
        // refusal, so the operator sees the cause and not only the consequence.
        assert!(
            report.refusals.iter().any(|r| r.name == "HELPER"),
            "{:?}",
            report.refusals
        );
    }

    #[test]
    fn a_global_rule_that_reads_an_ordinary_one_is_refused() {
        // The gate runs before everything else, so a global rule that reads a
        // non-global one has nothing to read, whatever order the two were
        // written in. Accepted, it would be `false` and the gate would close on
        // every file — a rule set that reports everything clean.
        let (db, report) = RuleDatabase::compile(
            r#"
global rule GATE {
    condition: OTHER
}

rule OTHER {
    condition: uint16(0) == 0x5a4d
}
"#,
        );
        // The gate is refused, and `OTHER` is still admitted: refusing the gate
        // costs the gate, not the set.
        assert_eq!(db.len(), 1, "{:?}", db.rules());
        assert_eq!(db.rules()[0].name, "OTHER");
        assert_eq!(report.refused(), 1, "{:?}", report.refusals);
        assert_eq!(report.refusals[0].feature, "rule dependency");
        assert!(
            report.refusals[0].reason.contains("not global"),
            "{}",
            report.refusals[0].reason
        );
    }

    #[test]
    fn a_global_rule_may_read_another_global_rule() {
        let (db, report) = RuleDatabase::compile(
            r#"
global rule GATE {
    condition: BASE
}

global rule BASE {
    condition: uint16(0) == 0x5a4d
}

rule BODY {
    strings: $a = "needle"
    condition: $a
}
"#,
        );
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        assert_eq!(db.len(), 3);
        // `BASE` reads nothing and `GATE` reads `BASE`, so the order puts
        // `BASE` first however the two were written.
        assert_eq!(db.rules()[0].name, "BASE");
        let gate = db.rules().iter().position(|r| r.name == "GATE").unwrap();
        let base = db.rules().iter().position(|r| r.name == "BASE").unwrap();
        assert!(base < gate, "{:?}", db.rules());
    }

    #[test]
    fn the_result_array_is_sized_by_the_corpus_and_not_by_the_survivors() {
        // `DEAD` occupies a corpus slot that nothing survives in. The array is
        // sized for the corpus anyway, because `USES` below names slot 0 — and a
        // rule that names a survivor must not have its reference shifted by a
        // refusal it never mentions.
        let (db, report) = RuleDatabase::compile(
            r#"
rule DEAD {
    strings: $a = "x"
    condition: pe.signatures[0].verified
}

rule BASE {
    condition: uint16(0) == 0x5a4d
}

rule USES {
    strings: $a = "needle"
    condition: BASE and $a
}
"#,
        );
        assert_eq!(report.refused(), 1, "{:?}", report.refusals);
        assert_eq!(report.refusals[0].name, "DEAD");
        assert_eq!(db.len(), 2);
        // `DEAD` is corpus 0, so `BASE` is 1 and `USES` is 2.
        assert_eq!(db.rules()[0].corpus_index, 1);
        assert_eq!(db.rules()[1].corpus_index, 2);
        assert_eq!(db.result_len(), 3);
    }

    #[test]
    fn a_reference_survives_a_round_trip_through_bytes() {
        use crate::scanner::Scanner;

        let (db, _) = RuleDatabase::compile(FORWARD_REFERENCE);
        let bytes = db.to_bytes().unwrap();
        let restored = RuleDatabase::from_bytes(&bytes).unwrap();
        assert_eq!(restored.result_len(), db.result_len());
        assert_eq!(restored.rules()[0].corpus_index, 1);
        assert_eq!(restored.rules()[1].corpus_index, 0);

        let mut scanner = Scanner::new(&restored);
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(b"..needle..");
        let outcome = scanner.scan(&data);
        assert_eq!(outcome.reportable().count(), 1, "{outcome:?}");
        let first = outcome.reportable().next().unwrap();
        assert_eq!(restored.rule(first.rule).unwrap().name, "USER");
    }

    #[test]
    fn a_cycle_of_references_is_refused_rather_than_ordered() {
        let (db, report) = RuleDatabase::compile(
            r#"
rule A {
    condition: B
}

rule B {
    condition: A
}
"#,
        );
        assert!(db.is_empty(), "{:?}", db.rules());
        assert_eq!(report.refusals.len(), 2, "{:?}", report.refusals);
        assert!(report
            .refusals
            .iter()
            .all(|r| r.feature == "rule dependency"));
    }
}

#[cfg(test)]
mod splitter_tests {
    use super::*;

    #[test]
    fn a_rule_written_on_one_line_is_still_a_rule() {
        // The splitter waits for a closing brace alone on a line, which a
        // one-line rule never produces. Left unhandled it vanishes: no chunk,
        // no malformed block, and nothing in the report to say so.
        let (db, report) = RuleDatabase::compile(
            "rule one { strings: $a = \"x\" condition: $a }\n\
             rule two { strings: $a = \"y\" condition: $a }\n",
        );
        assert_eq!(report.rules_seen, 2, "{:?}", report.refusals);
        assert_eq!(report.refused(), 0, "{:?}", report.refusals);
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn a_rule_header_with_its_brace_on_the_next_line_still_opens_a_rule() {
        // The shape a rule set with tags is written in. The header line has no
        // brace at all, so it can never be mistaken for a complete rule.
        let split = ruleset::split_rule_chunks("rule tagged : FILE\n{\n    condition: true\n}\n");
        assert_eq!(split.headers, 1);
        assert_eq!(split.chunks.len(), 1);
        assert_eq!(split.unaccounted(), 0);
    }

    #[test]
    fn every_rule_the_splitter_announces_is_accounted_for() {
        // A file that mixes both shapes, which is what a converter's output
        // looks like when it meets a hand-written rule.
        let source = "rule a {\n    condition: true\n}\n\
                      rule b { condition: false }\n\
                      rule c : TAG\n{\n    condition: true\n}\n";
        let split = ruleset::split_rule_chunks(source);
        assert_eq!(split.headers, 3);
        assert_eq!(split.chunks.len(), 3);
        assert_eq!(split.malformed, 0);
        assert_eq!(split.unaccounted(), 0);
    }
}
