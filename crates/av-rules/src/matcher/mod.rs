//! Finding a rule's strings in a buffer.
//!
//! Three kinds of string, three matchers, one interface. A string definition
//! becomes a [`CompiledString`], and a compiled string is asked to append its
//! matches to a [`MatchSet`] — the same table the interpreter reads. Nothing
//! here knows what a rule is or what its condition means; that separation is
//! what lets the interpreter be tested against a hand-built table and the
//! matchers against hand-built buffers.
//!
//! # Where the prefilter fits
//!
//! A scan has ten thousand rules and about seven strings each. Finding all of
//! them individually would be about 77,000 searches per file. The rule-level
//! prefilter ([`crate::prefilter`]) is what avoids that: one pass over the
//! buffer against atoms shared across the whole rule set decides which handful
//! of rules could possibly match, and only those have their strings found.
//!
//! That leaves these matchers doing the honest, direct thing — search for the
//! needle — rather than a second clever layer. `memchr` runs at gigabytes per
//! second, so for the few rules that survive the prefilter, a straightforward
//! search costs less than the bookkeeping a smarter one would need.
//!
//! # Refusals are named
//!
//! A construct the matcher does not implement is refused with a `feature` tag
//! rather than approximated. That matters more here than anywhere else in the
//! pipeline: a pattern compiled to something *nearly* what the author wrote is
//! a rule that fires on the wrong files, which is the one failure mode a user
//! notices and cannot forgive.

pub mod pattern;
pub mod text;
pub mod wide;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::ast::{Modifiers, StringDef, StringValue};
use crate::atoms::{
    group_from_variants, groups_from_runs, runs_of_hex, runs_of_regex, StringAtoms,
};
use crate::matches::{Match, MatchSet};

/// A string that could not be compiled into a matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherError {
    pub message: String,
    /// A stable tag naming the construct at fault, so refusals can be counted
    /// by kind. `None` when the string itself is at fault rather than a
    /// construct the engine lacks.
    pub feature: Option<&'static str>,
}

impl MatcherError {
    fn unsupported(feature: &'static str, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            feature: Some(feature),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            feature: None,
        }
    }
}

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MatcherError {}

/// What a compiled string does when asked to search.
#[derive(Debug)]
pub(crate) enum Kind {
    /// One or more fixed byte sequences. A plain string is one; `wide`, `xor`
    /// and `base64` multiply it.
    Literal(Vec<text::Literal>),
    /// A hex pattern: a set of byte sequences described by wildcards, jumps and
    /// alternatives.
    Hex(pattern::Pattern),
    /// A regular expression, matched over bytes rather than characters.
    Regex {
        /// Shared rather than owned: a corpus writes the same expression in many
        /// rules, and a compiled program is the largest thing a regex string
        /// costs. See [`RegexCache`].
        regex: Arc<regex::bytes::Regex>,
        /// The parse tree the regex was built from, kept because the compiled
        /// matcher has the structure folded away and the prefilter needs to ask
        /// which byte sequences the pattern *requires*.
        ///
        /// Parsed case-*sensitively* even when the pattern is not, so that the
        /// literals come back as themselves rather than as classes; the
        /// case-insensitivity is recorded beside it and applied to the atoms.
        hir: Box<regex_syntax::hir::Hir>,
        /// Whether matching ignores ASCII case, which decides whether the atoms
        /// this yields go into the case-insensitive automaton.
        nocase: bool,
        fullword: bool,
        /// The word boundaries a `wide` pattern asserted, for the matcher to
        /// check against each match.
        ///
        /// The regex engine cannot make the assertion — see [`wide`] — so it was
        /// taken out of the pattern and is asked here instead. Empty for every
        /// other kind of string, which is the case a caller can skip.
        boundary: wide::Boundary,
    },
}

/// A string definition, ready to search for.
#[derive(Debug)]
pub struct CompiledString {
    /// The slot this string occupies in the rule's match table.
    pub slot: u32,
    /// The identifier as written, for diagnostics.
    pub id: String,
    /// `private` strings record their matches but are never reported. Kept here
    /// rather than dropped at compile time because the condition may still
    /// depend on them.
    pub private: bool,
    kind: Kind,
}

impl CompiledString {
    /// The compiled form, for the memory probe. See [`crate::probe`].
    #[cfg(feature = "memory-probe")]
    pub(crate) fn probe_kind(&self) -> &Kind {
        &self.kind
    }

    /// Find every occurrence in `data` and record it in `matches`.
    ///
    /// Returns `false` if a matcher ran out of budget before finishing, in
    /// which case the string has *not* been shown to be absent and the caller
    /// should count it rather than trust the result.
    pub fn find_all(&self, data: &[u8], matches: &mut MatchSet) -> bool {
        // Collected into a scratch first, then pushed, because a matcher needs
        // the slot number to push and the closure that would carry it into the
        // search is more trouble than the copy is worth. The scratch is small:
        // it holds one string's matches, not a file's.
        let mut hits: Vec<(u32, u32)> = Vec::new();
        let completed = match &self.kind {
            Kind::Literal(literals) => {
                for literal in literals {
                    literal.find_all(data, &mut hits);
                }
                true
            }
            Kind::Hex(pattern) => pattern.find_all(data, &mut hits),
            Kind::Regex {
                regex,
                fullword,
                boundary,
                ..
            } => {
                find_regex(regex, *boundary, *fullword, data, &mut hits);
                true
            }
        };

        for (offset, length) in hits {
            matches.push(self.slot, Match::new(offset, length));
        }
        // Several literals can land on the same span — `ascii wide xor` gives
        // many matchers over the same bytes — and the table treats two entries
        // at one offset as two occurrences unless they are collapsed. Doing it
        // per string is also where the offsets get ordered, which `@a[i]`
        // depends on.
        matches.dedup_slot(self.slot);
        completed
    }

    /// Whether a unique occurrence of this string's atom pins down where its
    /// matches can start.
    ///
    /// True for a string with exactly one form. `$a = "kernel32.dll"` has one,
    /// so its atom sits at a fixed index of it and every match must start where
    /// that atom's one occurrence says. `$a = "abc" ascii wide` has two forms
    /// of different lengths, and the atom the automaton matched belongs to only
    /// one of them — the other could occur anywhere, so there is nothing to
    /// derive and a full search is the only correct answer.
    ///
    /// Narrow on purpose. It is asked once per string before a search, and
    /// answering `false` costs a search that was going to happen anyway.
    pub fn can_use_witness(&self) -> bool {
        matches!(&self.kind, Kind::Literal(literals) if literals.len() == 1)
    }

    /// Find every occurrence, given that this string's atom occurs exactly once
    /// in `data`, at `witness`.
    ///
    /// Does nothing for a string [`can_use_witness`](Self::can_use_witness)
    /// rejects, so the caller must ask that first and search properly when it
    /// says no. See [`text::Literal::find_all_from_witness`] for why the answer
    /// is exact rather than an approximation.
    pub fn find_all_from_witness(&self, data: &[u8], witness: u32, matches: &mut MatchSet) {
        let Kind::Literal(literals) = &self.kind else {
            return;
        };
        let [only] = literals.as_slice() else {
            return;
        };
        let mut hits: Vec<(u32, u32)> = Vec::new();
        only.find_all_from_witness(data, witness, &mut hits);
        for (offset, length) in hits {
            matches.push(self.slot, Match::new(offset, length));
        }
        matches.dedup_slot(self.slot);
    }

    /// Whether this string came from a hex pattern.
    pub fn is_hex(&self) -> bool {
        matches!(self.kind, Kind::Hex(_))
    }

    /// The fixed byte sequences this string is, or `None` for a string the
    /// automaton cannot carry.
    ///
    /// One entry for a plain string, and one per form for a string that is
    /// several — `ascii wide xor(1-3)` is eight — each with the case and word
    /// rules its own search applies. `None` for a hex pattern, for a regex, and
    /// for a string [`compile`] refused, which is the answer that sends
    /// [`crate::sweep`]'s caller back to [`find_all`](Self::find_all).
    ///
    /// [`find_all`](Self::find_all) is the contract: a sweep that carries these
    /// forms has to report exactly the matches that function reports, because
    /// it stands in for it.
    pub fn literal_forms(&self) -> Option<&[text::Literal]> {
        match &self.kind {
            Kind::Literal(literals) => Some(literals),
            Kind::Hex(_) | Kind::Regex { .. } => None,
        }
    }

    /// The bytes a matching file must contain.
    ///
    /// The contract the prefilter depends on is one-directional: if this string
    /// matches a buffer, the buffer satisfies every group returned. It says
    /// nothing about the converse, which is why a satisfied group selects a
    /// rule as a *candidate* rather than deciding it.
    ///
    /// Empty means the string imposes no constraint — every form it could take
    /// is too short or too vague to have an atom — and the prefilter has to let
    /// its rule through untested. That is the safe direction to fail in.
    pub fn atoms(&self) -> StringAtoms {
        match &self.kind {
            Kind::Literal(literals) => {
                let variants: Vec<(&[u8], bool)> = literals
                    .iter()
                    .map(|literal| (literal.bytes.as_slice(), literal.nocase))
                    .collect();
                group_from_variants(&variants)
            }
            Kind::Hex(pattern) => groups_from_runs(&runs_of_hex(&pattern.tokens), false),
            Kind::Regex { hir, nocase, .. } => groups_from_runs(&runs_of_regex(hir), *nocase),
        }
    }
}

/// Whether a `fullword` match is delimited by non-word bytes.
fn whole_word(data: &[u8], start: usize, end: usize) -> bool {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let before = start.checked_sub(1).and_then(|i| data.get(i)).copied();
    let after = data.get(end).copied();
    !before.is_some_and(is_word) && !after.is_some_and(is_word)
}

/// Find the matches of a compiled pattern that survive its own filters.
///
/// Split out of [`CompiledString::find_all`] because the filter changes how the
/// search has to be driven, and it is worth saying why in one place.
///
/// A pattern with no boundary to check is searched with `find_iter`, which finds
/// non-overlapping matches: after a match it carries on from the match's end.
/// That is the right answer for a pattern that describes a whole match, and it
/// is what makes `/ab/` over `abab` two occurrences rather than three.
///
/// A `wide` pattern that asserted a word boundary does not describe a whole
/// match any more — the assertion was taken out and is checked here — so a
/// candidate can be *rejected* after the fact, and a rejected candidate says
/// nothing about where the next one is. The `ab` inside `xab` is not a match of
/// `\bab`, but the `ab` at the end of `xabab` is, and it starts inside the
/// candidate that was rejected. So the search resumes one byte past the start of
/// the rejected match rather than past its end, which does find overlapping
/// candidates — the price of having a filter at all, and paid only by the
/// patterns that have one.
///
/// Empty matches are dropped in both paths: a pattern that can match nothing
/// reports a hit at every offset, which carries no information and would make
/// `#a` the buffer length.
fn find_regex(
    regex: &regex::bytes::Regex,
    boundary: wide::Boundary,
    fullword: bool,
    data: &[u8],
    hits: &mut Vec<(u32, u32)>,
) {
    // The offsets are checked rather than cast because a buffer can be longer
    // than `u32::MAX` in principle; a match past that is not one this scanner
    // can report, and dropping it is what the old `if let (Ok, Ok)` did.
    let keep = |m: regex::bytes::Match<'_>| -> Option<(u32, u32)> {
        if m.is_empty() {
            return None;
        }
        if !boundary.holds(data, m.start(), m.end()) {
            return None;
        }
        if fullword && !whole_word(data, m.start(), m.end()) {
            return None;
        }
        let offset = u32::try_from(m.start()).ok()?;
        let length = u32::try_from(m.len()).ok()?;
        Some((offset, length))
    };

    if boundary.is_none() {
        for m in regex.find_iter(data) {
            if let Some(hit) = keep(m) {
                hits.push(hit);
            }
        }
        return;
    }

    let mut at = 0;
    // `<=` rather than `<`: a match can be empty at the end of the buffer, and
    // asking the engine to search from one past the end is a panic rather than
    // an empty answer.
    while at <= data.len() {
        let Some(m) = regex.find_at(data, at) else {
            break;
        };
        at = m.start() + 1;
        if let Some(hit) = keep(m) {
            hits.push(hit);
        }
    }
}

/// What a compiled regex is built from.
///
/// The printed pattern and the three builder settings that change what it
/// means. Deliberately not `Regex::as_str()`, which reports the pattern text
/// and nothing else: two strings that wrote the same text under different flags
/// are different regexes, and keying on the text alone would hand one of them
/// the other's program.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RegexKey {
    pattern: String,
    nocase: bool,
    dot_matches_new_line: bool,
    multi_line: bool,
}

/// The compiled regexes built so far while loading one database.
///
/// A corpus writes the same expression in many rules — of 852 regex strings in
/// the shipping corpus, only 497 spell distinct expressions — and the compiled
/// program is by far the largest thing a regex string costs, far more than the
/// parse tree beside it. Without this, the 355 repeats each pay for a program
/// identical to one already in memory.
///
/// The cache belongs to one load: it is created by the caller and dropped with
/// it, so two databases never share a program, and the parse trees stay
/// per-string because the prefilter reads each string's own.
#[derive(Default)]
pub(crate) struct RegexCache {
    built: HashMap<RegexKey, Arc<regex::bytes::Regex>>,
}

/// A switch the memory probe flips to measure what sharing is worth: with it
/// set, every ask builds a fresh program, so two loads of the same file differ
/// in nothing else.
///
/// Only exists under `memory-probe`, and is only ever set by
/// [`crate::probe::load_without_sharing`]. A flag read on this path in the
/// shipping build would be a cost paid by every load to answer a question
/// nobody asked at runtime.
#[cfg(feature = "memory-probe")]
pub(crate) static SHARING_DISABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

impl RegexCache {
    /// The regex for `key`, building it the first time it is asked for.
    ///
    /// A pattern that does not compile is not recorded, so a later ask retries
    /// it and gets the same error rather than a cached absence.
    fn get_or_build(
        &mut self,
        key: RegexKey,
    ) -> Result<Arc<regex::bytes::Regex>, MatcherError> {
        #[cfg(feature = "memory-probe")]
        if SHARING_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(Arc::new(build_regex(&key)?));
        }
        if let Some(existing) = self.built.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let built = Arc::new(build_regex(&key)?);
        self.built.insert(key, Arc::clone(&built));
        Ok(built)
    }
}

/// Compile a string definition into a matcher.
///
/// `slot` is the index the compiler assigned this string, so that matches land
/// in the row the interpreter will read.
///
/// This builds a `RegexCache` of its own, so a caller compiling one string at
/// a time shares nothing. Loading a database should use
/// `compile_with` and one cache for the whole load; that is where the sharing
/// is worth having.
pub fn compile(def: &StringDef, slot: u32) -> Result<CompiledString, MatcherError> {
    compile_with(def, slot, &mut RegexCache::default())
}

/// The same, sharing compiled regexes through `cache`.
pub(crate) fn compile_with(
    def: &StringDef,
    slot: u32,
    cache: &mut RegexCache,
) -> Result<CompiledString, MatcherError> {
    let kind = match &def.value {
        StringValue::Text(bytes) => {
            let literals = text::variants(bytes, &def.modifiers).map_err(MatcherError::invalid)?;
            Kind::Literal(literals)
        }
        StringValue::Hex(pattern) => {
            Kind::Hex(pattern::Pattern::compile(pattern).map_err(MatcherError::invalid)?)
        }
        // Unreachable in the product: the definitions are shed after the
        // matchers have been built from them, and a matcher is never built from
        // a shed definition. An error rather than a panic because a caller
        // holding a shed database and asking for a matcher has made a mistake
        // that this function cannot see, and refusing is a better answer than
        // aborting the process. See [`StringValue::Shed`].
        StringValue::Shed => {
            return Err(MatcherError::invalid(format!(
                "string `{}` has no value: the database it came from had its string \
                 definitions shed after loading, and cannot be compiled from again",
                def.id
            )));
        }
        StringValue::Regex { body, flags } => {
            let nocase = def.modifiers.nocase || flags.contains('i');
            // Parsed once, then rewritten if the string is `wide`. Both the
            // thing that matches and the thing atoms are read from come from the
            // rewritten form, so the prefilter's atoms are the bytes that are
            // really there — a null-interleaved atom is what a wide match looks
            // like, and an atom taken from the unwidened pattern would select
            // every file the pattern cannot match.
            let hir = parse_for_atoms(body, flags)?;
            let (hir, boundary) = if def.modifiers.wide {
                let widened = wide::widen(&hir)?;
                (parse_for_atoms(&widened.pattern, flags)?, widened.boundary)
            } else {
                (hir, wide::Boundary::default())
            };
            Kind::Regex {
                regex: cache.get_or_build(regex_key(flags, &def.modifiers, &hir)?)?,
                hir: Box::new(hir),
                nocase,
                fullword: def.modifiers.fullword,
                boundary,
            }
        }
    };
    Ok(CompiledString {
        slot,
        id: def.id.clone(),
        private: def.modifiers.private,
        kind,
    })
}

/// Compile the pattern of a `matches` operator.
///
/// `<string> matches /re/` applies a pattern to a value the condition computed
/// — `pe.resources[0].name_string matches /[0-9]\x00[0-9]\x00/` — rather than to
/// the file, so there is no string definition for it to hang off and no atoms
/// to extract. What it does share with `$a = /re/` is the meaning of the
/// pattern, and that is the whole point of routing it through the same two
/// functions: one definition of what a `/regex/` in this language denotes.
///
/// Called at compile time and again on first use. The first call is what makes
/// a bad pattern a rule that does not compile rather than a rule that silently
/// never matches; the second is what makes it a regex the interpreter can run.
pub fn compile_condition_regex(
    body: &str,
    flags: &str,
) -> Result<regex::bytes::Regex, MatcherError> {
    let hir = parse_for_atoms(body, flags)?;
    build_regex(&regex_key(flags, &Modifiers::default(), &hir)?)
}

/// Parse a regex body into the tree the atom extractor walks.
///
/// A second parse of a pattern already parsed once, which is the price of
/// keeping the two questions separate: `regex` answers "does this match" and
/// keeps its structure to itself, and only the parse tree can answer "what must
/// be there".
///
/// The settings are the ones `regex::bytes::RegexBuilder` uses, with three
/// deliberate differences.
///
/// `utf8(false)` matches the bytes API, without which `\d` is rejected as a
/// class that could match invalid UTF-8.
///
/// Case-insensitivity is *not* set even when the pattern asks for it: folding
/// here would turn every literal letter into a class and there would be no
/// literals left to extract. The caller records the flag and marks the atoms
/// instead. That one is a property of the parse tree, so leaving it off costs
/// nothing: the builder applies it to the same tree.
///
/// `s` and `m` *are* set here, and that is the difference between working and
/// not. Both are decisions the parser bakes into the tree rather than flags the
/// builder can apply afterwards: `.` is expanded to a class that excludes
/// `\n`, so a builder told `dot_matches_new_line(true)` afterwards has no dot
/// left to widen; and `^` parses to a different assertion under `m`. Setting
/// them only on the builder would give a rule that compiles, runs, and is not
/// the pattern its author wrote.
fn parse_for_atoms(body: &str, flags: &str) -> Result<regex_syntax::hir::Hir, MatcherError> {
    regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .dot_matches_new_line(flags.contains('s'))
        .multi_line(flags.contains('m'))
        .build()
        .parse(&open_repetitions(body))
        .map_err(|e| MatcherError::invalid(format!("invalid regular expression: {e}")))
}

/// Rewrite `{,n}` into the `{0,n}` it means.
///
/// # Why this is a rewrite and not a refusal
///
/// `{,100}` is not a repetition in the usual regex grammar: a `{` that does not
/// begin a valid quantifier is a literal brace, and the five characters
/// `{,100}` would be a pattern matching those five characters. That is not what
/// the one rule in the corpus that writes it means, and it is not what any
/// author means by it: the pattern is
///
/// ```text
/// %@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe
/// ```
///
/// — a JSP webshell header, with "any run of up to a hundred bytes" between the
/// `[` and the `unsafe`. Read as five literal characters the rule could never
/// match a real file, so the literal reading makes a rule that is dead rather
/// than one that is wrong. Read as `{0,100}` it is the rule its author wrote.
///
/// The rewrite is textual and happens before the parse because the failure it
/// avoids is a parse failure: the parser reads `{,` as the start of a
/// repetition, then finds no decimal where one is required, and refuses the
/// whole pattern. There is nothing in the parse tree to fix afterwards.
///
/// # What it does not touch
///
/// A brace inside a character class is a literal in every regex dialect, so
/// `[{,2}]` is left alone — the scan tracks whether it is inside a class, and
/// whether the position is one where a `]` would close the class or is itself a
/// literal. An escaped `\{` is skipped by the same scan.
fn open_repetitions(body: &str) -> std::borrow::Cow<'_, str> {
    let bytes = body.as_bytes();
    // The rewrite is rare — one pattern in the whole corpus — so nothing is
    // allocated until one is found, and a pattern with none is returned as the
    // same borrowed text it arrived as.
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut i = 0usize;
    let mut class: Option<usize> = None;
    while i < bytes.len() {
        match bytes[i] {
            // A backslash escapes whatever follows it, including a bracket or a
            // brace, so the next byte is never structural.
            b'\\' => i += 2,
            b'[' if class.is_none() => {
                class = Some(i);
                i += 1;
            }
            b']' if class
                .is_some_and(|open| i > open + 1 + usize::from(bytes[open + 1] == b'^')) =>
            {
                class = None;
                i += 1;
            }
            b'{' if class.is_none() => {
                if let Some(end) = empty_lower_bound(&bytes[i..]) {
                    let text = out.get_or_insert_with(|| String::with_capacity(body.len() + 1));
                    text.push_str(&body[copied..i]);
                    // `{0` and then the `,n}` that was already there.
                    text.push_str("{0");
                    copied = i + 1;
                    i += end;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    match out {
        Some(mut text) => {
            text.push_str(&body[copied..]);
            std::borrow::Cow::Owned(text)
        }
        None => std::borrow::Cow::Borrowed(body),
    }
}

/// The length of a `{,n}` at the start of `bytes`, if there is one.
///
/// `None` for `{,}`, for `{n}`, for `{n,}` and for a brace that begins nothing
/// — each of which the parser reads for itself, and none of which means "up to
/// n".
fn empty_lower_bound(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&b'{') || bytes.get(1) != Some(&b',') {
        return None;
    }
    let mut at = 2;
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    // At least one digit, or there is no bound to open.
    if at == 2 || bytes.get(at) != Some(&b'}') {
        return None;
    }
    Some(at + 1)
}

/// Build a byte-oriented regex from a body and its flag letters.
///
/// `hir` is the parse tree the pattern is compiled from, which is the body
/// itself unless the string is `wide`, in which case it is the widened rewrite
/// ([`wide`]). Everything that decides what the regex *means* comes from it, so
/// the two can never disagree about which bytes to look for.
///
/// The pattern is printed back out of the parse tree rather than taken from the
/// source. For the ordinary case the two mean the same thing; for a `wide`
/// string only the tree has the nulls in the right places, and printing it is
/// what keeps the compiled regex and the atoms read from it describing the same
/// bytes. That printed text is also what [`RegexCache`] keys on, so the two
/// printed forms — unwidened and widened — are two entries, as they should be.
///
/// The refusals live here rather than in [`build_regex`] so that they are
/// checked before the cache is consulted: a cache hit is only a hit for a
/// pattern that would have been buildable anyway.
fn regex_key(
    flags: &str,
    modifiers: &Modifiers,
    hir: &regex_syntax::hir::Hir,
) -> Result<RegexKey, MatcherError> {
    if modifiers.xor.is_some() {
        return Err(MatcherError::unsupported(
            "xor regex",
            "an `xor` regular expression is not supported",
        ));
    }
    if modifiers.base64.is_some() {
        return Err(MatcherError::unsupported(
            "base64 regex",
            "a `base64` regular expression is not supported",
        ));
    }
    for flag in flags.chars() {
        if !matches!(flag, 'i' | 's' | 'm') {
            return Err(MatcherError::unsupported(
                "regex flag",
                format!("the `/.../{flag}` flag is not supported"),
            ));
        }
    }
    Ok(RegexKey {
        pattern: hir.to_string(),
        nocase: modifiers.nocase || flags.contains('i'),
        dot_matches_new_line: flags.contains('s'),
        multi_line: flags.contains('m'),
    })
}
///
/// Two decisions worth naming:
///
/// * **Bytes, not characters.** `unicode` is off, so `.` matches any byte and
///   a rule can express a pattern over a binary without the engine deciding
///   that some of its bytes are not valid UTF-8 and refusing to look at them.
///   The engine's own regexes are byte-oriented for the same reason, and it is
///   also what makes the widening total: a byte class names only code units
///   below `0x100`, and every one of those has a two-byte encoding.
///
/// * **`wide` is rewritten, not refused.** See [`wide`] for the rewrite, and for
///   why a word boundary comes out of the pattern and is checked against the
///   match instead.
fn build_regex(key: &RegexKey) -> Result<regex::bytes::Regex, MatcherError> {
    regex::bytes::RegexBuilder::new(&key.pattern)
        .unicode(false)
        .case_insensitive(key.nocase)
        .dot_matches_new_line(key.dot_matches_new_line)
        .multi_line(key.multi_line)
        .build()
        .map_err(|e| MatcherError::invalid(format!("invalid regular expression: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Base64Alphabet, Modifiers, StringValue};
    use crate::hex;

    fn def(id: &str, value: StringValue, modifiers: Modifiers) -> StringDef {
        StringDef {
            id: id.to_string(),
            value,
            modifiers,
            span: crate::ast::Span::default(),
        }
    }

    fn text_def(id: &str, bytes: &[u8]) -> StringDef {
        def(
            id,
            StringValue::Text(bytes.to_vec()),
            Modifiers {
                ascii: true,
                ..Modifiers::default()
            },
        )
    }

    /// A string as the UTF-16LE bytes a `wide` pattern is written for.
    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Compile one string and find it, returning its matches in order.
    fn hits(source: &str, id: &str, data: &[u8]) -> Vec<(u32, u32)> {
        let file = crate::parser::parse_file(source).expect("test source must parse");
        let rule = &file.rules[0];
        let def = rule
            .strings
            .iter()
            .find(|s| s.id == id)
            .expect("the string must exist");
        let compiled = compile(def, 0).expect("the string must compile");
        let mut set = MatchSet::with_capacity(1);
        assert!(compiled.find_all(data, &mut set), "budget ran out");
        set.matches(0)
            .iter()
            .map(|m| (m.offset, m.length))
            .collect()
    }

    // -- dispatch ----------------------------------------------------------

    #[test]
    fn a_text_string_becomes_a_literal_matcher() {
        let c = compile(&text_def("$a", b"abc"), 0).unwrap();
        assert!(matches!(c.kind, Kind::Literal(_)));
        assert!(!c.is_hex());
    }

    #[test]
    fn a_hex_string_becomes_a_pattern_matcher() {
        let d = def(
            "$a",
            StringValue::Hex(hex::parse("4D 5A").unwrap()),
            Modifiers::default(),
        );
        let c = compile(&d, 0).unwrap();
        assert!(c.is_hex());
    }

    #[test]
    fn the_slot_is_carried_through_so_matches_land_in_the_right_row() {
        let d = text_def("$a", b"x");
        let c = compile(&d, 7).unwrap();
        assert_eq!(c.slot, 7);
        let mut set = MatchSet::with_capacity(8);
        assert!(c.find_all(b"x", &mut set));
        assert_eq!(set.count(7), 1);
        assert_eq!(set.count(0), 0);
    }

    // -- end to end through the parser ------------------------------------

    #[test]
    fn a_plain_string_is_found() {
        let s = r#"rule r { strings: $a = "hello" condition: $a }"#;
        assert_eq!(hits(s, "$a", b"say hello there"), vec![(4, 5)]);
    }

    #[test]
    fn a_nocase_string_is_found_in_either_case() {
        let s = r#"rule r { strings: $a = "hello" nocase condition: $a }"#;
        assert_eq!(hits(s, "$a", b"HELLO hello"), vec![(0, 5), (6, 5)]);
    }

    #[test]
    fn a_wide_string_is_not_searched_for_in_its_ascii_form() {
        // `wide` on its own means *only* the UTF-16 form. The buffer opens with
        // the ascii spelling precisely so that a matcher which searched for it
        // anyway would be caught here rather than in the field.
        let s = r#"rule r { strings: $a = "ab" wide condition: $a }"#;
        assert_eq!(hits(s, "$a", b"ab\0a\0b\0"), vec![(3, 4)]);
    }

    #[test]
    fn ascii_and_wide_together_search_both_forms() {
        let s = r#"rule r { strings: $a = "ab" wide ascii condition: $a }"#;
        assert_eq!(hits(s, "$a", b"ab\0a\0b\0"), vec![(0, 2), (3, 4)]);
    }

    #[test]
    fn a_hex_pattern_is_found_through_its_wildcards() {
        let s = r#"rule r { strings: $a = { 4D 5A ?? 00 } condition: $a }"#;
        assert_eq!(hits(s, "$a", b"MZ\x90\x00"), vec![(0, 4)]);
        assert!(hits(s, "$a", b"MZ\x90\x01").is_empty());
    }

    #[test]
    fn a_hex_pattern_with_a_jump_is_found() {
        let s = r#"rule r { strings: $a = { 41 [2-3] 42 } condition: $a }"#;
        assert_eq!(hits(s, "$a", b"A..B"), vec![(0, 4)]);
    }

    #[test]
    fn a_fullword_string_is_restricted_to_whole_words() {
        let s = r#"rule r { strings: $a = "cat" fullword condition: $a }"#;
        assert_eq!(hits(s, "$a", b"a cat sat"), vec![(2, 3)]);
        assert!(hits(s, "$a", b"concatenate").is_empty());
    }

    #[test]
    fn a_regex_string_is_found() {
        let s = r#"rule r { strings: $a = /ab+c/ condition: $a }"#;
        assert_eq!(hits(s, "$a", b"xxabbbcyy"), vec![(2, 5)]);
    }

    #[test]
    fn a_case_insensitive_regex_flag_is_honoured() {
        let s = r#"rule r { strings: $a = /abc/i condition: $a }"#;
        assert_eq!(hits(s, "$a", b"ABC"), vec![(0, 3)]);
    }

    #[test]
    fn the_s_and_m_flags_reach_the_parse_and_not_only_the_builder() {
        // Both of these are decisions the parser bakes into the tree. `.` is
        // expanded to a class that excludes `\n` while parsing, so a builder
        // told `dot_matches_new_line` afterwards has no dot left to widen; `^`
        // parses to a different assertion under `m`. Setting the flags on the
        // builder alone gives a rule that compiles, runs, and is not the
        // pattern its author wrote — which is the failure mode with no symptom.
        let s = r#"rule r { strings: $a = /a.c/s condition: $a }"#;
        assert_eq!(hits(s, "$a", b"a\nc"), vec![(0, 3)]);
        let s = r#"rule r { strings: $a = /a.c/ condition: $a }"#;
        assert!(hits(s, "$a", b"a\nc").is_empty(), "without `s`");

        let s = r#"rule r { strings: $a = /^c/m condition: $a }"#;
        assert_eq!(hits(s, "$a", b"a\nc"), vec![(2, 1)]);
        let s = r#"rule r { strings: $a = /^c/ condition: $a }"#;
        assert!(hits(s, "$a", b"a\nc").is_empty(), "without `m`");
    }

    #[test]
    fn a_regex_matches_bytes_that_are_not_valid_utf8() {
        // Byte semantics, not character semantics. A rule written against a
        // binary has to be able to name the bytes in it.
        let s = r#"rule r { strings: $a = /\xff\xfe/ condition: $a }"#;
        assert_eq!(hits(s, "$a", b"\x00\xff\xfe\x00"), vec![(1, 2)]);
    }

    #[test]
    fn a_regex_that_can_match_nothing_records_nothing() {
        // `a*` matches the empty string at every offset; recording those would
        // make `#a` equal the buffer length and `@a` always zero.
        let s = r#"rule r { strings: $a = /z*/ condition: $a }"#;
        assert!(hits(s, "$a", b"abc").is_empty());
    }

    #[test]
    fn a_regex_match_is_deduplicated_like_any_other() {
        let s = r#"rule r { strings: $a = /ab/ condition: $a }"#;
        assert_eq!(hits(s, "$a", b"abab"), vec![(0, 2), (2, 2)]);
    }

    // -- the `{,n}` repetition ---------------------------------------------

    #[test]
    fn an_open_lower_bound_becomes_the_bound_it_means() {
        assert_eq!(open_repetitions("{,100}"), "{0,100}");
        assert_eq!(open_repetitions("a{,2}b"), "a{0,2}b");
        // Only the `{,n}` form. Everything else is a repetition the parser
        // already reads, or a brace that is not one.
        for untouched in [
            "{2,4}", "{2,}", "{2}", "{,}", "{,a}", "{", "a}b", "{100,2}", "",
        ] {
            assert_eq!(open_repetitions(untouched), untouched);
            assert!(
                matches!(open_repetitions(untouched), std::borrow::Cow::Borrowed(_)),
                "{untouched} must not allocate"
            );
        }
    }

    #[test]
    fn an_open_lower_bound_inside_a_class_or_behind_a_backslash_is_left_alone() {
        // A brace in a class is a literal in every dialect, and an escaped one
        // is a literal everywhere. Rewriting either would change what the
        // pattern matches rather than what it repeats.
        assert_eq!(open_repetitions("[{,2}]"), "[{,2}]");
        assert_eq!(open_repetitions(r"\{,2\}"), r"\{,2\}");
        assert_eq!(open_repetitions(r"[\{,2}]"), r"[\{,2}]");
        // A `]` as the first thing in a class is a literal, not the end of it:
        // the class `[]]` is one character wide, and the brace after it is
        // outside it.
        assert_eq!(open_repetitions("[]]{,2}"), "[]]{0,2}");
        assert_eq!(open_repetitions("[^]]{,2}"), "[^]]{0,2}");
        // And a class that really ends still ends.
        assert_eq!(open_repetitions("[ab]{,2}"), "[ab]{0,2}");
    }

    #[test]
    fn the_pattern_the_corpus_writes_with_an_open_bound_compiles() {
        // Corpus line 297144. Before the rewrite this was a parse error — the
        // parser reads `{,` as a repetition and then finds no decimal — so the
        // rule was refused rather than compiled into something else.
        let s = r#"rule r { strings: $a = /eval\(Request\.Item\[.{,5}unsafe/ condition: $a }"#;
        assert_eq!(
            hits(s, "$a", b"eval(Request.Item[abcunsafe"),
            vec![(0, 27)],
            "up to five bytes between the bracket and the word"
        );
    }

    // -- refusals ----------------------------------------------------------

    #[test]
    fn a_wide_regex_now_matches_the_utf16_text_it_was_written_for() {
        // The other half of the refusal this used to be: the pattern compiles,
        // and it matches the wide encoding of the text rather than the text.
        let s = r#"rule r { strings: $a = /abc/ wide condition: $a }"#;
        let file = crate::parser::parse_file(s).unwrap();
        let compiled = compile(&file.rules[0].strings[0], 0).unwrap();

        let wide: Vec<u8> = "abc".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut set = MatchSet::with_capacity(1);
        assert!(compiled.find_all(&wide, &mut set));
        assert_eq!(set.count(0), 1);

        let mut plain = MatchSet::with_capacity(1);
        assert!(compiled.find_all(b"abc", &mut plain));
        assert_eq!(plain.count(0), 0, "the ASCII bytes are not the wide text");
    }

    #[test]
    fn a_wide_regex_with_a_word_boundary_is_one_the_match_has_to_pass() {
        // The refusal this used to be, and the failure it was there for: with
        // `\b` left in the pattern, the assertion before `e` reads the high byte
        // of the previous character — always `00` — and reports a boundary, so
        // `\beval` matches the `eval` inside `aeval`. Taken out of the pattern
        // and checked against the match, it does not.
        let s = r#"rule r { strings: $a = /\beval/ wide condition: $a }"#;
        // Two bytes per character: `eval` is eight bytes and `(` is two more.
        assert_eq!(hits(s, "$a", &utf16("eval(x)")), vec![(0, 8)]);
        assert_eq!(hits(s, "$a", &utf16(" eval(x)")), vec![(2, 8)]);
        assert!(
            hits(s, "$a", &utf16("aeval(x)")).is_empty(),
            "the `eval` inside `aeval` is not a word"
        );
    }

    #[test]
    fn a_wide_word_boundary_looks_at_the_characters_and_not_the_bytes() {
        // The trap the whole module is about: `aeval` in UTF-16LE has the bytes
        // `61 00 65 00 ...`, so the byte before the `e` is `00` — a non-word byte
        // — and a check that looked one byte back would call it a boundary. One
        // *character* back is the `a`, which is a word character, and the
        // assertion fails. A check that is off by one byte passes this test only
        // if the answer is the one it should not give.
        let s = r#"rule r { strings: $a = /\beval/ wide condition: $a }"#;
        assert!(hits(s, "$a", &utf16("aeval")).is_empty());
        // And the same at the end: the byte after `l` is `00`, one character
        // after is `x`.
        let s = r#"rule r { strings: $a = /eval\b/ wide condition: $a }"#;
        assert_eq!(hits(s, "$a", &utf16("eval(")), vec![(0, 8)]);
        assert!(hits(s, "$a", &utf16("evals")).is_empty());
    }

    #[test]
    fn a_wide_word_boundary_at_both_ends_is_checked_at_both_ends() {
        let s = r#"rule r { strings: $a = /\beval\b/ wide condition: $a }"#;
        assert_eq!(hits(s, "$a", &utf16("run eval(x)")), vec![(8, 8)]);
        assert!(
            hits(s, "$a", &utf16("aeval(x)")).is_empty(),
            "not the start"
        );
        assert!(hits(s, "$a", &utf16("evalx")).is_empty(), "not the end");
    }

    #[test]
    fn a_rejected_wide_candidate_does_not_hide_the_one_after_it() {
        // The reason the filtered search resumes one byte past the *start* of a
        // rejected match rather than past its end: the `eval` at the end of
        // `aeval eval` starts inside the match that was rejected, and a search
        // that had moved past it would never see it.
        let s = r#"rule r { strings: $a = /\beval/ wide condition: $a }"#;
        assert_eq!(hits(s, "$a", &utf16("aeval eval")), vec![(12, 8)]);
    }

    #[test]
    fn a_wide_regex_with_a_boundary_in_the_middle_is_still_refused() {
        // The check is about the position a match starts at or the one it ends
        // at, and a position inside the match is neither. `a\Bb` rather than
        // `a\bb` because the second one's assertion holds nowhere and the
        // pattern is refused as one that can never match, which is a different
        // diagnosis reached a step earlier.
        let s = r#"rule r { strings: $a = /a\Bb/ wide condition: $a }"#;
        let file = crate::parser::parse_file(s).unwrap();
        let err = compile(&file.rules[0].strings[0], 0).unwrap_err();
        assert_eq!(err.feature, Some("wide regex"));
        assert!(err.message.contains("middle"), "{}", err.message);
    }

    #[test]
    fn a_wide_regex_whose_dead_branch_is_pruned_still_compiles() {
        // `DITEKSHEN_INDICATOR_TOOL_Extpassword`'s `$s6`, which is the pattern
        // that made the pruning necessary: `Web\browsers` is a `\s` typo'd as a
        // `\b`, so the branch matches nothing, and the eight branches beside it
        // are what the rule is for. How many branches survive is asserted
        // through the behaviour rather than the text: the seven live ones match
        // and the dead one does not.
        let body = r"Scanning\s(Credentials\sfolder|Firefox\sand\sother\sMozilla\sWeb\sbrowsers|Chromium-based\Web\browsers|Windows\sVault)";
        let s = format!(r#"rule r {{ strings: $a = /{body}/ wide condition: $a }}"#);
        // Offsets and lengths are in the bytes the pattern runs over, which for
        // a `wide` pattern is two per character.
        assert_eq!(
            hits(&s, "$a", &utf16("Scanning Windows Vault")),
            vec![(0, 22 * 2)]
        );
        assert_eq!(
            hits(
                &s,
                "$a",
                &utf16("Scanning Firefox and other Mozilla Web browsers")
            ),
            vec![(0, 47 * 2)]
        );
        // The pruned branch, with the byte its `\b` would have had to sit
        // between: `\b` is false between two word characters, so this is the
        // shape the live branches must not have been loosened into.
        assert!(hits(&s, "$a", &utf16("Scanning Chromium-basedXebrowsers")).is_empty());
    }

    #[test]
    fn a_wide_regex_whose_alternatives_disagree_about_the_boundary_is_refused() {
        // One assertion is checked for the whole match, so a branch that does
        // not make it would be filtered by an assertion its author never wrote.
        let s = r#"rule r { strings: $a = /(?:\beval|assert)/ wide condition: $a }"#;
        let file = crate::parser::parse_file(s).unwrap();
        let err = compile(&file.rules[0].strings[0], 0).unwrap_err();
        assert_eq!(err.feature, Some("wide regex"));
        assert!(err.message.contains("alternatives"), "{}", err.message);
    }

    #[test]
    fn a_wide_regex_whose_alternatives_all_assert_the_boundary_is_accepted() {
        // The corpus shape this is here for: every branch begins with `\b`, so
        // the assertion is one the whole match makes.
        let s = r#"rule r { strings: $a = /(?:\beval|\bassert)/ wide condition: $a }"#;
        assert_eq!(hits(s, "$a", &utf16("x assert(1)")), vec![(4, 12)]);
        assert!(hits(s, "$a", &utf16("xassert")).is_empty());
    }

    #[test]
    fn an_unsupported_regex_flag_is_refused_by_name() {
        let hir = parse_for_atoms("abc", "").unwrap();
        // The refusals are checked while the key is formed, before the cache is
        // consulted, so a cache hit can never stand in for a pattern that would
        // have been refused.
        let err = regex_key("g", &Modifiers::default(), &hir).unwrap_err();
        assert_eq!(err.feature, Some("regex flag"));
    }

    #[test]
    fn an_invalid_regex_is_reported_as_the_authors_mistake() {
        // Not an unimplemented feature: the pattern itself does not parse. The
        // distinction matters because one is a gap in the engine and the other
        // is a broken rule, and they are fixed in different places.
        let err = parse_for_atoms("(unclosed", "").unwrap_err();
        assert_eq!(err.feature, None);
        assert!(err.message.contains("invalid regular expression"), "{err}");
    }

    #[test]
    fn an_empty_string_is_refused_as_invalid() {
        let err = compile(&text_def("$a", b""), 0).unwrap_err();
        assert_eq!(err.feature, None);
    }

    // -- interaction with the match table ---------------------------------

    #[test]
    fn several_literals_landing_on_one_span_are_one_match() {
        // `ascii wide` over a string that appears once. The two forms cannot
        // both match the same bytes, but `xor` with a key of zero can — and a
        // string that reports two matches where it has one makes `#a == 1`
        // false.
        let mut modifiers = Modifiers {
            ascii: true,
            ..Modifiers::default()
        };
        modifiers.xor = Some(crate::ast::XorRange { min: 0, max: 0 });
        let d = def("$a", StringValue::Text(b"hi".to_vec()), modifiers);
        let c = compile(&d, 0).unwrap();
        let mut set = MatchSet::with_capacity(1);
        assert!(c.find_all(b"hi", &mut set));
        assert_eq!(
            set.count(0),
            1,
            "the same bytes found twice is one occurrence"
        );
    }

    #[test]
    fn a_base64_string_is_found_in_encoded_text() {
        let s = r#"rule r { strings: $a = "foobar" base64 condition: $a }"#;
        assert!(
            !hits(s, "$a", b"prefix Zm9vYmFy suffix").is_empty(),
            "the encoding must be found"
        );
    }

    #[test]
    fn a_string_with_no_match_records_nothing() {
        let s = r#"rule r { strings: $a = "needle" condition: $a }"#;
        assert_eq!(
            hits(s, "$a", b"a haystack with a needle in it"),
            vec![(18, 6)]
        );
        assert!(hits(s, "$a", b"a haystack containing nothing").is_empty());
    }

    #[test]
    fn a_base64_string_is_still_a_literal_matcher() {
        // The base64 pass rewrites the bytes to search for; it does not turn
        // the string into a pattern, and it must not silently fall back to one.
        let mut modifiers = Modifiers {
            ascii: true,
            ..Modifiers::default()
        };
        modifiers.base64 = Some(Base64Alphabet {
            standard: true,
            url_safe: true,
            wide: false,
        });
        let d = def("$a", StringValue::Text(b"hello world".to_vec()), modifiers);
        let c = compile(&d, 0).unwrap();
        match &c.kind {
            Kind::Literal(literals) => assert!(literals.len() > 1, "both alphabets"),
            other => panic!("expected literals, got {other:?}"),
        }
    }
}
