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

use std::fmt;

use crate::ast::{Modifiers, StringDef, StringValue};
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
enum Kind {
    /// One or more fixed byte sequences. A plain string is one; `wide`, `xor`
    /// and `base64` multiply it.
    Literal(Vec<text::Literal>),
    /// A hex pattern: a set of byte sequences described by wildcards, jumps and
    /// alternatives.
    Hex(pattern::Pattern),
    /// A regular expression, matched over bytes rather than characters.
    Regex {
        regex: Box<regex::bytes::Regex>,
        fullword: bool,
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
            Kind::Regex { regex, fullword } => {
                for m in regex.find_iter(data) {
                    // A regex that can match the empty string reports a hit at
                    // every offset. Those carry no information and would make
                    // `#a` the buffer length, so they are dropped.
                    if m.is_empty() {
                        continue;
                    }
                    if *fullword && !whole_word(data, m.start(), m.end()) {
                        continue;
                    }
                    if let (Ok(offset), Ok(length)) =
                        (u32::try_from(m.start()), u32::try_from(m.len()))
                    {
                        hits.push((offset, length));
                    }
                }
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

    /// Whether this string came from a hex pattern.
    pub fn is_hex(&self) -> bool {
        matches!(self.kind, Kind::Hex(_))
    }
}

/// Whether a `fullword` match is delimited by non-word bytes.
fn whole_word(data: &[u8], start: usize, end: usize) -> bool {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let before = start.checked_sub(1).and_then(|i| data.get(i)).copied();
    let after = data.get(end).copied();
    !before.is_some_and(is_word) && !after.is_some_and(is_word)
}

/// Compile a string definition into a matcher.
///
/// `slot` is the index the compiler assigned this string, so that matches land
/// in the row the interpreter will read.
pub fn compile(def: &StringDef, slot: u32) -> Result<CompiledString, MatcherError> {
    let kind = match &def.value {
        StringValue::Text(bytes) => {
            let literals = text::variants(bytes, &def.modifiers).map_err(MatcherError::invalid)?;
            Kind::Literal(literals)
        }
        StringValue::Hex(pattern) => {
            Kind::Hex(pattern::Pattern::compile(pattern).map_err(MatcherError::invalid)?)
        }
        StringValue::Regex { body, flags } => {
            Kind::Regex {
                regex: Box::new(build_regex(body, flags, &def.modifiers)?),
                fullword: def.modifiers.fullword,
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

/// Build a byte-oriented regex from a body and its flag letters.
///
/// Two decisions worth naming:
///
/// * **Bytes, not characters.** `unicode` is off, so `.` matches any byte and
///   a rule can express a pattern over a binary without the engine deciding
///   that some of its bytes are not valid UTF-8 and refusing to look at them.
///   YARA's regexes are byte-oriented for the same reason.
///
/// * **`wide` is refused rather than guessed at.** The right way to match a
///   UTF-16 expansion of a regex is to transform the pattern so that every
///   literal character is followed by a null byte, and doing that correctly
///   means parsing the regex — a character class, a quantifier and an escape
///   each need different treatment. Getting it nearly right would produce a
///   rule that matches the wrong bytes, so this reports what it cannot do and
///   the refusal is counted alongside the others.
fn build_regex(
    body: &str,
    flags: &str,
    modifiers: &Modifiers,
) -> Result<regex::bytes::Regex, MatcherError> {
    if modifiers.wide {
        return Err(MatcherError::unsupported(
            "wide regex",
            "a `wide` regular expression is not supported",
        ));
    }
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
    regex::bytes::RegexBuilder::new(body)
        .unicode(false)
        .case_insensitive(modifiers.nocase || flags.contains('i'))
        .dot_matches_new_line(flags.contains('s'))
        .multi_line(flags.contains('m'))
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

    // -- refusals ----------------------------------------------------------

    #[test]
    fn a_wide_regex_is_refused_by_name_rather_than_approximated() {
        let s = r#"rule r { strings: $a = /abc/ wide condition: $a }"#;
        let file = crate::parser::parse_file(s).unwrap();
        let err = compile(&file.rules[0].strings[0], 0).unwrap_err();
        assert_eq!(err.feature, Some("wide regex"));
    }

    #[test]
    fn an_unsupported_regex_flag_is_refused_by_name() {
        let body = "abc".to_string();
        let err = build_regex(&body, "g", &Modifiers::default()).unwrap_err();
        assert_eq!(err.feature, Some("regex flag"));
    }

    #[test]
    fn an_invalid_regex_is_reported_as_the_authors_mistake() {
        // Not an unimplemented feature: the pattern itself does not parse. The
        // distinction matters because one is a gap in the engine and the other
        // is a broken rule, and they are fixed in different places.
        let err = build_regex("(unclosed", "", &Modifiers::default()).unwrap_err();
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
        assert_eq!(set.count(0), 1, "the same bytes found twice is one occurrence");
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
        assert_eq!(hits(s, "$a", b"a haystack with a needle in it"), vec![(18, 6)]);
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
