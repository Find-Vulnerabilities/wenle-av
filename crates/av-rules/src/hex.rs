//! Parser for the `{ 4D 5A ?? [4-6] ( 41 | 42 ) }` hex pattern syntax.
//!
//! Roughly 43% of the strings in a typical third-party rule set are hex
//! patterns rather than text, and they carry the structural detail — wildcard
//! nibbles, variable-length gaps, alternation — that makes a signature
//! specific. Getting this parser exactly right matters more than it looks:
//! a wildcard silently read as a literal turns a precise rule into a rule that
//! never fires, and a jump read as a fixed gap turns it into one that fires on
//! the wrong thing.
//!
//! Grammar:
//!
//! ```text
//! pattern     := token*
//! token       := byte | nibble | jump | alternative | negation
//! byte        := hexdigit hexdigit
//! nibble      := hexdigit? hexdigit?          (at least one `?`)
//! jump        := '[' number ('-' number?)? ']'
//! alternative := '(' pattern ('|' pattern)* ')'
//! negation    := '~' ( alternative | byte )
//! ```

use std::fmt;

use crate::ast::{HexPattern, HexToken};

/// A syntax error inside a hex pattern, with the byte offset within the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexError {
    pub message: String,
    /// Offset from the start of the pattern body — the text between the braces.
    pub offset: usize,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at offset {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for HexError {}

/// Largest jump we will accept. A `[0-]` jump against a 4 GiB buffer would
/// otherwise generate an unbounded search per start offset.
const MAX_JUMP: u32 = 1 << 20;

/// Parse the body of a hex pattern (the text between the braces).
pub fn parse(body: &str) -> Result<HexPattern, HexError> {
    let mut p = Parser {
        src: body.as_bytes(),
        pos: 0,
        depth: 0,
    };
    let tokens = p.parse_pattern()?;
    p.skip_space();
    if p.pos < p.src.len() {
        return Err(p.error("unexpected trailing input in hex pattern"));
    }
    if tokens.is_empty() {
        return Err(HexError {
            message: "hex pattern is empty".into(),
            offset: 0,
        });
    }
    Ok(HexPattern { tokens })
}

/// Deepest alternation nesting accepted.
///
/// `parse_pattern` and `parse_alternative` are mutually recursive, so a body
/// that is nothing but `((((...` recurses once per character. Real patterns
/// nest two or three levels. See [`crate::parser::MAX_DEPTH`] for why a bound
/// like this has to exist at all.
const MAX_DEPTH: u32 = 64;

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    depth: u32,
}

impl<'a> Parser<'a> {
    fn error(&self, message: impl Into<String>) -> HexError {
        HexError {
            message: message.into(),
            offset: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_space(&mut self) {
        loop {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.pos += 1;
            }
            // Hex patterns in real rule sets annotate nearly every token:
            // `88 4C 34 10  //mov byte ptr [esp + esi + 0x10], cl`. Treating
            // `//` as anything but a comment makes those patterns unparseable,
            // and a hex pattern that fails to parse is a rule that silently
            // never fires.
            if self.peek() == Some(b'/') && self.src.get(self.pos + 1) == Some(&b'/') {
                while !matches!(self.peek(), None | Some(b'\n')) {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consume `byte`, which the caller has already peeked.
    ///
    /// The consumption must never live inside a `debug_assert!`. An assertion
    /// is stripped from the release build — the build that ships — so
    /// `debug_assert!(self.eat(b'('))` left the `(` unconsumed in release while
    /// behaving correctly under `cargo test`. The result was that
    /// `( AA | BB )` recursed between `parse_pattern` and `parse_alternative`
    /// until the stack was gone, in the shipping build only, with a green test
    /// suite. A guard that disappears in release is not a guard.
    fn expect_byte(&mut self, byte: u8) -> Result<(), HexError> {
        debug_assert_eq!(self.peek(), Some(byte), "caller peeked a different byte");
        if self.eat(byte) {
            Ok(())
        } else {
            Err(self.error(format!("expected `{}`", byte as char)))
        }
    }

    fn parse_pattern(&mut self) -> Result<Vec<HexToken>, HexError> {
        let mut out = Vec::new();
        loop {
            self.skip_space();
            match self.peek() {
                None | Some(b')' | b'|') => break,
                Some(b'(') => out.push(self.parse_alternative()?),
                Some(b'~') => out.push(self.parse_negation()?),
                Some(b'[') => out.push(self.parse_jump()?),
                Some(b'?') => {
                    // `??`, `?A` — a nibble with a wildcard high half.
                    self.pos += 1;
                    let low = self.parse_optional_nibble()?;
                    out.push(HexToken::Nibble { high: None, low });
                }
                Some(_) => out.push(self.parse_byte_or_nibble()?),
            }
        }
        Ok(out)
    }

    /// A token starting with a hex digit: either a full byte `4D`, or a nibble
    /// with a wildcard low half `4?`.
    fn parse_byte_or_nibble(&mut self) -> Result<HexToken, HexError> {
        let high = self.parse_nibble_digit()?;
        match self.peek() {
            Some(b'?') => {
                self.pos += 1;
                Ok(HexToken::Nibble {
                    high: Some(high),
                    low: None,
                })
            }
            Some(c) if c.is_ascii_hexdigit() => {
                let low = self.parse_nibble_digit()?;
                Ok(HexToken::Byte((high << 4) | low))
            }
            _ => Err(self.error("hex byte needs two digits, or `?` for a wildcard nibble")),
        }
    }

    /// Parse a single hex digit. The caller has already established that one
    /// is present.
    fn parse_nibble_digit(&mut self) -> Result<u8, HexError> {
        // Report the offset of the offending character, not the position after
        // it — an error that points one column past the problem is worse than
        // useless when the pattern is a wall of hex.
        let at = self.pos;
        let b = self.bump().ok_or_else(|| self.error("truncated hex pattern"))?;
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            other => Err(HexError {
                message: format!("`{}` is not a hex digit", other as char),
                offset: at,
            }),
        }
    }

    /// Used for the low half of a nibble, where `?` is also acceptable.
    fn parse_optional_nibble(&mut self) -> Result<Option<u8>, HexError> {
        match self.peek() {
            Some(b'?') => {
                self.pos += 1;
                Ok(None)
            }
            Some(c) if c.is_ascii_hexdigit() => Ok(Some(self.parse_nibble_digit()?)),
            _ => Err(self.error("`?` must be followed by a hex digit or another `?`")),
        }
    }

    /// `[n]`, `[n-m]`, `[n-]`, `[-]`.
    fn parse_jump(&mut self) -> Result<HexToken, HexError> {
        let start = self.pos;
        self.expect_byte(b'[')?;
        self.skip_space();
        // `[-]` is an unbounded jump — any number of bytes, including none.
        // It appears in the middle of long patterns where the author was
        // splicing in a gap to keep the surrounding code aligned, so refusing
        // it would reject the whole rule over a detail that carries no
        // matching constraint.
        if self.eat(b'-') {
            self.skip_space();
            if !self.eat(b']') {
                return Err(HexError {
                    message: "`[-]` takes no bounds; expected `]`".into(),
                    offset: start,
                });
            }
            return Ok(HexToken::Jump { min: 0, max: None });
        }
        let min = self.parse_number()?;
        self.skip_space();
        let max = if self.eat(b'-') {
            self.skip_space();
            if matches!(self.peek(), Some(b']')) {
                None // `[4-]` — unbounded
            } else {
                Some(self.parse_number()?)
            }
        } else {
            Some(min)
        };
        self.skip_space();
        if !self.eat(b']') {
            return Err(HexError {
                message: "unterminated jump; expected `]`".into(),
                offset: start,
            });
        }
        if min > MAX_JUMP {
            return Err(HexError {
                message: format!("jump lower bound {min} exceeds the maximum of {MAX_JUMP}"),
                offset: start,
            });
        }
        if let Some(max) = max {
            if max > MAX_JUMP {
                return Err(HexError {
                    message: format!("jump upper bound {max} exceeds the maximum of {MAX_JUMP}"),
                    offset: start,
                });
            }
            if max < min {
                return Err(HexError {
                    message: format!("jump range [{min}-{max}] is inverted"),
                    offset: start,
                });
            }
        }
        Ok(HexToken::Jump { min, max })
    }

    /// `( AA | BB CC )`.
    fn parse_alternative(&mut self) -> Result<HexToken, HexError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.error("hex pattern nests too deeply"));
        }
        self.depth = self.depth.saturating_add(1);
        let result = self.parse_alternative_inner();
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn parse_alternative_inner(&mut self) -> Result<HexToken, HexError> {
        let start = self.pos;
        self.expect_byte(b'(')?;
        let mut branches = Vec::new();
        loop {
            let branch = self.parse_pattern()?;
            if branch.is_empty() {
                return Err(HexError {
                    message: "empty branch in an alternative".into(),
                    offset: self.pos,
                });
            }
            branches.push(branch);
            self.skip_space();
            if self.eat(b'|') {
                continue;
            }
            if self.eat(b')') {
                break;
            }
            return Err(HexError {
                message: "unterminated alternative; expected `|` or `)`".into(),
                offset: start,
            });
        }
        if branches.len() == 1 {
            // `( AA )` is just `AA`. Collapsing it keeps `as_exact_bytes`
            // working on patterns that are exact but parenthesised, which is
            // common in machine-generated rules.
            return match branches.swap_remove(0).as_slice() {
                [only] => Ok(only.clone()),
                inner => Ok(HexToken::Alternative(vec![inner.to_vec()])),
            };
        }
        Ok(HexToken::Alternative(branches))
    }

    /// `~AA`, `~( AA | BB )`.
    fn parse_negation(&mut self) -> Result<HexToken, HexError> {
        let start = self.pos;
        self.expect_byte(b'~')?;
        self.skip_space();
        let inner = match self.peek() {
            // A single-branch, single-token alternative collapses to that
            // token, so this must tolerate a non-`Alternative` result.
            Some(b'(') => match self.parse_alternative()? {
                HexToken::Alternative(branches) => branches,
                other => vec![vec![other]],
            },
            Some(_) => vec![vec![self.parse_byte_or_nibble()?]],
            None => {
                return Err(HexError {
                    message: "`~` must be followed by a byte or an alternative".into(),
                    offset: start,
                });
            }
        };
        Ok(HexToken::Not(inner))
    }

    fn parse_number(&mut self) -> Result<u32, HexError> {
        let start = self.pos;
        let mut value: u64 = 0;
        while let Some(b) = self.peek() {
            if !b.is_ascii_digit() {
                break;
            }
            value = value
                .saturating_mul(10)
                .saturating_add(u64::from(b - b'0'));
            if value > u64::from(u32::MAX) {
                return Err(HexError {
                    message: "number in a jump is too large".into(),
                    offset: start,
                });
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(self.error("expected a number inside the jump brackets"));
        }
        Ok(value as u32)
    }
}

#[cfg(test)]
mod tests {
    //! Run these under `cargo test --release` as well as the default profile.
    //!
    //! The parser once consumed delimiters inside `debug_assert!`, which made
    //! `( AA | BB )` recurse until the stack ran out — in release only, while
    //! every debug-build test passed. A green default `cargo test` therefore
    //! says nothing about the build that ships, and the alternatives and
    //! negation tests below are the ones that catch this class of mistake.

    use super::*;

    fn p(body: &str) -> HexPattern {
        parse(body).unwrap_or_else(|e| panic!("`{body}` should parse: {e}"))
    }

    fn err(body: &str) -> HexError {
        parse(body).expect_err("pattern should be rejected")
    }

    #[test]
    fn parses_a_plain_byte_sequence() {
        assert_eq!(
            p("4D 5A 90").tokens,
            vec![
                HexToken::Byte(0x4D),
                HexToken::Byte(0x5A),
                HexToken::Byte(0x90)
            ]
        );
    }

    #[test]
    fn single_digit_nibbles_are_rejected() {
        // `4` alone is ambiguous between `04` and a truncated `4D`; refusing it
        // is better than guessing.
        assert!(err("4D 5").message.contains("two digits"));
    }

    #[test]
    fn parses_all_three_wildcard_nibble_forms() {
        assert_eq!(
            p("?? ?A 4?").tokens,
            vec![
                HexToken::Nibble { high: None, low: None },
                HexToken::Nibble { high: None, low: Some(0xA) },
                HexToken::Nibble { high: Some(4), low: None },
            ]
        );
    }

    #[test]
    fn parses_fixed_and_ranged_jumps() {
        assert_eq!(
            p("[4]").tokens,
            vec![HexToken::Jump { min: 4, max: Some(4) }]
        );
        assert_eq!(
            p("[2-6]").tokens,
            vec![HexToken::Jump { min: 2, max: Some(6) }]
        );
        assert_eq!(
            p("[4-]").tokens,
            vec![HexToken::Jump { min: 4, max: None }]
        );
    }

    #[test]
    fn whitespace_inside_a_jump_is_tolerated() {
        assert_eq!(
            p("[ 2 - 6 ]").tokens,
            vec![HexToken::Jump { min: 2, max: Some(6) }]
        );
    }

    #[test]
    fn inverted_jump_ranges_are_rejected() {
        assert!(err("[6-2]").message.contains("inverted"));
    }

    #[test]
    fn oversized_jumps_are_rejected() {
        assert!(err("[99999999]").message.contains("exceeds the maximum"));
    }

    #[test]
    fn parses_alternatives() {
        let pattern = p("( 41 | 42 43 )");
        match &pattern.tokens[0] {
            HexToken::Alternative(branches) => {
                assert_eq!(branches.len(), 2);
                assert_eq!(branches[0], vec![HexToken::Byte(0x41)]);
                assert_eq!(branches[1], vec![HexToken::Byte(0x42), HexToken::Byte(0x43)]);
            }
            other => panic!("expected an alternative, got {other:?}"),
        }
    }

    #[test]
    fn parses_alternatives_with_wildcards_and_jumps() {
        let pattern = p("( 41 FF | 42 ?? [1-2] 43 )");
        assert_eq!(pattern.length_bounds(), (2, 5));
    }

    #[test]
    fn parses_negation() {
        let pattern = p("~41");
        assert!(matches!(pattern.tokens[0], HexToken::Not(_)));
    }

    #[test]
    fn negation_of_an_alternative_captures_every_branch() {
        let pattern = p("~( 41 | 42 )");
        match &pattern.tokens[0] {
            HexToken::Not(branches) => assert_eq!(branches.len(), 2),
            other => panic!("expected a negation, got {other:?}"),
        }
    }

    #[test]
    fn nested_alternatives_parse() {
        let pattern = p("( 41 | ( 42 | 43 ) )");
        assert!(matches!(pattern.tokens[0], HexToken::Alternative(_)));
    }

    #[test]
    fn unterminated_alternative_is_reported() {
        assert!(err("( 41 | 42").message.contains("unterminated alternative"));
    }

    #[test]
    fn empty_alternative_branch_is_rejected() {
        assert!(err("( 41 | )").message.contains("empty branch"));
    }

    #[test]
    fn empty_pattern_is_rejected() {
        assert!(err("   ").message.contains("empty"));
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        assert!(err("41 )").message.contains("trailing input"));
    }

    #[test]
    fn exact_patterns_round_trip_to_bytes() {
        let pattern = p("4D 5A 90 00 03");
        assert_eq!(
            pattern.as_exact_bytes(),
            Some(vec![0x4D, 0x5A, 0x90, 0x00, 0x03])
        );
    }

    #[test]
    fn a_real_world_pattern_parses_and_reports_bounds() {
        // Taken from the shape of patterns in the source rule set.
        let pattern = p("49 89 CA 4? 89 ?? ( 41 FF | FF )");
        // 49 89 CA | 4? | 89 | ?? | one-or-two bytes for the alternative
        assert_eq!(pattern.length_bounds(), (7, 8));
        assert_eq!(pattern.as_exact_bytes(), None);
        assert_eq!(pattern.exact_prefix(), vec![0x49, 0x89, 0xCA]);
    }

    #[test]
    fn a_parenthesised_exact_sequence_is_still_exact() {
        assert_eq!(p("( 4D 5A )").as_exact_bytes(), Some(vec![0x4D, 0x5A]));
        assert_eq!(p("( 4D )").as_exact_bytes(), Some(vec![0x4D]));
    }

    #[test]
    fn negating_a_single_token_does_not_panic() {
        // Regression: collapsing single-branch alternatives must not break the
        // negation path, which expects an `Alternative`.
        let pattern = p("~( 41 )");
        match &pattern.tokens[0] {
            HexToken::Not(branches) => assert_eq!(branches.len(), 1),
            other => panic!("expected a negation, got {other:?}"),
        }
    }

    #[test]
    fn lowercase_hex_digits_are_accepted() {
        assert_eq!(p("4d 5a").tokens, vec![HexToken::Byte(0x4D), HexToken::Byte(0x5A)]);
    }

    #[test]
    fn comments_inside_a_pattern_are_ignored() {
        // Rule authors annotate nearly every token of a long pattern with the
        // disassembly it came from. Refusing the comment would reject the whole
        // rule over text that carries no matching constraint.
        let pattern = p(
            "8A 94 1C 10 01 ?? ??  //mov dl, byte ptr [esp + ebx + 0x110]\n\
             8D 8C 24 10 01 ?? ??  //lea ecx, [esp + 0x110]\n\
             46                    //inc esi",
        );
        // Seven tokens per annotated line, plus the trailing `46`.
        assert_eq!(pattern.tokens.len(), 15);
        assert_eq!(pattern.tokens[0], HexToken::Byte(0x8A));
        assert_eq!(
            pattern.tokens[7],
            HexToken::Byte(0x8D),
            "the second line must start at its own first byte"
        );
        assert_eq!(pattern.tokens[14], HexToken::Byte(0x46));
    }

    #[test]
    fn a_comment_at_the_end_of_a_pattern_is_ignored() {
        // Trailing comments are the common case, and `parse` rejects trailing
        // input after the last token — so a comment left unskipped here would
        // be read as trailing garbage.
        assert_eq!(p("4D 5A  // MZ").tokens.len(), 2);
    }

    #[test]
    fn a_lone_slash_is_not_a_comment() {
        let e = err("4D 5A / 90");
        assert!(e.message.contains('/'), "{e}");
    }

    #[test]
    fn an_unbounded_jump_is_accepted() {
        // `[-]` matches any number of bytes, including none.
        let pattern = p("8D 05 [-] 4? 8D 4D ??");
        assert_eq!(pattern.tokens[2], HexToken::Jump { min: 0, max: None });
    }

    #[test]
    fn an_unbounded_jump_takes_no_bounds() {
        // `[-]` and `[n-m]` are different forms; a bound after the `-` means
        // the author wrote one of each and the pattern is not what they meant.
        let e = err("8D 05 [-3] 90");
        assert!(e.message.contains("`[-]`"), "{e}");
    }

    #[test]
    fn a_non_hex_character_is_reported_with_its_offset() {
        let e = err("4D 5A ZZ");
        assert!(e.message.contains("not a hex digit"), "got: {e}");
        assert_eq!(e.offset, 6);
    }
}
