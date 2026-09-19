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

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
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
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
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

    /// `[n]`, `[n-m]`, `[n-]`.
    fn parse_jump(&mut self) -> Result<HexToken, HexError> {
        let start = self.pos;
        debug_assert!(self.eat(b'['));
        self.skip_space();
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
        let start = self.pos;
        debug_assert!(self.eat(b'('));
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
        debug_assert!(self.eat(b'~'));
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
    fn a_non_hex_character_is_reported_with_its_offset() {
        let e = err("4D 5A ZZ");
        assert!(e.message.contains("not a hex digit"), "got: {e}");
        assert_eq!(e.offset, 6);
    }
}
