//! Matching `{ 4D 5A ?? [4-6] (41|42) }` hex patterns.
//!
//! Roughly 43% of the strings in a third-party rule set are hex patterns, and
//! they carry the structural detail that makes a signature specific: the
//! wildcard nibbles, the variable-length gaps, the alternatives. A pattern is
//! therefore not a literal — it describes a *set* of byte sequences — and
//! finding it means walking it against the buffer.
//!
//! # Finding, not just testing
//!
//! It is tempting to write only "does this pattern match at offset N" and let
//! the atom prefilter supply the N. That is how a fast engine works, but it
//! puts the whole burden on the prefilter and makes the matcher untestable on
//! its own. So there are two entry points: [`Pattern::matches_at`] answers the
//! question at a known offset, and [`Pattern::find_all`] scans for every
//! occurrence, using the pattern's own longest fixed prefix to skip the offsets
//! that cannot possibly start a match.
//!
//! # Backtracking, and why the continuation is threaded through
//!
//! A pattern branches in two places — a jump tries each gap length, an
//! alternative each branch — and a choice that succeeds locally can still leave
//! the rest of the pattern unmatchable. `( 41 [1-2] 42 ) 43` against `41 42 42
//! 43` is the shape: the branch matches with a one-byte gap, but then there is
//! no `43` where the branch ended, and the two-byte gap is the one that works.
//! A matcher that returned "the branch matched" and then tried the rest would
//! miss it.
//!
//! So the walk takes a continuation: `seq(tokens, at, k)` matches `tokens` at
//! `at` and, on success, calls `k(end)` to match whatever follows, returning
//! whether that succeeded. Backtracking then falls out of the recursion instead
//! of being bolted on, and the alternative case passes `rest` into the branch's
//! continuation rather than running it afterwards.
//!
//! # Which match is reported
//!
//! A pattern with a jump can match several lengths at one offset: `{ 41 [2-6]
//! 42 }` is four bytes or five or six or seven or eight, all starting in the
//! same place. Only one is recorded, and it is the **shortest**, because gaps
//! are tried in increasing order. The consequence is worth stating plainly:
//! `!a` reports the shortest match, so a rule that expects the longest is a
//! rule that does not do what its author meant. YARA resolves the same
//! ambiguity the same way.
//!
//! # Bounded work
//!
//! A pattern of thirty `( 41 | 42 )` alternatives has a billion paths, and no
//! amount of care in the walk changes that. A scanner that can be handed one
//! rule and stop responding is not a scanner, so every walk carries a budget;
//! when it runs out the search stops and [`Pattern::find_all`] reports that it
//! did. The budget is sized so that no pattern that is not exponentially
//! branching can reach it — reaching it means the rule is an attack on the
//! scanner rather than a signature, and the caller counts it.

use std::cell::Cell;

use crate::ast::{HexPattern, HexToken};
use crate::hex::MAX_JUMP;

/// Work allowed per candidate start offset in [`Pattern::matches_at`].
const STEPS_PER_CANDIDATE: u32 = 4096;

/// A compiled hex pattern, ready to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub tokens: Vec<HexToken>,
    /// Shortest and longest byte length the whole pattern can match.
    pub min_length: usize,
    pub max_length: usize,
    /// The longest run of fully determined bytes at the start.
    ///
    /// This is what makes scanning affordable: a pattern beginning `4D 5A 90`
    /// only has to be tried where those bytes are, and finding them is a SIMD
    /// search. A pattern beginning with a wildcard gives an empty prefix and
    /// falls back to trying every offset, which is the slow path the atom
    /// prefilter exists to keep rules out of.
    pub prefix: Vec<u8>,
}

impl Pattern {
    pub fn compile(pattern: &HexPattern) -> Result<Self, &'static str> {
        check_jumps(&pattern.tokens)?;
        let (min_length, max_length) = pattern.length_bounds();
        Ok(Self {
            tokens: pattern.tokens.clone(),
            min_length,
            max_length,
            prefix: pattern.exact_prefix(),
        })
    }

    /// Whether the pattern matches starting exactly at `at`.
    ///
    /// Returns the length of the shortest match, or `None`. A pattern complex
    /// enough to exhaust the per-candidate budget also returns `None`, which is
    /// indistinguishable from "no match here" — the caller that needs to tell
    /// them apart is [`Pattern::find_all`], which reports it.
    pub fn matches_at(&self, data: &[u8], at: usize) -> Option<usize> {
        if at > data.len() {
            return None;
        }
        let limit = self.limit_for(data, at);
        let budget = Cell::new(STEPS_PER_CANDIDATE);
        let mut end = None;
        seq(data, &self.tokens, at, limit, &budget, &mut |e| {
            end = Some(e);
            true
        });
        end.map(|e| e - at)
    }

    /// Find every offset where the pattern matches.
    ///
    /// Returns `false` if the work budget ran out before the scan finished, in
    /// which case `out` holds the matches found up to that point. The caller
    /// counts that rather than treating it as an answer: a rule whose string
    /// could not be searched has not been shown *not* to match.
    pub fn find_all(&self, data: &[u8], out: &mut Vec<(u32, u32)>) -> bool {
        if self.min_length > data.len() {
            return true;
        }
        // Sized from the buffer: every candidate offset gets the allowance a
        // single `matches_at` call would give it, so a pattern that can be
        // tested once can be tested everywhere. The cap on the buffer's
        // contribution is what keeps a 4 GiB file from asking for a budget
        // nobody needs — past 64 Ki positions, the cost is dominated by
        // actually reading the file rather than by the walk.
        let budget = Cell::new(
            STEPS_PER_CANDIDATE.saturating_mul(
                u32::try_from(data.len()).unwrap_or(u32::MAX).min(1 << 16),
            ),
        );

        // One candidate start, one full walk. Returns whether the walk finished
        // rather than exhausting the budget.
        let try_at = |at: usize| -> Option<Option<usize>> {
            let limit = self.limit_for(data, at);
            let mut end = None;
            let completed = seq(data, &self.tokens, at, limit, &budget, &mut |e| {
                end = Some(e);
                true
            });
            if !completed && budget.get() == 0 {
                return None;
            }
            Some(end.map(|e| e - at))
        };

        let mut record = |at: usize, len: usize| {
            if let (Ok(offset), Ok(length)) = (u32::try_from(at), u32::try_from(len)) {
                out.push((offset, length));
            }
        };

        if self.prefix.is_empty() {
            let last = data.len().saturating_sub(self.min_length);
            for at in 0..=last {
                match try_at(at) {
                    Some(Some(len)) => record(at, len),
                    Some(None) => {}
                    None => return false,
                }
            }
            return true;
        }

        // Overlapping candidates matter: a pattern whose prefix is `41 41`
        // matches `AAA` at both 0 and 1, and `memmem::find_iter` yields only
        // non-overlapping occurrences, so it would report the first and skip
        // the second. Advancing one byte past each find costs a rescan of the
        // prefix, which is the cheap half of the work.
        let finder = memchr::memmem::Finder::new(&self.prefix);
        let mut from = 0usize;
        while from + self.prefix.len() <= data.len() {
            let Some(rel) = finder.find(&data[from..]) else {
                return true;
            };
            let at = from + rel;
            match try_at(at) {
                Some(Some(len)) => record(at, len),
                Some(None) => {}
                None => return false,
            }
            from = at + 1;
        }
        true
    }

    /// The furthest offset a match starting at `at` may reach.
    ///
    /// The buffer end, or the pattern's own maximum length, whichever is
    /// nearer. The second half matters: without it `{ 41 [1-2] 42 }` would
    /// happily find a `42` far beyond the four bytes its author allowed.
    fn limit_for(&self, data: &[u8], at: usize) -> usize {
        at.saturating_add(self.max_length).min(data.len())
    }
}

/// Refuse a jump the matcher will not walk.
///
/// The hex parser enforces the same bound ([`MAX_JUMP`]), so a pattern that
/// came through it can never fail this check. It is here because
/// [`Pattern::compile`] is public and [`HexPattern`] has public fields: a
/// pattern assembled by an importer or by a test never went past the parser,
/// and the matcher must not be the place where that is discovered by hanging.
/// The two messages differ on purpose — one says the pattern is not valid AVRL,
/// the other says the engine will not walk it — because they are fixed in
/// different places.
fn check_jumps(tokens: &[HexToken]) -> Result<(), &'static str> {
    for token in tokens {
        match token {
            HexToken::Jump { min, .. } => {
                if *min > MAX_JUMP {
                    return Err("a hex jump wider than the engine will walk");
                }
            }
            HexToken::Alternative(branches) | HexToken::Not(branches) => {
                for branch in branches {
                    check_jumps(branch)?;
                }
            }
            HexToken::Byte(_) | HexToken::Nibble { .. } => {}
        }
    }
    Ok(())
}

/// Match `tokens` at `at`, then hand the end offset to `k`.
///
/// Returns whether the tokens and the continuation both matched. `budget` is
/// spent one token at a time; a walk that runs out fails.
///
/// The budget is a [`Cell`] rather than a `&mut u32` because the continuation
/// is a closure that has to keep spending from the same counter while the call
/// that handed it the counter is still on the stack. A mutable borrow cannot be
/// in two places at once; interior mutability is the tool for exactly this, and
/// one cell read per token is not a cost worth avoiding.
///
/// The continuation is a trait object rather than another type parameter. A
/// generic `F` looks tidier and does not compile: the alternative case calls
/// `seq` with a *new* closure type, so each level of recursion would need its
/// own instantiation and monomorphisation never terminates. One virtual call
/// per token is a price worth paying for a function that exists.
fn seq(
    data: &[u8],
    tokens: &[HexToken],
    at: usize,
    limit: usize,
    budget: &Cell<u32>,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    let left = budget.get();
    if left == 0 {
        return false;
    }
    budget.set(left - 1);

    let Some((first, rest)) = tokens.split_first() else {
        return k(at);
    };

    match first {
        HexToken::Byte(b) => {
            at < limit && data.get(at) == Some(b) && seq(data, rest, at + 1, limit, budget, k)
        }

        HexToken::Nibble { high, low } => {
            if at >= limit {
                return false;
            }
            let Some(byte) = data.get(at).copied() else {
                return false;
            };
            let ok = high.is_none_or(|h| byte >> 4 == h) && low.is_none_or(|l| byte & 0x0F == l);
            ok && seq(data, rest, at + 1, limit, budget, k)
        }

        HexToken::Jump { min, max } => {
            // The gap may not take the match past the limit, so an unbounded
            // jump stops at the buffer end rather than at `u32::MAX`.
            let high = max.map_or(limit, |m| at.saturating_add(m as usize)).min(limit);
            let mut gap = *min as usize;
            while at.saturating_add(gap) <= high {
                if seq(data, rest, at + gap, limit, budget, k) {
                    return true;
                }
                gap += 1;
            }
            false
        }

        HexToken::Alternative(branches) => {
            // `rest` goes *into* the branch's continuation, not after it. That
            // is what lets a branch which matches locally but leaves the rest
            // unmatchable be abandoned in favour of another gap or branch.
            for branch in branches {
                if seq(data, branch, at, limit, budget, &mut |end| {
                    seq(data, rest, end, limit, budget, k)
                }) {
                    return true;
                }
            }
            false
        }

        HexToken::Not(branches) => {
            // "Any byte that does not begin one of these". One byte is
            // consumed, whichever branch matched — the byte is the negation.
            // Consuming the branch's own length instead would make this token's
            // length depend on what it matched, which nothing else in the
            // language does, and would make `~ ( 41 42 )` unable to match a
            // lone `41` at the end of a buffer.
            if at >= limit || at >= data.len() {
                return false;
            }
            for branch in branches {
                if seq(data, branch, at, data.len(), budget, &mut |_| true) {
                    return false;
                }
            }
            seq(data, rest, at + 1, limit, budget, k)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn compile(body: &str) -> Pattern {
        Pattern::compile(&hex::parse(body).expect("test pattern must parse")).expect("must compile")
    }

    fn find(body: &str, data: &[u8]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        assert!(compile(body).find_all(data, &mut out), "budget ran out");
        out
    }

    fn at(body: &str, data: &[u8], offset: usize) -> Option<usize> {
        compile(body).matches_at(data, offset)
    }

    // -- exact bytes -------------------------------------------------------

    #[test]
    fn an_exact_pattern_matches_its_bytes() {
        assert_eq!(find("4D 5A", b"MZ\x90\x00"), vec![(0, 2)]);
        assert_eq!(find("5A 90", b"MZ\x90\x00"), vec![(1, 2)]);
        assert!(find("41 41", b"MZ").is_empty());
    }

    #[test]
    fn an_exact_pattern_is_recognised_as_a_literal() {
        let exact = |body: &str| {
            let p = compile(body);
            HexPattern { tokens: p.tokens }.as_exact_bytes()
        };
        assert_eq!(exact("4D 5A 90"), Some(b"MZ\x90".to_vec()));
        assert_eq!(exact("4D ?? 90"), None);
    }

    #[test]
    fn a_parenthesised_single_branch_is_still_exact() {
        // `( 4D 5A )` constrains nothing beyond `4D 5A`, so treating it as
        // inexact would push a precisely known pattern through the general
        // matcher for no reason.
        let p = compile("( 4D 5A )");
        assert_eq!(HexPattern { tokens: p.tokens }.as_exact_bytes(), Some(b"MZ".to_vec()));
    }

    // -- wildcard nibbles --------------------------------------------------

    #[test]
    fn a_high_nibble_wildcard_ignores_the_low_nibble() {
        assert_eq!(at("4?", b"\x4A", 0), Some(1));
        assert_eq!(at("4?", b"\x5A", 0), None);
    }

    #[test]
    fn a_low_nibble_wildcard_ignores_the_high_nibble() {
        assert_eq!(at("?A", b"\x4A", 0), Some(1));
        assert_eq!(at("?A", b"\x4B", 0), None);
    }

    #[test]
    fn a_fully_wild_byte_matches_anything_but_still_consumes_one() {
        assert_eq!(at("??", b"\xFF", 0), Some(1));
        assert_eq!(at("??", b"", 0), None, "it still needs a byte to consume");
    }

    #[test]
    fn a_wildcard_runs_through_a_whole_buffer() {
        assert_eq!(at("?? ?? ??", b"abc", 0), Some(3));
        assert_eq!(at("?? ?? ?? ??", b"abc", 0), None);
    }

    #[test]
    fn a_wildcard_is_not_matched_at_the_end_of_the_buffer() {
        // `??` at 3 on a three-byte buffer has nothing to consume. Reading past
        // the end would be the bug; matching the buffer's last byte twice would
        // be the other one.
        assert_eq!(at("??", b"abc", 3), None);
        assert_eq!(at("?? ??", b"abc", 2), None);
        assert_eq!(at("?? ??", b"abc", 1), Some(2), "the last legal offset");
    }

    // -- jumps -------------------------------------------------------------

    #[test]
    fn a_fixed_jump_requires_exactly_that_gap() {
        assert_eq!(at("41 [2] 42", b"A..B", 0), Some(4));
        assert_eq!(at("41 [2] 42", b"A.B", 0), None);
        assert_eq!(at("41 [2] 42", b"A...B", 0), None);
    }

    #[test]
    fn a_ranged_jump_takes_the_shortest_gap_that_works() {
        // The documented resolution of the ambiguity: the shortest reading.
        assert_eq!(at("41 [1-3] 42", b"A.B", 0), Some(3));
        assert_eq!(at("41 [1-3] 42", b"A..B", 0), Some(4));
        // A gap of at least one needs a byte between the two, so a bare `AB`
        // cannot match however short the jump is allowed to be.
        assert_eq!(at("41 [1-3] 42", b"AB", 0), None);
    }

    #[test]
    fn a_jump_can_span_zero_bytes_where_the_language_allows_it() {
        assert_eq!(at("41 [0-2] 42", b"AB", 0), Some(2));
    }

    #[test]
    fn an_unbounded_jump_stops_at_the_buffer_end() {
        assert_eq!(at("41 [1-] 42", b"A....B", 0), Some(6));
        assert_eq!(at("41 [1-] 42", b"A", 0), None);
        // It must not run off looking for something that is not there.
        assert_eq!(at("41 [1-] 42", &[b'A'; 4096], 0), None);
    }

    #[test]
    fn a_jump_is_not_allowed_to_run_past_the_patterns_own_maximum() {
        assert_eq!(at("41 [1-2] 42", b"A...B", 0), None);
        assert_eq!(at("41 [1-2] 42", b"A..B", 0), Some(4));
    }

    // -- alternatives ------------------------------------------------------

    #[test]
    fn an_alternative_tries_each_branch() {
        assert_eq!(at("( 41 | 42 )", b"A", 0), Some(1));
        assert_eq!(at("( 41 | 42 )", b"B", 0), Some(1));
        assert_eq!(at("( 41 | 42 )", b"C", 0), None);
    }

    #[test]
    fn an_alternative_with_branches_of_different_lengths_is_matched_by_the_shortest() {
        let p = "41 ( 42 | 43 44 ) 45";
        assert_eq!(at(p, b"ABE", 0), Some(3), "the one-byte branch");
        assert_eq!(at(p, b"ACDE", 0), Some(4), "the two-byte branch");
        assert_eq!(at(p, b"ACD", 0), None);
    }

    #[test]
    fn a_branch_that_leaves_the_rest_unmatchable_is_abandoned_for_another_gap() {
        // The case that motivates threading the continuation through: branch
        // one matches locally with a one-byte gap, but then there is no `43`
        // where it ended, and only the two-byte gap leads to a whole match.
        // A matcher that ran the rest after the branch would report no match.
        assert_eq!(at("( 41 [1-2] 42 ) 43", b"ABBC", 0), Some(4));
    }

    #[test]
    fn a_branch_that_leaves_the_rest_unmatchable_is_abandoned_for_another_branch() {
        assert_eq!(at("( 41 | 41 42 ) 43", b"ABC", 0), Some(3));
    }

    #[test]
    fn a_nested_alternative_works() {
        let p = "( 41 ( 42 | 43 ) | 44 ) 45";
        assert_eq!(at(p, b"ABE", 0), Some(3), "inner branch one");
        assert_eq!(at(p, b"ACE", 0), Some(3), "inner branch two");
        assert_eq!(at(p, b"DE", 0), Some(2), "outer branch two");
        // `AE` takes the inner alternative, which requires a `42` or a `43`
        // after the `41`; the outer branch would need a `44` to start with.
        assert_eq!(at(p, b"AE", 0), None);
    }

    // -- negation ----------------------------------------------------------

    #[test]
    fn a_negated_byte_matches_anything_else() {
        assert_eq!(at("~41", b"B", 0), Some(1));
        assert_eq!(at("~41", b"A", 0), None);
    }

    #[test]
    fn a_negated_sequence_consumes_one_byte_not_the_sequence() {
        // `~ ( 41 42 )` is "not the start of `41 42`", and the byte it consumes
        // is the negation. Consuming both bytes would make the token's length
        // depend on what it matched, and would stop it matching a lone `41` at
        // the end of a buffer.
        assert_eq!(at("~ ( 41 42 )", b"AC", 0), Some(1), "`41` not followed by `42`");
        assert_eq!(at("~ ( 41 42 )", b"AB", 0), None, "the sequence itself");
        assert_eq!(at("~ ( 41 42 ) 43", b"AC", 0), Some(2));
    }

    // -- finding -----------------------------------------------------------

    #[test]
    fn every_occurrence_is_found_in_order() {
        assert_eq!(find("41 42", b"AB..AB"), vec![(0, 2), (4, 2)]);
    }

    #[test]
    fn overlapping_occurrences_are_found() {
        assert_eq!(find("41 41", b"AAA"), vec![(0, 2), (1, 2)]);
    }

    #[test]
    fn a_pattern_with_no_fixed_prefix_still_scans() {
        // The prefix search is an optimisation; correctness cannot depend on
        // it. A pattern starting with a wildcard has no prefix at all.
        assert_eq!(find("?? 42", b"AB"), vec![(0, 2)]);
        // Both offsets are genuine: a one-byte gap at 0, a two-byte one at 1.
        assert_eq!(find("[1-2] 42", b"A.B"), vec![(0, 3), (1, 2)]);
    }

    #[test]
    fn a_pattern_longer_than_the_buffer_is_skipped_entirely() {
        assert!(find("41 42 43 44 45", b"AB").is_empty());
    }

    #[test]
    fn a_match_ending_exactly_at_the_buffer_end_is_found() {
        assert_eq!(find("43 44", b"ABCD"), vec![(2, 2)]);
    }

    #[test]
    fn a_greedy_prefix_does_not_miss_a_later_match() {
        // The prefix search lands on the first `41`, where the rest of the
        // pattern fails; the scan must carry on to the second.
        assert_eq!(find("41 42", b"AAAB"), vec![(2, 2)]);
    }

    #[test]
    fn a_full_match_reports_its_own_length() {
        assert_eq!(find("41 [2-4] 42", b"A...B"), vec![(0, 5)]);
    }

    #[test]
    fn a_pattern_of_only_wildcards_finds_a_match_at_every_offset() {
        assert_eq!(find("?? ??", b"abc"), vec![(0, 2), (1, 2)]);
    }

    // -- limits ------------------------------------------------------------

    #[test]
    fn an_enormous_lower_jump_bound_is_refused() {
        // Built rather than parsed: the parser refuses this pattern first, with
        // an error about the language rather than about the engine. This is the
        // backstop for a pattern that never went past the parser.
        let pattern = HexPattern {
            tokens: vec![
                HexToken::Jump {
                    min: MAX_JUMP + 1,
                    max: None,
                },
                HexToken::Byte(0x41),
            ],
        };
        let err = Pattern::compile(&pattern).unwrap_err();
        assert!(err.contains("wider than"), "{err}");
    }

    #[test]
    fn the_parser_refuses_the_same_jump_before_the_matcher_sees_it() {
        // Pins that both checks use one constant, so they cannot drift apart
        // and leave a window where the parser accepts what the matcher will not
        // walk.
        let err = hex::parse("[2000000] 41").unwrap_err();
        assert!(err.message.contains("exceeds the maximum"), "{err}");
    }

    #[test]
    fn an_unbounded_upper_jump_bound_is_accepted() {
        // `[4-]` is legal and common; only the lower bound can make a single
        // step cost more than the buffer.
        assert!(Pattern::compile(&hex::parse("41 [4-] 42").unwrap()).is_ok());
    }

    #[test]
    fn an_oversized_jump_inside_an_alternative_is_refused_too() {
        // A jump nested in a branch is not on the top-level token list, so the
        // check has to recurse to find it.
        let pattern = HexPattern {
            tokens: vec![HexToken::Alternative(vec![
                vec![HexToken::Byte(0x41)],
                vec![
                    HexToken::Jump {
                        min: MAX_JUMP + 1,
                        max: None,
                    },
                    HexToken::Byte(0x42),
                ],
            ])],
        };
        let err = Pattern::compile(&pattern).unwrap_err();
        assert!(err.contains("wider than"), "{err}");
    }

    #[test]
    fn a_deeply_branching_pattern_runs_out_of_budget_rather_than_hanging() {
        // The shape that costs: forty alternatives, each of which can consume
        // one byte or two, followed by a byte the data never contains. Every
        // combination of choices matches locally and only fails at the very
        // end, so the walk has to come back and try all two to the fortieth of
        // them. A scanner handed this rule must stop and say so rather than
        // stop responding.
        //
        // Both branches have to be able to match for this to be expensive. A
        // pattern like `( 41 | 42 )` over a run of `41`s looks branching but is
        // not: the first branch always succeeds and the second always fails on
        // its first byte, so the walk is linear and the test would pass whether
        // or not the budget worked. The trailing `42` is what makes every path
        // fail, and it is the only reason any of them are revisited.
        let body = std::iter::repeat_n("( 41 | 41 41 )", 40)
            .chain(std::iter::once("42"))
            .collect::<Vec<_>>()
            .join(" ");
        let pattern = compile(&body);
        let data = vec![0x41u8; 64];
        let mut out = Vec::new();
        let completed = pattern.find_all(&data, &mut out);
        assert!(!completed, "the budget must have run out");
        assert!(out.is_empty(), "and the pattern does not match here");
    }

    #[test]
    fn an_ordinary_branching_pattern_does_not_run_out_of_budget() {
        // The other half of the guard: the budget must not be so tight that a
        // pattern a rule author would actually write trips it.
        let body = "( 41 | 42 ) ( 43 | 44 ) ( 45 | 46 ) ( 47 | 48 )";
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let mut out = Vec::new();
        assert!(compile(body).find_all(&data, &mut out));
    }
}
