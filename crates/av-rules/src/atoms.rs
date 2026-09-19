//! The bytes that must be present for a string to match.
//!
//! # Why this exists
//!
//! A scanner has ten thousand rules and about seven strings each — some
//! seventy-seven thousand searches per file if every rule is tried. That is
//! three orders of magnitude too slow to run on every write to disk, so the
//! rules that cannot possibly match have to be eliminated before any of them
//! are searched for.
//!
//! The elimination is sound only one way round. An *atom* is a short byte
//! sequence that any match of the string must contain, so its absence proves
//! the string is absent — but its presence proves nothing. That asymmetry is
//! the whole design: the prefilter may let a rule through that does not match,
//! and must never reject a rule that does. False positives cost a little time;
//! false negatives cost a detection, which is the failure a user cannot
//! forgive.
//!
//! # Groups
//!
//! A string rarely has one atom. `{ 41 42 43 [4] 44 45 46 }` requires both
//! `ABC` and `DEF`, and `"a" xor(1-255)` may be any of 255 different
//! sequences. So a string's atoms are a conjunction of disjunctions: every
//! *group* must be satisfied, and a group is satisfied by any one of its atoms.
//! `AND` of `OR`s, which is exactly what "must be present" means once a string
//! has alternatives in it.
//!
//! # Where the subtle mistakes live
//!
//! A string expands into variants — the ASCII form, the UTF-16 form, each XOR
//! key, each base64 alignment — and those are *alternatives*, so they belong in
//! one group. The trap is that a variant may be too short to yield an atom, and
//! then the group is no longer a necessary condition: the file might contain
//! the short variant and none of the others, and a prefilter that demanded one
//! of the long variants' atoms would reject a rule that matches. So a group
//! built from variants is used only when *every* variant contributed an atom,
//! and otherwise the string yields no groups at all — it is simply not
//! filtered, which is slower and correct. `"ab" wide ascii` is the smallest
//! case: the wide form is four bytes and yields an atom, the ASCII form is two
//! and does not.
//!
//! # What is not here yet
//!
//! The score below is a judgement about which bytes are distinctive, not a
//! measurement. Tuning it properly means scoring candidate atoms against a
//! corpus of benign files and preferring the ones that occur least often — a
//! set of engine internals like `kernel32.dll` is common, and a fragment of a
//! Windows path is not. There is no corpus yet, so the constants stay honest
//! heuristics rather than pretending to be data.

use smallvec::SmallVec;

use crate::ast::HexToken;

/// Shortest atom worth searching for.
///
/// Two bytes is not enough at this scale. There are 65,536 of them, and a rule
/// set with seventy thousand strings would fill most of that space, so a file
/// of any size would hit nearly every atom in the database and select nearly
/// every rule. Three bytes gives 16 million possibilities, which is thin but
/// usable; four gives 4 billion, which is where the filter starts doing real
/// work.
pub const MIN_ATOM_LEN: usize = 3;

/// Longest atom worth searching for. Beyond about four bytes the extra
/// discrimination stops paying for the larger automaton, which is the same
/// trade-off YARA makes at the same number.
pub const MAX_ATOM_LEN: usize = 4;

/// A short byte sequence a match must contain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Atom {
    pub bytes: SmallVec<[u8; MAX_ATOM_LEN]>,
    /// The bytes must be matched case-insensitively. Carried on the atom
    /// because it decides which automaton the atom is compiled into.
    pub nocase: bool,
}

impl Atom {
    /// Build an atom from bytes that are already the right length.
    ///
    /// A caller that has not been through [`best_atom`] has to respect the
    /// length bounds itself; anything longer is truncated rather than rejected,
    /// because a truncated atom is still a necessary condition and rejecting
    /// would silently drop the whole string out of the filter.
    pub fn new(bytes: &[u8], nocase: bool) -> Option<Self> {
        if bytes.len() < MIN_ATOM_LEN {
            return None;
        }
        Some(Self {
            bytes: SmallVec::from_slice(&bytes[..bytes.len().min(MAX_ATOM_LEN)]),
            nocase,
        })
    }
}

/// Atoms of which at least one must be present.
pub type AtomGroup = Vec<Atom>;

/// What a string guarantees about the bytes of a file that matches it.
///
/// Empty means the string guarantees nothing — every one of its variants is too
/// short or too vague to have an atom — and a string like that cannot be
/// filtered at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringAtoms {
    pub groups: Vec<AtomGroup>,
}

impl StringAtoms {
    /// A string that guarantees nothing.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether this string imposes no constraint.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// How much an atom narrows a search; higher is better.
///
/// Two things make an atom useful: its length, and how varied its bytes are.
/// Length is the number of bits it can pin down, and variety corrects for the
/// fact that those bits are not independent in a real file — `\0\0\0\0` and
/// `\xFF\xFF\xFF\xFF` occur in nearly every binary, so an atom made of them
/// matches almost everything and filters almost nothing. A case-insensitive
/// atom gives up one bit per letter, because each of those bytes matches two
/// values.
///
/// The weights are a judgement rather than a measurement; see the module
/// documentation.
pub fn score(bytes: &[u8], nocase: bool) -> u32 {
    let mut seen = [false; 256];
    let mut distinct = 0u32;
    let mut letters = 0u32;
    for byte in bytes {
        if !seen[*byte as usize] {
            seen[*byte as usize] = true;
            distinct += 1;
        }
        if nocase && byte.is_ascii_alphabetic() {
            letters += 1;
        }
    }

    let bits = (bytes.len() as u32 * 8).saturating_sub(letters);
    // Steep rather than gradual, because the difference between an atom made of
    // one repeated byte and one made of two is the difference between an atom
    // that fires on every file and one that does not.
    let penalty = match distinct {
        1 => 96,
        2 => 24,
        _ => 0,
    };
    (bits * 8 + distinct).saturating_sub(penalty)
}

/// The best atom a fixed run of bytes guarantees.
///
/// Every window of a fixed run is equally mandatory, so with the run longer
/// than an atom the choice is purely about which window is least likely to
/// occur by accident. Returns `None` when the run is too short to yield one,
/// which is the caller's signal that this run cannot contribute.
pub fn best_atom(run: &[u8], nocase: bool) -> Option<Atom> {
    if run.len() < MIN_ATOM_LEN {
        return None;
    }
    if run.len() <= MAX_ATOM_LEN {
        return Atom::new(run, nocase);
    }
    (0..=run.len() - MAX_ATOM_LEN)
        .map(|start| &run[start..start + MAX_ATOM_LEN])
        // The earliest of equally good windows, so that the choice is
        // reproducible rather than dependent on iteration order.
        .min_by_key(|window| std::cmp::Reverse(score(window, nocase)))
        .and_then(|window| Atom::new(window, nocase))
}

/// Turn fixed, mandatory runs into the groups they imply.
///
/// Each run is a separate group, so the runs are required together — which is
/// correct, because everything this function is handed is something a match
/// must contain.
pub fn groups_from_runs(runs: &[Vec<u8>], nocase: bool) -> StringAtoms {
    let groups = runs
        .iter()
        .filter_map(|run| best_atom(run, nocase).map(|atom| vec![atom]))
        .collect();
    StringAtoms { groups }
}

/// Turn a string's variants into the single group they imply.
///
/// The variants are alternatives, so one group of many atoms is the right
/// shape. It is returned only when *every* variant yielded an atom: a variant
/// too short to have one could be the form the file actually contains, and a
/// group that omitted it would be a condition the string does not have to
/// satisfy. See the module documentation.
pub fn group_from_variants(variants: &[(&[u8], bool)]) -> StringAtoms {
    let mut group = AtomGroup::with_capacity(variants.len());
    for (bytes, nocase) in variants {
        match best_atom(bytes, *nocase) {
            Some(atom) => group.push(atom),
            // One variant without an atom makes the whole group unsound, and
            // there is nothing better to fall back on: the remaining atoms
            // would be a requirement the string does not have.
            None => return StringAtoms::none(),
        }
    }
    if group.is_empty() {
        return StringAtoms::none();
    }
    group.sort();
    group.dedup();
    StringAtoms { groups: vec![group] }
}

/// The fixed byte runs a hex pattern must contain.
///
/// A run is a maximal sequence of fully determined bytes. A wildcard byte or a
/// half-known nibble breaks one, since neither names a byte. A jump breaks one
/// too, but only in the sense that the bytes stop being adjacent — the bytes on
/// each side are still both required, and this function asks about presence,
/// not adjacency, so they come back as two runs and both are kept.
///
/// An alternative contributes only what every branch agrees on, because a byte
/// one branch requires and another does not is not required at all. A negated
/// branch contributes nothing, for the same reason inverted: the bytes it names
/// are exactly the ones that must not be there.
pub fn runs_of_hex(tokens: &[HexToken]) -> Vec<Vec<u8>> {
    let mut runs = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for token in tokens {
        match token {
            HexToken::Byte(byte) => current.push(*byte),
            HexToken::Nibble { .. } | HexToken::Jump { .. } | HexToken::Not(_) => {
                flush(&mut current, &mut runs);
            }
            HexToken::Alternative(branches) => {
                let per_branch: Vec<Vec<Vec<u8>>> =
                    branches.iter().map(|branch| runs_of_hex(branch)).collect();
                let mut shared = shared_runs(&per_branch);
                // The first shared run sits at the start of every branch, so it
                // continues the run that precedes the alternative rather than
                // replacing it: `41 ( 42 43 44 | 42 43 45 )` requires `ABC` as
                // one unbroken sequence, and flushing the `41` into a run of
                // its own would leave a one-byte run that no atom can use.
                if let Some(head) = shared.first() {
                    current.extend_from_slice(head);
                }
                let rest = if shared.is_empty() {
                    shared
                } else {
                    shared.split_off(1)
                };
                flush(&mut current, &mut runs);
                runs.extend(rest);
            }
        }
    }
    flush(&mut current, &mut runs);
    runs
}

/// The fixed byte runs a regular expression must contain.
///
/// The same algebra as [`runs_of_hex`] over a different tree. `regex` hands
/// back a compiled matcher with this structure folded away, so the pattern is
/// parsed a second time purely to ask this question.
pub fn runs_of_regex(hir: &regex_syntax::hir::Hir) -> Vec<Vec<u8>> {
    use regex_syntax::hir::HirKind;

    match hir.kind() {
        HirKind::Literal(literal) => {
            if literal.0.is_empty() {
                Vec::new()
            } else {
                vec![literal.0.to_vec()]
            }
        }
        // A character class is a set, and a set of more than one byte fixes
        // nothing. A class of exactly one byte would be a literal, which is how
        // the parser hands it over.
        HirKind::Class(_) => Vec::new(),
        // The pattern that matches the empty string, which names no byte.
        HirKind::Empty => Vec::new(),
        // `^`, `\b` and friends constrain position, not content.
        HirKind::Look(_) => Vec::new(),
        // `x{0,3}` may not be there at all, so nothing inside it is required.
        // `x{2,}` matches the sub at least twice, so everything inside is.
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                Vec::new()
            } else {
                runs_of_regex(&repetition.sub)
            }
        }
        HirKind::Capture(capture) => runs_of_regex(&capture.sub),
        HirKind::Concat(parts) => parts.iter().flat_map(runs_of_regex).collect(),
        HirKind::Alternation(alternatives) => {
            let per_branch: Vec<Vec<Vec<u8>>> =
                alternatives.iter().map(runs_of_regex).collect();
            shared_runs(&per_branch)
        }
    }
}

/// Push the accumulated run, if it is long enough to matter.
fn flush(current: &mut Vec<u8>, runs: &mut Vec<Vec<u8>>) {
    if !current.is_empty() {
        runs.push(std::mem::take(current));
    }
}

/// The prefixes every branch has in common.
///
/// Used for both alternatives and character-level branching, which is why it
/// works on byte runs rather than on the syntax tree. For each run of the first
/// branch, the longest prefix that every other branch has *some* run sharing is
/// a prefix of a required byte sequence in each of them, and so is required by
/// the whole.
///
/// Runs come back at whatever length they are shared, including lengths too
/// short to be an atom on their own. That is deliberate: a short shared run is
/// useless as an atom but perfectly useful as the continuation of a run that
/// precedes it, and only the caller knows which case it has.
fn shared_runs(branches: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
    let Some((first, rest)) = branches.split_first() else {
        return Vec::new();
    };
    let mut shared = Vec::new();
    for run in first {
        let mut length = run.len();
        for other in rest {
            // The branches need not agree on *where* the prefix sits — a run
            // that follows a jump may be at any offset — so this is the best
            // match over the branch's runs rather than a positional one.
            let best = other
                .iter()
                .map(|candidate| common_prefix(run, candidate))
                .max()
                .unwrap_or(0);
            length = length.min(best);
            if length == 0 {
                break;
            }
        }
        if length == 0 {
            // Nothing of this run is shared, and the runs after it are not
            // necessarily shared either — but they are still worth reporting,
            // so the loop continues rather than stopping.
            continue;
        }
        shared.push(run[..length.min(MAX_ATOM_LEN)].to_vec());
    }
    shared
}

/// How many leading bytes two runs share.
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn tokens(body: &str) -> Vec<HexToken> {
        hex::parse(body).expect("test pattern must parse").tokens
    }

    fn groups_of(body: &str) -> StringAtoms {
        groups_from_runs(&runs_of_hex(&tokens(body)), false)
    }

    // -- scoring -----------------------------------------------------------

    #[test]
    fn a_longer_atom_scores_above_a_shorter_one_of_the_same_variety() {
        assert!(score(b"ABCD", false) > score(b"ABC", false));
    }

    #[test]
    fn a_repeated_byte_scores_far_below_a_varied_one_of_the_same_length() {
        // The whole point of the correction: `\0\0\0\0` is in every padded
        // binary, so it filters nothing even though it is four bytes long.
        let zeros = score(b"\0\0\0\0", false);
        let varied = score(b"\x4D\x5A\x90\x00", false);
        assert!(varied > zeros, "{varied} should beat {zeros}");
        // And it must lose to a shorter but varied atom too, or the correction
        // is not doing anything at the length where it matters.
        assert!(score(b"\x4D\x5A\x90", false) > zeros);
    }

    #[test]
    fn a_case_insensitive_atom_scores_below_the_same_atom_case_sensitively() {
        assert!(score(b"ABCD", true) < score(b"ABCD", false));
        // Only letters give up a bit; digits and punctuation do not.
        assert_eq!(score(b"1234", true), score(b"1234", false));
    }

    // -- choosing a window -------------------------------------------------

    #[test]
    fn a_short_run_is_its_own_atom() {
        assert_eq!(best_atom(b"abcd", false).unwrap().bytes.as_slice(), b"abcd");
    }

    #[test]
    fn a_run_shorter_than_the_minimum_yields_nothing() {
        assert!(best_atom(b"ab", false).is_none());
        assert!(best_atom(b"", false).is_none());
    }

    #[test]
    fn a_long_run_yields_a_window_of_at_most_four_bytes() {
        let atom = best_atom(b"Content-Type: text/html", false).unwrap();
        assert_eq!(atom.bytes.len(), MAX_ATOM_LEN);
        // And the window is somewhere inside the run, not a truncation of it.
        assert!(
            b"Content-Type: text/html"
                .windows(MAX_ATOM_LEN)
                .any(|w| w == atom.bytes.as_slice()),
            "{atom:?}"
        );
    }

    #[test]
    fn a_long_run_of_one_repeated_byte_still_yields_an_atom() {
        // `{ 41 41 41 41 41 }` is a real pattern, and a poor atom is better
        // than none — the alternative is a rule nothing can filter.
        let atom = best_atom(b"AAAAA", false).unwrap();
        assert_eq!(atom.bytes.as_slice(), b"AAAA");
    }

    // -- hex runs ----------------------------------------------------------

    #[test]
    fn an_exact_pattern_is_one_run() {
        assert_eq!(runs_of_hex(&tokens("41 42 43 44")), vec![b"ABCD".to_vec()]);
    }

    #[test]
    fn a_wildcard_breaks_a_run_without_discarding_either_side() {
        let runs = runs_of_hex(&tokens("41 42 ?? 43 44"));
        assert_eq!(runs, vec![b"AB".to_vec(), b"CD".to_vec()]);
    }

    #[test]
    fn a_half_known_nibble_breaks_a_run() {
        assert_eq!(
            runs_of_hex(&tokens("41 42 4? 43 44")),
            vec![b"AB".to_vec(), b"CD".to_vec()]
        );
    }

    #[test]
    fn a_jump_splits_a_run_but_keeps_both_halves() {
        // Presence, not adjacency. Both `ABCD` and `EFGH` have to be in the
        // file for the pattern to match, wherever the jump puts them.
        let runs = runs_of_hex(&tokens("41 42 43 44 [4-8] 45 46 47 48"));
        assert_eq!(runs, vec![b"ABCD".to_vec(), b"EFGH".to_vec()]);
    }

    #[test]
    fn an_unbounded_jump_also_keeps_both_halves() {
        let runs = runs_of_hex(&tokens("41 42 43 44 [4-] 45 46 47 48"));
        assert_eq!(runs, vec![b"ABCD".to_vec(), b"EFGH".to_vec()]);
    }

    #[test]
    fn a_negated_branch_contributes_nothing_but_does_not_hide_the_rest() {
        // `~( 41 42 )` means those bytes must *not* be there, so they are the
        // opposite of an atom; the run after it is still required.
        let runs = runs_of_hex(&tokens("~ ( 41 42 ) 43 44 45"));
        assert_eq!(runs, vec![b"CDE".to_vec()]);
    }

    #[test]
    fn an_alternative_contributes_only_its_branches_common_prefix() {
        let runs = runs_of_hex(&tokens("( 41 42 43 44 | 41 42 43 45 )"));
        assert_eq!(runs, vec![b"ABC".to_vec()]);
    }

    #[test]
    fn an_alternative_with_nothing_in_common_contributes_nothing() {
        assert!(runs_of_hex(&tokens("( 41 42 43 | 44 45 46 )")).is_empty());
    }

    #[test]
    fn a_shared_prefix_continues_the_run_before_the_alternative() {
        // `41 ( 42 43 44 | 42 43 45 )` requires `AB` and then `C`, and every
        // branch puts them next to each other — so `ABC` is one unbroken run.
        // Treating the `41` as a run of its own would leave a one-byte run that
        // no atom can use, and lose the three-byte atom that is right there.
        let runs = runs_of_hex(&tokens("41 ( 42 43 44 | 42 43 45 )"));
        assert_eq!(runs, vec![b"ABC".to_vec()]);
    }

    #[test]
    fn a_shared_prefix_too_short_to_use_is_still_kept_as_a_run() {
        // Two bytes is not an atom, but it is a fact about the pattern and
        // discarding it here would make the decision in the wrong place.
        let runs = runs_of_hex(&tokens("( 41 42 | 41 43 )"));
        assert_eq!(runs, vec![b"A".to_vec()]);
        // Which the group builder then declines to use.
        assert!(groups_of("( 41 42 | 41 43 )").is_empty());
    }

    #[test]
    fn a_run_after_an_alternative_is_still_required() {
        // The alternative contributes what it can, and the run that follows is
        // required whatever the alternative chose.
        let runs = runs_of_hex(&tokens("( 41 | 42 ) 43 44 45"));
        assert_eq!(runs, vec![b"CDE".to_vec()]);
    }

    #[test]
    fn nested_alternatives_are_resolved_to_what_all_branches_share() {
        // The inner alternative contributes `BC` to the `A` before it, so the
        // outer one sees `ABC` on one side and `ABCF` on the other, and `ABC`
        // is what both require.
        let runs = runs_of_hex(&tokens("( 41 ( 42 43 44 | 42 43 45 ) | 41 42 43 46 )"));
        assert_eq!(runs, vec![b"ABC".to_vec()]);
    }

    #[test]
    fn a_shared_run_of_two_bytes_is_reported_but_not_usable() {
        // Both branches require `AB`, and the third byte differs, so the run is
        // two bytes: a true statement about the pattern and not something the
        // prefilter can key an automaton on.
        let runs = runs_of_hex(&tokens("( 41 42 ( 43 | 44 ) | 41 42 45 )"));
        assert_eq!(runs, vec![b"AB".to_vec()]);
        assert!(groups_of("( 41 42 ( 43 | 44 ) | 41 42 45 )").is_empty());
    }

    // -- groups ------------------------------------------------------------

    #[test]
    fn each_required_run_becomes_its_own_group() {
        // Two runs means two groups: both must be present, which is a stronger
        // and more useful statement than either one alone.
        let atoms = groups_of("41 42 43 [4] 44 45 46");
        assert_eq!(atoms.groups.len(), 2);
        assert_eq!(atoms.groups[0][0].bytes.as_slice(), b"ABC");
        assert_eq!(atoms.groups[1][0].bytes.as_slice(), b"DEF");
    }

    #[test]
    fn a_pattern_with_no_usable_run_yields_no_groups() {
        assert!(groups_of("?? ?? ?? ?? ?? ?? ?? ?? ?? ??").is_empty());
    }

    #[test]
    fn a_run_too_short_to_use_is_dropped_rather_than_weakened() {
        // `{ 41 [4] 42 }` requires `41` and `42`, both of which are single
        // bytes — true, useless, and not worth an automaton keyed on one byte.
        assert!(groups_of("41 [4] 42").is_empty());
    }

    // -- variants ----------------------------------------------------------

    #[test]
    fn variants_become_one_group_of_alternatives() {
        let atoms = group_from_variants(&[(b"hello", false), (b"h\0e\0l\0l\0o\0", false)]);
        assert_eq!(atoms.groups.len(), 1);
        assert_eq!(atoms.groups[0].len(), 2, "one atom per variant");
    }

    #[test]
    fn a_variant_too_short_to_have_an_atom_voids_the_whole_group() {
        // The case that makes this sound. `"ab" wide ascii` expands to a
        // two-byte ASCII form and a four-byte UTF-16 form; only the second has
        // an atom. Keeping it would require the file to contain the UTF-16
        // spelling, and a file holding only the ASCII spelling would be
        // rejected by the prefilter before anything looked at it.
        assert!(group_from_variants(&[(b"ab", false), (b"a\0b\0", false)]).is_empty());
    }

    #[test]
    fn duplicate_variants_collapse_to_one_atom() {
        // `xor(0-0)` is `xor` with a single key, and the variant it produces is
        // the plaintext — one atom, not two.
        let atoms = group_from_variants(&[(b"hello", false), (b"hello", false)]);
        assert_eq!(atoms.groups[0].len(), 1);
    }

    #[test]
    fn no_variants_at_all_yields_no_groups() {
        assert!(group_from_variants(&[]).is_empty());
    }

    // -- regex runs --------------------------------------------------------

    fn regex_runs(body: &str) -> Vec<Vec<u8>> {
        // The same settings `regex::bytes::RegexBuilder` uses, so the tree
        // walked here is the tree the matcher was built from. `utf8(false)` is
        // part of that: without it `\d` is rejected, because a non-Unicode
        // class can match bytes that are not valid UTF-8 and the Unicode API
        // will not have it.
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(body)
            .expect("test regex must parse");
        runs_of_regex(&hir)
    }

    #[test]
    fn a_plain_regex_is_one_run() {
        assert_eq!(regex_runs("abcd"), vec![b"abcd".to_vec()]);
    }

    #[test]
    fn a_regex_concatenation_requires_every_part() {
        assert_eq!(
            regex_runs("abc.*def"),
            vec![b"abc".to_vec(), b"def".to_vec()]
        );
    }

    #[test]
    fn an_optional_regex_part_requires_nothing() {
        assert!(regex_runs("abc(xyz)?").contains(&b"abc".to_vec()));
        assert!(!regex_runs("abc(xyz)?").contains(&b"xyz".to_vec()));
    }

    #[test]
    fn a_repeated_regex_part_still_requires_its_contents() {
        // `x{2,}` matches `x` at least twice, so the `x` is not optional.
        assert_eq!(regex_runs("(abc){2,}"), vec![b"abc".to_vec()]);
        // `x{0,2}` may match nothing at all.
        assert!(regex_runs("(abc){0,2}").is_empty());
    }

    #[test]
    fn a_regex_alternative_keeps_what_the_branches_share() {
        assert_eq!(regex_runs("(abcdef|abcdxy)"), vec![b"abcd".to_vec()]);
    }

    #[test]
    fn a_regex_class_requires_nothing() {
        assert!(regex_runs("[a-z][0-9]").is_empty());
    }

    #[test]
    fn a_regex_anchor_requires_nothing_but_does_not_hide_the_rest() {
        assert_eq!(regex_runs("^abcd$"), vec![b"abcd".to_vec()]);
    }

    #[test]
    fn a_regex_that_is_only_classes_yields_nothing() {
        assert!(regex_runs(".*\\d+.*").is_empty());
    }
}
