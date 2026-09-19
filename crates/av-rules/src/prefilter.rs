//! Deciding which rules could possibly match, in one pass over the buffer.
//!
//! # The shape of the problem
//!
//! Ten thousand rules with about seven strings each is seventy thousand
//! searches per file. A scan that did that would take seconds per file, which
//! is three orders of magnitude away from what a resident scanner needs. The
//! prefilter is what closes the gap: every atom from every string in the rule
//! set goes into one Aho-Corasick automaton, one pass over the buffer finds all
//! of them at once, and only the rules those atoms point at are worth looking
//! at closely.
//!
//! # The one property that matters
//!
//! **The prefilter may return a rule that does not match. It must never omit a
//! rule that does.** Everything here is arranged around that asymmetry. An atom
//! is a byte sequence a match must contain, so its absence proves the string is
//! absent — but its presence proves nothing, and a rule selected on an atom
//! still has to be evaluated properly. A missed candidate is a missed
//! detection, and no amount of speed is worth one.
//!
//! # What "must contain" means for a whole string
//!
//! [`crate::atoms`] turns each string into a conjunction of disjunctions: every
//! group must be satisfied, and a group is satisfied by any one of its atoms.
//! A string with no groups — every form of it too short to have an atom —
//! constrains nothing, and a rule with such a string has to be let through
//! untested. Those rules are collected at build time into
//! [`Prefilter::unfiltered`], and how many there are is the honest measure of
//! how much the rule set can be filtered at all.
//!
//! # Two automata, and why
//!
//! Aho-Corasick folds case for all of its patterns or none of them, and a rule
//! set has both kinds. So there are two automatons and two passes over the
//! buffer — the second is not free, but the alternative is expanding each
//! case-insensitive atom into its two-to-the-n case variants, which for a
//! four-byte atom is sixteen times the states to save one pass over a buffer
//! that is already in cache.
//!
//! # Cost
//!
//! Building the automatons is the expensive part and happens once per rule
//! database, not once per file. The per-file state in [`PrefilterScratch`] is
//! stamped with an epoch rather than cleared, so a scan touches only what it
//! matched.
//!
//! Measured against the 10,764-rule set this engine is built for — 8,715 rules
//! that compile, 67,218 distinct atoms:
//!
//! ```text
//! 1 MiB of zeros    215 rules selected (2.47%)     47 MB/s
//! 1 MiB of text     230 rules selected (2.64%)    125 MB/s
//! 1 MiB random      234 rules selected (2.69%)     33 MB/s
//! ```
//!
//! Throughput is the weak half of that. It is not proportional to the number of
//! *matches*, which is near zero on the last two, but to the size of the
//! automaton: the transition tables spill out of cache and every byte of the
//! buffer pays for a miss. `examples/ac_bench.rs` measures the same effect in
//! isolation — 154 MB/s at a thousand patterns, 84 at ten thousand, 22 at
//! sixty-seven thousand.
//!
//! That is the range a signature engine of this kind lives in, so it is not
//! broken; it is the known next thing to fix if scanning turns out to be the
//! bottleneck. The path is a matcher specialised for fixed-length atoms rather
//! than a general automaton: bucket the atoms by their first two bytes and
//! verify the rest directly, which turns the per-byte cost from a cache miss
//! into a lookup in a table that fits in level 2. The automaton here would
//! remain the fallback for atoms that do not fit that shape.
//!
//! The other lever is fewer atoms. Scoring them by how rare they are across the
//! rule set — and across a corpus of benign files — rather than by their own
//! bytes, which is what [`crate::atoms::score`] does today, would cut the
//! automaton, and there is a second pass over the rule set that could do it.
//! Neither is worth building until something measures the end-to-end scan.

use std::collections::HashMap;
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use smallvec::SmallVec;

use crate::atoms::{Atom, StringAtoms};

/// What a prefilter was built from, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefilterStats {
    pub rules: usize,
    /// Distinct atoms across the whole rule set, after duplicates were merged.
    pub atoms: usize,
    pub case_insensitive_atoms: usize,
    /// Rules that have a string nothing can be said about, and so are evaluated
    /// on every file.
    pub unfiltered_rules: usize,
}

/// One rule's strings, as the prefilter needs them.
///
/// The order is the order the compiler assigned slots in, which nothing here
/// depends on but which makes a mismatch between the two easy to spot.
pub type RuleStrings = Vec<StringAtoms>;

/// Selects the rules worth evaluating against a buffer.
pub struct Prefilter {
    case_sensitive: Option<AhoCorasick>,
    case_insensitive: Option<AhoCorasick>,
    /// Automaton pattern index -> unified atom id, one table per automaton.
    sensitive_atom: Vec<u32>,
    insensitive_atom: Vec<u32>,
    /// Unified atom id -> the groups it satisfies. More than one when the same
    /// bytes appear in more than one rule, which is common — `kernel32.dll`
    /// alone is in hundreds.
    atom_groups: Vec<SmallVec<[u32; 1]>>,
    /// Group id -> the string it belongs to.
    group_string: Vec<u32>,
    /// String id -> how many groups must be satisfied before the rule is a
    /// candidate.
    string_group_count: Vec<u32>,
    /// String id -> the rule it belongs to.
    string_rule: Vec<u32>,
    /// Rules that some string with no groups makes unconditionally possible.
    unfiltered: Vec<u32>,
    stats: PrefilterStats,
}

/// Hand-written rather than derived, because the interesting thing about a
/// prefilter is its size and not its contents: a derived `Debug` would print
/// sixty-seven thousand atoms into whatever log it was reached from. The
/// automata are summarised by their pattern counts, which is the part that
/// decides how fast the thing runs.
impl fmt::Debug for Prefilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prefilter")
            .field("case_sensitive_patterns", &self.sensitive_atom.len())
            .field("case_insensitive_patterns", &self.insensitive_atom.len())
            .field("atoms", &self.atom_groups.len())
            .field("groups", &self.group_string.len())
            .field("strings", &self.string_group_count.len())
            .field("unfiltered", &self.unfiltered.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Prefilter {
    /// Build from every rule's strings.
    ///
    /// `rules[i][j]` is the atoms of string `j` of rule `i`; the string order
    /// must match the slots the rule's bytecode was compiled against, since a
    /// rule is reported by index.
    pub fn build(rules: &[RuleStrings]) -> Self {
        let mut atoms: Vec<Atom> = Vec::new();
        let mut atom_ids: HashMap<Atom, u32> = HashMap::new();
        let mut atom_groups: Vec<SmallVec<[u32; 1]>> = Vec::new();
        let mut group_string: Vec<u32> = Vec::new();
        let mut string_group_count: Vec<u32> = Vec::new();
        let mut string_rule: Vec<u32> = Vec::new();
        let mut unfiltered: Vec<u32> = Vec::new();

        for (rule, strings) in rules.iter().enumerate() {
            let rule = u32::try_from(rule).unwrap_or(u32::MAX);
            for string in strings {
                let string_id = string_group_count.len() as u32;
                string_rule.push(rule);
                string_group_count.push(string.groups.len() as u32);

                if string.groups.is_empty() {
                    // Nothing is known about this string, so the rule it
                    // belongs to cannot be ruled out on the strength of it. The
                    // whole rule has to be evaluated, which is slower and
                    // correct.
                    if unfiltered.last() != Some(&rule) {
                        unfiltered.push(rule);
                    }
                    continue;
                }

                for group in &string.groups {
                    let group_id = group_string.len() as u32;
                    group_string.push(string_id);
                    for atom in group {
                        let id = match atom_ids.get(atom) {
                            Some(id) => *id,
                            None => {
                                let id = atoms.len() as u32;
                                atoms.push(atom.clone());
                                atom_groups.push(SmallVec::new());
                                atom_ids.insert(atom.clone(), id);
                                id
                            }
                        };
                        atom_groups[id as usize].push(group_id);
                    }
                }
            }
        }

        // Split by case sensitivity, which is the one property the automaton
        // has to know about at build time.
        let mut sensitive_patterns: Vec<Vec<u8>> = Vec::new();
        let mut sensitive_atom: Vec<u32> = Vec::new();
        let mut insensitive_patterns: Vec<Vec<u8>> = Vec::new();
        let mut insensitive_atom: Vec<u32> = Vec::new();
        for (id, atom) in atoms.iter().enumerate() {
            let id = id as u32;
            let bytes = atom.bytes.to_vec();
            if atom.nocase {
                insensitive_patterns.push(bytes);
                insensitive_atom.push(id);
            } else {
                sensitive_patterns.push(bytes);
                sensitive_atom.push(id);
            }
        }

        let stats = PrefilterStats {
            rules: rules.len(),
            atoms: atoms.len(),
            case_insensitive_atoms: insensitive_patterns.len(),
            unfiltered_rules: unfiltered.len(),
        };

        Self {
            case_sensitive: build_automaton(&sensitive_patterns, false),
            case_insensitive: build_automaton(&insensitive_patterns, true),
            sensitive_atom,
            insensitive_atom,
            atom_groups,
            group_string,
            string_group_count,
            string_rule,
            unfiltered,
            stats,
        }
    }

    /// What this prefilter was built from.
    pub fn stats(&self) -> PrefilterStats {
        self.stats
    }

    /// A scratch buffer sized for this prefilter.
    pub fn scratch(&self) -> PrefilterScratch {
        PrefilterScratch::new(self)
    }

    /// Select every rule that could match `data`, appending to `out`.
    ///
    /// `out` is cleared first and left in ascending rule order, so that a scan
    /// reports the same thing whichever way the matches happened to arrive.
    /// Rules appear once each however many of their atoms matched.
    pub fn candidates(&self, data: &[u8], scratch: &mut PrefilterScratch, out: &mut Vec<u32>) {
        scratch.begin(self);
        out.clear();

        // The rules nothing can be said about come first and unconditionally.
        for rule in &self.unfiltered {
            scratch.report(*rule, out);
        }

        if let Some(ac) = &self.case_sensitive {
            self.select(ac, &self.sensitive_atom, data, scratch, out);
        }
        if let Some(ac) = &self.case_insensitive {
            self.select(ac, &self.insensitive_atom, data, scratch, out);
        }

        out.sort_unstable();
    }

    /// Run one automaton and turn its matches into satisfied groups.
    fn select(
        &self,
        ac: &AhoCorasick,
        atom_of_pattern: &[u32],
        data: &[u8],
        scratch: &mut PrefilterScratch,
        out: &mut Vec<u32>,
    ) {
        // `find_overlapping_iter`, not `find_iter`. Atoms from different rules
        // routinely overlap — `bcde` and `abcd` both occur in `abcde` — and
        // `find_iter` would report the first and skip the second, dropping the
        // rule that depends on it. That is a false negative, the one failure
        // this module exists to prevent, and it was this way until the test
        // below caught it. It requires `MatchKind::Standard`, which is what the
        // automatons are built with.
        for found in ac.find_overlapping_iter(data) {
            let atom = atom_of_pattern[found.pattern().as_usize()];
            if !scratch.visit_atom(atom) {
                continue;
            }
            for group in &self.atom_groups[atom as usize] {
                if scratch.satisfy_group(*group, &self.group_string, &self.string_group_count) {
                    let string = self.group_string[*group as usize];
                    scratch.report(self.string_rule[string as usize], out);
                }
            }
        }
    }
}

/// Build one automaton, or nothing if there is nothing to put in it.
///
/// An empty automaton is not a degenerate case worth supporting: it would be a
/// scan over every buffer that can never match, and `None` says the same thing
/// without the work.
fn build_automaton(patterns: &[Vec<u8>], ascii_case_insensitive: bool) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(ascii_case_insensitive)
        .build(patterns)
        .ok()
}

/// Per-file state, so that a scan allocates nothing.
///
/// Every table here is stamped with an epoch instead of being cleared. A scan
/// then costs the matches it found rather than the size of the rule set, which
/// matters because the rule set is the large number and the matches are the
/// small one. The vectors are grown once, when the scratch is made.
#[derive(Debug, Default)]
pub struct PrefilterScratch {
    epoch: u32,
    atom_seen: Vec<u32>,
    group_done: Vec<u32>,
    string_seen: Vec<u32>,
    string_left: Vec<u32>,
    rule_seen: Vec<u32>,
}

impl PrefilterScratch {
    fn new(prefilter: &Prefilter) -> Self {
        Self {
            epoch: 0,
            atom_seen: vec![0; prefilter.atom_groups.len()],
            group_done: vec![0; prefilter.group_string.len()],
            string_seen: vec![0; prefilter.string_group_count.len()],
            string_left: vec![0; prefilter.string_group_count.len()],
            rule_seen: vec![0; prefilter.stats.rules],
        }
    }

    /// Start a scan.
    ///
    /// A scratch made for one prefilter can be used with another as long as the
    /// tables are grown to fit; the alternative is a silent index-out-of-bounds
    /// or, worse, a silently wrong answer.
    fn begin(&mut self, prefilter: &Prefilter) {
        if self.atom_seen.len() < prefilter.atom_groups.len()
            || self.group_done.len() < prefilter.group_string.len()
            || self.string_seen.len() < prefilter.string_group_count.len()
            || self.rule_seen.len() < prefilter.stats.rules
        {
            let fresh = Self::new(prefilter);
            // Stamps from the other prefilter mean nothing here, so the epoch
            // restarts with them.
            *self = fresh;
        }
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            // Four billion files into a scan, start the stamps over. Reachable
            // only in a soak test, and cheap enough to be worth not thinking
            // about again.
            self.atom_seen.fill(0);
            self.group_done.fill(0);
            self.string_seen.fill(0);
            self.rule_seen.fill(0);
            self.epoch = 1;
        }
    }

    /// Note an atom as matched, returning whether this is the first time.
    fn visit_atom(&mut self, atom: u32) -> bool {
        let slot = &mut self.atom_seen[atom as usize];
        if *slot == self.epoch {
            return false;
        }
        *slot = self.epoch;
        true
    }

    /// Mark a group satisfied, returning whether this completed its string.
    ///
    /// A group is satisfied by any one of its atoms, so the first atom to
    /// arrive settles it and the rest are ignored. The string becomes possible
    /// exactly when its last outstanding group is settled, which is what the
    /// return value reports.
    fn satisfy_group(&mut self, group: u32, group_string: &[u32], counts: &[u32]) -> bool {
        let slot = &mut self.group_done[group as usize];
        if *slot == self.epoch {
            return false;
        }
        *slot = self.epoch;

        let string = group_string[group as usize] as usize;
        // The tally is set from the rule set the first time this scan reaches
        // the string, rather than for every string at the start of the scan.
        if self.string_seen[string] != self.epoch {
            self.string_seen[string] = self.epoch;
            self.string_left[string] = counts[string];
        }
        self.string_left[string] -= 1;
        self.string_left[string] == 0
    }

    /// Record a rule as a candidate, once.
    fn report(&mut self, rule: u32, out: &mut Vec<u32>) {
        let slot = &mut self.rule_seen[rule as usize];
        if *slot == self.epoch {
            return;
        }
        *slot = self.epoch;
        out.push(rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atoms::{best_atom, Atom};

    /// A string that requires `bytes`.
    fn one(bytes: &[u8]) -> StringAtoms {
        StringAtoms {
            groups: vec![vec![best_atom(bytes, false).expect("test atom must be long enough")]],
        }
    }

    /// A string that requires `bytes` case-insensitively.
    fn one_nocase(bytes: &[u8]) -> StringAtoms {
        StringAtoms {
            groups: vec![vec![best_atom(bytes, true).expect("test atom must be long enough")]],
        }
    }

    /// A string of which any one of `alternatives` must be present.
    fn any(alternatives: &[&[u8]]) -> StringAtoms {
        StringAtoms {
            groups: vec![alternatives
                .iter()
                .map(|bytes| best_atom(bytes, false).expect("test atom must be long enough"))
                .collect()],
        }
    }

    /// A string nothing can be said about.
    fn opaque() -> StringAtoms {
        StringAtoms::none()
    }

    fn scan(prefilter: &Prefilter, data: &[u8]) -> Vec<u32> {
        let mut scratch = prefilter.scratch();
        let mut out = Vec::new();
        prefilter.candidates(data, &mut scratch, &mut out);
        out
    }

    // -- the basic selection -----------------------------------------------

    #[test]
    fn a_rule_whose_atom_is_present_is_selected() {
        let p = Prefilter::build(&[vec![one(b"needle")]]);
        assert_eq!(scan(&p, b"a haystack with a needle in it"), vec![0]);
    }

    #[test]
    fn a_rule_whose_atom_is_absent_is_not_selected() {
        let p = Prefilter::build(&[vec![one(b"needle")]]);
        assert!(scan(&p, b"a haystack containing nothing").is_empty());
    }

    #[test]
    fn every_rule_that_matches_is_selected() {
        // The property the module exists to preserve, over a rule set big
        // enough that a mistake in the index tables would show up.
        //
        // The needles are four bytes each and differ in every position, so no
        // one of them contains another and the assertion can be exact. A family
        // of strings sharing a prefix — `marker00`, `marker01` — would all be
        // given the *same* atom, because the chooser in `atoms` scores a window
        // by its own bytes and has no idea that `mark` is the common part. That
        // is a real limitation, and the test below writes it down.
        let needles: Vec<Vec<u8>> = (0..64u8)
            .map(|i| vec![0x40 + i, 0xC0 + i, 0x20 + i, 0x80 + i])
            .collect();
        let rules: Vec<RuleStrings> = needles.iter().map(|n| vec![one(n)]).collect();
        let p = Prefilter::build(&rules);

        for (index, needle) in needles.iter().enumerate() {
            let mut file = b"padding ".to_vec();
            file.extend_from_slice(needle);
            file.extend_from_slice(b" more padding");
            let found = scan(&p, &file);
            assert_eq!(
                found,
                vec![index as u32],
                "rule {index} matches and must be selected"
            );
        }
    }

    #[test]
    fn strings_sharing_a_prefix_are_given_the_same_atom_and_all_selected() {
        // The limitation above, written down as a test so that it is a known
        // behaviour rather than a surprise. Sixty-four rules whose only
        // difference is at the end are all selected for any file containing the
        // prefix, so the prefilter saves nothing for them. The fix is to score
        // atoms by how *rare* they are across the rule set rather than by their
        // own bytes alone, which needs a second pass over the atoms and a
        // corpus to tune it against.
        let needles: Vec<Vec<u8>> = (0..8u8)
            .map(|i| format!("marker{i:02}").into_bytes())
            .collect();
        let rules: Vec<RuleStrings> = needles.iter().map(|n| vec![one(n)]).collect();
        let p = Prefilter::build(&rules);
        assert_eq!(p.stats().atoms, 1, "one atom, eight strings");
        assert_eq!(scan(&p, b"marker03"), (0..8).collect::<Vec<u32>>());
    }

    #[test]
    fn a_rule_is_reported_once_however_many_of_its_atoms_matched() {
        let atoms = StringAtoms {
            groups: vec![
                vec![best_atom(b"alpha", false).unwrap()],
                vec![best_atom(b"bravo", false).unwrap()],
            ],
        };
        let p = Prefilter::build(&[vec![atoms]]);
        assert_eq!(scan(&p, b"alpha bravo alpha bravo"), vec![0]);
    }

    #[test]
    fn every_group_of_a_string_must_be_satisfied() {
        // `{ 41 42 43 [4] 44 45 46 }` requires both runs. One of them alone is
        // not enough, and treating it as enough would select the rule for every
        // file containing `ABC` anywhere.
        let atoms = StringAtoms {
            groups: vec![
                vec![best_atom(b"ABC", false).unwrap()],
                vec![best_atom(b"DEF", false).unwrap()],
            ],
        };
        let p = Prefilter::build(&[vec![atoms]]);
        assert!(scan(&p, b"...ABC...").is_empty(), "only one of the two");
        assert_eq!(scan(&p, b"...ABC...DEF..."), vec![0]);
    }

    #[test]
    fn any_atom_of_a_group_is_enough() {
        // `xor(1-255)` is 255 alternatives in one group, and finding one of
        // them is finding the string.
        let p = Prefilter::build(&[vec![any(&[b"alpha", b"bravo", b"charlie"])]]);
        assert_eq!(scan(&p, b"xxcharliexx"), vec![0]);
        assert!(scan(&p, b"xxdeltaxx").is_empty());
    }

    #[test]
    fn overlapping_atoms_from_different_rules_are_both_reported() {
        // The false negative that a non-overlapping automaton would produce:
        // `abcde` contains both `abcd` and `bcde`, and an iterator that skipped
        // the second because it began inside the first would silently drop the
        // rule that depends on it.
        let p = Prefilter::build(&[vec![one(b"abcd")], vec![one(b"bcde")]]);
        assert_eq!(scan(&p, b"abcde"), vec![0, 1]);
    }

    #[test]
    fn one_rule_matching_many_times_is_still_one_candidate() {
        let p = Prefilter::build(&[vec![one(b"aaaaaaaa")]]);
        assert_eq!(scan(&p, b"aaaaaaaaaaaaaaaaaaaaaaaa"), vec![0]);
    }

    // -- case sensitivity --------------------------------------------------

    #[test]
    fn a_case_insensitive_atom_matches_either_case() {
        let p = Prefilter::build(&[vec![one_nocase(b"Kernel32")]]);
        assert_eq!(scan(&p, b"loading KERNEL32.DLL"), vec![0]);
        assert_eq!(scan(&p, b"loading kernel32.dll"), vec![0]);
        assert_eq!(scan(&p, b"loading KeRnEl32.DlL"), vec![0]);
    }

    #[test]
    fn a_case_sensitive_atom_does_not() {
        let p = Prefilter::build(&[vec![one(b"Kernel32")]]);
        assert_eq!(scan(&p, b"loading Kernel32.DLL"), vec![0]);
        assert!(scan(&p, b"loading KERNEL32.DLL").is_empty());
    }

    #[test]
    fn both_kinds_of_atom_are_found_in_one_scan() {
        let p = Prefilter::build(&[vec![one(b"exact")], vec![one_nocase(b"loose")]]);
        assert_eq!(scan(&p, b"EXACT loose"), vec![1], "only the loose one");
        assert_eq!(scan(&p, b"exact loose"), vec![0, 1]);
    }

    // -- rules that cannot be filtered -------------------------------------

    #[test]
    fn a_rule_with_an_opaque_string_is_always_selected() {
        // `{ ?? ?? ?? ?? }` says nothing about the bytes, so there is no
        // evidence that could rule its rule out, and it has to be evaluated
        // against every file.
        let p = Prefilter::build(&[vec![opaque()]]);
        assert_eq!(scan(&p, b""), vec![0]);
        assert_eq!(scan(&p, b"anything at all"), vec![0]);
        assert_eq!(p.stats().unfiltered_rules, 1);
    }

    #[test]
    fn one_opaque_string_makes_its_whole_rule_unfilterable() {
        // The safe direction. The other string's atom is a real constraint on
        // that string, but nothing says the rule needs that string.
        let p = Prefilter::build(&[vec![opaque(), one(b"needle")]]);
        assert_eq!(scan(&p, b"nothing relevant here"), vec![0]);
        assert_eq!(p.stats().unfiltered_rules, 1);
    }

    #[test]
    fn a_rule_whose_strings_are_all_usable_is_filterable() {
        let p = Prefilter::build(&[vec![one(b"alpha"), one(b"bravo")]]);
        assert!(scan(&p, b"nothing relevant here").is_empty());
        assert_eq!(p.stats().unfiltered_rules, 0);
    }

    // -- the scratch -------------------------------------------------------

    #[test]
    fn one_scratch_can_be_reused_across_files() {
        // Stamps rather than clears: if a scan left state behind, the second
        // file would inherit the first one's matches.
        let p = Prefilter::build(&[vec![one(b"alpha")], vec![one(b"bravo")]]);
        let mut scratch = p.scratch();
        let mut out = Vec::new();

        p.candidates(b"alpha", &mut scratch, &mut out);
        assert_eq!(out, vec![0]);
        p.candidates(b"bravo", &mut scratch, &mut out);
        assert_eq!(out, vec![1], "the first file's match must not survive");
        p.candidates(b"neither", &mut scratch, &mut out);
        assert!(out.is_empty());
        p.candidates(b"both alpha and bravo", &mut scratch, &mut out);
        assert_eq!(out, vec![0, 1]);
    }

    #[test]
    fn the_output_is_in_rule_order_whatever_order_the_matches_arrive() {
        // `bravo` comes first in the buffer and `alpha` is the lower rule
        // index, so an unsorted result would be the other way round.
        let p = Prefilter::build(&[vec![one(b"alpha")], vec![one(b"bravo")]]);
        assert_eq!(scan(&p, b"bravo then alpha"), vec![0, 1]);
    }

    #[test]
    fn a_scratch_from_another_prefilter_is_rebuilt_rather_than_misread() {
        // Reusing a small scratch with a larger prefilter would index out of
        // bounds, and the failure would be a panic at best and a wrong answer
        // at worst.
        let small = Prefilter::build(&[vec![one(b"alpha")]]);
        let large = Prefilter::build(&[
            vec![one(b"alpha")],
            vec![one(b"bravo")],
            vec![one(b"charlie")],
        ]);
        let mut scratch = small.scratch();
        let mut out = Vec::new();
        large.candidates(b"bravo and charlie", &mut scratch, &mut out);
        assert_eq!(out, vec![1, 2]);
    }

    // -- building ----------------------------------------------------------

    #[test]
    fn the_same_atom_in_two_rules_is_one_automaton_entry() {
        // `kernel32.dll` is in hundreds of rules; compiling it hundreds of
        // times would multiply the automaton for nothing.
        let p = Prefilter::build(&[
            vec![one(b"kernel32.dll")],
            vec![one(b"kernel32.dll")],
            vec![one(b"kernel32.dll")],
        ]);
        assert_eq!(p.stats().atoms, 1);
        assert_eq!(scan(&p, b"kernel32.dll"), vec![0, 1, 2]);
    }

    #[test]
    fn the_stats_count_what_was_built() {
        let p = Prefilter::build(&[
            vec![one(b"alpha"), one_nocase(b"bravo")],
            vec![one(b"alpha")],
            vec![opaque()],
        ]);
        let stats = p.stats();
        assert_eq!(stats.rules, 3);
        assert_eq!(stats.atoms, 2, "alpha and bravo, deduplicated");
        assert_eq!(stats.case_insensitive_atoms, 1);
        assert_eq!(stats.unfiltered_rules, 1);
    }

    #[test]
    fn an_empty_rule_set_selects_nothing_and_scans_nothing() {
        let p = Prefilter::build(&[]);
        assert_eq!(scan(&p, b"anything"), Vec::<u32>::new());
        assert_eq!(p.stats().atoms, 0);
    }

    #[test]
    fn a_rule_with_no_strings_at_all_selects_nothing() {
        let p = Prefilter::build(&[vec![]]);
        assert!(scan(&p, b"anything").is_empty());
    }

    #[test]
    fn an_empty_buffer_selects_only_the_unfilterable() {
        let p = Prefilter::build(&[vec![one(b"alpha")], vec![opaque()]]);
        assert_eq!(scan(&p, b""), vec![1]);
    }

    /// The atoms a real rule would produce, end to end through the matcher.
    #[test]
    fn atoms_come_from_the_matcher_and_select_the_right_rule() {
        let file = crate::parser::parse_file(
            r#"
            rule alpha_rule { strings: $a = "alpha" condition: $a }
            rule bravo_rule { strings: $a = { 62 72 61 76 6F } condition: $a }
            rule charlie_rule { strings: $a = /charlie/ condition: $a }
            "#,
        )
        .expect("test source must parse");

        let rules: Vec<RuleStrings> = file
            .rules
            .iter()
            .map(|rule| {
                rule.strings
                    .iter()
                    .enumerate()
                    .map(|(slot, def)| {
                        crate::matcher::compile(def, slot as u32)
                            .expect("test string must compile")
                            .atoms()
                    })
                    .collect()
            })
            .collect();

        let p = Prefilter::build(&rules);
        assert_eq!(scan(&p, b"xx alphaxx"), vec![0]);
        assert_eq!(scan(&p, b"xx bravoxx"), vec![1]);
        assert_eq!(scan(&p, b"xx charliexx"), vec![2]);
        assert!(scan(&p, b"xx deltaxx").is_empty());
    }

    /// An atom can only ever be a necessary condition, never a sufficient one.
    #[test]
    fn a_selected_rule_may_still_not_match() {
        let p = Prefilter::build(&[vec![one(b"needle")]]);
        // The atom is present, so the rule is a candidate — and a file that
        // contains the atom but fails the rule's other strings still has to be
        // evaluated, which is what the scanner does next.
        assert_eq!(scan(&p, b"a needle in a haystack"), vec![0]);
    }

    /// The types are re-exported where the scanner will want them.
    #[test]
    fn an_atom_is_hashable_so_duplicates_merge() {
        let a = Atom::new(b"abcd", false).unwrap();
        let b = Atom::new(b"abcd", false).unwrap();
        let c = Atom::new(b"abcd", true).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "case sensitivity is part of an atom's identity");
    }
}
