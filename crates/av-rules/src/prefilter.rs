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
//! # What "must contain" means for a whole rule
//!
//! Atoms say what a *string* must contain. Whether a rule can be dropped when a
//! string is absent is a question about the *condition*, and it is the one that
//! decides whether this module is useful on real files.
//!
//! Read the rule-level test as "some string might be present" and the filter
//! collapses: a rule with seven indicator strings survives whenever any one of
//! them is a common byte sequence, and on a Windows DLL most of them are. That
//! is what `examples/scan_bench.rs` measured — 51% of the rule set selected on
//! `notepad.exe`, 72% on `shell32.dll`, and 0.4 MB/s. The atoms were right; the
//! rule-level reading was too weak.
//!
//! So [`RuleFilter::required`] carries the slots the condition cannot be true
//! without, from [`crate::compiler::required_slots`]. `$a and $b and $c` gives
//! all three, and the rule is selected only when *all* of them are still
//! possible. A condition that proves nothing — `any of them`, `#a == 0` —
//! gives an empty list, and the rule falls back to the weaker disjunction. Both
//! are sound for the same reason: a rule that matches has every required string
//! matching, so it is never dropped by the stronger test, and the weaker test
//! drops only what it can prove absent.
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
    /// Rules selected only when every string their condition requires is
    /// possible, rather than when any string is.
    pub conjunctive_rules: usize,
    /// Strings those rules must find before their rule is selected.
    pub required_strings: usize,
}

/// One rule's strings, as the prefilter needs them.
///
/// The order is the order the compiler assigned slots in, which nothing here
/// depends on but which makes a mismatch between the two easy to spot.
pub type RuleStrings = Vec<StringAtoms>;

/// Everything the prefilter knows about one rule before a file is read.
///
/// The two halves come from different places and are only useful together. The
/// strings are the atom tables built from the rule's definitions; `required` is
/// what [`crate::compiler::required_slots`] proved about its condition, and it
/// is what turns the rule-level test from a disjunction into a conjunction for
/// the rules that support one.
#[derive(Debug, Clone, Default)]
pub struct RuleFilter {
    /// One entry per string slot, in slot order.
    pub strings: RuleStrings,
    /// Slots the condition cannot be true without. May be empty, may name
    /// slots out of range, and may be unsorted; all three are handled.
    pub required: Vec<u32>,
}

impl RuleFilter {
    /// A rule whose condition proved nothing, with no strings.
    pub fn new() -> Self {
        Self::default()
    }

    /// A rule with these strings and nothing required of them.
    pub fn of(strings: RuleStrings) -> Self {
        Self {
            strings,
            required: Vec::new(),
        }
    }

    /// The same rule, requiring these slots.
    pub fn requiring(mut self, required: Vec<u32>) -> Self {
        self.required = required;
        self
    }
}

impl From<RuleStrings> for RuleFilter {
    fn from(strings: RuleStrings) -> Self {
        RuleFilter::of(strings)
    }
}

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
    /// String id -> whether satisfying it moves its rule toward selection.
    ///
    /// True for a string in its rule's required set that has atoms. A required
    /// string *without* atoms is false here: it can never be refuted, so it can
    /// never keep its rule out, and counting it would make the tally
    /// unreachable and the rule unfireable.
    string_required: Vec<bool>,
    /// Rule -> how many of its required strings have atoms, and must therefore
    /// be found before the rule is selected. Zero means the rule is filtered on
    /// the weaker "any string" test instead.
    rule_required_count: Vec<u32>,
    /// Rule -> its first string slot, with a closing sentinel. See
    /// [`Prefilter::string_state`].
    rule_first_string: Vec<u32>,
    /// Rules that some string with no groups makes unconditionally possible.
    unfiltered: Vec<u32>,
    stats: PrefilterStats,
}

/// What the prefilter knows about one string of one rule, after a scan.
///
/// This is the handover that keeps the scanner from re-matching strings the
/// atoms already ruled out. The prefilter sees every atom occurrence in the
/// buffer, so when a string's groups were not all satisfied it knows the string
/// is not there — and saying so is worth more than the selection itself,
/// because matching is the expensive half.
///
/// The three states are exhaustive and the distinction between the last two
/// matters: [`Possible`](StringState::Possible) is a hint that costs a match to
/// confirm, [`Absent`](StringState::Absent) is a fact that saves one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringState {
    /// Every one of the string's atom groups was satisfied, so a match may
    /// exist. Only matching can tell.
    Possible,
    /// The string has no atoms, so nothing could be checked either way. It must
    /// be matched.
    Unknown,
    /// A group had no atom present anywhere in the buffer, and a group is
    /// satisfied by any one of its atoms — so none of them is present, so the
    /// string cannot match. Matching it would find nothing.
    Absent,
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
            .field("conjunctive", &self.stats.conjunctive_rules)
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
    pub fn build(rules: &[RuleFilter]) -> Self {
        let mut atoms: Vec<Atom> = Vec::new();
        let mut atom_ids: HashMap<Atom, u32> = HashMap::new();
        let mut atom_groups: Vec<SmallVec<[u32; 1]>> = Vec::new();
        let mut group_string: Vec<u32> = Vec::new();
        let mut string_group_count: Vec<u32> = Vec::new();
        let mut string_rule: Vec<u32> = Vec::new();
        let mut string_required: Vec<bool> = Vec::new();
        let mut rule_required_count: Vec<u32> = Vec::new();
        let mut unfiltered: Vec<u32> = Vec::new();
        let mut required_strings: usize = 0;
        // The first string slot of each rule, with a closing sentinel, so a
        // rule's slots are `rule_first_string[r]..rule_first_string[r + 1]`.
        // Strings are pushed in rule order, which is what makes this a range
        // rather than a list.
        let mut rule_first_string: Vec<u32> = Vec::new();

        for (rule, filter) in rules.iter().enumerate() {
            let rule = u32::try_from(rule).unwrap_or(u32::MAX);
            let strings = &filter.strings;
            rule_first_string.push(string_group_count.len() as u32);

            // Which of this rule's strings the condition cannot do without. A
            // slot the condition named but the rule does not define is dropped:
            // the compiler cannot produce one, and a corrupt database should
            // cost a rule its selectivity rather than panic the scanner.
            let required_here: SmallVec<[u32; 4]> = filter
                .required
                .iter()
                .copied()
                .filter(|slot| (*slot as usize) < strings.len())
                .collect();

            if strings.is_empty() {
                // A rule with no strings at all — `condition: filesize < 100`,
                // or anything decided entirely by a module. It has no atoms, so
                // nothing can ever select it, and it must be evaluated every
                // time or it is a rule that silently never fires.
                unfiltered.push(rule);
            }

            // Where this rule's strings start, so the tally below can be
            // counted off the flags rather than off `required_here`.
            let first_string = string_group_count.len();

            for (slot, string) in strings.iter().enumerate() {
                // A required string that has atoms is one the rule can be
                // refuted on; a required string without them is one it cannot,
                // and is left out of the tally so the tally can still reach
                // zero.
                string_required.push(
                    !string.groups.is_empty()
                        && required_here.contains(&u32::try_from(slot).unwrap_or(u32::MAX)),
                );
                let string_id = string_group_count.len() as u32;
                string_rule.push(rule);
                string_group_count.push(string.groups.len() as u32);

                if string.groups.is_empty() {
                    // Nothing is known about this string. In a rule filtered on
                    // "any string", that is fatal to the filter: the rule
                    // cannot be ruled out on the strength of this string, and
                    // *any* string being present is enough to select it, so the
                    // whole rule has to be evaluated. Correct, and slower.
                    //
                    // In a conjunctive rule it is harmless, and the rule is not
                    // let through: this string was left out of the tally above
                    // precisely because it can never be refuted, so the rule is
                    // still selected on the required strings that can be.
                    //
                    // Only once per rule: the loop is about to see this rule's
                    // remaining strings, and `unfiltered` is a list of rules,
                    // not of strings.
                    if required_here.is_empty() && unfiltered.last() != Some(&rule) {
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

            // How many of this rule's required strings can actually be looked
            // for. Zero means either the condition required nothing, or every
            // string it required is one no atom can speak for — and in both
            // cases the rule is selected by the weaker "any string" test, so
            // the count has to stay zero rather than leave a tally that can
            // never be reached.
            //
            // Counted off the flags just pushed rather than off `required_here`,
            // so that the number the tally counts to is by construction the
            // number of strings that decrement it. Counting the slots instead
            // would be wrong for a list naming one slot twice: two strings'
            // worth of tally against one string that can decrement it, so the
            // rule would never be selected. The compiler deduplicates, so that
            // list cannot come from a rule set — which makes it exactly the
            // kind of thing that arrives from a corrupt database instead, and
            // the kind worth not depending on.
            let refutable = string_required[first_string..]
                .iter()
                .filter(|counts| **counts)
                .count();
            let refutable = u32::try_from(refutable).unwrap_or(u32::MAX);

            if !required_here.is_empty() && refutable == 0 {
                // Every string the condition needs is one nothing can be said
                // about, so no atom can ever keep this rule out. Same outcome as
                // a string with no atoms in the disjunctive case, and reached
                // the same way.
                unfiltered.push(rule);
            }
            if refutable > 0 {
                required_strings += refutable as usize;
            }
            rule_required_count.push(refutable);
        }

        // A rule is either in the tally list or not, and `unfiltered` is
        // reported before either automaton runs. The two are disjoint by
        // construction — a rule reaches here with `refutable > 0` only when
        // `required_here` is non-empty, which is also the only case the
        // disjunctive push above is suppressed — but a duplicate would cost a
        // rule the filter rather than break it, so the sentinel check in
        // `report` is what actually enforces it.

        // Closing sentinel, so the last rule's slots are a range like every
        // other rule's.
        rule_first_string.push(string_group_count.len() as u32);

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
            conjunctive_rules: rule_required_count.iter().filter(|c| **c > 0).count(),
            required_strings,
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
            string_required,
            rule_required_count,
            rule_first_string,
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

    /// What is known about one string of one rule, from the scan that just ran.
    ///
    /// # When this may be called
    ///
    /// Between a [`candidates`](Self::candidates) call and the next one. The
    /// state lives in [`PrefilterScratch`] and is stamped with the scan's epoch,
    /// so a second scan overwrites it; a debug build asserts that the scratch
    /// belongs to this prefilter and that a scan has run.
    ///
    /// # Why it exists
    ///
    /// [`candidates`](Self::candidates) says which *rules* are worth evaluating.
    /// That is not the same as which *strings* are worth matching, and the
    /// difference is the bulk of the cost: a rule selected because one of its
    /// strings has a weak atom still has six other strings, and the atoms
    /// already proved five of them absent. Matching those five is pure waste,
    /// and on a clean file the prefilter's selection is mostly this case.
    pub fn string_state(
        &self,
        scratch: &PrefilterScratch,
        rule: u32,
        slot: u32,
    ) -> StringState {
        debug_assert_eq!(
            scratch.owner,
            self.address(),
            "this scratch has not been used for a scan with this prefilter, so its stamps \
             mean nothing here"
        );

        // A slot past the end means the program and the prefilter disagree about
        // how many strings the rule has, which is a corrupt database. `Unknown`
        // is the answer that costs a redundant match rather than a missed one.
        let Some(range) = self.rule_range(rule) else {
            return StringState::Unknown;
        };
        if slot as usize >= (range.end - range.start) as usize {
            return StringState::Unknown;
        }
        let string = range.start + slot;

        let groups = self.string_group_count[string as usize];
        if groups == 0 {
            // No atoms, so no group could have been satisfied or refuted.
            return StringState::Unknown;
        }
        if scratch.string_seen[string as usize] != scratch.epoch {
            // Not one group was satisfied, so at least one group had no atom in
            // the buffer, so the string cannot match.
            return StringState::Absent;
        }
        if scratch.string_left[string as usize] == 0 {
            StringState::Possible
        } else {
            // Some groups were satisfied and others were not. A group is
            // satisfied by any one of its atoms, so an unsatisfied group means
            // every atom in it is absent, which rules the string out.
            StringState::Absent
        }
    }

    /// The string slots of one rule, or `None` if there is no such rule.
    fn rule_range(&self, rule: u32) -> Option<std::ops::Range<u32>> {
        let start = *self.rule_first_string.get(rule as usize)?;
        let end = *self.rule_first_string.get(rule as usize + 1)?;
        Some(start..end)
    }

    /// How many string slots a rule has.
    pub fn string_count(&self, rule: u32) -> u32 {
        self.rule_range(rule).map_or(0, |r| r.end - r.start)
    }

    /// This prefilter's identity, for the scratch's ownership check. Not a
    /// value with any meaning outside that comparison.
    fn address(&self) -> usize {
        self as *const Prefilter as usize
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
                if !scratch.satisfy_group(*group, &self.group_string, &self.string_group_count) {
                    continue;
                }
                let string = self.group_string[*group as usize] as usize;
                let rule = self.string_rule[string];
                if self.string_required[string] {
                    // The condition needs this string, so the rule is selected
                    // when the last string it needs has now been found.
                    let needed = self.rule_required_count[rule as usize];
                    if scratch.satisfy_required(rule, needed) {
                        scratch.report(rule, out);
                    }
                } else if self.rule_required_count[rule as usize] == 0 {
                    // A rule filtered on "any string". This one is present, so
                    // the rule is worth evaluating.
                    scratch.report(rule, out);
                }
                // Otherwise: a string the condition does not need, in a rule
                // that is not selected on "any string". It says nothing about
                // whether the rule can match.
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
    /// Which prefilter this state belongs to, as an address.
    ///
    /// The tables are stamped with an epoch rather than cleared, so stamps from
    /// one prefilter would read as valid against another whose tables are laid
    /// out differently — a silent wrong answer, and one that would depend on
    /// allocation order. Recorded so a debug build can refuse instead.
    owner: usize,
    atom_seen: Vec<u32>,
    group_done: Vec<u32>,
    string_seen: Vec<u32>,
    string_left: Vec<u32>,
    rule_seen: Vec<u32>,
    /// Rule -> how many required strings are still to be found, and the epoch
    /// that tally belongs to.
    ///
    /// Two tables rather than one because an entry cannot be both a stamp and a
    /// count. `required_count` alone would have to be written for every rule at
    /// the start of every scan to say "nothing found yet", which is a loop over
    /// the whole rule set per file — the cost the epoch scheme exists to avoid.
    /// The stamp gates the count instead: an entry stamped with an older epoch
    /// has no tally, and the tally it would have is read from the rule set
    /// rather than written by a loop.
    required_left: Vec<u32>,
    required_epoch: Vec<u32>,
}

impl PrefilterScratch {
    fn new(prefilter: &Prefilter) -> Self {
        Self {
            epoch: 0,
            owner: prefilter.address(),
            atom_seen: vec![0; prefilter.atom_groups.len()],
            group_done: vec![0; prefilter.group_string.len()],
            string_seen: vec![0; prefilter.string_group_count.len()],
            string_left: vec![0; prefilter.string_group_count.len()],
            rule_seen: vec![0; prefilter.stats.rules],
            required_left: vec![0; prefilter.stats.rules],
            required_epoch: vec![0; prefilter.stats.rules],
        }
    }

    /// Start a scan.
    ///
    /// A scratch made for one prefilter can be used with another as long as the
    /// tables are grown to fit — the epoch stamps make the old contents
    /// unreadable, so nothing has to be cleared. What must not happen is a
    /// *query* against a scratch that was never used for a scan: a stamp from
    /// another prefilter reads as "not seen this epoch", which is how
    /// [`StringState::Absent`] is decided, so the answer would be a confident
    /// false negative. That is what `owner` is for.
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
        // Set unconditionally, not only when the tables were rebuilt: a reused
        // scratch is now this prefilter's, whatever it was before.
        self.owner = prefilter.address();
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            // Four billion files into a scan, start the stamps over. Reachable
            // only in a soak test, and cheap enough to be worth not thinking
            // about again.
            self.atom_seen.fill(0);
            self.group_done.fill(0);
            self.string_seen.fill(0);
            self.rule_seen.fill(0);
            self.required_epoch.fill(0);
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

    /// Note one of a rule's required strings as found, returning whether that
    /// was the last one it was waiting for.
    ///
    /// `needed` is the number of the rule's required strings that can be looked
    /// for, and is never zero: a rule in that state is in `unfiltered` instead,
    /// because a tally that starts at zero would have this function report a
    /// rule before any of its strings had been seen.
    fn satisfy_required(&mut self, rule: u32, needed: u32) -> bool {
        debug_assert!(needed > 0, "a rule with no refutable required strings is unfiltered");
        if self.required_epoch[rule as usize] != self.epoch {
            self.required_epoch[rule as usize] = self.epoch;
            self.required_left[rule as usize] = needed;
        }
        let left = &mut self.required_left[rule as usize];
        *left = left.saturating_sub(1);
        *left == 0
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

    /// Rules with no conjunctive information.
    ///
    /// Most of the tests below are about what the automaton and the per-string
    /// state machine do, which is the disjunctive path. The conjunctive path
    /// has its own tests, which build their rules directly.
    fn filters(rules: &[RuleStrings]) -> Vec<RuleFilter> {
        rules.iter().cloned().map(RuleFilter::of).collect()
    }

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
        let p = Prefilter::build(&filters(&[vec![one(b"needle")]]));
        assert_eq!(scan(&p, b"a haystack with a needle in it"), vec![0]);
    }

    #[test]
    fn a_rule_whose_atom_is_absent_is_not_selected() {
        let p = Prefilter::build(&filters(&[vec![one(b"needle")]]));
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
        let p = Prefilter::build(&filters(&rules));

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
        let p = Prefilter::build(&filters(&rules));
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
        let p = Prefilter::build(&filters(&[vec![atoms]]));
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
        let p = Prefilter::build(&filters(&[vec![atoms]]));
        assert!(scan(&p, b"...ABC...").is_empty(), "only one of the two");
        assert_eq!(scan(&p, b"...ABC...DEF..."), vec![0]);
    }

    #[test]
    fn any_atom_of_a_group_is_enough() {
        // `xor(1-255)` is 255 alternatives in one group, and finding one of
        // them is finding the string.
        let p = Prefilter::build(&filters(&[vec![any(&[b"alpha", b"bravo", b"charlie"])]]));
        assert_eq!(scan(&p, b"xxcharliexx"), vec![0]);
        assert!(scan(&p, b"xxdeltaxx").is_empty());
    }

    #[test]
    fn overlapping_atoms_from_different_rules_are_both_reported() {
        // The false negative that a non-overlapping automaton would produce:
        // `abcde` contains both `abcd` and `bcde`, and an iterator that skipped
        // the second because it began inside the first would silently drop the
        // rule that depends on it.
        let p = Prefilter::build(&filters(&[vec![one(b"abcd")], vec![one(b"bcde")]]));
        assert_eq!(scan(&p, b"abcde"), vec![0, 1]);
    }

    #[test]
    fn one_rule_matching_many_times_is_still_one_candidate() {
        let p = Prefilter::build(&filters(&[vec![one(b"aaaaaaaa")]]));
        assert_eq!(scan(&p, b"aaaaaaaaaaaaaaaaaaaaaaaa"), vec![0]);
    }

    // -- case sensitivity --------------------------------------------------

    #[test]
    fn a_case_insensitive_atom_matches_either_case() {
        let p = Prefilter::build(&filters(&[vec![one_nocase(b"Kernel32")]]));
        assert_eq!(scan(&p, b"loading KERNEL32.DLL"), vec![0]);
        assert_eq!(scan(&p, b"loading kernel32.dll"), vec![0]);
        assert_eq!(scan(&p, b"loading KeRnEl32.DlL"), vec![0]);
    }

    #[test]
    fn a_case_sensitive_atom_does_not() {
        let p = Prefilter::build(&filters(&[vec![one(b"Kernel32")]]));
        assert_eq!(scan(&p, b"loading Kernel32.DLL"), vec![0]);
        assert!(scan(&p, b"loading KERNEL32.DLL").is_empty());
    }

    #[test]
    fn both_kinds_of_atom_are_found_in_one_scan() {
        let p = Prefilter::build(&filters(&[vec![one(b"exact")], vec![one_nocase(b"loose")]]));
        assert_eq!(scan(&p, b"EXACT loose"), vec![1], "only the loose one");
        assert_eq!(scan(&p, b"exact loose"), vec![0, 1]);
    }

    // -- rules that cannot be filtered -------------------------------------

    #[test]
    fn a_rule_with_an_opaque_string_is_always_selected() {
        // `{ ?? ?? ?? ?? }` says nothing about the bytes, so there is no
        // evidence that could rule its rule out, and it has to be evaluated
        // against every file.
        let p = Prefilter::build(&filters(&[vec![opaque()]]));
        assert_eq!(scan(&p, b""), vec![0]);
        assert_eq!(scan(&p, b"anything at all"), vec![0]);
        assert_eq!(p.stats().unfiltered_rules, 1);
    }

    #[test]
    fn one_opaque_string_makes_its_whole_rule_unfilterable() {
        // The safe direction. The other string's atom is a real constraint on
        // that string, but nothing says the rule needs that string.
        let p = Prefilter::build(&filters(&[vec![opaque(), one(b"needle")]]));
        assert_eq!(scan(&p, b"nothing relevant here"), vec![0]);
        assert_eq!(p.stats().unfiltered_rules, 1);
    }

    #[test]
    fn a_rule_whose_strings_are_all_usable_is_filterable() {
        let p = Prefilter::build(&filters(&[vec![one(b"alpha"), one(b"bravo")]]));
        assert!(scan(&p, b"nothing relevant here").is_empty());
        assert_eq!(p.stats().unfiltered_rules, 0);
    }

    // -- the scratch -------------------------------------------------------

    #[test]
    fn one_scratch_can_be_reused_across_files() {
        // Stamps rather than clears: if a scan left state behind, the second
        // file would inherit the first one's matches.
        let p = Prefilter::build(&filters(&[vec![one(b"alpha")], vec![one(b"bravo")]]));
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
        let p = Prefilter::build(&filters(&[vec![one(b"alpha")], vec![one(b"bravo")]]));
        assert_eq!(scan(&p, b"bravo then alpha"), vec![0, 1]);
    }

    #[test]
    fn a_scratch_from_another_prefilter_is_rebuilt_rather_than_misread() {
        // Reusing a small scratch with a larger prefilter would index out of
        // bounds, and the failure would be a panic at best and a wrong answer
        // at worst.
        let small = Prefilter::build(&filters(&[vec![one(b"alpha")]]));
        let large = Prefilter::build(&filters(&[
            vec![one(b"alpha")],
            vec![one(b"bravo")],
            vec![one(b"charlie")],
        ]));
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
        let p = Prefilter::build(&filters(&[
            vec![one(b"kernel32.dll")],
            vec![one(b"kernel32.dll")],
            vec![one(b"kernel32.dll")],
        ]));
        assert_eq!(p.stats().atoms, 1);
        assert_eq!(scan(&p, b"kernel32.dll"), vec![0, 1, 2]);
    }

    #[test]
    fn the_stats_count_what_was_built() {
        let p = Prefilter::build(&filters(&[
            vec![one(b"alpha"), one_nocase(b"bravo")],
            vec![one(b"alpha")],
            vec![opaque()],
        ]));
        let stats = p.stats();
        assert_eq!(stats.rules, 3);
        assert_eq!(stats.atoms, 2, "alpha and bravo, deduplicated");
        assert_eq!(stats.case_insensitive_atoms, 1);
        assert_eq!(stats.unfiltered_rules, 1);
    }

    #[test]
    fn an_empty_rule_set_selects_nothing_and_scans_nothing() {
        let p = Prefilter::build(&filters(&[]));
        assert_eq!(scan(&p, b"anything"), Vec::<u32>::new());
        assert_eq!(p.stats().atoms, 0);
    }

    /// A rule with no strings is selected unconditionally.
    ///
    /// This test used to assert the opposite — that such a rule selects
    /// nothing — under the reasoning that a rule with no atoms is one nothing
    /// can be said about, so there is nothing to select it. The reasoning is
    /// backwards: nothing selects it, so if it is not selected by default it is
    /// never selected at all, and a rule whose condition is `filesize < 100` or
    /// `pe.is_dll()` becomes a rule that can never fire. The name was the same
    /// and the assertion was confident, which is exactly how a false negative
    /// survives a test suite.
    #[test]
    fn a_rule_with_no_strings_at_all_is_always_selected() {
        let p = Prefilter::build(&filters(&[vec![]]));
        assert_eq!(scan(&p, b"anything"), vec![0]);
        assert_eq!(scan(&p, b""), vec![0], "even an empty buffer");
    }

    // -- the conjunctive rule-level test ------------------------------------
    //
    // A rule whose condition is `$a and $b` can only match when both are
    // present, so it is only worth evaluating then. These tests pin that the
    // prefilter uses the stronger test where the condition supports one, and
    // falls back to the weaker one wherever it does not — because the second
    // half is what keeps the first half from dropping rules that match.

    /// `$a and $b`: selected only when both atoms are in the buffer.
    #[test]
    fn a_conjunctive_rule_needs_every_string_it_requires() {
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha"), one(b"bravo")])
            .requiring(vec![0, 1])]);
        assert_eq!(scan(&p, b"alpha and bravo"), vec![0]);
        assert_eq!(
            scan(&p, b"alpha on its own"),
            Vec::<u32>::new(),
            "one of the two required strings is provably absent"
        );
        assert_eq!(scan(&p, b"neither of them"), Vec::<u32>::new());
        assert_eq!(scan(&p, b""), Vec::<u32>::new());
    }

    /// The same rule with no declared requirement, for contrast. This is what
    /// every rule did before `required_slots` existed, and it is the behaviour
    /// that made a scan of `shell32.dll` select 72% of the rule set.
    #[test]
    fn the_weaker_test_selects_the_same_rule_on_one_string() {
        let p = Prefilter::build(&filters(&[vec![one(b"alpha"), one(b"bravo")]]));
        assert_eq!(scan(&p, b"alpha on its own"), vec![0]);
    }

    /// A string the condition does not need must not select the rule.
    #[test]
    fn an_unrequired_string_present_does_not_select_a_conjunctive_rule() {
        // `$a and $c` with `$b` also defined and unused. `$b` being present
        // says nothing about whether the condition can be satisfied.
        let p = Prefilter::build(&[RuleFilter::of(vec![
            one(b"alpha"),
            one(b"bravo"),
            one(b"charlie"),
        ])
        .requiring(vec![0, 2])]);
        assert_eq!(scan(&p, b"bravo alone"), Vec::<u32>::new());
        assert_eq!(scan(&p, b"alpha and charlie"), vec![0]);
    }

    /// A required string nothing can be said about cannot keep the rule out.
    ///
    /// `$a and $b` where `$b` is too short to have an atom. The rule is still
    /// worth evaluating whenever `$a` is present, because nothing can prove
    /// `$b` absent — counting it in the tally would make the tally unreachable
    /// and the rule would never fire at all.
    #[test]
    fn a_required_string_with_no_atoms_does_not_block_its_rule() {
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha"), opaque()])
            .requiring(vec![0, 1])]);
        assert_eq!(
            scan(&p, b"alpha"),
            vec![0],
            "the unrefutable half must not be waited for"
        );
        assert_eq!(scan(&p, b"nothing"), Vec::<u32>::new());
    }

    /// When *every* required string is unrefutable, nothing can filter the rule.
    #[test]
    fn a_conjunctive_rule_with_nothing_refutable_is_always_selected() {
        let p = Prefilter::build(&[RuleFilter::of(vec![opaque()]).requiring(vec![0])]);
        assert_eq!(scan(&p, b""), vec![0]);
        assert_eq!(p.stats().conjunctive_rules, 0, "it fell back to unfiltered");
        assert_eq!(p.stats().unfiltered_rules, 1);
    }

    /// A required slot the rule does not have falls back to the weaker test.
    ///
    /// Only a corrupt database produces one. Dropping such a slot from the
    /// tally is the safe reading — an unrefutable requirement, again — and
    /// reading it as "the rule can never be selected" would be a false
    /// negative on every file.
    #[test]
    fn a_required_slot_out_of_range_falls_back_to_the_weaker_test() {
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha")]).requiring(vec![7])]);
        assert_eq!(scan(&p, b"alpha"), vec![0]);
        assert_eq!(p.stats().conjunctive_rules, 0);
    }

    /// A slot named twice must not stall the tally.
    #[test]
    fn a_repeated_required_slot_is_counted_once() {
        // `$a and $a`, hand-built. The tally counts strings that can decrement
        // it, so a duplicate cannot leave it one short of zero — which would be
        // a rule that never fires.
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha"), one(b"bravo")])
            .requiring(vec![0, 0])]);
        assert_eq!(scan(&p, b"alpha"), vec![0]);
        assert_eq!(scan(&p, b"nothing"), Vec::<u32>::new());
    }

    /// Rules are independent: one rule's required strings are not another's.
    #[test]
    fn a_conjunctive_rule_does_not_wait_on_another_rules_strings() {
        let p = Prefilter::build(&[
            RuleFilter::of(vec![one(b"alpha"), one(b"bravo")]).requiring(vec![0, 1]),
            RuleFilter::of(vec![one(b"charlie"), one(b"delta")]).requiring(vec![0, 1]),
        ]);
        assert_eq!(scan(&p, b"alpha bravo"), vec![0]);
        assert_eq!(scan(&p, b"charlie delta"), vec![1]);
        assert_eq!(scan(&p, b"alpha delta"), Vec::<u32>::new(), "neither rule");
    }

    /// A conjunctive rule must be reported once, not once per string.
    #[test]
    fn a_conjunctive_rule_is_reported_exactly_once() {
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha"), one(b"bravo")])
            .requiring(vec![0, 1])]);
        assert_eq!(scan(&p, b"alpha bravo alpha bravo"), vec![0]);
    }

    /// The state must not survive from one scan into the next.
    ///
    /// The tally counts down over a scan and is reset by the epoch, not by a
    /// loop. A tally that survived would make every later scan select the rule
    /// on the first of its strings.
    #[test]
    fn a_second_scan_does_not_inherit_the_first_ones_tally() {
        let p = Prefilter::build(&[RuleFilter::of(vec![one(b"alpha"), one(b"bravo")])
            .requiring(vec![0, 1])]);
        assert_eq!(scan(&p, b"alpha bravo"), vec![0]);
        assert_eq!(
            scan(&p, b"alpha"),
            Vec::<u32>::new(),
            "the tally from the first scan has to be gone"
        );
        assert_eq!(scan(&p, b"alpha bravo"), vec![0], "and be rebuildable");
    }

    #[test]
    fn an_empty_buffer_selects_only_the_unfilterable() {
        let p = Prefilter::build(&filters(&[vec![one(b"alpha")], vec![opaque()]]));
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

        let p = Prefilter::build(&filters(&rules));
        assert_eq!(scan(&p, b"xx alphaxx"), vec![0]);
        assert_eq!(scan(&p, b"xx bravoxx"), vec![1]);
        assert_eq!(scan(&p, b"xx charliexx"), vec![2]);
        assert!(scan(&p, b"xx deltaxx").is_empty());
    }

    /// An atom can only ever be a necessary condition, never a sufficient one.
    #[test]
    fn a_selected_rule_may_still_not_match() {
        let p = Prefilter::build(&filters(&[vec![one(b"needle")]]));
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

    // -- a rule with no strings --------------------------------------------

    /// A rule whose condition is decided entirely by something other than a
    /// string — `filesize < 100`, `pe.is_dll()` — has no atoms at all, so
    /// nothing can select it. It has to be evaluated unconditionally.
    ///
    /// This was a real false negative: the rule was added to the unfiltered
    /// list from inside the loop over its strings, and a rule with no strings
    /// never entered that loop. Nothing else in the pipeline would have said
    /// so — the rule would simply have never fired again.
    #[test]
    fn a_rule_with_no_strings_is_evaluated_every_time() {
        let p = Prefilter::build(&filters(&[vec![], vec![one(b"needle")]]));
        assert_eq!(p.stats().unfiltered_rules, 1);
        assert_eq!(scan(&p, b"nothing relevant here"), vec![0]);
        assert_eq!(scan(&p, b"a needle"), vec![0, 1], "both, in rule order");
    }

    #[test]
    fn a_rule_with_no_strings_has_no_slots() {
        let p = Prefilter::build(&filters(&[vec![], vec![one(b"alpha"), one(b"bravo")]]));
        assert_eq!(p.string_count(0), 0);
        assert_eq!(p.string_count(1), 2);
        assert_eq!(p.string_count(2), 0, "past the end");
    }

    // -- per-string state ---------------------------------------------------

    /// What the prefilter knows per string, not just per rule. This is what
    /// keeps the scanner from re-matching strings the atoms already refuted.
    #[test]
    fn a_string_is_reported_possible_only_when_every_group_was_satisfied() {
        let atoms = StringAtoms {
            groups: vec![
                vec![best_atom(b"alpha", false).unwrap()],
                vec![best_atom(b"bravo", false).unwrap()],
            ],
        };
        let p = Prefilter::build(&filters(&[vec![atoms]]));
        let mut scratch = p.scratch();
        let mut out = Vec::new();

        p.candidates(b"alpha and bravo", &mut scratch, &mut out);
        assert_eq!(
            p.string_state(&scratch, 0, 0),
            StringState::Possible,
            "both groups present"
        );

        // Only one group present: the string cannot match, and saying so is
        // worth more than the rule selection, because matching is the expensive
        // half.
        p.candidates(b"alpha only", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Absent);

        p.candidates(b"neither", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Absent);
    }

    #[test]
    fn a_string_with_no_atoms_is_unknown_rather_than_absent() {
        // The distinction is load-bearing: `Absent` lets the scanner skip the
        // string, so answering it here would drop a string that does match.
        let p = Prefilter::build(&filters(&[vec![opaque()]]));
        let mut scratch = p.scratch();
        let mut out = Vec::new();
        p.candidates(b"anything at all", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Unknown);
    }

    #[test]
    fn each_string_of_a_rule_is_judged_separately() {
        let p = Prefilter::build(&filters(&[vec![one(b"alpha"), one(b"bravo"), opaque()]]));
        let mut scratch = p.scratch();
        let mut out = Vec::new();
        p.candidates(b"bravo", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Absent);
        assert_eq!(p.string_state(&scratch, 0, 1), StringState::Possible);
        assert_eq!(p.string_state(&scratch, 0, 2), StringState::Unknown);
    }

    #[test]
    fn a_slot_past_the_end_is_unknown_rather_than_a_panic() {
        // A program and a prefilter that disagree about string count is a
        // corrupt database. The answer that costs a redundant match is right;
        // the answer that skips a string is a missed detection.
        let p = Prefilter::build(&filters(&[vec![one(b"alpha")]]));
        let mut scratch = p.scratch();
        let mut out = Vec::new();
        p.candidates(b"alpha", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 99), StringState::Unknown);
        assert_eq!(p.string_state(&scratch, 99, 0), StringState::Unknown);
    }

    #[test]
    fn state_is_judged_against_the_scan_that_just_ran() {
        // Two scans, the second finding nothing: the state must be the second
        // scan's, not the first's. A run that left the previous answer in place
        // would report a string possible on a file that does not contain it.
        let p = Prefilter::build(&filters(&[vec![one(b"alpha")]]));
        let mut scratch = p.scratch();
        let mut out = Vec::new();
        p.candidates(b"alpha", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Possible);
        p.candidates(b"nothing", &mut scratch, &mut out);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Absent);
    }

    #[test]
    fn a_scratch_from_another_prefilter_is_still_usable_after_a_scan() {
        // Reuse is supported — the epoch stamps make the old contents
        // unreadable — but the ownership must follow the scan, or the debug
        // assertion in `string_state` would fire on a legitimate reuse.
        let a = Prefilter::build(&filters(&[vec![one(b"alpha"), one(b"bravo")]]));
        let b = Prefilter::build(&filters(&[vec![one(b"alpha")]]));
        let mut scratch = a.scratch();
        let mut out = Vec::new();
        b.candidates(b"alpha", &mut scratch, &mut out);
        assert_eq!(b.string_state(&scratch, 0, 0), StringState::Possible);
    }
}
