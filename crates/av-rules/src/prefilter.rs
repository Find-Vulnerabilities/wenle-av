//! Deciding which rules could possibly match, in one pass over the buffer.
//!
//! # The shape of the problem
//!
//! Ten thousand rules with about seven strings each is seventy thousand
//! searches per file. A scan that did that would take seconds per file, which
//! is three orders of magnitude away from what a resident scanner needs. The
//! prefilter is what closes the gap: every atom from every string in the rule
//! set goes into one multi-pattern search, one pass over the buffer finds all
//! of them at once, and only the rules those atoms point at are worth looking
//! at closely.
//!
//! # The one property that matters
//!
//! **The prefilter may return a rule that does not match. It must never omit a
//! rule that does.** Everything here is arranged around that asymmetry. An atom
//! is a byte sequence a match must contain, so its absence proves the string is
//! absent, but its presence proves nothing, and a rule selected on an atom
//! still has to be evaluated properly. A missed candidate is a missed
//! detection, and no amount of speed is worth one.
//!
//! # What "must contain" means for a whole string
//!
//! [`crate::atoms`] turns each string into a conjunction of disjunctions: every
//! group must be satisfied, and a group is satisfied by any one of its atoms.
//! A string with no groups (every form of it too short to have an atom)
//! constrains nothing, and a rule with such a string has to be let through
//! untested. Those rules are collected at build time and reported as
//! [`PrefilterStats::unfiltered_rules`], and how many there are is the honest
//! measure of how much the rule set can be filtered at all.
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
//! is what `examples/scan_bench.rs` measured: 51% of the rule set selected on
//! `notepad.exe`, 72% on `shell32.dll`, and 0.4 MB/s. The atoms were right; the
//! rule-level reading was too weak. With the conjunction read out of the
//! condition, the same binaries select 5.8% and 12.7%.
//!
//! So [`RuleFilter::required`] carries the slots the condition cannot be true
//! without, from [`crate::compiler::required_slots`]. `$a and $b and $c` gives
//! all three, and the rule is selected only when *all* of them are still
//! possible. A condition that proves nothing (`any of them`, `#a == 0`)
//! gives an empty list, and the rule falls back to the weaker disjunction. Both
//! are sound for the same reason: a rule that matches has every required string
//! matching, so it is never dropped by the stronger test, and the weaker test
//! drops only what it can prove absent.
//!
//! # Two searches, and why
//!
//! A case rule is a property of all of a matcher's patterns or of none of them,
//! and a rule set has both kinds. So there are two searches and two passes over
//! the buffer.
//!
//! The case-insensitive half needs the buffer folded first, because the matcher
//! under this one compares bytes and does not fold as it goes. That is a third
//! pass, and it is real work this design does not get for free, but it is
//! cheap next to the alternative, which is expanding each case-insensitive atom
//! into its two-to-the-n case variants: for a four-byte atom that is sixteen
//! times the patterns to save one pass over a buffer that is already in cache.
//! Measured on `shell32.dll`, the fold is 2.9 ms against the 208 ms the search
//! itself costs, so it is 1.4% of the pair and not worth a second design.
//!
//! # What searches, and what only the machine it runs on decides
//!
//! [`av_patterns::AtomSet`] rather than a general Aho-Corasick automaton, and
//! that is the one place this module is fitted to a fact about its input rather
//! than to the problem. Every atom [`crate::atoms`] produces is three or four
//! bytes ([`crate::atoms::MIN_ATOM_LEN`] and [`crate::atoms::MAX_ATOM_LEN`] bound it), and a
//! matcher that knows its patterns are all the same short length need not carry
//! automaton state between bytes at all. The atom set answers "which atoms
//! start here" with two tables keyed on the window's own bytes, so the per-byte
//! cost is a lookup in something that fits in level 2 rather than a miss. The
//! build asserts the premise: an atom shorter than the gate can use would fall
//! to a linear path, and a rule set that produced one should say so here rather
//! than quietly scan slower.
//!
//! This is a replacement and not an addition. `av-patterns` was written for
//! exactly this call site and `examples/pattern_bench.rs` runs both matchers
//! over the real atom set and the same buffer on the same machine, which is the
//! only way the claim is worth anything. Aho-Corasick remains in the workspace
//! for [`crate::sweep`], whose patterns are whole literal forms of any length
//! and are not this shape.
//!
//! # Cost
//!
//! Building the searches is the expensive part and happens once per rule
//! database, not once per file: the case-sensitive atom set is 5,091 KiB of
//! tables and the case-insensitive one 851 KiB, which is the memory this module
//! trades for the per-byte cost it does not pay. The per-file state in
//! [`PrefilterScratch`] is stamped with an epoch rather than cleared, so a scan
//! touches only what it matched.
//!
//! Measured against the 10,764-rule set this engine is built for: 8,715 rules
//! that compile, 92,182 distinct atoms, 156 rules nothing can be said about:
//!
//! ```text
//! 1 MiB of zeros     156 rules selected (1.79%)     9 MB/s
//! 1 MiB of text      156 rules selected (1.79%)    21 MB/s
//! 1 MiB random       165 rules selected (1.89%)    14 MB/s
//!
//! notepad.exe        504 rules selected (5.78%)     6 MB/s
//! kernel32.dll       702 rules selected (8.06%)     4 MB/s
//! shell32.dll      1,108 rules selected (12.71%)    3 MB/s
//! ```
//!
//! Those are whole-scan rates, and they were taken with an Aho-Corasick
//! automaton in the search position. They are left as they were measured rather
//! than retouched, because the swap to [`av_patterns::AtomSet`] moved the
//! end-to-end figure by about 6%, enough that the rows read as the floor and
//! not as the current number, and not enough to be worth restating a table whose
//! point is the selection rate. The component numbers below are the ones that
//! changed, and they are the ones to read.
//!
//! Selection is the number this module owns, and it is low enough that the
//! prefilter is not where the time goes. On `shell32.dll` the whole scan is
//! 2.04 s and the prefilter is 558 ms of it, 27%, with the sweep at 151 ms and
//! the remaining 1.33 s spent on the strings that survived the gate.
//!
//! Inside that 558 ms, the search is the part that changed. `pattern_bench` runs
//! both matchers over the real atom set and the same buffer in one process, so
//! the comparison has no second machine in it: the two searches cost 208 ms with
//! [`AtomSet`] against 336 ms with Aho-Corasick, and the case-insensitive half's
//! fold is a further 2.9 ms timed on its own. The rest of the 558 ms (some
//! 350 ms) is not the search at all but the work per match, and what makes it
//! that large is the count: 10.8 million matches on this one file, which is what
//! a set of three- and four-byte atoms finds in an 8 MB binary.
//!
//! `examples/ac_bench.rs` is where the case for the swap was made, and it is
//! worth keeping in view because it is the measurement that says the old search
//! could not be tuned out of the problem: 154 MB/s at a thousand patterns, 84 at
//! ten thousand, 22 at sixty-seven thousand. Flat in the number of matches and
//! linear in the number of automaton states, which is the shape of a transition
//! table that has spilled out of cache and charges every input byte for a miss.
//! Atoms of a fixed short length do not need that table, and this module stopped
//! paying for it.
//!
//! So the next lever is neither a faster search nor the automaton the earlier
//! version of this comment proposed. That matcher is the one this module now
//! has. It is **fewer matches to report**, which is a question about the atoms
//! rather than about the search. Scoring them by how rare they are across the
//! rule set (and across a corpus of benign files) rather than by their own
//! bytes, which is what [`crate::atoms::score`] does today, would cut both the
//! match count and the number of atoms, and there is a second pass over the rule
//! set that could do it. It is not worth building until something measures the
//! end-to-end scan, and the numbers above are that measurement.
//!
//! # Checking that none of this costs a detection
//!
//! Everything above is a filter, and every filter here is an optimization that
//! can lose a rule if its premise is wrong. `examples/verify_filters.rs` scans
//! the same buffer twice (once through this module and once with
//! [`crate::scanner::Scanner::unfiltered`], which decides nothing) and compares
//! the reported matches, rule by rule and offset by offset. Run it after any
//! change in this file or in [`crate::atoms`]: on the rule set's own text it
//! compares about ninety real detections, and it prints the slot and the offset
//! when the two scans disagree.

use std::collections::HashMap;
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use av_patterns::AtomSet;
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
    case_sensitive: Option<AtomSet>,
    /// The same atoms, folded, over a haystack folded to match.
    ///
    /// Folded at build time rather than searched case-insensitively, because
    /// the matcher has no case rule: it compares the bytes it was given. The
    /// fold of the *buffer* is what the second half of a scan pays for.
    case_insensitive: Option<AtomSet>,
    /// Search pattern index -> unified atom id, one table per search.
    ///
    /// An [`AtomSet`] reports an index into the slice it was built from, and
    /// both sets are built from these same two lists in these same orders, so
    /// this is the whole of the translation.
    sensitive_atom: Vec<u32>,
    insensitive_atom: Vec<u32>,
    /// Unified atom id -> the atom, for its trailer and its case rule.
    ///
    /// The bytes are in the search, but the bytes *after* them are not: an atom
    /// stops at `MAX_ATOM_LEN`, so the trailer is checked here at each hit.
    /// See [`crate::atoms::TRAILER_LEN`].
    atoms: Vec<Atom>,
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
/// sixty-seven thousand atoms into whatever log it was reached from. The two
/// searches are summarised by their pattern counts, which is the part that
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
        // reported before either search runs. The two are disjoint by
        // construction — a rule reaches here with `refutable > 0` only when
        // `required_here` is non-empty, which is also the only case the
        // disjunctive push above is suppressed — but a duplicate would cost a
        // rule the filter rather than break it, so the sentinel check in
        // `report` is what actually enforces it.

        // Closing sentinel, so the last rule's slots are a range like every
        // other rule's.
        rule_first_string.push(string_group_count.len() as u32);

        // Split by case sensitivity, which is the one property a search has to
        // know about at build time: the atom set compares bytes and does not
        // fold, so which side an atom belongs on decides what it is given.
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

        let case_sensitive = build_atom_set(&sensitive_patterns, false);
        let case_insensitive = build_atom_set(&insensitive_patterns, true);

        // The premise the matcher is chosen on, checked where it is cheap to
        // check rather than assumed. Every atom `crate::atoms` produces is
        // three or four bytes, so the atom set's gated path covers all of them
        // and the linear path for shorter atoms is never entered. A rule set
        // that ever produced a one- or two-byte atom would still be *correct*
        // here — the matcher handles them — but it would be quietly slower, and
        // this is where that would be noticed instead of inferred from a
        // benchmark that had drifted.
        debug_assert!(
            case_sensitive
                .iter()
                .chain(case_insensitive.iter())
                .all(|set| set.short_atom_count() == 0),
            "an atom shorter than {} bytes reached the prefilter, which no code path in \
             `crate::atoms` should produce; the matcher would fall back to a linear scan \
             for it",
            crate::atoms::MIN_ATOM_LEN
        );

        let stats = PrefilterStats {
            rules: rules.len(),
            atoms: atoms.len(),
            case_insensitive_atoms: insensitive_patterns.len(),
            unfiltered_rules: unfiltered.len(),
            conjunctive_rules: rule_required_count.iter().filter(|c| **c > 0).count(),
            required_strings,
        };

        Self {
            case_sensitive,
            case_insensitive,
            sensitive_atom,
            insensitive_atom,
            atoms,
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

        if let Some(set) = &self.case_sensitive {
            self.select(set, &self.sensitive_atom, data, data, scratch, out);
        }
        if let Some(set) = &self.case_insensitive {
            // The folded copy lives in the scratch so that a scan allocates
            // nothing, and it is taken out of the scratch for the duration of
            // the search rather than borrowed from it. Borrowing it would mean
            // holding a `&` into `scratch` while passing `&mut scratch` to the
            // search, and the two are not actually in conflict — the buffer and
            // the state it is borrowed from are different things — so taking it
            // out is how that is said rather than how it is worked around.
            let mut folded = std::mem::take(&mut scratch.folded);
            fold_ascii_into(&mut folded, data);
            // `data` and not `folded` for the trailer check: an atom's trailer
            // is compared case-insensitively against the file's own bytes, so
            // the folded copy would answer a different question. The offsets
            // are the same in both, which is the only reason one may be
            // searched and the other read.
            self.select(set, &self.insensitive_atom, &folded, data, scratch, out);
            // Given back only while it is still a buffer worth keeping. This one
            // grows to the largest file the thread has scanned and a `Vec` never
            // returns memory on its own, so a scan that met a single large file
            // leaves that thread holding that file's size for the rest of the
            // run — on every thread that met one, because each has its own
            // scratch. Ten workers and a few large files is gigabytes held for
            // no reason, and it is memory the scan budget was never told about:
            // the budget is charged `COPIES_PER_FILE` for the files in flight
            // and nothing for what the threads keep afterwards. A small buffer
            // is worth keeping, because a small file is the common case and
            // reallocating per file is the cost this scratch exists to avoid. A
            // large one is not, and is released here to be re-taken per file,
            // where the budget can see it.
            if folded.capacity() > RETAINED_FOLD_LIMIT {
                folded.shrink_to(RETAINED_FOLD_LIMIT);
            }
            scratch.folded = folded;
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
    pub fn string_state(&self, scratch: &PrefilterScratch, rule: u32, slot: u32) -> StringState {
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

    /// The offsets a string's matches can be derived from, when the atom pass
    /// saw its atoms often enough to be useful but rarely enough to be exact.
    ///
    /// # What this is for
    ///
    /// The scanner searches for a string by scanning the buffer. When the
    /// answer to "where could this string be" is already known from the atom
    /// pass, that scan is the whole cost of the rule set: a scan of
    /// `shell32.dll` does 19,977 full-buffer searches over eight megabytes,
    /// which is 160 GB of memory traffic and eighteen seconds.
    ///
    /// The atom the search matched is a byte sequence the string must
    /// contain. Every occurrence of it is somewhere a match of the string must
    /// reach, so every occurrence is a candidate: if the atom's bytes sit at
    /// index `k` of the pattern, a match containing the occurrence at `w` must
    /// start at `w - k`. Turning occurrences into match offsets is the
    /// matcher's job, because only the matcher knows the pattern — what comes
    /// back here is the occurrences.
    ///
    /// The first version of this asked only for the single-occurrence case,
    /// which measured at 5% of searches on a real binary: a four-byte atom in
    /// an eight-megabyte DLL usually occurs more than once. But nothing in the
    /// argument needs *one* occurrence, only that all of them are known, so the
    /// list is the general form and the single occurrence is its smallest case.
    ///
    /// # When this may be called
    ///
    /// Between a [`candidates`](Self::candidates) call and the next one, like
    /// [`string_state`](Self::string_state), and for the same reason.
    ///
    /// # Soundness
    ///
    /// Returns `false`, and leaves `out` empty, whenever anything is not known
    /// for certain: no witness was recorded, no occurrence was seen, or there
    /// were more occurrences than [`WITNESS_CAP`] and the later ones were not
    /// kept. The caller then searches properly. There is no case where a
    /// non-empty list comes back that does not contain *every* occurrence the
    /// matcher has to check — the count is the proof, and it counts overlapping
    /// occurrences individually.
    pub fn witnesses(
        &self,
        scratch: &PrefilterScratch,
        rule: u32,
        slot: u32,
        out: &mut Vec<u32>,
    ) -> bool {
        debug_assert_eq!(
            scratch.owner,
            self.address(),
            "this scratch has not been used for a scan with this prefilter, so its stamps \
             mean nothing here"
        );
        out.clear();

        // A corrupt database can name a rule or slot that does not exist. There
        // is no wrong answer that is worse than a full search, so every
        // unresolvable name returns the same thing.
        let Some(range) = self.rule_range(rule) else {
            return false;
        };
        if slot as usize >= (range.end - range.start) as usize {
            return false;
        }
        let string = (range.start + slot) as usize;

        if scratch.string_witness_epoch[string] != scratch.epoch {
            // No group of this string was satisfied, so the string cannot
            // match. `string_state` says the same thing more directly; this is
            // the answer that stays correct if it is asked on its own.
            return false;
        }

        let atom = scratch.string_witness[string] as usize;
        let Some(count) = scratch.atom_count.get(atom).copied() else {
            return false;
        };
        // The whole proof, in one comparison. Every occurrence of the atom is
        // an offset a match could start from, so `count` is exactly how many
        // candidate offsets there are — usable as long as they were all kept.
        // More than the cap means the extras are lost, and a lost offset is a
        // lost match, so the answer falls back to searching.
        if count == 0 || count as usize > WITNESS_CAP {
            return false;
        }
        let start = atom * WITNESS_CAP;
        let stored = scratch.atom_offsets.get(start..start + count as usize);
        let Some(stored) = stored else {
            return false;
        };
        out.extend_from_slice(stored);
        true
    }

    /// The string slots of one rule, or `None` if there is no such rule.
    fn rule_range(&self, rule: u32) -> Option<std::ops::Range<u32>> {
        let start = *self.rule_first_string.get(rule as usize)?;
        let end = *self.rule_first_string.get(rule as usize + 1)?;
        Some(start..end)
    }

    /// How many occurrences of one atom are remembered for the witness search.
    ///
    /// This is the point where locating a string stops being worth it and searching
    /// for it starts. `n` remembered offsets means the matcher verifies `n`
    /// candidate positions, each a comparison of the pattern's length — so the
    /// work is `n × len` instead of the length of the buffer. At sixteen, a
    /// hundred-byte pattern costs 1,600 byte comparisons against eight million for
    /// a pass over `shell32.dll`.
    ///
    /// How many string slots a rule has.
    pub fn string_count(&self, rule: u32) -> u32 {
        self.rule_range(rule).map_or(0, |r| r.end - r.start)
    }

    /// This prefilter's identity, for the scratch's ownership check. Not a
    /// value with any meaning outside that comparison.
    fn address(&self) -> usize {
        self as *const Prefilter as usize
    }

    /// Run one search and turn its matches into satisfied groups.
    ///
    /// `haystack` is what is searched and `data` is what the trailers are
    /// checked against. They are the same buffer for the case-sensitive half
    /// and the buffer and its folded copy for the case-insensitive one, which
    /// is why they are two arguments rather than one: the offsets are
    /// identical, so either may be read at an offset the other produced, and
    /// conflating them would fold the trailers too.
    fn select(
        &self,
        set: &AtomSet,
        atom_of_pattern: &[u32],
        haystack: &[u8],
        data: &[u8],
        scratch: &mut PrefilterScratch,
        out: &mut Vec<u32>,
    ) {
        // Overlapping occurrences, which is what `for_each_match` reports and
        // what a general matcher's `find_iter` would not: atoms from different
        // rules routinely overlap — `bcde` and `abcd` both occur in `abcde` —
        // and reporting the first while skipping the second drops the rule that
        // depends on it. That is a false negative, the one failure this module
        // exists to prevent, and it was this way until the test below caught it.
        set.for_each_match(haystack, |pattern, offset| {
            // Every id the matcher reports is an index into the list this set
            // was built from, so it is in range; a `None` here would be a
            // matcher bug and skipping is the safe direction for one.
            let Some(&atom) = atom_of_pattern.get(pattern as usize) else {
                return;
            };
            let atom = atom as usize;

            // The search found the atom's own bytes; the bytes that must
            // follow them are checked here, because four is all the atom
            // carries. A hit that fails this is not an occurrence of the atom
            // at all, so it is skipped exactly as if the search had never
            // reported it — which is what turns a four-byte match into a
            // twelve-byte one and keeps the scanner from searching for strings
            // that are not in the file.
            let Some(the) = self.atoms.get(atom) else {
                return;
            };
            if !the.is_present_at(data, offset as usize) {
                return;
            }

            if !scratch.visit_atom(atom as u32, offset) {
                return;
            }
            for group in &self.atom_groups[atom] {
                if !scratch.satisfy_group(*group, &self.group_string, &self.string_group_count) {
                    continue;
                }
                let string = self.group_string[*group as usize] as usize;
                scratch.set_witness(string as u32, atom as u32);
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
        });
    }
}

/// Build one atom set, or nothing if there is nothing to put in it.
///
/// An empty set is not a degenerate case worth supporting: it would be a scan
/// over every buffer that can never match, and `None` says the same thing
/// without the work.
///
/// `ascii_case_insensitive` folds the patterns rather than configuring the
/// matcher, because [`AtomSet`] has no such setting — it compares the bytes it
/// is given. The caller then owes it a folded haystack, which
/// [`Prefilter::candidates`] supplies. Folding here rather than in the scan is
/// the point: it is once per rule database instead of once per case-insensitive
/// atom, and it is what keeps a four-byte atom from becoming the sixteen
/// patterns a case-insensitive automaton would store it as.
fn build_atom_set(patterns: &[Vec<u8>], ascii_case_insensitive: bool) -> Option<AtomSet> {
    if patterns.is_empty() {
        return None;
    }
    if !ascii_case_insensitive {
        return Some(AtomSet::new(patterns));
    }
    let folded: Vec<Vec<u8>> = patterns.iter().map(|bytes| fold_ascii(bytes)).collect();
    Some(AtomSet::new(&folded))
}

/// ASCII upper case folded to lower, as a copy.
fn fold_ascii(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

/// The same, in place into a caller's buffer, so that a scan reuses one
/// allocation rather than making one per file.
///
/// A table and not a branch or an arithmetic trick: one lookup per byte, and
/// obviously right for all 256 values. It has to be right, because it is the
/// pass that decides whether a case-insensitive atom is found at all — and it
/// is the counterpart of `AhoCorasickBuilder::ascii_case_insensitive`, which
/// does the same fold inside its transition function. Anything that folded a
/// different set of bytes than that would find a different set of atoms, and
/// the difference would be a missed rule.
/// The largest folded buffer a scanning thread keeps between files.
///
/// One mebibyte, because that is the size above which keeping the buffer stops
/// being an optimisation and starts being a leak. Below it, a file costs one
/// `reserve` that finds the capacity already there, which is what the scratch is
/// for; above it, the buffer is released after the file rather than held for
/// ever, and the next large file pays one allocation that the budget can count.
///
/// The number is a compromise between two costs and not a measurement of
/// either, which is worth saying: the cost of keeping is `threads ×
/// largest_file` resident for the whole run, and the cost of releasing is one
/// `malloc` per large file. At ten workers, a 1 MiB limit bounds what the
/// scratch holds to ten mebibytes, and a folder of large executables pays about
/// one allocation each.
const RETAINED_FOLD_LIMIT: usize = 1 << 20;

fn fold_ascii_into(out: &mut Vec<u8>, data: &[u8]) {
    out.clear();
    out.reserve(data.len());
    for byte in data {
        out.push(byte.to_ascii_lowercase());
    }
}

/// Build one automaton, or nothing if there is nothing to put in it.
///
/// An empty automaton is not a degenerate case worth supporting: it would be a
/// scan over every buffer that can never match, and `None` says the same thing
/// without the work.
///
/// Shared with [`crate::sweep`], which needs the same automaton over literal
/// forms rather than atoms. The two must be built the same way for the same
/// reason the prefilter gives for `MatchKind::Standard`: an overlapping match
/// this automaton failed to report is an occurrence a string never learns about.
pub(crate) fn build_automaton(
    patterns: &[Vec<u8>],
    ascii_case_insensitive: bool,
) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(ascii_case_insensitive)
        .build(patterns)
        .ok()
}

/// How many occurrences of one atom are remembered for the witness search.
///
/// This is the point where locating a string stops being worth it and searching
/// for it starts. `n` remembered offsets means the matcher verifies `n`
/// candidate positions, each a comparison of the pattern's length — so the
/// work is `n × len` instead of the length of the buffer. At sixteen, a
/// hundred-byte pattern costs 1,600 byte comparisons against eight million for
/// a pass over `shell32.dll`.
///
/// The cost of raising it is the scratch: `4 × CAP` bytes for every atom in the
/// database, and 67,218 atoms at sixteen is 4.3 MB per scanning thread.
///
/// That cost is not incidental — it is the binding constraint, and it binds in
/// the direction opposite to the obvious one. Raising this to 64 was measured
/// on `shell32.dll` and made the scan *slower*: 22.6 s to 25.7 s across the six
/// test binaries, even though located searches rose from 24% to 36%. The extra
/// coverage did not pay for a 17 MB table, because every atom match now writes
/// to a different cache line and the automaton pass is what pays. Sixteen keeps
/// the table inside the last-level cache on the machines this was measured on.
///
/// So this is a cache-size constant as much as it is a search-strategy one, and
/// the number to trust is the one `examples/scan_bench.rs` reports, not the
/// reasoning here.
pub const WITNESS_CAP: usize = 16;

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
    /// Atom -> how many times it matched this scan, and where the first
    /// [`WITNESS_CAP`] occurrences were.
    ///
    /// Counted rather than merely noted because the count is what makes the
    /// offsets usable: the scanner can derive a string's matches from them only
    /// when every occurrence is on record, so a count that exceeds what was
    /// kept disqualifies the offsets. All three tables are gated by
    /// `atom_seen`, so none of them needs clearing.
    ///
    /// `atom_offsets` is flat with a stride of `WITNESS_CAP` rather than a
    /// vector per atom — 67,218 atoms at one `Vec` each is millions of
    /// allocations, once per scanning thread, for a table that is empty on
    /// almost every file.
    atom_count: Vec<u32>,
    atom_offsets: Vec<u32>,
    /// String -> the atom that satisfied one of its groups, and the epoch that
    /// answer belongs to.
    ///
    /// A witness, not an answer: which atom got there first says nothing about
    /// whether the string matches, and is only useful once the atom's
    /// occurrence count is known to be one.
    string_witness: Vec<u32>,
    string_witness_epoch: Vec<u32>,
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
    /// The folded copy of the buffer the case-insensitive atoms are searched in.
    ///
    /// Held here and reused rather than made per file so that a scan still
    /// allocates nothing, and left out of `begin`'s growth check because its
    /// size follows the file rather than the rule set — the fold reserves what
    /// it needs on the buffer it is folding. It saves a second pass over the
    /// atom set's own tables to expand case variants instead. Empty when the
    /// rule set has no case-insensitive atoms, which is when nothing ever
    /// writes to it.
    ///
    /// What it holds is bounded by [`RETAINED_FOLD_LIMIT`]: a buffer above that
    /// size is released after the file it was folded for rather than kept, so
    /// that one large file does not leave every scanning thread holding a copy
    /// of it for the rest of the run.
    folded: Vec<u8>,
}

impl PrefilterScratch {
    fn new(prefilter: &Prefilter) -> Self {
        Self {
            epoch: 0,
            owner: prefilter.address(),
            atom_seen: vec![0; prefilter.atom_groups.len()],
            atom_count: vec![0; prefilter.atom_groups.len()],
            atom_offsets: vec![0; prefilter.atom_groups.len() * WITNESS_CAP],
            string_witness: vec![0; prefilter.string_group_count.len()],
            string_witness_epoch: vec![0; prefilter.string_group_count.len()],
            group_done: vec![0; prefilter.group_string.len()],
            string_seen: vec![0; prefilter.string_group_count.len()],
            string_left: vec![0; prefilter.string_group_count.len()],
            rule_seen: vec![0; prefilter.stats.rules],
            required_left: vec![0; prefilter.stats.rules],
            required_epoch: vec![0; prefilter.stats.rules],
            folded: Vec::new(),
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

    /// Note an occurrence of an atom, returning whether this is the first.
    ///
    /// Counts every occurrence, not just the first, because the total is what
    /// says whether the offsets on record are all of them. The first
    /// [`WITNESS_CAP`] are kept and the rest only counted: an atom that occurs
    /// more often than that is one the scanner searches for the ordinary way,
    /// and paying to remember offsets nobody will read is the wrong trade.
    fn visit_atom(&mut self, atom: u32, offset: u32) -> bool {
        let slot = &mut self.atom_seen[atom as usize];
        let first = *slot != self.epoch;
        let count = if first {
            *slot = self.epoch;
            self.atom_count[atom as usize] = 0;
            0
        } else {
            self.atom_count[atom as usize] as usize
        };

        if count < WITNESS_CAP {
            self.atom_offsets[atom as usize * WITNESS_CAP + count] = offset;
        }

        // Saturating, not wrapping. A buffer can be four gigabytes of one byte,
        // and a count that wrapped back round would eventually reach a value
        // the witness search accepts while the offsets on record are long stale
        // — every match after the cap would be missed. Saturating leaves the
        // count above the cap for good, so the offsets stay refused and the
        // string is searched for properly.
        self.atom_count[atom as usize] = self.atom_count[atom as usize].saturating_add(1);
        first
    }

    /// Note the atom that satisfied one of a string's groups.
    ///
    /// An atom that satisfied a group is a byte sequence the string requires,
    /// so any of them can serve as the witness — but their occurrence counts
    /// differ, and only the rarest is likely to be within the cap. So the one
    /// on record is replaced whenever a rarer candidate turns up, which costs a
    /// comparison per satisfying atom and is what makes a string with a common
    /// alternative and a rare one localizable at all.
    ///
    /// Counts only grow during a scan, so an atom that was the rarest when it
    /// was recorded can stop being so later. That costs the localization, not
    /// the answer: [`Prefilter::witnesses`] re-checks the count of whichever
    /// atom is on record, and falls back to a full search when it has grown
    /// past the cap.
    fn set_witness(&mut self, string: u32, atom: u32) {
        let string = string as usize;
        if self.string_witness_epoch[string] == self.epoch {
            let current = self.string_witness[string] as usize;
            if self.atom_count[current] <= self.atom_count[atom as usize] {
                return;
            }
        }
        self.string_witness[string] = atom;
        self.string_witness_epoch[string] = self.epoch;
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
        debug_assert!(
            needed > 0,
            "a rule with no refutable required strings is unfiltered"
        );
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
    /// Most of the tests below are about what the search and the per-string
    /// state machine do, which is the disjunctive path. The conjunctive path
    /// has its own tests, which build their rules directly.
    fn filters(rules: &[RuleStrings]) -> Vec<RuleFilter> {
        rules.iter().cloned().map(RuleFilter::of).collect()
    }

    /// A string that requires `bytes`.
    fn one(bytes: &[u8]) -> StringAtoms {
        StringAtoms {
            groups: vec![vec![
                best_atom(bytes, false).expect("test atom must be long enough")
            ]],
        }
    }

    /// A string that requires `bytes` case-insensitively.
    fn one_nocase(bytes: &[u8]) -> StringAtoms {
        StringAtoms {
            groups: vec![vec![
                best_atom(bytes, true).expect("test atom must be long enough")
            ]],
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
        // of strings sharing a prefix — `marker00`, `marker01` — is covered by
        // the test below instead: those share a window, and the atom's trailer
        // is what tells them apart.
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
    fn strings_that_differ_only_at_the_end_are_told_apart() {
        // Eight rules whose only difference is at the end. Before the atom
        // carried the bytes that follow it, all eight shared one four-byte atom
        // and any file containing the prefix selected all of them, so the
        // prefilter saved nothing for a family of rules like this — which is
        // exactly the shape of a rule set with a variant per family member.
        //
        // The bytes after the window are as mandatory as the window itself, so
        // they belong to the atom: the eight literals now have eight atoms and
        // a file selects the one rule that is actually about it.
        let needles: Vec<Vec<u8>> = (0..8u8)
            .map(|i| format!("marker{i:02}").into_bytes())
            .collect();
        let rules: Vec<RuleStrings> = needles.iter().map(|n| vec![one(n)]).collect();
        let p = Prefilter::build(&filters(&rules));
        assert_eq!(p.stats().atoms, 8, "eight strings, eight atoms");
        assert_eq!(
            scan(&p, b"marker03"),
            vec![3],
            "and only one of them selected"
        );
        for (index, needle) in needles.iter().enumerate() {
            let mut file = b"padding ".to_vec();
            file.extend_from_slice(needle);
            file.extend_from_slice(b" more padding");
            assert_eq!(scan(&p, &file), vec![index as u32], "rule {index}");
        }
    }

    /// Four bytes of a string are not the string's atom.
    ///
    /// This is the property the trailer exists for, and it is worth a test of
    /// its own because it is what a file full of library code meets: a large
    /// binary contains short windows of hundreds of strings by accident, and
    /// each one used to cost a pass over the whole buffer to disprove.
    #[test]
    fn a_bare_window_is_not_the_atom() {
        let atoms = StringAtoms {
            groups: vec![vec![Atom::with_trailer(b"ABCD", false, b"EFGH").unwrap()]],
        };
        let p = Prefilter::build(&filters(&[vec![atoms]]));
        assert!(
            scan(&p, b"ABCD").is_empty(),
            "the four bytes alone are not the atom"
        );
        assert!(
            scan(&p, b"ABCD EFGH").is_empty(),
            "nor are they when the rest is somewhere else in the file"
        );
        assert_eq!(scan(&p, b"ABCDEFGH"), vec![0], "the atom, and the rule");
    }

    /// The trailer is verified, not merely required to be somewhere.
    ///
    /// Two atoms that differ only in the bytes after them are different atoms.
    /// If they were the same the prefilter would have to be satisfied by either
    /// one's trailer, which would put the false selects back.
    #[test]
    fn atoms_that_differ_only_in_their_trailer_are_different_atoms() {
        let first = StringAtoms {
            groups: vec![vec![Atom::with_trailer(b"ABCD", false, b"EFGH").unwrap()]],
        };
        let second = StringAtoms {
            groups: vec![vec![Atom::with_trailer(b"ABCD", false, b"IJKL").unwrap()]],
        };
        let p = Prefilter::build(&filters(&[vec![first], vec![second]]));
        assert_eq!(p.stats().atoms, 2);
        assert_eq!(scan(&p, b"ABCDEFGH"), vec![0]);
        assert_eq!(scan(&p, b"ABCDIJKL"), vec![1]);
        assert!(scan(&p, b"ABCD").is_empty(), "neither trailer is there");
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
    fn the_same_atom_in_two_rules_is_one_search_entry() {
        // `kernel32.dll` is in hundreds of rules; carrying it hundreds of times
        // would multiply the search's tables for nothing.
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
        let p = Prefilter::build(&[
            RuleFilter::of(vec![one(b"alpha"), one(b"bravo")]).requiring(vec![0, 1])
        ]);
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
        let p =
            Prefilter::build(
                &[RuleFilter::of(vec![one(b"alpha"), opaque()]).requiring(vec![0, 1])],
            );
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
        let p = Prefilter::build(&[
            RuleFilter::of(vec![one(b"alpha"), one(b"bravo")]).requiring(vec![0, 0])
        ]);
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
        let p = Prefilter::build(&[
            RuleFilter::of(vec![one(b"alpha"), one(b"bravo")]).requiring(vec![0, 1])
        ]);
        assert_eq!(scan(&p, b"alpha bravo alpha bravo"), vec![0]);
    }

    /// The state must not survive from one scan into the next.
    ///
    /// The tally counts down over a scan and is reset by the epoch, not by a
    /// loop. A tally that survived would make every later scan select the rule
    /// on the first of its strings.
    #[test]
    fn a_second_scan_does_not_inherit_the_first_ones_tally() {
        let p = Prefilter::build(&[
            RuleFilter::of(vec![one(b"alpha"), one(b"bravo")]).requiring(vec![0, 1])
        ]);
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

    // -- the witness --------------------------------------------------------

    /// Every occurrence of `needle` in `data`, in order.
    ///
    /// The strings these tests use are four bytes, which is `MAX_ATOM_LEN`, so
    /// the atom *is* the string and the atom's offsets are also the match's.
    /// That is what lets these assert on exact offsets. The correction for a
    /// longer literal, where the atom is a window somewhere inside it, belongs
    /// to `matcher::text` and is tested there.
    fn every_offset(needle: &[u8], data: &[u8]) -> Vec<u32> {
        assert_eq!(
            best_atom(needle, false)
                .expect("a four-byte needle has an atom")
                .bytes
                .as_slice(),
            needle,
            "these tests assume a four-byte string's atom is the whole string"
        );
        memchr::memmem::find_iter(data, needle)
            .map(|at| u32::try_from(at).expect("the test buffer is small"))
            .collect()
    }

    /// What the prefilter says the offsets of slot 0 of rule 0 are.
    fn witnesses_of(p: &Prefilter, scratch: &PrefilterScratch) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        p.witnesses(scratch, 0, 0, &mut out).then_some(out)
    }

    /// Run a scan and hand back the scratch, so a test can query it afterwards.
    fn scan_keeping_scratch(
        prefilter: &Prefilter,
        data: &[u8],
        scratch: &mut PrefilterScratch,
    ) -> Vec<u32> {
        let mut out = Vec::new();
        prefilter.candidates(data, scratch, &mut out);
        out
    }

    #[test]
    fn a_witness_is_reported_for_a_string_whose_atom_occurs_once() {
        // The case the scanner's shortcut is for: the search saw the atom
        // exactly once, so every match of the string must contain that one
        // occurrence and the search is a few byte comparisons instead of a pass
        // over the buffer.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let data = b"xxatomxx";
        let mut scratch = p.scratch();
        assert_eq!(scan_keeping_scratch(&p, data, &mut scratch), vec![0]);
        assert_eq!(
            witnesses_of(&p, &scratch),
            Some(every_offset(b"atom", data))
        );
    }

    #[test]
    fn an_atom_that_occurs_several_times_yields_all_of_them() {
        // The general case, and the one that matters on a real file: a
        // four-byte atom in a large binary usually occurs more than once. Every
        // occurrence is somewhere a match must reach, so every occurrence is a
        // candidate — reporting only the first would lose the match at the
        // second, which is the failure mode the single-occurrence version had
        // to avoid by refusing to answer at all.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let data = b"atom and atom and atom";
        let mut scratch = p.scratch();
        assert_eq!(scan_keeping_scratch(&p, data, &mut scratch), vec![0]);
        assert_eq!(
            witnesses_of(&p, &scratch),
            Some(every_offset(b"atom", data)),
            "all three, in the order the search met them"
        );
    }

    #[test]
    fn an_atom_that_occurs_nowhere_yields_no_witness() {
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let mut scratch = p.scratch();
        assert!(scan_keeping_scratch(&p, b"nothing relevant", &mut scratch).is_empty());
        assert_eq!(witnesses_of(&p, &scratch), None);
    }

    #[test]
    fn an_atom_that_occurs_too_often_yields_no_witness() {
        // Past the cap the later offsets are not kept, and a list that is
        // missing an occurrence is a list that would send the matcher past a
        // match. So the answer has to be "search for it" rather than a partial
        // list — the count is what makes that decision possible.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let mut data = Vec::new();
        for _ in 0..WITNESS_CAP + 1 {
            data.extend_from_slice(b"atom ");
        }
        let mut scratch = p.scratch();
        assert_eq!(scan_keeping_scratch(&p, &data, &mut scratch), vec![0]);
        assert_eq!(
            witnesses_of(&p, &scratch),
            None,
            "{} occurrences is one more than the cap",
            WITNESS_CAP + 1
        );
    }

    #[test]
    fn an_atom_at_exactly_the_cap_yields_all_of_them() {
        // The boundary, from the side that must still work: the cap'th
        // occurrence is kept, so the list is complete and usable. An off-by-one
        // in the comparison would throw away every localization at the cap.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let mut data = Vec::new();
        for _ in 0..WITNESS_CAP {
            data.extend_from_slice(b"atom ");
        }
        let mut scratch = p.scratch();
        assert_eq!(scan_keeping_scratch(&p, &data, &mut scratch), vec![0]);
        assert_eq!(
            witnesses_of(&p, &scratch),
            Some(every_offset(b"atom", &data)),
            "a full list is usable; it is only an incomplete one that is not"
        );
    }

    #[test]
    fn a_string_whose_groups_were_not_all_satisfied_has_no_witness() {
        // The atom matched, but the string as a whole cannot match, so there is
        // no match for the witness to point at. The two answers are separate:
        // `string_state` says `Absent`, and the witness must agree by saying
        // nothing.
        let atoms = StringAtoms {
            groups: vec![
                vec![best_atom(b"atom", false).unwrap()],
                vec![best_atom(b"beta", false).unwrap()],
            ],
        };
        let p = Prefilter::build(&filters(&[vec![atoms]]));
        let data = b"atom but not the other one";
        let mut scratch = p.scratch();
        scan_keeping_scratch(&p, data, &mut scratch);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Absent);
        assert_eq!(witnesses_of(&p, &scratch), None);
    }

    #[test]
    fn a_string_with_no_atoms_has_no_witness() {
        // Nothing was ever searched for, so nothing was seen and there is no
        // offset to report. `Unknown` is the state, and it must not be read as
        // "seen once at zero".
        let p = Prefilter::build(&filters(&[vec![opaque()]]));
        let data = b"any data at all";
        let mut scratch = p.scratch();
        scan_keeping_scratch(&p, data, &mut scratch);
        assert_eq!(p.string_state(&scratch, 0, 0), StringState::Unknown);
        assert_eq!(witnesses_of(&p, &scratch), None);
    }

    #[test]
    fn a_witness_belongs_to_the_scan_that_produced_it() {
        // Two files in a row, the second without the atom. The first scan's
        // witness is stamped with the first scan's epoch, so the second must
        // not read it — a stale offset would send the matcher to the wrong
        // place in a buffer it has never seen, which is a missed detection.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let mut scratch = p.scratch();
        assert_eq!(
            scan_keeping_scratch(&p, b"xxatomxx", &mut scratch),
            vec![0],
            "the first file selects"
        );
        assert!(witnesses_of(&p, &scratch).is_some());
        assert!(
            scan_keeping_scratch(&p, b"this buffer has nothing in it", &mut scratch).is_empty(),
            "the second file does not"
        );
        assert_eq!(witnesses_of(&p, &scratch), None);
    }

    #[test]
    fn a_witness_for_a_slot_or_rule_that_does_not_exist_is_none() {
        // A program and a prefilter that disagree about the shape of the rule
        // set is a corrupt database. The answer that costs a full search is
        // right; the answer that indexes out of bounds is not.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let data = b"xxatomxx";
        let mut scratch = p.scratch();
        scan_keeping_scratch(&p, data, &mut scratch);
        let mut out = Vec::new();
        assert!(!p.witnesses(&scratch, 0, 1, &mut out), "slot past the end");
        assert!(!p.witnesses(&scratch, 1, 0, &mut out), "rule past the end");
        assert!(!p.witnesses(&scratch, u32::MAX, 0, &mut out));
    }

    #[test]
    fn a_query_leaves_nothing_of_the_previous_answer_in_the_buffer() {
        // The buffer is reused across strings, so a query that appended instead
        // of replacing would hand the matcher the previous string's offsets.
        // Those are offsets into the same buffer, so they would not be
        // out-of-range failures — they would be silent wrong answers.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let mut scratch = p.scratch();
        scan_keeping_scratch(&p, b"xxatomxx", &mut scratch);
        let mut out = Vec::new();
        assert!(p.witnesses(&scratch, 0, 0, &mut out));
        assert_eq!(out.len(), 1);
        assert!(!p.witnesses(&scratch, 0, 1, &mut out), "no such slot");
        assert!(out.is_empty(), "the failed query must have cleared it");
    }

    #[test]
    fn a_witness_is_the_offset_where_the_atom_was_found() {
        // Checked at the start of a buffer, at the end, and deep inside one —
        // an offset stored as anything narrower than the buffer length would
        // fail at the last of these.
        let p = Prefilter::build(&filters(&[vec![one(b"atom")]]));
        let at_the_start = b"atom then padding".to_vec();
        let deep_inside = {
            let mut data = vec![b'a'; 4096];
            data.extend_from_slice(b"atom");
            data
        };
        let at_the_end = {
            let mut data = vec![b'z'; 7];
            data.extend_from_slice(b"atom");
            data
        };
        for data in [at_the_start, deep_inside, at_the_end] {
            let mut scratch = p.scratch();
            assert_eq!(scan_keeping_scratch(&p, &data, &mut scratch), vec![0]);
            assert_eq!(
                witnesses_of(&p, &scratch),
                Some(every_offset(b"atom", &data)),
                "in a buffer of {} bytes",
                data.len()
            );
        }
    }
}
