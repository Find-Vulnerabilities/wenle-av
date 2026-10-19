//! Running a rule set against a buffer.
//!
//! The scanner is the three stages of the pipeline joined together: the
//! prefilter chooses which rules are worth looking at, the matchers find the
//! strings of those rules, and the virtual machine decides whether the
//! conditions hold. Each stage is tested on its own; this is where they meet,
//! and where the mistakes that only exist between them would live.
//!
//! # The order of the stages is the cost model
//!
//! ```text
//!   1 MiB buffer
//!        │  prefilter         one pass, every atom            ~20 ms
//!        ▼
//!   ~2.5% of the rule set
//!        │  matchers          only strings the atoms allowed   ~1 ms
//!        ▼
//!   candidate rules with their strings found
//!        │  VM                one straight-line program each   ~10 µs
//!        ▼
//!   matches
//! ```
//!
//! Two things keep the middle stage from undoing the first. The prefilter does
//! not merely select rules — it reports, per string, whether the string can
//! still match, so a rule selected on one weak atom does not drag its six
//! sibling strings through a search each. And the matchers run only for strings
//! the prefilter could not refute, which on a clean file is very few.
//!
//! # Global and private rules
//!
//! A `global` rule gates the whole file: if it does not match, nothing else is
//! considered. It is evaluated first and unconditionally, which means the
//! prefilter is not allowed to filter it — a global rule that the prefilter
//! skipped would leave the gate silently open.
//!
//! A `private` rule is evaluated and its result is kept, but it is never
//! reported. That the engine still runs it is the point: a private rule is how
//! a rule set writes a helper, and dropping it would change what the rules that
//! depend on it mean.

use crate::database::{CompiledRule, RuleDatabase};
use crate::matches::MatchSet;
use crate::prefilter::StringState;
use crate::sweep::{LiteralSweep, SweepHits};
use crate::vm::{Input, Vm};

/// What a rule's match means, which is not always "a detection".
///
/// A rule set uses these two constructs to say something *about other rules*,
/// and reporting either of them as a finding is a false positive by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchRole {
    /// A detection. Report it and score it.
    Detection,
    /// A `private rule`: a helper the rule set uses internally. It is real and
    /// was evaluated — the condition of some other rule may depend on it — but
    /// it is not a finding.
    Helper,
    /// A `global rule` that held. It gates the rest of the rule set and is not
    /// itself a finding: a gate is normally a statement of file type, so
    /// reporting it would flag every executable on the machine.
    Gate,
}

impl MatchRole {
    pub const fn is_reportable(self) -> bool {
        matches!(self, MatchRole::Detection)
    }
}

/// One rule whose condition held.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Index into the database's rules.
    pub rule: u32,
    /// Where each string of the rule was found, indexed by slot.
    pub strings: MatchSet,
    pub role: MatchRole,
}

impl RuleMatch {
    /// Whether this match should reach the user.
    pub fn is_reportable(&self) -> bool {
        self.role.is_reportable()
    }
}

/// What one scan did.
#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub matches: Vec<RuleMatch>,
    /// Rules the prefilter selected.
    pub candidates: usize,
    /// Rules whose conditions the virtual machine evaluated. Lower than
    /// `candidates` when a rule's strings were all refuted by the prefilter
    /// before the machine was reached.
    pub evaluated: usize,
    /// Strings of *evaluated rules* that the prefilter proved absent, so no
    /// search was run for them.
    ///
    /// Only evaluated rules, because a rule the prefilter rejected outright
    /// never reaches the per-string step — and for such a rule every string was
    /// refuted, so counting them here would make this number mostly a
    /// restatement of `candidates` rather than a measure of searching avoided.
    pub strings_refuted: usize,
    /// Strings that were searched for.
    pub strings_searched: usize,
    /// Of those, the ones that did not have to scan the buffer.
    ///
    /// A string whose atom the automaton found exactly once is verified at the
    /// one offset that occurrence allows, instead of being searched for. When
    /// this is a large fraction of `string_searched`, the scan is bounded by
    /// the automaton pass rather than by the per-string searches, which is the
    /// difference between a scan measured in milliseconds and one measured in
    /// seconds.
    pub strings_localized: usize,
    /// Strings answered by the literal sweep instead of a search of their own.
    ///
    /// Every literal form in the rule set goes into one automaton, and one pass
    /// over the buffer finds the occurrences of all of them. A string the
    /// automaton carries is decided by that pass, so it costs the buffer once
    /// for the whole rule set rather than once per string — which is the
    /// difference between a scan that is linear in the file and one that is
    /// linear in the file times the rule set.
    ///
    /// These are deliberately *not* in `strings_searched`. That counter is the
    /// multiplier in the cost model the bench reports — `strings × size` — and
    /// keeping swept strings in it would leave the arithmetic reading as if the
    /// work had still been done. A string counted here was not searched for, and
    /// not refuted either: it was found, or proved absent, by the pass that had
    /// already happened.
    pub strings_swept: usize,
    /// Strings whose matcher gave up before finishing its search.
    ///
    /// A hex pattern with enough jumps that the number of ways it can align
    /// against a buffer exceeds the search budget. The matches found are real,
    /// but they are not all of them, so `#a` is an undercount and a rule
    /// depending on it may fail to fire. Counted rather than swallowed for the
    /// same reason as `vm_failures`: a rule that cannot run is a detection that
    /// cannot fire, and silence about it is how one goes unnoticed.
    pub matcher_failures: usize,
    /// Rules whose condition could not be evaluated because the bytecode is
    /// malformed. A corrupt database, never a property of the file — see
    /// [`crate::vm::VmError`]. Counted rather than swallowed, because a rule that cannot
    /// run is a detection that cannot fire.
    pub vm_failures: usize,
    /// A global rule did not match, so no other rule was allowed to.
    pub global_gate_failed: bool,
}

impl ScanOutcome {
    /// Whether anything detected.
    pub fn detected(&self) -> bool {
        self.matches.iter().any(RuleMatch::is_reportable)
    }

    /// The rules to report.
    pub fn reportable(&self) -> impl Iterator<Item = &RuleMatch> {
        self.matches.iter().filter(|m| m.is_reportable())
    }
}

/// Scans buffers against one rule set.
///
/// Holds the working state a scan needs — the prefilter's stamps, the operand
/// stack, the candidate list, the per-rule match table — so that scanning a
/// file allocates nothing. Make one per thread and keep it.
#[derive(Debug)]
pub struct Scanner<'a> {
    database: &'a RuleDatabase,
    vm: Vm,
    scratch: crate::prefilter::PrefilterScratch,
    candidates: Vec<u32>,
    /// The match table for the rule being evaluated, reused across rules.
    working: MatchSet,
    /// Where the prefilter says the current string's matches could be. Reused
    /// across strings, and empty whenever the search is done the ordinary way.
    witnesses: Vec<u32>,
    /// The literal automatons, and this thread's rows of what they found.
    ///
    /// The automatons belong to the database and are shared; the rows are this
    /// scanner's, and they are what a scan writes.
    sweep: &'a LiteralSweep,
    hit_rows: SweepHits,
    /// Search for every string one at a time, the way the engine did before the
    /// sweep existed. See [`Scanner::without_sweep`].
    no_sweep: bool,
    /// Resolved once, because the prefilter must not be allowed to filter a
    /// global rule and asking "which rules are global" per scan would be a
    /// linear pass over the rule set per file.
    globals: Vec<u32>,
    /// Skip every filter and search for everything. See [`Scanner::unfiltered`].
    unfiltered: bool,
}

impl<'a> Scanner<'a> {
    pub fn new(database: &'a RuleDatabase) -> Self {
        Self {
            scratch: database.prefilter().scratch(),
            candidates: Vec::new(),
            working: MatchSet::default(),
            witnesses: Vec::new(),
            sweep: database.sweep(),
            hit_rows: database.sweep().hits(),
            no_sweep: false,
            globals: database
                .rules()
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.global)
                .map(|(index, _)| index as u32)
                .collect(),
            unfiltered: false,
            vm: Vm::new(),
            database,
        }
    }

    /// A scanner that believes every rule is a candidate and every string may
    /// be in the file, so the prefilter decides nothing.
    ///
    /// This is the honest baseline the filtered scanner is measured against,
    /// and the only practical way to test that the filtering is
    /// *sound* rather than merely fast. Every filter here is an optimization
    /// that can lose a detection if it is wrong, and a lost detection is the
    /// one failure an antivirus cannot have: it says a file is clean when it is
    /// not, and nothing downstream will ever notice.
    ///
    /// The argument for each filter is a proof, but a proof is only as good as
    /// its premises — the atom really is a window of the string, the trailer
    /// really is implied by any match, the automaton really did see every
    /// occurrence. Running both scanners over the same file and comparing the
    /// reported matches checks the conclusion against the data instead, and it
    /// covers every filter at once rather than one at a time. It is slow by
    /// construction, which is what makes it a test rather than a mode.
    pub fn unfiltered(database: &'a RuleDatabase) -> Self {
        Self {
            unfiltered: true,
            ..Self::new(database)
        }
    }

    /// A scanner that searches for every string one at a time, as the engine
    /// did before the literal automaton existed.
    ///
    /// The sweep replaces a search per string with one pass over the buffer, and
    /// it is an optimization of exactly the kind that can lose a detection: an
    /// overlapping occurrence the automaton failed to report, a `fullword` hit
    /// accepted through a word character, a row that still holds the previous
    /// file's offsets. Each of those arguments is sound as written, and a
    /// soundness argument is only as good as its premises.
    ///
    /// So the per-string path is kept, and the differential test in this file
    /// runs both over the same binaries and compares every reported rule and
    /// every offset. It is slower by the amount the sweep saves, which is what
    /// makes it a test rather than a mode.
    pub fn without_sweep(database: &'a RuleDatabase) -> Self {
        Self {
            no_sweep: true,
            ..Self::new(database)
        }
    }

    pub fn database(&self) -> &'a RuleDatabase {
        self.database
    }

    /// Deepest the interpreter's operand stack has been, across every scan this
    /// scanner has run. For tuning `Program::max_stack` against reality.
    pub fn peak_stack(&self) -> usize {
        self.vm.peak_stack
    }

    /// Scan one buffer.
    pub fn scan(&mut self, data: &[u8]) -> ScanOutcome {
        self.scan_with(data, &Input::new(data))
    }

    /// Scan one buffer with a known entry point, for `entrypoint` in a
    /// condition.
    pub fn scan_with(&mut self, data: &[u8], input: &Input<'_>) -> ScanOutcome {
        // One verdict per corpus rule, refusals included: these are the slots
        // `Op::RuleRef` indexes, so a rule written in terms of another rule
        // reads what this scan recorded for it. Sized from the database rather
        // than from the number of rules that will be tried, because the two
        // differ by every refused rule and it is the corpus position that a
        // reference carries.
        self.vm.begin_scan(self.database.result_len());
        self.scan_rules(data, input)
    }

    /// The scan itself, over a `vm` whose result slots are already sized.
    fn scan_rules(&mut self, data: &[u8], input: &Input<'_>) -> ScanOutcome {
        let mut outcome = ScanOutcome::default();

        // One pass over the buffer against every literal form in the rule set,
        // before any rule is looked at.
        //
        // Here rather than per rule because the pass is the same whatever is
        // being searched for: its cost is the buffer, and its result is the
        // occurrences of every string in the rule set. Before the global rules
        // rather than after them, because a gate's strings are searched for like
        // any other rule's.
        //
        // It runs for the unfiltered scanner too, even though that one exists to
        // be an honest baseline. What `unfiltered` removes is the prefilter's
        // *selection*, and running both scanners with the sweep is what keeps
        // that comparison about one thing: a sweep mistake present on both sides
        // is invisible there and is what `without_sweep` is for.
        if !self.no_sweep {
            self.sweep.run(data, &mut self.hit_rows);
        }

        // Global rules first, and not through the prefilter's selection: a
        // global rule the prefilter skipped would leave the gate open. They are
        // chosen by the database rather than by the buffer, so this is the same
        // short list every time.
        // Indexed rather than iterated: the list lives in `self` and
        // `evaluate` needs `self` mutably.
        for index in 0..self.globals.len() {
            let rule = self.globals[index];
            outcome.candidates += 1;
            if !self.evaluate_recording(rule, data, input, &mut outcome) {
                outcome.global_gate_failed = true;
                return outcome;
            }
        }

        if self.unfiltered {
            // Every rule, in order, with nothing ruled out. The candidate
            // count still reports the rule set, because that is what the
            // prefilter would have been handed.
            outcome.candidates += self.database.rules().len();
            for rule in 0..self.database.rules().len() as u32 {
                if self.database.rule(rule).is_some_and(|r| r.global) {
                    continue;
                }
                let _matched = self.evaluate_recording(rule, data, input, &mut outcome);
            }
            return outcome;
        }

        self.database
            .prefilter()
            .candidates(data, &mut self.scratch, &mut self.candidates);
        outcome.candidates += self.candidates.len();

        for index in 0..self.candidates.len() {
            let rule = self.candidates[index];
            if self.database.rule(rule).is_some_and(|r| r.global) {
                // Already evaluated above. Running it twice would be harmless
                // except for the counters, and matching its strings twice is
                // not free.
                continue;
            }
            // Whether it matched, and the match itself, are recorded by
            // `evaluate`; the caller has nothing left to decide.
            let _matched = self.evaluate_recording(rule, data, input, &mut outcome);
        }

        outcome
    }

    /// Evaluate one rule, and leave its verdict where a rule that reads it will
    /// find it.
    ///
    /// The write happens after the machine has run, never before: a rule that
    /// read its own slot mid-evaluation would be reading a default rather than a
    /// verdict. The corpus refuses a rule that reads itself, so this is not the
    /// rule that catches that — it is what makes the array's contents a function
    /// of the rule set alone, whatever order the candidates arrive in.
    fn evaluate_recording(
        &mut self,
        rule_index: u32,
        data: &[u8],
        input: &Input<'_>,
        outcome: &mut ScanOutcome,
    ) -> bool {
        let matched = self.evaluate(rule_index, data, input, outcome);
        if let Some(rule) = self.database.rule(rule_index) {
            self.vm.record(rule.corpus_index, matched);
        }
        matched
    }

    /// Match a rule's strings and run its condition. Returns whether it held.
    ///
    /// Records the match in `outcome` when it did.
    ///
    /// # Why the required strings are searched first
    ///
    /// A rule is a candidate because the prefilter could not rule it out, which
    /// on a large binary is still thousands of rules. Each one that survives
    /// costs a search for every string whose atoms were present, and then a
    /// run of the machine — and almost all of them are candidates that will not
    /// match. The great majority of conditions in a real rule set say
    /// `$a and $b and $c and pe.something`, so the first string that turns out
    /// to be absent settles the rule: the condition is false whatever the rest
    /// of the file contains, and neither the remaining searches nor the machine
    /// can change that.
    ///
    /// The slots that can settle it are exactly the ones
    /// [`crate::compiler::required_slots`] proved the condition cannot be true
    /// without, which the prefilter is already carrying. Reading them here
    /// turns an average of four searches and a machine run per candidate into
    /// one search for the ones that fail, which on `shell32.dll` is nearly all
    /// of them.
    fn evaluate(
        &mut self,
        rule_index: u32,
        data: &[u8],
        input: &Input<'_>,
        outcome: &mut ScanOutcome,
    ) -> bool {
        let Some(rule) = self.database.rule(rule_index) else {
            return false;
        };

        self.working.reset(rule.program.string_count as usize);
        let required = &rule.program.required_strings;

        // Sound because `required_slots` only ever lists a slot the condition
        // cannot be true without, so a rule that matches has all of them
        // matching: bailing out here can only drop rules that were going to
        // fail.
        for slot in required {
            if !self.search_string(rule, rule_index, *slot, data, outcome) {
                return false;
            }
        }
        for slot in 0..rule.program.string_count {
            if required.contains(&slot) {
                // Already searched above, and its matches are in the table.
                continue;
            }
            // Optional: the condition can hold without it, so whether it was
            // found changes nothing about reaching the machine. The matches, if
            // any, are in the table for the machine to read.
            let _ = self.search_string(rule, rule_index, slot, data, outcome);
        }

        outcome.evaluated += 1;
        match self.vm.run(&rule.program, &self.working, input) {
            Ok(false) => false,
            Ok(true) => {
                let role = if rule.global {
                    MatchRole::Gate
                } else if rule.private {
                    MatchRole::Helper
                } else {
                    MatchRole::Detection
                };
                outcome.matches.push(RuleMatch {
                    rule: rule_index,
                    strings: self.working.clone(),
                    role,
                });
                true
            }
            Err(e) => {
                // A malformed program, never a property of the file. Counted
                // and treated as "did not match": the alternative is a scanner
                // that dies on a file somebody opened, and a corrupt rule that
                // fired on everything would be worse.
                log::warn!("rule {} could not be evaluated: {e}", rule.name);
                outcome.vm_failures += 1;
                false
            }
        }
    }

    /// Search for one of a rule's strings, and say whether it is there.
    ///
    /// Four things can settle a string. The sweep can hand over what its
    /// automaton found, the atoms can refute it, or the matcher can refuse it —
    /// and none of those three costs a search. Only the fourth, a search that
    /// runs, costs anything, and the return value does not distinguish between
    /// them, because the caller is asking one question: can the condition see
    /// this string at all.
    ///
    /// The counters do distinguish them, so that a scan can be read back and
    /// the work attributed.
    ///
    /// The prefilter's verdict on one string, which is `Unknown` when the
    /// filter is switched off: nothing was proved, so the string has to be
    /// searched for.
    fn string_state(&self, rule_index: u32, slot: u32) -> StringState {
        if self.unfiltered {
            return StringState::Unknown;
        }
        self.database
            .prefilter()
            .string_state(&self.scratch, rule_index, slot)
    }

    #[must_use]
    fn search_string(
        &mut self,
        rule: &CompiledRule,
        rule_index: u32,
        slot: u32,
        data: &[u8],
        outcome: &mut ScanOutcome,
    ) -> bool {
        match self.string_state(rule_index, slot) {
            // The atoms were all found, so the string may be there; and the
            // string has no atoms, so nothing could be said either way. Both
            // have to be searched for.
            StringState::Possible | StringState::Unknown => {}
            StringState::Absent => {
                // A group had no atom present, so the string cannot be here.
                // This is the whole reason the per-string state exists: the
                // search is the expensive half and it would find nothing.
                outcome.strings_refuted += 1;
                return false;
            }
        }

        let Some(matcher) = rule.matcher(slot) else {
            // The matcher refused this string when it was compiled — a
            // construct the engine cannot search for. The slot stays empty, so
            // the condition sees the string as never matching, which is the
            // honest reading.
            return false;
        };

        // The automaton pass has already looked for every literal form this
        // string can take, so its occurrences are known without going over the
        // buffer again. `None` means the sweep does not answer this string — a
        // hex pattern, a regex, one the matcher refused — and the search below
        // is what it gets.
        //
        // Asked after the prefilter's verdict rather than before it: a string
        // the atoms refuted has nothing to find, so moving it out of
        // `strings_refuted` and into `strings_swept` would cost that counter its
        // meaning — "the prefilter proved these absent" — to save nothing.
        if !self.no_sweep {
            if let Some(found) = self.sweep.matches(&self.hit_rows, rule_index, slot) {
                for m in found {
                    self.working.push(slot, *m);
                }
                outcome.strings_swept += 1;
                return !found.is_empty();
            }
        }

        outcome.strings_searched += 1;
        // If the automaton saw every occurrence of this string's atom, they say
        // where the string can be, and the search collapses to a few byte
        // comparisons each. This is the difference between a scan that costs
        // the buffer size per string and one that costs the string.
        let located = !self.unfiltered
            && matcher.can_use_witness()
            && self.database.prefilter().witnesses(
                &self.scratch,
                rule_index,
                slot,
                &mut self.witnesses,
            );
        match located {
            // A witnessed search is a handful of byte comparisons per
            // candidate, so it cannot run out of budget.
            true => {
                outcome.strings_localized += 1;
                for offset in &self.witnesses {
                    matcher.find_all_from_witness(data, *offset, &mut self.working);
                }
            }
            // Nothing to derive the position from, so the honest answer is a
            // search. Not a fallback in the sense of a degraded mode: it is
            // what every string did before, and most still do.
            false => {
                if !matcher.find_all(data, &mut self.working) {
                    outcome.matcher_failures += 1;
                }
            }
        }

        self.working.count(slot) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::RuleDatabase;

    fn scan(source: &str, data: &[u8]) -> (ScanOutcome, RuleDatabase) {
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        let mut scanner = Scanner::new(&db);
        let outcome = scanner.scan(data);
        (outcome, db)
    }

    /// The same scan with the literal sweep switched off.
    ///
    /// For the tests that are about the per-string path the sweep stands in for:
    /// the witness offsets, and the counters that say how a string was found. A
    /// literal string never reaches the matcher on an ordinary scanner — the
    /// sweep answers it from the pass it already made — so a test of the matcher
    /// has to ask for the scanner that still calls it.
    fn scan_without_sweep(source: &str, data: &[u8]) -> (ScanOutcome, RuleDatabase) {
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        let mut scanner = Scanner::without_sweep(&db);
        let outcome = scanner.scan(data);
        (outcome, db)
    }

    /// The names of the rules that *detected*, in order, for a readable
    /// assertion. Gates and helpers are deliberately left out: they are not
    /// findings, and a helper that collected them would let a test pass while
    /// the engine reported a file-type gate as malware.
    fn matched(source: &str, data: &[u8]) -> Vec<String> {
        let (outcome, db) = scan(source, data);
        outcome
            .reportable()
            .map(|m| db.rule(m.rule).unwrap().name.clone())
            .collect()
    }

    const NEEDLE: &str = r#"
rule needle {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
"#;

    #[test]
    fn a_rule_matches_when_its_string_is_present() {
        assert_eq!(
            matched(NEEDLE, b"prefix this is a needle suffix"),
            ["needle"]
        );
        assert!(matched(NEEDLE, b"nothing of interest here").is_empty());
    }

    /// The whole point of the split: a string the atoms refuted is not
    /// searched for at all.
    ///
    /// The rule is `$a and ($b or $c)`. The condition cannot be read as
    /// requiring `$b` or `$c` — either one will do — so the prefilter's
    /// conjunctive test can only demand `$a`, and the rule stays a candidate on
    /// `$a` alone. That is the case where the per-string handover earns its
    /// keep: two of the three strings are provably absent and are never
    /// searched for, and the machine is still the thing that decides the rule
    /// does not match.
    #[test]
    fn a_string_the_atoms_refuted_is_not_searched_for() {
        let source = r#"
rule two {
    strings:
        $a = "aaaaaaaaaaaa"
        $b = "bbbbbbbbbbbb"
        $c = "cccccccccccc"
    condition:
        $a and ($b or $c)
}
"#;
        let (outcome, _) = scan(source, b"has aaaaaaaaaaaa but not the others");
        assert_eq!(
            outcome.candidates, 1,
            "selected on $a, the one string it needs"
        );
        // `$a` is a literal, so the sweep answers it from the pass it already
        // made and no search runs for it either. What this test is about is the
        // two strings that were never looked for at all, and they are still
        // refuted rather than swept: a string the atoms proved absent is settled
        // before the sweep is consulted.
        assert_eq!(outcome.strings_searched, 0);
        assert_eq!(outcome.strings_swept, 1, "$a, from the automaton");
        assert_eq!(outcome.strings_refuted, 2, "$b and $c, never looked for");
        assert!(outcome.matches.is_empty(), "neither $b nor $c is present");
    }

    /// A string whose atom occurrences the prefilter knows is not searched for
    /// across the whole file.
    ///
    /// The prefilter's automaton already visited every byte, so it knows where
    /// the atom matched. Every one of those places is somewhere a match of the
    /// string must reach, so the match starts are derivable and the matcher
    /// only has to verify a few candidate offsets instead of passing over the
    /// buffer again. On a large binary that second pass is the scan's whole
    /// cost, because it is memory bandwidth.
    ///
    /// The string is ten bytes and every one of its four-byte windows is
    /// distinct from the padding, so the test does not depend on which window
    /// the atom chooser picks: whichever it is, it occurs exactly once in the
    /// first buffer and twice in the second.
    ///
    /// Run without the sweep, because the sweep answers this string from the
    /// pass it already made and the witness path would never be reached. What is
    /// under test is the path a string takes when the automaton cannot carry it
    /// — which is every hex pattern and every regex at least.
    #[test]
    fn a_string_whose_atom_occurrences_are_known_is_located_rather_than_searched() {
        let source = r#"
rule located {
    strings:
        $a = "zzqqxxjjvv"
    condition:
        $a
}
"#;
        let once = b"padding zzqqxxjjvv padding";
        let (outcome, _) = scan_without_sweep(source, once);
        assert_eq!(outcome.strings_localized, 1, "the witness must be used");
        assert_eq!(outcome.strings_searched, 1);
        assert_eq!(outcome.matches.len(), 1);
        let found = outcome.matches[0].strings.first(0).unwrap();
        assert_eq!((found.offset, found.length), (8, 10));

        // The same bytes twice. Both occurrences are candidates, both are
        // checked, and the answer is the one a full search gives — two matches,
        // at the right offsets. This half is what makes the test about
        // equivalence rather than just about the fast path being taken.
        let twice = b"padding zzqqxxjjvv padding padding zzqqxxjjvv padding";
        let (outcome, _) = scan_without_sweep(source, twice);
        assert_eq!(outcome.strings_localized, 1, "two occurrences, both known");
        assert_eq!(outcome.strings_searched, 1);
        assert_eq!(outcome.matches.len(), 1);
        let found = outcome.matches[0].strings.first(0).unwrap();
        assert_eq!(
            (found.offset, found.length),
            (8, 10),
            "the first of the two"
        );
        assert_eq!(outcome.matches[0].strings.count(0), 2, "both were found");

        // More occurrences than the prefilter keeps offsets for. The list it
        // could give would be incomplete, which is worse than not having one at
        // all, so the search stands down — and must still find every match,
        // including the ones whose offsets were never kept.
        let occurrences = u32::try_from(crate::prefilter::WITNESS_CAP + 1).unwrap();
        let mut too_many = b"padding ".to_vec();
        for _ in 0..occurrences {
            too_many.extend_from_slice(b"zzqqxxjjvv padding ");
        }
        let (outcome, _) = scan_without_sweep(source, &too_many);
        assert_eq!(
            outcome.strings_localized, 0,
            "an incomplete list of offsets is not usable"
        );
        assert_eq!(outcome.strings_searched, 1, "searched the long way instead");
        assert_eq!(
            outcome.matches[0].strings.count(0),
            occurrences,
            "every match, including the ones past the cap"
        );
    }

    /// The shortcut must not change the verdict when the atom is a coincidence.
    ///
    /// An atom is a window of the string, and a window is far more common than
    /// the thing it was cut from. The case the localization has to get right is
    /// the atom being present and the string not — it must derive the one
    /// candidate offset, compare the bytes there, and report nothing, rather
    /// than reporting the window as a match.
    ///
    /// The buffer is built from the atom the chooser actually picked rather than
    /// from a guess about which window that is, so the test holds whatever the
    /// scoring does. The atom is placed on its own, with the same number of
    /// bytes in front of where a match would have to start — bytes that are not
    /// the string's first byte — so the atom is there and the string is not.
    ///
    /// The literal is sixteen bytes so that the atom, which is at most twelve,
    /// can never cover it. With a string short enough for the atom to span it,
    /// "the atom is present" would mean "the string is present", and the case
    /// this test exists to tell apart would not arise.
    #[test]
    fn a_witness_that_points_at_a_coincidence_reports_no_match() {
        const LITERAL: &[u8] = b"zzqqxxjjvveemmww";
        let source = r#"
rule located {
    strings:
        $a = "zzqqxxjjvveemmww"
    condition:
        $a
}
"#;
        let atom = crate::atoms::best_atom(LITERAL, false).expect("the literal is long enough");
        assert!(
            atom.len() < LITERAL.len(),
            "the atom must be shorter than the string, or there is nothing to test"
        );
        let mut run = atom.bytes.to_vec();
        run.extend_from_slice(&atom.trailer);

        let mut data = b"................".to_vec();
        data.extend_from_slice(&run);
        data.extend_from_slice(b"\0\0\0\0");
        assert!(
            !data.windows(LITERAL.len()).any(|w| w == LITERAL),
            "the string must not be in the buffer, or this tests nothing"
        );
        // Without the sweep, for the reason the test above gives: the sweep
        // would answer this string from its own pass and the witness path — the
        // one that has to reject an atom's coincidence — would never run.
        let (outcome, _) = scan_without_sweep(source, &data);
        assert_eq!(
            outcome.strings_searched, 1,
            "the atom is there, so it is searched"
        );
        assert_eq!(
            outcome.strings_localized, 1,
            "and located, because its atom occurs once"
        );
        assert!(
            outcome.matches.is_empty(),
            "an atom in the buffer is not the string"
        );
    }

    /// A rule whose required string is absent is not a candidate at all.
    ///
    /// The counterpart to the test above, and the reason a scan of a real
    /// binary stopped selecting most of the rule set. `$a and $b` cannot match
    /// without `$b`, and `$b`'s atoms prove it absent, so the rule is dropped
    /// before the interpreter sees it — which is the whole point of doing the
    /// analysis at compile time instead of evaluating and finding out.
    ///
    /// This is also the end-to-end test for the wiring: the requirement is
    /// worked out by the compiler from the AST, carried in the compiled program
    /// and serialised with it, read back by `RuleDatabase::from_rules`, and
    /// understood by the prefilter. A break anywhere along that chain leaves the
    /// rule evaluated anyway, and this is the only test that sees all of it.
    #[test]
    fn a_rule_whose_required_string_is_absent_is_never_evaluated() {
        let source = r#"
rule both {
    strings:
        $a = "first marker here"
        $b = "second marker here"
    condition:
        $a and $b
}
"#;
        let (outcome, db) = scan(source, b"first marker here and nothing else");
        assert_eq!(
            db.prefilter().stats().conjunctive_rules,
            1,
            "the requirement has to survive compilation and the rule database"
        );
        assert_eq!(outcome.candidates, 0, "$b is provably absent");
        assert_eq!(outcome.evaluated, 0);
        assert_eq!(outcome.strings_searched, 0, "not even $a is searched for");
        assert!(outcome.matches.is_empty());
    }

    /// A rule whose condition proves nothing keeps the weaker selection.
    ///
    /// `any of them` can be true with one string, so no string can be demanded.
    /// The rule is a candidate on `$a` alone even though `$b` is absent, and
    /// the machine is what decides it — which is the behaviour every rule had
    /// before the conjunctive analysis existed, and the one to fall back to
    /// whenever the analysis cannot see a requirement.
    #[test]
    fn a_rule_that_requires_nothing_is_still_selected_on_one_string() {
        let source = r#"
rule either {
    strings:
        $a = "first marker here"
        $b = "second marker here"
    condition:
        any of them
}
"#;
        let (outcome, db) = scan(source, b"first marker here and nothing else");
        assert_eq!(db.prefilter().stats().conjunctive_rules, 0);
        assert_eq!(outcome.candidates, 1);
        assert_eq!(outcome.evaluated, 1);
        assert_eq!(
            matched(source, b"first marker here and nothing else"),
            ["either"]
        );
    }

    /// A rule selected by one string whose other strings are all absent must
    /// not match, and the machine must be the thing that decides it.
    ///
    /// `$a and #a > 5` is the shape that makes this testable now: `#a` can be
    /// zero, so nothing about it can keep the rule out of the candidate set,
    /// and the count that decides the rule is only known once `$a` has been
    /// searched for and the occurrences counted.
    #[test]
    fn a_candidate_whose_condition_fails_is_not_a_match() {
        let source = r#"
rule both {
    strings:
        $a = "first marker here"
    condition:
        $a and #a > 5
}
"#;
        let (outcome, _) = scan(source, b"first marker here and nothing else");
        assert_eq!(outcome.candidates, 1, "selected on $a");
        assert_eq!(outcome.evaluated, 1, "and evaluated");
        assert!(
            outcome.matches.is_empty(),
            "but $a occurs once, not six times"
        );
    }

    // -- string semantics through the scanner ---------------------------------

    #[test]
    fn count_offset_and_length_reach_the_machine() {
        let source = r#"
rule counted {
    strings:
        $a = "ab"
    condition:
        #a == 3 and @a[2] == 5 and !a == 2
}
"#;
        // Three occurrences of `ab`, at 0, 5 and 10 — the second is `@a[2]`.
        assert_eq!(matched(source, b"ab---ab---ab"), ["counted"]);
        assert!(
            matched(source, b"ab---ab").is_empty(),
            "two occurrences, so `#a == 3` is false"
        );
    }

    #[test]
    fn overlapping_occurrences_are_counted_separately() {
        // `aa` occurs three times in `aaaa`, and the search must find all
        // three. A non-overlapping search reports two and this rule goes
        // silent.
        let source = r#"
rule tripled {
    strings:
        $a = "aa"
    condition:
        #a == 3
}
"#;
        assert_eq!(matched(source, b"aaaa"), ["tripled"]);
    }

    #[test]
    fn a_string_at_an_offset_uses_the_offset() {
        let source = r#"
rule located {
    strings:
        $a = "needle"
    condition:
        $a at 4
}
"#;
        assert_eq!(matched(source, b"....needle...."), ["located"]);
        assert!(matched(source, b"...needle.....").is_empty());
    }

    #[test]
    fn a_string_in_a_range_requires_the_whole_match_inside_it() {
        let source = r#"
rule bounded {
    strings:
        $a = "needle"
    condition:
        $a in (0..10)
}
"#;
        assert_eq!(matched(source, b"needle....."), ["bounded"]);
        assert!(
            matched(source, b"......needle").is_empty(),
            "a match overrunning the range is not inside it"
        );
    }

    // -- a case the prefilter cannot filter -----------------------------------

    /// The engine has to be able to say "I do not know" without either guessing
    /// or giving up on the rule. A regex matching one character has no atom, so
    /// it must still be searched for and must still work.
    #[test]
    fn a_string_with_no_atom_is_still_matched() {
        let source = r#"
rule short_regex {
    strings:
        $a = /A.C/
    condition:
        $a
}
"#;
        assert_eq!(matched(source, b"xxAxCxx"), ["short_regex"]);
        assert!(matched(source, b"xxxxxxx").is_empty());
    }

    #[test]
    fn a_rule_with_no_strings_is_evaluated_against_every_file() {
        let source = r#"
rule by_size {
    condition:
        filesize < 10
}
"#;
        assert_eq!(matched(source, b"short"), ["by_size"]);
        assert!(matched(source, &[0u8; 64]).is_empty());
    }

    // -- global and private --------------------------------------------------

    #[test]
    fn a_failing_global_rule_suppresses_every_other_rule() {
        let source = r#"
global rule must_be_a_pe {
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule payload {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
"#;
        assert_eq!(
            matched(source, b"MZ....this is a needle"),
            ["payload"],
            "the gate holds and is not itself a finding, so only the payload is reported"
        );
        let (outcome, _) = scan(source, b"....this is a needle");
        assert!(outcome.global_gate_failed);
        assert!(
            outcome.matches.is_empty(),
            "the gate failed, so nothing else is considered"
        );
    }

    /// A global rule whose own strings are absent must still be evaluated — the
    /// prefilter is not allowed to skip the gate, or a file that fails it would
    /// look like a file with no global rule at all.
    #[test]
    fn a_global_rule_is_evaluated_even_when_its_strings_are_absent() {
        let source = r#"
global rule gate {
    strings:
        $mz = "MZ"
    condition:
        not $mz
}
rule payload {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
"#;
        // `$mz` is absent, which makes the gate *true*, and the payload rule
        // then has to be considered. A prefilter that skipped the gate would
        // never see this.
        assert_eq!(matched(source, b"....this is a needle"), ["payload"]);
    }

    /// A gate is a statement about the file, not a finding. Reporting one would
    /// flag every file whose type the gate names.
    #[test]
    fn a_matching_global_rule_is_recorded_but_is_not_a_detection() {
        let source = r#"
global rule gate {
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}
"#;
        let (outcome, _) = scan(source, b"MZ....");
        assert_eq!(outcome.matches.len(), 1, "it was evaluated and it matched");
        assert_eq!(outcome.matches[0].role, MatchRole::Gate);
        assert!(!outcome.detected());
        assert_eq!(outcome.reportable().count(), 0);
    }

    #[test]
    fn a_private_rule_matches_but_is_not_reported() {
        let source = r#"
private rule helper {
    strings:
        $a = "this is a needle"
    condition:
        $a
}

rule public {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
"#;
        let (outcome, db) = scan(source, b"this is a needle");
        assert_eq!(outcome.matches.len(), 2, "both evaluated and both matched");
        assert_eq!(outcome.matches[0].role, MatchRole::Helper);
        assert_eq!(outcome.matches[1].role, MatchRole::Detection);
        let reportable: Vec<_> = outcome
            .reportable()
            .map(|m| db.rule(m.rule).unwrap().name.clone())
            .collect();
        assert_eq!(reportable, ["public"], "the helper is not a detection");
        assert!(outcome.detected());
    }

    #[test]
    fn a_private_rule_alone_is_not_a_detection() {
        let source = r#"
private rule helper {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
"#;
        let (outcome, _) = scan(source, b"this is a needle");
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].role, MatchRole::Helper);
        assert!(!outcome.detected(), "nothing reportable matched");
        assert_eq!(outcome.reportable().count(), 0);
    }

    // -- reporting -----------------------------------------------------------

    #[test]
    fn a_match_carries_where_its_strings_were_found() {
        let (outcome, _) = scan(NEEDLE, b"....this is a needle....");
        let m = &outcome.matches[0];
        assert_eq!(m.strings.count(0), 1);
        let found = m.strings.first(0).unwrap();
        assert_eq!(found.offset, 4);
        assert_eq!(found.length, 16);
    }

    #[test]
    fn several_rules_matching_are_all_reported_once() {
        let source = r#"
rule one {
    strings:
        $a = "this is a needle"
    condition:
        $a
}
rule two {
    strings:
        $b = "a second marker"
    condition:
        $b
}
"#;
        assert_eq!(
            matched(source, b"this is a needle and a second marker"),
            ["one", "two"]
        );
    }

    // -- reuse ---------------------------------------------------------------

    /// The scanner reuses its state across files, so a second scan must not see
    /// the first one's matches. This is the failure that would make the engine
    /// report yesterday's detection on today's file.
    #[test]
    fn a_second_scan_does_not_inherit_the_first_ones_matches() {
        let (db, _) = RuleDatabase::compile(NEEDLE);
        let mut scanner = Scanner::new(&db);

        let first = scanner.scan(b"this is a needle");
        assert_eq!(first.matches.len(), 1);
        // Deliberately shares no four-byte window with `this is a needle`, so
        // the prefilter rejects the rule outright. An ordinary-looking buffer
        // is not good enough here: `nothing of interest` contains `thin`, which
        // is a window of `this`, and the rule would be a candidate after all.
        let second = scanner.scan(b"qqqq zzzz wwww");
        assert!(
            second.matches.is_empty(),
            "the second scan found a match the buffer does not contain"
        );
        assert_eq!(second.candidates, 0, "the atom is absent");
        assert_eq!(second.strings_searched, 0);
    }

    /// Rules have different string counts, so the reused table is resized
    /// between them. A table that kept the previous rule's slots would give a
    /// rule matches that belong to another rule.
    #[test]
    fn a_rule_with_fewer_strings_does_not_see_the_previous_rules_matches() {
        let source = r#"
rule three_strings {
    strings:
        $a = "the first marker"
        $b = "the second marker"
        $c = "the third marker"
    condition:
        $c
}
rule one_string {
    strings:
        $z = "an unrelated phrase"
    condition:
        $z
}
"#;
        // The two rules are independent: only the second should match, and its
        // single string must not be confused with the first rule's third slot.
        assert_eq!(matched(source, b"the third marker"), ["three_strings"]);
        assert_eq!(matched(source, b"an unrelated phrase"), ["one_string"]);
    }

    // -- counters ------------------------------------------------------------

    #[test]
    fn the_outcome_says_how_much_work_was_avoided() {
        let source = r#"
rule four {
    strings:
        $a = "aaaaaaaaaaaa"
        $b = "bbbbbbbbbbbb"
        $c = "cccccccccccc"
        $d = "dddddddddddd"
    condition:
        any of them
}
"#;
        let (outcome, _) = scan(source, b"only cccccccccccc is here");
        assert_eq!(outcome.candidates, 1);
        // The one string that is present is answered by the sweep rather than
        // searched for — it is a literal, so the pass the scan had already made
        // found it — and the three that are not never reach either path. So the
        // four strings of this rule cost one automaton pass and no search at
        // all, which is more avoided work than the count used to report rather
        // than less.
        assert_eq!(outcome.strings_searched, 0);
        assert_eq!(outcome.strings_swept, 1, "only the string that is present");
        assert_eq!(outcome.strings_refuted, 3);
        assert_eq!(outcome.evaluated, 1);
        assert_eq!(outcome.matches.len(), 1);
    }

    #[test]
    fn a_clean_file_evaluates_nothing() {
        let source = r#"
rule rare {
    strings:
        $a = "a most unlikely sequence"
    condition:
        $a
}
"#;
        let (outcome, _) = scan(source, b"an ordinary file with ordinary contents");
        assert_eq!(outcome.candidates, 0, "the atom is absent");
        assert_eq!(outcome.evaluated, 0);
        assert_eq!(outcome.strings_searched, 0);
        assert!(!outcome.detected());
    }

    #[test]
    fn an_empty_buffer_is_scanned_without_incident() {
        let (outcome, _) = scan(NEEDLE, b"");
        assert!(outcome.matches.is_empty());
        assert!(!outcome.detected());
    }
}

/// The real-file check for the literal sweep: two scanners, one answer.
///
/// [`Scanner::without_sweep`] is the engine as it was before the sweep existed,
/// so it is the honest baseline the sweep is measured against — not for speed,
/// which is the whole point of the sweep, but for whether it changes anything.
/// An optimization of this kind fails by losing a match: an overlapping
/// occurrence the automaton did not report, a `fullword` hit accepted through a
/// word character, a row left holding the previous file's offsets. Each of those
/// is argued away in `sweep.rs`, and an argument is only as good as its
/// premises, so the conclusion is checked against real binaries instead.
///
/// Rule set and files both matter here. The sweep is only exercised by binaries
/// that contain the literals the rules are about, and a clean system binary
/// matches almost nothing — so the rule set's own source is scanned as well. It
/// contains the literal of every rule in it, most rules therefore find
/// themselves, and the run compares thousands of non-empty answers rather than
/// five empty ones.
///
/// ```text
/// cargo test -p av-rules -- --ignored --nocapture
/// ```
///
/// `MRT.exe` is not in the list. It is 231 MB, and the scanner this test has to
/// run beside the sweep costs a search over the whole buffer for every string
/// the prefilter does not refute: measured at roughly 2 GB/s of memory traffic,
/// that is minutes for this one file, on top of the sweep pass that exists to
/// avoid exactly it. The four files below are the same test at a size that
/// finishes.
#[cfg(test)]
mod real_files {
    use super::*;
    use std::path::Path;
    use std::time::Instant;

    /// The rule set the engine ships.
    ///
    /// Read from the repository rather than from a build artefact, because what
    /// this test is checking is the sweep over the rule set that will be loaded
    /// in production, and a fixture small enough to be a constant would put a
    /// few hundred literals in the automaton instead of sixty-five thousand.
    const RULESET: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/converted/yara-forge-extended-0.9.1.yar"
    );

    /// System binaries to compare on, in ascending order of size.
    const BINARIES: &[&str] = &["notepad.exe", "kernel32.dll", "ntdll.dll", "shell32.dll"];

    /// How much of the rule set's own source to scan, and where.
    ///
    /// A rule set is alphabetically ordered, so a slice of it is a coherent
    /// family of rules rather than a random sample, and two slices a rule set
    /// apart cover two families. The second is taken from the middle for that
    /// reason.
    const SLICE: usize = 1 << 20;

    /// One reported match, reduced to what must be identical between two scans.
    ///
    /// The rule and its role, then every string's occurrences as
    /// `(offset, length)` in slot order. The offsets are in there because `at`,
    /// `in`, `#a` and `@a[i]` are computed from them: a sweep that reported a
    /// string at the wrong offset, or one occurrence too few, would keep the
    /// verdict of most rules and change what they mean.
    type Finding = (u32, MatchRole, Vec<Vec<(u32, u32)>>);

    fn findings(outcome: &ScanOutcome) -> Vec<Finding> {
        let mut out: Vec<Finding> = outcome
            .matches
            .iter()
            .map(|m| {
                let slots = (0..m.strings.string_count() as u32)
                    .map(|slot| {
                        m.strings
                            .matches(slot)
                            .iter()
                            .map(|found| (found.offset, found.length))
                            .collect()
                    })
                    .collect();
                (m.rule, m.role, slots)
            })
            .collect();
        // Sorted, because the two scans visit rules in different orders — the
        // swept one in whatever order its sweep answered them — and the
        // comparison is about the set, not the sequence.
        out.sort_by_key(|(rule, ..)| *rule);
        out
    }

    #[test]
    #[ignore = "reads the shipped rule set and the system binaries"]
    fn the_sweep_changes_no_verdict_on_a_real_binary() {
        // Compiling this rule set recurses over a deep expression tree, so it
        // gets the same bounded stack every other tool in this crate uses.
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(compare_over_real_inputs)
            .expect("spawning the worker thread");
        handle.join().expect("the comparison must not panic");
    }

    fn compare_over_real_inputs() {
        // The rule sources are not distributed with the repository, so a
        // checkout without them skips the comparison rather than failing on a
        // missing file. The shipped database is what a release runs.
        let Ok(source) = std::fs::read_to_string(RULESET) else {
            eprintln!("the rule sources are not present here; nothing to compare");
            return;
        };
        let started = Instant::now();
        let (database, report) = RuleDatabase::compile(&source);
        println!(
            "{} rules compiled from {} seen ({} refused) in {:?}",
            database.len(),
            report.rules_seen,
            report.refused(),
            started.elapsed()
        );
        assert_eq!(
            report.refused(),
            0,
            "the shipped rule set must compile whole"
        );

        let stats = database.sweep().stats();
        println!(
            "sweep: {} strings answered of {} slots in {} rules, {} literals ({} case-insensitive)",
            stats.strings,
            database.stats().strings,
            stats.rules,
            stats.literals,
            stats.case_insensitive_literals
        );

        let mut swept = Scanner::new(&database);
        let mut plain = Scanner::without_sweep(&database);
        let mut compared = 0usize;
        let mut matched = 0usize;

        let root = std::env::var_os("SystemRoot").expect("a Windows installation");
        let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
        for name in BINARIES {
            let path = Path::new(&root).join("System32").join(name);
            match std::fs::read(&path) {
                Ok(data) => inputs.push(((*name).to_string(), data)),
                Err(_) => println!("  {name:<22} unreadable, skipped"),
            }
        }
        inputs.extend(source_slices(&source));

        for (name, data) in &inputs {
            matched += compare(&database, &mut swept, &mut plain, name, data);
            compared += 1;
        }

        assert!(
            compared > 0,
            "no input was readable, so nothing was compared"
        );
        // Two empty results agreeing proves nothing, and on a clean machine the
        // system binaries are the empty half — which is why the rule set's own
        // source is in the list.
        assert!(
            matched > 0,
            "{compared} inputs compared, and nothing matched in any of them"
        );
        println!("\n{compared} inputs agreed on {matched} reported matches");
    }

    /// Scan one buffer both ways, check them, and say how many matches agreed.
    ///
    /// The panic carries only the file name: the two sets are thousands of
    /// offsets each, and a failed `assert_eq!` on them would bury the one line
    /// that says which rule differs. `describe` prints that first.
    fn compare(
        database: &RuleDatabase,
        swept: &mut Scanner<'_>,
        plain: &mut Scanner<'_>,
        name: &str,
        data: &[u8],
    ) -> usize {
        let started = Instant::now();
        let fast = swept.scan(data);
        let swept_time = started.elapsed();
        let started = Instant::now();
        let slow = plain.scan(data);
        let plain_time = started.elapsed();

        let ours = findings(&fast);
        let theirs = findings(&slow);
        println!(
            "  {name:<22} {:>9} bytes  sweep {swept_time:?}, without it {plain_time:?} ({:.1}x)  \
             {} matches, {} swept, {} searched",
            data.len(),
            plain_time.as_secs_f64() / swept_time.as_secs_f64().max(f64::MIN_POSITIVE),
            ours.len(),
            fast.strings_swept,
            fast.strings_searched
        );

        // Not equality on its own. The two scans have to have run the thing they
        // are supposed to: a baseline that quietly used the sweep would agree
        // with the swept scan by construction, and a matcher that gave up early
        // would make both answers incomplete in the same way only by luck.
        assert_eq!(
            slow.strings_swept, 0,
            "{name}: the baseline used the sweep, so this compared nothing"
        );
        for (which, outcome) in [("the swept scan", &fast), ("the baseline", &slow)] {
            assert_eq!(
                outcome.matcher_failures, 0,
                "{name}: a matcher gave up early on {which}, so its answers are incomplete"
            );
            assert_eq!(
                outcome.vm_failures, 0,
                "{name}: a rule could not be evaluated by {which}"
            );
        }

        if ours != theirs {
            describe(database, &ours, &theirs);
            panic!("{name}: the sweep changed the result — the differences are above");
        }
        ours.len()
    }

    /// Which rule differs, and in which direction.
    ///
    /// Printing both sets whole buries the answer in thousands of offsets. What
    /// a person needs is which rule, and whether the swept scan lost a match or
    /// invented one.
    fn describe(database: &RuleDatabase, ours: &[Finding], theirs: &[Finding]) {
        for (rule, role, slots) in theirs {
            match ours.iter().find(|(r, ..)| r == rule) {
                None => println!(
                    "    MISSED   {} ({role:?}) — the baseline matched it",
                    rule_name(database, *rule)
                ),
                Some((_, _, mine)) if mine != slots => {
                    println!(
                        "    DIFFER   {} — same rule, different offsets",
                        rule_name(database, *rule)
                    );
                    for slot in 0..mine.len().max(slots.len()) {
                        let mine = mine.get(slot).cloned().unwrap_or_default();
                        let theirs = slots.get(slot).cloned().unwrap_or_default();
                        if mine != theirs {
                            println!("      slot {slot}: swept {mine:?}, baseline {theirs:?}");
                        }
                    }
                }
                Some(_) => {}
            }
        }
        for (rule, role, slots) in ours {
            if !theirs.iter().any(|(r, ..)| r == rule) {
                println!(
                    "    EXTRA    {} ({role:?}) — only the swept scan matched it, with {slots:?}",
                    rule_name(database, *rule)
                );
            }
        }
    }

    fn rule_name(database: &RuleDatabase, rule: u32) -> String {
        database
            .rule(rule)
            .map_or_else(|| format!("#{rule}"), |r| r.name.clone())
    }

    /// Two slices of the rule set's source, as buffers to scan.
    ///
    /// The whole file would be the better input and is too slow to search
    /// without the sweep, so it is taken in pieces from two places. Cut on a
    /// line boundary, so the buffer is text rather than half a literal: a torn
    /// string at the seam is noise, not a test.
    fn source_slices(source: &str) -> Vec<(String, Vec<u8>)> {
        let bytes = source.as_bytes();
        let mut out = Vec::new();
        for (name, start) in [
            ("rules (first MiB)", 0usize),
            ("rules (middle MiB)", bytes.len() / 2),
        ] {
            let start = start.min(bytes.len());
            let end = (start + SLICE).min(bytes.len());
            let end = match bytes[end..].iter().position(|b| *b == b'\n') {
                Some(offset) if end + offset < bytes.len() => end + offset,
                _ => end,
            };
            if end > start {
                out.push((name.to_string(), bytes[start..end].to_vec()));
            }
        }
        out
    }
}
