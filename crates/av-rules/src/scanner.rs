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

use crate::database::RuleDatabase;
use crate::matches::MatchSet;
use crate::prefilter::StringState;
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
    /// Resolved once, because the prefilter must not be allowed to filter a
    /// global rule and asking "which rules are global" per scan would be a
    /// linear pass over the rule set per file.
    globals: Vec<u32>,
}

impl<'a> Scanner<'a> {
    pub fn new(database: &'a RuleDatabase) -> Self {
        Self {
            scratch: database.prefilter().scratch(),
            candidates: Vec::new(),
            working: MatchSet::default(),
            globals: database
                .rules()
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.global)
                .map(|(index, _)| index as u32)
                .collect(),
            vm: Vm::new(),
            database,
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
        let mut outcome = ScanOutcome::default();

        // Global rules first, and not through the prefilter's selection: a
        // global rule the prefilter skipped would leave the gate open. They are
        // chosen by the database rather than by the buffer, so this is the same
        // short list every time.
        // Indexed rather than iterated: the list lives in `self` and
        // `evaluate` needs `self` mutably.
        for index in 0..self.globals.len() {
            let rule = self.globals[index];
            outcome.candidates += 1;
            if !self.evaluate(rule, data, input, &mut outcome) {
                outcome.global_gate_failed = true;
                return outcome;
            }
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
            let _matched = self.evaluate(rule, data, input, &mut outcome);
        }

        outcome
    }

    /// Match a rule's strings and run its condition. Returns whether it held.
    ///
    /// Records the match in `outcome` when it did.
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
        for slot in 0..rule.program.string_count {
            match self
                .database
                .prefilter()
                .string_state(&self.scratch, rule_index, slot)
            {
                // The atoms were all found, so the string may be there; and the
                // string has no atoms, so nothing could be said either way. Both
                // have to be searched for.
                StringState::Possible | StringState::Unknown => {}
                StringState::Absent => {
                    // A group had no atom present, so the string cannot be here.
                    // This is the whole reason the per-string state exists: the
                    // search is the expensive half and it would find nothing.
                    outcome.strings_refuted += 1;
                    continue;
                }
            }
            let Some(matcher) = rule.matcher(slot) else {
                // The matcher refused this string when it was compiled — a
                // construct the engine cannot search for. The slot stays empty,
                // so the condition sees the string as never matching, which is
                // the honest reading.
                continue;
            };
            outcome.strings_searched += 1;
            matcher.find_all(data, &mut self.working);
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
        assert_eq!(matched(NEEDLE, b"prefix this is a needle suffix"), ["needle"]);
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
        assert_eq!(outcome.candidates, 1, "selected on $a, the one string it needs");
        assert_eq!(outcome.strings_searched, 1, "$a searched, $b and $c skipped");
        assert_eq!(outcome.strings_refuted, 2);
        assert!(outcome.matches.is_empty(), "neither $b nor $c is present");
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
        assert_eq!(matched(source, b"first marker here and nothing else"), ["either"]);
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
        assert!(outcome.matches.is_empty(), "but $a occurs once, not six times");
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
        assert_eq!(outcome.strings_searched, 1, "only the string that is present");
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
