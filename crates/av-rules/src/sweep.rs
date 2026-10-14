//! Finding every literal in the rule set, in one pass over the buffer.
//!
//! # The cost this removes
//!
//! A scan of `shell32.dll` ends up searching for 1,569 strings one at a time,
//! each a pass over eight megabytes of memory: 12.57 GB of traffic, and
//! measured at 2.96 s of the scan's 3.51 s. `memmem` runs at gigabytes per
//! second, so the cost of a scan is `(strings that need a full search) ×
//! (file size)` and nothing else — which is why the same model makes
//! `MRT.exe`'s 231 MB cost minutes.
//!
//! Nothing in that product depends on *which* strings are being looked for.
//! One Aho-Corasick pass over every literal form in the rule set finds the
//! occurrences of all of them at once, so the per-string term disappears and
//! what is left is the automaton's own pass over the buffer. That is the whole
//! idea here, and it is worth being exact about its limits: this covers
//! `Kind::Literal` strings and nothing else. A hex
//! pattern or a regex is not a fixed byte sequence, and
//! [`CompiledString::literal_forms`](crate::matcher::CompiledString::literal_forms)
//! returns `None` for one so that the caller searches for it the ordinary way.
//! Those are the minority of the rule set, and their atoms are what the
//! prefilter is for.
//!
//! # Two automatons, and one row per string
//!
//! Aho-Corasick folds case for all of its patterns or none of them, and a rule
//! set has both kinds — the same reason [`crate::prefilter`] has two. A pattern
//! is one *literal form*, so a string with several of them (`ascii wide`, `xor`,
//! `base64`) contributes one pattern per form and every one of them points back
//! at the same string.
//!
//! What comes out is a row of occurrences per string, and the row has to be
//! exactly what [`crate::matcher::CompiledString::find_all`] would have
//! produced: sorted by offset, and two hits at one offset collapsed into the
//! longer reading. `#a` counts a row's entries and `@a[i]` indexes it, so a row
//! with an entry too many makes `#a == 1` false and a rule that counts
//! occurrences stops firing — on a file it used to detect, with nothing in the
//! scan to show for it.
//!
//! # Built once, run per buffer
//!
//! The split is [`crate::prefilter`]'s, for the same reason. The automaton and
//! the tables that read it belong to the rule database and are shared by every
//! scanning thread; the rows belong to one thread and are stamped with an epoch
//! rather than cleared, so a scan touches only the strings some byte of the
//! file actually matched. A file that matches nothing allocates nothing and
//! writes nothing.
//!
//! # Checking that it costs no detection
//!
//! This replaces a search with an automaton, so it can lose a match if it is
//! wrong in a way the old path was not — an overlapping occurrence the
//! automaton dropped, a `fullword` hit accepted through a word character, a row
//! left holding the previous file's offsets. `Scanner::without_sweep` is the
//! honest baseline it is measured against, and the ignored differential test in
//! `scanner.rs` runs both over the same system binaries and compares every
//! reported rule and every offset. Run it after any change here.

use std::collections::HashMap;
use std::fmt;

use aho_corasick::AhoCorasick;
use smallvec::SmallVec;

use crate::database::CompiledRule;
use crate::matcher::text;
use crate::matches::Match;
use crate::prefilter::build_automaton;

/// What a sweep was built from, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub rules: usize,
    /// Strings the sweep answers. A string whose matcher refused it, or which
    /// is a hex pattern or a regex, is not one of these and takes the ordinary
    /// path.
    pub strings: usize,
    /// Distinct literal forms, after the same bytes in two rules were merged.
    pub literals: usize,
    pub case_insensitive_literals: usize,
}

/// Every literal form in the rule set, as two automatons.
pub struct LiteralSweep {
    case_sensitive: Option<AhoCorasick>,
    case_insensitive: Option<AhoCorasick>,
    /// Automaton pattern index -> unified literal id, one table per automaton.
    sensitive_literal: Vec<u32>,
    insensitive_literal: Vec<u32>,
    /// Literal id -> the form itself, for its length and its two rules.
    ///
    /// The bytes are in the automaton; what is *not* is which of the strings
    /// that share these bytes require a whole word, and how long the form is —
    /// both of which are needed at every hit, and neither of which the automaton
    /// reports.
    literals: Vec<text::Literal>,
    /// Literal id -> the strings it is a form of. More than one when the same
    /// bytes appear in more than one rule, which is common: `kernel32.dll`
    /// alone is a string in hundreds.
    literal_strings: Vec<SmallVec<[u32; 1]>>,
    /// Rule -> its first string id, with a closing sentinel. See
    /// [`LiteralSweep::string_of`].
    rule_first_string: Vec<u32>,
    /// String id -> whether the sweep has an answer for it.
    ///
    /// False for a hex pattern, a regex, a string the matcher refused, and a
    /// string that could not be put in an automaton. Those are the strings
    /// [`LiteralSweep::matches`] returns `None` for, which sends the caller back
    /// to the per-string search — the direction in which a gap in this module
    /// costs time rather than a detection.
    answered: Vec<bool>,
    stats: SweepStats,
}

/// Hand-written rather than derived, for the reason [`crate::prefilter`]'s is:
/// a derived `Debug` would print fifty thousand literal forms into whatever log
/// it was reached from. The pattern counts are what decide how fast this runs.
impl fmt::Debug for LiteralSweep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiteralSweep")
            .field("case_sensitive_patterns", &self.sensitive_literal.len())
            .field("case_insensitive_patterns", &self.insensitive_literal.len())
            .field("literals", &self.literals.len())
            .field("strings", &self.answered.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl LiteralSweep {
    /// Build from every rule, in database order.
    ///
    /// The order is the order the scanner indexes rules by, and a rule's strings
    /// are laid out in slot order within it, so a query is arithmetic on those
    /// two numbers rather than a lookup.
    pub fn build(rules: &[CompiledRule]) -> Self {
        let mut literals: Vec<text::Literal> = Vec::new();
        // Keyed by the bytes *and* the two rules, because two strings that
        // search for the same bytes with different case or word rules are not
        // the same pattern: merging them would apply one string's `fullword` to
        // the other's hits.
        let mut literal_ids: HashMap<(Vec<u8>, bool, bool), u32> = HashMap::new();
        let mut literal_strings: Vec<SmallVec<[u32; 1]>> = Vec::new();
        let mut rule_first_string: Vec<u32> = Vec::new();
        let mut answered: Vec<bool> = Vec::new();
        let mut answered_strings = 0usize;

        for rule in rules {
            rule_first_string.push(answered.len() as u32);
            for slot in 0..rule.program.string_count {
                let string = answered.len() as u32;
                let forms = rule.matcher(slot).and_then(|m| m.literal_forms());
                // A zero-length form matches at every offset, and one string
                // that cannot be automated is worth more than one wrong answer
                // for the whole rule set. Unreachable — `text::variants` refuses
                // an empty string and no expansion produces one — which is
                // exactly why it is a check rather than an assumption.
                let usable =
                    forms.is_some_and(|f| !f.is_empty() && !f.iter().any(|l| l.bytes.is_empty()));
                if let (true, Some(forms)) = (usable, forms) {
                    for form in forms {
                        let key = (form.bytes.clone(), form.nocase, form.fullword);
                        let id = match literal_ids.get(&key) {
                            Some(id) => *id,
                            None => {
                                let id = literals.len() as u32;
                                literals.push(form.clone());
                                literal_strings.push(SmallVec::new());
                                literal_ids.insert(key, id);
                                id
                            }
                        };
                        // Once per string, not once per form. Two forms of one
                        // string can be the same bytes — `xor(0-0)` is the plain
                        // form again, and a `base64` alphabet pair collapses
                        // when the encoding has no `+` or `/` — and recording
                        // every occurrence of those twice would be work
                        // `finish` throws away again.
                        let strings = &mut literal_strings[id as usize];
                        if strings.last() != Some(&string) {
                            strings.push(string);
                        }
                    }
                    answered_strings += 1;
                }
                answered.push(usable);
            }
        }
        // Closing sentinel, so the last rule's strings are a range like every
        // other rule's.
        rule_first_string.push(answered.len() as u32);

        // Split by case sensitivity, which is the one property the automaton has
        // to know at build time.
        let mut sensitive_patterns: Vec<Vec<u8>> = Vec::new();
        let mut sensitive_literal: Vec<u32> = Vec::new();
        let mut insensitive_patterns: Vec<Vec<u8>> = Vec::new();
        let mut insensitive_literal: Vec<u32> = Vec::new();
        for (id, literal) in literals.iter().enumerate() {
            let id = id as u32;
            if literal.nocase {
                insensitive_patterns.push(literal.bytes.clone());
                insensitive_literal.push(id);
            } else {
                sensitive_patterns.push(literal.bytes.clone());
                sensitive_literal.push(id);
            }
        }

        let stats = SweepStats {
            rules: rules.len(),
            strings: answered_strings,
            literals: literals.len(),
            case_insensitive_literals: insensitive_patterns.len(),
        };

        Self {
            case_sensitive: build_automaton(&sensitive_patterns, false),
            case_insensitive: build_automaton(&insensitive_patterns, true),
            sensitive_literal,
            insensitive_literal,
            literals,
            literal_strings,
            rule_first_string,
            answered,
            stats,
        }
    }

    /// What this sweep was built from.
    pub fn stats(&self) -> SweepStats {
        self.stats
    }

    /// A hit table sized for this sweep.
    pub fn hits(&self) -> SweepHits {
        SweepHits::new(self)
    }

    /// Find every literal in `data`, filling `hits`.
    ///
    /// One pass per automaton, and the rows are left sorted and deduplicated by
    /// `SweepHits::finish`.
    pub fn run(&self, data: &[u8], hits: &mut SweepHits) {
        hits.begin(self);
        if let Some(ac) = &self.case_sensitive {
            self.find(ac, &self.sensitive_literal, data, hits);
        }
        if let Some(ac) = &self.case_insensitive {
            self.find(ac, &self.insensitive_literal, data, hits);
        }
        hits.finish();
    }

    /// Every occurrence of string `slot` of rule `rule`, or `None` when the
    /// sweep does not answer that string.
    ///
    /// `None` — for a hex pattern, a regex, a string the matcher refused, or a
    /// name that does not exist — means the caller has to search for it the
    /// ordinary way. `Some` with an empty row means the sweep looked and found
    /// nothing, which is an answer: the buffer does not contain the string.
    ///
    /// # When this may be called
    ///
    /// Between a [`run`](Self::run) and the next one, like
    /// [`Prefilter::string_state`](crate::prefilter::Prefilter::string_state) and
    /// for the same reason: the rows are stamped with the scan's epoch, so a
    /// second scan overwrites them. A hit table that has never been run says
    /// `None` rather than an empty row, because "no occurrences" is a claim it
    /// has not earned yet.
    pub fn matches<'h>(&self, hits: &'h SweepHits, rule: u32, slot: u32) -> Option<&'h [Match]> {
        debug_assert_eq!(
            hits.owner,
            self.address(),
            "this hit table has not been used for a scan with this sweep, so its stamps \
             mean nothing here"
        );
        hits.answer(self.string_of(rule, slot)?)
    }

    /// The string id a rule and slot name, if the sweep answers it.
    ///
    /// A rule or slot that does not exist is a corrupt database — the program
    /// and the sweep disagreeing about the shape of the rule set — and the
    /// answer that costs a search is the right one.
    fn string_of(&self, rule: u32, slot: u32) -> Option<u32> {
        let start = *self.rule_first_string.get(rule as usize)?;
        let end = *self.rule_first_string.get(rule as usize + 1)?;
        if slot >= end - start {
            return None;
        }
        let string = start + slot;
        self.answered
            .get(string as usize)
            .copied()
            .filter(|yes| *yes)?;
        Some(string)
    }

    /// One automaton's pass over the buffer.
    fn find(
        &self,
        ac: &AhoCorasick,
        literal_of_pattern: &[u32],
        data: &[u8],
        hits: &mut SweepHits,
    ) {
        // `find_overlapping_iter`, not `find_iter`, for the reason the prefilter
        // gives: patterns routinely contain one another — `aa` and `aaa` are two
        // forms of two strings, and `#a` counts three occurrences of `aa` in
        // `aaaa` — and an iterator that skipped a match beginning inside the one
        // before it would report two and leave the rule that counts to three
        // silently unfiring.
        for found in ac.find_overlapping_iter(data) {
            let literal = literal_of_pattern[found.pattern().as_usize()] as usize;
            let form = &self.literals[literal];
            let at = found.start();
            // `fullword` is a property of the string, not of the bytes, so it is
            // checked here rather than being folded into the pattern: two rules
            // can search for `cat`, one of them requiring a whole word.
            if form.fullword && !text::is_whole_word(data, at, form.bytes.len()) {
                continue;
            }
            // Both fit for the same reason they do in the matcher: the match
            // lies inside a slice, so its offset and length cannot exceed the
            // buffer's, and a buffer longer than `u32::MAX` is the one case
            // where they could — dropped rather than truncated.
            let (Ok(offset), Ok(length)) = (u32::try_from(at), u32::try_from(form.bytes.len()))
            else {
                continue;
            };
            hits.visit(&self.literal_strings[literal], Match::new(offset, length));
        }
    }

    /// This sweep's identity, for the hit table's ownership check. Not a value
    /// with any meaning outside that comparison.
    fn address(&self) -> usize {
        self as *const LiteralSweep as usize
    }
}

/// One string's occurrences, in the order they were found.
///
/// Per-file state, so that a scan allocates nothing. The rows are stamped with
/// an epoch instead of being cleared, which matters more here than in the
/// prefilter: there are 65,192 rows in this rule set and a scan touches a
/// handful of them.
#[derive(Debug, Default)]
pub struct SweepHits {
    epoch: u32,
    /// Which sweep these rows belong to, as an address.
    ///
    /// The same argument as [`PrefilterScratch`](crate::prefilter::PrefilterScratch)'s:
    /// stamps from one sweep read as valid against another whose rows are laid
    /// out differently, which is a wrong answer that depends on allocation
    /// order, and a debug build refuses rather than answering it.
    owner: usize,
    /// String id -> the epoch its row belongs to.
    string_epoch: Vec<u32>,
    /// String id -> every occurrence found this scan.
    ///
    /// A vector per string rather than one flat table, because the counts are
    /// wildly uneven: most strings have none, and the ones that do have as many
    /// as the buffer contains. Empty rows cost a `Vec` header each and no
    /// allocation.
    rows: Vec<Vec<Match>>,
    /// The strings stamped this scan. Sorting and deduplicating is a pass per
    /// touched row, and this is how many rows that is without walking all of
    /// them.
    touched: Vec<u32>,
    /// Hits recorded this scan, before deduplication.
    found: usize,
}

impl SweepHits {
    fn new(sweep: &LiteralSweep) -> Self {
        Self {
            epoch: 0,
            owner: sweep.address(),
            string_epoch: vec![0; sweep.answered.len()],
            rows: vec![Vec::new(); sweep.answered.len()],
            touched: Vec::new(),
            found: 0,
        }
    }

    /// Start a scan.
    ///
    /// Nothing is cleared here. A row whose stamp is not this scan's epoch is
    /// invisible to [`answer`](Self::answer) and is cleared by the first hit
    /// that claims it, so the cost of a scan is the strings the file actually
    /// matched rather than the size of the rule set.
    fn begin(&mut self, sweep: &LiteralSweep) {
        if self.rows.len() < sweep.answered.len() {
            // A hit table made for another sweep: rebuilt, and the epoch with
            // it, because old stamps mean nothing against new rows.
            *self = Self::new(sweep);
        }
        self.owner = sweep.address();
        self.touched.clear();
        self.found = 0;
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            // Four billion files into a scan, start the stamps over. Reachable
            // only in a soak test, and cheap enough to be worth not thinking
            // about again.
            self.string_epoch.fill(0);
            self.epoch = 1;
        }
    }

    /// Record an occurrence against every string that form belongs to.
    fn visit(&mut self, strings: &[u32], m: Match) {
        for &string in strings {
            let string = string as usize;
            if self.string_epoch[string] != self.epoch {
                self.string_epoch[string] = self.epoch;
                // Keeps the capacity, which is what makes the second scan of a
                // file the size of the first allocate nothing.
                self.rows[string].clear();
                self.touched.push(string as u32);
            }
            self.rows[string].push(m);
            self.found += 1;
        }
    }

    /// Put every row touched this scan in the order and shape the interpreter
    /// reads.
    ///
    /// The rule is [`MatchSet::dedup_slot`](crate::matches::MatchSet::dedup_slot)'s,
    /// applied to a row of this table: sorted by offset, and two hits at one
    /// offset collapsed into the longer reading. Two forms of one string can
    /// land on the same span — `xor(0-0)` is the plain form again — and the
    /// automaton reports patterns in the order their matches *end*, so the
    /// offsets arrive shuffled and one form of a string can be reported after a
    /// later occurrence of another.
    fn finish(&mut self) {
        for i in 0..self.touched.len() {
            let row = &mut self.rows[self.touched[i] as usize];
            row.sort_unstable();
            row.dedup_by(|later, earlier| {
                if later.offset == earlier.offset {
                    earlier.length = earlier.length.max(later.length);
                    true
                } else {
                    false
                }
            });
        }
    }

    /// The occurrences of one string, or `None` if this table cannot say.
    fn answer(&self, string: u32) -> Option<&[Match]> {
        if self.epoch == 0 {
            // No scan has run, so nothing has been looked for. `Some(&[])` here
            // would be the claim that the buffer holds none of this string.
            return None;
        }
        if self.string_epoch[string as usize] != self.epoch {
            // Not touched this scan: the automaton saw none of its forms, or the
            // row still holds the previous file's offsets. Either way the answer
            // is that the buffer holds none of it.
            return Some(&[]);
        }
        Some(&self.rows[string as usize])
    }

    /// Hits recorded by the last scan, before deduplication.
    ///
    /// The number that says how much work the automaton's matches cost — a row
    /// per hit, sorted at the end — which is the half of this module's cost that
    /// is not the pass itself.
    pub fn found(&self) -> usize {
        self.found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::RuleDatabase;
    use crate::matches::MatchSet;

    /// Compile a rule set, refusing to test against one that lost a rule.
    fn database(source: &str) -> RuleDatabase {
        let (db, report) = RuleDatabase::compile(source);
        assert_eq!(report.refused(), 0, "refusals: {:?}", report.refusals);
        db
    }

    /// Run the sweep over a buffer, leaving the rows readable.
    fn swept(db: &RuleDatabase, data: &[u8]) -> SweepHits {
        let mut hits = db.sweep().hits();
        db.sweep().run(data, &mut hits);
        hits
    }

    /// What the sweep reports for one string, as `(offset, length)` pairs.
    fn swept_row(db: &RuleDatabase, hits: &SweepHits, rule: u32, slot: u32) -> Vec<(u32, u32)> {
        db.sweep()
            .matches(hits, rule, slot)
            .expect("the sweep must answer a literal string")
            .iter()
            .map(|m| (m.offset, m.length))
            .collect()
    }

    /// What searching for the same string reports, which is what the sweep
    /// stands in for.
    fn searched_row(db: &RuleDatabase, rule: u32, slot: u32, data: &[u8]) -> Vec<(u32, u32)> {
        let matcher = db
            .rule(rule)
            .and_then(|r| r.matcher(slot))
            .expect("the string must exist");
        let mut set = MatchSet::with_capacity(slot as usize + 1);
        assert!(
            matcher.find_all(data, &mut set),
            "the matcher ran out of budget"
        );
        set.matches(slot)
            .iter()
            .map(|m| (m.offset, m.length))
            .collect()
    }

    const OVERLAPPING: &str = r#"
rule r {
    strings:
        $a = "aa"
    condition:
        $a
}
"#;

    const FULLWORD: &str = r#"
rule r {
    strings:
        $a = "cat" fullword
    condition:
        $a
}
"#;

    const TWO_FORMS: &str = r#"
rule r {
    strings:
        $a = "hi" ascii xor(0-0)
    condition:
        $a
}
"#;

    const MIXED: &str = r#"
rule mixed {
    strings:
        $plain = "abcd"
        $nocase = "EFGH" nocase
        $word = "cat" fullword
        $both = "ab" ascii wide
        $zero = "hi" ascii xor(0-0)
        $encoded = "secret" base64
        $long = "a longer phrase that is only here once"
    condition:
        any of them
}
"#;

    const SHARED: &str = r#"
rule one {
    strings:
        $a = "a shared marker"
    condition:
        $a
}
rule two {
    strings:
        $b = "a shared marker"
    condition:
        $b
}
"#;

    const HEX_AND_REGEX: &str = r#"
rule r {
    strings:
        $a = { 4D 5A ?? 00 }
        $b = /ab+c/
        $c = "a plain string"
    condition:
        any of them
}
"#;

    // -- what a row says ----------------------------------------------------

    #[test]
    fn an_overlapping_needle_is_reported_at_every_offset() {
        // Three, not two. An automaton walked with `find_iter` would report the
        // first and resume past its end, and `#a == 3` over `aaaa` is a
        // condition rules are written against.
        let db = database(OVERLAPPING);
        let hits = swept(&db, b"aaaa");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(0, 2), (1, 2), (2, 2)]);
    }

    #[test]
    fn a_needle_at_several_offsets_is_reported_at_each_of_them() {
        let db = database(OVERLAPPING);
        let hits = swept(&db, b"aa--aa--aa");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(0, 2), (4, 2), (8, 2)]);
    }

    /// The automaton reports patterns in the order their matches end, so a
    /// needle that is a prefix of another arrives out of order. The row has to
    /// come out sorted anyway: `@a[2]` is the second match, and an unsorted row
    /// makes a rule's answer depend on the automaton's internals.
    #[test]
    fn a_row_comes_out_sorted_however_the_automaton_reported_it() {
        let source = r#"
rule r {
    strings:
        $a = "ab"
        $b = "abc"
    condition:
        any of them
}
"#;
        let db = database(source);
        let hits = swept(&db, b"abcab cabc");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(0, 2), (3, 2), (7, 2)]);
        assert_eq!(swept_row(&db, &hits, 0, 1), [(0, 3), (7, 3)]);
    }

    #[test]
    fn a_fullword_hit_inside_a_longer_word_is_rejected() {
        let db = database(FULLWORD);
        let hits = swept(&db, b"concatenate");
        assert!(
            swept_row(&db, &hits, 0, 0).is_empty(),
            "the `cat` inside `concatenate` is not a word"
        );
        let hits = swept(&db, b"a cat sat");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(2, 3)]);
    }

    #[test]
    fn a_fullword_hit_at_either_end_of_the_buffer_is_accepted() {
        // Nothing is before the first byte or after the last to contradict the
        // claim, so both ends count as delimited — the reading
        // `text::is_whole_word` gives, which is why the check is shared with the
        // matcher rather than written out again here.
        let db = database(FULLWORD);
        for (data, expected) in [
            (b"cat".as_slice(), vec![(0, 3)]),
            (b"cat!".as_slice(), vec![(0, 3)]),
            (b"!cat".as_slice(), vec![(1, 3)]),
            (b"cat_".as_slice(), vec![]),
        ] {
            let hits = swept(&db, data);
            assert_eq!(
                swept_row(&db, &hits, 0, 0),
                expected,
                "{:?}",
                String::from_utf8_lossy(data)
            );
        }
    }

    #[test]
    fn two_forms_of_one_string_are_one_occurrence() {
        // `xor(0-0)` is the plain form again, so this string searches for the
        // same bytes twice. The row is per string, so the occurrence is recorded
        // once: two entries at one offset would make `#a == 1` false.
        let db = database(TWO_FORMS);
        assert_eq!(
            db.sweep().stats().literals,
            1,
            "the two forms are the same bytes, so one pattern"
        );
        assert_eq!(db.sweep().stats().strings, 1);
        let hits = swept(&db, b"hi there hi");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(0, 2), (9, 2)]);
        assert_eq!(
            hits.found(),
            2,
            "one entry per occurrence, not one per form"
        );
    }

    #[test]
    fn the_same_bytes_in_two_rules_answer_both() {
        // The bytes go into the automaton once; the rows are per string, so each
        // rule reads its own. A sweep that answered only the first rule to
        // declare the string would make the second rule undetectable.
        let db = database(SHARED);
        assert_eq!(db.sweep().stats().literals, 1, "one pattern for both");
        assert_eq!(db.sweep().stats().strings, 2, "but two strings to answer");
        let hits = swept(&db, b"has a shared marker in it");
        assert_eq!(swept_row(&db, &hits, 0, 0), [(4, 15)]);
        assert_eq!(swept_row(&db, &hits, 1, 0), [(4, 15)]);
    }

    // -- what is not a row --------------------------------------------------

    #[test]
    fn a_string_the_automaton_cannot_carry_has_no_answer() {
        // `None`, not an empty row: an empty row is the claim that the buffer
        // holds none of this string, and a caller given that would skip the
        // search that is the only way to find out.
        let db = database(HEX_AND_REGEX);
        let hits = swept(&db, b"MZ\x90\x00 xxabbbcyy a plain string");
        assert!(
            db.sweep().matches(&hits, 0, 0).is_none(),
            "a hex pattern is not a fixed sequence"
        );
        assert!(
            db.sweep().matches(&hits, 0, 1).is_none(),
            "a regex is not one either"
        );
        assert_eq!(
            swept_row(&db, &hits, 0, 2),
            [(15, 14)],
            "and the literal beside them is answered as usual"
        );
    }

    #[test]
    fn a_name_that_is_not_a_string_is_not_answered() {
        // A corrupt database, in the same family as a slot past the end of a
        // match table. The answer that costs a search is the right one.
        let db = database(OVERLAPPING);
        let hits = swept(&db, b"aa");
        assert!(db.sweep().matches(&hits, 0, 1).is_none(), "no such slot");
        assert!(db.sweep().matches(&hits, 1, 0).is_none(), "no such rule");
    }

    #[test]
    fn a_table_that_has_not_been_run_answers_nothing() {
        // `Some(&[])` here would be a claim about a buffer this table has never
        // seen.
        let db = database(OVERLAPPING);
        let hits = db.sweep().hits();
        assert!(db.sweep().matches(&hits, 0, 0).is_none());
    }

    // -- reuse --------------------------------------------------------------

    #[test]
    fn a_second_scan_does_not_inherit_the_first_ones_hits() {
        // The failure that would have the engine report yesterday's file in
        // today's.
        let db = database(OVERLAPPING);
        let mut hits = db.sweep().hits();
        db.sweep().run(b"aa", &mut hits);
        assert_eq!(swept_row(&db, &hits, 0, 0), [(0, 2)]);
        db.sweep().run(b"qqqq", &mut hits);
        assert!(
            swept_row(&db, &hits, 0, 0).is_empty(),
            "the row still held the first buffer's offsets"
        );
        assert_eq!(hits.found(), 0);
    }

    #[test]
    fn an_empty_buffer_finds_nothing() {
        let db = database(OVERLAPPING);
        let hits = swept(&db, b"");
        assert!(swept_row(&db, &hits, 0, 0).is_empty());
    }

    #[test]
    fn a_needle_longer_than_the_buffer_finds_nothing() {
        let db = database(SHARED);
        let hits = swept(&db, b"a shared");
        assert!(swept_row(&db, &hits, 0, 0).is_empty());
    }

    // -- the contract -------------------------------------------------------

    /// Every form the expansion produces, in buffers that exercise it.
    ///
    /// Built here rather than kept as files, and shaped so that most rows find
    /// something: two empty results agreeing is not a test.
    fn buffers() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            b"qq".to_vec(),
            b"abcd efgh ABCD EFGH".to_vec(),
            b"cat concatenate cat_ !cat cat".to_vec(),
            b"ab\0a\0b\0".to_vec(),
            b"hi there hi".to_vec(),
            b"abcdabcdab".to_vec(),
            b"prefix c2VjcmV0 suffix".to_vec(),
            b"a longer phrase that is only here once, and a longer phrase that is only here once"
                .to_vec(),
        ]
    }

    /// A sweep row has to be the row a search for the same string would give.
    ///
    /// This is the contract [`CompiledString::literal_forms`] states: the sweep
    /// stands in for [`CompiledString::find_all`], so it must report exactly
    /// what that reports — the same offsets, the same lengths, the same count —
    /// over every kind of form the expansion produces. The forms are where a row
    /// can gain an entry: a `nocase` form is a second automaton, a `wide` form
    /// is longer than the plain one, and a form that is the plain one again is
    /// the same bytes twice.
    ///
    /// Checked against the matcher rather than against a hand-written list,
    /// because a hand-written list would be a second guess at what the answer is
    /// rather than the answer itself.
    #[test]
    fn a_swept_row_is_the_row_a_search_would_give() {
        let db = database(MIXED);
        let slots = db.rule(0).expect("the rule is there").program.string_count;
        let mut per_slot = vec![0usize; slots as usize];
        for data in &buffers() {
            let hits = swept(&db, data);
            for slot in 0..slots {
                let ours = swept_row(&db, &hits, 0, slot);
                per_slot[slot as usize] += ours.len();
                assert_eq!(
                    ours,
                    searched_row(&db, 0, slot, data),
                    "slot {slot} on {:?}",
                    String::from_utf8_lossy(data)
                );
            }
        }
        // Two empty results agreeing proves almost nothing, so every string has
        // to have been found somewhere: a row that was empty on both sides says
        // nothing about the forms it was built from.
        for (slot, matches) in per_slot.iter().enumerate() {
            assert!(
                *matches > 0,
                "slot {slot} matched nothing in any buffer, so its row was never compared"
            );
        }
    }

    /// A database that has been written and read back sweeps the same.
    ///
    /// The sweep is rebuilt from the rules on load rather than serialised, so
    /// this is what says the two paths agree. A loaded database that swept
    /// differently from the one that compiled it would detect differently
    /// depending on whether the engine had restarted since the database was
    /// built, which is the kind of difference nobody ever reproduces.
    #[test]
    fn a_loaded_database_sweeps_the_same() {
        let db = database(MIXED);
        let bytes = db.to_bytes().expect("the database must serialise");
        let loaded = RuleDatabase::from_bytes(&bytes).expect("and load back");
        assert_eq!(loaded.sweep().stats(), db.sweep().stats());

        for data in &buffers() {
            let before = swept(&db, data);
            let after = swept(&loaded, data);
            for rule in 0..db.rules().len() as u32 {
                let slots = db
                    .rule(rule)
                    .expect("every rule is present")
                    .program
                    .string_count;
                for slot in 0..slots {
                    assert_eq!(
                        db.sweep().matches(&before, rule, slot),
                        loaded.sweep().matches(&after, rule, slot),
                        "rule {rule} slot {slot} on {:?}",
                        String::from_utf8_lossy(data)
                    );
                }
            }
        }
    }
}
