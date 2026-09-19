//! Where the strings of a rule were found.
//!
//! This is the handover between the matchers and the interpreter. The matchers
//! scan the buffer once for every atom in the rule set and know, per string,
//! every offset it occurred at; the interpreter needs to answer `$a`, `#a`,
//! `@a[2]`, `!a`, `$a at 4096` and `$a in (0..512)` about exactly that. Keeping
//! the two apart means the interpreter can be tested against a hand-built table
//! with no scanner involved — which is the only way to test that `@a[2]` is the
//! *second* match rather than the third.
//!
//! # Sorted, and why it matters
//!
//! Offsets within a slot are kept in ascending order. `@a[i]` is defined as the
//! i-th match, so an unsorted table would make a rule's answer depend on the
//! order a hash map happened to iterate in — the same file would be judged
//! differently between runs, and a rule that fires today would not fire
//! tomorrow. Order is part of the interface, not an implementation detail.

/// One occurrence of a string.
///
/// `offset` and `length` are both in bytes. `length` varies between matches of
/// the same string whenever the pattern has alternatives or variable jumps —
/// `{ 41 [2-6] 42 }` matches anything from four to eight bytes — so it cannot
/// be derived from the string's definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Match {
    pub offset: u32,
    pub length: u32,
}

impl Match {
    pub fn new(offset: u32, length: u32) -> Self {
        Self { offset, length }
    }

    /// One past the last byte of the match.
    pub fn end(&self) -> u32 {
        self.offset.saturating_add(self.length)
    }
}

/// Every match found for one rule, indexed by string slot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchSet {
    slots: Vec<Vec<Match>>,
}

impl MatchSet {
    /// An empty table with room for `string_count` strings.
    pub fn with_capacity(string_count: usize) -> Self {
        Self {
            slots: vec![Vec::new(); string_count],
        }
    }

    pub fn string_count(&self) -> usize {
        self.slots.len()
    }

    /// Record a match.
    ///
    /// A slot past the end is dropped rather than panicking. The slot comes
    /// from a compiled program, so an out-of-range one means the program and
    /// the table disagree about how many strings the rule has — a corrupt
    /// database, not a rule author's mistake. Dropping it makes that rule
    /// under-match; panicking would take down the scanner on a file the user
    /// merely opened.
    pub fn push(&mut self, slot: u32, m: Match) {
        if let Some(list) = self.slots.get_mut(slot as usize) {
            list.push(m);
        }
    }

    /// Put every slot's matches in ascending offset order.
    ///
    /// Called once after matching. Matchers emit in whatever order their
    /// automaton walks, which is not sorted.
    pub fn sort(&mut self) {
        for list in &mut self.slots {
            list.sort_unstable();
        }
    }

    /// Drop overlapping duplicates in every slot, keeping the earliest and
    /// longest.
    pub fn dedup(&mut self) {
        for slot in 0..self.slots.len() as u32 {
            self.dedup_slot(slot);
        }
    }

    /// The same, for one slot, after its matches have just been found.
    ///
    /// The same bytes can be found by more than one variant of a string —
    /// `"abc" ascii wide xor` produces several matchers that can land on the
    /// same span — and a string that reports two matches where it has one makes
    /// `#a == 1` false and `all of them` unsatisfiable. Two matches that start
    /// at the same offset are one occurrence; the longer reading is kept
    /// because it is the one that consumed more of the buffer.
    ///
    /// Doing this per string rather than once at the end is also what puts a
    /// slot's offsets in order as soon as they are known, which `@a[i]`
    /// depends on and which is much cheaper to maintain incrementally than to
    /// re-establish later.
    pub fn dedup_slot(&mut self, slot: u32) {
        if let Some(list) = self.slots.get_mut(slot as usize) {
            list.sort_unstable();
            list.dedup_by(|later, earlier| {
                if later.offset == earlier.offset {
                    earlier.length = earlier.length.max(later.length);
                    true
                } else {
                    false
                }
            });
        }
    }

    pub fn matches(&self, slot: u32) -> &[Match] {
        self.slots.get(slot as usize).map_or(&[], Vec::as_slice)
    }

    /// How many times the string matched.
    pub fn count(&self, slot: u32) -> u32 {
        self.matches(slot).len() as u32
    }

    pub fn has(&self, slot: u32) -> bool {
        !self.matches(slot).is_empty()
    }

    pub fn first(&self, slot: u32) -> Option<Match> {
        self.matches(slot).first().copied()
    }

    /// The `index`-th match, counting from one.
    ///
    /// One-based because that is what the language uses: `@a` and `@a[1]` mean
    /// the same thing, and `@a[0]` is undefined. Off-by-one here is invisible
    /// in a rule that only ever asks for `@a`, and silently wrong in one that
    /// asks for `@a[2]`.
    pub fn nth(&self, slot: u32, index: i64) -> Option<Match> {
        let index = usize::try_from(index).ok()?;
        if index == 0 {
            return None;
        }
        self.matches(slot).get(index - 1).copied()
    }

    /// Whether some match begins exactly at `offset`.
    ///
    /// Binary search rather than a scan: `$a at <n>` inside a `for` loop asks
    /// this question once per element, over a string that may have thousands of
    /// matches.
    pub fn at(&self, slot: u32, offset: i64) -> bool {
        let Ok(offset) = u32::try_from(offset) else {
            return false;
        };
        self.matches(slot)
            .binary_search_by_key(&offset, |m| m.offset)
            .is_ok()
    }

    /// Whether some match lies entirely inside `from..to`.
    ///
    /// Entirely, not merely starting there: `$a in (0..4)` asks whether `$a` is
    /// found within the first four bytes, and a five-byte string starting at
    /// offset 3 is not. Allowing a match to hang past the end would let a rule
    /// claim a string is inside a region it overruns.
    pub fn in_range(&self, slot: u32, from: i64, to: i64) -> bool {
        if from > to {
            return false;
        }
        self.matches(slot)
            .iter()
            .any(|m| i64::from(m.offset) >= from && i64::from(m.end()) <= to)
    }

    /// Discard every match of `slot` that is not wholly inside `from..to`.
    ///
    /// Used when a rule's `$a in (x..y)` is known ahead of interpretation, so a
    /// string with a thousand matches outside the region does not have to be
    /// walked. Lives here because the invariant that matters — offsets stay
    /// sorted — is this type's to keep.
    pub fn retain_in_range(&mut self, slot: u32, from: i64, to: i64) {
        if let Some(list) = self.slots.get_mut(slot as usize) {
            list.retain(|m| i64::from(m.offset) >= from && i64::from(m.end()) <= to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(entries: &[(u32, u32, u32)]) -> MatchSet {
        let mut s = MatchSet::with_capacity(4);
        for (slot, offset, length) in entries {
            s.push(*slot, Match::new(*offset, *length));
        }
        s.sort();
        s
    }

    #[test]
    fn a_slot_with_no_match_reports_nothing() {
        let s = set(&[]);
        assert!(!s.has(0));
        assert_eq!(s.count(0), 0);
        assert_eq!(s.first(0), None);
        assert_eq!(s.nth(0, 1), None);
    }

    #[test]
    fn the_nth_match_is_one_based() {
        // `@a` and `@a[1]` are the same match. Getting this wrong is invisible
        // in a rule that only asks for `@a`.
        let s = set(&[(0, 100, 4), (0, 200, 4), (0, 300, 4)]);
        assert_eq!(s.nth(0, 1), Some(Match::new(100, 4)));
        assert_eq!(s.nth(0, 2), Some(Match::new(200, 4)));
        assert_eq!(s.nth(0, 3), Some(Match::new(300, 4)));
        assert_eq!(s.nth(0, 4), None);
        assert_eq!(s.first(0), s.nth(0, 1));
    }

    #[test]
    fn index_zero_and_negative_are_undefined() {
        let s = set(&[(0, 100, 4)]);
        assert_eq!(s.nth(0, 0), None);
        assert_eq!(s.nth(0, -1), None);
    }

    #[test]
    fn matches_are_ordered_by_offset_whatever_order_they_arrived_in() {
        let mut s = MatchSet::with_capacity(1);
        s.push(0, Match::new(300, 4));
        s.push(0, Match::new(100, 4));
        s.push(0, Match::new(200, 4));
        s.sort();
        assert_eq!(
            s.matches(0).iter().map(|m| m.offset).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    #[test]
    fn a_string_found_twice_at_one_offset_is_one_match() {
        // `ascii wide xor` gives several matchers that can land on the same
        // span. Two entries for one occurrence makes `#a == 1` false.
        let mut s = MatchSet::with_capacity(1);
        s.push(0, Match::new(50, 4));
        s.push(0, Match::new(50, 4));
        s.dedup();
        assert_eq!(s.count(0), 1);
    }

    #[test]
    fn deduplicating_at_one_offset_keeps_the_longer_reading() {
        // `{ 41 [2-6] 42 }` can report a short match and a long one at the same
        // start; the long one is the reading that consumed the buffer.
        let mut s = MatchSet::with_capacity(1);
        s.push(0, Match::new(50, 4));
        s.push(0, Match::new(50, 7));
        s.dedup();
        assert_eq!(s.matches(0), &[Match::new(50, 7)]);
    }

    #[test]
    fn deduplicating_keeps_distinct_offsets() {
        let mut s = MatchSet::with_capacity(1);
        s.push(0, Match::new(50, 4));
        s.push(0, Match::new(60, 4));
        s.dedup();
        assert_eq!(s.count(0), 2);
    }

    #[test]
    fn at_needs_the_match_to_begin_there_exactly() {
        let s = set(&[(0, 4096, 8)]);
        assert!(s.at(0, 4096));
        assert!(!s.at(0, 4097), "a match starting later is not at 4096");
        assert!(!s.at(0, 4095));
        assert!(!s.at(0, -1));
    }

    #[test]
    fn in_needs_the_whole_match_inside_the_range() {
        let s = set(&[(0, 0, 8)]);
        assert!(s.in_range(0, 0, 8), "the range is inclusive of the end");
        assert!(!s.in_range(0, 0, 7), "a match overrunning the end is not inside");
        assert!(!s.in_range(0, 1, 100));
    }

    #[test]
    fn an_empty_or_inverted_range_matches_nothing() {
        let s = set(&[(0, 5, 1)]);
        assert!(!s.in_range(0, 10, 0));
        assert!(!s.in_range(0, 5, 5), "a zero-width range holds no byte");
    }

    #[test]
    fn a_slot_past_the_end_is_dropped_rather_than_panicking() {
        // Reachable from a corrupt rule database. The cost is one rule that
        // under-matches; the alternative is a scanner that dies on a file
        // somebody opened.
        let mut s = MatchSet::with_capacity(1);
        s.push(99, Match::new(0, 1));
        assert_eq!(s.count(99), 0);
        assert!(!s.has(99));
    }

    #[test]
    fn retain_in_range_narrows_a_slot_to_the_region() {
        let mut s = set(&[(0, 0, 4), (0, 100, 4), (0, 200, 4)]);
        s.retain_in_range(0, 50, 150);
        assert_eq!(s.matches(0), &[Match::new(100, 4)]);
    }

    #[test]
    fn match_end_saturates_rather_than_wrapping() {
        // A length near u32::MAX comes from a corrupt table. Wrapping would
        // turn an absurd match into one that looks like it ends at zero.
        let m = Match::new(u32::MAX - 1, 100);
        assert_eq!(m.end(), u32::MAX);
    }
}
