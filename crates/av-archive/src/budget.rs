//! The ceiling on how much a container is allowed to become.
//!
//! # The attack this exists for
//!
//! A zip bomb is a few kilobytes that expands to petabytes. The naive defence —
//! expand it, then check the size — is not a defence at all, because the check
//! runs after the memory has been spent. Every limit here is therefore applied
//! *while* the bytes are being produced: the decompressor is handed a writer
//! that refuses the byte after the ceiling, so the maximum memory a hostile
//! archive can cause to be allocated is the ceiling itself and not one byte
//! more.
//!
//! # The three ceilings, and why one is not enough
//!
//! * **Total expansion** bounds the whole walk. A container of ten thousand
//!   members, each of which is small, is bounded by this and not by any of the
//!   others.
//! * **Per member** bounds a single member. Without it, one member could
//!   consume the entire total and leave the other nine thousand unexamined —
//!   which is a way of hiding a payload behind a decoy, and a way of turning
//!   one refusal into a scan that found nothing.
//! * **Member count** bounds a container that declares a million empty members.
//!   Each costs nothing to expand and something to open, and an archive whose
//!   directory is the payload is a real thing.
//!
//! # What a refusal means
//!
//! It is a statement about the scan, not the file. The member was not read, so
//! nothing is known about it, and [`crate::ArchiveError::Budget`] is the error
//! that says so. The caller records it against the member and marks the walk
//! exhausted — never clean.
//!
//! # Ratio
//!
//! A fourth ceiling — the ratio of produced bytes to compressed bytes — is the
//! one a lay description of zip bombs usually names, and it is deliberately not
//! here. A ratio needs a denominator, and a member of one compressed byte that
//! produces a kilobyte of zeros is a perfectly ordinary run of a well-behaved
//! compressor. The absolute ceilings above are what actually bound the damage,
//! and adding a ratio on top would refuse ordinary files while not bounding
//! anything the others do not.

use crate::error::ArchiveError;
use crate::Result;

/// How much a single container is allowed to expand to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionBudget {
    /// Bytes still available across the whole container.
    remaining: u64,
    /// The largest single member this will produce.
    max_member: u64,
    /// Members still allowed to be opened.
    members_left: u32,
}

impl ExpansionBudget {
    /// A budget of `total` bytes, with no single member allowed above
    /// `max_member` and the default member ceiling.
    ///
    /// `max_member` is clamped to `total`: a member ceiling above the total is
    /// not a second limit, it is a confusing way of writing the first one.
    pub fn new(total: u64, max_member: u64) -> Self {
        Self {
            remaining: total,
            max_member: max_member.min(total),
            members_left: Self::DEFAULT_MEMBERS,
        }
    }

    /// How many members a container may open before the walk is called off.
    ///
    /// Four thousand is far above any archive a person made on purpose and far
    /// below the counts a directory-flood bomb uses. It is a member of the
    /// struct rather than a constant so that a caller scanning a known corpus
    /// can raise it without changing this crate.
    pub const DEFAULT_MEMBERS: u32 = 4096;

    /// Replace the member ceiling.
    #[must_use]
    pub fn with_member_limit(mut self, members: u32) -> Self {
        self.members_left = members;
        self
    }

    /// Bytes still available.
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// The largest single member this will produce.
    pub const fn max_member(&self) -> u64 {
        self.max_member
    }

    /// Members still allowed to be opened.
    pub const fn members_left(&self) -> u32 {
        self.members_left
    }

    /// True when nothing can be produced at all.
    pub const fn is_exhausted(&self) -> bool {
        self.remaining == 0 || self.members_left == 0
    }

    /// Claim one member slot, before any of its bytes are read.
    ///
    /// Separate from [`ExpansionBudget::spend`] because a member whose header
    /// is malformed never spends a byte and still costs a slot: the thing being
    /// bounded is the work of opening members, and an archive of a million
    /// broken headers is exactly as expensive as one of a million empty ones.
    pub fn open_member(&mut self) -> Result<()> {
        if self.members_left == 0 {
            return Err(ArchiveError::Budget {
                needed: 0,
                remaining: self.remaining,
            });
        }
        self.members_left -= 1;
        Ok(())
    }

    /// Claim `bytes` of the budget.
    pub fn spend(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.remaining {
            return Err(ArchiveError::Budget {
                needed: bytes,
                remaining: self.remaining,
            });
        }
        self.remaining -= bytes;
        Ok(())
    }

    /// How many bytes may be produced for one member, given both ceilings.
    ///
    /// This is the number the decompressor's writer is capped at. It is
    /// `remaining.min(max_member)` and not either alone: the member ceiling
    /// stops one member eating the whole budget, and the remaining budget stops
    /// the last member overrunning the total that the earlier ones have already
    /// partly spent.
    pub const fn allowance(&self) -> u64 {
        if self.max_member < self.remaining {
            self.max_member
        } else {
            self.remaining
        }
    }

    /// Whether a member of this declared size may be opened at all.
    ///
    /// Asked before the member is read, so that a header declaring four
    /// gigabytes is refused without a decompressor ever being constructed for
    /// it. A container that lies about the size downwards is caught by
    /// [`ExpansionBudget::spend`] when the real bytes arrive, and one that lies
    /// upwards is caught here — which is the right way round, because the lie
    /// that costs memory is the one that would have gone unnoticed.
    pub fn admits(&self, declared: u64) -> bool {
        declared <= self.allowance() && self.members_left > 0
    }
}

impl Default for ExpansionBudget {
    fn default() -> Self {
        Self::new(1024 * 1024 * 1024, 256 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_ceiling_above_the_total_is_the_total() {
        let budget = ExpansionBudget::new(100, 1000);
        assert_eq!(budget.max_member(), 100);
        assert_eq!(budget.allowance(), 100);
    }

    #[test]
    fn spending_reduces_what_is_left_and_refuses_to_overdraw() {
        let mut budget = ExpansionBudget::new(100, 100);
        budget.spend(60).expect("within the budget");
        assert_eq!(budget.remaining(), 40);
        budget.spend(40).expect("exactly the budget");
        assert_eq!(budget.remaining(), 0);
        assert!(budget.is_exhausted());

        let error = budget.spend(1).expect_err("one byte too far");
        assert_eq!(error.skip_reason(), av_core::SkipReason::Budget);
    }

    #[test]
    fn the_allowance_is_whichever_ceiling_is_reached_first() {
        // Member ceiling first, while the total has room.
        let mut budget = ExpansionBudget::new(1000, 100);
        assert_eq!(budget.allowance(), 100);
        // Total first, once earlier members have eaten into it.
        budget.spend(950).expect("within the budget");
        assert_eq!(budget.allowance(), 50);
    }

    #[test]
    fn a_member_is_admitted_by_its_declared_size_before_it_is_read() {
        let budget = ExpansionBudget::new(1000, 100);
        assert!(budget.admits(100));
        assert!(budget.admits(0));
        // A header claiming four gigabytes, on a budget that will never produce
        // them. Refused at the door, which is the only refusal that saves the
        // memory the read would have taken.
        assert!(!budget.admits(4 * 1024 * 1024 * 1024));
        assert!(!budget.admits(101));
    }

    #[test]
    fn opening_members_is_bounded_separately_from_their_bytes() {
        let mut budget = ExpansionBudget::new(u64::MAX, u64::MAX).with_member_limit(2);
        budget.open_member().expect("the first");
        budget.open_member().expect("the second");
        assert_eq!(budget.members_left(), 0);
        assert!(budget.is_exhausted());
        // Reading nothing at all still runs out: the thing bounded is the work
        // of opening members, and a million empty ones cost a million opens.
        assert!(budget.open_member().is_err());
        assert!(budget.remaining() > 0);
    }

    #[test]
    fn a_member_is_not_admitted_once_the_member_ceiling_is_reached() {
        let budget = ExpansionBudget::new(u64::MAX, u64::MAX).with_member_limit(0);
        assert!(!budget.admits(0));
    }

    #[test]
    fn the_default_budget_is_the_one_the_configuration_names() {
        // One gibibyte of expansion, a quarter of a gibibyte per member. Stated
        // as a test because `av_core::ScanOptions::default` carries the same
        // two numbers and the two must not drift.
        let budget = ExpansionBudget::default();
        assert_eq!(budget.remaining(), 1024 * 1024 * 1024);
        assert_eq!(budget.max_member(), 256 * 1024 * 1024);
        assert_eq!(budget.members_left(), ExpansionBudget::DEFAULT_MEMBERS);
    }
}
