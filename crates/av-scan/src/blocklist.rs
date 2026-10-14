//! Exact-match detection: a file whose digest a rule already knows.
//!
//! # Where the hashes come from
//!
//! The rule set. A rule that identifies a sample by content carries the
//! digests in its own metadata — that is what a hash in a rule *is* — so there
//! is no second corpus to keep in step with the first, and no import step that
//! can silently fall behind. [`Blocklist::build`] walks the database once and
//! collects them.
//!
//! # Why this is a separate stage and not a rule
//!
//! A hash match is the one detection in this engine with no meaningful
//! false-positive rate: SHA-256 does not collide, so a file whose digest a rule
//! names *is* the sample that rule names. That makes it [`decisive`], and
//! decisive detections short-circuit the score and survive both trust and the
//! thresholds.
//!
//! It is also the cheapest detection available — three passes over the buffer,
//! no parsing, no automaton — and it is worth running before anything that
//! costs more, because a known-bad file does not need its import table read.
//!
//! [`decisive`]: av_core::Detection::decisive
//!
//! # What is computed, and what is not
//!
//! A scan does not compute every digest it could. It computes SHA-256 always,
//! because that is the file's identity and the report carries it; it computes
//! MD5 and SHA-1 only when some rule in the loaded set names a hash of that
//! width. A corpus with no MD5 in it costs no MD5 pass, and that is not a
//! micro-optimisation — on a full-disk scan it is one whole pass over every
//! byte of every file.

use std::collections::HashMap;

use av_core::{Digests, HashKind};
use av_rules::database::RuleDatabase;

/// A digest in the blocklist that matched the file being scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHit {
    /// Index into [`RuleDatabase::rules`] of a rule carrying this hash.
    pub rule: u32,
    /// Which algorithm produced the digest that matched.
    pub kind: HashKind,
    /// The digest, lowercase, as the rule wrote it.
    pub hash: String,
}

/// The exact-match blocklist, built from a rule set's metadata.
#[derive(Debug, Default)]
pub struct Blocklist {
    /// Lowercase hex digest to a rule index. One entry per distinct digest: a
    /// sample named by four rules is still one sample, and reporting it four
    /// times would be four detections for one file.
    entries: HashMap<String, u32>,
    /// How many entries there are of each width, indexed by [`HashKind`].
    counts: [usize; 3],
    /// Entries that are not a digest at all, with the reason.
    ///
    /// Kept rather than dropped. A rule with a hash of the wrong length is a
    /// rule that can never fire, which is one detection the product does not
    /// have, and the number is the only place that shows up.
    rejected: Vec<(String, &'static str)>,
    /// Rules that carry a hash the blocklist already had.
    duplicates: usize,
}

impl Blocklist {
    /// Collect every hash the rule set carries.
    pub fn build(database: &RuleDatabase) -> Self {
        let mut list = Self::default();
        for (hash, rule) in database.hashes() {
            match classify_hash(hash) {
                Ok(kind) => {
                    let normalised = hash.to_ascii_lowercase();
                    // `entry` rather than `insert`: the first rule to name a
                    // sample is the one reported, and the choice is stable
                    // because `hashes()` walks the rule set in order.
                    match list.entries.entry(normalised) {
                        std::collections::hash_map::Entry::Occupied(_) => {
                            list.duplicates = list.duplicates.saturating_add(1);
                        }
                        std::collections::hash_map::Entry::Vacant(slot) => {
                            slot.insert(rule);
                            list.counts[hash_kind_index(kind)] += 1;
                        }
                    }
                }
                Err(why) => list.rejected.push((hash.to_owned(), why)),
            }
        }
        list
    }

    /// How many distinct digests are known.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no rule carries a digest at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many digests of `kind` the list holds.
    pub fn count_of(&self, kind: HashKind) -> usize {
        self.counts[hash_kind_index(kind)]
    }

    /// Whether a digest of this kind is worth computing.
    pub fn needs(&self, kind: HashKind) -> bool {
        self.count_of(kind) > 0
    }

    /// Hashes that could not be read as a digest, and why.
    pub fn rejected(&self) -> &[(String, &'static str)] {
        &self.rejected
    }

    /// Hashes that named a sample the list already had.
    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// The first digest in `digests` that the blocklist knows.
    ///
    /// Strongest first. It cannot matter to the verdict — a hit is decisive
    /// whichever width it was — but it decides which digest the report names,
    /// and naming the SHA-256 is more useful to whoever reads it than naming
    /// the MD5.
    pub fn lookup(&self, digests: &Digests) -> Option<BlockHit> {
        for (kind, digest) in [
            (HashKind::Sha256, digests.sha256.as_deref()),
            (HashKind::Sha1, digests.sha1.as_deref()),
            (HashKind::Md5, digests.md5.as_deref()),
        ] {
            let Some(digest) = digest else { continue };
            // The stored keys are lowercase and so are the computed digests, so
            // this is a plain lookup. It is written as one rather than as a
            // case-insensitive scan because a scan happens per file and a
            // `to_lowercase` allocation per lookup is a real cost at disk speed.
            if let Some(&rule) = self.entries.get(digest) {
                return Some(BlockHit {
                    rule,
                    kind,
                    hash: digest.to_owned(),
                });
            }
        }
        None
    }
}

/// The index of a kind in [`Blocklist::counts`].
fn hash_kind_index(kind: HashKind) -> usize {
    match kind {
        HashKind::Md5 => 0,
        HashKind::Sha1 => 1,
        HashKind::Sha256 => 2,
    }
}

/// Which digest a string is, from its length and its alphabet.
///
/// Case is not an error. A rule that writes a digest in uppercase is comparing
/// against the same file, and refusing it would be refusing a detection over a
/// spelling; [`Blocklist::build`] lowercases it instead.
fn classify_hash(text: &str) -> Result<HashKind, &'static str> {
    for kind in [HashKind::Md5, HashKind::Sha1, HashKind::Sha256] {
        if kind.is_well_formed(text) {
            return Ok(kind);
        }
    }
    // One message for both failures, because the fix is the same either way:
    // the literal has to be rewritten. Naming the length it does have is the
    // part that helps.
    Err(match text.len() {
        32 | 40 | 64 => "a digest of this length contains a non-hexadecimal character",
        _ => "not a digest: the length matches no supported algorithm",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::HashKind;

    fn digests(md5: Option<&str>, sha1: Option<&str>, sha256: Option<&str>) -> Digests {
        Digests {
            md5: md5.map(str::to_owned),
            sha1: sha1.map(str::to_owned),
            sha256: sha256.map(str::to_owned),
        }
    }

    /// A blocklist with the entries named, bypassing the rule set so that the
    /// lookup itself is what is under test.
    fn list(entries: &[(&str, u32)]) -> Blocklist {
        let mut list = Blocklist::default();
        for (hash, rule) in entries {
            let kind = classify_hash(hash).expect("a well-formed digest");
            list.entries.insert((*hash).to_owned(), *rule);
            list.counts[hash_kind_index(kind)] += 1;
        }
        list
    }

    #[test]
    fn a_known_digest_is_found() {
        let sha = "a".repeat(64);
        let list = list(&[(&sha, 7)]);
        let hit = list
            .lookup(&digests(None, None, Some(&sha)))
            .expect("the digest is in the list");
        assert_eq!(hit.rule, 7);
        assert_eq!(hit.kind, HashKind::Sha256);
        assert_eq!(hit.hash, sha);
    }

    #[test]
    fn the_strongest_digest_is_the_one_reported() {
        // All three are known and all three match: the report names the
        // SHA-256, because that is the one a user can check anywhere.
        let md5 = "b".repeat(32);
        let sha1 = "c".repeat(40);
        let sha256 = "d".repeat(64);
        let list = list(&[(&md5, 1), (&sha1, 2), (&sha256, 3)]);
        let hit = list
            .lookup(&digests(Some(&md5), Some(&sha1), Some(&sha256)))
            .expect("a hit");
        assert_eq!(hit.kind, HashKind::Sha256);
        assert_eq!(hit.rule, 3);
    }

    #[test]
    fn a_digest_that_is_not_known_is_not_a_hit() {
        let list = list(&[(&"a".repeat(64), 1)]);
        assert!(list
            .lookup(&digests(None, None, Some(&"b".repeat(64))))
            .is_none());
        assert!(list.lookup(&Digests::default()).is_none());
    }

    #[test]
    fn only_the_widths_the_list_holds_are_worth_computing() {
        let list = list(&[(&"a".repeat(64), 1)]);
        assert!(list.needs(HashKind::Sha256));
        assert!(!list.needs(HashKind::Md5));
        assert!(!list.needs(HashKind::Sha1));
        assert_eq!(list.count_of(HashKind::Sha256), 1);
    }

    #[test]
    fn a_well_formed_digest_is_recognised_by_its_length() {
        assert_eq!(classify_hash(&"a".repeat(32)), Ok(HashKind::Md5));
        assert_eq!(classify_hash(&"a".repeat(40)), Ok(HashKind::Sha1));
        assert_eq!(classify_hash(&"a".repeat(64)), Ok(HashKind::Sha256));
        assert_eq!(classify_hash(&"A".repeat(64)), Ok(HashKind::Sha256));
    }

    #[test]
    fn a_literal_that_is_not_a_digest_says_which_way_it_is_wrong() {
        // The right length with a character that cannot be hexadecimal, and the
        // right alphabet with a length no algorithm produces. Both are a rule
        // that can never fire, but naming the mistake is what makes it fixable.
        assert_eq!(
            classify_hash(&"z".repeat(64)),
            Err("a digest of this length contains a non-hexadecimal character")
        );
        assert_eq!(
            classify_hash("deadbeef"),
            Err("not a digest: the length matches no supported algorithm")
        );
    }

    #[test]
    fn an_empty_blocklist_finds_nothing_and_needs_nothing() {
        let list = Blocklist::default();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        for kind in [HashKind::Md5, HashKind::Sha1, HashKind::Sha256] {
            assert!(!list.needs(kind));
        }
    }
}
