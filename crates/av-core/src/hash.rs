//! The digests the whole product agrees on: what a rule compares against, what
//! the scan cache keys on, and what a report shows a user.
//!
//! # One implementation, three callers
//!
//! A rule asks for `hash.md5(offset, size)`; the scanner computes a file's
//! digests before anything else; the cache and the report both display them. If
//! those were three implementations the day would come when they disagreed, and
//! the disagreement would look like a detection that fires in one place and not
//! another. They are one function here.
//!
//! # Why these three and not more
//!
//! MD5, SHA-1 and SHA-256, because those are the three the rule language names
//! and the three a threat-intelligence feed publishes. CRC-32 is deliberately
//! **not** here: it is a checksum whose textual form is engine-specific — one
//! rule language writes it as decimal, another as hex — and a rule comparing
//! against the wrong spelling would never match. That is a silent false
//! negative, so the compiler refuses `hash.crc32` by name instead. See
//! [`crate`]'s note on refusals.
//!
//! # Not a security boundary
//!
//! Collision resistance is irrelevant to every use here. MD5 and SHA-1 are
//! present because the corpus and the feeds are written in them, not because
//! anything trusts them: an attacker who wants a file to *evade* a hash match
//! does not need a collision, they need to change one byte. The hashes are
//! identifiers, and the engine's actual decisions are made by the rule text.

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

/// A digest a rule or a report can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashKind {
    Md5,
    Sha1,
    Sha256,
}

impl HashKind {
    /// How the algorithm reads in a rule and in a report.
    pub const fn as_str(self) -> &'static str {
        match self {
            HashKind::Md5 => "md5",
            HashKind::Sha1 => "sha1",
            HashKind::Sha256 => "sha256",
        }
    }

    /// The lowercase hexadecimal digest of `data`.
    ///
    /// Lowercase and unpadded-in-the-sense-of-fixed-width, which is to say
    /// exactly the spelling every feed and every rule in the corpus uses: a
    /// hash written in uppercase, or with `0x`, is a comparison that never
    /// matches and never says so.
    pub fn digest(self, data: &[u8]) -> String {
        match self {
            HashKind::Md5 => hex(&Md5::digest(data)),
            HashKind::Sha1 => hex(&Sha1::digest(data)),
            HashKind::Sha256 => hex(&Sha256::digest(data)),
        }
    }

    /// The digest's length in characters, for a caller sizing a buffer or
    /// validating a literal.
    pub const fn hex_len(self) -> usize {
        match self {
            HashKind::Md5 => 32,
            HashKind::Sha1 => 40,
            HashKind::Sha256 => 64,
        }
    }

    /// Whether `text` is a digest of this algorithm.
    ///
    /// Used to tell a rule author that their literal is the wrong length or
    /// contains a character that cannot be hexadecimal — a mistake worth
    /// naming, because a rule comparing a 64-character SHA-256 against an MD5
    /// is a detection that can never fire.
    pub fn is_well_formed(self, text: &str) -> bool {
        text.len() == self.hex_len() && text.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// A byte slice as lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    // `hex::encode` writes lowercase, which is the spelling compared against.
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digests_are_the_published_ones_for_the_empty_string() {
        // The three canonical vectors, quoted from every reference on the
        // algorithms. They are here because a digest that is wrong in a
        // systematic way — byte order, padding, an uppercase table — produces
        // plausible-looking output that no other test in this file would catch.
        assert_eq!(
            HashKind::Md5.digest(b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            HashKind::Sha1.digest(b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            HashKind::Sha256.digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_digests_are_the_published_ones_for_a_known_input() {
        assert_eq!(
            HashKind::Md5.digest(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            HashKind::Sha1.digest(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            HashKind::Sha256.digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn every_digest_is_lowercase_and_the_length_it_claims() {
        for kind in [HashKind::Md5, HashKind::Sha1, HashKind::Sha256] {
            let digest = kind.digest(b"the quick brown fox");
            assert_eq!(digest.len(), kind.hex_len(), "{kind:?}");
            assert_eq!(digest, digest.to_lowercase(), "{kind:?}");
            assert!(kind.is_well_formed(&digest), "{kind:?}");
        }
    }

    #[test]
    fn a_literal_of_the_wrong_length_or_alphabet_is_not_well_formed() {
        assert!(HashKind::Md5.is_well_formed("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!HashKind::Md5.is_well_formed("d41d8cd9"), "too short");
        // A SHA-256 written where an MD5 is expected: the rule is a detection
        // that can never fire, which is what this predicate exists to say.
        assert!(!HashKind::Md5
            .is_well_formed("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(!HashKind::Md5.is_well_formed("d41d8cd98f00b204e9800998ecf8427g"));
    }
}
