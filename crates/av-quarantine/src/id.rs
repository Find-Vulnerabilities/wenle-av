//! Identifiers for quarantined items.
//!
//! # Why these are random and not derived
//!
//! The obvious identifier for a quarantined file is its SHA-256, and it is the
//! wrong one. Two files with the same content are the same file, so a
//! content-derived name silently collapses `bad.exe` quarantined from the
//! Downloads folder and `bad.exe` quarantined from a USB stick into one entry,
//! and restoring it puts one copy back where two were taken from. The vault
//! stores what happened to *files*, so an entry is identified by an event, and
//! an event has no content-derived name.
//!
//! Random also means an attacker cannot predict the path a blob will land on,
//! which matters the moment the vault directory is writable by anyone the
//! antivirus is protecting the machine from.
//!
//! # Why hexadecimal text and not a UUID
//!
//! Sixteen random bytes rendered as thirty-two lowercase hex characters. It
//! sorts lexicographically in the same order it sorts as bytes, it is a legal
//! Windows file name with no escaping, and it needs no dependency to parse. A
//! `Uuid` crate would add a version nibble and a hyphen layout that nothing
//! here reads.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::random;

/// The number of random bytes behind an identifier.
pub const ID_BYTES: usize = 16;

/// A random identifier for one quarantined item, rendered as 32 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QuarantineId([u8; ID_BYTES]);

impl QuarantineId {
    /// A fresh identifier from the operating system's random source.
    pub fn new() -> Self {
        let mut bytes = [0u8; ID_BYTES];
        random::fill(&mut bytes);
        Self(bytes)
    }

    /// Wrap bytes that came from somewhere else — the index on disk, or a test.
    pub const fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, which are also the associated data the payload is sealed
    /// against: a blob cannot be moved to another item's file without the tag
    /// check failing.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES] {
        &self.0
    }

    /// Parse the 32-character hexadecimal spelling.
    ///
    /// Accepts either case, because the only place this is fed from outside is
    /// a command line, and refusing `ABC...` would be a puzzle rather than a
    /// protection. Refuses anything that is not exactly 32 hex characters.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != ID_BYTES * 2 {
            return None;
        }
        let mut bytes = [0u8; ID_BYTES];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_value(text.as_bytes()[i * 2])?;
            let lo = hex_value(text.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Some(Self(bytes))
    }

    /// The 32-character lowercase spelling, which is also the blob's file name.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(ID_BYTES * 2);
        for byte in self.0 {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
        out
    }

    /// The first eight characters, for log lines and table rows where a full
    /// identifier would push everything else off the screen.
    pub fn short(self) -> String {
        self.to_hex()[..8].to_string()
    }

    /// The file name a blob is stored under.
    pub(crate) fn blob_name(self) -> String {
        format!("{}.qtn", self.to_hex())
    }
}

impl Default for QuarantineId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for QuarantineId {
    /// Prints the hex spelling rather than sixteen decimal bytes, since every
    /// other place this value appears — the index, the file name, the command
    /// line — uses hex and a test failure should show the same thing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuarantineId({})", self.to_hex())
    }
}

impl std::str::FromStr for QuarantineId {
    type Err = InvalidId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidId)
    }
}

/// Returned when a string is not a quarantine identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a quarantine id is exactly 32 hexadecimal characters")]
pub struct InvalidId;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_fresh_ids_differ() {
        assert_ne!(QuarantineId::new(), QuarantineId::new());
    }

    #[test]
    fn the_hex_spelling_round_trips() {
        let id = QuarantineId::new();
        let text = id.to_hex();
        assert_eq!(text.len(), 32);
        assert_eq!(QuarantineId::parse(&text), Some(id));
    }

    #[test]
    fn uppercase_is_accepted_but_never_produced() {
        let id = QuarantineId::new();
        let upper = id.to_hex().to_uppercase();
        assert_eq!(QuarantineId::parse(&upper), Some(id));
        assert_eq!(id.to_hex(), id.to_hex().to_lowercase());
    }

    #[test]
    fn the_wrong_length_or_a_non_hex_character_is_refused() {
        assert_eq!(QuarantineId::parse(""), None);
        assert_eq!(QuarantineId::parse(&"a".repeat(31)), None);
        assert_eq!(QuarantineId::parse(&"a".repeat(33)), None);
        assert_eq!(QuarantineId::parse(&"g".repeat(32)), None);
        assert_eq!(QuarantineId::parse(&"z".repeat(32)), None);
        // A hyphenated UUID is a plausible thing to paste in, and is refused
        // rather than silently half-parsed.
        assert_eq!(
            QuarantineId::parse("550e8400-e29b-41d4-a716-446655440000"),
            None
        );
    }

    #[test]
    fn every_byte_value_survives_the_hex_round_trip() {
        let bytes: [u8; ID_BYTES] = [
            0x00, 0x0f, 0x10, 0xff, 0x7a, 0x80, 0x01, 0xfe, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
            0x78, 0x9a,
        ];
        let id = QuarantineId::from_bytes(bytes);
        assert_eq!(id.to_hex(), "000f10ff7a8001feabcdef123456789a");
        assert_eq!(QuarantineId::parse(&id.to_hex()), Some(id));
    }

    #[test]
    fn the_short_form_is_the_first_eight_characters() {
        let id = QuarantineId::from_bytes([0xab; ID_BYTES]);
        assert_eq!(id.short(), "abababab");
        assert!(id.to_hex().starts_with(&id.short()));
    }

    #[test]
    fn a_blob_name_carries_the_extension_the_vault_owns() {
        let id = QuarantineId::from_bytes([0x00; ID_BYTES]);
        assert_eq!(id.blob_name(), "00000000000000000000000000000000.qtn");
    }

    #[test]
    fn display_debug_and_parse_from_str_agree() {
        let id = QuarantineId::new();
        assert_eq!(id.to_string(), id.to_hex());
        assert_eq!(format!("{id:?}"), format!("QuarantineId({})", id.to_hex()));
        assert_eq!(id.to_string().parse::<QuarantineId>(), Ok(id));
        assert!("nonsense".parse::<QuarantineId>().is_err());
    }
}
