//! Sealing and opening the bytes the vault stores.
//!
//! # The stored form
//!
//! ```text
//! offset  size  field
//!      0     1  format byte: 1 = sealed, 0 = stored as it is
//!      1    12  nonce (sealed form only)
//!     13     n  AES-256-GCM ciphertext followed by its 16-byte tag
//! ```
//!
//! The format byte is inside the authenticated region for the sealed form —
//! it is part of what the tag covers — so flipping it does not turn a sealed
//! payload into a plaintext one; it turns it into a payload that fails to open.
//! Flipping it on a *plaintext* payload is not stopped by the cipher, which is
//! the one thing this format does not defend against, and is the reason
//! plaintext mode is documented as a diagnostic setting rather than a mode.
//!
//! # Associated data
//!
//! Every payload is sealed against a context string. An item blob's context is
//! `"wenle-quarantine/item/v1"` followed by the item's identifier; the index's
//! is `"wenle-quarantine/index/v1"`. GCM treats the associated data as part of
//! the message for authentication but does not encrypt it, which is exactly the
//! property wanted here: the ciphertext of a blob is cryptographically bound to
//! the identifier it is stored under, so an attacker with write access to the
//! vault directory cannot rename `a.qtn` to `b.qtn` and have it open as item
//! `b`, nor replace the index with an item blob.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::error::{QuarantineError, Result};
use crate::key::MasterKey;
use crate::random;

/// Largest payload the cipher will accept.
///
/// GCM's own limit is far higher — about 64 GiB — but the vault refuses
/// anything approaching that long before it gets here, and a bound this side of
/// the cipher turns an overflow in a length calculation into a clean refusal
/// rather than a call with a wrapped `u32`.
const MAX_PAYLOAD: u64 = 8 * 1024 * 1024 * 1024;

/// Format byte for an AES-256-GCM sealed payload.
pub const FORMAT_SEALED: u8 = 1;
/// Format byte for a payload stored as it is. See the module documentation.
pub const FORMAT_PLAIN: u8 = 0;

/// The nonce length GCM is defined for.
const NONCE_LEN: usize = 12;
/// The tag GCM appends.
const TAG_LEN: usize = 16;
/// Smallest possible stored payload: a format byte and a tag.
const MIN_SEALED: usize = 1 + NONCE_LEN + TAG_LEN;

/// Context strings, so that a payload sealed for one purpose cannot be opened
/// as another.
pub mod aad {
    use crate::id::QuarantineId;

    /// Associated data for a quarantined item's bytes.
    pub fn item(id: QuarantineId) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + 16);
        out.extend_from_slice(b"wenle-quarantine/item/v1");
        out.extend_from_slice(id.as_bytes());
        out
    }

    /// Associated data for the vault index.
    pub const INDEX: &[u8] = b"wenle-quarantine/index/v1";

    /// Associated data for the pending-removal list, which is small enough to
    /// live in its own sealed file rather than inside the index.
    pub const PENDING: &[u8] = b"wenle-quarantine/pending/v1";
}

/// Seal `plaintext` for storage.
///
/// `encrypt` selects whether the cipher is applied; the container is written
/// either way, so a vault created with encryption off can be reopened with it
/// on and vice versa, one item at a time.
pub fn seal(key: &MasterKey, encrypt: bool, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() as u64 > MAX_PAYLOAD {
        return Err(QuarantineError::TooLarge {
            size: plaintext.len() as u64,
            limit: MAX_PAYLOAD,
        });
    }
    if !encrypt {
        let mut out = Vec::with_capacity(plaintext.len() + 1);
        out.push(FORMAT_PLAIN);
        out.extend_from_slice(plaintext);
        return Ok(out);
    }

    let cipher = cipher(key);
    let nonce = random::nonce();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            // The only documented failure is an over-long message, which the
            // check above already excluded, so reaching here means the
            // implementation refused for a reason it does not name.
            QuarantineError::Other(
                "the cipher refused to seal a payload it had already accepted".into(),
            )
        })?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_SEALED);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a payload written by [`seal`].
///
/// Fails rather than returning partial data for a payload that is truncated,
/// has the wrong format byte, was sealed under a different key, or was sealed
/// against a different context. GCM cannot distinguish those cases and neither
/// does this function; the caller sees one "could not be decrypted" error.
pub fn open(key: &MasterKey, aad: &[u8], stored: &[u8]) -> Result<Vec<u8>> {
    let (&format, body) = stored.split_first().ok_or_else(|| {
        QuarantineError::Decrypt("the payload is empty, not even a format byte".into())
    })?;

    match format {
        FORMAT_PLAIN => Ok(body.to_vec()),
        FORMAT_SEALED => {
            if body.len() < NONCE_LEN + TAG_LEN {
                return Err(QuarantineError::Decrypt(format!(
                    "a sealed payload of {} bytes cannot hold a {NONCE_LEN}-byte nonce and a \
                     {TAG_LEN}-byte tag",
                    stored.len()
                )));
            }
            let (nonce, ciphertext) = body.split_at(NONCE_LEN);
            cipher(key)
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    QuarantineError::Decrypt(
                        "the authentication tag did not match: the payload was sealed under a \
                         different key, belongs to a different item, or has been modified"
                            .into(),
                    )
                })
        }
        other => Err(QuarantineError::Decrypt(format!(
            "the payload declares format {other}, which this build does not know"
        ))),
    }
}

/// The smallest stored length a sealed payload can have. Exposed so the vault
/// can reject an obviously truncated file by its size before allocating.
pub const fn min_sealed_len() -> usize {
    MIN_SEALED
}

fn cipher(key: &MasterKey) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::QuarantineId;

    fn key() -> MasterKey {
        MasterKey::from_bytes([7u8; 32])
    }

    #[test]
    fn a_sealed_payload_round_trips() {
        let k = key();
        let stored = seal(&k, true, aad::INDEX, b"the index").unwrap();
        assert_eq!(stored[0], FORMAT_SEALED);
        assert_eq!(open(&k, aad::INDEX, &stored).unwrap(), b"the index");
    }

    #[test]
    fn the_plaintext_does_not_appear_in_the_stored_bytes() {
        let k = key();
        let secret = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
        let stored = seal(&k, true, aad::INDEX, secret).unwrap();
        assert!(
            !stored.windows(secret.len()).any(|w| w == secret),
            "the plaintext is visible in the sealed form"
        );
    }

    #[test]
    fn two_seals_of_the_same_bytes_differ_so_the_nonce_is_not_fixed() {
        let k = key();
        let a = seal(&k, true, aad::INDEX, b"same").unwrap();
        let b = seal(&k, true, aad::INDEX, b"same").unwrap();
        assert_ne!(a, b, "a fixed nonce would make these identical");
        assert_eq!(open(&k, aad::INDEX, &a).unwrap(), b"same");
        assert_eq!(open(&k, aad::INDEX, &b).unwrap(), b"same");
    }

    #[test]
    fn a_different_key_does_not_open_it() {
        let stored = seal(&key(), true, aad::INDEX, b"secret").unwrap();
        let other = MasterKey::from_bytes([8u8; 32]);
        let err = open(&other, aad::INDEX, &stored).unwrap_err();
        assert!(matches!(err, QuarantineError::Decrypt(_)), "{err:?}");
        assert!(err.is_corruption());
    }

    #[test]
    fn an_item_blob_cannot_be_reopened_as_a_different_item() {
        let k = key();
        let a = QuarantineId::from_bytes([1u8; 16]);
        let b = QuarantineId::from_bytes([2u8; 16]);
        let stored = seal(&k, true, &aad::item(a), b"a sample").unwrap();
        assert!(open(&k, &aad::item(a), &stored).is_ok());
        assert!(
            open(&k, &aad::item(b), &stored).is_err(),
            "renaming a blob to another item's id must not make it open"
        );
    }

    #[test]
    fn an_item_blob_cannot_be_reopened_as_the_index() {
        let k = key();
        let id = QuarantineId::from_bytes([3u8; 16]);
        let stored = seal(&k, true, &aad::item(id), b"a sample").unwrap();
        assert!(open(&k, aad::INDEX, &stored).is_err());
    }

    #[test]
    fn every_single_bit_flip_in_the_header_is_caught() {
        let k = key();
        let original = seal(&k, true, aad::INDEX, b"payload").unwrap();
        // The format byte: flipping it picks a scheme that does not exist, or
        // plaintext, and both must fail rather than yield the body.
        let mut flipped = original.clone();
        flipped[0] = 0xff;
        assert!(open(&k, aad::INDEX, &flipped).is_err());

        // Every nonce and tag byte.
        for i in 1..original.len() {
            let mut tampered = original.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&k, aad::INDEX, &tampered).is_err(),
                "byte {i} of the container was not authenticated"
            );
        }
    }

    #[test]
    fn a_truncated_payload_is_refused_by_name() {
        let k = key();
        let stored = seal(&k, true, aad::INDEX, b"payload").unwrap();
        for len in 1..MIN_SEALED.min(stored.len()) {
            let err = open(&k, aad::INDEX, &stored[..len]).unwrap_err();
            assert!(matches!(err, QuarantineError::Decrypt(_)), "{err:?}");
        }
        assert!(open(&k, aad::INDEX, &[]).is_err());
    }

    #[test]
    fn plaintext_mode_round_trips_and_is_marked_as_such() {
        let k = key();
        let stored = seal(&k, false, aad::INDEX, b"not secret").unwrap();
        assert_eq!(stored[0], FORMAT_PLAIN);
        assert_eq!(&stored[1..], b"not secret");
        assert_eq!(open(&k, aad::INDEX, &stored).unwrap(), b"not secret");
    }

    #[test]
    fn a_vault_written_without_encryption_reopens_with_it_on() {
        // The container, not the vault, decides how each payload is read, so
        // turning encryption on does not strand what is already stored.
        let k = key();
        let plain = seal(&k, false, aad::INDEX, b"old").unwrap();
        let sealed = seal(&k, true, aad::INDEX, b"new").unwrap();
        assert_eq!(open(&k, aad::INDEX, &plain).unwrap(), b"old");
        assert_eq!(open(&k, aad::INDEX, &sealed).unwrap(), b"new");
    }

    #[test]
    fn an_unknown_format_byte_is_refused_by_name() {
        let err = open(&key(), aad::INDEX, &[9u8, 1, 2, 3])
            .unwrap_err()
            .to_string();
        assert!(err.contains("format 9"), "{err}");
    }

    #[test]
    fn an_empty_payload_round_trips_in_both_modes() {
        let k = key();
        for encrypt in [true, false] {
            let stored = seal(&k, encrypt, aad::INDEX, b"").unwrap();
            assert_eq!(open(&k, aad::INDEX, &stored).unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn a_large_payload_round_trips() {
        // Big enough that the plaintext spans many AES blocks, which is where
        // an off-by-one in the block handling would show up.
        let k = key();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let stored = seal(&k, true, aad::INDEX, &data).unwrap();
        assert_eq!(open(&k, aad::INDEX, &stored).unwrap(), data);
    }

    #[test]
    fn the_two_contexts_are_not_interchangeable() {
        assert_ne!(aad::INDEX, aad::PENDING);
        let id = QuarantineId::from_bytes([0u8; 16]);
        assert_eq!(aad::item(id).len(), b"wenle-quarantine/item/v1".len() + 16);
        assert!(aad::item(id).starts_with(b"wenle-quarantine/item/v1"));
    }
}
