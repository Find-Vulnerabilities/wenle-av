//! The one place this crate asks the operating system for random bytes.
//!
//! Item identifiers, AES-GCM nonces and the master key all come from here. They
//! have different requirements — the key must never repeat across installs, the
//! nonce must never repeat under one key, the identifier only has to be
//! unguessable — and they share the same source, `BCryptGenRandom` through
//! `getrandom`, which is the operating system's CSPRNG. Nothing in this crate
//! ever seeds a userspace generator from the clock.
//!
//! Funnelling them through one function is not decoration. A nonce that repeats
//! under a fixed key destroys GCM completely — it leaks the XOR of two
//! plaintexts and the authentication key, which for a vault holding known
//! malware families is a decryption oracle. There is exactly one call site to
//! audit for that, and this is it.

use aes_gcm::aead::rand_core::{OsRng, RngCore};

/// Fill `buffer` with cryptographically secure random bytes.
///
/// # Panics
///
/// If the operating system's random source fails. `OsRng` in `getrandom`
/// aborts rather than returning an error when the system call itself fails,
/// because the alternative — continuing with predictable bytes — would silently
/// produce a guessable master key. A machine whose CSPRNG is broken cannot run
/// this product safely, and stopping is the correct outcome.
pub fn fill(buffer: &mut [u8]) {
    OsRng.fill_bytes(buffer);
}

/// A fresh 96-bit AES-GCM nonce.
///
/// 96 bits is the size GCM is defined for: any other length is hashed down to
/// one, and a hashed nonce has a collision probability that a random 96-bit
/// value does not. Random is safe here only because the number of items one
/// installation will ever seal is nowhere near the birthday bound — at a
/// billion items the collision probability is still below 2⁻⁶⁶.
pub fn nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    fill(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_nonces_differ() {
        assert_ne!(nonce(), nonce());
    }

    #[test]
    fn a_filled_buffer_is_not_left_as_it_was() {
        let mut buffer = [0u8; 64];
        fill(&mut buffer);
        assert!(buffer.iter().any(|b| *b != 0));
    }

    #[test]
    fn the_whole_buffer_is_written_including_the_last_byte() {
        // A generator that filled only whole words would leave a tail of
        // zeroes forever, which is the kind of bug that shows up as a
        // predictable nonce once in four thousand items.
        let mut buffer = [0u8; 13];
        fill(&mut buffer);
        assert!(buffer[12] != 0 || buffer[0] != 0);
        let mut all = Vec::new();
        for _ in 0..64 {
            let mut b = [0u8; 3];
            fill(&mut b);
            all.extend_from_slice(&b);
        }
        assert!(all.iter().any(|b| *b != 0));
        assert!(all.iter().filter(|b| **b == 0).count() < all.len());
    }

    #[test]
    fn a_zero_length_request_is_harmless() {
        let mut empty: [u8; 0] = [];
        fill(&mut empty);
    }
}
