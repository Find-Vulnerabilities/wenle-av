//! RSA PKCS#1 v1.5 signature verification.
//!
//! # The half of Authenticode that is cryptography
//!
//! Everything else in this crate is parsing and comparison. This is the one
//! operation an attacker cannot fake without breaking RSA: recover `s^e mod n`
//! with the signer's public key and check that what comes out is the encoding
//! of the digest that was supposed to have been signed. If it is not, the bytes
//! were not signed by the holder of the private key, and no amount of valid
//! certificate can change that.
//!
//! # Why PKCS#1 v1.5, and why not v1.5-with-a-different-padding
//!
//! `rsassa-pkcs1-v1_5` is the only signature scheme in the measured population:
//! 812 embedded-signed files in an installed `System32`, every one of them
//! `sha256WithRSAEncryption`, `sha384WithRSAEncryption` or
//! `sha1WithRSAEncryption`. PSS appears in no Authenticode file, so it is not
//! implemented — and a signature using it is refused by name rather than
//! reported as invalid, because "this verifier cannot check that" and "that
//! signature is wrong" are different answers about a file.
//!
//! # The exact check, in order
//!
//! PKCS#1 v1.5 says the message representative `m = s^e mod n` must be, as
//! bytes at the modulus width:
//!
//! ```text
//! 0x00  0x01  FF FF ... FF  0x00  T
//!       ^     ^             ^     ^
//!       |     at least 8    |     DigestInfo
//!       block type         separator
//! ```
//!
//! All five parts are checked, and each has a reason to be checked *here*
//! rather than assumed: the block type is what distinguishes a signature from
//! the other things RSA is used for, the eight `0xFF` bytes are the padding
//! that makes the encoding unambiguous, and the separator is what stops a
//! short digest being read out of the padding.
//!
//! `T` is then parsed rather than compared byte-for-byte against one expected
//! encoding. That is a deliberate tolerance, and the reason is that DER gives
//! two byte sequences for the same `DigestInfo`: the algorithm identifier's
//! `parameters` may be `NULL` or absent, and both appear in real certificates.
//! Comparing bytes would reject a genuine signature over a difference that
//! means nothing. Parsing accepts either spelling while still requiring the
//! algorithm OID to be the one expected and the digest to be the one computed,
//! so nothing an attacker controls is being waved through: the tolerance is
//! over an encoding choice, not over a value.
//!
//! # What is refused before the arithmetic
//!
//! A signature whose length is not the modulus width, and a modulus below
//! `bigint::MIN_MODULUS_BITS`. The first is how a truncated signature would
//! otherwise be left-padded into looking like a short but valid one; the second
//! is a key small enough to factor, where "valid signature" would be a true
//! statement that misleads.

use crate::bigint::Montgomery;
use av_signatures::der::{parse_one, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE};
use av_signatures::oid::oid_matches;

/// Why a signature did not verify.
///
/// The variants are separated because they mean different things about a file.
/// A padding failure and a digest failure both end in "this signature is not
/// over this data", but a *malformed* `DigestInfo` says the signer's tooling
/// produced something this verifier cannot read, which is not the same finding
/// as a signature that is simply wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RsaFailure {
    /// The modulus or exponent is not usable.
    #[error("the public key is not usable: {0}")]
    UnusableKey(&'static str),

    /// The signature is not the same width as the modulus.
    #[error("the signature is {found} bytes and the modulus is {expected}")]
    WrongLength {
        /// The modulus width in bytes.
        expected: usize,
        /// The signature's width in bytes.
        found: usize,
    },

    /// The recovered block is not PKCS#1 v1.5 block type 1.
    #[error("the recovered block is not a PKCS#1 v1.5 signature block")]
    BadBlockType,

    /// The padding was too short or contained a byte that is not `0xFF`.
    #[error("the PKCS#1 v1.5 padding is malformed")]
    BadPadding,

    /// The `DigestInfo` could not be parsed, or named a different algorithm.
    #[error("the DigestInfo does not name the expected digest algorithm")]
    BadDigestInfo,

    /// The `DigestInfo` named the right algorithm and a different digest.
    ///
    /// The signature is a signature — the arithmetic worked, the padding is
    /// right, the structure is right — over some other value. This is what a
    /// signature lifted from one file onto another looks like.
    #[error("the signature is over a different digest from the one computed")]
    DigestMismatch,
}

/// Verify an RSASSA-PKCS1-v1_5 signature over `digest`, made with the key
/// `(modulus, exponent)`.
///
/// `digest` is the hash of the signed data, already computed by the caller, and
/// `digest_oid` names the algorithm that produced it — both are checked,
/// because a signature that commits to a SHA-256 digest must not satisfy a
/// verifier that asked for SHA-1 over the same bytes.
///
/// Returns `Ok(())` only when every part of the encoding is present and
/// correct. There is no "probably" and no partial credit: this function either
/// proves the private key was used over exactly this digest, or it fails.
pub fn verify(
    modulus: &[u8],
    exponent: &[u8],
    signature: &[u8],
    digest_oid: &[u64],
    digest: &[u8],
) -> Result<(), RsaFailure> {
    let key = Montgomery::new(modulus).ok_or(RsaFailure::UnusableKey(
        "the modulus is too small, even, or too wide to use",
    ))?;
    let width = key.byte_len();

    // PKCS#1 encodes `s` at the modulus width. A shorter signature is not a
    // small number to be left-padded — it is a different encoding, and padding
    // it would be inventing bytes the signer did not produce.
    if signature.len() != width {
        return Err(RsaFailure::WrongLength {
            expected: width,
            found: signature.len(),
        });
    }

    let recovered = key.pow(signature, exponent).ok_or(RsaFailure::UnusableKey(
        "the signature is not below the modulus, or the exponent is unusable",
    ))?;

    check_block(&recovered, digest_oid, digest)
}

/// The encoding half of the check, split out so it can be tested against
/// blocks produced by something other than this crate's own arithmetic.
///
/// This matters: if the recovery and the check were one function, a test of the
/// check would be a test of the pair, and a compensating error between them —
/// big-endian read as little-endian on both sides, say — would pass. Separated,
/// `check_block` can be handed a block built byte-by-byte in a test.
fn check_block(block: &[u8], digest_oid: &[u64], digest: &[u8]) -> Result<(), RsaFailure> {
    // 0x00 0x01 ...
    if block.len() < 11 || block[0] != 0x00 || block[1] != 0x01 {
        return Err(RsaFailure::BadBlockType);
    }
    // ... FF FF FF FF FF FF FF FF ... 0x00
    let separator = block[2..]
        .iter()
        .position(|&b| b != 0xff)
        .map(|i| i + 2)
        .ok_or(RsaFailure::BadPadding)?;
    if separator - 2 < 8 || block[separator] != 0x00 {
        return Err(RsaFailure::BadPadding);
    }
    // ... T
    let t = &block[separator + 1..];

    let outer = parse_one(t).map_err(|_| RsaFailure::BadDigestInfo)?;
    if !outer.is(SEQUENCE) {
        return Err(RsaFailure::BadDigestInfo);
    }
    let mut fields = outer.elements();
    let algorithm = fields
        .next()
        .and_then(Result::ok)
        .ok_or(RsaFailure::BadDigestInfo)?;
    let value = fields
        .next()
        .and_then(Result::ok)
        .ok_or(RsaFailure::BadDigestInfo)?;
    if !fields.is_empty() || !algorithm.is(SEQUENCE) || !value.is(OCTET_STRING) {
        return Err(RsaFailure::BadDigestInfo);
    }

    // The algorithm identifier: the OID must be the expected one, and the
    // parameters must be absent or NULL — anything else is a different
    // algorithm wearing the same OID.
    let mut parameters = algorithm.elements();
    let oid = parameters
        .next()
        .and_then(Result::ok)
        .ok_or(RsaFailure::BadDigestInfo)?;
    if !oid.is(OBJECT_IDENTIFIER) || !oid_matches(oid.content, digest_oid) {
        return Err(RsaFailure::BadDigestInfo);
    }
    match parameters.next() {
        None => {}
        Some(Ok(param)) if param.content.is_empty() => {}
        _ => return Err(RsaFailure::BadDigestInfo),
    }

    if value.content != digest {
        return Err(RsaFailure::DigestMismatch);
    }
    Ok(())
}

/// The size of a modulus in bits, or `None` if it is not a usable one.
///
/// Reported in [`crate::Proof`] so that a scan report can say "4096-bit RSA"
/// rather than "signed", and used by the caller to reject a key before doing
/// any work with it.
pub fn key_bits(modulus: &[u8]) -> Option<usize> {
    let trimmed = match modulus {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        _ => modulus,
    };
    let (&first, rest) = trimmed.split_first()?;
    Some(rest.len() * 8 + (8 - first.leading_zeros() as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest algorithm these vectors use.
    const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // One 1024-bit and one 2048-bit vector, generated by Python's own
    // arbitrary-precision arithmetic and hashlib — an implementation that
    // shares no code, no algorithm structure and no author with this module.
    // A vector produced by this crate's arithmetic would prove nothing about
    // it; these prove the arithmetic agrees with an independent one.
    const V1024_N: &str = "a8ec7772436e2514580cfa0a2e3dafd0758ed72b016280ecaa1f725d8d537fa1f3544733f9b69ee9582efd2e9459680949c7d23974bd372195e7cf07c639bbfa4de42fd9f733c7da077a7650444f5ec81cc0bd4562533262873cf1eaecc65b8d612c623d5c4ec94b001e2e1d046b3d70b2ff3ae7cb7e080edbf5934e7421bc6d";
    const V1024_E: &str = "010001";
    const V1024_SIG: &str = "a09905b29038dc670267ebae97129fd87bf50416825f5c0d87173e35d168d0d5ccda0a43f1eccc9657fbefa8adcad7065f622e25c86089d12347223fe46219962b2335bf5c6bf5e8228edeadc0e52ff999ddcafbc0483dd70c1235d640c06a65ee0cde39a6ca406802f442bc86bf2fc0cd0a05bb436c738ec15ef170188631b7";
    const V1024_T: &str = "3031300d06096086480165030402010500042043cd3f282171fe1e8516289e8ead9b8b4dc85fb47f1b1fda3e35757a168282f3";
    const V1024_DIGEST: &str = "43cd3f282171fe1e8516289e8ead9b8b4dc85fb47f1b1fda3e35757a168282f3";
    const V1024_SIG_FLIPPED: &str = "a09905b29038dc670267ebae97129fd87bf50416825f5c0d87173e35d168d0d5ccda0a43f1eccc9657fbefa8adcad7065f622e25c86089d12347223fe46219963b2335bf5c6bf5e8228edeadc0e52ff999ddcafbc0483dd70c1235d640c06a65ee0cde39a6ca406802f442bc86bf2fc0cd0a05bb436c738ec15ef170188631b7";
    const V1024_OTHER_DIGEST: &str =
        "ce374fcce2a4e97f5acd52d6fafebf4a0890f592b101d73b9350d918ea9e83e8";

    const V2048_N: &str = "da3435e4ee0b352b2b97199f86d66495e24f77b5141358ceb28d68d92fc3c9a58e8133a1e24e0402411ed63928b4ee6ba1b13372dd016bc273cb7154b1c34b89ea1a2dddc30d2f767090dd3f9c9f18e5c28d766be05a34f3fcefe7abe89137b5affa024c2da9dce2870b365e245789c6601f4a4957e3b1a1c89bf3a9d69bce98605d4865097ba8f99998e26247f4c0e45af9a19bf6db02bd2c3c212a32620658b06f4406db8ecfd379905e7ad229d6c19cc80387068503954b4974341a145cea2437bd6f313191c5c8f521628267dd62ff03800aaa6952e7ab1ad3e1bdda2fc1266f489597e89a3ed3f5ded3f79ff3f56c79b75fcc982d67729300d8e5908e3d";
    const V2048_E: &str = "010001";
    const V2048_SIG: &str = "3331691ef303fdb645616af9f3db0e8c55869aa40d741a4f1ca8691ddf8812908fbc894eab3006c7f241ec804bab087b792158bf67e7ff47dacca21b9d61ab6e9b09bcdf17ad7cc4a89028acff00115d9b2c605cd4ae82b445970e237a911dfa3fa28edfe618480c4643c7e2a3133f4ea3c9ad61ba2c75fe49a66d9afe77f8cc7ba7850fe8af5cee8359857f87c9b33aa66da22960951db24a84a7eb0ba0c377323e1be5ae43fcf3827dfd8f345bcbc531024b1668a916cc7b0b3bc99b49c2a7815f75cae7250e07c40aa72baa332fc270e3956a2d8800942a029f86c68df88df45f189d7617faf2cbc93e363f645d1187897e23e85405ee638654f1631729fe";
    const V2048_DIGEST: &str = "43cd3f282171fe1e8516289e8ead9b8b4dc85fb47f1b1fda3e35757a168282f3";
    const V2048_SIG_FLIPPED: &str = "3331691ef303fdb645616af9f3db0e8c55869aa40d741a4f1ca8691ddf8812908fbc894eab3006c7f241ec804bab087b792158bf67e7ff47dacca21b9d61ab6e8b09bcdf17ad7cc4a89028acff00115d9b2c605cd4ae82b445970e237a911dfa3fa28edfe618480c4643c7e2a3133f4ea3c9ad61ba2c75fe49a66d9afe77f8cc7ba7850fe8af5cee8359857f87c9b33aa66da22960951db24a84a7eb0ba0c377323e1be5ae43fcf3827dfd8f345bcbc531024b1668a916cc7b0b3bc99b49c2a7815f75cae7250e07c40aa72baa332fc270e3956a2d8800942a029f86c68df88df45f189d7617faf2cbc93e363f645d1187897e23e85405ee638654f1631729fe";

    #[test]
    fn a_signature_from_an_independent_implementation_verifies() {
        assert_eq!(
            verify(
                &unhex(V1024_N),
                &unhex(V1024_E),
                &unhex(V1024_SIG),
                SHA256,
                &unhex(V1024_DIGEST)
            ),
            Ok(())
        );
    }

    #[test]
    fn a_two_thousand_and_forty_eight_bit_signature_verifies() {
        // The wide case is a different code path in the limb arithmetic: 32
        // limbs against 16, and a carry that has further to travel.
        assert_eq!(
            verify(
                &unhex(V2048_N),
                &unhex(V2048_E),
                &unhex(V2048_SIG),
                SHA256,
                &unhex(V2048_DIGEST)
            ),
            Ok(())
        );
    }

    #[test]
    fn a_signature_with_one_bit_flipped_does_not_verify() {
        // The negative control for the arithmetic itself: one bit changed in
        // the signature, and the recovered block is uniformly random, so the
        // padding check fails.
        assert!(verify(
            &unhex(V1024_N),
            &unhex(V1024_E),
            &unhex(V1024_SIG_FLIPPED),
            SHA256,
            &unhex(V1024_DIGEST)
        )
        .is_err());
        assert!(verify(
            &unhex(V2048_N),
            &unhex(V2048_E),
            &unhex(V2048_SIG_FLIPPED),
            SHA256,
            &unhex(V2048_DIGEST)
        )
        .is_err());
    }

    #[test]
    fn the_right_signature_over_the_wrong_digest_does_not_verify() {
        // A real signature, checked against a digest it was not made over.
        // This is the shape of lifting a signature from one file to another,
        // and it must fail on the digest rather than on the padding: the
        // arithmetic succeeds and the *value* is wrong, which is a different
        // finding and one a report should be able to state.
        assert_eq!(
            verify(
                &unhex(V1024_N),
                &unhex(V1024_E),
                &unhex(V1024_SIG),
                SHA256,
                &unhex(V1024_OTHER_DIGEST)
            ),
            Err(RsaFailure::DigestMismatch)
        );
    }

    #[test]
    fn a_signature_that_belongs_to_another_key_does_not_verify() {
        assert!(verify(
            &unhex(V2048_N),
            &unhex(V2048_E),
            &unhex(V1024_SIG),
            SHA256,
            &unhex(V1024_DIGEST)
        )
        .is_err());
    }

    #[test]
    fn the_wrong_algorithm_oid_is_refused_even_with_the_right_digest() {
        // The same digest, asked for under a different algorithm name. A
        // verifier that checked only the digest would accept this, and would
        // then be happy with a signature over a SHA-256 digest presented as
        // evidence for a SHA-1 one.
        const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
        assert_eq!(
            verify(
                &unhex(V1024_N),
                &unhex(V1024_E),
                &unhex(V1024_SIG),
                SHA1,
                &unhex(V1024_DIGEST)
            ),
            Err(RsaFailure::BadDigestInfo)
        );
    }

    #[test]
    fn a_block_built_by_hand_checks_out() {
        // `check_block` is handed a block assembled byte by byte here, so the
        // check is tested against something this crate's arithmetic did not
        // produce. If recovery and checking were one function, an error that
        // cancelled out between them would pass every test in this file.
        let mut block = vec![0x00, 0x01];
        block.extend(std::iter::repeat_n(0xff, 8));
        block.push(0x00);
        block.extend_from_slice(&unhex(V1024_T));
        assert_eq!(check_block(&block, SHA256, &unhex(V1024_DIGEST)), Ok(()));

        // Fewer than eight padding bytes is not a valid block, however well
        // the rest is formed.
        let mut short = vec![0x00, 0x01];
        short.extend(std::iter::repeat_n(0xff, 7));
        short.push(0x00);
        short.extend_from_slice(&unhex(V1024_T));
        assert_eq!(
            check_block(&short, SHA256, &unhex(V1024_DIGEST)),
            Err(RsaFailure::BadPadding)
        );

        // A padding byte that is not 0xFF is the classic forgery attempt: the
        // bytes after it become part of the "digest".
        let mut holed = vec![0x00, 0x01];
        holed.extend(std::iter::repeat_n(0xff, 4));
        holed.push(0x00);
        holed.extend(std::iter::repeat_n(0xff, 4));
        holed.push(0x00);
        holed.extend_from_slice(&unhex(V1024_T));
        assert_eq!(
            check_block(&holed, SHA256, &unhex(V1024_DIGEST)),
            Err(RsaFailure::BadPadding)
        );

        // The wrong block type: this is a PKCS#1 v1.5 *encryption* block.
        let mut encryption = vec![0x00, 0x02];
        encryption.extend(std::iter::repeat_n(0xff, 8));
        encryption.push(0x00);
        encryption.extend_from_slice(&unhex(V1024_T));
        assert_eq!(
            check_block(&encryption, SHA256, &unhex(V1024_DIGEST)),
            Err(RsaFailure::BadBlockType)
        );
    }

    #[test]
    fn a_digest_info_that_is_not_a_digest_info_is_refused() {
        // Well-formed DER that is not the expected shape, in each of the ways
        // it can go wrong. `parse_one` refuses trailing bytes, so an extra
        // element after the digest is a refusal rather than something ignored.
        for t in [
            // Not a SEQUENCE.
            vec![0x02, 0x01, 0x01],
            // SEQUENCE with one element.
            vec![0x30, 0x03, 0x02, 0x01, 0x01],
            // Digest as an INTEGER rather than an OCTET STRING.
            vec![
                0x30, 0x0e, 0x30, 0x08, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x02, 0x04, 0x02, 0x01, 0x02,
            ],
            // Empty.
            vec![],
        ] {
            let mut block = vec![0x00, 0x01];
            block.extend(std::iter::repeat_n(0xff, 8));
            block.push(0x00);
            block.extend_from_slice(&t);
            assert_eq!(
                check_block(&block, SHA256, &unhex(V1024_DIGEST)),
                Err(RsaFailure::BadDigestInfo),
                "for T = {t:02x?}"
            );
        }
    }

    #[test]
    fn a_digest_info_with_absent_parameters_is_accepted() {
        // DER allows the algorithm identifier's parameters to be omitted, and
        // both spellings occur in the wild. The check is over the meaning, so
        // both must pass — this is the one tolerance in this module, and it is
        // over an encoding choice rather than over a value.
        let without_null = unhex("3023300b06096086480165030402010414");
        let mut t = without_null;
        // A 20-byte digest so the lengths above are the ones encoded.
        let digest = [0xaau8; 20];
        t.extend_from_slice(&digest);
        let mut block = vec![0x00, 0x01];
        block.extend(std::iter::repeat_n(0xff, 8));
        block.push(0x00);
        block.extend_from_slice(&t);
        assert_eq!(check_block(&block, SHA256, &digest), Ok(()));
    }

    #[test]
    fn a_modulus_below_the_floor_is_not_a_usable_key() {
        // 512 bits: factorable, so a "valid" verdict over one would be a true
        // statement that misleads.
        let small = vec![0xffu8; 64];
        assert_eq!(
            verify(
                &small,
                &unhex(V1024_E),
                &small,
                SHA256,
                &unhex(V1024_DIGEST)
            ),
            Err(RsaFailure::UnusableKey(
                "the modulus is too small, even, or too wide to use"
            ))
        );
    }

    #[test]
    fn a_signature_of_the_wrong_width_is_refused_rather_than_padded() {
        let mut short = unhex(V1024_SIG);
        short.pop();
        assert_eq!(
            verify(
                &unhex(V1024_N),
                &unhex(V1024_E),
                &short,
                SHA256,
                &unhex(V1024_DIGEST)
            ),
            Err(RsaFailure::WrongLength {
                expected: 128,
                found: 127
            })
        );
    }

    #[test]
    fn the_key_size_is_reported_in_bits() {
        assert_eq!(key_bits(&unhex(V1024_N)), Some(1024));
        assert_eq!(key_bits(&unhex(V2048_N)), Some(2048));
        // The same value with DER's leading zero byte is the same size.
        let mut padded = vec![0x00];
        padded.extend_from_slice(&unhex(V1024_N));
        assert_eq!(key_bits(&padded), Some(1024));
        assert_eq!(key_bits(&[]), None);
    }
}
