//! `SpcIndirectDataContent`, which is what an Authenticode signature is really
//! over.
//!
//! # Where this sits in the chain of equalities
//!
//! A signature is not over the file. It is over a small DER structure that
//! *names* the file by its digest:
//!
//! ```text
//! SpcIndirectDataContent ::= SEQUENCE {
//!     data            SpcAttributeTypeAndOptionalValue,
//!     messageDigest   DigestInfo }
//!
//! SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
//!     type    OBJECT IDENTIFIER,
//!     value   [0] EXPLICIT ANY OPTIONAL }
//!
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm     AlgorithmIdentifier,
//!     digest              OCTET STRING }
//! ```
//!
//! The `data` field says what the digest is a digest *of* — for a program,
//! `SPC_PE_IMAGE_DATA_OBJID`, `1.3.6.1.4.1.311.2.1.15`. The `messageDigest` is
//! the Authenticode image digest computed by [`crate::digest`], and comparing
//! the two is [`crate::InvalidReason::FileDigestMismatch`] when they differ.
//! That comparison is the whole reason a tampered file is detected: the
//! signature stays intact because the attacker cannot forge it, and the number
//! inside it stops matching the bytes on disk.
//!
//! # The digest algorithm is named twice
//!
//! Once here and once in the `SignerInfo`, and they are allowed to differ in
//! principle — the `SpcIndirectDataContent` digest could be SHA-256 while the
//! signature over it is SHA-1. This crate reads this one for the *file* digest
//! and the `SignerInfo`'s for the signature, and never assumes they are the
//! same. Assuming they were would produce a verifier that reports a mismatch
//! for a file that is correctly signed with two algorithms.
//!
//! # The optional value, and why it is reported but not acted on
//!
//! `value` is present in a minority of real signatures and carries
//! `SpcPeImageData`, which can in turn name a page-hash form of the digest.
//! Whether it is present does not change where the digest is taken from: the
//! `messageDigest` field is the image digest either way, and a file signed with
//! page hashes still has its `messageDigest` computed over the whole image. So
//! the flag is carried into the proof — a reader comparing this crate's output
//! against `signtool`'s wants to know — and nothing branches on it. If a real
//! file turns out to have the page-hash scope, the measurement over the 812
//! will say so: it would fail to verify, and it would fail loudly.

use crate::digest::DigestAlgorithm;
use crate::error::AuthError;
use av_signatures::der::{Tlv, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE};
use av_signatures::SignatureError;

/// The digest an Authenticode signature states, and what it states it over.
#[derive(Debug, Clone)]
pub struct SpcIndirectData<'a> {
    /// The `data` type, dotted. `1.3.6.1.4.1.311.2.1.15` for a program.
    pub data_type: String,
    /// Whether the `data` field carried a value.
    pub has_data_value: bool,
    /// The digest algorithm the file digest was taken with.
    pub digest_algorithm: DigestAlgorithm,
    /// The digest the signer committed to.
    pub digest: &'a [u8],
}

impl SpcIndirectData<'_> {
    /// Whether the digest is stated over a Windows PE image.
    pub fn is_pe_image(&self) -> bool {
        self.data_type == "1.3.6.1.4.1.311.2.1.15"
    }
}

/// Parse the encapsulated content of an Authenticode signature.
pub fn parse<'a>(content: &'a [u8]) -> Result<SpcIndirectData<'a>, AuthError> {
    let root = av_signatures::der::parse_one(content).map_err(AuthError::Malformed)?;
    if !root.is(SEQUENCE) {
        return Err(AuthError::BadIndirectData {
            reason: "the encapsulated content is not a sequence",
        });
    }
    let mut fields = root.elements();
    let data = fields.next().and_then(Result::ok).ok_or_else(short)?;
    let message_digest = fields.next().and_then(Result::ok).ok_or_else(short)?;

    let (data_type, has_data_value) = parse_data(&data)?;
    let (digest_algorithm, digest) = parse_digest_info(&message_digest)?;

    Ok(SpcIndirectData {
        data_type,
        has_data_value,
        digest_algorithm,
        digest,
    })
}

/// `SpcAttributeTypeAndOptionalValue ::= SEQUENCE { type OID, value [0] OPTIONAL }`.
fn parse_data(data: &Tlv<'_>) -> Result<(String, bool), AuthError> {
    if !data.is(SEQUENCE) {
        return Err(AuthError::BadIndirectData {
            reason: "the data field is not a sequence",
        });
    }
    let mut fields = data.elements();
    let id = fields.next().and_then(Result::ok).ok_or_else(short)?;
    if !id.is(OBJECT_IDENTIFIER) {
        return Err(AuthError::BadIndirectData {
            reason: "the data field has no type",
        });
    }
    let dotted = av_signatures::oid::dotted(id.content);
    // The value is not read. It is recorded as present so that a report says
    // what was in the file — see the module documentation for why nothing
    // branches on it.
    let has_data_value = fields.next().is_some();
    Ok((dotted, has_data_value))
}

/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`.
fn parse_digest_info<'a>(
    message_digest: &Tlv<'a>,
) -> Result<(DigestAlgorithm, &'a [u8]), AuthError> {
    if !message_digest.is(SEQUENCE) {
        return Err(AuthError::BadIndirectData {
            reason: "the messageDigest field is not a sequence",
        });
    }
    let mut fields = message_digest.elements();
    let algorithm = fields.next().and_then(Result::ok).ok_or_else(short)?;
    let digest = fields.next().and_then(Result::ok).ok_or_else(short)?;

    if !algorithm.is(SEQUENCE) {
        return Err(AuthError::BadIndirectData {
            reason: "the digest algorithm is not a sequence",
        });
    }
    let mut algorithm_fields = algorithm.elements();
    let id = algorithm_fields
        .next()
        .and_then(Result::ok)
        .ok_or_else(short)?;
    if !id.is(OBJECT_IDENTIFIER) {
        return Err(AuthError::BadIndirectData {
            reason: "the digest algorithm has no OID",
        });
    }
    let Some(digest_algorithm) = DigestAlgorithm::from_oid(id.content) else {
        return Err(AuthError::UnsupportedDigestAlgorithm {
            oid: av_signatures::oid::dotted(id.content),
        });
    };

    if !digest.is(OCTET_STRING) {
        return Err(AuthError::BadIndirectData {
            reason: "the digest is not an octet string",
        });
    }
    if digest.content.len() != digest_algorithm.output_len() {
        // A digest of the wrong length is not a digest that will not match —
        // it is a structure that does not mean what it says, and reporting it
        // as a mismatch would blame the file for a malformed signature.
        return Err(AuthError::BadIndirectData {
            reason: "the digest is not the length its algorithm produces",
        });
    }

    Ok((digest_algorithm, digest.content))
}

/// A truncated structure, which is the error every `ok_or` above wants.
fn short() -> AuthError {
    AuthError::Malformed(SignatureError::UnexpectedEnd { wanted: SEQUENCE })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing as fixture;

    const SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    const SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];

    #[test]
    fn a_real_shaped_indirect_data_parses() {
        let content = fixture::spc_indirect_data(SHA256, &[0xab; 32]);
        let parsed = parse(&content).unwrap();
        assert!(parsed.is_pe_image());
        assert!(
            !parsed.has_data_value,
            "the fixture omits the optional value"
        );
        assert_eq!(parsed.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(parsed.digest, &[0xab; 32]);
    }

    #[test]
    fn the_file_digest_algorithm_is_read_independently_of_the_signature_algorithm() {
        // A SHA-1 file digest, which six of the 812 measured files have. A
        // verifier that assumed the two algorithms matched would report these
        // as malformed.
        let content = fixture::spc_indirect_data(SHA1, &[0xcd; 20]);
        let parsed = parse(&content).unwrap();
        assert_eq!(parsed.digest_algorithm, DigestAlgorithm::Sha1);
        assert_eq!(parsed.digest.len(), 20);
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused_rather_than_compared() {
        // Truncating the digest is the cheapest way to build a file that
        // "verifies" against something shorter. It never reaches the
        // comparison: this is a malformed signature, not a mismatch, and the
        // two lead to different sentences in a report.
        let content = fixture::spc_indirect_data(SHA256, &[0xab; 16]);
        assert!(matches!(
            parse(&content),
            Err(AuthError::BadIndirectData { .. })
        ));
        // And a digest that is too long.
        let content = fixture::spc_indirect_data(SHA256, &[0xab; 64]);
        assert!(matches!(
            parse(&content),
            Err(AuthError::BadIndirectData { .. })
        ));
    }

    #[test]
    fn an_unsupported_digest_algorithm_is_named() {
        let content = fixture::spc_indirect_data(&[1, 2, 840, 113549, 3, 2], &[0xab; 16]);
        match parse(&content) {
            Err(AuthError::UnsupportedDigestAlgorithm { oid }) => {
                assert_eq!(oid, "1.2.840.113549.3.2")
            }
            other => panic!("expected an unsupported digest algorithm, got {other:?}"),
        }
    }

    #[test]
    fn a_structure_that_is_not_indirect_data_is_refused() {
        assert!(matches!(parse(&[]), Err(AuthError::Malformed(_))));
        assert!(matches!(
            parse(&[0x30, 0x00]),
            Err(AuthError::Malformed(_)) | Err(AuthError::BadIndirectData { .. })
        ));
        // The right outer shape with the wrong field where the digest goes.
        let wrong = fixture::seq(&[
            fixture::seq(&[fixture::oid(fixture::SPC_PE_IMAGE_DATA)]),
            fixture::tlv(0x04, &[0x00]),
        ]);
        assert!(matches!(
            parse(&wrong),
            Err(AuthError::BadIndirectData { .. })
        ));
    }

    #[test]
    fn the_pe_image_data_oid_is_the_one_a_program_is_signed_with() {
        // Pinned by rendering, because `is_pe_image` compares this string: a
        // wrong arc here would silently make every real file report a digest
        // over something this crate does not reproduce.
        assert_eq!(
            av_signatures::oid::dotted(&av_signatures::testing::encode(fixture::SPC_PE_IMAGE_DATA)),
            "1.3.6.1.4.1.311.2.1.15"
        );
    }
}
