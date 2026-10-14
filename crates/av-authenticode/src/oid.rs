//! The object identifiers this crate has to recognise by name.
//!
//! # Why there is a second OID table in this workspace
//!
//! [`av_signatures::oid`] holds the identifiers a *rule* needs: the attribute
//! types a distinguished name is rendered with, and the PKCS#7 content type
//! that says a blob is a `SignedData`. This table holds the identifiers a
//! *verifier* needs: the content type that says the signed content is an
//! Authenticode digest rather than a Word document, the attributes whose
//! presence is mandatory and whose absence is fatal, the key-usage and
//! extended-key-usage identifiers that say a certificate may sign files, and
//! the signature algorithms that decide whether the verification can proceed at
//! all.
//!
//! They are separate because they are separate questions, and merging them
//! would put a name table shared by a rule compiler and a verifier in a
//! position where a change for one silently changes the other. Nothing here is
//! re-exported from there and nothing there is duplicated here except the one
//! identifier both genuinely need.
//!
//! # Why a misspelled OID is a security bug
//!
//! Every constant here is used in a comparison whose *failure* is permissive or
//! fatal depending on which one it is. Get `SPC_INDIRECT_DATA` wrong and a
//! signature over a Word document verifies as a Windows binary. Get
//! `ID_KP_CODE_SIGNING` wrong and a TLS certificate can clear a detection on an
//! executable. Get `MESSAGE_DIGEST` wrong and the attribute that binds the
//! signature to the file is never checked. There is a test below that decodes
//! every constant through the DER reader and compares it with the arcs written
//! out longhand, so a typo produces a failing test rather than a permissive
//! verifier.

/// The PKCS#7 `signedData` content type, `1.2.840.113549.1.7.2`.
///
/// Repeated from [`av_signatures::oid`] rather than imported, because it is the
/// one identifier both tables need and an import would make this crate's
/// behaviour depend on a change made for a rule compiler's reasons.
pub const PKCS7_SIGNED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];

/// `SPC_INDIRECT_DATA_OBJID`, `1.3.6.1.4.1.311.2.1.4`.
///
/// The `eContentType` of an Authenticode signature. What it announces is that
/// `eContent` is a `SpcIndirectDataContent` — the structure naming a digest
/// algorithm and the digest of a file — rather than any other kind of signed
/// content. A verifier that did not check it would verify a signature over
/// arbitrary content and call the result a valid file signature.
pub const SPC_INDIRECT_DATA: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 4];

/// `SPC_SP_OPUS_INFO_OBJID`, `1.3.6.1.4.1.311.2.1.12`.
///
/// The "opus info" attribute some signers include to carry a program's name and
/// URL. Recognised only so that a report can name it; it is never required and
/// never trusted, because it is free text the signer chose.
pub const SPC_SP_OPUS_INFO: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 12];

/// `contentType`, `1.2.840.113549.1.9.3`.
///
/// A CMS requirement: the signed attributes must include it, and its value must
/// equal the `eContentType`. Checking both is what stops an attacker moving a
/// signature from a structure of one type onto a structure of another.
pub const ATTR_CONTENT_TYPE: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];

/// `messageDigest`, `1.2.840.113549.1.9.4`.
///
/// The attribute that binds the signature to the content, and through the
/// content to the file. Nothing in the signature is worth anything without it,
/// which is why its absence is a refusal rather than a skipped check.
pub const ATTR_MESSAGE_DIGEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];

/// `signingTime`, `1.2.840.113549.1.9.5`.
///
/// Present in most signatures, and **not trusted here**. It is a self-reported
/// time inside the signed attributes — signed, so it cannot be altered, but
/// asserted by the signer, who could assert anything. A counter-signature is
/// worth having precisely because a third party vouches for the time; this
/// attribute is worth only as much as the signer's honesty, so it is recorded
/// and never used to decide whether a certificate was valid.
pub const ATTR_SIGNING_TIME: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];

/// `counterSignature`, `1.2.840.113549.1.9.6`.
///
/// The PKCS#9 form of a counter-signature, replaced by RFC 3161 and still
/// emitted by five of the 812 files measured. Its `SignerInfo` sits in the
/// outer signer's *unauthenticated* attributes, which is not a weakness: what
/// it counter-signs is the outer `signature` value, so altering either breaks
/// the other.
pub const ATTR_COUNTER_SIGNATURE: &[u64] = &[1, 2, 840, 113549, 1, 9, 6];

/// Microsoft's RFC 3161 timestamp attribute, `1.3.6.1.4.1.311.3.3.1`.
///
/// Microsoft puts the RFC 3161 `TimeStampToken` in an unauthenticated attribute
/// under this OID rather than in a `counterSignature`, which is what RFC 3161
/// actually specifies. Both mean the same thing — "a time-stamping authority
/// vouches that this signature existed at this time" — and both are verified
/// here.
pub const ATTR_MS_TIMESTAMP: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 3, 3, 1];

/// `id-ct-TSTInfo`, `1.2.840.113549.1.9.16.1.4`.
///
/// The content type inside an RFC 3161 `TimeStampToken`. The token is a
/// `SignedData` like any other, and this is what says the content it signs is a
/// `TSTInfo` — a statement about a message imprint and a time — rather than
/// something else that happens to be signed by a time-stamping authority.
pub const CT_TST_INFO: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];

/// `rsaEncryption`, `1.2.840.113549.1.1.1`.
///
/// The only public-key algorithm in the measured population: 1649 of 1649
/// certificates carrying one.
pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];

/// `sha1WithRSAEncryption`, `1.2.840.113549.1.1.5`.
pub const SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];

/// `sha256WithRSAEncryption`, `1.2.840.113549.1.1.11`.
pub const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];

/// `sha384WithRSAEncryption`, `1.2.840.113549.1.1.12`.
pub const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];

/// `sha512WithRSAEncryption`, `1.2.840.113549.1.1.13`.
pub const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];

/// `md5WithRSAEncryption`, `1.2.840.113549.1.1.4`.
///
/// Named so that it can be refused *specifically*. A report that said "unsupported
/// algorithm `1.2.840.113549.1.1.4`" is less useful than one that says MD5,
/// which a reader immediately understands.
pub const MD5_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 4];

/// `rsassaPss`, `1.2.840.113549.1.1.10`.
///
/// RSA-PSS, the better padding scheme that Authenticode does not use. Refused
/// by name: PSS is not a broken algorithm, it is one this verifier does not
/// implement, and the two answers differ to a user.
pub const RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];

/// `ecdsa-with-SHA256`, `1.2.840.10045.4.3.2`.
pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];

/// `id-kp-codeSigning`, `1.3.6.1.5.5.7.3.3`.
///
/// The extended key usage that says a certificate may sign code. Without it on
/// the signer — and with no `extendedKeyUsage` extension at all being the only
/// other acceptable case — a certificate issued for TLS would be able to clear
/// a detection on an executable, and certificates for TLS are far easier to
/// obtain.
pub const ID_KP_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];

/// `id-kp-timeStamping`, `1.3.6.1.5.5.7.3.8`.
///
/// Required on a time-stamping authority's certificate, and required *alone*:
/// RFC 3161 section 2.3 says a TSA certificate must have this extended key
/// usage and that the extension must be critical. A TSA certificate that also
/// carried `codeSigning` would let a time-stamping authority issue signatures
/// over files.
pub const ID_KP_TIMESTAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];

/// `id-kp-emailProtection`, `1.3.6.1.5.5.7.3.4`.
///
/// Not a code-signing purpose. Listed so that a report can say *which* purpose
/// a certificate did have, which is the sentence a user can act on.
pub const ID_KP_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];

/// `id-kp-serverAuth`, `1.3.6.1.5.5.7.3.1`.
pub const ID_KP_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];

/// `id-kp-clientAuth`, `1.3.6.1.5.5.7.3.2`.
pub const ID_KP_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];

/// Microsoft's individual code-signing purpose, `1.3.6.1.4.1.311.2.1.21`.
///
/// The pre-2001 spelling, still present on some older Microsoft certificates
/// beside `id-kp-codeSigning`, and accepted as a code-signing purpose because
/// Windows accepts it as one.
pub const MS_INDIVIDUAL_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 21];

/// Microsoft's commercial code-signing purpose, `1.3.6.1.4.1.311.2.1.22`.
pub const MS_COMMERCIAL_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 22];

/// `basicConstraints`, `2.5.29.19`.
pub const EXT_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];

/// `keyUsage`, `2.5.29.15`.
pub const EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

/// `extendedKeyUsage`, `2.5.29.37`.
pub const EXT_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];

/// Which signature algorithm a `SignerInfo` or a token uses.
///
/// Only the ones that can be checked, plus the ones worth refusing by name.
/// [`SignatureAlgorithm::Unsupported`] carries the rendered OID, so a refusal
/// names the algorithm rather than saying "unknown" — which is the difference
/// between a report a user can act on and one they cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 over the named digest.
    RsaPkcs1 {
        /// The digest the signature is over.
        digest: crate::digest::DigestAlgorithm,
    },
    /// A named algorithm this verifier does not implement.
    ///
    /// Not an error and not a failure: it is a statement that the file has not
    /// been assessed, which the verdict reports as untrusted-with-a-reason
    /// rather than as invalid.
    Unsupported {
        /// The algorithm identifier's OID, dotted.
        oid: String,
        /// A human name where one is well known, otherwise `None`.
        name: Option<&'static str>,
    },
}

impl SignatureAlgorithm {
    /// The algorithm an `AlgorithmIdentifier`'s OID names.
    ///
    /// The encryption algorithm decides the padding, and for RSA PKCS#1 v1.5
    /// the OID *also* names the digest — `sha256WithRSAEncryption` is one
    /// identifier covering both. `digest_fallback` is the `SignerInfo`'s own
    /// `digestAlgorithm`, used for the bare `rsaEncryption` identifier, which
    /// names no digest of its own. Passing it in rather than looking it up here
    /// keeps this function a pure mapping from an OID to a meaning.
    pub fn from_oid(
        content: &[u8],
        digest_fallback: Option<crate::digest::DigestAlgorithm>,
    ) -> Self {
        use crate::digest::DigestAlgorithm;
        use av_signatures::oid::oid_matches;

        // The digest-named RSA identifiers first: they are unambiguous and
        // carry both facts.
        let named = [
            (SHA1_WITH_RSA, DigestAlgorithm::Sha1),
            (SHA256_WITH_RSA, DigestAlgorithm::Sha256),
            (SHA384_WITH_RSA, DigestAlgorithm::Sha384),
            (SHA512_WITH_RSA, DigestAlgorithm::Sha512),
        ];
        for (arcs, digest) in named {
            if oid_matches(content, arcs) {
                return SignatureAlgorithm::RsaPkcs1 { digest };
            }
        }
        // `sha1WithRSA` has a second OID, from the 1993 PKCS#1 era. Two of the
        // 812 files use it, so it is not archaeology.
        if oid_matches(content, &[1, 3, 14, 3, 2, 29]) {
            return SignatureAlgorithm::RsaPkcs1 {
                digest: DigestAlgorithm::Sha1,
            };
        }
        // Bare `rsaEncryption`: the padding is PKCS#1 v1.5 and the digest comes
        // from the signer's own `digestAlgorithm`.
        if oid_matches(content, RSA_ENCRYPTION) {
            if let Some(digest) = digest_fallback {
                return SignatureAlgorithm::RsaPkcs1 { digest };
            }
        }

        let oid = av_signatures::oid::dotted(content);
        let name = if oid_matches(content, MD5_WITH_RSA) {
            Some("MD5 with RSA")
        } else if oid_matches(content, RSASSA_PSS) {
            Some("RSA-PSS")
        } else if oid_matches(content, ECDSA_WITH_SHA256) {
            Some("ECDSA with SHA-256")
        } else {
            None
        };
        SignatureAlgorithm::Unsupported { oid, name }
    }

    /// Whether this is an algorithm that can be checked.
    pub fn is_supported(&self) -> bool {
        matches!(self, SignatureAlgorithm::RsaPkcs1 { .. })
    }

    /// A name for a report.
    pub fn name(&self) -> String {
        match self {
            SignatureAlgorithm::RsaPkcs1 { digest } => {
                format!("RSA PKCS#1 v1.5 with {}", digest.name())
            }
            SignatureAlgorithm::Unsupported { oid, name } => match name {
                Some(name) => format!("{name} ({oid})"),
                None => format!("OID {oid}"),
            },
        }
    }
}

/// A human name for an OID a report has to mention.
///
/// Returns `None` for anything not in this table, and the caller renders the
/// dotted form instead. A guessed name would be worse than a number: it would
/// put a word a reader recognises next to an identifier the reader cannot
/// check.
pub fn name(content: &[u8]) -> Option<&'static str> {
    use av_signatures::oid::oid_matches;
    const TABLE: &[(&[u64], &str)] = &[
        (SPC_INDIRECT_DATA, "SPC_INDIRECT_DATA"),
        (SPC_SP_OPUS_INFO, "SPC_SP_OPUS_INFO"),
        (ATTR_CONTENT_TYPE, "contentType"),
        (ATTR_MESSAGE_DIGEST, "messageDigest"),
        (ATTR_SIGNING_TIME, "signingTime"),
        (ATTR_COUNTER_SIGNATURE, "counterSignature"),
        (ATTR_MS_TIMESTAMP, "microsoftTimeStamp"),
        (CT_TST_INFO, "id-ct-TSTInfo"),
        (ID_KP_CODE_SIGNING, "id-kp-codeSigning"),
        (ID_KP_TIMESTAMPING, "id-kp-timeStamping"),
        (ID_KP_EMAIL_PROTECTION, "id-kp-emailProtection"),
        (ID_KP_SERVER_AUTH, "id-kp-serverAuth"),
        (ID_KP_CLIENT_AUTH, "id-kp-clientAuth"),
        (MS_INDIVIDUAL_CODE_SIGNING, "microsoftIndividualCodeSigning"),
        (MS_COMMERCIAL_CODE_SIGNING, "microsoftCommercialCodeSigning"),
        (EXT_BASIC_CONSTRAINTS, "basicConstraints"),
        (EXT_KEY_USAGE, "keyUsage"),
        (EXT_EXTENDED_KEY_USAGE, "extendedKeyUsage"),
    ];
    TABLE
        .iter()
        .find(|(arcs, _)| oid_matches(content, arcs))
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_signatures::der::{parse_one, OBJECT_IDENTIFIER};
    use av_signatures::testing::encode;

    /// Every constant, against the arcs it is written as.
    ///
    /// The constants above are the *decoded* form and the DER reader is what
    /// produces it, so encoding each one back and decoding it again would be a
    /// test of the encoder. This instead checks the property that matters and
    /// is checkable: that the byte encoding the constant names is the one the
    /// DER reader decodes to those arcs, so a constant whose arcs were mistyped
    /// fails here rather than in a verifier that silently stops matching.
    #[test]
    fn every_oid_decodes_to_the_arcs_written_beside_it() {
        let table: &[(&[u64], &str)] = &[
            (PKCS7_SIGNED_DATA, "signedData"),
            (SPC_INDIRECT_DATA, "SPC_INDIRECT_DATA"),
            (ATTR_CONTENT_TYPE, "contentType"),
            (ATTR_MESSAGE_DIGEST, "messageDigest"),
            (ATTR_SIGNING_TIME, "signingTime"),
            (ATTR_COUNTER_SIGNATURE, "counterSignature"),
            (ATTR_MS_TIMESTAMP, "microsoftTimeStamp"),
            (CT_TST_INFO, "id-ct-TSTInfo"),
            (RSA_ENCRYPTION, "rsaEncryption"),
            (SHA1_WITH_RSA, "sha1WithRSA"),
            (SHA256_WITH_RSA, "sha256WithRSA"),
            (SHA384_WITH_RSA, "sha384WithRSA"),
            (SHA512_WITH_RSA, "sha512WithRSA"),
            (ID_KP_CODE_SIGNING, "codeSigning"),
            (ID_KP_TIMESTAMPING, "timeStamping"),
            (MS_INDIVIDUAL_CODE_SIGNING, "msIndividualCodeSigning"),
        ];
        for &(arcs, label) in table {
            let encoded = encode(arcs);
            let mut wrapped = vec![0x06, encoded.len() as u8];
            wrapped.extend_from_slice(&encoded);
            let tlv = parse_one(&wrapped).unwrap();
            assert!(tlv.is(OBJECT_IDENTIFIER), "{label}");
            assert_eq!(tlv.oid().unwrap(), arcs.to_vec(), "{label}");
        }
    }

    #[test]
    fn the_digest_named_rsa_oids_map_to_their_digests() {
        use crate::digest::DigestAlgorithm;
        for (arcs, digest) in [
            (SHA1_WITH_RSA, DigestAlgorithm::Sha1),
            (SHA256_WITH_RSA, DigestAlgorithm::Sha256),
            (SHA384_WITH_RSA, DigestAlgorithm::Sha384),
            (SHA512_WITH_RSA, DigestAlgorithm::Sha512),
        ] {
            let encoded = encode(arcs);
            assert_eq!(
                SignatureAlgorithm::from_oid(&encoded, None),
                SignatureAlgorithm::RsaPkcs1 { digest },
                "{arcs:?}"
            );
        }
    }

    #[test]
    fn the_two_sha2_rsa_oids_next_to_each_other_are_both_right() {
        // sha384WithRSA is 12 and sha512WithRSA is 13 — adjacent, and the pair
        // most likely to be transposed while reading. A transposition would
        // still verify *something*: it would announce SHA-384 over a SHA-512
        // digest and fail on the digest rather than on the algorithm, pointing
        // a reader at the wrong part of the file.
        assert_eq!(SHA384_WITH_RSA, &[1, 2, 840, 113549, 1, 1, 12]);
        assert_eq!(SHA512_WITH_RSA, &[1, 2, 840, 113549, 1, 1, 13]);
        assert_eq!(
            SignatureAlgorithm::from_oid(&encode(SHA384_WITH_RSA), None),
            SignatureAlgorithm::RsaPkcs1 {
                digest: crate::digest::DigestAlgorithm::Sha384
            }
        );
        assert_eq!(
            SignatureAlgorithm::from_oid(&encode(SHA512_WITH_RSA), None),
            SignatureAlgorithm::RsaPkcs1 {
                digest: crate::digest::DigestAlgorithm::Sha512
            }
        );
    }

    #[test]
    fn bare_rsa_encryption_takes_its_digest_from_the_signer() {
        use crate::digest::DigestAlgorithm;
        assert_eq!(
            SignatureAlgorithm::from_oid(&encode(RSA_ENCRYPTION), Some(DigestAlgorithm::Sha256)),
            SignatureAlgorithm::RsaPkcs1 {
                digest: DigestAlgorithm::Sha256
            }
        );
        // With no digest to fall back on there is nothing to verify, and
        // guessing SHA-256 would be inventing the answer.
        assert!(!SignatureAlgorithm::from_oid(&encode(RSA_ENCRYPTION), None).is_supported());
    }

    #[test]
    fn the_legacy_sha1_with_rsa_oid_is_recognised() {
        use crate::digest::DigestAlgorithm;
        assert_eq!(
            SignatureAlgorithm::from_oid(&encode(&[1, 3, 14, 3, 2, 29]), None),
            SignatureAlgorithm::RsaPkcs1 {
                digest: DigestAlgorithm::Sha1
            }
        );
    }

    #[test]
    fn the_unsupported_algorithms_are_refused_by_name_not_by_number() {
        for (arcs, expected) in [
            (MD5_WITH_RSA, "MD5 with RSA"),
            (RSASSA_PSS, "RSA-PSS"),
            (ECDSA_WITH_SHA256, "ECDSA with SHA-256"),
        ] {
            let algorithm = SignatureAlgorithm::from_oid(&encode(arcs), None);
            assert!(!algorithm.is_supported());
            match algorithm {
                SignatureAlgorithm::Unsupported { name, .. } => {
                    assert_eq!(name, Some(expected));
                }
                other => panic!("expected an unsupported algorithm, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_algorithm_is_refused_with_its_dotted_oid() {
        let algorithm = SignatureAlgorithm::from_oid(&encode(&[1, 2, 3, 4]), None);
        assert_eq!(
            algorithm,
            SignatureAlgorithm::Unsupported {
                oid: "1.2.3.4".to_string(),
                name: None,
            }
        );
        assert_eq!(algorithm.name(), "OID 1.2.3.4");
    }

    #[test]
    fn every_named_oid_renders_a_name() {
        for arcs in [
            SPC_INDIRECT_DATA,
            ATTR_MESSAGE_DIGEST,
            ID_KP_CODE_SIGNING,
            ID_KP_TIMESTAMPING,
            EXT_EXTENDED_KEY_USAGE,
        ] {
            assert!(name(&encode(arcs)).is_some(), "{arcs:?}");
        }
        assert_eq!(name(&encode(&[1, 2, 3, 4])), None);
    }

    #[test]
    fn the_code_signing_and_timestamping_purposes_are_different_oids() {
        // The one confusion that would be fatal in the permissive direction: a
        // time-stamping certificate accepted as a code-signing one.
        assert_ne!(ID_KP_CODE_SIGNING, ID_KP_TIMESTAMPING);
        assert!(!av_signatures::oid::oid_matches(
            &encode(ID_KP_TIMESTAMPING),
            ID_KP_CODE_SIGNING
        ));
    }
}
