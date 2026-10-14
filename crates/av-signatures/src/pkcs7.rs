//! Just enough PKCS#7 to reach the certificates.
//!
//! # The structure, and how little of it is needed
//!
//! ```text
//! ContentInfo ::= SEQUENCE {
//!     contentType   OBJECT IDENTIFIER,   -- 1.2.840.113549.1.7.2, signedData
//!     content   [0] EXPLICIT SignedData }
//!
//! SignedData ::= SEQUENCE {
//!     version            INTEGER,
//!     digestAlgorithms   SET OF AlgorithmIdentifier,
//!     encapContentInfo   EncapsulatedContentInfo,
//!     certificates   [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
//!     crls           [1] IMPLICIT SET OF RevocationInfoChoices OPTIONAL,
//!     signerInfos        SET OF SignerInfo }
//! ```
//!
//! An Authenticode signature is a *degenerate* PKCS#7: `signerInfos` is empty
//! and everything of interest is in `certificates`. The signature itself is
//! carried in the `SpcIndirectDataContent` inside `encapContentInfo`, and
//! checking it is a separate problem this module does not take on.
//!
//! # The one place the shape matters
//!
//! `certificates` is `[0] IMPLICIT`, which means the `SET` tag is *replaced* by
//! `0xA0` rather than wrapped in it. A reader expecting the explicit form would
//! look for a `SET` inside the `[0]` and find a `Certificate` instead — and
//! would then report a signed file as having no certificates, which is a missed
//! detection rather than an error.
//!
//! # Choice elements
//!
//! `CertificateChoices` is a `CHOICE`, so the `[0]` holds a mixture of element
//! types. Only the plain `Certificate` — a `SEQUENCE` — is read. The others
//! (attribute certificates, `OtherCertificateFormat`) are skipped by tag rather
//! than refused: a chain that carries one is still a chain, and abandoning the
//! whole signature over an element no rule reads would lose the leaf
//! certificate that every rule in this corpus is about.

use crate::der::SEQUENCE;
use crate::error::SignatureError;
use crate::oid;
use crate::x509::Certificate;

/// The `[0]` context tag holding the certificate set.
const CERTIFICATES_TAG: u8 = crate::der::context(0);

/// Read the certificates out of a PKCS#7 `SignedData` blob.
///
/// Returns them in the order the blob lists them. A chain is usually leaf
/// first, but the format does not require it and nothing here reorders: a rule
/// that reads `pe.signatures[i].subject` and `pe.signatures[i].issuer` is
/// asking about one certificate, and reordering would change which index that
/// is.
///
/// An empty result is not an error. A `SignedData` with no `certificates`
/// field is well-formed, and the caller — which is counting signatures for
/// `pe.number_of_signatures` — needs a zero rather than a failure.
pub fn certificates(blob: &[u8]) -> Result<Vec<Certificate<'_>>, SignatureError> {
    let content_info = crate::der::parse_one(blob)?;
    let mut fields = content_info.sequence()?;
    let content_type = fields.expect(crate::der::OBJECT_IDENTIFIER)?;
    if !oid::is_signed_data(content_type.content) {
        return Err(SignatureError::NotPkcs7 {
            reason: "the content type is not signedData",
        });
    }
    let content = fields
        .expect(CERTIFICATES_TAG)
        .map_err(|_| SignatureError::NotPkcs7 {
            reason: "signedData has no content",
        })?;
    let signed_data = crate::der::parse_one(content.content)?;
    let mut signed_fields = signed_data.sequence()?;

    // version, digestAlgorithms, encapContentInfo, then certificates.
    signed_fields.skip_n(3)?;
    let mut probe = signed_fields;
    let has_certificates = match probe.next() {
        Some(Ok(tlv)) => tlv.is(CERTIFICATES_TAG),
        _ => false,
    };
    if !has_certificates {
        return Ok(Vec::new());
    }
    let set = signed_fields.expect(CERTIFICATES_TAG)?;

    let mut out = Vec::new();
    let mut choices = set.elements();
    while let Some(choice) = choices.next_with_span() {
        let (tlv, span) = choice?;
        // Only a plain `Certificate` is a `SEQUENCE`. The other choices use
        // context tags, and `OtherCertificateFormat` is a `SEQUENCE` that is
        // not a certificate — but it can only appear as `[3]`, so a bare
        // `SEQUENCE` here is always the certificate alternative.
        if !tlv.is(SEQUENCE) {
            continue;
        }
        match Certificate::parse(span) {
            Ok(certificate) => out.push(certificate),
            // A certificate that cannot be parsed is skipped rather than
            // failing the blob. The chain in a real signature often carries a
            // root this parser has no reason to understand, and losing the leaf
            // over it would lose the whole signature.
            Err(_) => continue,
        }
    }
    Ok(out)
}

/// Whether a buffer is a PKCS#7 `SignedData` at all.
///
/// Used by the scanner to decide whether a `WIN_CERTIFICATE` is worth handing
/// to [`certificates`]. Reads only the outer two elements, so a blob that is
/// not PKCS#7 is rejected before any of its inner lengths are trusted.
pub fn is_signed_data(blob: &[u8]) -> bool {
    let Ok(content_info) = crate::der::parse_one(blob) else {
        return false;
    };
    let Ok(mut fields) = content_info.sequence() else {
        return false;
    };
    matches!(fields.next(), Some(Ok(tlv)) if tlv.is(crate::der::OBJECT_IDENTIFIER) && oid::is_signed_data(tlv.content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    /// A `SignedData` wrapping `certificates`, with the two forms the caller can
    /// choose between.
    fn signed_data(chain: &[Vec<u8>], implicit: bool) -> Vec<u8> {
        let inner = chain.concat();
        let certs = if implicit {
            // `[0] IMPLICIT`: the SET tag is replaced, not wrapped.
            tlv(0xa0, &inner)
        } else {
            tlv(0xa0, &set(chain))
        };
        let data = seq(&[
            integer(1),
            set(&[algorithm()]),
            seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &[])]),
            certs,
            set(&[]),
        ]);
        seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)])
    }

    fn leaf() -> Vec<u8> {
        certificate(&[0x01], "Leaf", "110616000000Z", "140615000000Z")
    }

    fn intermediate() -> Vec<u8> {
        certificate(&[0x02], "Intermediate", "110616000000Z", "140615000000Z")
    }

    #[test]
    fn the_certificates_come_back_in_the_order_the_blob_lists_them() {
        let blob = signed_data(&[leaf(), intermediate()], true);
        let certs = certificates(&blob).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
        assert_eq!(certs[1].subject().unwrap(), "/CN=Intermediate");
    }

    #[test]
    fn the_implicit_form_is_the_one_read() {
        // `[0] IMPLICIT` replaces the SET tag. A reader that expected the
        // explicit form would find a Certificate where it looked for a SET and
        // report a signed file as having no certificates.
        let blob = signed_data(&[leaf()], true);
        assert_eq!(certificates(&blob).unwrap().len(), 1);
    }

    #[test]
    fn the_explicit_form_would_not_yield_the_same_certificates() {
        // The differential for the test above: with the SET left in place, the
        // single element inside `[0]` is a SET, not a SEQUENCE, so nothing is
        // read. This is what makes the implicit form a decision rather than an
        // accident.
        let blob = signed_data(&[leaf()], false);
        assert!(certificates(&blob).unwrap().is_empty());
    }

    #[test]
    fn a_blob_with_no_certificates_yields_an_empty_list_rather_than_an_error() {
        // Well-formed, and the caller counting signatures needs a zero.
        let data = seq(&[
            integer(1),
            set(&[algorithm()]),
            seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &[])]),
            set(&[]),
        ]);
        let blob = seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)]);
        assert_eq!(certificates(&blob).unwrap().len(), 0);
    }

    #[test]
    fn a_blob_whose_content_type_is_not_signed_data_is_refused() {
        let data = seq(&[integer(1), set(&[]), set(&[])]);
        let blob = seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &data)]);
        assert!(matches!(
            certificates(&blob),
            Err(SignatureError::NotPkcs7 { .. })
        ));
        assert!(!is_signed_data(&blob));
    }

    #[test]
    fn a_choice_that_is_not_a_certificate_is_skipped_not_refused() {
        // An attribute certificate is `[1]` and is not a `SEQUENCE`. Refusing
        // the whole blob over one would lose the leaf certificate that every
        // rule in the corpus is about.
        let mut body = tlv(0xa1, &[0x02, 0x01, 0x01]);
        body.extend_from_slice(&leaf());
        let choices = tlv(0xa0, &body);
        let data = seq(&[
            integer(1),
            set(&[algorithm()]),
            seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &[])]),
            choices,
            set(&[]),
        ]);
        let blob = seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)]);
        let certs = certificates(&blob).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Leaf");
    }

    #[test]
    fn an_element_that_is_a_sequence_but_not_a_certificate_is_skipped() {
        // A truncated fixture would prove nothing here: cutting bytes off the
        // end of one certificate leaves the next certificate's header to fill
        // the gap, so the outer length still matches the buffer and the element
        // still parses. A `SEQUENCE` whose first element is an `INTEGER` rather
        // than a `TBSCertificate` is malformed whatever follows it.
        let broken = seq(&[integer(1)]);
        let blob = signed_data(&[broken, intermediate()], true);
        let certs = certificates(&blob).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject().unwrap(), "/CN=Intermediate");
    }

    #[test]
    fn a_blob_that_is_not_der_at_all_is_refused() {
        assert!(certificates(&[0xFF, 0xFF, 0xFF]).is_err());
        assert!(certificates(&[]).is_err());
        assert!(!is_signed_data(&[0xFF, 0xFF, 0xFF]));
    }

    #[test]
    fn trailing_bytes_after_the_content_info_are_refused() {
        let mut blob = signed_data(&[leaf()], true);
        blob.push(0x00);
        assert!(certificates(&blob).is_err());
    }

    #[test]
    fn a_signed_data_that_is_truncated_inside_its_certificates_is_refused() {
        let blob = signed_data(&[leaf(), intermediate()], true);
        let cut = blob.len() - 4;
        assert!(certificates(&blob[..cut]).is_err());
    }
}
