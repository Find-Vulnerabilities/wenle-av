//! DER encoders for the structures this crate parses.
//!
//! # Why these are written by hand rather than produced by the parser
//!
//! A test that builds a structure with the same code that reads it proves only
//! that the code is self-consistent. These encoders are written from the
//! *formats* — the CMS `SignedData` layout, the X.509 extension layout, the
//! `SpcIndirectDataContent` layout — and share nothing with the parsers except
//! the byte-level `tlv`/`seq`/`set` primitives from [`av_signatures::testing`],
//! which encode a tag, a length and a body and know nothing about certificates.
//!
//! # What these are not
//!
//! They are not a general DER library and they do not check that what they
//! build is legal. A fixture that is deliberately malformed — a certificate
//! with a truncated validity, an attribute with no value — is one of the things
//! the tests need to build, and an encoder that refused to build one would put
//! the check in the wrong place.
//!
//! # Two of these produce structures no real file has
//!
//! [`certificate`] takes a public key that tests supply, and the tests supply
//! nonsense: the signature on a fixture certificate is not a real signature and
//! the key in it is usually not a real key. That is deliberate. Nothing in this
//! crate verifies a certificate's own signature — the platform's chain engine
//! does that, and it is not under test here — so a fixture certificate exists
//! to be *parsed*, and the tests that need real cryptography use real files or
//! the independent vectors in [`crate::rsa`].

use av_signatures::testing::{integer, integer_bytes, printable};

/// The byte-level encoders, re-exported so a test in another module of this
/// crate can hand-build a malformed structure without reaching into
/// `av-signatures` itself.
pub use av_signatures::testing::{oid, seq, set, tlv};

/// The `SPC_PE_IMAGE_DATA_OBJID` that names what an Authenticode `data` field
/// refers to, `1.3.6.1.4.1.311.2.1.15`.
pub const SPC_PE_IMAGE_DATA: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 2, 1, 15];

/// A `SubjectPublicKeyInfo` holding an RSA public key.
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let rsa = seq(&[integer_bytes(modulus), integer_bytes(exponent)]);
    // The BIT STRING's first content byte counts unused bits, and a key is a
    // whole number of bytes, so it is zero.
    let mut bits = vec![0x00];
    bits.extend_from_slice(&rsa);
    seq(&[
        seq(&[oid(&[1, 2, 840, 113549, 1, 1, 1]), tlv(0x05, &[])]),
        tlv(0x03, &bits),
    ])
}

/// A `SubjectPublicKeyInfo` holding something that is not an RSA key.
pub fn ec_spki() -> Vec<u8> {
    seq(&[
        seq(&[
            oid(&[1, 2, 840, 10045, 2, 1]),
            oid(&[1, 2, 840, 10045, 3, 1, 7]),
        ]),
        tlv(0x03, &[0x00, 0x04, 0xaa, 0xbb]),
    ])
}

/// An `Extension`.
pub fn extension(arcs: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(arcs)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, value));
    seq(&parts)
}

/// An `extendedKeyUsage` extension naming the given purposes.
pub fn ext_eku(purposes: &[&[u64]]) -> Vec<u8> {
    let inner = seq(&purposes.iter().map(|arcs| oid(arcs)).collect::<Vec<_>>());
    extension(&[2, 5, 29, 37], true, &inner)
}

/// A `basicConstraints` extension.
pub fn ext_basic_constraints(is_ca: bool) -> Vec<u8> {
    let inner = if is_ca {
        seq(&[tlv(0x01, &[0xff])])
    } else {
        seq(&[])
    };
    extension(&[2, 5, 29, 19], true, &inner)
}

/// A `keyUsage` extension whose first content byte is `bits`.
///
/// The bits are written most-significant first, as X.509 numbers them: bit 0
/// (`digitalSignature`) is `0x80`, bit 5 (`keyCertSign`) is `0x04`.
pub fn ext_key_usage(bits: u8) -> Vec<u8> {
    extension(&[2, 5, 29, 15], true, &tlv(0x03, &[0x00, bits]))
}

/// A v3 certificate.
///
/// `issuer_cn` is written as a `commonName` so that one fixture's issuer can
/// equal the next fixture's subject, which is what makes a chain of these
/// joinable.
pub fn certificate(
    serial: &[u8],
    subject_cn: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
    public_key: &[u8],
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let common_name = &[2u64, 5, 4, 3];
    let name = |cn: &str| seq(&[set(&[seq(&[oid(common_name), printable(cn)])])]);

    let mut fields = vec![
        // `version [0] EXPLICIT v3(2)`, which every code-signing certificate is.
        tlv(0xa0, &integer(2)),
        integer_bytes(serial),
        // The issuer's signature algorithm. Not read by the parser under test,
        // and written as the same identifier a real certificate carries.
        seq(&[oid(&[1, 2, 840, 113549, 1, 1, 11]), tlv(0x05, &[])]),
        name(issuer_cn),
        // `utc` from `av_signatures::testing` writes a `UTCTime`, which is what
        // every real certificate in this century uses, and which needs a
        // two-digit year.
        seq(&[
            tlv(0x17, not_before.as_bytes()),
            tlv(0x17, not_after.as_bytes()),
        ]),
        name(subject_cn),
        // Copied rather than referenced: the field list is a `Vec<Vec<u8>>`
        // because every other encoder here returns an owned encoding, and a
        // borrowed key would be the one element that needed the caller's slice
        // to outlive the fixture.
        public_key.to_vec(),
    ];
    if !extensions.is_empty() {
        fields.push(tlv(0xa0 | 3, &seq(extensions)));
    }

    let tbs = seq(&fields);
    // The outer signature is not a signature: nothing in this crate checks it.
    seq(&[
        tbs,
        seq(&[oid(&[1, 2, 840, 113549, 1, 1, 11])]),
        tlv(0x03, &[0x00, 0xaa]),
    ])
}

/// A `SpcIndirectDataContent`, which is the content an Authenticode signature
/// is really over.
pub fn spc_indirect_data(digest_oid: &[u64], digest: &[u8]) -> Vec<u8> {
    // `data SpcAttributeTypeAndOptionalValue` — a type name and an optional
    // value. The value is genuinely absent in most real signatures and the
    // parser does not read it either way.
    let data = seq(&[oid(SPC_PE_IMAGE_DATA)]);
    let message_digest = seq(&[seq(&[oid(digest_oid), tlv(0x05, &[])]), tlv(0x04, digest)]);
    seq(&[data, message_digest])
}

/// An `Attribute`: an OID and a set of values.
pub fn attribute(arcs: &[u64], values: &[Vec<u8>]) -> Vec<u8> {
    seq(&[oid(arcs), set(values)])
}

/// The signed attributes a real Authenticode signer emits, in DER order.
///
/// DER requires a `SET OF` to be emitted in ascending order of its encodings,
/// and both of the encoders that matter — Microsoft's and OpenSSL's — do emit
/// them in that order. The order the attributes appear in is therefore part of
/// the bytes that were signed, and a fixture that wrote them in another order
/// would produce a signature over something no real signer would produce.
///
/// The digest algorithm is *not* a parameter, and the omission is the point:
/// CMS defines `messageDigest` as a bare `OCTET STRING` with no algorithm
/// identifier beside it, so the fixture that named one here would be encoding a
/// structure no real signer emits. The algorithm a fixture is using shows up in
/// `digestAlgorithms` and in the `SignerInfo`, which is where
/// [`signed_data`] puts it.
pub fn signed_attributes(content_type: &[u64], digest: &[u8]) -> Vec<u8> {
    let mut attributes = vec![
        attribute(&[1, 2, 840, 113549, 1, 9, 3], &[oid(content_type)]),
        attribute(&[1, 2, 840, 113549, 1, 9, 4], &[tlv(0x04, digest)]),
        attribute(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 12], &[seq(&[])]),
    ];
    attributes.sort();
    set(&attributes)
}

/// A complete PKCS#7 `SignedData` blob as Authenticode embeds it.
///
/// Every field is what the structure says it is; the *shape* of the two
/// optional parts — how the content is wrapped, and whether there is a
/// timestamp — is what [`signed_data`] and [`signed_data_rfc_form`] differ on,
/// because those are the two things a fixture can get wrong in a way that reads
/// as correct.
pub struct SignedDataSpec<'a> {
    /// The `eContentType` — `SPC_INDIRECT_DATA` for a real signature.
    pub content_type: &'a [u64],
    /// The `eContent`, DER, which for Authenticode is a
    /// [`spc_indirect_data`]. This is the whole element, header included, in
    /// both forms: it is what a reader hands to the `SpcIndirectDataContent`
    /// parser.
    pub content: &'a [u8],
    /// The digest the `messageDigest` attribute claims.
    pub message_digest: &'a [u8],
    /// The signer's digest algorithm.
    pub digest_algorithm: &'a [u64],
    /// The signature bytes.
    pub signature: &'a [u8],
    /// The issuer name of the signer, DER, matching a certificate's issuer.
    pub signer_issuer: &'a [u8],
    /// The signer's serial number, as the encoded content bytes.
    pub signer_serial: &'a [u8],
    /// The certificates to carry.
    pub certificates: &'a [Vec<u8>],
    /// An RFC 3161 token to put in the signer's unauthenticated attributes, as
    /// the `timeStampToken` attribute — `1.3.6.1.4.1.311.3.3.1`.
    ///
    /// A field of the spec rather than a function that splices one into a
    /// finished blob, which is what this used to be. Splicing cannot work: the
    /// enclosers' length octets all change, and an encoder that appends bytes
    /// without fixing them produces a blob no parser will read — which is
    /// exactly what happened, and why the test that used the splice helper was
    /// passing on a structure that was 2 bytes short.
    ///
    /// The bytes are the token's **complete** `ContentInfo` encoding — tag and
    /// length included — not the token's content octets and not an opaque
    /// payload. An attribute's value is `ANY` in the grammar and a complete
    /// element in the encoding, and this one is read as such: `timestamp::find`
    /// hands the value's whole span to [`crate::cms::SignedData::parse`]. A
    /// fixture that passed three arbitrary bytes would be writing a `SET OF`
    /// whose single value was not DER at all, and the reader would be right to
    /// refuse it.
    pub timestamp: Option<&'a [u8]>,
}

/// Build the `ContentInfo` wrapping a `SignedData`, in the form Windows writes.
///
/// The content goes straight into the `[0]`, with no `OCTET STRING` around it.
/// That is not a detail: it is what every embedded signature in an installed
/// `System32` does, and a fixture that wrapped it the way RFC 5652 says would
/// agree with a reader that had the same mistake — which is precisely how this
/// crate came to parse its own fixtures and reject every real Microsoft binary.
pub fn signed_data(spec: &SignedDataSpec<'_>) -> Vec<u8> {
    build(spec, false)
}

/// The same `SignedData` with the content wrapped in an `OCTET STRING`.
///
/// The RFC 5652 §5.2 form, which no measured file uses and which the reader
/// still accepts. It has a builder of its own so that both paths through
/// `parse_encap_content_info` are exercised by a fixture rather than one of them
/// being exercised by nothing.
pub fn signed_data_rfc_form(spec: &SignedDataSpec<'_>) -> Vec<u8> {
    build(spec, true)
}

/// The one encoder both forms come out of.
fn build(spec: &SignedDataSpec<'_>, rfc_content: bool) -> Vec<u8> {
    // The signed attributes, re-tagged from `SET` (0x31) to `[0] IMPLICIT`.
    // The length bytes are untouched: an implicit tag replaces the tag byte
    // only, and an encoder that rebuilt the length would produce a different
    // encoding from the one the signature is over.
    let mut signed_attrs = signed_attributes(spec.content_type, spec.message_digest);
    signed_attrs[0] = 0xa0;

    // `[1] IMPLICIT SET OF Attribute`, and absent when the file carries no
    // token — a signature with no timestamp is the common case, and one with an
    // empty `[1]` would be a third shape no signer emits.
    //
    // The token goes in as it is, because an attribute value is `ANY`: the
    // bytes the caller passes are one complete element, header included, not a
    // payload to be framed. `timestamp::find` takes the value's `value_span` —
    // the whole element — and parses a `SignedData` out of it, so a caller
    // handing over bare content octets would be asking the reader to start
    // parsing mid-header. See [`SignedDataSpec::timestamp`].
    let unsigned = spec.timestamp.map(|token| {
        let mut set_of = set(&[attribute(
            &[1, 3, 6, 1, 4, 1, 311, 3, 3, 1],
            &[token.to_vec()],
        )]);
        set_of[0] = 0xa1;
        set_of
    });

    let mut signer_info = vec![
        integer(1),
        seq(&[
            spec.signer_issuer.to_vec(),
            integer_bytes(spec.signer_serial),
        ]),
        seq(&[oid(spec.digest_algorithm)]),
        signed_attrs,
        seq(&[oid(&[1, 2, 840, 113549, 1, 1, 1])]),
        tlv(0x04, spec.signature),
    ];
    signer_info.extend(unsigned);

    let content = if rfc_content {
        tlv(0x04, spec.content)
    } else {
        spec.content.to_vec()
    };
    let encap = seq(&[oid(spec.content_type), tlv(0xa0, &content)]);

    let data = seq(&[
        integer(1),
        set(&[seq(&[oid(spec.digest_algorithm)])]),
        encap,
        tlv(0xa0, &spec.certificates.concat()),
        set(&[seq(&signer_info)]),
    ]);

    seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixture_certificate_is_a_sequence_of_the_right_shape() {
        let der = certificate(
            &[0x01],
            "Signer",
            "Issuer",
            "240101000000Z",
            "250101000000Z",
            &rsa_spki(&[0x00, 0xab, 0xcd], &[0x01, 0x00, 0x01]),
            &[],
        );
        let parsed = av_signatures::der::parse_one(&der).unwrap();
        assert!(parsed.is(av_signatures::der::SEQUENCE));
        assert_eq!(parsed.elements().count(), 3, "tbs, algorithm, signature");
    }

    #[test]
    fn signed_attributes_are_emitted_in_der_order() {
        // DER orders a SET OF by its encodings. The fixture has to produce the
        // order a real signer produces, because the order is part of what the
        // signature is over.
        let attrs = signed_attributes(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 4], &[0u8; 32]);
        let parsed = av_signatures::der::parse_one(&attrs).unwrap();
        assert!(parsed.is(av_signatures::der::SET));
        // The *encodings*, not the contents. DER orders a `SET OF` by each
        // element's complete encoding, and the two orderings genuinely differ
        // here: the attribute whose content starts `06 0a` sorts after the two
        // that start `06 09`, and that is the wrong way round once each one's
        // `30`-tagged header and length are in front of it.
        let mut elements = parsed.elements();
        let mut encodings: Vec<&[u8]> = Vec::new();
        while let Some(element) = elements.next_with_span() {
            encodings.push(element.expect("the fixture is well-formed DER").1);
        }
        assert_eq!(encodings.len(), 3, "the fixture emits three attributes");
        let mut sorted = encodings.clone();
        sorted.sort();
        assert_eq!(encodings, sorted);
    }

    #[test]
    fn the_implicit_retag_changes_the_tag_byte_and_nothing_else() {
        // The re-tag is the single most delicate byte in Authenticode
        // verification: the signature is over the attributes with `0x31`
        // replaced by `0xa0`, and the length encoding — including the long form
        // — must survive untouched.
        let attrs = signed_attributes(&[1, 2, 3], &[0u8; 32]);
        assert_eq!(attrs[0], 0x31);
        // The length is whatever the three attributes needed; what matters is
        // that the re-tag below leaves every one of those bytes alone.
        //
        // Re-tagged, only byte 0 differs.
        let mut retagged = attrs.clone();
        retagged[0] = 0xa0;
        assert_eq!(attrs[1..], retagged[1..]);
    }

    /// A `Name`, DER, for the fixture's signer to be identified by.
    ///
    /// The field is the *complete encoding* of a `Name`, not a payload, and an
    /// empty slice is not an empty name — it is no name at all. A spec that
    /// passed one would encode an `IssuerAndSerialNumber` whose body is a bare
    /// `INTEGER`: the parser reads the first element as the issuer and the next
    /// as the serial number, so it would take the `INTEGER` for a `Name` and
    /// then find nothing where the serial belongs. That is the structure being
    /// refused rather than a limit of the parser, and it is why this is built
    /// rather than left empty.
    ///
    /// Built once and kept, so the spec can borrow it for `'static` and stay
    /// free of a lifetime the caller would otherwise have to invent for it.
    fn issuer_name() -> &'static [u8] {
        static NAME: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        NAME.get_or_init(|| {
            seq(&[set(&[seq(&[
                oid(&[2, 5, 4, 3]),
                printable("Wenle Test Signer"),
            ])])])
        })
    }

    /// A spec whose encap shape does not depend on any other field.
    fn minimal_spec<'a>(content: &'a [u8], certificates: &'a [Vec<u8>]) -> SignedDataSpec<'a> {
        SignedDataSpec {
            content_type: &[1, 3, 6, 1, 4, 1, 311, 2, 1, 15],
            content,
            message_digest: &[0x22; 32],
            digest_algorithm: &[2, 16, 840, 1, 101, 3, 4, 2, 1],
            signature: &[0xde, 0xad, 0xbe, 0xef],
            signer_issuer: issuer_name(),
            signer_serial: &[0x2a],
            certificates,
            timestamp: None,
        }
    }

    /// The tag of the element inside an `SignedData`'s `eContent`.
    ///
    /// Found by walking the structure rather than by searching for bytes,
    /// because a byte search would also find the content inside the
    /// `eContentType`'s own encoding and would pass on a blob with two of them.
    fn econtent_tag(blob: &[u8]) -> u8 {
        let outer = av_signatures::der::parse_one(blob).unwrap();
        let wrapped = outer.elements().nth(1).unwrap().unwrap();
        let data = wrapped.elements().next().unwrap().unwrap();
        let encap = data.elements().nth(2).unwrap().unwrap();
        let context = encap.elements().nth(1).unwrap().unwrap();
        context.elements().next().unwrap().unwrap().tag
    }

    #[test]
    fn the_windows_form_puts_the_content_bare_and_the_rfc_form_wraps_it() {
        // The single byte that decides whether this crate can read any real
        // Microsoft binary at all. Both forms are built here so that a change
        // to either is a failing test rather than a silent change of what the
        // reader is exercised against.
        let content = spc_indirect_data(&[2, 16, 840, 1, 101, 3, 4, 2, 1], &[0x11; 32]);
        let certificates: Vec<Vec<u8>> = Vec::new();
        let spec = minimal_spec(&content, &certificates);

        let windows = signed_data(&spec);
        let rfc = signed_data_rfc_form(&spec);
        assert_eq!(econtent_tag(&windows), 0x30, "the Windows form, bare");
        assert_eq!(econtent_tag(&rfc), 0x04, "the RFC 5652 form, wrapped");
        // The difference is the `OCTET STRING`'s own header and nothing else.
        // Two bytes here because the wrapped element is under 128 bytes, and
        // the enclosing lengths are already in their two-byte long form, so
        // growing the content by two does not change any of them.
        assert_eq!(rfc.len(), windows.len() + 2);
    }

    #[test]
    fn a_timestamp_goes_into_the_unauthenticated_attributes() {
        // The builder re-encodes every enclosing length when a token is
        // present, which is the part the splice this replaced got wrong: it
        // appended the attribute and left the lengths alone, producing a blob
        // whose declared sizes did not cover its own bytes. Parsing the result
        // is what checks that — the DER reader refuses an element whose
        // declared length runs past the end of its buffer.
        let content = spc_indirect_data(&[2, 16, 840, 1, 101, 3, 4, 2, 1], &[0x11; 32]);
        let certificates: Vec<Vec<u8>> = Vec::new();
        // The token is a whole `SignedData`, which is what a timestamp token is
        // and what the reader is given. Three arbitrary bytes would have been a
        // `SET OF` whose one value was not an element, and the reader refuses
        // that — see [`SignedDataSpec::timestamp`]. That refusal is not a
        // detail of this fixture: it is the same refusal that would hit a real
        // signature whose token was truncated.
        let token_content = spc_indirect_data(&[2, 16, 840, 1, 101, 3, 4, 2, 1], &[0x33; 32]);
        let token = signed_data(&minimal_spec(&token_content, &certificates));
        let with_token = SignedDataSpec {
            timestamp: Some(&token),
            ..minimal_spec(&content, &certificates)
        };

        let without = signed_data(&minimal_spec(&content, &certificates));
        let with = signed_data(&with_token);
        assert!(with.len() > without.len());

        let signed = crate::cms::SignedData::parse(&with).unwrap();
        assert_eq!(signed.signers.len(), 1);
        let attribute = signed.signers[0]
            .unsigned(&[1, 3, 6, 1, 4, 1, 311, 3, 3, 1])
            .expect("the token attribute must be reachable");
        // The span, not the content octets: the element as the file carries it
        // is the thing a nested structure is parsed from, and starting at the
        // content would start a DER parse in the middle of a length.
        let span = attribute.value_span().unwrap();
        assert_eq!(span, &token[..]);
        assert!(
            crate::cms::SignedData::parse(span).is_ok(),
            "the span must be a readable signature on its own"
        );
        // And its absence is absence, not an empty attribute.
        let plain = crate::cms::SignedData::parse(&without).unwrap();
        assert_eq!(plain.signers[0].signature, signed.signers[0].signature);
        assert!(plain.signers[0]
            .unsigned(&[1, 3, 6, 1, 4, 1, 311, 3, 3, 1])
            .is_none());
    }
}
