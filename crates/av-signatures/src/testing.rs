//! Certificates and signatures built in memory.
//!
//! Not fixtures on disk, for the same reason [`av_pe::testing`] is not: a
//! checked-in binary is opaque, and a test that says
//! `assert_eq!(cert.serial(), "00:11:5c")` against one cannot show where the
//! `00:11:5c` came from. These are built field by field, so a test can point at
//! the byte it depends on and can vary exactly one field and say what it is
//! varying.
//!
//! Public rather than `#[cfg(test)]` because the crate above — the rule engine
//! — needs a signed file to point rules at, and a second copy of these builders
//! would be a second thing to keep in step with the format.
//!
//! # The one builder that is also a check
//!
//! [`encode`] writes an OID from its arcs, while [`crate::oid`] reads one by
//! comparing encoded bytes against a table of arcs. The two are separate
//! implementations in separate modules, so a mistake in either shows up as a
//! disagreement rather than as two copies of the same error.

use av_pe::testing::{append_security_directory, minimal_pe32};

/// The revision and type a `WIN_CERTIFICATE` record carries.
const REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
const TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
/// The size of the `WIN_CERTIFICATE` header.
const HEADER_LEN: usize = 8;
/// Records start on this boundary.
const ALIGNMENT: usize = 8;

/// Wrap `content` in a tag and a length, in whichever DER form it needs.
///
/// The length encoding has to be right for the fixture to mean anything. A
/// builder that always wrote one length byte would produce a valid-looking
/// structure whose declared length wrapped at 256, and every test built on a
/// certificate chain — which is where the fixtures grow past that — would fail
/// somewhere far from the cause.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        assert!(len < 0x1_0000, "the fixtures stay under 64 KiB");
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

/// `SEQUENCE { ... }`.
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// `SET { ... }`.
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

/// `INTEGER` from raw content bytes, sign byte included.
///
/// The der sign byte is the caller's to supply, because the serial-number
/// string a rule compares against includes it — a builder that trimmed it would
/// make every fixture disagree with every rule.
pub fn integer_bytes(bytes: &[u8]) -> Vec<u8> {
    tlv(0x02, bytes)
}

/// `INTEGER` from a value, adding the sign byte when the top bit is set.
pub fn integer(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

/// `OBJECT IDENTIFIER` from arcs.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    tlv(0x06, &encode(arcs))
}

/// `PrintableString`.
pub fn printable(text: &str) -> Vec<u8> {
    tlv(0x13, text.as_bytes())
}

/// `UTF8String`.
pub fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

/// `UTCTime`.
pub fn utc(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

/// `GeneralizedTime`.
pub fn generalized(text: &str) -> Vec<u8> {
    tlv(0x18, text.as_bytes())
}

/// `[n] EXPLICIT`, constructed.
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// One relative distinguished name holding a single attribute.
pub fn rdn(arcs: &[u64], value: Vec<u8>) -> Vec<u8> {
    set(&[seq(&[oid(arcs), value])])
}

/// A distinguished name from a list of `(arcs, value)` pairs.
pub fn name(parts: &[(&[u64], Vec<u8>)]) -> Vec<u8> {
    seq(&parts
        .iter()
        .map(|(arcs, value)| rdn(arcs, value.clone()))
        .collect::<Vec<_>>())
}

/// An `AlgorithmIdentifier` of `sha256WithRSAEncryption`.
pub fn algorithm() -> Vec<u8> {
    seq(&[oid(&[1, 2, 840, 113549, 1, 1, 11]), tlv(0x05, &[])])
}

/// A certificate with the given serial, subject, issuer and validity.
///
/// v3, as essentially every code-signing certificate is: the `[0]` version
/// wrapper is present, which is the case that shifts every field below it.
pub fn certificate(serial: &[u8], subject_cn: &str, not_before: &str, not_after: &str) -> Vec<u8> {
    certificate_issued_by(serial, subject_cn, "Test CA", not_before, not_after)
}

/// [`certificate`] with the issuer named.
pub fn certificate_issued_by(
    serial: &[u8],
    subject_cn: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
) -> Vec<u8> {
    certificate_named(
        serial,
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        ORGANISATION_NAME,
    )
}

/// A link in a chain: a certificate whose issuer is named the same way its
/// subject is, so one link's `issuer` can equal the next link's `subject`.
///
/// [`certificate_issued_by`] names the issuer as an *organisation*, which no
/// subject in a fixture uses, so no two certificates it builds can be joined
/// into a chain. A chain is the shape the signer has to be picked out of — the
/// leaf is the certificate nothing else is issued by — so the walk needs links
/// that meet.
pub fn chain_link(
    serial: &[u8],
    subject_cn: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
) -> Vec<u8> {
    certificate_named(
        serial,
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        COMMON_NAME,
    )
}

/// `commonName`.
const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
/// `organizationName`.
const ORGANISATION_NAME: &[u64] = &[2, 5, 4, 10];

/// A certificate with the issuer named in the given attribute.
fn certificate_named(
    serial: &[u8],
    subject_cn: &str,
    issuer_cn: &str,
    not_before: &str,
    not_after: &str,
    issuer_attribute: &[u64],
) -> Vec<u8> {
    let tbs = seq(&[
        explicit(0, &integer(2)),
        integer_bytes(serial),
        algorithm(),
        name(&[(issuer_attribute, printable(issuer_cn))]),
        seq(&[utc(not_before), utc(not_after)]),
        name(&[(COMMON_NAME, printable(subject_cn))]),
        seq(&[algorithm(), tlv(0x03, &[0x00, 0x01, 0x02])]),
    ]);
    seq(&[tbs, algorithm(), tlv(0x03, &[0x00, 0xAA])])
}

/// A degenerate PKCS#7 `SignedData` carrying `chain`, as Authenticode uses.
///
/// `[0] IMPLICIT`, so the certificate set's `SET` tag is replaced by `0xA0`
/// rather than wrapped in it — which is what a real signature does, and the
/// form a reader has to expect.
pub fn signed_data(chain: &[Vec<u8>]) -> Vec<u8> {
    let data = seq(&[
        integer(1),
        set(&[algorithm()]),
        seq(&[oid(&[1, 2, 840, 113549, 1, 7, 1]), tlv(0xa0, &[])]),
        tlv(0xa0, &chain.concat()),
        set(&[]),
    ]);
    seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), tlv(0xa0, &data)])
}

/// One `WIN_CERTIFICATE` record wrapping a PKCS#7 blob, the way Windows writes
/// it: `dwLength` rounded up to the alignment, with the padding counted inside
/// it.
///
/// Measured over the 2363 records in an installed `System32`: every one
/// declared a length that was a multiple of eight, and 2084 of them were one to
/// seven bytes longer than the PKCS#7 blob inside. A fixture that declared the
/// unrounded length instead would leave the padding outside the record and
/// never exercise the trim that reading those 2084 needs.
pub fn win_certificate(blob: &[u8]) -> Vec<u8> {
    let length = (HEADER_LEN + blob.len()).div_ceil(ALIGNMENT) * ALIGNMENT;
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.extend_from_slice(&REVISION_2_0.to_le_bytes());
    out.extend_from_slice(&TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    out.extend_from_slice(blob);
    out.resize(length, 0);
    out
}

/// The `szOID_CTL` content type of a catalog, `1.3.6.1.4.1.311.10.1`.
const CTL_CONTENT_TYPE: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 10, 1];

/// `subjectUsage`, the OID a Windows catalog names itself with.
const SUBJECT_USAGE: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 12, 1, 1];

/// A `CertificateTrustList`, written the way a real catalog writes one.
///
/// The field order and the field *set* are the point of this builder. A fixture
/// that wrote a version `INTEGER` first — as nearly every other structure in
/// this format has — would let a reader that counted elements off the front
/// pass while failing on every catalog Windows actually produces, and the
/// absence of that integer is the single most important fact about the layout.
/// `subjectAlgorithm` is written as `SEQUENCE { OID, NULL }` for the same
/// reason: it is the element a positional reader would find where the subject
/// list is.
pub fn trust_list(subjects: Vec<u8>, extension: Option<Vec<u8>>) -> Vec<u8> {
    let mut fields = vec![
        seq(&[oid(SUBJECT_USAGE)]),
        // `listIdentifier`: sixteen bytes Windows derives from the catalog's
        // own contents, so no fixture can predict it and none needs to.
        tlv(0x04, &[0x6D; 16]),
        utc("240401132058Z"),
        seq(&[oid(&[1, 3, 6, 1, 4, 1, 311, 12, 1, 3]), tlv(0x05, &[])]),
        subjects,
    ];
    if let Some(extension) = extension {
        fields.push(explicit(0, &extension));
    }
    seq(&fields)
}

/// A subject list covering the given digests.
pub fn subject_list(digests: &[&[u8]]) -> Vec<u8> {
    seq(&digests
        .iter()
        .map(|digest| seq(&[tlv(0x04, digest)]))
        .collect::<Vec<_>>())
}

/// A `.cat` file covering `digests`.
///
/// A PKCS#7 `SignedData` like an Authenticode blob, and distinguishable from
/// one only by its content type and what sits behind it.
pub fn catalog(digests: &[&[u8]]) -> Vec<u8> {
    catalog_of(trust_list(subject_list(digests), None))
}

/// A catalog whose `ctlExtensions` carries a digest-shaped decoy.
///
/// The extension nests a sequence of sequences holding a digest-width `OCTET
/// STRING` — the shape a reader searching every descendant rather than the
/// direct children would seize on.
pub fn catalog_with_extension(digests: &[&[u8]], decoy: &[u8]) -> Vec<u8> {
    let extension = seq(&[seq(&[tlv(0x04, decoy)])]);
    catalog_of(trust_list(subject_list(digests), Some(extension)))
}

/// A trust list with a well-formed subject and one whose first element is an
/// OID rather than a digest.
pub fn catalog_with_malformed_subject(good: &[u8]) -> Vec<u8> {
    let subjects = seq(&[seq(&[oid(SUBJECT_USAGE)]), seq(&[tlv(0x04, good)])]);
    catalog_of(trust_list(subjects, None))
}

/// A trust list with no subject list at all.
///
/// Not an empty catalog: `trustedSubjects` is not optional, so its absence is a
/// structure this reader does not understand.
pub fn catalog_without_subjects() -> Vec<u8> {
    let ctl = seq(&[
        seq(&[oid(SUBJECT_USAGE)]),
        tlv(0x04, &[0x6D; 16]),
        utc("240401132058Z"),
        seq(&[oid(&[1, 3, 6, 1, 4, 1, 311, 12, 1, 3]), tlv(0x05, &[])]),
    ]);
    catalog_of(ctl)
}

/// A `.cat` covering `digests` and published by the given chain.
///
/// Every other catalog fixture in this module carries an empty certificate set,
/// which is enough for the digest half and useless for the other one. Real
/// catalogs are signed — measured over the store on this machine, all 7,300
/// carry a chain — so the publisher half of the index needs a fixture that has
/// one.
pub fn catalog_signed_by(digests: &[&[u8]], chain: &[Vec<u8>]) -> Vec<u8> {
    catalog_of_with_chain(trust_list(subject_list(digests), None), chain)
}

/// Wrap a trust list in the `SignedData` a `.cat` file is.
fn catalog_of(ctl: Vec<u8>) -> Vec<u8> {
    catalog_of_with_chain(ctl, &[])
}

/// [`catalog_of`] with certificates in the `SignedData`.
///
/// The certificate field is written as `[0]` IMPLICIT around the concatenated
/// certificates, which is the shape [`signed_data`] writes and the shape a real
/// catalog has — *not* a plain `SET`. It was a plain `SET` here until the
/// publisher half of the index needed to read it, and the difference was
/// invisible for as long as nothing did: an empty `SET` and an empty `[0]` are
/// both "no certificates", and every catalog fixture carries none.
fn catalog_of_with_chain(ctl: Vec<u8>, chain: &[Vec<u8>]) -> Vec<u8> {
    let data = seq(&[
        integer(1),
        set(&[algorithm()]),
        seq(&[oid(CTL_CONTENT_TYPE), explicit(0, &ctl)]),
        tlv(0xa0, &chain.concat()),
    ]);
    seq(&[oid(&[1, 2, 840, 113549, 1, 7, 2]), explicit(0, &data)])
}

/// A minimal PE32 image signed with one record carrying `chain`.
///
/// The whole path a scan walks, in one call: DOS header, optional header,
/// security directory, `WIN_CERTIFICATE`, PKCS#7, certificates.
pub fn signed_pe(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut pe = minimal_pe32();
    let table = win_certificate(&signed_data(chain));
    append_security_directory(&mut pe, &table);
    pe
}

/// A signed PE whose single signature carries one certificate.
pub fn pe_with_one_signature(serial: &[u8], subject_cn: &str) -> Vec<u8> {
    signed_pe(&[certificate(
        serial,
        subject_cn,
        "110616000000Z",
        "140615000000Z",
    )])
}

/// Encode a dotted arc list the way DER would.
///
/// The inverse of [`crate::oid::oid_matches`], written independently of it.
pub fn encode(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let rest = match arcs {
        [x, y, tail @ ..] => {
            out.extend_from_slice(&encode_arc(x * 40 + y));
            tail
        }
        _ => return out,
    };
    for &arc in rest {
        out.extend_from_slice(&encode_arc(arc));
    }
    out
}

/// One arc in base-128, continuation bit on all but the last byte.
fn encode_arc(mut value: u64) -> Vec<u8> {
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        bytes.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}
