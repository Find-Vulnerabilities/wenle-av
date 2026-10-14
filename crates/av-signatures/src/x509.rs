//! The certificate fields rules read.
//!
//! # What is exposed, and why so little
//!
//! The corpus reads exactly six members off a signature —
//! `serial`, `subject`, `issuer`, `not_before`, `not_after`, `thumbprint` — and
//! the counts are lopsided: 1,886 rules read the serial, 1,580 the subject, 930
//! `not_after`, 25 the issuer, 3 the thumbprint, 1 `not_before`. That
//! measurement is why the certificate is parsed into six fields and a version,
//! rather than into an object model. A general X.509 library would expose key
//! usage, extended key usage, name constraints, CRL distribution points and
//! thirty more, none of which any rule here reads, all of which would be
//! attacker-reachable code to fuzz.
//!
//! `.verified` is deliberately **not** exposed. See the crate documentation:
//! verifying an Authenticode signature means implementing the whole chain
//! validation path, and a `.verified` that answered `false` for every file
//! would make `not ... .verified` mean "every file" — a detection rule that
//! fires on the entire disk.
//!
//! # The serial string
//!
//! `serial` is the raw content bytes of the `INTEGER`, lowercase, `:`-separated,
//! **with the DER sign byte preserved**. The corpus fixes this: of 1,885
//! `serial ==` literals, 393 begin `00:`, and the lengths cluster hard at 47
//! characters (1,363 rules — 16 bytes) and 50 (382 rules — 17 bytes). A string
//! built by trimming the sign byte would be one byte short of every one of
//! those 393 literals and would match none of them.
//!
//! # The thumbprint string
//!
//! Also colon-separated, from the same reasoning, and with the corpus to back
//! it: two of the three `thumbprint` literals are 59 characters — twenty bytes
//! with nineteen colons — and only one is a bare 40-character hex string. The
//! format the majority of rules use is the one implemented; the odd one out is
//! a rule that cannot match a real thumbprint either way.
//!
//! SHA-1 is chosen because that is what a certificate thumbprint *is*: the
//! Windows certificate store, `certutil -hashfile`, and `Get-FileHash
//! -Algorithm SHA1` all define it that way. SHA-1 being unsuitable for
//! signatures does not make it unsuitable for this, which is an identifier
//! rather than a security boundary.

use crate::der::{Tlv, INTEGER, SEQUENCE};
use crate::error::SignatureError;
use crate::{name, time};

/// The `[0]` context tag that carries the version when it is not v1.
const VERSION_TAG: u8 = crate::der::context(0);

/// A parsed X.509 certificate.
///
/// Holds borrowed elements rather than rendered strings: a signed file carries
/// a chain of two to four certificates, and rendering all of their distinguished
/// names costs several allocations each for values that most rules never look
/// at. Parsing is a walk over seven elements, and rendering happens when a
/// member is read.
#[derive(Debug, Clone, Copy)]
pub struct Certificate<'a> {
    der: &'a [u8],
    serial: Tlv<'a>,
    issuer: Tlv<'a>,
    validity: Tlv<'a>,
    subject: Tlv<'a>,
    version: u32,
}

impl<'a> Certificate<'a> {
    /// Parse one certificate from its complete encoding.
    ///
    /// Takes the whole element including its tag and length, because that is
    /// what the thumbprint hashes.
    pub fn parse(der: &'a [u8]) -> Result<Self, SignatureError> {
        let certificate = crate::der::parse_one(der)?;
        let mut fields = certificate.sequence()?;
        let tbs = fields.expect(SEQUENCE)?;
        let mut tbs_fields = tbs.sequence()?;

        // The version is `[0] EXPLICIT` and `DEFAULT v1`, so it is absent
        // exactly when the certificate is v1. Reading it as unconditional would
        // shift every field below it by one and produce a certificate whose
        // "serial" is really its signature algorithm.
        // `Der` is `Copy`, so the peek costs a cursor rather than a re-parse.
        let mut probe = tbs_fields;
        let has_version = matches!(probe.next(), Some(Ok(tlv)) if tlv.is(VERSION_TAG));
        let version = if has_version {
            let wrapper = tbs_fields.expect(VERSION_TAG)?;
            // An explicit wrapper holds exactly one element. Parsing it as a
            // whole document, rather than as a cursor, is what makes `[0]` with
            // no content an error instead of a version of zero with the field
            // cursor left one element short.
            crate::der::parse_one(wrapper.content)?.unsigned()? as u32
        } else {
            0
        };

        let serial = tbs_fields.expect(INTEGER)?;
        // The signature algorithm, which nothing here reads. Skipped by
        // position rather than matched, because a certificate whose algorithm
        // field is malformed should fail here where the offsets are still
        // known, not three fields later.
        tbs_fields.skip_n(1)?;
        let issuer = tbs_fields.expect(SEQUENCE)?;
        let validity = tbs_fields.expect(SEQUENCE)?;
        let subject = tbs_fields.expect(SEQUENCE)?;

        Ok(Self {
            der,
            serial,
            issuer,
            validity,
            subject,
            version,
        })
    }

    /// The complete encoding, which the thumbprint hashes.
    pub fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The X.509 version: 0 for v1, 1 for v2, 2 for v3.
    ///
    /// The number as encoded, not as named. A rule comparing `== 3` would be
    /// comparing against the name, and there is no rule here doing either.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The serial number as the colon-separated lowercase hex rules compare.
    ///
    /// Empty only if the `INTEGER` has no content bytes, which DER forbids and
    /// [`Certificate::parse`] would have refused.
    pub fn serial(&self) -> String {
        match self.serial.integer_bytes() {
            Ok(bytes) => colon_hex(bytes),
            Err(_) => String::new(),
        }
    }

    /// The issuer's distinguished name.
    pub fn issuer(&self) -> Result<String, SignatureError> {
        name::render(&self.issuer)
    }

    /// The subject's distinguished name.
    pub fn subject(&self) -> Result<String, SignatureError> {
        name::render(&self.subject)
    }

    /// When the certificate becomes valid.
    pub fn not_before(&self) -> Result<time::UnixTime, SignatureError> {
        let mut fields = self.validity.sequence()?;
        let time = fields.next().ok_or(SignatureError::UnexpectedEnd {
            wanted: crate::der::UTC_TIME,
        })??;
        time::parse_time(time.tag, &time.time_text()?)
    }

    /// When the certificate expires.
    ///
    /// Read as the second element of the `Validity` sequence rather than by
    /// searching for a `GeneralizedTime`, because a certificate that carries
    /// two `UTCTime`s is ordinary and one where the fields are swapped is
    /// exactly the case that must not silently answer "valid".
    pub fn not_after(&self) -> Result<time::UnixTime, SignatureError> {
        let mut fields = self.validity.sequence()?;
        fields.skip_n(1)?;
        let time = fields.next().ok_or(SignatureError::UnexpectedEnd {
            wanted: crate::der::UTC_TIME,
        })??;
        time::parse_time(time.tag, &time.time_text()?)
    }

    /// The SHA-1 thumbprint, colon-separated lowercase hex.
    pub fn thumbprint(&self) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(self.der);
        colon_hex(&hasher.finalize())
    }
}

/// The index of the certificate that signed the blob a chain came out of.
///
/// Not `0`. [`crate::pkcs7::certificates`] returns the certificates in the order
/// the blob lists them, and the format does not require the leaf to come first
/// — measured over the 836 embedded-signed files in an installed `System32`, 55
/// of the chains list an intermediate ahead of the leaf. Reading `[0]` as the
/// signer therefore reports an intermediate authority's name as the publisher
/// and checks the intermediate's validity window instead of the signer's, which
/// is a wrong name shown to a user and a wrong date compared.
///
/// A leaf is the certificate that nothing else in the chain is issued by. A
/// self-signed certificate names itself as its own issuer, so it always issues
/// something and a root can never be mistaken for a leaf, whether or not it is
/// listed first. Where a blob is signed twice, the flattened list holds two
/// leaves and the first is the first signature's — three of the measured chains
/// are of that shape.
///
/// Falls back to `0` if every certificate issues something, which no chain built
/// out of distinct certificates is: that would need a cycle. `0` on an empty
/// chain, which the caller has to handle anyway because there is no signer.
///
/// Lives here rather than at either call site because two now need it — the
/// embedded-signature path and the catalog index — and the measurement that
/// makes it necessary is a fact about certificate chains, not about scanning.
pub fn signer_index(chain: &[Certificate<'_>]) -> usize {
    let subjects: Vec<String> = chain
        .iter()
        .map(|certificate| certificate.subject().unwrap_or_default())
        .collect();
    let issues_nothing = |index: usize| {
        !chain
            .iter()
            .any(|other| other.issuer().ok().as_deref() == Some(subjects[index].as_str()))
    };
    (0..chain.len())
        .find(|index| issues_nothing(*index))
        .unwrap_or(0)
}

/// Lowercase hex with `:` between bytes.
fn colon_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn the_six_members_a_rule_reads_are_all_reachable() {
        let der = certificate(
            &[0x00, 0x11, 0x5c],
            "Atera Networks Ltd",
            "110616000000Z",
            "140615000000Z",
        );
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.serial(), "00:11:5c");
        assert_eq!(cert.subject().unwrap(), "/CN=Atera Networks Ltd");
        assert_eq!(cert.issuer().unwrap(), "/O=Test CA");
        assert_eq!(cert.not_before().unwrap().seconds(), 1_308_182_400);
        assert_eq!(cert.thumbprint().len(), 59);
    }

    #[test]
    fn the_serial_keeps_the_der_sign_byte() {
        // 393 literals in the corpus begin `00:`. Trimming the sign byte would
        // make the string one byte short of every one of them.
        let der = certificate(&[0x00, 0xFF, 0x01], "A", "110616000000Z", "140615000000Z");
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.serial(), "00:ff:01");
    }

    #[test]
    fn a_serial_without_a_sign_byte_renders_without_one() {
        let der = certificate(&[0x7F, 0x01], "A", "110616000000Z", "140615000000Z");
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.serial(), "7f:01");
    }

    #[test]
    fn a_v3_certificate_reads_its_version_and_keeps_the_fields_aligned() {
        // The version is `DEFAULT v1`, so it is present only when it is not v1.
        // A parser that read it unconditionally would take the version integer
        // for the serial and the serial for the algorithm.
        let der = certificate(&[0x2A], "A", "110616000000Z", "140615000000Z");
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.version(), 2, "the fixture declares v3");
        assert_eq!(cert.serial(), "2a");
        assert_eq!(cert.subject().unwrap(), "/CN=A");
    }

    #[test]
    fn a_v1_certificate_with_no_version_field_is_read_as_v1() {
        // Built without the `[0]` wrapper: the fields below it do not shift.
        let validity = seq(&[utc("110616000000Z"), utc("140615000000Z")]);
        let subject = name(&[(&[2, 5, 4, 3], printable("A"))]);
        let tbs = seq(&[
            integer_bytes(&[0x2A]),
            algorithm(),
            name(&[(&[2, 5, 4, 10], printable("Test CA"))]),
            validity,
            subject,
            seq(&[algorithm(), tlv(0x03, &[0x00, 0x01])]),
        ]);
        let der = seq(&[tbs, algorithm(), tlv(0x03, &[0x00, 0xAA])]);
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.version(), 0);
        assert_eq!(cert.serial(), "2a");
        assert_eq!(cert.subject().unwrap(), "/CN=A");
    }

    #[test]
    fn the_thumbprint_is_the_sha1_of_the_whole_encoding() {
        // Not of the TBS, and not of the content alone: dropping the tag and
        // length gives a different, equally plausible-looking 20 bytes.
        use sha1::{Digest, Sha1};
        let der = certificate(&[0x01], "A", "110616000000Z", "140615000000Z");
        let cert = Certificate::parse(&der).unwrap();
        let mut hasher = Sha1::new();
        hasher.update(&der);
        assert_eq!(cert.thumbprint(), colon_hex(&hasher.finalize()));
        assert_ne!(
            cert.thumbprint(),
            colon_hex(&Sha1::digest(&der[2..])),
            "the header must be hashed too"
        );
    }

    #[test]
    fn not_after_is_the_second_time_and_not_the_first() {
        let der = certificate(&[0x01], "A", "110616000000Z", "140615000000Z");
        let cert = Certificate::parse(&der).unwrap();
        assert_ne!(cert.not_before().unwrap(), cert.not_after().unwrap());
        assert!(cert.not_after().unwrap() > cert.not_before().unwrap());
        // 140615000000Z is 2014-06-15.
        assert_eq!(cert.not_after().unwrap().civil(), (2014, 6, 15));
    }

    #[test]
    fn a_generalized_time_is_read_where_a_utc_time_would_be() {
        let validity = seq(&[
            generalized("20200101000000Z"),
            generalized("20400101000000Z"),
        ]);
        let tbs = seq(&[
            explicit(0, &integer(2)),
            integer_bytes(&[0x01]),
            algorithm(),
            name(&[(&[2, 5, 4, 10], printable("Test CA"))]),
            validity,
            name(&[(&[2, 5, 4, 3], printable("A"))]),
            seq(&[algorithm(), tlv(0x03, &[0x00, 0x01])]),
        ]);
        let der = seq(&[tbs, algorithm(), tlv(0x03, &[0x00, 0xAA])]);
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.not_before().unwrap().civil(), (2020, 1, 1));
        assert_eq!(cert.not_after().unwrap().civil(), (2040, 1, 1));
    }

    #[test]
    fn a_truncated_certificate_is_refused_rather_than_half_read() {
        let der = certificate(&[0x01], "A", "110616000000Z", "140615000000Z");
        assert!(Certificate::parse(&der[..der.len() - 3]).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_certificate_are_refused() {
        // Otherwise a file could carry a second, different structure after the
        // one that was parsed.
        let mut der = certificate(&[0x01], "A", "110616000000Z", "140615000000Z");
        der.push(0x00);
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn a_certificate_missing_the_validity_field_is_refused() {
        let tbs = seq(&[
            explicit(0, &integer(2)),
            integer_bytes(&[0x01]),
            algorithm(),
            name(&[(&[2, 5, 4, 10], printable("Test CA"))]),
            // no validity
            name(&[(&[2, 5, 4, 3], printable("A"))]),
        ]);
        let der = seq(&[tbs, algorithm(), tlv(0x03, &[0x00, 0xAA])]);
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn a_certificate_whose_version_field_is_present_but_empty_is_refused() {
        // `[0]` with no content would otherwise read as version 0 and leave the
        // field cursor pointing one element short of the serial.
        let tbs = seq(&[
            tlv(0xa0, &[]),
            integer_bytes(&[0x01]),
            algorithm(),
            name(&[(&[2, 5, 4, 10], printable("Test CA"))]),
            seq(&[utc("110616000000Z"), utc("140615000000Z")]),
            name(&[(&[2, 5, 4, 3], printable("A"))]),
        ]);
        let der = seq(&[tbs, algorithm(), tlv(0x03, &[0x00, 0xAA])]);
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn the_colon_hex_form_is_the_one_the_corpus_literals_use() {
        // 16 bytes is 47 characters and 17 is 50, which is where 1,745 of the
        // 1,885 serial literals fall.
        assert_eq!(colon_hex(&[0u8; 16]).len(), 47);
        assert_eq!(colon_hex(&[0u8; 17]).len(), 50);
        assert_eq!(colon_hex(&[0x0d, 0xbf]), "0d:bf");
        assert_eq!(colon_hex(&[]), "");
    }
}
