//! The certificate fields a verifier reads, parsed from the DER a file carries.
//!
//! # Why this is not [`av_signatures::x509::Certificate`]
//!
//! That type answers what a *rule* asks: who issued this, who is it for, when
//! does it expire, what is its thumbprint. This one answers what a *verifier*
//! asks, and the difference is not a matter of degree. A verifier needs the
//! public key — the modulus and exponent that the signature is checked against
//! — and needs the extensions that decide whether the certificate was allowed
//! to sign a file at all. Neither is in the other type, and neither is
//! obtainable from it without re-parsing.
//!
//! The DER *reader* is shared, which is the part that has to be safe against a
//! hostile file and the part that has been fuzzed. What is not shared is the
//! set of fields read and the meaning given to them, and that is exactly the
//! part a verifier should own.
//!
//! # What is deliberately not read
//!
//! Extensions this crate does not process, including critical ones. RFC 5280
//! says a certificate with a critical extension the reader does not understand
//! must be rejected, and that rule is *not* enforced here — because the chain
//! is built by the platform's chain engine (see [`crate::chain`]), which does
//! enforce it, and two implementations of that rule would eventually disagree
//! about which extensions are understood. Enforcing it here as well could only
//! refuse a certificate the platform accepts, and the platform is the authority
//! for exactly this.
//!
//! # The one check that is here rather than delegated
//!
//! Whether the certificate is permitted to sign code. That is not a property of
//! the platform's trust policy — it is a fact about what the certificate says
//! about itself, and a chain engine asked to build a path answers "does this
//! reach a root", not "was this certificate issued to sign programs". A TLS
//! server certificate chains to a root perfectly well, and letting one clear a
//! detection on an executable would be the most permissive bug this crate could
//! have.

use crate::error::{hex, AuthError};
use crate::oid;
use av_signatures::der::{
    Der, Tlv, BIT_STRING, BOOLEAN, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE,
};
use av_signatures::name;
use av_signatures::time::{parse_time, UnixTime};
use av_signatures::{oid::oid_matches, SignatureError};

/// The public key of a certificate.
///
/// An enum rather than an `Option<Rsa>`, because "this certificate uses a key
/// type this verifier cannot check" is a different answer from "this
/// certificate has no usable key", and the verdicts they lead to differ: the
/// first is an explicit refusal naming the algorithm, the second is a malformed
/// certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// An RSA key, as `RSAPublicKey` encodes it.
    Rsa {
        /// The modulus, big-endian, with any DER sign byte kept — the caller
        /// strips it, and a verifier that stripped it here would report a key
        /// size one byte larger than the modulus.
        modulus: &'a [u8],
        /// The public exponent, big-endian.
        exponent: &'a [u8],
    },
    /// A key type this crate does not implement.
    Unsupported {
        /// The algorithm identifier's OID, dotted.
        algorithm: String,
    },
}

/// The fields of a certificate that verification reads.
///
/// Parsed eagerly rather than lazily. A certificate is read once per
/// verification and every field here is either always needed or needed on a
/// path the caller cannot predict, so the cost of a lazy parse would be paid in
/// code rather than saved in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert<'a> {
    /// The complete DER encoding, which is what a thumbprint is taken over.
    der: &'a [u8],
    serial: &'a [u8],
    subject: String,
    issuer: String,
    /// The complete DER encoding of the issuer `Name`, which is what a
    /// `SignerInfo`'s issuer-and-serial identifier has to be compared against.
    ///
    /// The *rendered* issuer is not enough for that comparison. Two encodings
    /// of the same name — a `PrintableString` where a `UTF8String` would do,
    /// attributes in another order — render identically and are different
    /// bytes, and the identifier in the blob is a byte string. Comparing the
    /// encodings is what CMS asks for and what makes the match unambiguous.
    issuer_der: &'a [u8],
    not_before: UnixTime,
    not_after: UnixTime,
    key: PublicKey<'a>,
    /// Whether `basicConstraints` is present and says `cA = TRUE`.
    is_ca: bool,
    /// Whether `basicConstraints` is present at all.
    has_basic_constraints: bool,
    /// The `keyUsage` bits, without the unused-bits byte, or `None`.
    key_usage: Option<&'a [u8]>,
    /// The `extendedKeyUsage` sequence's content, or `None`.
    extended_key_usage: Option<&'a [u8]>,
}

impl<'a> Cert<'a> {
    /// Parse a certificate from its complete DER encoding.
    ///
    /// Every failure is a typed error rather than a panic: the bytes come from
    /// a file the scanner did not write, and a certificate is three levels of
    /// length-prefixed attacker-controlled structure.
    pub fn parse(der: &'a [u8]) -> Result<Self, AuthError> {
        let certificate = av_signatures::der::parse_one(der)?;
        if !certificate.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
                wanted: SEQUENCE,
                found: certificate.tag,
            }));
        }
        let mut outer = certificate.elements();
        let tbs = outer.next().and_then(Result::ok).ok_or_else(truncated)?;
        if !tbs.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::NotConstructed {
                tag: tbs.tag,
            }));
        }

        let mut fields = tbs.elements();
        // `version [0] EXPLICIT` is optional and defaults to v1. Its absence is
        // not a defect: a v1 certificate simply does not say.
        let first = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
        if !first.is_context(0) {
            // Not a version, so it is the serial number and the version was
            // omitted. Put it back by reading the fields from here.
            return Self::from_tbs(der, tbs, Some(first), fields);
        }
        Self::from_tbs(der, tbs, None, fields)
    }

    /// The body of the parse, once the optional version is out of the way.
    fn from_tbs(
        der: &'a [u8],
        tbs: Tlv<'a>,
        first_field: Option<Tlv<'a>>,
        mut fields: Der<'a>,
    ) -> Result<Self, AuthError> {
        let serial_number = match first_field {
            Some(tlv) => tlv,
            None => fields.next().and_then(Result::ok).ok_or_else(truncated)?,
        };
        let serial = serial_number
            .integer_bytes()
            .map_err(AuthError::Malformed)?;

        // `signature AlgorithmIdentifier` — the algorithm the *issuer* used.
        // Not read: the chain engine verifies the issuer's signature, so
        // parsing it here would be reading a field nobody acts on.
        fields.skip_n(1).map_err(AuthError::Malformed)?;

        let (issuer, issuer_der) = fields
            .next_with_span()
            .and_then(Result::ok)
            .ok_or_else(truncated)?;
        let issuer = name::render(&issuer).map_err(AuthError::Malformed)?;

        let validity = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
        let (not_before, not_after) = parse_validity(&validity)?;

        let subject = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
        let subject = name::render(&subject).map_err(AuthError::Malformed)?;

        let spki = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
        let key = parse_spki(&spki)?;

        // The remaining fields are `[1]` and `[2]` unique identifiers, both
        // optional, and `[3]` the extensions. Walking rather than indexing,
        // because the two optional identifiers are frequently absent and a
        // fixed offset would read the extensions as one of them.
        let mut is_ca = false;
        let mut has_basic_constraints = false;
        let mut key_usage = None;
        let mut extended_key_usage = None;
        for field in fields {
            let field = field.map_err(AuthError::Malformed)?;
            if !field.is_context(3) {
                continue;
            }
            // `[3] EXPLICIT Extensions` — the content is a SEQUENCE OF
            // Extension, and the explicit tag means it is wrapped.
            let inner = field.elements().next().and_then(Result::ok);
            let Some(inner) = inner else { continue };
            for extension in inner.elements() {
                let extension = extension.map_err(AuthError::Malformed)?;
                if !extension.is(SEQUENCE) {
                    continue;
                }
                let mut parts = extension.elements();
                let Some(Ok(id)) = parts.next() else { continue };
                if !id.is(OBJECT_IDENTIFIER) {
                    continue;
                }
                // `critical` is a BOOLEAN with a DEFAULT of FALSE, so it is
                // present only when true — reading the next element as the
                // value without skipping it would read the BOOLEAN as the
                // extension value.
                let mut value = parts.next();
                if let Some(Ok(next)) = value {
                    if next.is(BOOLEAN) {
                        value = parts.next();
                    }
                }
                let Some(Ok(value)) = value else { continue };
                if !value.is(OCTET_STRING) {
                    continue;
                }
                if oid_matches(id.content, oid::EXT_BASIC_CONSTRAINTS) {
                    has_basic_constraints = true;
                    is_ca = parse_is_ca(value.content).unwrap_or(true);
                } else if oid_matches(id.content, oid::EXT_KEY_USAGE) {
                    // Stored as the *bits*, with the `BIT STRING` header and the
                    // unused-bit count taken off, because that is the form
                    // [`Cert::permits_code_signing`] reads and the form the
                    // comment there describes. Storing the whole value instead
                    // puts the `0x03` tag byte where the first bit belongs, and
                    // then every certificate that names a `keyUsage` reads as one
                    // that forbids `digitalSignature` — which is a real Microsoft
                    // leaf reading as "not valid for code signing", a false
                    // refusal this crate measured on `MRT.exe`. An unreadable
                    // extension is stored as no bits rather than as no extension,
                    // so the refusal above is what an unparseable value gets.
                    key_usage = Some(bit_string_bits(value.content).unwrap_or(&[]));
                } else if oid_matches(id.content, oid::EXT_EXTENDED_KEY_USAGE) {
                    extended_key_usage = Some(value.content);
                }
            }
        }

        let _ = tbs;
        Ok(Cert {
            der,
            serial,
            subject,
            issuer,
            issuer_der,
            not_before,
            not_after,
            key,
            is_ca,
            has_basic_constraints,
            key_usage,
            extended_key_usage,
        })
    }

    /// The complete DER encoding.
    pub fn der(&self) -> &'a [u8] {
        self.der
    }

    /// The serial number, as the encoded bytes without the DER sign byte.
    pub fn serial(&self) -> &'a [u8] {
        match self.serial {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            other => other,
        }
    }

    /// The subject, rendered the way [`av_signatures`] renders it, so that a
    /// report from here matches a report from a rule.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The issuer, rendered the same way.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The complete DER encoding of the issuer `Name`.
    ///
    /// This is the form a `SignerInfo` identifier carries, and the form a match
    /// has to be made in.
    pub fn issuer_der(&self) -> &'a [u8] {
        self.issuer_der
    }

    /// The start of the validity period.
    pub fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// The end of the validity period.
    pub fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// The public key.
    pub fn public_key(&self) -> &PublicKey<'a> {
        &self.key
    }

    /// The SHA-1 thumbprint, as `av_signatures` computes it.
    ///
    /// SHA-1 because that is what a thumbprint is: an identifier, not a
    /// security boundary. Two certificates that collide in it are a curiosity;
    /// nobody is asked to trust a file because its thumbprint matches.
    pub fn thumbprint(&self) -> String {
        hex(&crate::digest::DigestAlgorithm::Sha1.digest(self.der))
    }

    /// Whether the certificate says it is an issuing certificate.
    ///
    /// Reads `basicConstraints` and nothing else, so it is a statement about
    /// what the certificate claims, not about whether it is one in the chain
    /// the platform built.
    pub fn is_issuing_ca(&self) -> bool {
        self.is_ca
    }

    /// Whether this certificate may sign code.
    ///
    /// Three checks, in the order that produces the most useful report:
    ///
    /// 1. **It must not be a CA.** `basicConstraints` with `cA = TRUE` on the
    ///    signer means an issuing certificate was used to sign a file
    ///    directly, which is not what an issuing certificate is for. An absent
    ///    extension is fine — most code-signing certificates have none.
    /// 2. **`keyUsage`, if present, must allow `digitalSignature`** and must not
    ///    allow `keyCertSign`.
    /// 3. **`extendedKeyUsage`, if present, must include a code-signing
    ///    purpose.** An absent extension means all purposes, which is what
    ///    RFC 5280 says and what Windows does, so it passes.
    pub fn permits_code_signing(&self) -> bool {
        if self.has_basic_constraints && self.is_ca {
            return false;
        }
        if let Some(bits) = self.key_usage {
            match bits.first() {
                // Bit 0 is `digitalSignature`; bit 5 is `keyCertSign`. The
                // `BIT STRING` header and the unused-bits count were taken off
                // by `Cert::parse`, so bit 0 of the first byte here is the most
                // significant bit of the value X.509 numbers bit 0.
                Some(first) => {
                    if first & 0x80 == 0 || first & 0x04 != 0 {
                        return false;
                    }
                }
                None => return false,
            }
        }
        match self.extended_key_usage {
            None => true,
            Some(sequence) => self.eku_includes_any(
                &[
                    oid::ID_KP_CODE_SIGNING,
                    oid::MS_INDIVIDUAL_CODE_SIGNING,
                    oid::MS_COMMERCIAL_CODE_SIGNING,
                ],
                sequence,
            ),
        }
    }

    /// Whether `extendedKeyUsage` is present and names exactly one purpose,
    /// the given one.
    ///
    /// Used for a time-stamping authority, where RFC 3161 requires the
    /// `id-kp-timeStamping` purpose *and requires the extension to be critical
    /// and to contain only that purpose* — a TSA certificate that also carried
    /// `codeSigning` would be a time-stamping authority that could sign files.
    pub fn is_purpose_exactly(&self, purpose: &[u64]) -> bool {
        let Some(sequence) = self.extended_key_usage else {
            return false;
        };
        let Ok(parsed) = av_signatures::der::parse_one(sequence) else {
            return false;
        };
        if !parsed.is(SEQUENCE) {
            return false;
        }
        let mut found = false;
        for element in parsed.elements() {
            let Ok(element) = element else { return false };
            if !element.is(OBJECT_IDENTIFIER) || !oid_matches(element.content, purpose) {
                return false;
            }
            found = true;
        }
        found
    }

    /// Whether any of `purposes` appears in an `extendedKeyUsage` sequence.
    fn eku_includes_any(&self, purposes: &[&[u64]], sequence: &[u8]) -> bool {
        let Ok(parsed) = av_signatures::der::parse_one(sequence) else {
            return false;
        };
        if !parsed.is(SEQUENCE) {
            return false;
        }
        for element in parsed.elements() {
            let Ok(element) = element else { return false };
            if !element.is(OBJECT_IDENTIFIER) {
                continue;
            }
            if purposes
                .iter()
                .any(|purpose| oid_matches(element.content, purpose))
            {
                return true;
            }
        }
        false
    }

    /// The purposes this certificate does name, rendered for a report.
    ///
    /// Empty when the extension is absent, which is the case that means "all
    /// purposes" rather than "none".
    pub fn extended_key_usage_names(&self) -> Vec<String> {
        let Some(sequence) = self.extended_key_usage else {
            return Vec::new();
        };
        let Ok(parsed) = av_signatures::der::parse_one(sequence) else {
            return Vec::new();
        };
        parsed
            .elements()
            .filter_map(Result::ok)
            .filter(|element| element.is(OBJECT_IDENTIFIER))
            .map(|element| {
                oid::name(element.content)
                    .map(str::to_string)
                    .unwrap_or_else(|| av_signatures::oid::dotted(element.content))
            })
            .collect()
    }
}

/// A truncated certificate, which is the error every `ok_or` above wants.
fn truncated() -> AuthError {
    AuthError::Malformed(SignatureError::UnexpectedEnd { wanted: SEQUENCE })
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
fn parse_validity(validity: &Tlv<'_>) -> Result<(UnixTime, UnixTime), AuthError> {
    if !validity.is(SEQUENCE) {
        return Err(AuthError::Malformed(SignatureError::NotConstructed {
            tag: validity.tag,
        }));
    }
    let mut fields = validity.elements();
    let not_before = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
    let not_after = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
    let not_before =
        parse_time(not_before.tag, &not_before.time_text()?).map_err(AuthError::Malformed)?;
    let not_after =
        parse_time(not_after.tag, &not_after.time_text()?).map_err(AuthError::Malformed)?;
    Ok((not_before, not_after))
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }`.
fn parse_spki<'a>(spki: &Tlv<'a>) -> Result<PublicKey<'a>, AuthError> {
    if !spki.is(SEQUENCE) {
        return Err(AuthError::Malformed(SignatureError::NotConstructed {
            tag: spki.tag,
        }));
    }
    let mut fields = spki.elements();
    let algorithm = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
    let bits = fields.next().and_then(Result::ok).ok_or_else(truncated)?;
    let key = bits.bit_string().map_err(AuthError::Malformed)?;

    let mut algorithm = algorithm.elements();
    let id = algorithm
        .next()
        .and_then(Result::ok)
        .ok_or_else(truncated)?;

    if !oid_matches(id.content, oid::RSA_ENCRYPTION) {
        return Ok(PublicKey::Unsupported {
            algorithm: av_signatures::oid::dotted(id.content),
        });
    }

    // `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`,
    // carried inside the BIT STRING.
    let rsa = av_signatures::der::parse_one(key).map_err(AuthError::Malformed)?;
    if !rsa.is(SEQUENCE) {
        return Err(AuthError::Malformed(SignatureError::NotConstructed {
            tag: rsa.tag,
        }));
    }
    let mut parts = rsa.elements();
    let modulus = parts.next().and_then(Result::ok).ok_or_else(truncated)?;
    let exponent = parts.next().and_then(Result::ok).ok_or_else(truncated)?;
    if !modulus.is(INTEGER) || !exponent.is(INTEGER) {
        return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
            wanted: INTEGER,
            found: modulus.tag,
        }));
    }
    Ok(PublicKey::Rsa {
        modulus: modulus.content,
        exponent: exponent.content,
    })
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }`.
///
/// Defaults to `true` on a parse failure, which is the fail-closed direction: a
/// certificate whose `basicConstraints` cannot be read is treated as an issuing
/// certificate, and an issuing certificate may not sign code.
fn parse_is_ca(content: &[u8]) -> Option<bool> {
    let parsed = av_signatures::der::parse_one(content).ok()?;
    if !parsed.is(SEQUENCE) {
        return None;
    }
    match parsed.elements().next() {
        None => Some(false),
        Some(Ok(first)) if first.is(BOOLEAN) => {
            Some(first.content.first().is_some_and(|&b| b != 0))
        }
        // The first element is the path length, so `cA` was defaulted to false.
        Some(Ok(_)) => Some(false),
        Some(Err(_)) => None,
    }
}

/// The bits of a DER `BIT STRING`, with the header and the unused-bit count
/// taken off.
///
/// `KeyUsage` is a `BIT STRING` and its extension value is the DER of one, so
/// the bits sit three headers deep: the extension's `OCTET STRING`, the
/// `BIT STRING`'s tag and length, and then the count of unused trailing bits.
/// What [`Cert::permits_code_signing`] reads is what is left after all three,
/// and getting this wrong is not a matter of a mislabelled report: reading the
/// tag byte as the bits makes bit 0 clear, and bit 0 clear means
/// `digitalSignature` is absent, so a certificate that permits code signing
/// refuses it.
///
/// `None` — never an empty success — when the value is not a `BIT STRING`, is
/// empty, or counts more than the seven unused bits X.690 allows: a caller that
/// cannot read the bits must not read them as permission.
fn bit_string_bits(value: &[u8]) -> Option<&[u8]> {
    let parsed = av_signatures::der::parse_one(value).ok()?;
    if !parsed.is(BIT_STRING) {
        return None;
    }
    let (unused, bits) = parsed.content.split_first()?;
    if *unused > 7 {
        return None;
    }
    Some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing as fixture;

    /// A modulus with a leading sign byte, which is what a real 2048-bit
    /// `RSAPublicKey` carries and what the key-size arithmetic has to strip.
    const MODULUS: &[u8] = &[
        0x00, 0xc0, 0xff, 0xee, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22,
        0x33,
    ];
    const EXPONENT: &[u8] = &[0x01, 0x00, 0x01];

    /// A certificate built by this crate's own encoder, which writes DER from
    /// the format rather than from the reader under test.
    ///
    /// `av_signatures::testing::certificate` cannot be used here: it writes
    /// `tlv(0x03, &[0x00, 0x01, 0x02])` as the `SubjectPublicKeyInfo`, which is
    /// a BIT STRING holding a `BOOLEAN`, not an `RSAPublicKey`, and it wraps a
    /// fifteen-character string in a `UTCTime`, which is three digits too many
    /// for one. Both are fine for a rule that only reads the subject and the
    /// dates, and both are refused here.
    fn simple() -> Vec<u8> {
        fixture::certificate(
            &[0x01, 0x02],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[],
        )
    }

    #[test]
    fn a_certificate_parses_into_the_fields_a_verifier_reads() {
        let der = simple();
        let cert = Cert::parse(&der).unwrap();
        assert_eq!(cert.der(), &der[..]);
        assert_eq!(cert.serial(), &[0x01, 0x02]);
        assert!(
            cert.subject().contains("Example Signer"),
            "{}",
            cert.subject()
        );
        assert!(
            cert.issuer().contains("Example Issuer"),
            "{}",
            cert.issuer()
        );
        assert_eq!(cert.thumbprint().len(), 40, "SHA-1 is 20 bytes of hex");
    }

    #[test]
    fn the_public_key_is_the_modulus_and_exponent_a_signature_is_checked_against() {
        // The DER is bound rather than inlined: `Cert<'a>` borrows the bytes it
        // was parsed from, so `Cert::parse(&simple())` would free the buffer at
        // the end of the statement and leave the certificate pointing at it.
        let der = simple();
        let cert = Cert::parse(&der).unwrap();
        match cert.public_key() {
            PublicKey::Rsa { modulus, exponent } => {
                assert_eq!(*modulus, MODULUS);
                assert_eq!(*exponent, EXPONENT);
            }
            other => panic!("expected an RSA key, got {other:?}"),
        }
    }

    #[test]
    fn a_key_type_this_crate_cannot_check_is_named_rather_than_refused() {
        // "This certificate uses a key type I cannot verify" is a different
        // answer from "this certificate is malformed", and it has to reach the
        // caller as one: the first names the algorithm in the report, the
        // second blames the file.
        let der = fixture::certificate(
            &[0x03],
            "Elliptic Signer",
            "Elliptic Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::ec_spki(),
            &[],
        );
        let cert = Cert::parse(&der).unwrap();
        match cert.public_key() {
            PublicKey::Unsupported { algorithm } => assert_eq!(algorithm, "1.2.840.10045.2.1"),
            other => panic!("expected an unsupported key, got {other:?}"),
        }
    }

    #[test]
    fn the_validity_period_is_read_as_unix_seconds() {
        let der = simple();
        let cert = Cert::parse(&der).unwrap();
        assert_eq!(cert.not_before().seconds(), 1_704_067_200);
        assert_eq!(cert.not_after().seconds(), 1_735_689_600);
    }

    #[test]
    fn the_issuer_encoding_is_kept_byte_for_byte_for_identifier_matching() {
        // The `SignerInfo` names its signer by the issuer's *encoding*, so the
        // encoding is what has to survive the parse. A rendered name would
        // match two different encodings of the same name, and the identifier
        // would then identify two certificates.
        let der = simple();
        let cert = Cert::parse(&der).unwrap();
        let issuer = cert.issuer_der();
        assert_eq!(issuer[0], SEQUENCE, "a Name is a SEQUENCE");
        // It is somewhere inside the certificate, not a copy of it.
        assert!(der.windows(issuer.len()).any(|w| w == issuer));
        assert!(issuer.len() < der.len());
    }

    #[test]
    fn a_non_certificate_is_refused_rather_than_misread() {
        // A bare INTEGER where a Certificate is expected: the same shape of
        // hostile input the DER reader is designed against, one level up.
        let mut der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert!(Cert::parse(&der).is_err());
        // A SEQUENCE that ends before its fields do.
        der = vec![0x30, 0x00];
        assert!(Cert::parse(&der).is_err());
        assert!(Cert::parse(&[]).is_err());
        assert!(Cert::parse(&[0x30]).is_err());
    }

    #[test]
    fn a_certificate_with_no_extensions_is_not_a_ca_and_may_sign_code() {
        // An absent `extendedKeyUsage` means all purposes, and an absent
        // `basicConstraints` means not a CA. Both defaults point the same way —
        // the certificate is *usable* — which is what Windows does and what
        // RFC 5280 says.
        let der = simple();
        let cert = Cert::parse(&der).unwrap();
        assert!(cert.permits_code_signing());
        assert!(cert.extended_key_usage_names().is_empty());
    }

    #[test]
    fn a_ca_certificate_may_not_sign_code() {
        // The most permissive bug this crate could have is letting an issuing
        // certificate clear a detection on a program.
        let der = fixture::certificate(
            &[0x10],
            "Example Issuing CA",
            "Example Root",
            "240101000000Z",
            "340101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_basic_constraints(true)],
        );
        let cert = Cert::parse(&der).unwrap();
        assert!(cert.is_issuing_ca());
        assert!(!cert.permits_code_signing());
    }

    #[test]
    fn a_key_usage_that_forbids_digital_signature_may_not_sign_code() {
        // Bit 5 is `keyCertSign` and bit 7 is `encipherOnly`; neither permits
        // signing a program.
        let der = fixture::certificate(
            &[0x11],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_key_usage(0x04)],
        );
        let cert = Cert::parse(&der).unwrap();
        assert!(!cert.permits_code_signing());
        // And a usage that does permit it, with `digitalSignature` set.
        let der = fixture::certificate(
            &[0x12],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_key_usage(0x80)],
        );
        assert!(Cert::parse(&der).unwrap().permits_code_signing());
    }

    #[test]
    fn a_key_usage_that_cannot_be_read_is_not_a_permission() {
        // The fail-closed direction of the extraction, and the one that keeps
        // this from being a permissive bug: a `keyUsage` that is present and
        // unreadable must refuse, the way an *absent* extension permits. The
        // value here is a well-formed element that is not a `BIT STRING`; the
        // same refusal covers an empty one and an unused-bit count above seven.
        let der = fixture::certificate(
            &[0x17],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::extension(&[2, 5, 29, 15], true, &[0x30, 0x00])],
        );
        assert!(!Cert::parse(&der).unwrap().permits_code_signing());
    }

    #[test]
    fn a_code_signing_purpose_is_accepted_and_a_tls_purpose_is_not() {
        let code = fixture::certificate(
            &[0x13],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_eku(&[oid::ID_KP_CODE_SIGNING])],
        );
        assert!(Cert::parse(&code).unwrap().permits_code_signing());

        let tls = fixture::certificate(
            &[0x14],
            "example.com",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_eku(&[oid::ID_KP_SERVER_AUTH])],
        );
        let cert = Cert::parse(&tls).unwrap();
        assert!(
            !cert.permits_code_signing(),
            "a TLS certificate chains to a root perfectly well and must never clear a detection"
        );
        // The spelling is the OID table's, which names extended key usages in
        // their PKIX form — `id-kp-serverAuth`, `id-kp-codeSigning` — the same
        // way it names `sha256WithRSA` and `id-ct-TSTInfo`. What this assertion
        // is here for is that the purpose is *reported* and reported as the one
        // the certificate carries; the exact spelling belongs to `oid`.
        assert_eq!(cert.extended_key_usage_names(), vec!["id-kp-serverAuth"]);
    }

    #[test]
    fn a_timestamping_authority_must_carry_that_purpose_and_no_other() {
        let tsa = fixture::certificate(
            &[0x15],
            "Example TSA",
            "Example Issuer",
            "240101000000Z",
            "340101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_eku(&[oid::ID_KP_TIMESTAMPING])],
        );
        let cert = Cert::parse(&tsa).unwrap();
        assert!(cert.is_purpose_exactly(oid::ID_KP_TIMESTAMPING));

        // A certificate that is both a time-stamping authority *and* a code
        // signer is not a time-stamping authority: RFC 3161 requires the
        // extension to contain exactly the one purpose.
        let both = fixture::certificate(
            &[0x16],
            "Example TSA",
            "Example Issuer",
            "240101000000Z",
            "340101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[fixture::ext_eku(&[
                oid::ID_KP_TIMESTAMPING,
                oid::ID_KP_CODE_SIGNING,
            ])],
        );
        let cert = Cert::parse(&both).unwrap();
        assert!(!cert.is_purpose_exactly(oid::ID_KP_TIMESTAMPING));

        // And one with no `extendedKeyUsage` at all is not a TSA either, even
        // though an absent extension means all purposes for a code signer.
        let plain = simple();
        let none = Cert::parse(&plain).unwrap();
        assert!(!none.is_purpose_exactly(oid::ID_KP_TIMESTAMPING));
    }

    #[test]
    fn a_truncated_validity_is_refused() {
        // A `Validity` with only one time in it. Hand-building this means
        // splicing the certificate, which is what a hostile file does.
        let der = fixture::certificate(
            &[0x17],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(MODULUS, EXPONENT),
            &[],
        );
        // Cut the certificate in half: every remaining field is then short.
        assert!(Cert::parse(&der[..der.len() / 2]).is_err());
    }
}
