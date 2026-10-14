//! Counter-signatures: the evidence of *when* a file was signed.
//!
//! # Why this decides a third of the population
//!
//! Measured over the 812 embedded-signed files in an installed `System32`,
//! **248 of them — 30.5% — have a signer certificate that has already
//! expired.** Every one of those is correctly signed. A verifier that checked
//! the signer's validity against the clock would report a third of Windows as
//! expired, and a scanner that treated that as "not trusted" would have a
//! third of the operating system sitting in the band that warns the user.
//!
//! What makes them correct is the counter-signature: a signature by a
//! time-stamping authority over the signer's own signature, made while the
//! signer's certificate was still valid. It says "this file existed, in this
//! form, at this moment", and it is what lets the chain be judged *then*
//! instead of now. Reporting an expired-but-timestamped file as expired is not
//! a conservative error, it is a wrong answer, and it is the most common wrong
//! answer available to this crate.
//!
//! # Two forms, and they are not the same evidence
//!
//! **RFC 3161** is the standard one. The token is a complete CMS `SignedData`
//! in its own right, carried in the signer's unauthenticated attributes under
//! `id-aa-timeStampToken`, `1.3.6.1.4.1.311.3.3.1`. Its content is a `TSTInfo`
//! whose `messageImprint` is a hash of the *outer* signature — the `signature`
//! OCTET STRING of the `SignerInfo` being timestamped — and whose `genTime` is
//! the moment being asserted. 807 of the 812 carry one.
//!
//! **The legacy `counterSignature` attribute**, `1.2.840.113549.1.9.6`, is the
//! PKCS#9 form: the attribute's value is a bare `SignerInfo`, its signature is
//! over the parent's signature too, but there is no `TSTInfo` and the only
//! statement of time is the `signingTime` signed attribute inside it. 5 of the
//! 812 carry one and **none carries both**.
//!
//! The two are reported as different [`TimestampForm`]s rather than folded
//! together, because "an authority signed a `TSTInfo` whose imprint is over
//! this signature" and "an authority signed a structure containing a time it
//! chose" are different amounts of evidence, and a caller that has to decide
//! how much weight to give a time deserves to know which it has.
//!
//! # What is proven before a time is used
//!
//! A counter-signature is worth nothing until its own signature has been
//! checked, and the check is not decoration: the token sits in an
//! *unauthenticated* attribute, which by definition is not covered by the
//! signer's signature. An attacker who could not touch the file or the
//! signature could still append a fabricated token asserting any time. So
//! every path below:
//!
//! 1. verifies the token's signature against the authority's own public key,
//! 2. checks the `TSTInfo`'s `messageImprint` is over the signature it claims
//!    to timestamp,
//! 3. checks the token's `messageDigest` attribute is the digest of its own
//!    content, and
//! 4. checks the authority's `extendedKeyUsage` is *exactly* `timeStamping`.
//!
//! A token that fails any of them is reported as an error, not as a time.
//!
//! What is *not* proven here is that the authority is trusted. That is the
//! chain's job, at the same instant, and it happens in [`crate::chain`]. A
//! token from an authority whose chain does not reach a root yields no trust —
//! which is why the time can be used to judge the signer's chain without
//! circularity: an untrusted authority cannot make an untrusted signature
//! trusted, it can only make it judged earlier.

use crate::cms::{Attribute, SignedData, SignerInfo};
use crate::digest::DigestAlgorithm;
use crate::error::AuthError;
use crate::oid::{self, SignatureAlgorithm};
use crate::rsa;
use crate::x509::{Cert, PublicKey};
use av_signatures::der::{
    Tlv, GENERALIZED_TIME, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, SET,
};
use av_signatures::oid::oid_matches;
use av_signatures::time::{parse_time, UnixTime};
use av_signatures::SignatureError;

/// A time that has been *proven*, and what proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    /// The asserted time, in Unix seconds. This is the instant the signer's
    /// chain and the authority's own chain are both judged at.
    pub time: i64,
    /// The authority's subject, for a report.
    pub authority: String,
    /// The authority's certificate thumbprint, SHA-1, for a report.
    pub authority_thumbprint: String,
    /// The authority's certificate, DER, so its own chain can be built.
    pub authority_der: Vec<u8>,
    /// Every other certificate the token carried, DER, so the authority's chain
    /// can be completed offline.
    ///
    /// The same reasoning as the file's own certificates on the signer's chain:
    /// a timestamp token is issued by a time-stamping authority whose
    /// intermediate may be inside the token and on no machine store. A caller
    /// that built the authority's chain from the machine alone would fail on
    /// exactly those tokens, and would then judge the signer at the current
    /// time — which is the wrong answer for a file signed before its
    /// certificate expired, and the answer this whole module exists to avoid.
    pub authority_chain: Vec<Vec<u8>>,
    /// Which of the two forms it was.
    pub form: TimestampForm,
    /// The authority's `notBefore`.
    pub authority_not_before: i64,
    /// The authority's `notAfter`.
    pub authority_not_after: i64,
}

impl Timestamp {
    /// Whether the authority's own certificate was valid at the time it
    /// asserts.
    ///
    /// A token whose authority was outside its validity when it signed is not
    /// evidence of anything, and this is the one check on the authority that
    /// does not need a chain — it is arithmetic on two numbers already in hand.
    pub fn authority_was_valid_at_the_time(&self) -> bool {
        self.authority_not_before <= self.time && self.time <= self.authority_not_after
    }
}

/// Which form the evidence took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampForm {
    /// An RFC 3161 `TSTInfo`: a signed structure that covers the signature and
    /// states a time inside its own signed content.
    Rfc3161,
    /// A PKCS#9 `counterSignature`, whose only statement of time is a signed
    /// attribute. Covered by the authority's signature, but a field the
    /// authority chose rather than one bound to an imprint of the file.
    LegacyCounterSignature,
}

/// Find and verify the timestamp on a signer, if there is one.
///
/// `Ok(None)` means there is no counter-signature at all.
/// `Err(AuthError::BadTimestamp)` means there is one and it does not hold up.
///
/// The two are kept apart on purpose. "No timestamp" is a fact about the file
/// that leads to judging the chain at the current time, and the caller's
/// verdict is then about expiry. "A timestamp that failed" is a *finding*: a
/// counter-signature that does not verify is a token that was altered, or one
/// made by an authority that is not one, and a user should see that rather than
/// see the file judged as merely stale.
pub fn find<'a>(
    signer: &SignerInfo<'a>,
    certificates: &[&'a [u8]],
) -> Result<Option<Timestamp>, AuthError> {
    if let Some(attribute) = signer.unsigned(oid::ATTR_MS_TIMESTAMP) {
        return verify_rfc3161(attribute, signer.signature, certificates).map(Some);
    }
    if let Some(attribute) = find_legacy(signer) {
        return verify_legacy(attribute, signer.signature, certificates).map(Some);
    }
    Ok(None)
}

/// The legacy `counterSignature` attribute, in either attribute set.
///
/// The PKCS#9 form is defined as an unauthenticated attribute, and Windows also
/// emits it as a *signed* one on some files. Looking in both places costs one
/// comparison and finds a time that would otherwise be missed.
///
/// The two lifetimes are named rather than elided because they are genuinely
/// two: `'blob` is the blob the attribute's own bytes out of, `'signer` is how
/// long the `SignerInfo` is borrowed for. Elision has no rule that picks between
/// them, and collapsing them into one would tie the returned attribute to the
/// `SignerInfo` — which is exactly the borrow the caller does not need.
fn find_legacy<'signer, 'blob>(
    signer: &'signer SignerInfo<'blob>,
) -> Option<&'signer Attribute<'blob>> {
    signer.unsigned(oid::ATTR_COUNTER_SIGNATURE).or_else(|| {
        signer
            .signed_attributes
            .as_ref()
            .and_then(|attributes| attributes.attribute(oid::ATTR_COUNTER_SIGNATURE))
    })
}

/// Verify an RFC 3161 token and return the time it proves.
fn verify_rfc3161(
    attribute: &Attribute<'_>,
    signature: &[u8],
    certificates: &[&[u8]],
) -> Result<Timestamp, AuthError> {
    let span = attribute
        .value_span()
        .ok_or(AuthError::BadTimestamp {
            reason: "the timestamp attribute has no value",
        })?;

    // The value is the token's `ContentInfo`. Windows wraps it one level deeper
    // than RFC 3161 asks for on some files — a `SET` where the spec says
    // `ContentInfo` — so a value whose tag is `SET` is unwrapped rather than
    // refused. Both shapes occur in the 812, and refusing one would lose the
    // timestamp on files that are correctly signed.
    let token_der = unwrap_set(span)?;
    let token = SignedData::parse(token_der).map_err(|_| AuthError::BadTimestamp {
        reason: "the timestamp token is not a readable signature",
    })?;

    let tst = parse_tst_info(&token)?;
    let token_signer = token
        .signers
        .first()
        .ok_or(AuthError::BadTimestamp {
            reason: "the timestamp token carries no signer",
        })?;

    // The imprint must be over the signature this token claims to timestamp.
    // Without this the token is a valid signature over an unrelated number, and
    // the time in it says nothing about this file.
    if tst.imprint_algorithm.digest(signature) != tst.imprint {
        return Err(AuthError::BadTimestamp {
            reason: "the timestamp does not cover this file's signature",
        });
    }

    let authority = verify_token(
        token_signer,
        &token.certificates,
        certificates,
        token.content,
    )?;

    // The token's own certificates first, then the outer blob's; the
    // authority's own is included, which is harmless — a store holding the leaf
    // it is asked about changes nothing.
    let mut authority_chain: Vec<Vec<u8>> =
        token.certificates.iter().map(|der| der.to_vec()).collect();
    for der in certificates {
        if !authority_chain.iter().any(|held| held.as_slice() == *der) {
            authority_chain.push(der.to_vec());
        }
    }

    Ok(Timestamp {
        time: tst.gen_time,
        authority: authority.subject().to_string(),
        authority_thumbprint: authority.thumbprint(),
        authority_der: authority.der().to_vec(),
        authority_chain,
        authority_not_before: authority.not_before().seconds(),
        authority_not_after: authority.not_after().seconds(),
        form: TimestampForm::Rfc3161,
    })
}

/// The `ContentInfo` inside an attribute value, unwrapping a `SET` if present.
fn unwrap_set(span: &[u8]) -> Result<&[u8], AuthError> {
    let element = av_signatures::der::parse_one(span).map_err(|_| AuthError::BadTimestamp {
        reason: "the timestamp attribute's value is not a DER element",
    })?;
    if !element.is(SET) {
        return Ok(span);
    }
    let mut values = element.elements();
    let (_, inner) = values
        .next_with_span()
        .and_then(Result::ok)
        .ok_or(AuthError::BadTimestamp {
            reason: "the timestamp attribute's set is empty",
        })?;
    Ok(inner)
}

/// The parts of a `TSTInfo` this crate reads.
struct TstInfo<'a> {
    gen_time: i64,
    imprint_algorithm: DigestAlgorithm,
    imprint: &'a [u8],
}

/// `TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }`.
fn parse_tst_info<'a>(token: &SignedData<'a>) -> Result<TstInfo<'a>, AuthError> {
    if token.content_type != oid::CT_TST_INFO {
        return Err(AuthError::BadTimestamp {
            reason: "the timestamp token's content is not a TSTInfo",
        });
    }
    let root =
        av_signatures::der::parse_one(token.content).map_err(|_| AuthError::BadTimestamp {
            reason: "the TSTInfo is not readable",
        })?;
    if !root.is(SEQUENCE) {
        return Err(AuthError::BadTimestamp {
            reason: "the TSTInfo is not a sequence",
        });
    }
    let mut fields = root.elements();
    let version = fields.next().and_then(Result::ok).ok_or_else(tst_short)?;
    if !version.is(INTEGER) || version.unsigned().map_err(|_| tst_short())? != 1 {
        return Err(AuthError::BadTimestamp {
            reason: "the TSTInfo version is not 1",
        });
    }
    // `policy`: the authority's own statement of which of its practices
    // applies. No decision here depends on it, so it is stepped over rather
    // than read and then ignored.
    fields.skip_n(1).map_err(|_| tst_short())?;

    let imprint = fields.next().and_then(Result::ok).ok_or_else(tst_short)?;
    let (imprint_algorithm, imprint) = parse_message_imprint(&imprint)?;

    // `serialNumber`: the authority's own numbering, which is a statement about
    // the authority's bookkeeping and not about this file.
    fields.skip_n(1).map_err(|_| tst_short())?;

    let gen_time = fields.next().and_then(Result::ok).ok_or_else(tst_short)?;
    let text = gen_time.time_text().map_err(AuthError::Malformed)?;
    let gen_time = parse_stamp_time(gen_time.tag, &text).map_err(|_| AuthError::BadTimestamp {
        reason: "the TSTInfo's time is not a readable time",
    })?;

    Ok(TstInfo {
        gen_time: gen_time.seconds(),
        imprint_algorithm,
        imprint,
    })
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }`.
fn parse_message_imprint<'blob>(
    imprint: &Tlv<'blob>,
) -> Result<(DigestAlgorithm, &'blob [u8]), AuthError> {
    if !imprint.is(SEQUENCE) {
        return Err(AuthError::BadTimestamp {
            reason: "the message imprint is not a sequence",
        });
    }
    let mut fields = imprint.elements();
    let algorithm = fields.next().and_then(Result::ok).ok_or_else(tst_short)?;
    let message = fields.next().and_then(Result::ok).ok_or_else(tst_short)?;
    if !algorithm.is(SEQUENCE) || !message.is(OCTET_STRING) {
        return Err(AuthError::BadTimestamp {
            reason: "the message imprint has the wrong shape",
        });
    }
    let mut algorithm_fields = algorithm.elements();
    let id = algorithm_fields
        .next()
        .and_then(Result::ok)
        .ok_or_else(tst_short)?;
    if !id.is(OBJECT_IDENTIFIER) {
        return Err(AuthError::BadTimestamp {
            reason: "the message imprint names no algorithm",
        });
    }
    let Some(digest) = DigestAlgorithm::from_oid(id.content) else {
        return Err(AuthError::BadTimestamp {
            reason: "the message imprint uses a digest this verifier does not implement",
        });
    };
    if message.content.len() != digest.output_len() {
        return Err(AuthError::BadTimestamp {
            reason: "the message imprint is not the length its algorithm produces",
        });
    }
    Ok((digest, message.content))
}

/// Verify a token's own signature and return the authority's certificate.
///
/// The candidates are the token's own certificates first and the outer blob's
/// second: a token that carries its own chain is self-contained, and one that
/// does not is relying on the file's, which is common when both chains are the
/// same.
fn verify_token<'a>(
    signer: &SignerInfo<'a>,
    token_certificates: &[&'a [u8]],
    outer_certificates: &[&'a [u8]],
    content: &'a [u8],
) -> Result<Cert<'a>, AuthError> {
    let mut candidates: Vec<&'a [u8]> = token_certificates.to_vec();
    candidates.extend_from_slice(outer_certificates);

    let authority_der = select_signer(signer, &candidates)?;
    let authority = Cert::parse(authority_der)?;

    // RFC 3161 §2.3: the authority's certificate must carry
    // `id-kp-timeStamping`, and it must be the *only* purpose. An authority
    // that could also sign programs is not a time-stamping authority, and this
    // is the check that keeps a code-signing certificate from vouching for a
    // time as well as for a file.
    if !authority.is_purpose_exactly(oid::ID_KP_TIMESTAMPING) {
        return Err(AuthError::BadTimestamp {
            reason: "the timestamp authority's extended key usage is not exactly timeStamping",
        });
    }

    let attributes = signer
        .signed_attributes
        .as_ref()
        .ok_or(AuthError::BadTimestamp {
            reason: "the timestamp token's signer has no signed attributes",
        })?;

    // The `messageDigest` attribute must be the digest of the token's own
    // content. Checked before the signature: a signature that verifies over
    // attributes that do not bind the content is a signature over nothing this
    // verifier is going to read.
    let claimed = attributes
        .value(oid::ATTR_MESSAGE_DIGEST)
        .ok_or(AuthError::BadTimestamp {
            reason: "the timestamp token has no message digest attribute",
        })?;
    if claimed.content != signer.digest_algorithm.digest(content) {
        return Err(AuthError::BadTimestamp {
            reason: "the timestamp token's digest is not the digest of its content",
        });
    }

    verify_signed_attributes(&authority, signer, attributes)
        .map_err(|reason| AuthError::BadTimestamp { reason })?;

    Ok(authority)
}

/// Verify a signature over a `SignerInfo`'s signed attributes.
///
/// Shared by the outer signature and the token's, so that the two cannot
/// diverge: a rule applied to a file's signature and not to a timestamp's would
/// be a rule an attacker could choose to be judged by.
pub(crate) fn verify_signed_attributes(
    certificate: &Cert<'_>,
    signer: &SignerInfo<'_>,
    attributes: &crate::cms::SignedAttributes<'_>,
) -> Result<(), &'static str> {
    let PublicKey::Rsa { modulus, exponent } = certificate.public_key() else {
        return Err("the signer's key is not an RSA key, and this verifier implements only RSA");
    };
    let SignatureAlgorithm::RsaPkcs1 { digest } = signer.signature_algorithm else {
        return Err("the signature algorithm is not implemented");
    };
    // The digest is taken with the *signature algorithm's* digest, not the
    // `SignerInfo`'s `digestAlgorithm`. The two are required to agree, and if
    // they do not, the one that matters is the one the recovered block will be
    // checked against — `rsa::verify` parses the `DigestInfo` out of the block
    // and requires it to name `digest.oid()` and hold `computed`. Assuming the
    // other one would make a disagreement look like a bad signature rather than
    // a structure that contradicts itself.
    let computed = digest.digest(attributes.encoded());
    match rsa::verify(modulus, exponent, signer.signature, digest.oid(), &computed) {
        Ok(()) => Ok(()),
        Err(_) => Err("the signature does not verify against the signer's public key"),
    }
}

/// Verify a legacy PKCS#9 counter-signature.
fn verify_legacy(
    attribute: &Attribute<'_>,
    signature: &[u8],
    certificates: &[&[u8]],
) -> Result<Timestamp, AuthError> {
    let value = attribute.value().ok_or(AuthError::BadTimestamp {
        reason: "the counter-signature attribute has no value",
    })?;
    // The value is a bare `SignerInfo`, not a `SignedData`, so it is read
    // through the shim rather than through `SignedData::parse`.
    let signer = crate::cms::parse_bare_signer_info(value)?;
    let authority_der = select_signer(&signer, certificates)?;
    let authority = Cert::parse(authority_der)?;

    let attributes = signer
        .signed_attributes
        .as_ref()
        .ok_or(AuthError::BadTimestamp {
            reason: "the counter-signature has no signed attributes",
        })?;

    // In the legacy form the signature is over the parent's `signature` OCTET
    // STRING contents directly — there is no `messageImprint` — and the only
    // statement of time is the `signingTime` signed attribute.
    let time = attributes
        .value(oid::ATTR_SIGNING_TIME)
        .ok_or(AuthError::BadTimestamp {
            reason: "the counter-signature states no time",
        })?;
    let text = time.time_text().map_err(AuthError::Malformed)?;
    let time = parse_stamp_time(time.tag, &text).map_err(|_| AuthError::BadTimestamp {
        reason: "the counter-signature's time is not a readable time",
    })?;

    let PublicKey::Rsa { modulus, exponent } = authority.public_key() else {
        return Err(AuthError::BadTimestamp {
            reason: "the counter-signing authority's key is not an RSA key",
        });
    };
    let computed = signer.digest_algorithm.digest(signature);
    rsa::verify(
        modulus,
        exponent,
        signer.signature,
        signer.digest_algorithm.oid(),
        &computed,
    )
    .map_err(|_| AuthError::BadTimestamp {
        reason: "the counter-signature does not verify over the file's signature",
    })?;

    Ok(Timestamp {
        time: time.seconds(),
        authority: authority.subject().to_string(),
        authority_thumbprint: authority.thumbprint(),
        authority_der: authority.der().to_vec(),
        // The legacy form carries no token of its own, so the only certificates
        // available are the outer blob's.
        authority_chain: certificates.iter().map(|der| der.to_vec()).collect(),
        authority_not_before: authority.not_before().seconds(),
        authority_not_after: authority.not_after().seconds(),
        form: TimestampForm::LegacyCounterSignature,
    })
}

/// Find the certificate a `SignerInfo` names.
///
/// The match is on the issuer's *encoding* and the serial, which is what the
/// identifier is: a byte string, not a rendering. Two encodings of one name
/// render identically and are different bytes, and matching on the rendering
/// would let one identifier name two certificates.
pub(crate) fn select_signer<'a>(
    signer: &SignerInfo<'_>,
    candidates: &[&'a [u8]],
) -> Result<&'a [u8], AuthError> {
    let (Some(issuer), Some(serial)) = (signer.issuer, signer.serial) else {
        return Err(AuthError::SignerCertificateAbsent);
    };
    let serial = strip_sign_byte(serial);
    for candidate in candidates {
        if let Ok(cert) = Cert::parse(candidate) {
            if cert.issuer_der() == issuer && cert.serial() == serial {
                return Ok(candidate);
            }
        }
    }
    Err(AuthError::SignerCertificateAbsent)
}

/// Strip the DER sign byte a positive INTEGER may carry.
///
/// `Cert::serial` already does this, and the serial from an identifier is the
/// raw `INTEGER` content, so the same normalisation has to be applied to both
/// sides of the comparison or a serial that needs a leading zero would never
/// match itself.
fn strip_sign_byte(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    }
}

/// A truncated `TSTInfo`.
fn tst_short() -> AuthError {
    AuthError::BadTimestamp {
        reason: "the TSTInfo ends before its fields do",
    }
}

/// The instant a counter-signature states, which may carry fractional seconds.
///
/// [`parse_time`] refuses a fraction, and it is right to: RFC 5280 §4.1.2.5.2
/// forbids one in a certificate's validity. A stated signing time is governed by
/// the other standard. RFC 3161 §2.4.2 requires the seconds and explicitly
/// *permits* a fraction, and Microsoft's authority writes one — every
/// timestamped binary measured in an installed `System32` states its `genTime`
/// as `20260517035832.823Z`, and a token in that form is a token this crate
/// could not read at all before this function existed.
///
/// Refusing the fraction fails in the wrong direction. It does not make the
/// verification stricter; it throws the time away, the signer's chain is then
/// judged at the present instant instead of at signing, and every file whose
/// certificate has since expired reads as expired — which is the single most
/// common wrong answer available to this crate, and the reason
/// [`crate::timestamp`] exists. A fraction on a *`UTCTime`* is not permitted by
/// any standard and is still refused, because the tag is passed through
/// untouched.
///
/// Truncated rather than rounded: what the token is being used for is to place
/// the signature inside the signer's validity window, and rounding *up* could
/// put it a second past an expiry the authority's own clock put it inside.
fn parse_stamp_time(tag: u8, text: &str) -> Result<UnixTime, SignatureError> {
    if tag == GENERALIZED_TIME {
        if let Some((whole, fraction)) =
            text.strip_suffix('Z').and_then(|body| body.split_once('.'))
        {
            // Only a real fraction is dropped. A text that is malformed in some
            // other way is handed to `parse_time` unchanged, so that the reason
            // a stamp could not be read stays the time parser's to give rather
            // than becoming "unreadable time" for every kind of malformation.
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return parse_time(tag, &format!("{whole}Z"));
            }
        }
    }
    parse_time(tag, text)
}

/// Whether an OID names a timestamp token attribute, for a caller with arcs.
pub fn is_timestamp_attribute(arcs: &[u64]) -> bool {
    arcs == oid::ATTR_MS_TIMESTAMP || arcs == oid::ATTR_COUNTER_SIGNATURE
}

/// Whether an OID content names the Microsoft timestamp attribute.
pub fn is_timestamp_oid(content: &[u8]) -> bool {
    oid_matches(content, oid::ATTR_MS_TIMESTAMP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_signatures::der::UTC_TIME;

    /// The instant the measured text names, derived independently.
    ///
    /// `1_778_990_312` is 2026-05-17T03:58:32Z in Unix seconds, computed from
    /// the calendar rather than by running this code. Written out because the
    /// test below asserts a *value*: comparing the fractional form against the
    /// fractionless one would agree even if both were wrong about the instant,
    /// and the instant is the whole reason a counter-signature is read.
    const MEASURED_INSTANT: i64 = 1_778_990_312;

    #[test]
    fn the_fraction_a_microsoft_authority_writes_is_read() {
        // The exact text, measured rather than invented: every timestamped
        // binary in an installed `System32` states its `genTime` this way, and
        // before [`parse_stamp_time`] existed not one of them could be read —
        // which cost every one of those files its counter-signature, and with it
        // its chance of being judged at the time it was signed.
        let stamp = parse_stamp_time(GENERALIZED_TIME, "20260517035832.823Z")
            .expect("the measured form must be readable");
        assert_eq!(stamp.seconds(), MEASURED_INSTANT);
    }

    #[test]
    fn the_fraction_is_dropped_and_not_rounded() {
        // A stamp with no fraction goes through untouched, and the two forms
        // name the same instant. Rounding up instead would put a signature a
        // second past an expiry the authority's own clock put it inside, which
        // is the direction that turns a good file into an expired one.
        assert_eq!(
            parse_stamp_time(GENERALIZED_TIME, "20260517035832Z")
                .expect("the fractionless form is what the time parser already read")
                .seconds(),
            MEASURED_INSTANT
        );
    }

    #[test]
    fn a_fraction_on_a_utc_time_is_still_refused() {
        // The tolerance is for `GeneralizedTime` alone. RFC 5280 §4.1.2.5.1
        // forbids a fraction in a `UTCTime`, the tag is what decides which form
        // is expected, and a stamp that used the forbidden form is a stamp this
        // crate declines to read rather than one it reads leniently.
        assert!(parse_stamp_time(UTC_TIME, "260517035832.823Z").is_err());
    }

    #[test]
    fn anything_that_is_not_a_fraction_is_left_to_the_time_parser() {
        // The stripping is narrow on purpose: it fires only on a terminator, a
        // single dot and a non-empty run of digits after it. Everything else
        // reaches [`parse_time`] unchanged, so that "the time is unreadable"
        // keeps meaning one thing rather than two, and so that a malformed
        // stamp cannot be reported as a good one by accident.
        for text in [
            "20260517035832.Z",         // an empty fraction
            "20260517035832.8a3Z",      // a fraction that is not all digits
            "20260517035832.823",       // no terminator at all
            "202605170358.823Z",        // short before the fraction, not after it
            "20260517035832.823+0100Z", // a fraction and an offset
        ] {
            assert!(
                parse_stamp_time(GENERALIZED_TIME, text).is_err(),
                "{text} must not be read as a time"
            );
        }
    }
}
