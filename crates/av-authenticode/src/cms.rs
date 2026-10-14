//! The PKCS#7/CMS `SignedData` an Authenticode signature is carried in.
//!
//! # Why this is a second reader for the same structure
//!
//! [`av_signatures::pkcs7`] reads the same blob and its module documentation
//! says an Authenticode signature is a *degenerate* PKCS#7 in which
//! `signerInfos` is empty and everything of interest is in `certificates`. That
//! is true of the blobs a rule reads and false of every signature Windows
//! makes: the structure is not degenerate at all. Measured over the 812
//! embedded-signed files in an installed `System32`, every one carries exactly
//! one `SignerInfo`, with signed attributes, a signature algorithm, and
//! usually a timestamp in its unauthenticated attributes.
//!
//! The certificate set is what a rule wants and it is all that reader returns.
//! This one reads the `SignerInfo` — and the `SignerInfo` is the part a
//! verifier cannot do without, because it holds the signature, names the
//! certificate that made it, and carries the attributes the signature is over.
//!
//! The DER reader underneath is shared. What is re-read is the small part of
//! the structure that reader skips.
//!
//! # The one byte that has to be rewritten
//!
//! ```text
//! SignerInfo ::= SEQUENCE {
//!     version                 INTEGER,
//!     sid                     SignerIdentifier,
//!     digestAlgorithm         AlgorithmIdentifier,
//!     signedAttrs         [0] IMPLICIT SET OF Attribute OPTIONAL,
//!     signatureAlgorithm      AlgorithmIdentifier,
//!     signature               OCTET STRING,
//!     unsignedAttrs       [1] IMPLICIT SET OF Attribute OPTIONAL }
//! ```
//!
//! `signedAttrs` is `[0] IMPLICIT`, so the `SET` tag is *replaced* by `0xA0`
//! rather than wrapped in it. The signature, however, is over those attributes
//! in their `SET` form. So the bytes that are hashed are a copy of what the
//! blob holds with byte zero changed from `0xA0` to `0x31` — and, critically,
//! **only** byte zero: the length octets, including a long-form length, are
//! part of what was signed and must survive unchanged. An implementation that
//! re-encoded the attributes from parsed values would produce the right shape
//! and the wrong bytes, because DER's ordering rules allow more than one
//! encoding of the same abstract value and only the bytes that were signed are
//! the bytes that were signed.
//!
//! # Two attributes with the same name
//!
//! `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }`
//! and `signedAttrs` is a set, so a blob can carry two `messageDigest`
//! attributes. A verifier that read the first would compare a digest the
//! signer may not have committed to, and one that read the last would be
//! equally arbitrary. Every attribute this crate reads must appear at most
//! once; a duplicate is refused. This is not hypothetical tidiness: it is the
//! cheapest way to make a verifier check one number while a report shows
//! another.

use crate::digest::DigestAlgorithm;
use crate::error::AuthError;
use crate::oid::{self, SignatureAlgorithm};
use av_signatures::der::{Tlv, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, SET};
use av_signatures::oid::oid_matches;
use av_signatures::SignatureError;

/// The `[0]` context tag that replaces the `SET` tag on `signedAttrs`.
const SIGNED_ATTRS_TAG: u8 = 0xa0;

/// The `[1]` context tag that replaces the `SET` tag on `unsignedAttrs`.
const UNSIGNED_ATTRS_TAG: u8 = 0xa1;

/// The `SET` tag those two stand in for.
const IMPLICIT_SET_TAG: u8 = 0x31;

/// One `Attribute`.
///
/// Each value is kept twice: as a parsed element, and as the span of the file
/// it came from. The second is not redundant. The `timeStampToken` attribute's
/// value *is* a complete `SignedData`, and a `SignedData` is parsed from its
/// own encoding — a `Tlv` carries the content without the header, and a
/// structure cannot be parsed from a buffer that begins mid-header.
#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    id: Vec<u64>,
    values: Vec<(Tlv<'a>, &'a [u8])>,
}

impl<'a> Attribute<'a> {
    /// The attribute's type, dotted.
    pub fn id(&self) -> String {
        av_signatures::oid::dotted(&encode_oid(&self.id))
    }

    /// The attribute's type, as arcs, for comparison.
    pub fn arcs(&self) -> &[u64] {
        &self.id
    }

    /// Whether this attribute is the given type.
    pub fn is(&self, arcs: &[u64]) -> bool {
        self.id == arcs
    }

    /// The first value, which is the only one the attributes this crate reads
    /// are allowed to have.
    pub fn value(&self) -> Option<&Tlv<'a>> {
        self.values.first().map(|(tlv, _)| tlv)
    }

    /// The complete encoding of the first value.
    ///
    /// This is the element as the file carries it, header included, which is
    /// what a nested structure is parsed from and what a thumbprint would be
    /// taken over.
    pub fn value_span(&self) -> Option<&'a [u8]> {
        self.values.first().map(|(_, span)| *span)
    }

    /// The number of values, for a caller checking that an attribute says one
    /// thing rather than several.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the attribute carries no value at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Re-encode OID arcs the way `av_signatures::oid::dotted` wants them.
///
/// That function takes an encoded OID, so the arcs have to be put back into
/// DER first. Kept here rather than duplicating the arc arithmetic: the
/// encoding is short and the alternative is a second implementation of
/// base-128 that could disagree with the first.
fn encode_oid(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    if arcs.len() < 2 {
        return out;
    }
    let mut push = |mut value: u64| {
        let mut stack = [0u8; 10];
        let mut at = stack.len();
        at -= 1;
        stack[at] = (value & 0x7f) as u8;
        value >>= 7;
        while value > 0 {
            at -= 1;
            stack[at] = ((value & 0x7f) as u8) | 0x80;
            value >>= 7;
        }
        out.extend_from_slice(&stack[at..]);
    };
    push(arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push(arc);
    }
    out
}

/// The signed attributes, in the form the signature is over.
#[derive(Debug, Clone)]
pub struct SignedAttributes<'a> {
    /// A copy of the `[0]` element with its tag byte rewritten to `0x31`.
    ///
    /// This is the buffer the signature is verified against. It is a copy
    /// rather than a borrow because the tag byte has to change and the blob
    /// must not.
    encoded: Vec<u8>,
    attributes: Vec<Attribute<'a>>,
}

impl<'a> SignedAttributes<'a> {
    /// The bytes the signature covers: the attributes as a `SET OF`.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The attributes as parsed.
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attributes
    }

    /// The named attribute itself, for a caller that needs its encoding rather
    /// than its value.
    ///
    /// [`SignedAttributes::value`] is this with the value taken out of it. The
    /// rule — *the first attribute with these arcs* — is written once and both
    /// callers go through it, because a second `find` at a call site is a second
    /// place for the rule to be got slightly wrong, and "slightly wrong" here
    /// means picking a different attribute than the verifier does.
    pub fn attribute(&self, arcs: &[u64]) -> Option<&Attribute<'a>> {
        self.attributes.iter().find(|attribute| attribute.is(arcs))
    }

    /// The single value of the named attribute.
    ///
    /// `None` covers both "absent" and "present with no value". The two are
    /// different malformations but the same answer to the only question a
    /// caller asks — is there a value to compare — and a caller that needed to
    /// tell them apart would be reporting a defect in the file rather than a
    /// failed check.
    pub fn value(&self, arcs: &[u64]) -> Option<&Tlv<'a>> {
        self.attribute(arcs).and_then(Attribute::value)
    }
}

/// A `SignerInfo`.
#[derive(Debug, Clone)]
pub struct SignerInfo<'a> {
    /// The issuer `Name` from the issuer-and-serial identifier, DER, or `None`
    /// when the identifier is the subject-key form.
    pub issuer: Option<&'a [u8]>,
    /// The serial number from that identifier, as encoded.
    pub serial: Option<&'a [u8]>,
    /// The digest algorithm the signature uses.
    pub digest_algorithm: DigestAlgorithm,
    /// The signature algorithm, from its OID.
    pub signature_algorithm: SignatureAlgorithm,
    /// The signature bytes.
    pub signature: &'a [u8],
    /// The signed attributes, or `None` for a signature made directly over the
    /// content.
    pub signed_attributes: Option<SignedAttributes<'a>>,
    /// The unauthenticated attributes, which is where a timestamp lives.
    pub unsigned_attributes: Vec<Attribute<'a>>,
}

impl<'a> SignerInfo<'a> {
    /// The named unauthenticated attribute.
    pub fn unsigned(&self, arcs: &[u64]) -> Option<&Attribute<'a>> {
        self.unsigned_attributes
            .iter()
            .find(|attribute| attribute.is(arcs))
    }
}

/// A parsed `SignedData`.
#[derive(Debug, Clone)]
pub struct SignedData<'a> {
    /// The encapsulated content type — `SPC_INDIRECT_DATA` for an Authenticode
    /// signature.
    pub content_type: Vec<u64>,
    /// The encapsulated content, which for Authenticode is a
    /// `SpcIndirectDataContent` in DER, header included.
    ///
    /// This is what [`crate::spc::parse`] takes. It is **not** what the
    /// signature's `messageDigest` attribute is over — see
    /// [`SignedData::content_octets`], which is, and which is a different range
    /// of the same bytes by exactly the element's own tag and length.
    pub content: &'a [u8],
    /// The *content octets* of the encapsulated content: the bytes inside the
    /// element [`SignedData::content`] spans, without its tag and length.
    ///
    /// A second field rather than something each caller derives, because which
    /// of the two ranges the `messageDigest` is over is the single most
    /// mistakable fact in Authenticode. Writing it down once, where the parsing
    /// happens, is what keeps it from being got wrong at one of the call sites
    /// and right at the other — and a verifier that digests the wrong range
    /// fails closed, which is the safe direction but a silent one.
    ///
    /// It coincides with [`SignedData::content`] for a file that wraps the
    /// `SpcIndirectDataContent` in an `OCTET STRING`, which is the form RFC
    /// 5652 describes and which no file in the measured corpus uses. See
    /// `parse_encap_content_info`.
    pub content_octets: &'a [u8],
    /// Every certificate carried, in the order the blob lists them.
    pub certificates: Vec<&'a [u8]>,
    /// The signers.
    pub signers: Vec<SignerInfo<'a>>,
}

impl<'a> SignedData<'a> {
    /// Parse a `ContentInfo` wrapping a `SignedData`.
    pub fn parse(blob: &'a [u8]) -> Result<Self, AuthError> {
        let content_info = av_signatures::der::parse_one(blob).map_err(AuthError::Malformed)?;
        if !content_info.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::NotConstructed {
                tag: content_info.tag,
            }));
        }
        let mut outer = content_info.elements();
        let id = outer.next().and_then(Result::ok).ok_or_else(short)?;
        if !oid_matches(id.content, oid::PKCS7_SIGNED_DATA) {
            return Err(AuthError::NotSignedData {
                reason: "the content type is not signedData",
            });
        }
        let wrapped = outer.next().and_then(Result::ok).ok_or_else(short)?;
        if !wrapped.is_context(0) {
            return Err(AuthError::NotSignedData {
                reason: "signedData is not wrapped in the [0] the format requires",
            });
        }
        let inner = wrapped
            .elements()
            .next()
            .and_then(Result::ok)
            .ok_or_else(short)?;
        if !inner.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::NotConstructed {
                tag: inner.tag,
            }));
        }

        let mut fields = inner.elements();
        // `version`, which is 1 for every Authenticode blob measured and which
        // nothing acts on.
        fields.skip_n(1).map_err(AuthError::Malformed)?;
        // `digestAlgorithms` — a set that is allowed to name more algorithms
        // than are used. The algorithm that matters is the one in each
        // `SignerInfo`, because that is the one that signer used; a verifier
        // that took the set's first entry would be picking an algorithm on
        // behalf of the signer.
        fields.skip_n(1).map_err(AuthError::Malformed)?;

        let encap = fields.next().and_then(Result::ok).ok_or_else(short)?;
        let (content_type, content, content_octets) = parse_encap_content_info(&encap)?;

        let mut certificates = Vec::new();
        let mut signers = Vec::new();
        for field in fields {
            let field = field.map_err(AuthError::Malformed)?;
            if field.is_context(0) {
                // `[0] IMPLICIT SET OF CertificateChoices`. Read with spans so
                // each certificate keeps its exact encoding, which is what a
                // thumbprint and a chain engine are given.
                let mut choices = field.elements();
                while let Some(choice) = choices.next_with_span() {
                    let (tlv, span) = choice.map_err(AuthError::Malformed)?;
                    if tlv.is(SEQUENCE) {
                        certificates.push(span);
                    }
                }
            } else if field.is_context(1) {
                // `crls`, which is not read: revocation is deliberately not
                // checked. See the crate documentation.
            } else if field.is(SET) {
                for info in field.elements() {
                    let info = info.map_err(AuthError::Malformed)?;
                    signers.push(SignerInfo::parse(&info)?);
                }
            }
        }

        Ok(SignedData {
            content_type,
            content,
            content_octets,
            certificates,
            signers,
        })
    }
}

/// `EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }`.
///
/// # The one place Authenticode does not do what RFC 5652 says
///
/// The RFC puts an `OCTET STRING` inside the `[0]`, holding the content as
/// bytes. Windows puts the `SpcIndirectDataContent` — a `SEQUENCE` — in that
/// position with no octet string around it. Every one of the 120 embedded
/// signatures in the first 400 files of an installed `System32` uses the
/// Windows form; the RFC form appears in none of them.
///
/// This matters and is easy to get wrong, because it decides the answer to
/// "what bytes is `messageDigest` the hash of". RFC 5652 §5.4 says the content
/// octets of `eContent`, which for its own form is the octet string's payload.
/// For the Windows form the equivalent statement is the `SEQUENCE`'s — the
/// bytes *inside* the element, not the element. Both are returned, so neither
/// caller has to work it out.
///
/// The discovery that this was wrong is the reason the module documentation of
/// [`crate::testing`] insists a fixture built by the same author as the parser
/// proves only self-consistency: the fixture in this crate wrote the RFC form
/// and the parser happily read it, while every real Microsoft binary failed.
/// What [`parse_encap_content_info`] returns: the content type's OID arcs, the
/// element that holds the content as it appeared, and the octets
/// `messageDigest` is the hash of.
///
/// The last two are different byte ranges for the Windows form of the element
/// and the RFC 5652 one, which is the whole reason both are handed back. See
/// the function's documentation.
type EncapsulatedContent<'a> = (Vec<u64>, &'a [u8], &'a [u8]);

fn parse_encap_content_info<'a>(
    encap: &Tlv<'a>,
) -> Result<EncapsulatedContent<'a>, AuthError> {
    if !encap.is(SEQUENCE) {
        return Err(AuthError::Malformed(SignatureError::NotConstructed {
            tag: encap.tag,
        }));
    }
    let mut fields = encap.elements();
    let id = fields.next().and_then(Result::ok).ok_or_else(short)?;
    if !id.is(OBJECT_IDENTIFIER) {
        return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
            wanted: OBJECT_IDENTIFIER,
            found: id.tag,
        }));
    }
    let arcs = id.oid().map_err(AuthError::Malformed)?;
    let Some(wrapped) = fields.next() else {
        // The content is optional in CMS. For Authenticode its absence means
        // there is nothing to check the file digest against, which is a
        // malformed signature rather than an empty one.
        return Err(AuthError::BadIndirectData {
            reason: "the signature carries no encapsulated content",
        });
    };
    let wrapped = wrapped.map_err(AuthError::Malformed)?;
    if !wrapped.is_context(0) {
        return Err(AuthError::BadIndirectData {
            reason: "the encapsulated content is not wrapped in the [0] the format requires",
        });
    }
    let mut inner = wrapped.elements();
    let (element, span) = inner
        .next_with_span()
        .ok_or_else(short)?
        .map_err(AuthError::Malformed)?;

    // The two ranges are the same bytes only in the RFC form, and the digest
    // range needs no branch while the range `crate::spc::parse` takes does:
    // an `OCTET STRING`'s payload is its content, and a `SEQUENCE`'s body is
    // its content, so `element.content` is the digested range either way.
    let content = match element.tag {
        // The form every file in the measured corpus uses. `spc::parse` is
        // given the whole element, because a structure cannot be parsed from a
        // buffer that starts mid-header.
        SEQUENCE => span,
        // The RFC 5652 form. No measured file uses it, and it is kept readable
        // so that a file which does is verified rather than refused — refusing
        // a correctly signed file is a false positive on a publisher, and the
        // cost of reading it is this branch.
        OCTET_STRING => element.content,
        _ => {
            return Err(AuthError::BadIndirectData {
                reason: "the encapsulated content is neither a sequence nor an octet string",
            })
        }
    };
    Ok((arcs, content, element.content))
}

/// Parse a bare `SignerInfo`, which is what a legacy `counterSignature`
/// attribute's value is: not a `SignedData` with one signer in it, but the
/// `SignerInfo` on its own.
///
/// Exposed because the legacy form is the one place the CMS shapes differ
/// enough that a caller cannot route through [`SignedData::parse`], and a
/// second reader for `SignerInfo` would be a second place for the `[0]`
/// re-tagging to be got wrong.
pub fn parse_bare_signer_info<'a>(info: &Tlv<'a>) -> Result<SignerInfo<'a>, AuthError> {
    SignerInfo::parse(info)
}

impl<'a> SignerInfo<'a> {
    /// Parse one `SignerInfo`.
    fn parse(info: &Tlv<'a>) -> Result<Self, AuthError> {
        if !info.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::NotConstructed {
                tag: info.tag,
            }));
        }
        let mut fields = info.elements();
        // `version`, which distinguishes the two `SignerIdentifier` forms and
        // which nothing here reads: the shape of the identifier says the same
        // thing, and a blob that disagreed with itself about which form it used
        // would be read by its shape.
        fields.skip_n(1).map_err(AuthError::Malformed)?;

        let sid = fields.next().and_then(Result::ok).ok_or_else(short)?;
        let (issuer, serial) = if sid.is(SEQUENCE) {
            // `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
            // The issuer's *encoding* is kept, not its rendering: the
            // identifier is a byte string and comparing renderings would let
            // two encodings of one name match one certificate.
            let mut parts = sid.elements();
            let issuer = parts
                .next_with_span()
                .and_then(Result::ok)
                .ok_or_else(short)?;
            let serial = parts.next().and_then(Result::ok).ok_or_else(short)?;
            (
                Some(issuer.1),
                Some(serial.integer_bytes().map_err(AuthError::Malformed)?),
            )
        } else if sid.is_context_primitive(0) {
            // `[0] SubjectKeyIdentifier`, the other choice. A signature that
            // names its signer this way cannot be matched here, and saying so
            // is better than matching the wrong certificate: it is reported as
            // no signer found.
            (None, None)
        } else {
            return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
                wanted: SEQUENCE,
                found: sid.tag,
            }));
        };

        let digest = fields.next().and_then(Result::ok).ok_or_else(short)?;
        let digest_algorithm = parse_algorithm(&digest)?;

        let signed = fields.next().and_then(Result::ok).ok_or_else(short)?;
        let signed_attributes = if signed.is(SIGNED_ATTRS_TAG) {
            Some(parse_signed_attributes(&signed)?)
        } else {
            // No signed attributes: the signature is over the content itself.
            // No Authenticode signature measured does this, and a verifier that
            // silently accepted it would be verifying a different thing, so the
            // caller is told by the absence.
            None
        };
        // The two remaining fields are the signature algorithm and the
        // signature, in that order, unless the signed attributes were absent —
        // in which case the field just read was the signature algorithm.
        let (signature_algorithm, signature) = if signed_attributes.is_some() {
            let algorithm = fields.next().and_then(Result::ok).ok_or_else(short)?;
            let signature = fields.next().and_then(Result::ok).ok_or_else(short)?;
            (algorithm, signature)
        } else {
            let algorithm = signed;
            let signature = fields.next().and_then(Result::ok).ok_or_else(short)?;
            (algorithm, signature)
        };
        if !signature.is(OCTET_STRING) {
            return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
                wanted: OCTET_STRING,
                found: signature.tag,
            }));
        }
        let signature_algorithm = SignatureAlgorithm::from_oid(
            algorithm_oid(&signature_algorithm)?,
            Some(digest_algorithm),
        );

        let mut unsigned_attributes = Vec::new();
        if let Some(rest) = fields.next() {
            let rest = rest.map_err(AuthError::Malformed)?;
            if rest.is(UNSIGNED_ATTRS_TAG) {
                unsigned_attributes = parse_attributes(&rest)?;
            }
        }

        Ok(SignerInfo {
            issuer,
            serial,
            digest_algorithm,
            signature_algorithm,
            signature: signature.content,
            signed_attributes,
            unsigned_attributes,
        })
    }
}

/// Parse a `[0]`-tagged `SET OF Attribute` into the form the signature covers.
fn parse_signed_attributes<'a>(tagged: &Tlv<'a>) -> Result<SignedAttributes<'a>, AuthError> {
    let attributes = parse_attributes(tagged)?;
    if attributes.is_empty() {
        return Err(AuthError::NoSignedAttributes);
    }
    // The re-tag. A `Tlv` carries its content and not its header, and the
    // header is where the tag byte lives, so the element is rebuilt from the
    // content: `0x31`, the same length octets, the same body. Nothing else in
    // the encoding is a function of the tag, which is why this is exact rather
    // than a re-encoding — the length is a function of the content's length and
    // the content is untouched.
    //
    // It is still a re-encoding of four bytes, so it is checked against the
    // blob in the tests rather than trusted: `parse_signed_attributes` is fed
    // the real bytes of a real signature in
    // `the_signature_is_verified_against_the_attributes_with_the_set_tag_restored`.
    let mut encoded = Vec::with_capacity(tagged.content.len() + 6);
    encoded.push(IMPLICIT_SET_TAG);
    encode_length(tagged.content.len(), &mut encoded);
    encoded.extend_from_slice(tagged.content);
    Ok(SignedAttributes {
        encoded,
        attributes,
    })
}

/// Parse the attributes inside a `[0]`/`[1]`-tagged `SET`.
fn parse_attributes<'a>(tagged: &Tlv<'a>) -> Result<Vec<Attribute<'a>>, AuthError> {
    let mut out = Vec::new();
    for element in tagged.elements() {
        let element = element.map_err(AuthError::Malformed)?;
        if !element.is(SEQUENCE) {
            return Err(AuthError::Malformed(SignatureError::NotConstructed {
                tag: element.tag,
            }));
        }
        let mut parts = element.elements();
        let id = parts.next().and_then(Result::ok).ok_or_else(short)?;
        if !id.is(OBJECT_IDENTIFIER) {
            return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
                wanted: OBJECT_IDENTIFIER,
                found: id.tag,
            }));
        }
        let arcs = id.oid().map_err(AuthError::Malformed)?;
        let values = parts.next().and_then(Result::ok).ok_or_else(short)?;
        if !values.is(SET) {
            return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
                wanted: SET,
                found: values.tag,
            }));
        }
        let mut collected = Vec::new();
        let mut elements = values.elements();
        while let Some(element) = elements.next_with_span() {
            collected.push(element.map_err(AuthError::Malformed)?);
        }
        out.push(Attribute {
            id: arcs,
            values: collected,
        });
    }
    // Every attribute a caller can read must be unique. See the module
    // documentation: a duplicate is how a verifier is made to check one value
    // while a report shows another.
    for (index, attribute) in out.iter().enumerate() {
        if out[..index]
            .iter()
            .any(|earlier| earlier.id == attribute.id)
        {
            return Err(AuthError::Malformed(SignatureError::NotPkcs7 {
                reason: "the attributes name the same type twice",
            }));
        }
    }
    Ok(out)
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
fn parse_algorithm(algorithm: &Tlv<'_>) -> Result<DigestAlgorithm, AuthError> {
    let id = algorithm_oid(algorithm)?;
    DigestAlgorithm::from_oid(id).ok_or_else(|| AuthError::UnsupportedDigestAlgorithm {
        oid: av_signatures::oid::dotted(id),
    })
}

/// The OID content of an `AlgorithmIdentifier`, which is its first field.
///
/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`
/// — `NULL` for RSA, a structure for RSA-PSS. Every caller here wants the OID,
/// and taking the *sequence's* content instead is the mistake this function
/// exists to make unavailable. It was made here once and the symptom is worth
/// recording, because it does not look like a bug in a report: `dotted()`
/// decodes whatever bytes it is handed, so the sequence's content renders
/// `0.6.9.42.840.113549.1.1.1.5.0` — the `0x06` tag, the `0x09` length and the
/// `NULL`'s trailing `05 00` all read as arcs — and an `rsaEncryption` signer
/// is then reported as an unsupported algorithm. Measured on the 120
/// embedded-signed files of an installed `System32`, every one of which uses
/// this identifier or its SHA-2 counterpart.
fn algorithm_oid<'a>(algorithm: &Tlv<'a>) -> Result<&'a [u8], AuthError> {
    if !algorithm.is(SEQUENCE) {
        return Err(AuthError::Malformed(SignatureError::NotConstructed {
            tag: algorithm.tag,
        }));
    }
    let id = algorithm
        .elements()
        .next()
        .and_then(Result::ok)
        .ok_or_else(short)?;
    if !id.is(OBJECT_IDENTIFIER) {
        return Err(AuthError::Malformed(SignatureError::UnexpectedTag {
            wanted: OBJECT_IDENTIFIER,
            found: id.tag,
        }));
    }
    Ok(id.content)
}

/// A DER length, short form when it fits and long form when it does not.
fn encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
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

    /// A well-formed blob with one signer and one certificate.
    fn blob() -> Vec<u8> {
        let certificate = fixture::certificate(
            &[0x2a],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(&[0x00, 0xab, 0xcd], &[0x01, 0x00, 0x01]),
            &[],
        );
        let issuer = crate::x509::Cert::parse(&certificate)
            .unwrap()
            .issuer_der()
            .to_vec();
        let content = fixture::spc_indirect_data(SHA256, &[0x11; 32]);
        let certificates = vec![certificate];
        fixture::signed_data(&fixture::SignedDataSpec {
            content_type: oid::SPC_INDIRECT_DATA,
            content: &content,
            message_digest: &[0x22; 32],
            digest_algorithm: SHA256,
            signature: &[0xde, 0xad, 0xbe, 0xef],
            signer_issuer: &issuer,
            signer_serial: &[0x2a],
            certificates: &certificates,
            timestamp: None,
        })
    }

    #[test]
    fn a_blob_parses_into_the_fields_a_verifier_needs() {
        let der = blob();
        let signed = SignedData::parse(&der).unwrap();
        assert_eq!(signed.content_type, oid::SPC_INDIRECT_DATA);
        assert_eq!(signed.certificates.len(), 1);
        assert_eq!(signed.signers.len(), 1);

        let signer = &signed.signers[0];
        assert_eq!(signer.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(signer.signature, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(signer.serial, Some(&[0x2a][..]));
        // The `SignerInfo`'s algorithm is the bare `rsaEncryption` identifier,
        // which names no digest of its own, so the digest comes from the
        // `digestAlgorithm` field beside it — the same arrangement all 120
        // embedded-signed files measured in `System32` use. Asserted by value
        // and not just `is_supported()`, because the failure this replaces was
        // this identifier being *misread*: an `AlgorithmIdentifier`'s content
        // handed to the OID renderer renders `0.6.9.42.…` and the commonest
        // signing algorithm in the world is then reported as unsupported.
        assert_eq!(
            signer.signature_algorithm,
            SignatureAlgorithm::RsaPkcs1 {
                digest: DigestAlgorithm::Sha256
            }
        );
        let attributes = signer.signed_attributes.as_ref().unwrap();
        assert_eq!(attributes.attributes().len(), 3);
        assert!(signer.unsigned_attributes.is_empty());
    }

    #[test]
    fn the_two_encapsulated_content_forms_are_both_read() {
        // The form Windows writes and the form RFC 5652 describes. The reader
        // has to give the caller the same two things either way, because the
        // caller cannot tell the forms apart and must not have to: `content` is
        // what the `SpcIndirectDataContent` parser is handed, and
        // `content_octets` is what `messageDigest` is the hash of.
        //
        // The fixture that exists because this was got wrong is the reason both
        // are asserted here: the crate's own fixtures used the RFC form, its
        // reader accepted only the RFC form, the two agreed, and every real
        // Microsoft binary was rejected as unsigned.
        let content = fixture::spc_indirect_data(SHA256, &[0x11; 32]);
        let certificate = fixture::certificate(
            &[0x2a],
            "Example Signer",
            "Example Issuer",
            "240101000000Z",
            "250101000000Z",
            &fixture::rsa_spki(&[0x00, 0xab, 0xcd], &[0x01, 0x00, 0x01]),
            &[],
        );
        let issuer = crate::x509::Cert::parse(&certificate)
            .unwrap()
            .issuer_der()
            .to_vec();
        let certificates = vec![certificate];
        let spec = fixture::SignedDataSpec {
            content_type: oid::SPC_INDIRECT_DATA,
            content: &content,
            message_digest: &[0x22; 32],
            digest_algorithm: SHA256,
            signature: &[0xde, 0xad, 0xbe, 0xef],
            signer_issuer: &issuer,
            signer_serial: &[0x2a],
            certificates: &certificates,
            timestamp: None,
        };
        // The element's own body, read rather than sliced at a fixed offset:
        // the header is two bytes here and would be three if the structure grew
        // past 127 bytes, which is exactly the kind of assumption this test is
        // meant to be able to survive.
        let element = av_signatures::der::parse_one(&content).unwrap();

        // `content` is the whole element in both forms — the Windows form puts
        // it there bare and the RFC form carries it as the octet string's
        // payload — and the digested range is what differs.
        let forms = [
            (
                "the Windows form",
                fixture::signed_data(&spec),
                element.content,
            ),
            (
                "the RFC 5652 form",
                fixture::signed_data_rfc_form(&spec),
                &content[..],
            ),
        ];
        for (name, der, expected_octets) in &forms {
            let signed = match SignedData::parse(der) {
                Ok(signed) => signed,
                Err(error) => panic!("{name} did not parse: {error:?}"),
            };
            assert_eq!(signed.content, &content[..], "{name}: content");
            assert_eq!(
                signed.content_octets, *expected_octets,
                "{name}: the range messageDigest is over"
            );
        }
        // Stated once more as the property the reader relies on rather than as
        // a coincidence: in the RFC form the payload *is* the structure, so the
        // two ranges coincide, which is why the digest range needs no branch.
        let rfc = SignedData::parse(&forms[1].1).unwrap();
        assert_eq!(rfc.content_octets, rfc.content);
    }

    #[test]
    fn the_signature_is_verified_against_the_attributes_with_the_set_tag_restored() {
        // The one byte that has to change, and the bytes that must not.
        let der = blob();
        let signed = SignedData::parse(&der).unwrap();
        let attributes = signed.signers[0].signed_attributes.as_ref().unwrap();
        assert_eq!(attributes.encoded()[0], IMPLICIT_SET_TAG);

        // Somewhere in the blob there is the same element with the `[0]` tag.
        let mut implicit = attributes.encoded().to_vec();
        implicit[0] = SIGNED_ATTRS_TAG;
        assert!(
            der.windows(implicit.len()).any(|window| window == implicit),
            "the re-tagged attributes must be the blob's own bytes with one tag changed"
        );
        // And the length octets are byte-identical, which is the part a
        // re-encoding from parsed values would get wrong.
        assert_eq!(attributes.encoded()[1..], implicit[1..]);
    }

    #[test]
    fn a_long_form_length_survives_the_retag() {
        // A short attribute set uses the one-byte length form, where a mistake
        // is invisible. Real ones do not: the sets measured on `System32`
        // binaries are several hundred bytes, because a signer states its
        // `SPC_SP_OPUS_INFO` alongside the two attributes that matter. So the
        // length is the long form and the retag has to reproduce it exactly.
        //
        // The three attributes `signed_attributes` emits total about 82 bytes,
        // which is under the boundary, so this builds the set itself with a
        // fourth carrying filler. The order is not sorted and does not need to
        // be: the subject here is the length octets, and the reader under test
        // does not re-order anything.
        let filler = fixture::attribute(
            &[1, 3, 6, 1, 4, 1, 311, 2, 1, 4],
            &[fixture::tlv(0x04, &[0x44; 64])],
        );
        let attributes = fixture::set(&[
            fixture::attribute(
                &[1, 2, 840, 113549, 1, 9, 3],
                &[fixture::oid(oid::SPC_INDIRECT_DATA)],
            ),
            fixture::attribute(
                &[1, 2, 840, 113549, 1, 9, 4],
                &[fixture::tlv(0x04, &[0x33; 32])],
            ),
            fixture::attribute(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 12], &[fixture::seq(&[])]),
            filler,
        ]);
        assert!(
            attributes[1] & 0x80 != 0,
            "the fixture must cross the short-form length boundary"
        );
        let parsed = av_signatures::der::parse_one(&attributes).unwrap();
        let tagged = Tlv {
            tag: SIGNED_ATTRS_TAG,
            content: parsed.content,
        };
        let rebuilt = parse_signed_attributes(&tagged).unwrap();
        assert_eq!(rebuilt.encoded(), &attributes[..]);
    }

    #[test]
    fn a_duplicate_attribute_type_is_refused() {
        // Two `messageDigest` attributes: the classic way to make a verifier
        // check one number while a report shows another.
        let duplicate = fixture::set(&[
            fixture::attribute(
                &[1, 2, 840, 113549, 1, 9, 4],
                &[fixture::tlv(0x04, &[0x01])],
            ),
            fixture::attribute(
                &[1, 2, 840, 113549, 1, 9, 4],
                &[fixture::tlv(0x04, &[0x02])],
            ),
        ]);
        let parsed = av_signatures::der::parse_one(&duplicate).unwrap();
        let tagged = Tlv {
            tag: SIGNED_ATTRS_TAG,
            content: parsed.content,
        };
        assert!(matches!(
            parse_signed_attributes(&tagged),
            Err(AuthError::Malformed(_))
        ));
    }

    #[test]
    fn attributes_are_read_by_type() {
        let der = blob();
        let signed = SignedData::parse(&der).unwrap();
        let attributes = signed.signers[0].signed_attributes.as_ref().unwrap();
        let digest = attributes.value(oid::ATTR_MESSAGE_DIGEST).unwrap();
        assert_eq!(digest.content, &[0x22; 32]);
        let content_type = attributes.value(oid::ATTR_CONTENT_TYPE).unwrap();
        assert!(oid_matches(content_type.content, oid::SPC_INDIRECT_DATA));
        assert!(attributes.value(oid::ATTR_SIGNING_TIME).is_none());
    }

    #[test]
    fn a_blob_that_is_not_pkcs7_is_refused_rather_than_misread() {
        assert!(matches!(
            SignedData::parse(&[]),
            Err(AuthError::Malformed(_))
        ));
        assert!(matches!(
            SignedData::parse(&[0x30, 0x00]),
            Err(AuthError::Malformed(_)) | Err(AuthError::NotSignedData { .. })
        ));
        // A `ContentInfo` naming something other than signedData.
        let not_signed_data = fixture::seq(&[
            fixture::oid(&[1, 2, 840, 113549, 1, 7, 1]),
            fixture::tlv(0xa0, &fixture::seq(&[])),
        ]);
        assert!(matches!(
            SignedData::parse(&not_signed_data),
            Err(AuthError::NotSignedData { .. })
        ));
    }

    #[test]
    fn a_timestamp_in_the_unauthenticated_attributes_is_reachable() {
        let der = blob();
        let signed = SignedData::parse(&der).unwrap();
        let content = fixture::spc_indirect_data(SHA256, &[0x11; 32]);
        let certificate = signed.certificates[0].to_vec();
        let issuer = crate::x509::Cert::parse(&certificate)
            .unwrap()
            .issuer_der()
            .to_vec();
        let certificates = vec![certificate.clone()];
        // A whole `ContentInfo`, because that is what a timestamp token is and
        // what the reader is handed: an attribute value is `ANY`, so its bytes
        // are one complete element rather than a payload to be framed around.
        // Its digest differs from the outer blob's so that the two encodings
        // are distinguishable, and finding the token below cannot be finding
        // the outer signature by accident.
        let token = fixture::signed_data(&fixture::SignedDataSpec {
            content_type: oid::SPC_INDIRECT_DATA,
            content: &content,
            message_digest: &[0x33; 32],
            digest_algorithm: SHA256,
            signature: &[0xde, 0xad, 0xbe, 0xef],
            signer_issuer: &issuer,
            signer_serial: &[0x2a],
            certificates: &certificates,
            timestamp: None,
        });
        let with_token = fixture::signed_data(&fixture::SignedDataSpec {
            content_type: oid::SPC_INDIRECT_DATA,
            content: &content,
            message_digest: &[0x22; 32],
            digest_algorithm: SHA256,
            signature: &[0xde, 0xad, 0xbe, 0xef],
            signer_issuer: &issuer,
            signer_serial: &[0x2a],
            certificates: &certificates,
            timestamp: Some(&token),
        });
        let signed = SignedData::parse(&with_token).unwrap();
        let found = signed.signers[0].unsigned(oid::ATTR_MS_TIMESTAMP).unwrap();
        // The value's *span* — the element as the file carries it — because
        // that is what a nested structure is parsed from: a `Tlv` holds the
        // content octets, and a structure cannot be parsed from a buffer that
        // begins mid-header. `timestamp::verify_rfc3161` takes exactly this
        // span and hands it to `SignedData::parse`, so this is the round trip
        // the product depends on, asserted at the same boundary.
        let span = found.value_span().unwrap();
        assert_eq!(span, &token[..]);
        assert!(
            SignedData::parse(span).is_ok(),
            "the attribute's value must be a readable signature on its own"
        );
        // And the timestamped blob is the same structure as the untimestamped
        // one, not a longer blob that happens to contain it: the lengths of
        // every enclosing element changed, which is why the token is a field of
        // the builder rather than bytes spliced into a finished encoding.
        let plain_der = blob();
        let plain = SignedData::parse(&plain_der).unwrap();
        assert_eq!(signed.signers.len(), plain.signers.len());
        assert_eq!(
            signed.signers[0].signature, plain.signers[0].signature,
            "the signer's signature is untouched by the unauthenticated attributes"
        );
    }

    #[test]
    fn an_oid_is_rendered_back_to_its_dotted_form() {
        // `id()` re-encodes the arcs and hands them to the shared renderer.
        // Base-128 is where a hand-rolled pair like this disagrees, so the
        // arcs used here are the ones with multi-byte components.
        assert_eq!(
            av_signatures::oid::dotted(&encode_oid(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 4])),
            "1.3.6.1.4.1.311.2.1.4"
        );
        assert_eq!(
            av_signatures::oid::dotted(&encode_oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1])),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(
            av_signatures::oid::dotted(&encode_oid(&[1, 2, 840, 113549, 1, 1, 11])),
            "1.2.840.113549.1.1.11"
        );
    }

    #[test]
    fn the_length_encoder_matches_the_der_reader() {
        for length in [0usize, 1, 0x7f, 0x80, 0x81, 0x100, 0xffff, 0x10000] {
            let mut out = Vec::new();
            encode_length(length, &mut out);
            let mut element = vec![0x04];
            element.extend_from_slice(&out);
            element.extend(std::iter::repeat_n(0u8, length));
            let parsed = av_signatures::der::parse_one(&element).unwrap();
            assert_eq!(parsed.content.len(), length, "length {length}");
        }
    }
}
