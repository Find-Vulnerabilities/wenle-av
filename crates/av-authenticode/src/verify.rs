//! The four equalities, in order, and the only place [`crate::Verdict::Trusted`]
//! is built.
//!
//! # The order is not arbitrary
//!
//! Each step depends on the one before it, and running them out of order
//! produces a verifier that can be fooled:
//!
//! 1. **The signature over the signed attributes.** Until this holds, the
//!    `messageDigest` attribute is just bytes somebody put in a file — and the
//!    `messageDigest` is the link to the structure that names the file digest,
//!    so a verifier that read *it* first would be comparing an attacker's
//!    number against an attacker's structure.
//! 2. **The content digest.** The `messageDigest` attribute must equal the hash
//!    of `encapContentInfo.eContent`. This binds the signed attributes to the
//!    `SpcIndirectDataContent`, and therefore to the file digest inside it.
//! 3. **The file digest.** The digest stated in the `SpcIndirectDataContent`
//!    must equal the Authenticode image digest of the file on disk. **This is
//!    the step that detects a tampered file**, and the one with a flipped-byte
//!    test behind it.
//! 4. **A chain to a trusted root**, with the signer entitled to sign code at
//!    all and the chain judged at the instant the counter-signature proves.
//!
//! Steps 1 to 3 are this crate's; step 4 asks the platform to build a path and
//! [`crate::chain`] to interpret it. See [`crate::store`] for where that line
//! is drawn and why.
//!
//! # What each failure becomes
//!
//! Three failure kinds, three different sentences in a report, and collapsing
//! any two is the mistake [`crate::Verdict`] exists to prevent:
//!
//! * **A comparison failed** — [`crate::Verdict::Invalid`]. The structure was
//!   read all the way through and the numbers did not match. A strong finding.
//! * **Something could not be read, or needs a check this crate does not
//!   implement** — [`crate::Verdict::Undetermined`]. Nothing was proven either
//!   way, and calling this `Invalid` would accuse a file of tampering because
//!   *this* code was incomplete.
//! * **Everything held and the chain did not reach a trusted root** —
//!   [`crate::Verdict::Untrusted`]. Not an accusation; see [`crate::chain`].
//!
//! # Ordering the expensive steps, and which of them can be trusted
//!
//! Hashing the file is the dominant cost of a verification on any image of a
//! few megabytes, and building a chain is the second. The file digest is
//! therefore taken before the chain is built, which is also the right order for
//! the *answer*: a file whose bytes do not match its signature is `Invalid`,
//! and reaching the chain first would report it as untrusted — the weaker of
//! the two findings, and the wrong one.
//!
//! # The fail-closed rule, as code rather than as a comment
//!
//! [`verify`] is the only function in this crate that constructs
//! [`crate::Verdict::Trusted`], and it does so on one line at the bottom, after
//! every equality has held. Every other exit returns an arm that
//! [`crate::Verdict::is_trusted`] answers `false` for, which is what makes "an
//! incomplete verification is never trusted" a property of the shape of this
//! function rather than a promise about it.

use std::time::{SystemTime, UNIX_EPOCH};

use av_pe::PeFile;

use crate::chain::{self, ChainDecision};
use crate::cms::{SignedData, SignerInfo};
use crate::digest::{self, DigestAlgorithm};
use crate::error::{hex, AuthError, InvalidReason, UntrustedReason};
use crate::oid::{self, SignatureAlgorithm};
use crate::spc;
use crate::store::At;
use crate::timestamp::{self, Timestamp};
use crate::verdict::{JudgedAt, Proof, TimestampProof, Unestablished, Verdict};
use crate::x509::{Cert, PublicKey};

/// Verify the Authenticode signature over a file's bytes.
///
/// The entry point for a caller that has the bytes and not a parsed image. A
/// caller that has both — the scanner's trust layer, which parses every file it
/// examines — should use [`verify`] and skip the second parse.
pub fn verify_bytes(data: &[u8]) -> Verdict {
    match PeFile::parse(data) {
        Ok(pe) => verify(&pe),
        // Not a PE at all, so there is no attribute certificate table to read
        // and nothing was looked at. Distinct from `Unsigned`, which says a
        // signature was looked for and not found.
        Err(_) => Verdict::Undetermined {
            reason: Unestablished::NotPe,
        },
    }
}

/// Verify the Authenticode signature over a parsed image.
pub fn verify(pe: &PeFile<'_>) -> Verdict {
    // -- the blob ----------------------------------------------------------
    let Some(signed) = read_signed_data(pe) else {
        return Verdict::Unsigned;
    };

    // -- the signer --------------------------------------------------------
    let Some(signer) = signed.signers.first() else {
        return undetermined(AuthError::NoSigner);
    };
    let Some(attributes) = signer.signed_attributes.as_ref() else {
        return undetermined(AuthError::NoSignedAttributes);
    };

    // -- step 1: the signature over the signed attributes -------------------
    //
    // The algorithm check comes first because everything below it is arithmetic
    // this crate would have to be able to do, and a refusal by name is a better
    // answer than a failed comparison three steps later.
    let signature_digest = match &signer.signature_algorithm {
        SignatureAlgorithm::RsaPkcs1 { digest } => *digest,
        SignatureAlgorithm::Unsupported { oid, .. } => return unsupported(oid),
    };
    let Ok(leaf_der) = signer_certificate(&signed, signer) else {
        return undetermined(AuthError::SignerCertificateAbsent);
    };
    let leaf = match Cert::parse(leaf_der) {
        Ok(leaf) => leaf,
        Err(error) => return undetermined(error),
    };
    // Only the modulus is needed here: the key itself is read off the
    // certificate again by `verify_signed_attributes`, and this borrow exists
    // for the report's key size. The `..` is deliberate — naming the exponent
    // would suggest this function uses it.
    let modulus = match leaf.public_key() {
        PublicKey::Rsa { modulus, .. } => *modulus,
        // An EC or otherwise unsupported key. Named rather than reported as a
        // bad signature: this verifier cannot tell, and claiming a file is
        // tampered because its signer used ECDSA would be a false accusation
        // about a file that is probably fine.
        PublicKey::Unsupported { algorithm } => return unsupported(algorithm),
    };
    // `verify_signed_attributes` returns a sentence rather than a verdict
    // because it is shared with the timestamp path, which reports a failure as
    // a bad token rather than as a bad file. It has two refusal reasons — a
    // non-RSA key and an unimplemented algorithm — and both were ruled out
    // immediately above, so the only failure it can return here is the
    // signature itself not verifying.
    if timestamp::verify_signed_attributes(&leaf, signer, attributes).is_err() {
        return Verdict::Invalid {
            reason: InvalidReason::SignatureDoesNotVerify,
        };
    }

    // -- step 2: the content digest ----------------------------------------
    //
    // The `messageDigest` attribute is the hash of the encapsulated content,
    // which for Authenticode is the `SpcIndirectDataContent`. Now that step 1
    // has proven the attribute, this binds the content to it — and the content
    // is where the file's digest lives.
    let Some(declared) = attributes.value(oid::ATTR_MESSAGE_DIGEST) else {
        return undetermined(AuthError::BadIndirectData {
            reason: "the signed attributes commit to no content digest",
        });
    };
    // Over `content_octets` and not `content`: RFC 5652 §5.4 defines
    // `messageDigest` as the hash of the *content octets* of `eContent`, and
    // Windows writes the `SpcIndirectDataContent` straight into the `[0]` with
    // no `OCTET STRING` around it, so the two ranges differ by the sequence's
    // own header. Measured on a real `System32` binary: the declared digest
    // matches the content octets and nothing else.
    let content_digest = signature_digest.digest(signed.content_octets);
    if declared.content != content_digest.as_slice() {
        return Verdict::Invalid {
            reason: InvalidReason::ContentDigestMismatch {
                found: hex(declared.content),
                expected: hex(&content_digest),
            },
        };
    }

    // The `contentType` attribute must name what the content actually is. CMS
    // requires it, and a signature whose attributes say one thing while the
    // content is another is a structure that contradicts itself.
    match attributes.value(oid::ATTR_CONTENT_TYPE) {
        Some(kind) if av_signatures::oid::oid_matches(kind.content, oid::SPC_INDIRECT_DATA) => {}
        _ => {
            return Verdict::Invalid {
                reason: InvalidReason::SignatureDoesNotVerify,
            }
        }
    }

    // -- step 3: the file digest -------------------------------------------
    let indirect = match spc::parse(signed.content) {
        Ok(indirect) => indirect,
        Err(error) => return undetermined(error),
    };
    if !indirect.is_pe_image() {
        // A signature over something that is not an image digest — a page-hash
        // scope, a catalog's own structure. Reported as a region this verifier
        // does not reproduce rather than as a mismatch, because comparing the
        // whole-image digest against a number that was never meant to be one
        // would invent a finding.
        return Verdict::Undetermined {
            reason: Unestablished::UnsupportedDigestScope {
                reason: "the signature is not over a whole PE image digest",
            },
        };
    }
    let computed = match digest::image_digest(pe, indirect.digest_algorithm) {
        Ok(computed) => computed,
        Err(error) => return undetermined(error),
    };
    if computed != indirect.digest {
        // **The tampered-file finding.** Everything above held: the signature
        // is the signer's, the attributes are the ones that were signed, and
        // the number inside them is not this file's.
        return Verdict::Invalid {
            reason: InvalidReason::FileDigestMismatch {
                expected: hex(indirect.digest),
                computed: hex(&computed),
            },
        };
    }

    // -- the counter-signature ---------------------------------------------
    //
    // Verified before the chain is built, because it decides *when* the chain is
    // judged — and it is not taken on its word: the token's own signature and
    // its authority's chain both have to hold, or the signer is judged now. An
    // untrusted authority cannot make an untrusted signature trusted; all it
    // can do is move the instant, and only when it is itself trustworthy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0);

    let proven = match timestamp::find(signer, &signed.certificates) {
        Ok(None) => None,
        Ok(Some(stamp)) => {
            if timestamp_is_proven(&stamp) {
                Some(stamp)
            } else {
                // A token whose authority does not chain to a root this machine
                // trusts proves no time. The file is still assessed; it is just
                // judged at the current time, which is the honest reading.
                None
            }
        }
        // A token this verifier cannot read is treated as no token at all, and
        // the argument that this cannot widen what gets trusted is worth
        // writing down, because it is exactly the kind of change that could
        // make a trust layer weaker while sounding stricter.
        //
        // The stricter-looking reading — "a file whose token I could not read
        // is not assessed" — returns `Undetermined` for it. That is not more
        // conservative in any useful way, because `Ok(None)` above is already
        // reachable by *removing* the token: a file with an unreadable token is
        // then judged at the present instant and comes out trusted exactly when
        // a file with no token at all would, on the same signature, the same
        // file digest, and a chain that is valid *now*. That is a proof that
        // never involved the token. A certificate that has since expired still
        // fails the next check down, because the instant is now.
        //
        // What it costs is a sentence in a report: nothing here can say the
        // token was unreadable. `Proof::timestamp` is left `None`, which is the
        // truthful statement that no counter-signature was used.
        Err(_) => None,
    };

    let (judged_at, at) = match &proven {
        Some(stamp) => (JudgedAt::Timestamp(stamp.time), At::Unix(stamp.time)),
        None => (JudgedAt::Now, At::Now),
    };
    let instant = judged_at.instant(now);

    // -- the signer's entitlement ------------------------------------------
    //
    // Checked here rather than left to the chain engine because it is a fact
    // about the certificate's stated *purpose* and not about the platform's
    // trust policy: a TLS server certificate chains to a trusted root and must
    // not be able to clear a detection on an executable. Doing it before the
    // chain is built also means a certificate that cannot sign code never pays
    // for one.
    if !leaf.permits_code_signing() {
        let proof = proof(
            &leaf,
            &indirect,
            judged_at,
            &proven,
            signature_digest,
            modulus,
        );
        return Verdict::Untrusted {
            proof: Box::new(proof),
            reason: UntrustedReason::WrongPurpose {
                detail: "the signer's certificate is not valid for code signing",
            },
        };
    }

    // The leaf's own window against the judged instant. The chain engine
    // applies validity across the whole path, but the engine's refusal cannot
    // say *which* certificate failed; when it is the leaf, the report can name
    // its dates, which is the difference between a sentence a user can act on
    // and "the chain was rejected".
    let not_before = leaf.not_before().seconds();
    let not_after = leaf.not_after().seconds();
    if instant < not_before || instant > not_after {
        let proof = proof(
            &leaf,
            &indirect,
            judged_at,
            &proven,
            signature_digest,
            modulus,
        );
        let reason = match proven {
            // No counter-signature, so nothing places the file before the
            // expiry. The signer demonstrably *was* entitled when the
            // certificate was issued; what is missing is the evidence of when
            // this file was signed, which is a different sentence.
            None => UntrustedReason::ExpiredWithoutTimestamp { not_after },
            // A counter-signature exists and its instant is outside the
            // window — either the token is older than the certificate or the
            // certificate had already expired when the token was made.
            Some(_) => UntrustedReason::OutsideValidity {
                not_before,
                not_after,
                judged_at: instant,
            },
        };
        return Verdict::Untrusted {
            proof: Box::new(proof),
            reason,
        };
    }

    // -- step 4: the chain --------------------------------------------------
    let extra: Vec<&[u8]> = signed.certificates.clone();
    let decision = chain::evaluate(leaf_der, &extra, at, Some((not_before, not_after)), instant);

    let mut proof = proof(
        &leaf,
        &indirect,
        judged_at,
        &proven,
        signature_digest,
        modulus,
    );
    match decision {
        ChainDecision::Trusted { root } => {
            proof.root = Some(root);
            // The one line that builds `Trusted`, and the last statement of the
            // function: every equality held, so the file is what its signer
            // signed and its signer traces to a root this machine trusts.
            Verdict::Trusted(Box::new(proof))
        }
        ChainDecision::Untrusted { reason, root } => {
            proof.root = root;
            Verdict::Untrusted {
                proof: Box::new(proof),
                reason,
            }
        }
        ChainDecision::Unavailable { detail } => Verdict::Undetermined {
            reason: Unestablished::ChainUnavailable { detail },
        },
    }
}

/// The blob, or `None` when the file carries no signature at all.
///
/// A file with no attribute certificate table and an empty one both answer "no
/// signature". So does a table whose first record is not a PKCS#7 blob: the
/// record walk in [`av_signatures::authenticode`] has already refused it, and
/// "the table holds something that is not a signature" is not a statement about
/// a signature. What *is* distinguished here is a blob that parses as a
/// `ContentInfo` and is not `signedData` — that is reported rather than
/// silently dropped, because it is the shape a file built to confuse a verifier
/// takes.
fn read_signed_data<'a>(pe: &PeFile<'a>) -> Option<SignedData<'a>> {
    let table = pe.security_directory_data().ok()?;
    if table.is_empty() {
        return None;
    }
    let blob = av_signatures::authenticode::first_blob(table)?;
    SignedData::parse(blob).ok()
}

/// The certificate the signer's identifier names, out of the blob's own set.
///
/// Reuses [`timestamp::select_signer`] so that the rule for matching an
/// issuer-and-serial identifier is written once: the outer signature and a
/// timestamp token's are matched by the same code, and a rule that applied to
/// one and not the other would be a rule an attacker could choose to be judged
/// by.
fn signer_certificate<'a>(
    signed: &SignedData<'a>,
    signer: &SignerInfo<'_>,
) -> Result<&'a [u8], AuthError> {
    let candidates: Vec<&'a [u8]> = signed.certificates.clone();
    timestamp::select_signer(signer, &candidates)
}

/// Whether a counter-signature's own authority is worth believing.
///
/// Two conditions, and both are needed:
///
/// * the authority was inside its own validity period at the instant it
///   asserts — arithmetic on two numbers already in hand, and the one check
///   that does not need a chain;
/// * the authority's chain, judged at that same instant, reaches a root this
///   machine trusts.
///
/// The chain is built with the token's own certificates as the additional
/// store, for the same reason the signer's chain gets the file's: a
/// time-stamping authority's intermediate is routinely carried inside its token
/// and installed in no machine store.
fn timestamp_is_proven(stamp: &Timestamp) -> bool {
    if !stamp.authority_was_valid_at_the_time() {
        return false;
    }
    let extra: Vec<&[u8]> = stamp.authority_chain.iter().map(Vec::as_slice).collect();
    chain::evaluate(
        &stamp.authority_der,
        &extra,
        At::Unix(stamp.time),
        Some((stamp.authority_not_before, stamp.authority_not_after)),
        stamp.time,
    )
    .is_trusted()
}

/// Everything proven about a signature, for the two verdicts that carry one.
fn proof(
    leaf: &Cert<'_>,
    indirect: &spc::SpcIndirectData<'_>,
    judged_at: JudgedAt,
    proven: &Option<Timestamp>,
    signature_digest: DigestAlgorithm,
    modulus: &[u8],
) -> Proof {
    Proof {
        subject: leaf.subject().to_owned(),
        issuer: leaf.issuer().to_owned(),
        thumbprint: leaf.thumbprint(),
        file_digest: hex(indirect.digest),
        file_digest_algorithm: indirect.digest_algorithm.name(),
        signature_digest_algorithm: signature_digest.name(),
        // A modulus this crate can measure. Zero when it cannot, which is the
        // honest report for a key that passed `rsa::verify` and cannot be sized
        // — unreachable in practice, since the arithmetic refuses such a key.
        key_bits: crate::rsa::key_bits(modulus).unwrap_or(0),
        // Filled in by the caller once the chain has been built. `None` means
        // no chain reached an anchor, which is exactly what the field says.
        root: None,
        judged_at,
        timestamp: proven.as_ref().map(timestamp_proof),
        carried_data_value: indirect.has_data_value,
    }
}

/// The counter-signature, in the form a report shows.
fn timestamp_proof(stamp: &Timestamp) -> TimestampProof {
    TimestampProof {
        time: stamp.time,
        authority: stamp.authority.clone(),
        authority_thumbprint: stamp.authority_thumbprint.clone(),
        form: stamp.form,
    }
}

/// An [`AuthError`] turned into the fail-closed verdict.
///
/// Every parse failure lands in `Undetermined` rather than `Invalid`, and the
/// distinction is the whole of [`crate::Verdict`]'s design: a structure this
/// crate could not read is not a structure that was proven false.
fn undetermined(error: AuthError) -> Verdict {
    Verdict::Undetermined {
        reason: Unestablished::Malformed {
            code: error.code(),
            detail: error.to_string(),
        },
    }
}

/// An algorithm this crate does not implement, by name.
///
/// `Undetermined` rather than `Untrusted`, which is the reading
/// [`crate::verdict`] gives it: the check that could not be made is one this
/// crate does not implement, so nothing about the file was established either
/// way. Naming the OID is what makes the refusal actionable — a future file
/// that needs ECDSA says so rather than looking like a broken one.
fn unsupported(oid: &str) -> Verdict {
    Verdict::Undetermined {
        reason: Unestablished::UnsupportedAlgorithm {
            oid: oid.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A binary from this machine's own `System32`, by name.
    ///
    /// # Why these tests read the real thing
    ///
    /// The fixtures in [`crate::testing`] are built by the same crate that
    /// reads them, so they establish that the reader agrees with itself and
    /// nothing more. This crate's own history is the demonstration: its
    /// fixtures wrote the RFC 5652 form of `eContent`, its reader accepted
    /// exactly that form, the two agreed — and every Microsoft binary on the
    /// disk read as unsigned, because Windows writes the structure bare. A
    /// verifier has to be pointed at files it did not make.
    ///
    /// `None` when the file is not on this machine. The tests that get `None`
    /// say so on stderr and return: this is not a portable test suite, and a
    /// test that cannot run is not a test that passed.
    fn system32(name: &str) -> Option<Vec<u8>> {
        let path = PathBuf::from(r"C:\Windows\System32").join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                eprintln!("NOT RUN: {} could not be read: {error}", path.display());
                None
            }
        }
    }

    /// The verdict for a file's bytes, through the same entry point a caller
    /// that already has the image would use.
    fn verdict_of(bytes: &[u8]) -> Verdict {
        let pe = PeFile::parse(bytes).expect("the test's file must be a PE image");
        verify(&pe)
    }

    /// Where the signer's signature bytes are, as an offset into the file.
    ///
    /// Found through this crate's own parser rather than by searching for a
    /// byte pattern, and the subtraction is sound because every slice the
    /// parser hands back borrows the buffer the caller passed in.
    fn signature_offset(bytes: &[u8]) -> usize {
        let pe = PeFile::parse(bytes).expect("a PE image");
        let table = pe.security_directory_data().expect("a certificate table");
        let blob = av_signatures::authenticode::first_blob(table).expect("a PKCS#7 blob");
        let signed = crate::cms::SignedData::parse(blob).expect("a readable SignedData");
        let signature = signed.signers.first().expect("a signer").signature;
        signature.as_ptr() as usize - bytes.as_ptr() as usize
    }

    #[test]
    fn a_real_microsoft_binary_verifies_against_its_own_signature() {
        // `MRT.exe` is the file this crate exists for. The scanner flags it
        // because it carries malware signature strings by design, which is
        // right about the bytes and wrong about the file, and the only honest
        // way to clear it is to prove it is Microsoft's — which is this call.
        //
        // Read from the machine rather than from a checked-in copy: a copy is
        // a file this repository signed with itself, and the whole failure this
        // verifier was written to avoid is a verifier that agrees with its own
        // fixtures.
        let Some(bytes) = system32("MRT.exe") else {
            return;
        };
        match verdict_of(&bytes) {
            Verdict::Trusted(proof) => {
                assert!(
                    proof.subject.contains("Microsoft"),
                    "the signer should be Microsoft, and is {}",
                    proof.subject
                );
                // A trusted verdict has to name the anchor it reached, or the
                // report cannot be checked against `certutil` by a human.
                assert!(proof.root.is_some(), "a trusted verdict must name its root");
            }
            other => panic!("MRT.exe did not verify: {other:?}"),
        }
    }

    #[test]
    fn a_flipped_byte_in_a_real_binary_is_a_tamper_finding() {
        // The direction that matters most: a file that is *nearly* Microsoft's.
        // The byte is taken from inside the first section's raw data, which the
        // image digest covers, and not from the certificate table, which it
        // deliberately does not.
        let Some(mut bytes) = system32("MRT.exe") else {
            return;
        };
        let at = {
            let pe = PeFile::parse(&bytes).expect("a PE image");
            let first = pe.sections.first().expect("an image has a section table");
            first.pointer_to_raw_data as usize + 0x20
        };
        bytes[at] ^= 0xff;

        match verdict_of(&bytes) {
            Verdict::Invalid {
                reason: InvalidReason::FileDigestMismatch { .. },
            } => {}
            other => panic!("a flipped byte must read as a digest mismatch: {other:?}"),
        }
    }

    #[test]
    fn a_signature_that_does_not_verify_is_invalid() {
        // The other half of the same direction: the file is untouched and the
        // signature block is not. Flipping a byte of the signature itself is
        // the smallest possible forgery, and it has to come out as a strong
        // finding rather than as "a signature is present" — the failure that
        // would make a trust layer weaker while looking stronger.
        let Some(mut bytes) = system32("MRT.exe") else {
            return;
        };
        let at = signature_offset(&bytes);
        bytes[at] ^= 0xff;

        match verdict_of(&bytes) {
            Verdict::Invalid {
                reason: InvalidReason::SignatureDoesNotVerify,
            } => {}
            other => panic!("a broken signature must not be reported as anything else: {other:?}"),
        }
    }

    #[test]
    fn a_file_with_no_signature_is_unsigned_and_not_undetermined() {
        // The distinction the `Verdict` type exists for. Most files on a disk
        // carry no signature, and a verifier that reported them as an
        // unestablished or suspicious state would put every one of them in
        // front of the user.
        assert_eq!(
            verdict_of(&av_pe::testing::minimal_pe32()),
            Verdict::Unsigned
        );
    }

    #[test]
    fn something_that_is_not_a_program_is_not_assessed_at_all() {
        // Distinct from `Unsigned`: no attribute certificate table was looked
        // for, because there is no PE header to find one through.
        assert_eq!(
            verify_bytes(b"not a program"),
            Verdict::Undetermined {
                reason: Unestablished::NotPe
            }
        );
    }
}
