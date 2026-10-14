//! The answer, in a shape where the cases cannot be confused.
//!
//! # The five states, and why five
//!
//! | state | means | a caller may |
//! |---|---|---|
//! | [`Verdict::Trusted`] | every equality held, and the chain reached a root this machine trusts | let it clear a detection |
//! | [`Verdict::Untrusted`] | every equality held, and the chain did not | treat it as a weak signal |
//! | [`Verdict::Invalid`] | the structure was read all the way through and a comparison failed | treat it as a strong finding |
//! | [`Verdict::Unsigned`] | the file carries no signature at all | treat it as no signal |
//! | [`Verdict::Undetermined`] | something could not be read, or a check this crate does not implement was needed | treat it as no signal, and say why |
//!
//! The distinction that earns its keep is the last one. It is tempting to fold
//! "the signature is over a digest scope I do not reproduce" into [`InvalidReason`],
//! and that would be a false accusation: the file may be perfectly signed and
//! this verifier simply cannot say. It is equally tempting to fold it into
//! [`UntrustedReason`], and that would be a *missed* accusation — a file that does
//! not verify is a much stronger signal than a file signed by an unknown CA,
//! and a scanner that treated the two alike would either discard detections on
//! self-signed malware or accuse Microsoft of tampering.
//!
//! # Fail closed, and it is a test
//!
//! The rule is: **anything not positively verified lands in
//! [`Verdict::Undetermined`] and never in [`Verdict::Trusted`].** It is
//! expressed by construction rather than by a comment —
//! [`Verdict::is_trusted`] is the only predicate that clears a detection, and
//! [`Verdict::Trusted`] is only ever built by
//! [`crate::verify::verify_bytes`] after every equality has held. The test that
//! enforces it is
//! `an_incomplete_verification_is_never_trusted`, which walks every error
//! variant and every partial result and asserts none of them is trusted.
//!
//! # Why `Trusted` carries a proof and `Undetermined` carries a reason
//!
//! A verdict a user acts on has to be defensible. "This file is signed by
//! Microsoft" is a claim that a person will repeat, so what it rests on is
//! carried alongside it: the subject, the thumbprint, the digest that was
//! checked, the root the chain reached, and the time the chain was judged at.
//! The undetermined case carries the opposite — the specific thing that could
//! not be established — because a report that says only "could not determine"
//! is a report nobody can act on.

// Re-exported rather than imported privately, because these two are part of the
// answer this module curates: a caller matching on a `Verdict` cannot read the
// reason it carries without naming the type, and making it reach into
// [`crate::error`] for it would put half the answer in one module and half in
// another.
pub use crate::error::{InvalidReason, UntrustedReason};

/// What was proven, in enough detail to be checked by a person.
///
/// Carried by [`Verdict::Trusted`] and [`Verdict::Untrusted`] — the two states
/// where a signature was read and verified. The fields are the ones a person
/// compares against `signtool` or `certutil` output, which is the only
/// independent check a user has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The signer's subject, rendered the way [`av_signatures`] renders one.
    pub subject: String,
    /// The signer's issuer, rendered the same way.
    pub issuer: String,
    /// The signer's certificate thumbprint, SHA-1, lower case hex, no
    /// separators — the form a thumbprint is compared in.
    pub thumbprint: String,
    /// The digest the signature committed to, hex: the value the file was
    /// checked against.
    pub file_digest: String,
    /// The algorithm that digest was taken with.
    pub file_digest_algorithm: &'static str,
    /// The signature's own digest algorithm.
    pub signature_digest_algorithm: &'static str,
    /// The key size, in bits, of the signer's public key.
    pub key_bits: usize,
    /// The root the chain reached, rendered. Only present when the chain
    /// reached one.
    pub root: Option<String>,
    /// The instant the signer's chain was judged at, and what set it.
    pub judged_at: JudgedAt,
    /// The counter-signature, if the file has one that verified.
    pub timestamp: Option<TimestampProof>,
    /// Whether the certificate table's `SpcIndirectDataContent` carried the
    /// optional `data` value, which is where page hashes live.
    ///
    /// Recorded and not acted on: the file digest is taken over the whole image
    /// whether it is present or not. See [`crate::spc`].
    pub carried_data_value: bool,
}

/// A counter-signature that verified, in the form a report shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampProof {
    /// The asserted time, in Unix seconds.
    pub time: i64,
    /// The authority's subject.
    pub authority: String,
    /// The authority's thumbprint, SHA-1, hex.
    pub authority_thumbprint: String,
    /// Which of the two forms.
    pub form: crate::timestamp::TimestampForm,
}

/// What set the instant the chain was judged at.
///
/// This is the field that decides whether a third of `System32` reads as
/// expired, so it is named rather than left implicit in a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JudgedAt {
    /// Now, because no counter-signature proved a time. Three cases reach it:
    /// the file carries no token, the token it carries did not verify, or the
    /// token could not be read at all.
    ///
    /// [`Proof::timestamp`] is `None` in all three, so it records that no
    /// counter-signature was *used* and not whether one was present. A report
    /// therefore cannot tell an unreadable token from an absent one — the price
    /// of judging the file at the present instant instead of refusing to assess
    /// it, argued at the `Err(_)` arm of [`crate::verify()`].
    Now,
    /// The counter-signature's time, because it verified.
    Timestamp(i64),
    /// The moment the caller asked for, for a scan that has to be reproducible
    /// rather than to agree with the clock.
    Requested(i64),
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every equality held and the chain reached a trusted root.
    ///
    /// The only verdict that may clear a detection, and the only one a caller
    /// should treat as evidence that a file is what it claims to be.
    Trusted(Box<Proof>),

    /// The signature verified, and the chain did not reach a trusted root.
    ///
    /// Not an accusation. An in-house build signed with an internal CA lands
    /// here, and so does a file signed by a CA outside the Windows root
    /// programme. The correct treatment is "no trust signal".
    Untrusted {
        /// What was proven about the signature.
        proof: Box<Proof>,
        /// Why it is nevertheless not trusted.
        reason: UntrustedReason,
    },

    /// The structure was read all the way through and a comparison failed.
    ///
    /// A strong finding. Either the file was altered after signing or the
    /// signature block was, and both are things a scanner should say out loud.
    Invalid {
        /// Which comparison failed.
        reason: InvalidReason,
    },

    /// The file carries no signature at all.
    ///
    /// Distinct from every failure above, and distinct on purpose: "no
    /// signature" is the normal state of most files on a disk, and a caller
    /// that confused it with "a signature that failed" would flag every
    /// unsigned program.
    Unsigned,

    /// The file could not be assessed, for the stated reason.
    ///
    /// The fail-closed state. Anything that is not positively verified — a
    /// structure that would not parse, an algorithm this crate does not
    /// implement, a digest scope it does not reproduce, a chain engine that
    /// returned something it cannot classify — lands here, and never in
    /// [`Verdict::Trusted`].
    Undetermined {
        /// What could not be established.
        reason: Unestablished,
    },
}

/// What a verifier could not establish.
///
/// A separate type from [`crate::error::AuthError`] because it is a
/// *conclusion*, not a failure of this code: the caller is being told that the
/// file cannot be assessed, which is an answer, and the answer has to be usable
/// without matching on parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unestablished {
    /// The file is not a PE file, so there is nothing to verify.
    NotPe,
    /// The certificate table could not be read or the structure in it is
    /// malformed.
    Malformed {
        /// The error's own label, from [`crate::AuthError::code`].
        code: &'static str,
        /// A human-readable explanation.
        detail: String,
    },
    /// The signature uses an algorithm this crate does not implement.
    UnsupportedAlgorithm {
        /// The algorithm's OID, dotted.
        oid: String,
    },
    /// The digest is stated over a region this crate does not reproduce.
    UnsupportedDigestScope {
        /// Which form was found.
        reason: &'static str,
    },
    /// A counter-signature was present and did not verify.
    BadTimestamp {
        /// Why it did not hold up.
        detail: String,
    },
    /// The chain engine could not be asked, or answered something this crate
    /// cannot classify.
    ChainUnavailable {
        /// The platform's status, or the reason the call failed.
        detail: String,
    },
}

impl Unestablished {
    /// A short label for logs and reports.
    pub fn code(&self) -> &'static str {
        match self {
            Unestablished::NotPe => "not-pe",
            Unestablished::Malformed { code, .. } => code,
            Unestablished::UnsupportedAlgorithm { .. } => "unsupported-algorithm",
            Unestablished::UnsupportedDigestScope { .. } => "unsupported-digest-scope",
            Unestablished::BadTimestamp { .. } => "bad-timestamp",
            Unestablished::ChainUnavailable { .. } => "chain-unavailable",
        }
    }
}

impl Verdict {
    /// Whether this verdict permits a file to clear a detection.
    ///
    /// The single predicate a scanner's trust layer should branch on. It is
    /// deliberately the narrowest possible question: it does not ask whether
    /// the file is signed, or whether a signature verified, or whether the
    /// chain looks reasonable — only whether every one of those was
    /// established.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Verdict::Trusted(_))
    }

    /// Whether a signature was present and verified, whether or not it is
    /// trusted.
    ///
    /// The predicate for "this file is the file its signer signed", which is a
    /// different question from "this signer is worth trusting". Used to decide
    /// whether a file counts as signed at all.
    pub fn is_signature_valid(&self) -> bool {
        matches!(self, Verdict::Trusted(_) | Verdict::Untrusted { .. })
    }

    /// Whether the file carries a signature that could not be cleared.
    ///
    /// True for [`Verdict::Invalid`] and for an [`Verdict::Undetermined`] that
    /// found a signature. False for [`Verdict::Unsigned`] and for a file that
    /// is not a PE file at all. This is the predicate for "the file has a
    /// signature and this verifier is not happy with it", which is the one a
    /// scanner that wants to *lower* its suspicion on signed files needs.
    pub fn is_suspiciously_signed(&self) -> bool {
        match self {
            Verdict::Invalid { .. } => true,
            Verdict::Undetermined { reason } => !matches!(reason, Unestablished::NotPe),
            _ => false,
        }
    }

    /// The proof, for the two states that have one.
    pub fn proof(&self) -> Option<&Proof> {
        match self {
            Verdict::Trusted(proof) => Some(proof),
            Verdict::Untrusted { proof, .. } => Some(proof),
            _ => None,
        }
    }

    /// A short label for logs.
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Trusted(_) => "trusted",
            Verdict::Untrusted { .. } => "untrusted",
            Verdict::Invalid { .. } => "invalid",
            Verdict::Unsigned => "unsigned",
            Verdict::Undetermined { .. } => "undetermined",
        }
    }
}

impl JudgedAt {
    /// The instant, in Unix seconds, given the clock reading to use for
    /// [`JudgedAt::Now`].
    ///
    /// `Now` carries no time of its own, because a verdict that stored the
    /// clock reading would be a verdict that could not be compared with
    /// another. The caller supplies the clock and the verdict stays a value.
    pub fn instant(self, now: i64) -> i64 {
        match self {
            JudgedAt::Now => now,
            JudgedAt::Timestamp(seconds) | JudgedAt::Requested(seconds) => seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof() -> Proof {
        Proof {
            subject: "CN=Example".to_string(),
            issuer: "CN=Example CA".to_string(),
            thumbprint: "00".repeat(20),
            file_digest: "11".repeat(32),
            file_digest_algorithm: "SHA-256",
            signature_digest_algorithm: "SHA-256",
            key_bits: 2048,
            root: Some("CN=Example Root".to_string()),
            judged_at: JudgedAt::Now,
            timestamp: None,
            carried_data_value: false,
        }
    }

    #[test]
    fn only_a_fully_verified_file_is_trusted() {
        // The fail-closed rule, as a test rather than a comment. Every state
        // that is not a positive verification must answer `false` here, because
        // this is the predicate a scanner's trust layer branches on.
        assert!(Verdict::Trusted(Box::new(proof())).is_trusted());
        assert!(!Verdict::Untrusted {
            proof: Box::new(proof()),
            reason: UntrustedReason::NoTrustedRoot,
        }
        .is_trusted());
        assert!(!Verdict::Invalid {
            reason: InvalidReason::SignatureDoesNotVerify,
        }
        .is_trusted());
        assert!(!Verdict::Unsigned.is_trusted());
        assert!(!Verdict::Undetermined {
            reason: Unestablished::NotPe,
        }
        .is_trusted());
    }

    #[test]
    fn every_undetermined_reason_is_never_trusted() {
        // The list is exhaustive by construction: a new variant would have to
        // be added here, and the assertion is written so that adding one
        // without thinking about it fails rather than passes.
        let reasons = [
            Unestablished::NotPe,
            Unestablished::Malformed {
                code: "malformed",
                detail: "the blob would not parse".to_string(),
            },
            Unestablished::UnsupportedAlgorithm {
                oid: "1.2.840.113549.1.1.10".to_string(),
            },
            Unestablished::UnsupportedDigestScope {
                reason: "page hashes",
            },
            Unestablished::BadTimestamp {
                detail: "the token does not cover this signature".to_string(),
            },
            Unestablished::ChainUnavailable {
                detail: "the chain engine returned 0x800B010A".to_string(),
            },
        ];
        for reason in reasons {
            let verdict = Verdict::Undetermined {
                reason: reason.clone(),
            };
            assert!(!verdict.is_trusted(), "{reason:?} must not be trusted");
            assert!(
                !verdict.is_signature_valid(),
                "{reason:?} is not a valid signature"
            );
        }
    }

    #[test]
    fn an_unsigned_file_is_not_reported_as_a_failed_signature() {
        // The distinction the brief asks for: a file with no signature is the
        // normal state of most of a disk, and confusing it with a failed
        // verification would flag every unsigned program.
        assert!(!Verdict::Unsigned.is_signature_valid());
        assert!(!Verdict::Unsigned.is_suspiciously_signed());
        assert!(Verdict::Invalid {
            reason: InvalidReason::FileDigestMismatch {
                expected: "00".to_string(),
                computed: "11".to_string(),
            },
        }
        .is_suspiciously_signed());
    }

    #[test]
    fn a_file_that_is_not_a_pe_file_is_not_a_signed_file_with_a_problem() {
        assert!(!Verdict::Undetermined {
            reason: Unestablished::NotPe,
        }
        .is_suspiciously_signed());
    }

    #[test]
    fn the_judged_at_instant_is_the_timestamp_when_there_is_one() {
        assert_eq!(JudgedAt::Now.instant(1_700_000_000), 1_700_000_000);
        assert_eq!(
            JudgedAt::Timestamp(1_600_000_000).instant(1_700_000_000),
            1_600_000_000
        );
        assert_eq!(
            JudgedAt::Requested(1_500_000_000).instant(1_700_000_000),
            1_500_000_000
        );
    }

    #[test]
    fn every_verdict_has_a_distinct_code() {
        let verdicts = [
            Verdict::Trusted(Box::new(proof())),
            Verdict::Untrusted {
                proof: Box::new(proof()),
                reason: UntrustedReason::NoTrustedRoot,
            },
            Verdict::Invalid {
                reason: InvalidReason::SignatureDoesNotVerify,
            },
            Verdict::Unsigned,
            Verdict::Undetermined {
                reason: Unestablished::NotPe,
            },
        ];
        let mut codes: Vec<&str> = verdicts.iter().map(Verdict::code).collect();
        codes.sort_unstable();
        let count = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), count, "two verdicts share a code");
    }
}
