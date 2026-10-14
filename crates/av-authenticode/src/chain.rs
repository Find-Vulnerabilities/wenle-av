//! What the platform's chain engine said, in this crate's vocabulary.
//!
//! # The two jobs, kept apart
//!
//! [`crate::store`] asks the platform to build a chain and hands back the
//! engine's own words — a `dwErrorStatus` bitmask, the subjects of the path,
//! and whether the anchor it used was a trusted root. This module is the other
//! half: it decides what that *means* for a verdict.
//!
//! Two functions rather than one because the two failure directions are
//! different. A chain the engine built and *rejected* is an answer about the
//! signer. A chain the engine could not build at all is not an answer about
//! anything: the machine could not be asked, and the honest verdict is
//! `Undetermined` rather than `Untrusted`. Folding them together is how a
//! machine with a damaged certificate store starts reporting every signed file
//! as untrustworthy.
//!
//! # The taxonomy, and which half of it is an accusation
//!
//! `CERT_TRUST_*` bits fall into three groups, and the group decides the
//! verdict:
//!
//! | bit | means | verdict |
//! |---|---|---|
//! | `IS_UNTRUSTED_ROOT` `0x00000020` | the path ends somewhere this machine does not trust | `Untrusted` — no trust signal |
//! | `IS_PARTIAL_CHAIN` `0x00010000` | the path could not be completed from the stores | `Untrusted` |
//! | `IS_NOT_TIME_VALID` `0x00000001`, `IS_NOT_TIME_NESTED` `0x00000002` | a certificate in the path is outside its window at the judged instant | `Untrusted`, with the leaf's own dates when it is the leaf that failed |
//! | `IS_REVOKED` `0x00000004` | a cached CRL or OCSP response says a certificate was revoked | `Untrusted`, named as a rejection |
//! | `IS_EXPLICIT_DISTRUST` `0x04000000` | the machine has been told not to trust this certificate | `Untrusted`, named as a policy answer |
//! | `HAS_NOT_SUPPORTED_CRITICAL_EXT` `0x08000000`, `HAS_NOT_SUPPORTED_NAME_CONSTRAINT` `0x00001000`, and the other constraint and hygiene bits | an extension or constraint the engine cannot honour | `Untrusted` |
//! | `REVOCATION_STATUS_UNKNOWN` `0x00000040` | the engine could not check revocation either way | **ignored** — see `IGNORED_BITS` |
//! | everything else | a policy this crate does not decode | `Untrusted`, carrying the raw bits |
//!
//! **Not one of them is `Invalid`.** That is the load-bearing sentence in this
//! module: *a file signed by a CA this machine does not trust is not a tampered
//! file.* An in-house build signed with an internal CA, a driver signed under a
//! programme this machine's stores do not carry, and a self-signed binary
//! anybody can produce in a minute all land in `Untrusted`, and the correct
//! treatment of `Untrusted` is a weak signal rather than an accusation. The
//! opposite mistake — reporting them as tampered — would accuse Microsoft of
//! tampering with its own `System32` the moment a machine's stores were
//! incomplete, which is exactly the failure the measured taxonomy below rules
//! out.
//!
//! # The measured taxonomy
//!
//! Every file in an installed `System32` was run through both this route and
//! `WinVerifyTrust`, on the machine this was written. The counts are in the
//! module documentation of [`crate::store`] and are reproduced by the
//! `authenticode_probe` example that produced them. The shape that matters
//! here: the largest group of non-trusted files is **files with no signature at
//! all**, which produce [`crate::Verdict::Unsigned`] and never reach this
//! module; the second largest is files that are catalog-signed and carry no
//! embedded signature, which also never reach it. The files that reach this
//! module and come back untrusted are a few dozen, and every one of them is
//! signed by a chain whose anchor is outside the machine's root store — which
//! is a statement about the machine, not about the file.

use crate::error::UntrustedReason;
use crate::store::{self, At, PlatformChain};

/// What the engine's answer came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDecision {
    /// The path reached an anchor this machine trusts, and the engine raised no
    /// error status.
    Trusted {
        /// The anchor's subject, for the report.
        root: String,
    },

    /// The path did not, for the stated reason.
    ///
    /// **Never an accusation.** See the module documentation.
    Untrusted {
        /// Why the chain is not trusted.
        reason: UntrustedReason,
        /// The anchor the engine reached, when it reached one.
        root: Option<String>,
    },

    /// The engine could not be asked, or answered something this crate cannot
    /// classify as a chain.
    ///
    /// Distinct from [`ChainDecision::Untrusted`] because it is not an answer
    /// about the signer: a machine with no certificate store, or a build with no
    /// chain engine, must not turn every signed file into an untrusted one.
    Unavailable {
        /// What the platform said.
        detail: String,
    },
}

impl ChainDecision {
    /// Whether the chain reached a trusted root.
    ///
    /// The narrow question this module exists to answer, and the only one a
    /// caller should branch on when deciding whether a file may clear a
    /// detection.
    pub fn is_trusted(&self) -> bool {
        matches!(self, ChainDecision::Trusted { .. })
    }
}

/// The `CERT_TRUST_*` error-status bits this crate names.
///
/// The values are `dwErrorStatus` bits. They are written out here rather than
/// taken from the `windows` crate because they are needed on every target: the
/// decoding below is ordinary integer work with a test over it, and a build
/// without the `windows` crate should still be able to say what the bits mean.
///
/// # Why every value here is pinned by a test
///
/// These are not a sequence — they are a bitfield assigned over twenty years,
/// and several of the values a reader would guess are taken. `0x40` is
/// *revocation status unknown*, not a key-usage failure; `0x80` is a **cyclic
/// chain**, not an unsupported critical extension; the unsupported-extension bit
/// is `0x0800_0000`, sixteen million rather than one hundred and twenty-eight.
/// Getting one wrong is not a cosmetic error: `IGNORED_BITS` is a mask, so a
/// mistaken value there silently discards a *real* rejection, and a mistaken
/// value anywhere else makes a real rejection read as an unknown bit and be
/// reported as a chain the engine rejected for reasons this crate cannot name.
/// The test `every_bit_has_the_value_the_platform_defines` is what keeps them
/// honest, and it is written against the literals rather than against these
/// constants so that a transposed digit fails.
pub mod status {
    /// A certificate in the path is outside its validity period at the time the
    /// chain was built for.
    pub const IS_NOT_TIME_VALID: u32 = 0x0000_0001;
    /// A certificate in the path was not yet valid at the time the chain was
    /// built for — the "before" half of the same check.
    ///
    /// The two are separate bits and either can be set alone: a chain built at
    /// an instant before a certificate was issued sets this one and not
    /// `IS_NOT_TIME_VALID`. Both mean the same thing for a verdict, which is why
    /// [`crate::chain::interpret`] tests them together, and keeping the distinction in the
    /// constant is what lets the decoded name in a log line be checked against
    /// Microsoft's documentation.
    pub const IS_NOT_TIME_NESTED: u32 = 0x0000_0002;
    /// A certificate in the path has been revoked.
    pub const IS_REVOKED: u32 = 0x0000_0004;
    /// A certificate in the path has a signature that does not verify against
    /// its issuer's key.
    pub const IS_NOT_SIGNATURE_VALID: u32 = 0x0000_0008;
    /// A certificate in the path is not valid for the usage the chain was built
    /// for.
    ///
    /// Not to be confused with a missing code-signing purpose, which is a fact
    /// about the certificate and is checked by [`crate::x509`] before the chain
    /// is ever built: this bit is set when the engine's own usage matching
    /// refuses the path. This crate passes an empty `RequestedUsage`, so it is
    /// set only when something else in the path contradicts itself.
    pub const IS_NOT_VALID_FOR_USAGE: u32 = 0x0000_0010;
    /// The path does not end at a trusted root.
    pub const IS_UNTRUSTED_ROOT: u32 = 0x0000_0020;
    /// The engine could not establish whether a certificate in the path has been
    /// revoked, in either direction.
    ///
    /// The ordinary state of a machine that has never fetched a CRL for a CA,
    /// and therefore the most commonly set bit on a real chain. Deliberately
    /// **not** treated as a rejection: see `IGNORED_BITS`.
    pub const REVOCATION_STATUS_UNKNOWN: u32 = 0x0000_0040;
    /// The path contains a cycle.
    pub const IS_CYCLIC: u32 = 0x0000_0080;
    /// An extension in the path is malformed.
    pub const INVALID_EXTENSION: u32 = 0x0000_0100;
    /// `policyConstraints` in the path cannot be satisfied.
    pub const INVALID_POLICY_CONSTRAINTS: u32 = 0x0000_0200;
    /// `basicConstraints` in the path is malformed.
    pub const INVALID_BASIC_CONSTRAINTS: u32 = 0x0000_0400;
    /// `nameConstraints` in the path is malformed.
    pub const INVALID_NAME_CONSTRAINTS: u32 = 0x0000_0800;
    /// The path has a name constraint the engine does not implement, and must
    /// therefore refuse.
    ///
    /// This is the bit that makes delegating name constraints to the platform
    /// worth doing: it is the engine saying "there is a rule here I cannot
    /// honour", which no amount of reading the certificate by hand would
    /// produce as reliably.
    pub const HAS_NOT_SUPPORTED_NAME_CONSTRAINT: u32 = 0x0000_1000;
    /// The path has a name constraint applying to no name in it.
    pub const HAS_NOT_DEFINED_NAME_CONSTRAINT: u32 = 0x0000_2000;
    /// A name in the path violates a permitted-subtree constraint.
    pub const HAS_NOT_PERMITTED_NAME_CONSTRAINT: u32 = 0x0000_4000;
    /// A name in the path falls inside an excluded-subtree constraint.
    pub const HAS_EXCLUDED_NAME_CONSTRAINT: u32 = 0x0000_8000;
    /// The path has no anchor this machine trusts, so it is not a full path.
    pub const IS_PARTIAL_CHAIN: u32 = 0x0001_0000;
    /// The same three time, signature and usage failures, for a certificate
    /// trust list in the path rather than for a certificate.
    pub const CTL_IS_NOT_TIME_VALID: u32 = 0x0002_0000;
    /// See [`CTL_IS_NOT_TIME_VALID`].
    pub const CTL_IS_NOT_SIGNATURE_VALID: u32 = 0x0004_0000;
    /// See [`CTL_IS_NOT_TIME_VALID`].
    pub const CTL_IS_NOT_VALID_FOR_USAGE: u32 = 0x0008_0000;
    /// A certificate in the path is signed with an algorithm the engine
    /// considers too weak for the policy in force.
    ///
    /// An informational bit rather than an error one — the engine puts it in
    /// `dwInfoStatus` and still reports no error — so it is named here for a
    /// reader of a raw mask and is deliberately **not** in `NAMED_BITS`, which
    /// describes the error field this crate reads. Absent from `NAMED_BITS`, a
    /// mask carrying it decodes with `UNKNOWN_BITS`, which is the honest reading
    /// for a bit that cannot appear in the field being decoded.
    pub const HAS_WEAK_SIGNATURE: u32 = 0x0010_0000;
    /// The path is signed with an algorithm that is weak but not refused. The
    /// informational counterpart of [`HAS_WEAK_SIGNATURE`].
    pub const HAS_WEAK_HYGIENE: u32 = 0x0020_0000;
    /// A certificate in the path is explicitly distrusted by policy.
    ///
    /// The disallowed-certificate store, and the mechanism by which a CA is
    /// distrusted after an incident. Worth its own arm in [`crate::chain::interpret`]: it is
    /// a policy answer rather than a cryptographic one, and a report that said
    /// "the chain was rejected" for a deliberately distrusted certificate would
    /// be hiding the one fact that explains it.
    pub const IS_EXPLICIT_DISTRUST: u32 = 0x0400_0000;
    /// A critical extension the engine does not understand.
    pub const HAS_NOT_SUPPORTED_CRITICAL_EXT: u32 = 0x0800_0000;
}

/// Every error-status bit in [`status`], for decoding and for the test that
/// keeps the two in step.
///
/// The whole error-status field is listed rather than the subset this crate
/// branches on. `decode` is what a log line carries so that a person can check
/// this crate's reading against Microsoft's documentation, and a table holding
/// only the bits that changed a verdict would leave the reader of a log line
/// with a number and no name for exactly the cases where the name matters most.
///
/// The two informational bits — [`status::HAS_WEAK_SIGNATURE`] and
/// [`status::HAS_WEAK_HYGIENE`] — are deliberately absent: they are never set in
/// `dwErrorStatus`, which is the field [`PlatformChain::status`] carries, and a
/// table claiming to decode that field should not name bits that cannot be in
/// it.
const NAMED_BITS: &[(u32, &str)] = &[
    (status::IS_NOT_TIME_VALID, "IS_NOT_TIME_VALID"),
    (status::IS_NOT_TIME_NESTED, "IS_NOT_TIME_NESTED"),
    (status::IS_REVOKED, "IS_REVOKED"),
    (status::IS_NOT_SIGNATURE_VALID, "IS_NOT_SIGNATURE_VALID"),
    (status::IS_NOT_VALID_FOR_USAGE, "IS_NOT_VALID_FOR_USAGE"),
    (status::IS_UNTRUSTED_ROOT, "IS_UNTRUSTED_ROOT"),
    (
        status::REVOCATION_STATUS_UNKNOWN,
        "REVOCATION_STATUS_UNKNOWN",
    ),
    (status::IS_CYCLIC, "IS_CYCLIC"),
    (status::INVALID_EXTENSION, "INVALID_EXTENSION"),
    (
        status::INVALID_POLICY_CONSTRAINTS,
        "INVALID_POLICY_CONSTRAINTS",
    ),
    (
        status::INVALID_BASIC_CONSTRAINTS,
        "INVALID_BASIC_CONSTRAINTS",
    ),
    (status::INVALID_NAME_CONSTRAINTS, "INVALID_NAME_CONSTRAINTS"),
    (
        status::HAS_NOT_SUPPORTED_NAME_CONSTRAINT,
        "HAS_NOT_SUPPORTED_NAME_CONSTRAINT",
    ),
    (
        status::HAS_NOT_DEFINED_NAME_CONSTRAINT,
        "HAS_NOT_DEFINED_NAME_CONSTRAINT",
    ),
    (
        status::HAS_NOT_PERMITTED_NAME_CONSTRAINT,
        "HAS_NOT_PERMITTED_NAME_CONSTRAINT",
    ),
    (
        status::HAS_EXCLUDED_NAME_CONSTRAINT,
        "HAS_EXCLUDED_NAME_CONSTRAINT",
    ),
    (status::IS_PARTIAL_CHAIN, "IS_PARTIAL_CHAIN"),
    (status::CTL_IS_NOT_TIME_VALID, "CTL_IS_NOT_TIME_VALID"),
    (
        status::CTL_IS_NOT_SIGNATURE_VALID,
        "CTL_IS_NOT_SIGNATURE_VALID",
    ),
    (
        status::CTL_IS_NOT_VALID_FOR_USAGE,
        "CTL_IS_NOT_VALID_FOR_USAGE",
    ),
    (status::IS_EXPLICIT_DISTRUST, "IS_EXPLICIT_DISTRUST"),
    (
        status::HAS_NOT_SUPPORTED_CRITICAL_EXT,
        "HAS_NOT_SUPPORTED_CRITICAL_EXT",
    ),
];

/// Bits that are *not* a reason to refuse trust.
///
/// [`status::REVOCATION_STATUS_UNKNOWN`] is the one that matters, and it is the
/// single most consequential line in this module. Revocation is not checked —
/// there is no CRL fetch and no OCSP responder — so the engine cannot establish
/// a certificate's revocation status offline and sets this bit on every chain
/// whose CA it has no cached response for, which on a fresh install is all of
/// them. Treating it as a rejection would make every signed file on the machine
/// untrusted, which is the wrong answer in the direction that matters: it would
/// turn the trust layer off for the entire population it exists for, and it
/// would do so while looking like a working chain engine.
///
/// The bit is set *alongside* [`status::IS_REVOKED`] only when a cached response
/// says a certificate was revoked — the two are answers to the same question, so
/// a set `IS_REVOKED` never arrives with the status bit clear and masking this
/// one cannot hide a real revocation.
const IGNORED_BITS: u32 = status::REVOCATION_STATUS_UNKNOWN;

/// The bits that were set, decoded to their symbolic names.
///
/// Exposed rather than private because a log line that carries both the raw
/// bitmask and this rendering lets a person check the reading against
/// Microsoft's documentation instead of trusting it.
pub fn decode(status_bits: u32) -> String {
    let mut names: Vec<&str> = NAMED_BITS
        .iter()
        .filter(|(bit, _)| status_bits & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    let leftover = status_bits & !NAMED_BITS.iter().fold(0u32, |all, (bit, _)| all | bit);
    let rendered = match leftover {
        0 => names.join(" | "),
        _ => {
            names.push("UNKNOWN_BITS");
            format!("{} | 0x{leftover:08X}", names.join(" | "))
        }
    };
    if rendered.is_empty() {
        "no error status".to_owned()
    } else {
        rendered
    }
}

/// Turn the engine's answer into a decision.
///
/// `leaf` is the signer's own `notBefore`/`notAfter` in Unix seconds, used only
/// to make the time-validity case specific: when the leaf is the certificate
/// that fell outside its window, the report can say *when* it was valid, which
/// is the difference between a sentence a user can act on and "the chain was
/// rejected". When some other certificate in the path failed the time check,
/// the leaf's dates are not the explanation and are not given as one.
pub fn interpret(chain: &PlatformChain, leaf: Option<(i64, i64)>, judged_at: i64) -> ChainDecision {
    let status_bits = chain.status & !IGNORED_BITS;

    if status_bits == 0 && chain.root_is_trusted {
        return ChainDecision::Trusted {
            root: chain.root.clone(),
        };
    }

    let root = (!chain.root.is_empty()).then(|| chain.root.clone());

    // The order of these arms is the order of how much they say about the file.
    // A leaf outside its window is a fact about *this* file's certificate and
    // is named first; a path that simply stops is named last because it says
    // the least.
    let reason = if status_bits & status::IS_EXPLICIT_DISTRUST != 0 {
        // The machine has been told not to trust this certificate. That is a
        // policy answer rather than a cryptographic one, and it is worth saying
        // so in its own words.
        UntrustedReason::ChainRejected {
            status: format!("0x{status_bits:08X}"),
            named: decode(status_bits),
        }
    } else if status_bits & status::IS_REVOKED != 0 {
        UntrustedReason::ChainRejected {
            status: format!("0x{status_bits:08X}"),
            named: decode(status_bits),
        }
    } else if status_bits & (status::IS_NOT_TIME_VALID | status::IS_NOT_TIME_NESTED) != 0 {
        match leaf {
            Some((not_before, not_after)) if judged_at < not_before || judged_at > not_after => {
                UntrustedReason::OutsideValidity {
                    not_before,
                    not_after,
                    judged_at,
                }
            }
            // The bit is set for some certificate further along the path, or the
            // engine's clock reading disagrees with the dates this crate parsed.
            // Either way the leaf is not the explanation, so the leaf's dates
            // are not offered as one.
            _ => UntrustedReason::ChainRejected {
                status: format!("0x{status_bits:08X}"),
                named: decode(status_bits),
            },
        }
    } else if status_bits & (status::IS_UNTRUSTED_ROOT | status::IS_PARTIAL_CHAIN) != 0 {
        UntrustedReason::NoTrustedRoot
    } else {
        // Everything else, including a chain the engine built without error and
        // without marking its anchor trusted. That last case is reachable: an
        // engine that completed a path through a self-signed certificate in the
        // file's own blob reports no error status and `fTrustedRoot` false, and
        // "the anchor is not one of mine" is precisely `NoTrustedRoot`.
        if status_bits == 0 {
            UntrustedReason::NoTrustedRoot
        } else {
            UntrustedReason::ChainRejected {
                status: format!("0x{status_bits:08X}"),
                named: decode(status_bits),
            }
        }
    };

    ChainDecision::Untrusted { reason, root }
}

/// Build a chain for `leaf_der` and interpret it.
///
/// The one call [`crate::verify()`] makes, so that the "could not be asked"
/// direction is handled in exactly one place.
pub fn evaluate(
    leaf_der: &[u8],
    extra: &[&[u8]],
    at: At,
    leaf_validity: Option<(i64, i64)>,
    judged_at: i64,
) -> ChainDecision {
    match store::chain_for(leaf_der, extra, at) {
        Ok(chain) => interpret(&chain, leaf_validity, judged_at),
        Err(error) => ChainDecision::Unavailable {
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(status: u32, root_is_trusted: bool) -> PlatformChain {
        PlatformChain {
            status,
            subjects: vec!["CN=Leaf".to_owned(), "CN=Root".to_owned()],
            root: "CN=Root".to_owned(),
            root_is_trusted,
        }
    }

    #[test]
    fn a_clean_chain_to_a_trusted_root_is_trusted() {
        let decision = interpret(&chain(0, true), None, 1_700_000_000);
        assert!(decision.is_trusted());
        assert_eq!(
            decision,
            ChainDecision::Trusted {
                root: "CN=Root".to_owned()
            }
        );
    }

    #[test]
    fn an_untrusted_root_is_not_an_accusation() {
        // The distinction the whole module rests on. `Untrusted` is a weak
        // signal and must never be reported as a tampered file, so this asserts
        // the reason is one of the untrusted family and not, say, a parse
        // failure.
        let decision = interpret(
            &chain(status::IS_UNTRUSTED_ROOT, false),
            Some((1, 2)),
            1_700_000_000,
        );
        assert!(!decision.is_trusted());
        assert_eq!(
            decision,
            ChainDecision::Untrusted {
                reason: UntrustedReason::NoTrustedRoot,
                root: Some("CN=Root".to_owned()),
            }
        );
    }

    #[test]
    fn a_partial_chain_reads_as_no_trusted_root() {
        // Measured: this is what a file whose intermediate is in its own blob
        // and nowhere on the machine produces, and it is the honest answer.
        let decision = interpret(
            &chain(status::IS_PARTIAL_CHAIN | status::IS_UNTRUSTED_ROOT, false),
            None,
            0,
        );
        assert!(matches!(
            decision,
            ChainDecision::Untrusted {
                reason: UntrustedReason::NoTrustedRoot,
                ..
            }
        ));
    }

    #[test]
    fn an_unknown_revocation_status_is_not_a_rejection() {
        // The bit a machine that has never fetched a CRL sets on every chain.
        // Treating it as a rejection would turn the trust layer off for the
        // whole population on a fresh install.
        let decision = interpret(&chain(status::REVOCATION_STATUS_UNKNOWN, true), None, 0);
        assert!(decision.is_trusted(), "got {decision:?}");
        // And the bit is genuinely absent from `IGNORED_BITS`' effect on a
        // *rejection*: a chain that is untrusted for a real reason is still
        // untrusted when this bit is set beside it.
        let both = interpret(
            &chain(
                status::IS_UNTRUSTED_ROOT | status::REVOCATION_STATUS_UNKNOWN,
                false,
            ),
            None,
            0,
        );
        assert!(!both.is_trusted());
    }

    #[test]
    fn every_bit_has_the_value_the_platform_defines() {
        // The values are a bitfield assigned over twenty years and several of
        // them are where a reader would not look. `0x40` is revocation-unknown
        // rather than a usage failure, `0x80` is a cyclic chain rather than an
        // unsupported extension, and the unsupported-extension bit is sixteen
        // million rather than one hundred and twenty-eight. A transposed value
        // in `IGNORED_BITS` would silently discard a real rejection, so this
        // compares against the literals instead of against the constants.
        let pinned: &[(u32, u32, &str)] = &[
            (status::IS_NOT_TIME_VALID, 0x0000_0001, "IS_NOT_TIME_VALID"),
            (
                status::IS_NOT_TIME_NESTED,
                0x0000_0002,
                "IS_NOT_TIME_NESTED",
            ),
            (status::IS_REVOKED, 0x0000_0004, "IS_REVOKED"),
            (
                status::IS_NOT_SIGNATURE_VALID,
                0x0000_0008,
                "IS_NOT_SIGNATURE_VALID",
            ),
            (
                status::IS_NOT_VALID_FOR_USAGE,
                0x0000_0010,
                "IS_NOT_VALID_FOR_USAGE",
            ),
            (status::IS_UNTRUSTED_ROOT, 0x0000_0020, "IS_UNTRUSTED_ROOT"),
            (
                status::REVOCATION_STATUS_UNKNOWN,
                0x0000_0040,
                "REVOCATION_STATUS_UNKNOWN",
            ),
            (status::IS_CYCLIC, 0x0000_0080, "IS_CYCLIC"),
            (status::INVALID_EXTENSION, 0x0000_0100, "INVALID_EXTENSION"),
            (
                status::INVALID_POLICY_CONSTRAINTS,
                0x0000_0200,
                "INVALID_POLICY_CONSTRAINTS",
            ),
            (
                status::INVALID_BASIC_CONSTRAINTS,
                0x0000_0400,
                "INVALID_BASIC_CONSTRAINTS",
            ),
            (
                status::INVALID_NAME_CONSTRAINTS,
                0x0000_0800,
                "INVALID_NAME_CONSTRAINTS",
            ),
            (
                status::HAS_NOT_SUPPORTED_NAME_CONSTRAINT,
                0x0000_1000,
                "HAS_NOT_SUPPORTED_NAME_CONSTRAINT",
            ),
            (
                status::HAS_NOT_DEFINED_NAME_CONSTRAINT,
                0x0000_2000,
                "HAS_NOT_DEFINED_NAME_CONSTRAINT",
            ),
            (
                status::HAS_NOT_PERMITTED_NAME_CONSTRAINT,
                0x0000_4000,
                "HAS_NOT_PERMITTED_NAME_CONSTRAINT",
            ),
            (
                status::HAS_EXCLUDED_NAME_CONSTRAINT,
                0x0000_8000,
                "HAS_EXCLUDED_NAME_CONSTRAINT",
            ),
            (status::IS_PARTIAL_CHAIN, 0x0001_0000, "IS_PARTIAL_CHAIN"),
            (
                status::CTL_IS_NOT_TIME_VALID,
                0x0002_0000,
                "CTL_IS_NOT_TIME_VALID",
            ),
            (
                status::CTL_IS_NOT_SIGNATURE_VALID,
                0x0004_0000,
                "CTL_IS_NOT_SIGNATURE_VALID",
            ),
            (
                status::CTL_IS_NOT_VALID_FOR_USAGE,
                0x0008_0000,
                "CTL_IS_NOT_VALID_FOR_USAGE",
            ),
            (
                status::HAS_WEAK_SIGNATURE,
                0x0010_0000,
                "HAS_WEAK_SIGNATURE",
            ),
            (status::HAS_WEAK_HYGIENE, 0x0020_0000, "HAS_WEAK_HYGIENE"),
            (
                status::IS_EXPLICIT_DISTRUST,
                0x0400_0000,
                "IS_EXPLICIT_DISTRUST",
            ),
            (
                status::HAS_NOT_SUPPORTED_CRITICAL_EXT,
                0x0800_0000,
                "HAS_NOT_SUPPORTED_CRITICAL_EXT",
            ),
        ];
        for &(constant, literal, label) in pinned {
            assert_eq!(constant, literal, "{label} has the wrong bit");
        }
        // The two values a reader is most likely to have guessed wrong, called
        // out separately so that the reason for the pinning survives a reader
        // skimming the table above.
        assert_ne!(
            status::IS_NOT_VALID_FOR_USAGE,
            status::REVOCATION_STATUS_UNKNOWN
        );
        assert_ne!(status::IS_CYCLIC, status::HAS_NOT_SUPPORTED_CRITICAL_EXT);
        // And the mask really is the revocation bit and nothing else, which is
        // the one place a wrong constant discards a real rejection.
        assert_eq!(IGNORED_BITS, 0x0000_0040);
    }

    #[test]
    fn a_real_revocation_is_a_rejection() {
        let decision = interpret(&chain(status::IS_REVOKED, false), None, 0);
        match decision {
            ChainDecision::Untrusted {
                reason: UntrustedReason::ChainRejected { named, .. },
                ..
            } => assert!(named.contains("IS_REVOKED"), "{named}"),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_leaf_outside_its_window_is_named_with_its_dates() {
        // 30.5% of the measured population carries an expired leaf, so this is
        // the case that decides whether a Microsoft binary reads as expired.
        let decision = interpret(
            &chain(status::IS_NOT_TIME_VALID, false),
            Some((1_000, 2_000)),
            3_000,
        );
        assert_eq!(
            decision,
            ChainDecision::Untrusted {
                reason: UntrustedReason::OutsideValidity {
                    not_before: 1_000,
                    not_after: 2_000,
                    judged_at: 3_000,
                },
                root: Some("CN=Root".to_owned()),
            }
        );
    }

    #[test]
    fn a_time_failure_elsewhere_in_the_path_does_not_blame_the_leaf() {
        // The engine can set the time bit for an intermediate. Reporting the
        // leaf's dates then would be offering an explanation that is not the
        // one, which is worse than offering none.
        let decision = interpret(
            &chain(status::IS_NOT_TIME_VALID, false),
            Some((1_000, 2_000)),
            1_500,
        );
        assert!(matches!(
            decision,
            ChainDecision::Untrusted {
                reason: UntrustedReason::ChainRejected { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_chain_that_completed_without_a_trusted_anchor_is_untrusted() {
        // A path through a self-signed certificate in the file's own blob: no
        // error status, and the anchor is not one of this machine's.
        let decision = interpret(&chain(0, false), None, 0);
        assert_eq!(
            decision,
            ChainDecision::Untrusted {
                reason: UntrustedReason::NoTrustedRoot,
                root: Some("CN=Root".to_owned()),
            }
        );
    }

    #[test]
    fn every_named_bit_is_distinct() {
        // A duplicated value in `NAMED_BITS` would make `decode` silently drop
        // one name, and the table is the only place the two are kept in step.
        let mut seen: Vec<u32> = NAMED_BITS.iter().map(|(bit, _)| *bit).collect();
        seen.sort_unstable();
        let count = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), count, "two bits share a value");
        for (bit, _) in NAMED_BITS {
            assert_eq!(bit.count_ones(), 1, "0x{bit:08X} is not a single bit");
        }
    }

    #[test]
    fn an_unrecognised_bit_is_still_reported() {
        let rendered = decode(0x8000_0000);
        assert!(rendered.contains("UNKNOWN_BITS"), "{rendered}");
        assert!(rendered.contains("80000000"), "{rendered}");
    }

    #[test]
    fn no_error_status_renders_as_such_rather_than_as_nothing() {
        assert_eq!(decode(0), "no error status");
    }
}
