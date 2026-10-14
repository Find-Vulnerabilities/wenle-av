//! Why verification did not reach an answer.
//!
//! This is the "we could not tell" half of the verdict, and keeping it separate
//! from "the signature is wrong" is the whole reason [`crate::Verdict`] is an
//! enum. A file whose signature block is a truncated mess has not been shown to
//! be tampered with, and a file whose signature verifies but whose chain is
//! unknown has not been shown to be unsigned. Collapsing either into the other
//! is how a scan report ends up telling a user something it did not establish.
//!
//! Every variant here is reachable from a file on disk, which is the standard
//! this crate's error types are held to: the input is bytes written by whoever
//! built the sample, so the failure mode to design against is a crafted file
//! producing an allocation or an index from a number it supplied, rather than a
//! typed error.

use av_signatures::SignatureError;
use std::fmt;

/// A failure that stopped verification from producing a verdict.
///
/// The variants divide into two kinds, and the split is the same one
/// [`crate::Verdict::Undetermined`] and [`crate::Verdict::Invalid`] make:
///
/// * **Structural** — the file's signature block is not the structure it claims
///   to be. Nothing has been proved; the bytes could be a corruption, a
///   half-written download, or an attempt to make a verifier choke. These end
///   in [`crate::Verdict::Undetermined`].
/// * **Evidential** — the structure was read completely and one of the required
///   equalities did not hold. These end in [`crate::Verdict::Invalid`] or
///   [`crate::Verdict::Untrusted`], and each names *which* equality failed,
///   because "the signature is bad" and "the file changed after signing" are
///   different findings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The file carries no Authenticode signature at all.
    ///
    /// Not a defect and not an error in the caller's sense — most files on a
    /// Windows installation have no signature — but it *is* a reason no verdict
    /// of "verified" can be given, so it travels as one rather than as a
    /// separate `Option` the caller has to remember to check.
    #[error("this file carries no Authenticode signature")]
    Absent,

    /// The signature block is present and is not the structure it claims.
    ///
    /// The inner error is [`av_signatures`]' DER reader's, which is reused
    /// deliberately rather than reimplemented: a second parser for the same
    /// bytes would be a second parser to keep safe, and the one being reused is
    /// the one with the fuzzing and the tests.
    #[error("the signature block could not be read: {0}")]
    Malformed(#[from] SignatureError),

    /// The blob parsed but is not a PKCS#7 `SignedData`.
    ///
    /// Reachable when a file's certificate table holds something else — a
    /// detached signature, a catalog, a raw certificate. Distinct from
    /// [`AuthError::Malformed`] because the bytes are well-formed; they are the
    /// wrong kind of well-formed.
    #[error("the signature blob is not PKCS#7 SignedData: {reason}")]
    NotSignedData {
        /// Which part of the structure was wrong.
        reason: &'static str,
    },

    /// The `SignedData` carried no `SignerInfo`.
    ///
    /// A `SignedData` with an empty signer set is legal ASN.1 and is what a file
    /// built to confuse a verifier looks like. There is nothing to verify
    /// against, so this is a refusal rather than an "unsigned".
    #[error("the SignedData has no signer, so there is no signature to verify")]
    NoSigner,

    /// The signer's certificate is not among those the blob carries.
    ///
    /// PKCS#7 lets a signer be identified by issuer-and-serial alone; the
    /// certificate then has to come from somewhere else. Authenticode files
    /// always embed it, so the `sid` pointing outside the blob means either a
    /// malformed file or one expecting a verifier that fetches certificates
    /// over the network — which this one will not do.
    #[error("the signer names a certificate the blob does not carry")]
    SignerCertificateAbsent,

    /// The signer used no signed attributes.
    ///
    /// In CMS the signature may be over the content directly. In Authenticode
    /// it never is: the digest of the file lives in the signed attributes, so a
    /// signer without them has nowhere to have committed to the file. There is
    /// no digest to compare and no `contentType` attribute to bind the structure
    /// — verification stops here rather than guessing which of the two
    /// arrangements was meant.
    #[error("the signer has no signed attributes, so nothing commits to the file")]
    NoSignedAttributes,

    /// The signature algorithm is not one this crate implements.
    ///
    /// A named refusal rather than a `false`, because the two are different
    /// answers about a file. `Unsupported` says the verifier cannot tell;
    /// reporting it as a failed verification would claim knowledge the verifier
    /// does not have, and would make an ECDSA-signed file look tampered rather
    /// than unassessed.
    #[error("the signature algorithm `{oid}` is not implemented by this verifier")]
    UnsupportedSignatureAlgorithm {
        /// The algorithm identifier's OID, dotted.
        oid: String,
    },

    /// The digest algorithm is not one this crate implements.
    ///
    /// The counterpart of [`AuthError::UnsupportedSignatureAlgorithm`] for the
    /// hash. Authenticode files in the wild use MD5 and SHA-1 as well as
    /// SHA-2, and MD5 is refused by name rather than computed: an MD5 digest
    /// comparison is not evidence of anything, and a verifier that computed one
    /// and returned `true` would be at its most confident exactly where it is
    /// least sound.
    #[error("the digest algorithm `{oid}` is not implemented by this verifier")]
    UnsupportedDigestAlgorithm {
        /// The algorithm identifier's OID, dotted.
        oid: String,
    },

    /// The signer's public key is not one this crate can use.
    ///
    /// Reached for an EC key, and for an RSA key whose modulus is not a
    /// sensible size. The 2048-bit floor is deliberate: a 512-bit RSA key is
    /// forgeable, and reporting "valid signature" over one would be a
    /// technically-true statement that misleads.
    #[error("the signer's {algorithm} key is not usable: {reason}")]
    UnusableKey {
        /// The key algorithm, as read from the certificate.
        algorithm: &'static str,
        /// What about it is unusable.
        reason: &'static str,
    },

    /// The `SpcIndirectDataContent` could not be read.
    ///
    /// This is the structure the signature is over: it names the digest
    /// algorithm and the digest of the file. Without it there is no stated file
    /// digest to check, so no amount of cryptography further on can mean
    /// anything.
    #[error("the SpcIndirectDataContent could not be read: {reason}")]
    BadIndirectData {
        /// Which part of the structure was wrong.
        reason: &'static str,
    },

    /// The file is not a PE, so it has no Authenticode digest.
    #[error("the file is not a PE image, so it has no Authenticode digest")]
    NotPe,

    /// The PE headers describe a digest region that is not inside the file.
    ///
    /// Separate from [`AuthError::NotPe`] because the file *is* a PE: the
    /// headers are structurally sound enough to parse and describe sections or
    /// a certificate table that do not fit. Clamping the region to the file
    /// would produce a digest over bytes the signer never hashed, which is a
    /// number that agrees with nothing and would be reported as a mismatch
    /// against a file whose real problem is its headers.
    #[error("the PE headers describe a region outside the file: {reason}")]
    BadDigestRegion {
        /// Which part of the description does not fit.
        reason: &'static str,
    },

    /// A counter-signature is present and could not be read or verified.
    ///
    /// Distinguishing this from "there is no counter-signature" matters because
    /// the caller's next step differs: no counter-signature means the signer's
    /// validity is judged at the current time, while an unreadable one means the
    /// question cannot be answered. See [`crate::timestamp`].
    #[error("the counter-signature could not be verified: {reason}")]
    BadTimestamp {
        /// What about the token was wrong.
        reason: &'static str,
    },

    /// The certificate store could not be opened.
    ///
    /// The only variant about the *machine* rather than about the file. It is
    /// deliberately not an [`std::io::Error`]: this type is `Clone + PartialEq`
    /// because verdicts are compared in tests and carried in reports, and
    /// `io::Error` is neither. The cost is the lost `source` chain on a variant
    /// whose callers log it verbatim.
    #[error("the certificate store could not be read: {reason}")]
    Store {
        /// What the platform said, rendered.
        reason: String,
    },

    /// The chain engine refused to build a chain at all.
    ///
    /// Separate from a chain that was built and rejected. An engine that could
    /// not produce a chain — because the signer's issuer is not installed, or a
    /// certificate in the path is malformed — has not said the chain is bad, and
    /// the verdicts they lead to are different: this one is `Undetermined`, a
    /// rejected chain is `Untrusted`.
    #[error("no chain could be built for the signer's certificate: {reason}")]
    NoChain {
        /// What the platform said, rendered.
        reason: String,
    },
}

impl AuthError {
    /// Whether this means "the file does not have one", as opposed to "what it
    /// has is broken".
    ///
    /// The same distinction [`SignatureError::is_absence`] makes, and for the
    /// same reason: a caller deciding whether to report a parse failure to a
    /// user needs to know that most files on disk land on the `true` side.
    pub fn is_absence(&self) -> bool {
        matches!(self, AuthError::Absent)
    }

    /// A short label for logs and reports.
    ///
    /// Deliberately not [`ToString`]: the `Display` form carries a sentence for
    /// a human, and this is the token a scan report or a log line groups on.
    /// Making them the same function would mean either a log line with a
    /// sentence in it or a sentence that reads like a token.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::Absent => "no-signature",
            AuthError::Malformed(_) => "malformed-blob",
            AuthError::NotSignedData { .. } => "not-signed-data",
            AuthError::NoSigner => "no-signer",
            AuthError::SignerCertificateAbsent => "signer-absent",
            AuthError::NoSignedAttributes => "no-signed-attributes",
            AuthError::UnsupportedSignatureAlgorithm { .. } => "unsupported-signature-algorithm",
            AuthError::UnsupportedDigestAlgorithm { .. } => "unsupported-digest-algorithm",
            AuthError::UnusableKey { .. } => "unusable-key",
            AuthError::BadIndirectData { .. } => "bad-indirect-data",
            AuthError::NotPe => "not-pe",
            AuthError::BadDigestRegion { .. } => "bad-digest-region",
            AuthError::BadTimestamp { .. } => "bad-timestamp",
            AuthError::Store { .. } => "store-unreadable",
            AuthError::NoChain { .. } => "no-chain",
        }
    }
}

/// Which of the required equalities failed.
///
/// Every variant is a *positive* finding: the structure was read all the way
/// through and the comparison was made. That is what separates these from
/// [`AuthError`], and it is why they are a different type rather than more
/// variants of it — a caller that has one of these knows the file has a
/// signature, that the signature was readable, and exactly which step rejected
/// it.
///
/// It derives [`thiserror::Error`] for the `Display` it generates and not to be
/// an error: a finding is something a report has to print, and a second
/// hand-written rendering of the same numbers would be a second place for the
/// same sentence to drift. Nothing in this crate returns one of these as an
/// `Err`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidReason {
    /// The signature does not verify against the signer's public key.
    ///
    /// The signed attributes were reconstructed and the RSA operation over them
    /// did not produce the encoding it must. Either the file's signature block
    /// was altered after signing, or the signature was never valid. Nothing
    /// further down is examined, because everything further down depends on the
    /// attributes having been proven.
    #[error("the signature does not verify against the signer's public key")]
    SignatureDoesNotVerify,

    /// The signer's signature is over different attributes from the ones the
    /// blob carries.
    ///
    /// The `messageDigest` attribute is supposed to be the hash of the content
    /// the signer signed. When it is not, the attributes in the blob are not the
    /// ones that were signed — an attacker who can alter the attributes can
    /// alter the file digest inside them.
    #[error("the signed attributes' digest is {found}, and the content hashes to {expected}")]
    ContentDigestMismatch {
        /// The digest the attribute claims.
        found: String,
        /// The digest the content actually has.
        expected: String,
    },

    /// The digest the signature commits to is not the digest of this file.
    ///
    /// **This is the variant a tampered file produces.** The signature is
    /// intact, the certificate is the real signer's, and the bytes on disk are
    /// not the bytes that were signed — which is what a byte flipped inside a
    /// section's raw data looks like from here. It is the one finding in this
    /// type that is about the *file* rather than about the signature block, and
    /// it is the reason byte-flipping tests exist.
    #[error("the signature is over file digest {expected}, and this file hashes to {computed}")]
    FileDigestMismatch {
        /// The digest the `SpcIndirectDataContent` states.
        expected: String,
        /// The digest this file's Authenticode image digest actually is.
        computed: String,
    },

    /// The file digest is stated, and over a region this verifier cannot
    /// reproduce.
    ///
    /// Reached when the `SpcIndirectDataContent` carries the optional page-hash
    /// form or a digest of something other than the whole image. A verifier that
    /// hashed the whole file anyway and compared would be comparing against a
    /// number that was never meant to be that, so it reports that it cannot
    /// reproduce the region instead of reporting a mismatch it invented.
    #[error("the signature is over a region this verifier does not reproduce: {reason}")]
    UnsupportedDigestScope {
        /// Which form of the digest was found.
        reason: &'static str,
    },
}

impl InvalidReason {
    /// A short label for logs and reports.
    pub fn code(&self) -> &'static str {
        match self {
            InvalidReason::SignatureDoesNotVerify => "signature-invalid",
            InvalidReason::ContentDigestMismatch { .. } => "content-digest-mismatch",
            InvalidReason::FileDigestMismatch { .. } => "file-digest-mismatch",
            InvalidReason::UnsupportedDigestScope { .. } => "unsupported-digest-scope",
        }
    }
}

/// Why a signature that covers this file is nevertheless not trusted.
///
/// Every variant here means the signature *verified* — the file is the file the
/// signer signed — and the reason it still cannot clear a detection. Keeping
/// these apart from [`InvalidReason`] is what stops "signed by a certificate
/// nobody trusts" being reported as "tampered": the first is a weak signal, the
/// second is a strong one, and a scanner that confused them would either discard
/// detections on self-signed malware or accuse Microsoft of tampering.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UntrustedReason {
    /// The chain does not end at a certificate this machine trusts.
    ///
    /// The ordinary case for a self-signed binary, and for one signed by a
    /// certificate from a CA outside the Windows root programme. It is not an
    /// accusation: an in-house build signed with an internal CA lands here, and
    /// the correct treatment of it is "no trust signal", not "malware".
    #[error("the signer's chain does not end at a trusted root")]
    NoTrustedRoot,

    /// The chain engine rejected the chain, and said why.
    ///
    /// Carries the platform's status bits rather than a hand-written summary,
    /// because the summary would be this crate's opinion about the platform's
    /// policy. `status` is the raw bitmask and `named` its decoded names, so a
    /// log line can be read by a person and the bits re-checked against
    /// Microsoft's documentation without trusting the rendering.
    #[error("the chain engine rejected the chain: {named} ({status})")]
    ChainRejected {
        /// The error-status bitmask, in hex.
        status: String,
        /// The bits that were set, decoded to their symbolic names.
        named: String,
    },

    /// The signer's certificate was outside its validity period.
    ///
    /// Reached only when there is no counter-signature to move the judgement
    /// to, or when the counter-signature's own time is outside the period. The
    /// time the chain was judged *at* is carried, because that is the whole
    /// content of the finding: a certificate that expired last year is fine if
    /// a timestamp says the file was signed the year before, and the difference
    /// between the two cases is exactly this field. It is 30.5% of the measured
    /// `System32` population, so it is not a corner.
    #[error("the signer's certificate was valid from {} to {}, and the chain was judged at {}", At(*not_before), At(*not_after), At(*judged_at))]
    OutsideValidity {
        /// The certificate's `notBefore`, in Unix seconds.
        not_before: i64,
        /// The certificate's `notAfter`, in Unix seconds.
        not_after: i64,
        /// The moment the chain was judged at, in Unix seconds.
        judged_at: i64,
    },

    /// The signer's certificate is not permitted to sign files.
    ///
    /// Checked here rather than delegated, because it is a fact about the
    /// certificate's *stated purpose* rather than about the platform's trust
    /// policy, and because it is the difference between "signed by a certificate
    /// that chains to a root" and "signed by a code-signing certificate". A TLS
    /// server certificate is issued by a trusted CA and must not be able to
    /// clear a detection on an executable.
    #[error("the signer's certificate is not valid for code signing: {detail}")]
    WrongPurpose {
        /// Which extension excluded it.
        detail: &'static str,
    },

    /// The signature algorithm is one this verifier does not implement.
    ///
    /// Carried as untrusted rather than as an error because the signature *was*
    /// read and the file *was* digested — what is missing is the ability to
    /// check the one operation that ties them together. It is a refusal to
    /// certify, not a claim of forgery, and the two are different answers about
    /// a file that a caller acts on differently.
    #[error("the signature algorithm `{oid}` is not implemented, so this file is not assessed")]
    UnsupportedAlgorithm {
        /// The algorithm identifier's OID, dotted.
        oid: String,
    },

    /// The signature is valid and the signer's certificate has expired since.
    ///
    /// No counter-signature was present to show the file was signed *before* the
    /// expiry, so the file cannot be placed before the certificate's end. Named
    /// separately from [`UntrustedReason::OutsideValidity`] because the signer
    /// demonstrably *was* entitled when the certificate was issued — what is
    /// missing is the evidence of *when* this file was signed, which is a
    /// sentence a user can act on.
    #[error("the signer's certificate expired at {} and the file carries no counter-signature", At(*not_after))]
    ExpiredWithoutTimestamp {
        /// The certificate's `notAfter`, in Unix seconds.
        not_after: i64,
    },
}

impl UntrustedReason {
    /// A short label for logs and reports.
    pub fn code(&self) -> &'static str {
        match self {
            UntrustedReason::NoTrustedRoot => "no-trusted-root",
            UntrustedReason::ChainRejected { .. } => "chain-rejected",
            UntrustedReason::OutsideValidity { .. } => "outside-validity",
            UntrustedReason::WrongPurpose { .. } => "wrong-purpose",
            UntrustedReason::UnsupportedAlgorithm { .. } => "unsupported-algorithm",
            UntrustedReason::ExpiredWithoutTimestamp { .. } => "expired-without-timestamp",
        }
    }
}

/// A hex rendering of a byte string, lower case, for a digest or a thumbprint.
///
/// Lives here rather than in a caller because both [`InvalidReason`] and the
/// proof report one, and two implementations would eventually disagree about
/// case or separators — which matters when the strings end up in a log a person
/// compares by eye against `certutil`'s output.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// A helper for the times in these variants, which are raw `i64` seconds.
///
/// Kept as a free function rather than a method so the variants stay plain data
/// — a caller matching on one gets numbers it can format however its report
/// needs, rather than a pre-templated string.
pub(crate) struct At(pub i64);

impl fmt::Display for At {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The date comes from `av-signatures`' civil-date arithmetic, which is
        // the code that already renders a `UTCTime` for a report and is the one
        // place in the workspace where the leap-year rule lives. Only the time
        // of day is computed here, and that part is a division because a Unix
        // day is exactly 86 400 seconds.
        let (year, month, day) = av_signatures::UnixTime(self.0).civil();
        let day_seconds = self.0.rem_euclid(86_400);
        write!(
            f,
            "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC (unix {})",
            day_seconds / 3_600,
            (day_seconds / 60) % 60,
            day_seconds % 60,
            self.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lower_case_and_two_digits_per_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn absence_is_the_only_absence() {
        assert!(AuthError::Absent.is_absence());
        assert!(!AuthError::NotPe.is_absence());
        assert!(!AuthError::Malformed(SignatureError::Empty).is_absence());
        // The two errors that are about the machine rather than the file are
        // still not "absent": a caller that skipped a file because the store
        // failed would be reporting the wrong thing.
        assert!(!AuthError::Store { reason: "x".into() }.is_absence());
    }

    #[test]
    fn every_variant_has_a_distinct_code() {
        // The codes are what a report groups on, so two variants sharing one
        // would merge two findings that a reader needs to tell apart.
        let all = [
            AuthError::Absent,
            AuthError::Malformed(SignatureError::Empty),
            AuthError::NotSignedData { reason: "x" },
            AuthError::NoSigner,
            AuthError::SignerCertificateAbsent,
            AuthError::NoSignedAttributes,
            AuthError::UnsupportedSignatureAlgorithm { oid: "1".into() },
            AuthError::UnsupportedDigestAlgorithm { oid: "1".into() },
            AuthError::UnusableKey {
                algorithm: "RSA",
                reason: "x",
            },
            AuthError::BadIndirectData { reason: "x" },
            AuthError::NotPe,
            AuthError::BadDigestRegion { reason: "x" },
            AuthError::BadTimestamp { reason: "x" },
            AuthError::Store { reason: "x".into() },
            AuthError::NoChain { reason: "x".into() },
        ];
        let mut codes: Vec<&str> = all.iter().map(AuthError::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "two AuthError variants share a code");

        let invalid = [
            InvalidReason::SignatureDoesNotVerify,
            InvalidReason::ContentDigestMismatch {
                found: "a".into(),
                expected: "b".into(),
            },
            InvalidReason::FileDigestMismatch {
                expected: "a".into(),
                computed: "b".into(),
            },
            InvalidReason::UnsupportedDigestScope { reason: "x" },
        ];
        let mut codes: Vec<&str> = invalid.iter().map(InvalidReason::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(
            codes.len(),
            before,
            "two InvalidReason variants share a code"
        );

        let untrusted = [
            UntrustedReason::NoTrustedRoot,
            UntrustedReason::ChainRejected {
                status: "0x1".into(),
                named: "x".into(),
            },
            UntrustedReason::OutsideValidity {
                not_before: 0,
                not_after: 1,
                judged_at: 2,
            },
            UntrustedReason::WrongPurpose { detail: "x" },
            UntrustedReason::UnsupportedAlgorithm { oid: "1".into() },
            UntrustedReason::ExpiredWithoutTimestamp { not_after: 0 },
        ];
        let mut codes: Vec<&str> = untrusted.iter().map(UntrustedReason::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(
            codes.len(),
            before,
            "two UntrustedReason variants share a code"
        );
    }
}
