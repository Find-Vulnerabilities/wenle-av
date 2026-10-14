//! Authenticode signatures, read far enough to answer what a rule asks.
//!
//! # What this is for
//!
//! Rules in the corpus identify a signed sample by who signed it:
//!
//! ```text
//! uint16(0) == 0x5a4d and
//! for any i in ( 0 .. pe.number_of_signatures ) : (
//!     pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
//!     pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8" and
//!     ( pe.signatures[i].not_before > 1706486400 or pe.timestamp > 1706486400 ) )
//! ```
//!
//! 1,601 rules in this corpus do something of that shape, which is the largest
//! single lever in the rule set. Reading a certificate is therefore not a feature
//! bolted on beside the scanner; it is a third of what the scanner is for.
//!
//! The prediction was checked against the corpus rather than assumed. Rule
//! coverage went from 8,766 of 10,764 (81.44%) compiled to 10,366 (96.30%) when
//! these members landed: 1,600 rules, one short of the 1,601 that reference a
//! signature member, the difference being a rule refused for an unrelated
//! reason. What was refused afterwards was 398 rules across four features, none
//! of them a certificate.
//!
//! The import, export and imphash members then took that to 10,612 of 10,764
//! (98.59%), leaving 152 refused. Every one of the remaining features is a
//! different module, not a certificate: `hash.*` and `math.*` calls, the
//! resource and version-info directories, the .NET metadata, and the two loops
//! that iterate a module array or name another rule.
//!
//! The import lever measured 10,629 once, and the number is lower now because
//! that count was wrong. String refusals were recorded only for rules whose
//! *condition* had already compiled, and the rule was admitted either way. So
//! 133 rules that could not search one of their own strings were being counted
//! as compiled. That is unsound in both directions: `$a and $b` with `$b`
//! refused is a detection that never fires, and `not $b` with `$b` refused is a
//! condition true on every file. Both are now refused, which costs 133
//! detections and buys a count that means what it says.
//!
//! # What is parsed, and what is deliberately not
//!
//! The path from a file to a field is four layers deep, and each one is
//! attacker-controlled:
//!
//! ```text
//! PE optional header  ->  attribute certificate table  ->  WIN_CERTIFICATE
//!     ->  PKCS#7 SignedData  ->  X.509 Certificate  ->  the field a rule reads
//! ```
//!
//! Every layer is bounds-checked, every failure is a `Result` rather than a
//! panic, and the failures are typed so that "this file has no signature" (which
//! is most files) stays distinct from "this file's signature is
//! malformed", which is worth reporting.
//!
//! **Signature verification is not implemented, and `.verified` is not
//! exposed.** That is a decision, not an omission. Verifying Authenticode means
//! implementing the whole chain-validation path: trust anchors, expiry at
//! signing time, revocation, the countersignature over the `SpcIndirectData`
//! digest, and the rules about which of those failures are fatal. A member that
//! answered that question *wrongly* is worse than one that refuses to answer:
//! `not pe.signatures[i].verified` written by someone expecting real
//! verification would select every file on the disk. The rule compiler refuses
//! the member instead, so the failure is a rule that does not load rather than
//! a verdict that is confidently inverted.
//!
//! # The other half: catalogs
//!
//! Reading a file's own signature reaches far less of Windows than it sounds
//! like it should. Measured over an installed `System32`, 3,331 of its DLLs are
//! signed by *catalog* and 71 by an embedded signature. The signature is not in
//! the file but in a `.cat` in `CatRoot`, which names the file by digest.
//! [`catalog`] reads those, which is what makes the trust layer reach the
//! population it exists for.
//!
//! # No cryptography beyond hashing
//!
//! Two hashes are computed anywhere here: SHA-1 for a certificate's thumbprint,
//! and SHA-1 or SHA-256 for a file's catalog digest. Both are *identifiers*: the
//! thumbprint names a certificate, the catalog digest names a file. Neither is a
//! security boundary this crate enforces, because no signature is
//! verified anywhere in it. There is no RSA or ECDSA code, no big-integer
//! arithmetic, and no timing-sensitive comparison. What it does is parse, which
//! is the part that has to be safe against a hostile file, and parsing is where
//! the tests are.
//!
//! That a digest is not a boundary is worth being exact about, because catalog
//! membership *is* used as a trust signal. What a match establishes is that the
//! file digests to a value listed in a catalog sitting in the catalog store.
//! Nothing here checks that the catalog's own signature is valid, and nothing
//! here checks that the store has not been written to, and an administrator can
//! put a `.cat` there. Both are handled where the signal is *used*: the trust
//! policy reads the signer out of the catalog and puts it through the same
//! authority check an embedded certificate goes through, and a trust signal can
//! only ever discount a score, never convict. See [`catalog`]'s own
//! documentation for the full statement.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
// Unwrapping is how a test asserts. The workspace lint stays on for the
// library, where a panic on a malformed file is a denial of service, and is
// relaxed here rather than by sprinkling `allow` over a hundred test bodies.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod authenticode;
pub mod catalog;
mod catalog_cache;
pub mod der;
pub mod error;
pub mod name;
pub mod oid;
pub mod pkcs7;
pub mod testing;
pub mod time;
pub mod x509;

pub use error::SignatureError;
pub use time::UnixTime;
pub use x509::Certificate;

use av_pe::PeFile;

/// Every certificate in a PE's attribute certificate table, in file order.
///
/// The one function most callers want. Returns an empty list for a file with no
/// signature, which is the ordinary case: of the executables on a normal
/// Windows installation, the large majority are unsigned, and making that an
/// error would make the common path the error path.
pub fn certificates<'a>(pe: &PeFile<'a>) -> Vec<Certificate<'a>> {
    authenticode::certificates(pe)
}

/// Whether a PE carries a signature that could be read.
///
/// Distinct from "has a signature": a file whose attribute certificate table is
/// present but malformed answers `false` here, and a scan report can say so.
/// The distinction matters to a user asking why a signed file was flagged.
pub fn has_readable_signature(pe: &PeFile<'_>) -> bool {
    pe.security_directory_data()
        .map(authenticode::is_parseable)
        .unwrap_or(false)
}
