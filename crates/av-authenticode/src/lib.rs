//! Authenticode verification: turning "this file claims to be signed by
//! Microsoft" into "this file *is* what Microsoft signed".
//!
//! # The false positive this exists to fix
//!
//! `C:\Windows\System32\MRT.exe`, Microsoft's own Malicious Software Removal
//! Tool, is flagged as suspicious by this product. That is not a bug in the
//! rules. MRT carries malware signature strings *by design*, so a rule that
//! looks for those strings is right about the bytes and wrong about the file.
//! The file is Authenticode-signed by `CN=Microsoft Windows, O=Microsoft
//! Corporation`.
//!
//! [`av_signatures`] reads that signature and reports the signer. The trust
//! layer nevertheless refuses to let it clear the detection, and **that refusal
//! is correct**. An embedded certificate is a *claim*: the certificate block is
//! bytes in a file, and anyone can copy Microsoft's bytes into their own
//! program. Clearing a file because it carries a certificate would be a one-line
//! bypass of the whole trust system. Paste the block out of `MRT.exe` into your
//! malware and it is trusted.
//!
//! The only thing that separates the two is the signature over the file, checked
//! against the public key in that certificate. That is what this crate does, and
//! why it exists rather than a certificate comparison.
//!
//! # What "proof" means here, exactly
//!
//! Four equalities, in order. Each one is mandatory, and a file has to satisfy
//! all of them for the verdict to be [`Verdict::Trusted`]:
//!
//! 1. **The signature over the signed attributes.** `SignerInfo.signature` is
//!    verified with the signer's public key over the DER of
//!    `SignerInfo.signedAttrs` with the implicit `[0]` tag rewritten to `SET`.
//!    This is what makes the attributes unforgeable, the digest in step 2
//!    included.
//! 2. **The content digest.** The `messageDigest` attribute must equal the hash
//!    of `encapContentInfo.eContent`, the DER of the `SpcIndirectDataContent`.
//!    This binds the signature to the structure that names a file digest.
//! 3. **The file digest.** The digest inside that `SpcIndirectDataContent` must
//!    equal the Authenticode **PE image digest** of the file on disk, which is
//!    not a hash of the file; see [`digest`]. This is the step that binds the
//!    signature to *these bytes*, and the one that fails when a byte is changed.
//! 4. **A chain to a trusted root.** The signer's certificate must be issued by
//!    a certificate that is issued by ... up to a self-issued certificate in
//!    the Windows root store. Every link's signature is verified here; only the
//!    *set of roots* comes from the operating system.
//!
//! A verifier that answered `true` for everything would pass step 3 on exactly
//! the files it is supposed to catch. That is why the negative controls in the
//! test suite, a signed binary with one byte flipped, are the tests that make
//! the positive ones mean anything.
//!
//! # Why the cryptography is this crate's own, and where the platform is asked
//!
//! Two routes were on the table, and they divide the job differently.
//!
//! **`WinVerifyTrust`** answers the whole question (file, digest, signature and
//! chain) in one call from `wintrust.dll`. It is not forbidden by anything: the
//! product's no-cloud rule is about where a *verdict* comes from, and that call
//! has flags (`WTD_CACHE_ONLY_URL_RETRIEVAL`, `WTD_REVOKE_NONE`, `WTD_UI_NONE`)
//! that keep it off the network. It was measured against the route below over
//! every file in an installed `System32` and rejected **on the measurement**,
//! not on principle. The numbers and the taxonomy are in [`chain`]; the short
//! form is that it fails on exactly the files whose chain needs a certificate
//! the file itself carries, and it does not say which of the four equalities
//! failed when it fails at all.
//!
//! **What is done here** splits it. `CertGetCertificateChain` from `crypt32`
//! builds the path and says whether its anchor is trusted (that is [`store`],
//! and it is asked because the set of roots is OS policy and not this crate's to
//! hold), while everything about the *file* is this crate's own arithmetic. The
//! signature over the attributes, the content digest, the Authenticode image
//! digest and the comparison against the stated one are all [`rsa`], [`cms`] and
//! [`digest`], and none of them is a call into the platform.
//!
//! The reason for that split is the product's own rule: a verdict this engine
//! acts on has to be this engine's verdict, reasoning it can state, log and
//! bound. "The operating system said there is a valid signature" is not a
//! sentence a scan report can give a user, and it is not a sentence this crate
//! can log a *reason* for. It is one bit. The sentence a report needs is "the
//! signature over this file verifies against `CN=Microsoft Windows`, and its
//! chain reaches `CN=Microsoft Root Certificate Authority 2010`", and that
//! sentence is assembled here.
//!
//! The scope of the cryptography was measured before it was written, over the
//! embedded-signed files in an installed `System32`:
//!
//! | what | measured |
//! |---|---|
//! | signature algorithm | RSA PKCS#1 v1.5, every one |
//! | signer key | `rsaEncryption`, none EC |
//! | content digest | SHA-256, with a handful of SHA-1 and one SHA-384 |
//! | counter-signature | RFC 3161 almost always; the legacy form on a few |
//! | self-signed root in the blob | none |
//! | leaf already expired | **about a third** |
//!
//! Two of those rows decide the design. No blob contains a root, so path
//! building against the OS store is required rather than optional. And a third
//! of the population carries an expired leaf, so the RFC 3161 counter-signature
//! is not a refinement. Without it a third of `System32` would be reported
//! expired, which is the wrong answer and exactly the kind of wrong answer that
//! produces a false positive on a Microsoft binary.
//!
//! What the same table says about what to *leave out* is just as load-bearing:
//! ECDSA is not implemented, because no certificate in the measured population
//! uses an EC key. The exact counts, and the probe that produced them, are in
//! [`chain`].
//!
//! # The trust boundary
//!
//! The set of roots is operating-system policy and is read from the Windows
//! certificate store ([`store`]). Rebuilding that list inside an antivirus
//! would be both wrong and a liability: it is a list maintained by Microsoft and
//! the CAs, updated by Windows Update, and a stale copy is a security hole
//! rather than a portability win. Reading it is asking the OS *which
//! certificates it trusts*, which is a fact about the machine. The question
//! *"is this signature good?"* is answered here, by
//! [`rsa`], [`digest`] and [`chain`], and nowhere else.
//!
//! On a non-Windows target the root list is empty, not guessed at: every chain
//! then fails to reach a trusted root and the verdict is
//! [`Verdict::Untrusted`]. That is the only answer available to a build with no
//! trust anchors, and it is not the same as [`Verdict::Unsigned`].
//!
//! # What is not implemented
//!
//! Naming these is part of the API rather than a footnote, because a caller that
//! assumed any of them was checked would be trusting something this crate never
//! looked at.
//!
//! * **Revocation.** No CRL is fetched and no OCSP responder is asked, so a
//!   certificate revoked yesterday still validates today. This is the same trade
//!   `WinVerifyTrust`'s cache-only mode makes, forced by the product's no-cloud
//!   constraint, and it is why [`Verdict::Trusted`] means "this file is what the
//!   named signer signed" rather than "the signer is currently in good
//!   standing". The direction matters and is why this is stated here rather than
//!   left to the caller: [`Verdict::Trusted`] is evidence *for* a file and never
//!   against one, so a caller may use it to discount or to clear a detection but
//!   never to convict. Using it at all is the caller's policy, and what the
//!   caller is handing over is a statement about a publisher and not about a
//!   file's behaviour.
//! * **ECDSA and EdDSA.** RSA PKCS#1 v1.5 only. Zero of the 1649 certificates in
//!   the measured population use anything else, and an algorithm nobody signs
//!   with is code nobody exercises. A signature using one is refused by name
//!   ([`UntrustedReason::UnsupportedAlgorithm`]) rather than silently reported
//!   as invalid, so a future file that needs it says so.
//! * **Page hashes and the SIP.** A signature may carry per-page hashes so the
//!   loader can validate pages independently, and a file signed twice carries a
//!   nested signature. Both are *extra* structures: a signature that has them
//!   still verifies without them, against the whole file, which is the stronger
//!   check. Ignoring them can only refuse a file, never accept one.
//! * **The legacy counter-signature is verified**, not ignored, but through its
//!   own shape rather than RFC 3161's: see [`timestamp`].
//!
//! # The verdict
//!
//! [`Verdict`] is an enum with five states rather than a boolean, and the splits
//! are the point:
//!
//! * [`Verdict::Unsigned`]: no signature. The ordinary case for most files.
//! * [`Verdict::Undetermined`]: a signature *is* there and could not be read all
//!   the way through, or needs a check this crate does not implement. Distinct
//!   from `Unsigned` because it is a different thing to tell a user, and
//!   distinct from `Invalid` because nothing was proved either way.
//! * [`Verdict::Invalid`]: the signature was read and does **not** cover this
//!   file. The tampered case.
//! * [`Verdict::Untrusted`]: the signature verifies over this file, and the
//!   signer traces to no root this machine trusts.
//! * [`Verdict::Trusted`]: all four equalities hold.
//!
//! `Unsigned`, `Undetermined` and `Invalid` are three different answers to "is
//! there a signature and does it hold", and collapsing any two of them is the
//! mistake this type exists to prevent. A scanner that conflated `Untrusted`
//! with `Unsigned` would report a tampered file as merely unsigned.

#![warn(missing_docs)]
// `unsafe` appears in exactly one module, `store`, and only to walk a
// certificate store with the Win32 enumeration API. Everything else is safe
// Rust, and the DER reader this crate is built on is `forbid(unsafe_code)` in
// its own crate.
#![cfg_attr(not(windows), allow(unused))]
// Unwrapping is how a test asserts. The workspace lint stays on for the library,
// where a panic on a malformed file is a denial of service — this parser reads
// bytes chosen by whoever wrote the file, and the workspace has already been
// bitten by a panic-on-malformed-input.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod chain;
pub mod cms;
pub mod digest;
pub mod error;
pub mod oid;
pub mod rsa;
pub mod spc;
pub mod store;
pub mod timestamp;
pub mod verdict;
pub mod verify;
pub mod x509;

/// Big-integer arithmetic, existence-proof sized.
///
/// Private, because the only thing anyone should be able to ask for is "does
/// this signature verify", which [`rsa`] answers. A public modular
/// exponentiation would be an invitation to build something else out of it, and
/// something else built out of it would not have the tests this has.
mod bigint;

/// DER encoders the tests build fixtures with.
///
/// `cfg(test)` and not a feature: a fixture builder shipped in a library is a
/// second encoder for the same structures that nothing in production uses, and
/// the tests that need a *real* signature use real files — see the tests in
/// [`verify`] — rather than a fixture that this crate signed with itself.
#[cfg(test)]
mod testing;

pub use digest::DigestAlgorithm;
pub use error::AuthError;
pub use verdict::{InvalidReason, Proof, UntrustedReason, Verdict};
pub use verify::{verify, verify_bytes};
