//! Trust: the evidence that discounts a weak detection.
//!
//! # What trust is allowed to do
//!
//! A heuristic that says "this file is packed" is a probabilistic statement
//! about how the file was built. A valid Authenticode signature from a real
//! publisher is evidence about exactly that question, and an engine that
//! ignores it flags every copy-protected game, every packed installer and every
//! binary that ships with a security product. So trust discounts those
//! detections — and only those.
//!
//! # What trust is not allowed to do
//!
//! It has no standing against a detection that says what the file *is*. A rule
//! that names a family — `Win32.Ransom.LockBit` — is not a statement about how
//! the file was built, and no code-signing certificate makes a file not be
//! LockBit. Stolen certificates exist, and "signed by someone" is precisely the
//! property a competent attacker arranges to have. So a detection that names a
//! family, or that is marked decisive, is never discounted by a single point,
//! whatever the file is signed with.
//!
//! The rest of this module follows from that one distinction. Read
//! [`TrustPolicy::discount`] for the arithmetic, and note that the arithmetic
//! is bounded twice over: a percentage of the score trust has standing on, and
//! an absolute ceiling no combination of reasons can raise.
//!
//! # The honest limitation, and where the line now is
//!
//! There are two signature signals here and they are **not** the same evidence.
//! Which one a file gets decides what trust may do with it, so the line between
//! them is the most important thing in this module:
//!
//! * **A certificate that was read** — [`TrustReason::KnownAuthority`],
//!   [`TrustReason::UnknownAuthority`], [`TrustReason::StaleCertificate`]. This
//!   is a *claim*. Nothing was verified: the certificate parsed, its dates
//!   contain the present, and its issuer string is a name a public CA uses.
//!   A forged certificate saying `CN=Microsoft Windows` earns exactly the 40
//!   points a real one does, because it is the same string. Worth a discount,
//!   never a suppression.
//!
//! * **A signature that was verified** — [`TrustReason::VerifiedSignature`],
//!   which [`mod@av_authenticode::verify`] produces only when four things hold, in
//!   order: the RSA signature verifies over the signer's signed attributes
//!   against the public key in the signer's own certificate; the `messageDigest`
//!   attribute is the hash of the encapsulated content those attributes cover;
//!   the digest inside that content is the Authenticode image digest of **this
//!   file's bytes**; and the platform's own chain engine reaches a root this
//!   machine trusts. The third is the tamper check and the fourth is what makes
//!   the first three mean a publisher rather than a number. This is a *proof*,
//!   in the same sense [`TrustReason::CatalogSigned`] is, and it is entitled to
//!   the same response.
//!
//! Nothing in this module reads a certificate to decide that a signature is
//! verified. The two paths are separate functions over separate evidence, and
//! `Verdict::Trusted` — the only verdict that yields the second reason — is
//! constructed on exactly one line of one function in `av-authenticode`, after
//! every check has passed. "A signature is present and parses" cannot reach it.
//!
//! What is still *not* checked, on either path: **revocation**. Neither the
//! catalog path nor this one consults a CRL or an OCSP responder, so a
//! certificate revoked after the file was signed is treated as good. That is a
//! deliberate choice about a scan that has to work with no network, and it is
//! stated here rather than buried, because it is the one way a verified
//! signature is weaker than it sounds.
//!
//! The 40-point claim being unverifiable is why the discount is a discount and
//! not a suppression. For a file whose signature *was* verified, the answer is
//! different, and [`TrustPolicy::clear_generic`] says so.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use av_core::{Assessment, Detection, DetectionSource, Severity, Verdict};
use av_rules::vm::PeInput;
use av_signatures::catalog::CatalogIndex;

/// How much standing a piece of evidence has.
///
/// Additive, and only the strongest of each kind counts: a path is either in a
/// trusted directory or it is not, however many trusted directories contain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustReason {
    /// A certificate that parses, is currently valid, and was issued by a name
    /// a public certificate authority uses.
    KnownAuthority {
        /// The certificate's subject, as the certificate spells it.
        subject: String,
        /// The issuing authority, matched against the known list.
        issuer: String,
    },
    /// A certificate that parses and is currently valid, from an issuer this
    /// product does not recognise — a private CA, an internal PKI, or a
    /// self-signed certificate anyone can produce in a minute.
    UnknownAuthority {
        /// The certificate's subject.
        subject: String,
        /// The issuer, recorded so a user can see who it actually was.
        issuer: String,
    },
    /// A certificate that parses, from an issuer that is recognised, whose
    /// validity window does not contain the present.
    StaleCertificate {
        /// The certificate's subject.
        subject: String,
    },
    /// The file's own bytes digest to a value a **catalog** lists, and that
    /// catalog names a recognised authority.
    ///
    /// A different kind of statement from [`TrustReason::KnownAuthority`], and a
    /// strictly stronger one. A certificate attached to a file is a *claim*:
    /// nothing in this product verifies it, and a self-signed certificate whose
    /// own issuer reads `CN=Microsoft Root Certificate Authority 2010` is
    /// recognised by the same substring test a real chain is. A catalog entry is
    /// a *proof of identity*: matching one means these bytes are the bytes
    /// somebody hashed, and producing a file that matches a digest already in
    /// the store needs a preimage, not a certificate.
    ///
    /// That difference is why the two are not the same variant with different
    /// magnitudes — see [`TrustPolicy::clear_generic`], which the proof is
    /// entitled to and the claim is not.
    CatalogSigned {
        /// The catalog's signing certificate's subject.
        subject: String,
        /// The recognised authority found in the catalog's chain.
        authority: String,
    },
    /// The file's bytes digest to a value a catalog lists, but nothing in that
    /// catalog's chain is an authority this product recognises.
    ///
    /// Worth nothing, and recorded rather than dropped because it is a different
    /// fact from "no catalog lists this file" and the two point at different
    /// explanations: an OEM's catalog signed by a CA this product does not know,
    /// or a catalog somebody put in the store by hand.
    CatalogUnvouched {
        /// The catalog's signing certificate's subject, as it spells it.
        subject: String,
    },
    /// The file's signature was **cryptographically verified**: the signature
    /// verifies against the signer's public key, the signed structure digests
    /// to what the signature covers, the file's own bytes digest to what that
    /// structure states, and the signer's chain reaches a root this machine
    /// trusts.
    ///
    /// A different kind of statement from every other certificate-based reason
    /// here, and the same kind as [`TrustReason::CatalogSigned`]. The three
    /// reasons above it say a certificate *parsed*; this one says the bytes in
    /// this file were signed by the holder of a private key, and that a chain
    /// from that key's certificate reaches a root the operating system trusts.
    /// Producing a file that earns it needs either the publisher's private key
    /// or a SHA-2 collision — the same bar as a catalog entry, and the reason
    /// the two share [`TrustAssessment::identity_proven`] and its consequences.
    ///
    /// The evidence is produced by [`mod@av_authenticode::verify`], whose
    /// [`av_authenticode::Verdict::Trusted`] is constructed on one line, at the
    /// end, after every equality has held. A file whose signature is merely
    /// present, or present and parseable, cannot produce this reason — it is
    /// what separates this variant from [`TrustReason::KnownAuthority`], and a
    /// caller that confused the two would have made this module weaker while
    /// making it look stronger.
    VerifiedSignature {
        /// The signer's subject, as its certificate spells it.
        subject: String,
        /// The root the chain reached, as the platform renders it.
        ///
        /// The *root* and not the issuer, which is what the claim reasons carry:
        /// a binary's signer is issued by an intermediate, so the leaf's issuer
        /// names the intermediate and says nothing about which anchor the chain
        /// was accepted under. The root is the fact that makes this a proof.
        root: String,
    },
    /// The file is in a directory the user or the product treats as trusted.
    TrustedPath(PathBuf),
    /// The file is in the user's own allowlist.
    UserAllowed,
    /// No signature at all. Not evidence for anything, and recorded because
    /// "why was this not trusted" is a question a report should answer.
    Unsigned,
}

impl TrustReason {
    /// The most this reason can take off a score, before the policy's own
    /// limits are applied.
    ///
    /// Calibrated against [`av_core::VerdictThresholds::default`]: a known
    /// authority is worth more than one [`Severity::Low`] detection and less
    /// than one [`Severity::Medium`], which is the right size — it clears the
    /// noise a signed binary collects without clearing an observation that
    /// took more than one indicator to make.
    pub const fn magnitude(&self) -> i32 {
        match self {
            TrustReason::KnownAuthority { .. } => 40,
            // Above a known authority, because it is a proof rather than a
            // claim — see [`TrustReason::CatalogSigned`]. Still below
            // `max_discount`, so a catalog match cannot erase a score on its
            // own: it takes the same 60-point ceiling any other reason does, and
            // the difference the variant makes is in
            // [`TrustPolicy::clear_generic`], not in the arithmetic.
            TrustReason::CatalogSigned { .. } => 60,
            // The same 60, and the equality is deliberate rather than
            // incidental: both are proofs that bind these bytes to a published
            // key, and neither is a stronger statement about *who* the
            // publisher is than the other. A verified signature needs the
            // publisher's private key; a catalog entry needs a digest that
            // matches one already in the store. The ceiling `max_discount` puts
            // on any single file makes the ordering moot for the arithmetic
            // anyway — what the variant decides is in
            // [`TrustPolicy::clear_generic`], which both are entitled to.
            TrustReason::VerifiedSignature { .. } => 60,
            TrustReason::UnknownAuthority { .. } => 10,
            TrustReason::TrustedPath(_) => 10,
            TrustReason::UserAllowed => 40,
            TrustReason::StaleCertificate { .. }
            | TrustReason::Unsigned
            | TrustReason::CatalogUnvouched { .. } => 0,
        }
    }

    /// A sentence for the scan report.
    pub fn describe(&self) -> String {
        match self {
            TrustReason::KnownAuthority { subject, issuer } => format!(
                "The file is signed by `{subject}`, issued by `{issuer}`. The signature was \
                 parsed, not cryptographically verified."
            ),
            TrustReason::UnknownAuthority { subject, issuer } => format!(
                "The file is signed by `{subject}`, issued by `{issuer}`, which is not a public \
                 certificate authority this product recognises."
            ),
            TrustReason::StaleCertificate { subject } => format!(
                "The file's certificate names `{subject}` and is outside its validity window."
            ),
            TrustReason::CatalogSigned { subject, authority } => format!(
                "The file's own bytes are listed in a catalog signed by `{subject}`, issued under \
                 `{authority}`. This is what Windows means by a catalog-signed file: the bytes are \
                 the bytes that were signed, and producing a file that matches requires breaking \
                 SHA-1 or SHA-256 rather than forging a certificate. The catalog's signature was \
                 parsed, not cryptographically verified."
            ),
            TrustReason::CatalogUnvouched { subject } => format!(
                "The file's bytes are listed in a catalog signed by `{subject}`, whose chain names \
                 no authority this product recognises. A catalog listing a digest proves the bytes \
                 are the ones that were hashed; it is the catalog's own publisher that says who \
                 hashed them, and nothing here vouches for this one."
            ),
            TrustReason::VerifiedSignature { subject, root } => format!(
                "The file is signed by `{subject}` and the signature was verified: the signature \
                 checks against the signer's public key, the file's own bytes digest to the value \
                 the signature commits to, and the signer's chain reaches `{root}`, a root this \
                 machine trusts. Revocation was not checked."
            ),
            TrustReason::TrustedPath(path) => {
                format!(
                    "The file is in {}, which is treated as trusted.",
                    path.display()
                )
            }
            TrustReason::UserAllowed => "The file is on the user's allowlist.".to_owned(),
            TrustReason::Unsigned => "The file carries no readable signature.".to_owned(),
        }
    }
}

/// What a file's trust signals came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAssessment {
    /// The most the reasons justify taking off a score.
    pub magnitude: i32,
    /// Everything that was noticed, including the reasons worth nothing.
    pub reasons: Vec<TrustReason>,
}

impl TrustAssessment {
    /// Whether anything was found that argues for the file.
    pub fn is_trusted(&self) -> bool {
        self.magnitude > 0
    }

    /// The reasons worth showing a user, strongest first.
    ///
    /// [`TrustReason::Unsigned`] is left out: a report listing "this file has no
    /// signature" beside every clean scan of every file on the disk is noise,
    /// and the absence of a signature is already visible from the absence of
    /// anything else. [`TrustReason::CatalogUnvouched`] is left out for the same
    /// reason — it is worth no points and describes most third-party files that
    /// happen to be listed somewhere.
    pub fn reportable(&self) -> impl Iterator<Item = &TrustReason> {
        self.reasons.iter().filter(|reason| reason.magnitude() > 0)
    }

    /// Whether the file's identity is *proven* rather than claimed.
    ///
    /// Two reasons qualify, and they are the two that rest on arithmetic rather
    /// than on a string in a certificate:
    ///
    /// * [`TrustReason::CatalogSigned`] — the file's own bytes digest to a value
    ///   a catalog lists, under a chain naming a recognised authority.
    /// * [`TrustReason::VerifiedSignature`] — the file's own bytes digest to the
    ///   value its signature commits to, and that signature verifies against a
    ///   key whose chain reaches a root this machine trusts.
    ///
    /// Everything else in [`TrustReason`] is a claim: a subject, an issuer, a
    /// path or a user's decision, each of which an attacker with a text editor
    /// can produce. Those are worth a discount and nothing more. This predicate
    /// is what entitles a reason to the stronger response in
    /// [`TrustPolicy::clear_generic`], so adding a variant to it is the single
    /// most consequential edit this module admits.
    pub fn identity_proven(&self) -> bool {
        self.reasons.iter().any(|reason| {
            matches!(
                reason,
                TrustReason::CatalogSigned { .. } | TrustReason::VerifiedSignature { .. }
            )
        })
    }
}

/// How much a file's trust signals are worth.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustPolicy {
    /// Whether to consult trust at all. [`av_core::ScanOptions::trust`] is the
    /// per-scan switch; this is the engine-wide one.
    pub enabled: bool,
    /// Directories whose contents are treated as trusted.
    pub trusted_paths: Vec<PathBuf>,
    /// Issuer names, matched as case-insensitive substrings.
    pub known_authorities: Vec<String>,
    /// What fraction of the discountable score a trust signal removes, in
    /// percent.
    ///
    /// Proportional rather than fixed so that trust cannot clear a score it has
    /// no business clearing: a file with one observation loses a fraction of
    /// one observation's worth, whatever the reason. A fixed subtraction would
    /// mean a 40-point reason erases a 30-point score entirely and half of a
    /// 60-point one, which is a much bigger claim than "this file is signed".
    pub strength_percent: i32,
    /// The ceiling on any single file's discount, however many reasons apply.
    ///
    /// The backstop that makes "trust cannot clear a pile of evidence" true
    /// regardless of what reasons are added later. At the default of 60, a file
    /// has to score at least 100 on generic detections alone before trust
    /// leaves it in the malicious band — which is a file with several
    /// independent things wrong with it, and the right place for the line.
    pub max_discount: i32,
    /// The magnitude at which trust keeps a file out of the band that acts.
    ///
    /// The discount above is arithmetic, and a file with enough generic
    /// observations outruns any of it. Measured: `OneDriveSetup.exe` in an
    /// installed `System32` scores 170 against a malicious threshold of 100,
    /// and with `max_discount` at 60 no arrangement of discounts brings it
    /// under without also making the discount large enough to erase a real
    /// detection. So the *band* is capped rather than the score, which is a
    /// claim of a different kind: nothing here is evidence of a specific
    /// threat, and the publisher is known.
    ///
    /// At the default of 20 a file has to be signed *and* live in a trusted
    /// directory, or be signed by a recognised authority. Measured against an
    /// installed `System32`, that is every one of the 836 files carrying an
    /// embedded signature, and no file that carries none.
    pub remediation_floor: i32,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_paths: system_paths(),
            known_authorities: KNOWN_AUTHORITIES
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            strength_percent: 60,
            max_discount: 60,
            remediation_floor: 20,
        }
    }
}

impl TrustPolicy {
    /// Trust that finds nothing, for a scan that was asked not to consult it.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Assess a file, given its parsed image when it has one.
    ///
    /// `catalog` is evidence rather than policy, which is why it is a parameter
    /// and not a field: it is 6.5 MB of digests read off this machine's disk,
    /// the same way the rule database is, and a `TrustPolicy` that carried one
    /// would be a policy that could not be compared, cloned cheaply or written
    /// to a configuration file.
    pub fn assess(
        &self,
        path: &Path,
        pe: Option<&PeInput<'_>>,
        catalog: Option<&CatalogIndex>,
    ) -> TrustAssessment {
        let mut out = TrustAssessment::default();
        if !self.enabled {
            return out;
        }

        // Nothing to say about a file's signature if the file could not be
        // parsed, and a path is still evidence either way.
        match pe {
            Some(image) => {
                // The verified signature first: it answers the same question the
                // certificate reading does, and answers it with arithmetic, so
                // the reading is skipped when it holds. See
                // [`Self::assess_verified`].
                if !self.assess_verified(image, &mut out) {
                    self.assess_signature(image, &mut out);
                }
                // Both halves, not either. A file can carry an embedded
                // signature and be catalogued, and the two are different facts
                // about it — `strongest_per_kind` below keeps only the stronger,
                // but the stronger is not always the embedded one and neither
                // may be assumed to imply the other.
                self.assess_catalog(image, catalog, &mut out);
            }
            None => out.reasons.push(TrustReason::Unsigned),
        }
        self.assess_path(path, &mut out);

        // Only the strongest of each kind counts. Two certificates in one file
        // is a dual signature, which is one statement by one publisher.
        out.magnitude = strongest_per_kind(&out.reasons);
        out
    }

    /// The catalog half of the assessment.
    ///
    /// # Why every catalog listing the file is consulted
    ///
    /// The question is "does anything vouch for these bytes", and a digest is
    /// routinely listed by several catalogs — the same file is in an
    /// operating-system catalog and a cumulative-update one. Taking the first
    /// and checking only it makes the answer depend on how the store happened to
    /// be numbered, so a file listed by both a Microsoft catalog and an OEM's
    /// would come back unvouched whenever the OEM's catalog sorted first. That
    /// is a silent loss of trust for exactly the population this exists to
    /// cover, and it is the reason [`CatalogIndex`] keeps every owner.
    ///
    /// # Why the answer is one reason and not a list
    ///
    /// `strongest_per_kind` keeps the strongest reason in each bucket, so a
    /// second vouched catalog adds nothing to the arithmetic. The first is
    /// recorded and the search stops; a user reading the report gets one
    /// publisher's name, which is what the field is for.
    fn assess_catalog(
        &self,
        image: &PeInput<'_>,
        catalog: Option<&CatalogIndex>,
        out: &mut TrustAssessment,
    ) {
        let Some(index) = catalog else {
            return;
        };
        let mut unvouched: Option<String> = None;
        for identity in index.catalogs_listing(image.pe()) {
            match identity
                .issuers
                .iter()
                .find(|issuer| self.recognises(issuer))
            {
                Some(authority) => {
                    out.reasons.push(TrustReason::CatalogSigned {
                        subject: identity.subject.clone(),
                        authority: authority.clone(),
                    });
                    return;
                }
                None => unvouched = unvouched.or_else(|| Some(identity.subject.clone())),
            }
        }
        if let Some(subject) = unvouched {
            out.reasons.push(TrustReason::CatalogUnvouched { subject });
        }
    }

    /// The verified half of the signature assessment.
    ///
    /// Returns whether a verified signature was recorded, and the caller uses
    /// that to decide whether to read the certificates the other way at all.
    ///
    /// # Why this runs first, and why it replaces the other path
    ///
    /// Verification answers the same question [`Self::assess_signature`] does —
    /// who published these bytes — and answers it conclusively. Running both
    /// would put a claim and a proof of the same fact in one report, and the
    /// claim is the one a reader would notice: a verified Microsoft binary
    /// whose leaf issuer is an intermediate would be described as "signed by
    /// `CN=Microsoft Windows`, issued by `CN=Microsoft Windows Production PCA
    /// 2011`, which is not a public certificate authority this product
    /// recognises" beside the proof that its chain reaches a trusted root.
    ///
    /// It is not only a cosmetic problem. [`Self::assess_signature`] judges the
    /// signer's validity against the *present*, which is the one thing a
    /// counter-signature exists to make irrelevant: measured over an installed
    /// `System32`, 248 of the 836 embedded-signed files are signed by a
    /// certificate that has already expired, and every one of them is correctly
    /// signed. That path calls them stale. Verification judges the chain at the
    /// instant the counter-signature proves, so for those files it is not just
    /// the stronger answer, it is the *right* one.
    ///
    /// # What it costs
    ///
    /// A file that carries a signature pays for a chain build and an image
    /// digest. Both are per-file and neither is paid by a file with no
    /// signature at all, which is the vast majority of what a scan of a disk
    /// meets. Off by default it is not: a trust layer whose strongest evidence
    /// depended on a switch would be a trust layer with two answers.
    fn assess_verified(&self, image: &PeInput<'_>, out: &mut TrustAssessment) -> bool {
        let av_authenticode::Verdict::Trusted(proof) = av_authenticode::verify(image.pe()) else {
            // Everything that is not `Trusted` — unsigned, unreadable, tampered
            // with, or signed by a chain that reaches no trusted root — leaves
            // the certificate-reading path to say what it can. `Invalid` is
            // deliberately *not* turned into a reason here: a tampered file is a
            // finding for the scanner's own detections to carry, and a trust
            // module that could report one would be a trust module whose
            // vocabulary includes "this file is bad", which is not trust.
            return false;
        };
        // The root, not the leaf's issuer. A chain that reached an anchor has a
        // name for it by construction, and the fallback is unreachable rather
        // than a silent hole: `Trusted` is only built after `chain::evaluate`
        // returned a root.
        let root = proof.root.unwrap_or_else(|| "<unnamed root>".to_owned());
        out.reasons.push(TrustReason::VerifiedSignature {
            subject: proof.subject,
            root,
        });
        true
    }

    /// The signature half of the assessment.
    fn assess_signature(&self, image: &PeInput<'_>, out: &mut TrustAssessment) {
        // The signer is picked out of the chain rather than taken as the first
        // certificate: see [`av_signatures::x509::signer_index`].
        let chain = image.signatures();
        // Hoisted to `av_signatures::x509`, where the measurement that makes
        // it necessary lives and where the catalog index uses it too.
        let Some(signer) = chain.get(av_signatures::x509::signer_index(chain)) else {
            out.reasons.push(TrustReason::Unsigned);
            return;
        };
        let subject = signer
            .subject()
            .unwrap_or_else(|_| "<unreadable subject>".to_owned());
        // An issuer that cannot be read is an issuer that cannot be recognised,
        // which is the `Unknown` arm and not an error: a certificate with a
        // malformed issuer field is a certificate nothing can be concluded
        // from, and concluding nothing is the correct response.
        //
        // The authority is looked for in **every** issuer in the chain, not
        // just the leaf's. Measured over the installed `System32`: not one of
        // the 836 embedded-signed files carries a self-signed root, so the only
        // certificate whose issuer names a root is the last one. For a Windows
        // binary the leaf's own issuer is an intermediate — `Microsoft Windows
        // Production PCA 2011` — and reading that alone left every signed file
        // in the installation an unknown authority, with the trust mechanism
        // inert for exactly the population it exists for.
        //
        // A *subject* is deliberately not matched. An issuer is a claim made by
        // a different party; a subject is a claim a certificate makes about
        // itself, and with no chain validation a self-issued certificate can
        // claim any subject it likes. The rule above already reaches the
        // measured population on issuers alone, so matching subjects would
        // widen what a forgery buys without widening what is recognised.
        let issued_by: Vec<String> = chain
            .iter()
            .filter_map(|certificate| certificate.issuer().ok())
            .collect();
        let authority = issued_by.iter().find(|issuer| self.recognises(issuer));
        let issuer = authority
            .cloned()
            .unwrap_or_else(|| issued_by.first().cloned().unwrap_or_default());

        if !currently_valid(signer.not_before().ok(), signer.not_after().ok()) {
            out.reasons.push(TrustReason::StaleCertificate { subject });
            return;
        }
        out.reasons.push(match authority.is_some() {
            true => TrustReason::KnownAuthority { subject, issuer },
            false => TrustReason::UnknownAuthority { subject, issuer },
        });
    }

    /// Whether an issuer name is one of the recognised authorities.
    fn recognises(&self, issuer: &str) -> bool {
        self.known_authorities
            .iter()
            .any(|name| contains_ignoring_case(issuer, name))
    }

    /// The path half of the assessment.
    fn assess_path(&self, path: &Path, out: &mut TrustAssessment) {
        if let Some(dir) = self.trusted_paths.iter().find(|dir| is_under(path, dir)) {
            out.reasons.push(TrustReason::TrustedPath(dir.clone()));
        }
    }

    /// Take the discount a trust assessment justifies off an assessment.
    ///
    /// Bounded three times, and each bound is there for a different failure:
    ///
    /// * Only the score contributed by *generic* detections is discountable.
    ///   This is the distinction the module is built on — see
    ///   [`is_generic`] — and it is what makes a family-naming rule immune.
    /// * The discount is a fraction of that score, so trust cannot turn one
    ///   observation into none of them.
    /// * The whole discount is capped, so no accumulation of reasons can clear
    ///   a file that several independent detectors agreed about.
    ///
    /// An incontestable detection is not consulted at all: such a file is
    /// malicious by construction and [`Assessment::finalize`] will say so
    /// whatever the score reads.
    ///
    /// The score is recomputed from the detections rather than adjusted,
    /// because [`Assessment::apply_trust`] sees one number and cannot tell the
    /// discountable part of it from the rest. Recomputing also keeps the field
    /// consistent with the list, which is what a caller reading both expects.
    pub fn discount(&self, assessment: &mut Assessment, trust: &TrustAssessment) {
        if !self.enabled || trust.magnitude <= 0 {
            return;
        }
        if assessment.detections.iter().any(|d| d.incontestable) {
            return;
        }
        let discountable: i32 = assessment
            .detections
            .iter()
            .filter(|d| is_generic(d))
            .map(|d| i32::from(d.score))
            .sum();
        if discountable <= 0 {
            return;
        }
        let proportional = discountable.saturating_mul(self.strength_percent) / 100;
        let cut = proportional
            .min(trust.magnitude)
            .min(self.max_discount)
            .min(discountable);
        if cut <= 0 {
            return;
        }
        assessment.score = assessment
            .score
            .saturating_sub(u16::try_from(cut).unwrap_or(u16::MAX));
    }

    /// Hold a verdict out of the band that acts on a file.
    ///
    /// Runs after [`Assessment::finalize`], because it answers a different
    /// question: the discount asks how much of the score trust has standing on,
    /// and this asks whether the remaining score should be read as an
    /// instruction to delete the file. Three conditions, and each is there for
    /// a different reason:
    ///
    /// * The verdict is `Malicious`. `Suspicious` is already the band that
    ///   tells a user without acting, which is where a capped file belongs, and
    ///   `Clean` and `Unknown` are not trust's business.
    /// * The magnitude reaches [`Self::remediation_floor`]. A path on its own
    ///   is worth 10 and is not enough on purpose: `trusted_paths` includes
    ///   `ProgramData`, which anything can write to, so a path is evidence
    ///   about where a file is and not about who wrote it.
    /// * **Every** detection is generic, by the same test the discount uses. A
    ///   detection that states a family of its own, that was rated decisive by
    ///   its author, or that matched a known hash, is not a statement about how
    ///   the file was built and a code-signing certificate does not answer it —
    ///   which is also why a stolen certificate buys nothing here. A detection
    ///   this product read out of its rule — a title that names an instance, a
    ///   condition nothing ordinary satisfies — is generic, and
    ///   `convicts_on_a_reading` says why. This is the property that makes the
    ///   cap safe to have at all, and it is the same property the module rests
    ///   on.
    ///
    /// What it costs is stated plainly: an *unknown* threat that is signed and
    /// running from a trusted directory is reported and never removed. That is
    /// the deliberate trade — the alternative is deleting `OneDriveSetup.exe`
    /// off a clean installation — and the user is told, because the score, the
    /// detections and the withheld flag are all in the report.
    pub fn cap_verdict(&self, assessment: &mut Assessment, trust: &TrustAssessment) {
        if !self.enabled || assessment.verdict != Verdict::Malicious {
            return;
        }
        if trust.magnitude < self.remediation_floor {
            return;
        }
        if assessment.detections.iter().any(|d| !is_generic(d)) {
            return;
        }
        assessment.verdict = Verdict::Suspicious;
        assessment.withhold_remediation();
    }

    /// Report a file whose identity is **proven** as clean, when everything
    /// found against it is generic.
    ///
    /// # Why this is not the same as [`Self::cap_verdict`]
    ///
    /// The cap is the right answer to a *claim*: an unverified certificate says
    /// "somebody says this is Microsoft's", a forged one says it just as well,
    /// and the honest response is to stop short of deleting the file while still
    /// telling the user what was seen. It is not the right answer to a *proof*.
    /// Catalog membership says these bytes are the bytes a recognised authority
    /// hashed, and that settles a generic detection completely: a heuristic
    /// reporting that a file is packed is reporting a property of how it was
    /// built, and "these are the bytes Microsoft shipped" is a full answer to
    /// it. There is no residual doubt to notify anybody about.
    ///
    /// The cost of getting this wrong is the reason it is worth doing at all.
    /// Measured on a clean installation: a scan of `System32` produced 758
    /// findings, 750 of them in the suspicious band, and 742 of those files are
    /// catalog-signed — Microsoft's own binaries, flagged as suspicious by
    /// heuristics that are correctly describing how Microsoft built them. A
    /// product that shows a user 750 warnings on an untouched machine has taught
    /// them to dismiss all 750, including the one that matters.
    ///
    /// # Why it is safe
    ///
    /// Three conditions, and each rules out a different way of being wrong:
    ///
    /// * **Identity is proven** — a catalog listing these exact bytes, whose own
    ///   chain names a recognised authority. Not an embedded certificate.
    /// * **The verdict is one that acts or notifies.** `Clean` and `Unknown` are
    ///   not this method's business, and `Unknown` in particular must survive:
    ///   a scan that could not finish has no business being called clean.
    /// * **Every detection is generic**, by the same [`is_generic`] test the
    ///   discount and the cap use. One detection that states a family, that was
    ///   rated decisive by its author, or that matched a known hash, and this
    ///   does nothing at all — a signed file that a rule identifies as a
    ///   specific threat is exactly the case where the rule being over-broad is
    ///   worth a user's attention, and it is worth more than 750 false alarms
    ///   are worth. A detection this product read out of its rule does not stop
    ///   it: see `convicts_on_a_reading` for what that costs and why the trade
    ///   is the right way round.
    ///
    /// # What it costs, stated plainly
    ///
    /// **An administrator can silence a finding.** The catalog store is
    /// administrator-writable and this product does not verify the catalog's
    /// signature, so an administrator who plants a catalog listing a file's
    /// digest, under a certificate whose issuer string reads like a Microsoft
    /// root, makes that file clean. That is a real hole and it is not hidden:
    /// the crate documentation says signatures are parsed and not verified, and
    /// verification is the change that would close it. It is accepted here
    /// because an administrator on this machine can already stop the service,
    /// delete the quarantine and add an exclusion — so the hole widens what an
    /// attacker who has already won can do quietly, and does not widen what one
    /// who has not won can do at all.
    ///
    /// # What it leaves behind
    ///
    /// Nothing is thrown away. Every detection stays in the list with its score,
    /// the score stays the sum of them, `suppressed` gains their rule ids, and
    /// [`Assessment::withhold_remediation`] records that trust overrode the
    /// band. So a report can still answer "was anything seen in this file"
    /// — which is the question a user asks when they are told a file is clean
    /// and do not believe it — and the score and the verdict disagreeing is the
    /// intended record that trust, not the evidence, decided.
    pub fn clear_generic(&self, assessment: &mut Assessment, trust: &TrustAssessment) {
        if !self.enabled || !trust.identity_proven() {
            return;
        }
        // `Unknown` is excluded by this: it is not a detection, and a scan that
        // did not finish must not be reported as a clean one.
        if !assessment.verdict.is_detection() {
            return;
        }
        if assessment
            .detections
            .iter()
            .any(|detection| !is_generic(detection))
        {
            return;
        }
        let suppressed: Vec<String> = assessment
            .detections
            .iter()
            .filter(|detection| is_generic(detection))
            .map(|detection| detection.rule_id.clone())
            .collect();
        for rule_id in suppressed {
            assessment.suppress(rule_id);
        }
        assessment.verdict = Verdict::Clean;
        assessment.withhold_remediation();
    }
}

/// Whether a detection is a claim trust has standing to argue with.
///
/// True for the probabilistic half of the engine: heuristics, signature rules
/// that name no family and claim no severity above [`Severity::Medium`], and
/// rules that convict only because this product read them as decisive — see
/// `convicts_on_a_reading`. False for anything that says what the file *is*
/// beyond argument.
///
/// The severity clause is what separates "this program imports the sequence for
/// injecting code into another process" from "this file is a known dropper".
/// Both arrive as [`DetectionSource::Signature`], because both are rules; only
/// the second is a claim a signature cannot answer. The reading clause is asked
/// first, so that a rule whose metadata names a family cannot buy an exemption
/// from the trust layer for a conviction this product reached by reading the
/// rule — the family is the author's label on the rule, and a reading is still
/// a reading either way.
pub fn is_generic(detection: &Detection) -> bool {
    if detection.incontestable {
        return false;
    }
    // Asked before the family test, and that order is the point. A rule can
    // carry a `family` in its metadata *and* convict on a reading — this
    // corpus's three Hiddencobra rules do — and the family test would then
    // exempt it from the trust layer on the strength of a label its author put
    // on the *rule*. A reading is this product's inference either way, which is
    // what the trust layer has standing on, so the reading decides first for
    // the source that readings come from. Behaviour, memory and reputation are
    // not read out of a rule at all and keep the family test first.
    if detection.source == DetectionSource::Signature && convicts_on_a_reading(detection) {
        return true;
    }
    if detection
        .threat
        .as_ref()
        .is_some_and(|threat| threat.family.is_some())
    {
        return false;
    }
    match detection.source {
        DetectionSource::Heuristic => true,
        DetectionSource::Signature => {
            detection.severity <= Severity::Medium || convicts_on_a_reading(detection)
        }
        // Behaviour was watched happening, memory was read, a reputation was
        // consulted. Code-signing is evidence about none of them.
        DetectionSource::Behavior
        | DetectionSource::Memory
        | DetectionSource::Reputation
        | DetectionSource::User => false,
    }
}

/// Whether a detection took itself past the threshold on a *reading* of its
/// rule rather than on its author's rating.
///
/// The predicate is `decisive && !incontestable`, and [`av_core::Detection`]
/// defines both halves: a decisive detection is one that ends the assessment on
/// its own, and an incontestable one is a decisive detection whose author
/// staked the strongest claim the rule language can make. So this is exactly
/// "this product decided the rule was decisive; the author did not".
///
/// Two readings reach it, and they are the same kind of claim about the same
/// kind of evidence. A rule whose **title** identifies a family and one of its
/// instances convicts on its own, and so does a rule whose **condition** cannot
/// be satisfied by anything ordinary. Neither was rated decisive by its author
/// — the corpus rates its rules in `score` and `quality`, and a rule read either
/// way was rated ordinary by both. So the severity clause above must not bite: a
/// title is a claim, the shape of a condition is an argument, and a published
/// certificate is an answer to both.
///
/// What this costs is stated plainly, because it is a real loss and not a
/// rounding error: a **signed** file that either reading identifies is reported
/// `Suspicious` and never removed, and if its identity is *proven* — a verified
/// signature or a catalog entry — it is reported `Clean` with the detection kept
/// in `suppressed`. A rule read this way still convicts an unsigned file, which
/// is the case the reading exists for. What is given up is the case where the
/// rule is right about a file whose bytes somebody else's private key signed,
/// and the measured cost of keeping it is `System32\MRT.exe` — Microsoft's own
/// removal tool, whose signature database holds malware strings on purpose —
/// reported malicious on every machine.
fn convicts_on_a_reading(detection: &Detection) -> bool {
    detection.decisive && !detection.incontestable
}

/// The sum of the strongest reason of each kind.
fn strongest_per_kind(reasons: &[TrustReason]) -> i32 {
    let mut best: Vec<(Kind, i32)> = Vec::new();
    for reason in reasons {
        let kind = Kind::of(reason);
        let magnitude = reason.magnitude();
        match best.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, slot)) => *slot = (*slot).max(magnitude),
            None => best.push((kind, magnitude)),
        }
    }
    best.iter().map(|(_, m)| *m).sum()
}

/// Which bucket a reason competes in.
///
/// The buckets are *questions*, not sources: `Publisher` is "who produced these
/// bytes", and an embedded certificate, a verified signature and a catalog entry
/// are three answers to it, not three pieces of evidence. The strongest two
/// both reaching 60 rather than one reaching 100 is the point — a file that is
/// signed by a key that verifies *and* listed in a catalog is one publisher
/// saying so twice, and a file that is signed twice is one publisher saying so
/// once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Publisher,
    Path,
    User,
}

impl Kind {
    fn of(reason: &TrustReason) -> Self {
        match reason {
            TrustReason::KnownAuthority { .. }
            | TrustReason::UnknownAuthority { .. }
            | TrustReason::StaleCertificate { .. }
            | TrustReason::CatalogSigned { .. }
            | TrustReason::VerifiedSignature { .. } => Kind::Publisher,
            TrustReason::TrustedPath(_) => Kind::Path,
            // Worth nothing, so it must not occupy a bucket that evidence would
            // otherwise fill: `sum` takes the strongest of each kind, and a
            // zero-magnitude reason sharing a bucket with a real one is
            // harmless, whereas one occupying a bucket of its own would be a
            // bucket that never contributes.
            TrustReason::UserAllowed | TrustReason::Unsigned => Kind::User,
            // In `Publisher` rather than a bucket of its own, and deliberately:
            // it is a statement about who published the file that came out
            // inconclusive, which is the same question, so it competes with a
            // certificate rather than adding to one.
            TrustReason::CatalogUnvouched { .. } => Kind::Publisher,
        }
    }
}

/// Whether `path` is inside `dir`.
///
/// Prefix comparison on a component boundary, and case-insensitive because this
/// is Windows: `c:\windows\system32` and `C:\Windows\System32` are the same
/// directory, and a comparison that said otherwise would leave the whole
/// mechanism silently inert.
fn is_under(path: &Path, dir: &Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    let mut dir = dir.to_string_lossy().to_ascii_lowercase();
    if !dir.ends_with(std::path::MAIN_SEPARATOR) {
        dir.push(std::path::MAIN_SEPARATOR);
    }
    path.starts_with(&dir)
}

/// Whether a substring occurs, ignoring ASCII case.
fn contains_ignoring_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Whether a validity window contains the present.
///
/// A certificate whose dates cannot be read is treated as invalid. The opposite
/// default would make a malformed date field a way to earn trust.
fn currently_valid(
    not_before: Option<av_signatures::UnixTime>,
    not_after: Option<av_signatures::UnixTime>,
) -> bool {
    let (Some(from), Some(to)) = (not_before, not_after) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        // A clock before 1970 is not a state this product supports, and
        // guessing in either direction would be inventing an answer.
        return false;
    };
    let now = now.as_secs() as i64;
    from.seconds() <= now && now <= to.seconds()
}

/// Directories treated as trusted by default.
///
/// Read from the environment rather than written as literals, because a Windows
/// installation is not required to be on `C:`. A variable that is not set
/// contributes nothing, which is the safe direction.
fn system_paths() -> Vec<PathBuf> {
    [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ]
    .iter()
    .filter_map(std::env::var_os)
    .map(PathBuf::from)
    .collect()
}

/// Issuer names that identify a public certificate authority.
///
/// Substrings of the issuer's common name, matched case-insensitively. Not a
/// trust store: a real one is a list of root certificates with their public
/// keys, and comparing names is a much weaker check than comparing keys. It is
/// what this product can do without a verification implementation, and the
/// module documentation says so at length.
///
/// # Where the names come from
///
/// `what_authorities_sign_the_installed_operating_system` prints every issuer
/// in every embedded-signed file in an installed `System32`, most common first,
/// and this list is written from that output rather than from memory. The
/// Microsoft half is the half that matters and the half a list written from
/// memory gets wrong: measured there, the fourteen most common issuers are
/// Microsoft's, led by `Microsoft Root Certificate Authority 2010` on 745
/// certificates and `Microsoft Windows Production PCA 2011` on 700, and the
/// commercial roots a memorised list would contain cover a few dozen files
/// between them.
///
/// The names are the specific ones, not the organisation: `O=Microsoft
/// Corporation` appears in the issuer of both the parent of every Windows
/// binary and of certificates anyone can write, and matching it would recognise
/// the second as readily as the first. Nothing here matches on the organisation
/// field alone.
const KNOWN_AUTHORITIES: &[&str] = &[
    // Measured on an installed `System32`, most common first.
    "Microsoft Root Certificate Authority",
    "Microsoft Windows Production PCA",
    "Microsoft Root Authority",
    "Microsoft Windows Third Party Component CA",
    "Microsoft Windows Code Signing PCA",
    "Microsoft Code Signing PCA",
    "Microsoft Code Verification Root",
    "Microsoft Windows Publisher",
    "Microsoft Windows Software Compatibility Publisher",
    "Microsoft Windows Hardware Compatibility Publisher",
    "Microsoft Windows Hardware Abstraction Layer Publisher",
    "Microsoft Windows Kits Publisher",
    "Microsoft Azure Code Sign",
    "Microsoft Time-Stamp PCA",
    "Microsoft Timestamping PCA",
    // The commercial authorities, which the same measurement finds on third
    // party drivers and on the handful of Windows components signed outside
    // Microsoft's own PKI.
    "DigiCert",
    "Sectigo",
    "USERTrust",
    "Comodo",
    "AAA Certificate Services",
    "GlobalSign",
    "Entrust",
    "Go Daddy",
    "Starfield",
    "Thawte",
    "VeriSign",
    "Symantec",
    "Certum",
    "Buypass",
    "Actalis",
    "QuoVadis",
    "SwissSign",
    "T-Systems",
    "SSL.com",
    "IdenTrust",
    "Amazon",
    "Google Trust Services",
];

#[cfg(test)]
mod tests {
    use super::*;
    // Moved to `av-signatures`, where the catalog index needs it too; the tests
    // that pinned its behaviour stayed here with the reasons they exist for.
    use av_core::{Detection, DetectionSource, Severity, ThreatCategory, ThreatName};
    use av_signatures::x509::signer_index;

    fn signed(rule: &str, severity: Severity, source: DetectionSource) -> Detection {
        Detection::new(rule, "test", severity, source)
    }

    fn with_family(rule: &str, severity: Severity) -> Detection {
        Detection::new(rule, "test", severity, DetectionSource::Signature).with_threat(
            ThreatName::new(av_core::Platform::Win32, ThreatCategory::Trojan).with_family("Emotet"),
        )
    }

    fn assessment(detections: Vec<Detection>) -> Assessment {
        let mut a = Assessment::clean();
        for d in detections {
            a.push(d);
        }
        a
    }

    fn known_cert() -> TrustAssessment {
        TrustAssessment {
            magnitude: 40,
            reasons: vec![TrustReason::KnownAuthority {
                subject: "Contoso Ltd".into(),
                issuer: "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1".into(),
            }],
        }
    }

    #[test]
    fn trust_never_touches_a_detection_that_names_a_family() {
        // The invariant the module exists for. A signed file that a rule has
        // identified as a named family is still that family.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![with_family("lockbit", Severity::Medium)]);
        assert_eq!(a.score, 60);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 60, "a family-naming detection was discounted");
    }

    #[test]
    fn trust_never_touches_an_incontestable_detection() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "known_bad_hash",
            Severity::High,
            DetectionSource::Reputation,
        )
        .incontestable()]);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 100);
    }

    /// Decisive is not the same as beyond argument, and this is the whole of
    /// the difference: a rule this product convicts on a reading of is
    /// discounted like any other claim.
    #[test]
    fn a_detection_decisive_on_a_reading_is_discounted() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "HARFANGLAB_Wingtb_Rootkit",
            Severity::High,
            DetectionSource::Signature,
        )
        .decisive()]);
        assert_eq!(a.score, 100);
        policy.discount(&mut a, &known_cert());
        // 60% of 100 is 60 and `max_discount` allows 60, but the reason itself
        // is a known authority and worth 40, which is the binding bound.
        assert_eq!(a.score, 60);
    }

    #[test]
    fn trust_never_touches_an_observation_of_running_behaviour() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "behaviour/encrypts_files",
            Severity::Low,
            DetectionSource::Behavior,
        )]);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 30);
    }

    #[test]
    fn a_strong_signature_rule_is_not_discounted() {
        // A rule the author scored High is a rule the author is confident
        // about, regardless of whether it names a family. Trust discounts the
        // probabilistic half of the engine and stops there.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "specific_dropper",
            Severity::High,
            DetectionSource::Signature,
        )]);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 100);
    }

    #[test]
    fn a_generic_rule_is_discounted() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "generic_packer",
            Severity::Low,
            DetectionSource::Signature,
        )]);
        policy.discount(&mut a, &known_cert());
        // 60% of 30 is 18, and the reason is worth at most 40.
        assert_eq!(a.score, 12);
    }

    #[test]
    fn a_medium_heuristic_on_a_signed_file_stops_being_suspicious() {
        // The case this mechanism exists for: an ordinary signed binary that
        // trips one packing heuristic is a notification the user should not
        // get. 60 is exactly the suspicious line, and the discount takes it
        // under.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "packed/a",
            Severity::Medium,
            DetectionSource::Heuristic,
        )]);
        assert_eq!(a.score, 60);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 24);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        assert!(!a.verdict.is_detection(), "verdicts {}", a.verdict);
    }

    #[test]
    fn a_signature_does_not_clear_a_file_two_detectors_agree_about() {
        // The bound, stated as the case it declines. Two Medium heuristics is
        // 120, and the most a known authority can take off is its own 40 —
        // `max_discount` is 60 but the reason is worth less — so the file stays
        // at 80 and stays suspicious.
        //
        // That is deliberate rather than a gap. `Severity::Medium` twice is two
        // independent observations, and a certificate is one statement by one
        // publisher about how the file was built; it is evidence about packing
        // and not evidence that two detectors were wrong. The file is notified
        // about and not touched, which is what the yellow band is for.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![
            signed("packed/a", Severity::Medium, DetectionSource::Heuristic),
            signed("packed/b", Severity::Medium, DetectionSource::Heuristic),
        ]);
        assert_eq!(a.score, 120);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 80);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        assert_eq!(a.verdict, av_core::Verdict::Suspicious);
    }

    /// A file whose detections are all generic and add up past the malicious
    /// line. The shape trust is for, and the shape the cap is about.
    fn piled_up_generic(count: u32) -> Assessment {
        assessment(
            (0..count)
                .map(|i| {
                    signed(
                        &format!("heuristic/r{i}"),
                        Severity::High,
                        DetectionSource::Heuristic,
                    )
                })
                .collect(),
        )
    }

    /// A trust assessment worth only the path a file sits in.
    fn path_only() -> TrustAssessment {
        TrustAssessment {
            magnitude: 10,
            reasons: vec![TrustReason::TrustedPath(PathBuf::from("C:\\Windows"))],
        }
    }

    #[test]
    fn a_signed_file_with_nothing_but_generic_evidence_is_not_remediated() {
        // The measured case. `OneDriveSetup.exe` in an installed `System32`
        // scores 170 from six independent heuristics; it is a Microsoft binary
        // and deleting it is not an option. No discount reaches it — the
        // ceiling is 60 and a percentage of a percentage does not clear 100 —
        // so the band is capped instead of the score.
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let mut a = piled_up_generic(2);
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Malicious);
        assert_eq!(a.score, 200);

        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Suspicious);
        assert!(a.remediation_withheld);
        // The band changed and the evidence did not. A report showing a lower
        // score here would be claiming the file is less suspicious than it is.
        assert_eq!(a.score, 200);
        assert_eq!(a.detections.len(), 2);
    }

    #[test]
    fn one_detection_that_names_a_family_defeats_the_cap() {
        // The invariant that makes the cap safe to have at all. A stolen
        // certificate buys nothing against a rule that says what the file *is*.
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let mut a = assessment(vec![
            signed("heuristic/r0", Severity::High, DetectionSource::Heuristic),
            with_family("win/ransom/lockbit", Severity::High),
        ]);
        a.finalize(&thresholds);
        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Malicious);
        assert!(!a.remediation_withheld);
    }

    #[test]
    fn an_incontestable_detection_defeats_the_cap() {
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let mut decisive = signed("hash/known-bad", Severity::High, DetectionSource::Signature);
        decisive = decisive.incontestable();
        let mut a = assessment(vec![
            signed("heuristic/r0", Severity::High, DetectionSource::Heuristic),
            decisive,
        ]);
        a.finalize(&thresholds);
        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Malicious);
        assert!(!a.remediation_withheld);
    }

    /// The other route to `decisive`, and the one that must **not** defeat the
    /// cap: a rule whose title names a family and one of its instances, rated
    /// ordinary by the author who wrote it.
    ///
    /// This is the `MRT.exe` case, reduced. The rule is right about the string
    /// it matched and the file is still Microsoft's removal tool, because a
    /// removal tool's database holds malware strings on purpose. Reading the
    /// rule was what made the match decisive; reading the file is what has to
    /// be able to answer it, and only a rating or a hash may refuse the answer.
    #[test]
    fn a_detection_decisive_on_a_rules_name_is_still_capped() {
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        // Decisive on its name: `decisive`, not `incontestable`, and at the
        // convicting rung this product raises a named signature to.
        let named = signed(
            "SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1",
            Severity::High,
            DetectionSource::Signature,
        )
        .decisive();
        let mut a = assessment(vec![
            signed("heuristic/r0", Severity::Low, DetectionSource::Heuristic),
            named,
        ]);
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Malicious, "it convicts alone");
        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Suspicious, "and is still answerable");
        assert!(a.remediation_withheld);
    }

    #[test]
    fn a_path_on_its_own_is_not_enough_to_hold_a_verdict_back() {
        // 10 points, which is what a file gets for being in `System32`.
        // `trusted_paths` contains `ProgramData`, which anything can write to,
        // so a path is evidence about where a file is and not about who wrote
        // it — which is why the floor is above what a path is worth.
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let mut a = piled_up_generic(2);
        a.finalize(&thresholds);
        policy.cap_verdict(&mut a, &path_only());
        assert_eq!(a.verdict, Verdict::Malicious);
        assert!(!a.remediation_withheld);
    }

    #[test]
    fn the_floor_is_the_boundary_and_not_a_neighbour_of_it() {
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        for (magnitude, capped) in [
            (policy.remediation_floor - 1, false),
            (policy.remediation_floor, true),
            (policy.remediation_floor + 1, true),
        ] {
            let trust = TrustAssessment {
                magnitude,
                reasons: Vec::new(),
            };
            let mut a = piled_up_generic(2);
            a.finalize(&thresholds);
            policy.cap_verdict(&mut a, &trust);
            assert_eq!(
                a.verdict == Verdict::Suspicious,
                capped,
                "magnitude {magnitude} against a floor of {}",
                policy.remediation_floor
            );
        }
    }

    #[test]
    fn nothing_below_the_malicious_line_is_touched() {
        // `Suspicious` is already the band that tells a user without acting, so
        // there is nothing to hold back — and flagging it would report a
        // decision that was never needed.
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let mut a = assessment(vec![signed(
            "heuristic/r0",
            Severity::Medium,
            DetectionSource::Heuristic,
        )]);
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Suspicious);
        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Suspicious);
        assert!(!a.remediation_withheld);
    }

    #[test]
    fn a_disabled_policy_holds_nothing_back() {
        let policy = TrustPolicy::disabled();
        let thresholds = av_core::VerdictThresholds::default();
        let mut a = piled_up_generic(2);
        a.finalize(&thresholds);
        policy.cap_verdict(&mut a, &known_cert());
        assert_eq!(a.verdict, Verdict::Malicious);
        assert!(!a.remediation_withheld);
    }

    #[test]
    fn a_clean_or_unknown_verdict_is_not_trusts_business() {
        let policy = TrustPolicy::default();
        for verdict in [Verdict::Clean, Verdict::Unknown] {
            let mut a = Assessment::clean();
            a.verdict = verdict;
            policy.cap_verdict(&mut a, &known_cert());
            assert_eq!(a.verdict, verdict);
            assert!(!a.remediation_withheld);
        }
    }

    #[test]
    fn no_accumulation_of_trust_clears_a_file_past_the_malicious_line() {
        // `max_discount` stated as a property rather than as a number. Whatever
        // a file accumulates in reasons — four kinds here, worth more between
        // them than the ceiling — the most that comes off one file is the
        // ceiling. So trust cannot become the thing that clears a file.
        //
        // The fixture carries one detection that reaches the convicting rung,
        // and that is deliberate rather than convenient. A pile of Mediums is 60
        // points each and never reaches the rung on its own, so a pile of them
        // is the band that warns — see `Assessment::finalize` — and a test that
        // asserted a pile of Mediums was malicious would be asserting the defect
        // that band exists to fix. What is being stated here is the stronger
        // claim anyway: once a file's own evidence convicts it, no amount of
        // trust on the meter takes it out of the band that acts.
        let policy = TrustPolicy::default();
        let everything = TrustAssessment {
            magnitude: 100,
            reasons: vec![
                TrustReason::KnownAuthority {
                    subject: "Contoso Ltd".into(),
                    issuer: "DigiCert".into(),
                },
                TrustReason::UserAllowed,
                TrustReason::TrustedPath(PathBuf::from("C:\\Windows")),
                TrustReason::UnknownAuthority {
                    subject: "Self".into(),
                    issuer: "Self".into(),
                },
            ],
        };
        let thresholds = av_core::VerdictThresholds::default();

        for count in 1..=8u32 {
            let mut detections: Vec<Detection> = (0..count)
                .map(|i| {
                    signed(
                        &format!("r{i}"),
                        Severity::Medium,
                        DetectionSource::Heuristic,
                    )
                })
                .collect();
            detections.push(signed(
                "convicting",
                Severity::High,
                DetectionSource::Heuristic,
            ));
            let mut a = assessment(detections);
            let before = a.score;
            policy.discount(&mut a, &everything);
            let cut = i32::from(before) - i32::from(a.score);
            assert!(
                cut <= policy.max_discount,
                "{count} detections: {cut} came off, past a ceiling of {}",
                policy.max_discount
            );
            a.finalize(&thresholds);
            assert_eq!(
                a.verdict,
                av_core::Verdict::Malicious,
                "a score of {before} became {}",
                a.verdict
            );
        }
    }

    #[test]
    fn trust_cannot_clear_a_pile_of_independent_observations() {
        // Six Medium heuristics is 360 points of evidence from six different
        // directions. Trust takes its ceiling off and the file keeps its band.
        //
        // Both halves are asserted, because the score is no longer what decides
        // the band. On its own the pile is `Suspicious`: six generic heuristics
        // are six descriptions of how a file was built, which is worth telling a
        // user and is not worth acting on. Add one detection that reaches the
        // convicting rung and the file is malicious, and the largest discount
        // this policy allows does not move it.
        let policy = TrustPolicy::default();
        let thresholds = av_core::VerdictThresholds::default();
        let pile = |extra: Option<Severity>| {
            let mut detections: Vec<Detection> = (0..6)
                .map(|i| {
                    signed(
                        &format!("packed/{i}"),
                        Severity::Medium,
                        DetectionSource::Heuristic,
                    )
                })
                .collect();
            if let Some(severity) = extra {
                detections.push(signed("packed/convicting", severity, DetectionSource::Heuristic));
            }
            assessment(detections)
        };

        let mut generic = pile(None);
        assert_eq!(generic.score, 360);
        generic.finalize(&thresholds);
        assert_eq!(
            generic.verdict,
            av_core::Verdict::Suspicious,
            "six heuristics warn; none of them convicts"
        );

        let mut a = pile(Some(Severity::High));
        assert_eq!(a.score, 460);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 460 - 40, "the reason's own magnitude bounds it");
        a.finalize(&thresholds);
        assert_eq!(a.verdict, av_core::Verdict::Malicious);
    }

    #[test]
    fn the_ceiling_holds_whatever_the_reasons_add_up_to() {
        // The backstop, tested directly. 60% of 150 is 90 and the reason's own
        // magnitude is 40, so without a ceiling the cut would be 40; with one
        // at 20 it is 20. The ceiling is what makes "trust cannot clear more
        // than this" true independently of which reasons exist.
        let policy = TrustPolicy {
            max_discount: 20,
            ..TrustPolicy::default()
        };
        let mut a = assessment(vec![signed(
            "packed",
            Severity::Medium,
            DetectionSource::Heuristic,
        )]);
        assert_eq!(a.score, 60);
        policy.discount(&mut a, &known_cert());
        // 60% of 60 is 36, the reason is worth 40, and the ceiling is 20.
        assert_eq!(a.score, 40);
    }

    #[test]
    fn the_discount_is_proportional_and_never_erases_the_whole_score() {
        // 60% of 30 is 18, so a single Low detection keeps 12 points. The point
        // is that trust cannot zero a score it has standing on: a file with one
        // observation still has one observation's worth of a third of itself.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "packed",
            Severity::Low,
            DetectionSource::Heuristic,
        )]);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 12);
    }

    #[test]
    fn a_disabled_policy_discounts_nothing() {
        let policy = TrustPolicy::disabled();
        let mut a = assessment(vec![signed(
            "packed",
            Severity::Low,
            DetectionSource::Heuristic,
        )]);
        policy.discount(&mut a, &known_cert());
        assert_eq!(a.score, 30);
        assert!(!policy
            .assess(Path::new("C:\\anything"), None, None)
            .is_trusted());
    }

    #[test]
    fn a_trust_assessment_with_no_evidence_discounts_nothing() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "packed",
            Severity::Low,
            DetectionSource::Heuristic,
        )]);
        policy.discount(&mut a, &TrustAssessment::default());
        assert_eq!(a.score, 30);
    }

    #[test]
    fn only_the_strongest_reason_of_a_kind_counts() {
        let reasons = vec![
            TrustReason::UnknownAuthority {
                subject: "a".into(),
                issuer: "b".into(),
            },
            TrustReason::KnownAuthority {
                subject: "a".into(),
                issuer: "DigiCert".into(),
            },
            TrustReason::TrustedPath(PathBuf::from("C:\\Windows")),
            TrustReason::TrustedPath(PathBuf::from("C:\\Program Files")),
        ];
        // 40 for the certificate, 10 for the path, and neither doubled.
        assert_eq!(strongest_per_kind(&reasons), 50);
    }

    #[test]
    fn an_unsigned_file_is_recorded_but_is_not_evidence() {
        let reasons = vec![TrustReason::Unsigned];
        assert_eq!(strongest_per_kind(&reasons), 0);
        let assessment = TrustAssessment {
            magnitude: 0,
            reasons,
        };
        assert!(!assessment.is_trusted());
        assert_eq!(assessment.reportable().count(), 0);
    }

    #[test]
    fn a_path_under_a_trusted_directory_is_recognised() {
        assert!(is_under(
            Path::new("C:\\Windows\\System32\\kernel32.dll"),
            Path::new("C:\\Windows")
        ));
        assert!(is_under(
            Path::new("c:\\windows\\system32\\kernel32.dll"),
            Path::new("C:\\WINDOWS")
        ));
        // The boundary matters: `C:\Windows.old` is not inside `C:\Windows`.
        assert!(!is_under(
            Path::new("C:\\Windows.old\\evil.exe"),
            Path::new("C:\\Windows")
        ));
        assert!(!is_under(
            Path::new("D:\\evil.exe"),
            Path::new("C:\\Windows")
        ));
    }

    #[test]
    fn a_trusted_path_is_only_worth_a_tenth_of_the_score() {
        // Deliberately small: malware is dropped into `Program Files` routinely,
        // and a path is the weakest evidence in this module.
        let policy = TrustPolicy::default();
        let trust = TrustAssessment {
            magnitude: 10,
            reasons: vec![TrustReason::TrustedPath(PathBuf::from("C:\\Windows"))],
        };
        let mut a = assessment(vec![signed(
            "packed",
            Severity::Low,
            DetectionSource::Heuristic,
        )]);
        policy.discount(&mut a, &trust);
        assert_eq!(a.score, 20);
    }

    #[test]
    fn an_issuer_name_is_matched_ignoring_case_and_as_a_substring() {
        assert!(contains_ignoring_case(
            "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
            "digicert"
        ));
        assert!(contains_ignoring_case(
            "Sectigo Public Code Signing CA",
            "Sectigo"
        ));
        assert!(!contains_ignoring_case("Evil Corp Root CA", "DigiCert"));
        assert!(!contains_ignoring_case("anything", ""));
    }

    #[test]
    fn a_validity_window_that_cannot_be_read_is_not_valid() {
        assert!(!currently_valid(None, None));
        assert!(!currently_valid(Some(av_signatures::UnixTime(0)), None));
    }

    /// Parse a chain built by [`chain_link`], in the order given.
    fn chain(links: &[Vec<u8>]) -> Vec<av_signatures::x509::Certificate<'static>> {
        // Leaked so the certificates can borrow for the length of the test.
        // The alternative is threading a buffer through every caller of a
        // helper that exists to keep the tests readable.
        links
            .iter()
            .map(|der| {
                let der: &'static [u8] = Box::leak(der.clone().into_boxed_slice());
                av_signatures::x509::Certificate::parse(der).expect("a fixture certificate")
            })
            .collect()
    }

    /// A chain in the shape a real one has: each certificate's issuer is the
    /// next one's subject, and the last one's issuer is a root that is not
    /// present.
    fn real_chain() -> Vec<Vec<u8>> {
        vec![
            av_signatures::testing::chain_link(
                &[0x01],
                "Publisher",
                "Intermediate CA",
                "110616000000Z",
                "140615000000Z",
            ),
            av_signatures::testing::chain_link(
                &[0x02],
                "Intermediate CA",
                "Root CA",
                "110616000000Z",
                "140615000000Z",
            ),
        ]
    }

    #[test]
    fn the_signer_is_the_certificate_nothing_else_is_issued_by() {
        let chain = chain(&real_chain());
        assert_eq!(chain[0].subject().unwrap(), "/CN=Publisher");
        assert_eq!(signer_index(&chain), 0);
    }

    #[test]
    fn an_intermediate_listed_first_is_not_mistaken_for_the_signer() {
        // Measured: 55 of the 836 embedded-signed files in an installed
        // `System32` list an intermediate ahead of the leaf. Taking `[0]` as
        // the signer reports the authority's name as the file's publisher and
        // checks the authority's validity window instead of the signer's.
        let mut links = real_chain();
        links.reverse();
        let chain = chain(&links);
        assert_eq!(chain[0].subject().unwrap(), "/CN=Intermediate CA");
        assert_eq!(signer_index(&chain), 1);
        assert_eq!(
            chain[signer_index(&chain)].subject().unwrap(),
            "/CN=Publisher"
        );
    }

    #[test]
    fn a_self_signed_root_is_never_taken_for_the_signer() {
        // A root names itself as its own issuer, so it issues something — its
        // own certificate — and cannot be childless however the chain is
        // ordered.
        let mut links = real_chain();
        links.push(av_signatures::testing::chain_link(
            &[0x03],
            "Root CA",
            "Root CA",
            "110616000000Z",
            "140615000000Z",
        ));
        for order in [links.clone(), {
            let mut reversed = links.clone();
            reversed.reverse();
            reversed
        }] {
            let chain = chain(&order);
            assert_eq!(
                chain[signer_index(&chain)].subject().unwrap(),
                "/CN=Publisher"
            );
        }
    }

    #[test]
    fn a_lone_certificate_is_its_own_signer() {
        let chain = chain(&[av_signatures::testing::certificate(
            &[0x01],
            "Publisher",
            "110616000000Z",
            "140615000000Z",
        )]);
        assert_eq!(signer_index(&chain), 0);
    }

    #[test]
    fn the_first_of_two_signatures_is_the_signer() {
        // A file signed twice flattens to two chains, so two certificates issue
        // nothing. The first is the first signature's signer, which is the one
        // a rule reading `pe.signatures[0]` means.
        let mut links = real_chain();
        links.push(av_signatures::testing::chain_link(
            &[0x04],
            "Second Publisher",
            "Second CA",
            "110616000000Z",
            "140615000000Z",
        ));
        links.push(av_signatures::testing::chain_link(
            &[0x05],
            "Second CA",
            "Root CA",
            "110616000000Z",
            "140615000000Z",
        ));
        let chain = chain(&links);
        let index = signer_index(&chain);
        assert_eq!(index, 0);
        assert_eq!(chain[index].subject().unwrap(), "/CN=Publisher");
    }

    #[test]
    fn a_window_containing_the_present_is_valid() {
        let long_ago = av_signatures::UnixTime(0);
        let far_ahead = av_signatures::UnixTime(i64::MAX / 2);
        assert!(currently_valid(Some(long_ago), Some(far_ahead)));
        // And one that ended in 1971 is not.
        assert!(!currently_valid(
            Some(av_signatures::UnixTime(0)),
            Some(av_signatures::UnixTime(31_536_000))
        ));
    }

    #[test]
    fn a_default_policy_trusts_the_windows_directory() {
        // Environment-dependent, so the assertion is conditional rather than
        // absolute: on a machine with no `SystemRoot` there is nothing to test.
        let policy = TrustPolicy::default();
        let Some(root) = std::env::var_os("SystemRoot") else {
            return;
        };
        let path = PathBuf::from(root).join("System32").join("kernel32.dll");
        let trust = policy.assess(&path, None, None);
        assert!(
            trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::TrustedPath(_))),
            "{:?}",
            trust.reasons
        );
        assert_eq!(trust.magnitude, 10);
    }

    #[test]
    fn every_reason_that_carries_evidence_has_something_to_say() {
        let reasons = [
            TrustReason::KnownAuthority {
                subject: "a".into(),
                issuer: "b".into(),
            },
            TrustReason::UnknownAuthority {
                subject: "a".into(),
                issuer: "b".into(),
            },
            TrustReason::StaleCertificate {
                subject: "a".into(),
            },
            TrustReason::TrustedPath(PathBuf::from("C:\\Windows")),
            TrustReason::UserAllowed,
            TrustReason::Unsigned,
            TrustReason::CatalogSigned {
                subject: "a".into(),
                authority: "b".into(),
            },
            TrustReason::CatalogUnvouched {
                subject: "a".into(),
            },
        ];
        for reason in &reasons {
            assert!(reason.describe().len() > 15, "{reason:?}");
        }
    }

    // -- the catalog half ----------------------------------------------------
    //
    // The fixtures below are the whole path a shipping scan walks: a PE built in
    // memory, its catalog digest computed by the same function the index uses,
    // and a `.cat` written around that digest. `av_pe::testing` and
    // `av_signatures::testing` are public for exactly this — a checked-in binary
    // would be a fixture no test could point at.

    use av_signatures::catalog::{CatalogIndex, HashAlgorithm};
    use av_signatures::testing::{catalog_signed_by, certificate_issued_by};

    /// A Microsoft-sounding issuer, so `recognises` accepts it. Note that
    /// nothing verifies the certificate — that is the point of the trust model,
    /// and [`a_forged_certificate_earns_the_discount_but_not_the_clear`] pins it.
    const MS_ROOT: &str = "Microsoft Root Certificate Authority 2010";

    /// A minimal PE, its digest under both algorithms, and an index whose single
    /// catalog lists it.
    ///
    /// Returns the bytes as well because the caller needs them to parse the
    /// image the assessment is made against.
    fn catalogued(issuer: &str) -> (Vec<u8>, CatalogIndex) {
        let data = av_pe::testing::minimal_pe32();
        let image = PeInput::parse(&data).expect("the fixture is a PE");
        let sha1 =
            av_signatures::catalog::file_digest(image.pe(), HashAlgorithm::Sha1).expect("a digest");
        let sha256 = av_signatures::catalog::file_digest(image.pe(), HashAlgorithm::Sha256)
            .expect("a digest");
        let catalog = catalog_signed_by(
            &[&sha1, &sha256],
            &[certificate_issued_by(
                &[0x07],
                "Microsoft Windows",
                issuer,
                "110616000000Z",
                "400615000000Z",
            )],
        );
        (data, CatalogIndex::from_blobs(&[&catalog]))
    }

    #[test]
    fn a_catalogued_file_has_its_identity_proven() {
        let (data, index) = catalogued(MS_ROOT);
        let image = PeInput::parse(&data).expect("the fixture is a PE");
        let policy = TrustPolicy::default();
        let trust = policy.assess(
            Path::new("C:\\elsewhere\\thing.dll"),
            Some(&image),
            Some(&index),
        );
        assert!(trust.identity_proven(), "{:?}", trust.reasons);
        let reason = trust
            .reasons
            .iter()
            .find(|r| matches!(r, TrustReason::CatalogSigned { .. }))
            .expect("a catalog vouched for the file");
        let TrustReason::CatalogSigned { subject, authority } = reason else {
            unreachable!("just matched")
        };
        // The rendered distinguished name, not the substring that matched —
        // the same thing `KnownAuthority::issuer` holds, so a report shows one
        // spelling of an authority whichever half recognised it.
        assert!(
            authority.contains(MS_ROOT),
            "the authority is named in full: {authority}"
        );
        assert!(
            subject.contains("Microsoft Windows"),
            "the publisher's own name is reported: {subject}"
        ); // 60, which is more than a certificate is worth, and the difference is
           // the claim/proof distinction the whole design turns on.
        assert_eq!(trust.magnitude, 60);
    }

    #[test]
    fn a_file_no_catalog_lists_earns_nothing_from_the_index() {
        // The other half of the membership question. An index that is present
        // and does not list the file must not be mistaken for a signature.
        //
        // The population this covers is the ordinary one: almost nothing on a
        // disk is in a catalog, and the index has to say nothing at all about
        // those files rather than something reassuring.
        let (_, index) = catalogued(MS_ROOT);
        let unlisted = av_pe::testing::minimal_pe64();
        let image = PeInput::parse(&unlisted).expect("the fixture is a PE");
        let policy = TrustPolicy::default();
        let trust = policy.assess(
            Path::new("C:\\elsewhere\\thing.dll"),
            Some(&image),
            Some(&index),
        );
        assert!(!trust.identity_proven(), "{:?}", trust.reasons);
        assert!(
            !trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::CatalogUnvouched { .. })),
            "a file no catalog mentions is not `unvouched`, it is unmentioned: {:?}",
            trust.reasons
        );
        assert_eq!(trust.magnitude, 0);
    }

    #[test]
    fn a_catalog_from_an_unknown_authority_is_recorded_but_earns_nothing() {
        let (data, index) = catalogued("Some OEM Root CA");
        let image = PeInput::parse(&data).expect("the fixture is a PE");
        let policy = TrustPolicy::default();
        let trust = policy.assess(
            Path::new("C:\\elsewhere\\thing.dll"),
            Some(&image),
            Some(&index),
        );
        assert!(!trust.identity_proven());
        assert!(
            trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::CatalogUnvouched { .. })),
            "{:?}",
            trust.reasons
        );
        assert_eq!(trust.magnitude, 0);
        // And so it is not shown. Most third-party files are listed in some
        // catalog; reporting that fact on every one of them is noise.
        assert_eq!(trust.reportable().count(), 0);
    }

    #[test]
    fn a_certificate_and_a_catalog_are_one_statement_not_two() {
        // Both are statements about who published the file, so they share a
        // bucket and the stronger wins. Adding them would let a file that is
        // signed *and* catalogued claim 100 points of trust for one publisher.
        let (data, index) = catalogued(MS_ROOT);
        let image = signed_pe_with(&data, MS_ROOT);
        let parsed = PeInput::parse(&image).expect("the fixture is a PE");
        let policy = TrustPolicy::default();
        let trust = policy.assess(
            Path::new("C:\\elsewhere\\thing.dll"),
            Some(&parsed),
            Some(&index),
        );
        assert!(
            trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::KnownAuthority { .. })),
            "the fixture should carry an embedded signature too: {:?}",
            trust.reasons
        );
        assert!(trust.identity_proven());
        assert_eq!(trust.magnitude, 60, "{:?}", trust.reasons);
    }

    /// A trust assessment whose signature was *verified*, built without a real
    /// signature.
    ///
    /// Nothing here is verified: the assessment is handed over ready-made, the
    /// way [`catalogued_trust`] is. The proof itself is made and tested where it
    /// belongs — [`mod@av_authenticode::verify`] against real binaries in an
    /// installed `System32`, and
    /// [`a_signature_that_only_parses_earns_the_discount_and_not_the_clear`]
    /// below for the other direction. What these tests pin is the policy's
    /// arithmetic once a proof *exists*, which is the half that decides whether
    /// the wiring is worth anything at all.
    fn verified_trust() -> TrustAssessment {
        TrustAssessment {
            magnitude: 60,
            reasons: vec![TrustReason::VerifiedSignature {
                subject: "/CN=Microsoft Windows, O=Microsoft Corporation, C=US".into(),
                root: MS_ROOT.into(),
            }],
        }
    }

    #[test]
    fn a_verified_signature_proves_identity_the_way_a_catalog_entry_does() {
        // The point of wiring verification in at all. A catalog listing proves
        // the file's bytes are the ones an authority vouched for; a verified
        // signature proves the same thing by arithmetic, so it has to open the
        // same response — the clear — and not a narrower one, or the wiring
        // would buy nothing over the certificate reading it replaces.
        let policy = TrustPolicy::default();
        let trust = verified_trust();
        assert!(trust.identity_proven(), "{:?}", trust.reasons);
        assert_eq!(trust.magnitude, 60);

        let mut a = assessment(vec![
            signed(
                "heuristic/packed/a",
                Severity::High,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/packed/b",
                Severity::Medium,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/packed/c",
                Severity::Low,
                DetectionSource::Heuristic,
            ),
        ]);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        // Malicious to start with, so the clear is doing work rather than
        // confirming a band that was already harmless. One High heuristic is
        // what puts it there: 100 is the convicting rung, and generic evidence
        // reaches it only by being confident, never by being plentiful.
        assert_eq!(a.verdict, Verdict::Malicious);
        policy.discount(&mut a, &trust);
        policy.cap_verdict(&mut a, &trust);
        policy.clear_generic(&mut a, &trust);
        assert_eq!(a.verdict, Verdict::Clean);
        assert_eq!(a.suppressed.len(), 3);
    }

    #[test]
    fn a_signature_that_only_parses_earns_the_discount_and_not_the_clear() {
        // **The failure mode that would matter**, and the reason the verified
        // path is a variant of its own rather than a flag on the reading.
        //
        // [`signed_pe_with`] appends a well-formed PKCS#7 that nobody signed:
        // the bytes all parse, the issuer reads as Microsoft's, and not one octet
        // of it verifies. A trust layer that called *that* verified would be
        // weaker than this one rather than stronger, so the assessment has to
        // reach the file through the reading — a claim, 40 points, a discount and
        // no clear — and must not manufacture a proof for it.
        let (data, _) = catalogued(MS_ROOT);
        let image = signed_pe_with(&data, MS_ROOT);
        let parsed = PeInput::parse(&image).expect("the fixture is a PE");
        let policy = TrustPolicy::default();
        // No catalog, so the signature is the only thing that could prove the
        // identity — which is exactly what must not happen here.
        let trust = policy.assess(Path::new("C:\\elsewhere\\thing.dll"), Some(&parsed), None);
        assert!(
            !trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::VerifiedSignature { .. })),
            "a signature that merely parsed was reported as verified: {:?}",
            trust.reasons
        );
        assert!(!trust.identity_proven(), "{:?}", trust.reasons);
        assert!(
            trust
                .reasons
                .iter()
                .any(|r| matches!(r, TrustReason::KnownAuthority { .. })),
            "the reading should still record the claim: {:?}",
            trust.reasons
        );
        assert_eq!(trust.magnitude, 40);
    }

    #[test]
    fn a_certificate_that_only_parsed_is_never_a_proven_identity() {
        // The boundary, pinned directly rather than through a scan of a
        // fixture. Everything in `TrustReason` other than the two arithmetic
        // reasons is a string an attacker with a text editor can write, and
        // `identity_proven` is what entitles a reason to clear a detection.
        // Joining `KnownAuthority` to that match would make the trust layer
        // weaker while every other test here still passed; this is the one that
        // fails.
        let claim = known_cert();
        assert!(!claim.identity_proven(), "{:?}", claim.reasons);
        assert_eq!(claim.magnitude, 40);
    }

    #[test]
    fn a_verified_signature_and_a_certificate_are_one_statement_not_two() {
        // Both are answers to "who published these bytes", so `strongest_per_kind`
        // keeps the stronger of the two and the file earns 60 — not 100, and not
        // 160 with a catalog as well. This is the measured population's shape: a
        // Microsoft binary is signed *and* listed in a catalog, and adding the
        // halves would claim two publishers' worth of trust for one publisher
        // saying the same thing twice.
        let reasons = vec![
            TrustReason::KnownAuthority {
                subject: "Microsoft Windows".into(),
                issuer: MS_ROOT.into(),
            },
            TrustReason::CatalogSigned {
                subject: "Microsoft Windows".into(),
                authority: MS_ROOT.into(),
            },
            TrustReason::VerifiedSignature {
                subject: "Microsoft Windows".into(),
                root: MS_ROOT.into(),
            },
        ];
        assert_eq!(strongest_per_kind(&reasons), 60);
    }

    #[test]
    fn a_disabled_policy_verifies_nothing() {
        // `--no-trust` means no trust, including the half that now costs a chain
        // build and an image digest on every signed file. The switch is checked
        // before anything is read or verified, so a scan that was told not to
        // consult trust does not pay for it either. The contrast with the same
        // file under the default policy is what makes this test mean something:
        // an assertion that an empty assessment is empty would hold just as well
        // if the fixture earned nothing in the first place.
        let (data, index) = catalogued(MS_ROOT);
        let image = signed_pe_with(&data, MS_ROOT);
        let parsed = PeInput::parse(&image).expect("the fixture is a PE");
        let path = Path::new("C:\\elsewhere\\thing.dll");

        let off = TrustPolicy::disabled().assess(path, Some(&parsed), Some(&index));
        assert!(off.reasons.is_empty(), "{:?}", off.reasons);
        assert_eq!(off.magnitude, 0);
        assert!(!off.identity_proven());

        let on = TrustPolicy::default().assess(path, Some(&parsed), Some(&index));
        assert_eq!(on.magnitude, 60, "{:?}", on.reasons);
    }

    /// The same PE with an embedded Authenticode signature added.
    ///
    /// Appending a security directory changes the catalog digest unless the
    /// digest is taken the way Windows takes it — see
    /// [`av_signatures::catalog::hashed_regions`], which cuts out exactly the
    /// two header fields the append edits. So a file can be both signed and
    /// catalogued, which is the case this builds.
    fn signed_pe_with(data: &[u8], issuer: &str) -> Vec<u8> {
        let mut pe = data.to_vec();
        let table =
            av_signatures::testing::win_certificate(&av_signatures::testing::signed_data(&[
                certificate_issued_by(
                    &[0x08],
                    "Microsoft Windows",
                    issuer,
                    "110616000000Z",
                    "400615000000Z",
                ),
            ]));
        av_pe::testing::append_security_directory(&mut pe, &table);
        pe
    }

    #[test]
    fn a_proven_identity_clears_a_pile_of_generic_evidence() {
        // The measured problem, in miniature: a Microsoft binary that four
        // packing heuristics correctly describe, and which no user should ever
        // be shown. 60+60+30+30 = 180, which is past the suspicious line and
        // deliberately short of the convicting one — generic evidence reaches
        // that rung by being confident, not by being plentiful.
        //
        // So the file starts in the warning band and the clear removes the
        // warning. That is the whole job: a heuristic correctly describing how
        // Microsoft built a binary is not a finding, and 750 of them on an
        // untouched installation have taught the user to dismiss all 750.
        let policy = TrustPolicy::default();
        let trust = catalogued_trust();
        let mut a = assessment(vec![
            signed(
                "heuristic/packed/a",
                Severity::Medium,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/packed/b",
                Severity::Medium,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/packed/c",
                Severity::Low,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/imports/d",
                Severity::Low,
                DetectionSource::Heuristic,
            ),
        ]);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Suspicious);
        policy.clear_generic(&mut a, &trust);
        assert_eq!(a.verdict, Verdict::Clean);
        // Nothing thrown away: the evidence is all still there to be read, and
        // the score disagreeing with the verdict is the record that trust
        // decided this and not the detections.
        assert_eq!(a.detections.len(), 4);
        assert_eq!(a.score, 180);
        assert_eq!(a.suppressed.len(), 4);
        assert!(a.remediation_withheld);

        // And the same clear has to answer the harder case, because a proven
        // identity is not only for files that were going to be warned about. A
        // pile that carries one confident heuristic is in the band that acts,
        // and the proof of whose bytes these are settles it just as completely.
        let mut convicted = piled_up_generic(1);
        let thresholds = av_core::VerdictThresholds::default();
        convicted.finalize(&thresholds);
        assert_eq!(convicted.verdict, Verdict::Malicious);
        policy.clear_generic(&mut convicted, &trust);
        assert_eq!(convicted.verdict, Verdict::Clean);
        assert_eq!(convicted.suppressed.len(), 1);
        assert!(convicted.remediation_withheld);
    }

    /// A trust assessment with a proven identity, built without a real catalog.
    fn catalogued_trust() -> TrustAssessment {
        TrustAssessment {
            magnitude: 60,
            reasons: vec![TrustReason::CatalogSigned {
                subject: "/CN=Microsoft Windows".into(),
                authority: MS_ROOT.into(),
            }],
        }
    }

    #[test]
    fn one_detection_that_names_a_family_survives_a_proven_identity() {
        // The bound. A signed file that a rule has identified as a named family
        // is exactly the case where an over-broad rule is worth a user's
        // attention, and it is worth more than 750 false alarms.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![
            signed(
                "heuristic/packed/a",
                Severity::Medium,
                DetectionSource::Heuristic,
            ),
            with_family("lockbit", Severity::Medium),
        ]);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        let before = a.verdict;
        policy.clear_generic(&mut a, &catalogued_trust());
        assert_eq!(a.verdict, before);
        assert!(a.suppressed.is_empty());
    }

    /// The other side of that bound, and the case that made this field
    /// necessary. A rule this product convicts on a *reading* of is a claim
    /// about the rule, not a proof about the file, and a proven identity
    /// answers it — the file is reported clean and the match is kept in
    /// `suppressed`.
    ///
    /// This is `System32\MRT.exe`. The rule matched `http://lockbit` XOR-encoded
    /// in a 228 MB Microsoft binary, and it was right to: MRT is the Malicious
    /// Software Removal Tool, and its own signature database holds malware URLs
    /// in exactly that form. A product that quarantines it has broken the
    /// machine it was installed on.
    #[test]
    fn a_detection_decisive_on_a_reading_yields_to_a_proven_identity() {
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![
            signed(
                "heuristic/packed/a",
                Severity::Low,
                DetectionSource::Heuristic,
            ),
            signed(
                "SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1",
                Severity::High,
                DetectionSource::Signature,
            )
            .decisive(),
        ]);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Malicious);
        policy.cap_verdict(&mut a, &catalogued_trust());
        policy.clear_generic(&mut a, &catalogued_trust());
        assert_eq!(a.verdict, Verdict::Clean);
        // Nothing is thrown away: the report can still answer "was anything
        // seen in this file", which is what a user asks when they are told a
        // file is clean and do not believe it.
        assert_eq!(
            a.suppressed,
            vec![
                "heuristic/packed/a".to_owned(),
                "SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1".to_owned(),
            ]
        );
        assert_eq!(a.detections.len(), 2);
    }

    /// The reading is asked before the family is, and this is the case that
    /// needs it to be: a rule that declares a family in its metadata *and*
    /// convicts on a reading.
    ///
    /// The corpus has three such rules — the Hiddencobra ones, which carry both
    /// `family` and `category`. Asked the other way round they would be exempt
    /// from the trust layer on the strength of a label their author put on the
    /// *rule*, which is exactly the kind of claim the trust layer has standing
    /// on.
    #[test]
    fn a_reading_conviction_is_generic_even_when_the_rule_declares_a_family() {
        const HIDDENCOBRA: &str = "SIGNATURE_BASE_APT_Hiddencobra_Enc_PK_Header";

        let labelled = with_family(HIDDENCOBRA, Severity::High);
        assert!(!is_generic(&labelled), "a declared family is not generic");

        let read = with_family(HIDDENCOBRA, Severity::High).decisive();
        assert!(convicts_on_a_reading(&read));
        assert!(is_generic(&read), "but a reading of it is");

        let rated = with_family(HIDDENCOBRA, Severity::High).incontestable();
        assert!(!is_generic(&rated), "and an author's rating is not");
    }

    #[test]
    fn a_forged_certificate_earns_the_discount_but_not_the_clear() {
        // The distinction the whole design turns on, pinned as a test. Nothing
        // verifies a signature — `recognises` is a substring match on the issuer
        // — so a self-signed certificate that *claims* to be Microsoft's earns
        // the 40-point discount like any other. It does not earn the clear,
        // because the clear asks for a catalog listing the file's own bytes,
        // which needs a preimage.
        let policy = TrustPolicy::default();
        let forged = TrustAssessment {
            magnitude: 40,
            reasons: vec![TrustReason::KnownAuthority {
                subject: "Totally Legit Software".into(),
                issuer: MS_ROOT.into(),
            }],
        };
        // One confident heuristic beside one ordinary one, so the file starts in
        // the band that acts: the discount has a band to move it out of, and the
        // clear has a claim to decline. Two ordinary heuristics would be the
        // warning band, where declining to clear proves nothing.
        let mut a = assessment(vec![
            signed(
                "heuristic/packed/a",
                Severity::High,
                DetectionSource::Heuristic,
            ),
            signed(
                "heuristic/packed/b",
                Severity::Medium,
                DetectionSource::Heuristic,
            ),
        ]);
        let thresholds = av_core::VerdictThresholds::default();
        a.finalize(&thresholds);
        assert_eq!(a.verdict, Verdict::Malicious);
        policy.discount(&mut a, &forged);
        policy.cap_verdict(&mut a, &forged);
        policy.clear_generic(&mut a, &forged);
        assert_eq!(
            a.verdict,
            Verdict::Suspicious,
            "a claim is worth a notification, not a clean bill of health"
        );
        assert!(a.suppressed.is_empty());
    }

    #[test]
    fn an_unknown_verdict_is_not_cleared_by_a_proven_identity() {
        // A scan that could not finish has no business being called clean, and
        // the exclusion is structural: `Unknown` is not a detection.
        let policy = TrustPolicy::default();
        let mut a = Assessment::unknown("the scan ran out of budget");
        policy.clear_generic(&mut a, &catalogued_trust());
        assert_eq!(a.verdict, Verdict::Unknown);
    }

    #[test]
    fn a_disabled_policy_clears_nothing() {
        let policy = TrustPolicy::disabled();
        let mut a = assessment(vec![signed(
            "heuristic/packed/a",
            Severity::Low,
            DetectionSource::Heuristic,
        )]);
        a.finalize(&av_core::VerdictThresholds::default());
        policy.clear_generic(&mut a, &catalogued_trust());
        assert_eq!(a.verdict, Verdict::Suspicious);
    }

    #[test]
    fn an_observation_of_running_behaviour_is_never_cleared() {
        // The strongest form of the bound: not because the file is guilty, but
        // because code-signing is evidence about how a file was built and about
        // nothing that happened on this machine afterwards.
        let policy = TrustPolicy::default();
        let mut a = assessment(vec![signed(
            "behaviour/encrypts_files",
            Severity::Low,
            DetectionSource::Behavior,
        )]);
        a.finalize(&av_core::VerdictThresholds::default());
        policy.clear_generic(&mut a, &catalogued_trust());
        assert_eq!(a.verdict, Verdict::Suspicious);
    }
}

/// The trust measurement, opt-in because it reads the installed operating
/// system.
///
/// ```text
/// cargo test -p av-scan -- --ignored --nocapture
/// ```
///
/// It exists because the interesting question about trust is not what the policy
/// does with a reason — the tests above cover that — but **which reasons real
/// signed binaries actually earn**. A policy that discounts 40 points for a
/// known authority is worth nothing if the authority is never recognised, and
/// the failure is invisible: a file that earns only its path's 10 points looks
/// exactly like a file that was never signed at all.
#[cfg(test)]
mod measurement {
    use crate::trust::{TrustPolicy, TrustReason};
    use av_rules::vm::PeInput;
    use std::path::PathBuf;

    /// The binaries Windows is most obviously signed with, and the ones a scan
    /// of `System32` flagged.
    const SUBJECTS: &[&str] = &[
        "System32\\OneDriveSetup.exe",
        "System32\\MRT.exe",
        "System32\\Faultrep.dll",
        "System32\\WinSAT.exe",
        "System32\\ieframe.dll",
        "System32\\Windows.Media.Protection.PlayReady.dll",
        "System32\\kernel32.dll",
        "System32\\notepad.exe",
        "System32\\SogouPY.ime",
    ];

    #[test]
    #[ignore = "reads the installed Windows binaries"]
    fn what_trust_real_signed_binaries_earn() {
        let root = std::env::var_os("SystemRoot").expect("a Windows installation");
        let policy = TrustPolicy::default();
        let mut signed_by_authority = 0usize;
        let mut verified = 0usize;
        let mut seen = 0usize;

        for name in SUBJECTS {
            let path = PathBuf::from(&root).join(name);
            // `av_fs::read`, not `std::fs::read`. The difference is the one this
            // crate's manifest documents: the standard library's version reports
            // every file whose permissions exclude the scanning account as
            // unreadable, and a diagnostic that cannot tell "this machine does
            // not have the file" from "this account may not read it" prints a
            // ratio over a population it did not choose.
            let bytes = match av_fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    println!("{name:56} unread ({error})");
                    continue;
                }
            };
            seen += 1;
            let image = PeInput::parse(&bytes).expect("parses");
            let certificates = image.signatures().len();
            let trust = policy.assess(&path, Some(&image), None);
            let authority = trust
                .reasons
                .iter()
                .any(|reason| matches!(reason, TrustReason::KnownAuthority { .. }));
            if authority {
                signed_by_authority += 1;
            }
            // The count that matters: these are the files whose identity is
            // *proven* rather than claimed, and the population the verified
            // path is supposed to reach. Zero here means the wiring is inert.
            let is_verified = trust
                .reasons
                .iter()
                .any(|reason| matches!(reason, TrustReason::VerifiedSignature { .. }));
            if is_verified {
                verified += 1;
            }
            println!(
                "{name:56} certs={certificates} magnitude={:3} authority={authority} \
                 verified={is_verified}",
                trust.magnitude
            );
            for reason in &trust.reasons {
                println!(
                    "{:58} {:<28} magnitude={}",
                    "",
                    match reason {
                        TrustReason::KnownAuthority { .. } => "KnownAuthority",
                        TrustReason::UnknownAuthority { .. } => "UnknownAuthority",
                        TrustReason::StaleCertificate { .. } => "StaleCertificate",
                        TrustReason::TrustedPath(_) => "TrustedPath",
                        TrustReason::UserAllowed => "UserAllowed",
                        TrustReason::Unsigned => "Unsigned",
                        TrustReason::CatalogSigned { .. } => "CatalogSigned",
                        TrustReason::CatalogUnvouched { .. } => "CatalogUnvouched",
                        TrustReason::VerifiedSignature { .. } => "VerifiedSignature",
                    },
                    reason.magnitude()
                );
                if let TrustReason::KnownAuthority { subject, issuer }
                | TrustReason::UnknownAuthority { subject, issuer } = reason
                {
                    println!("{:58} subject={subject:?}", "");
                    println!("{:58} issuer={issuer:?}", "");
                }
                if let TrustReason::VerifiedSignature { subject, root } = reason {
                    println!("{:58} subject={subject:?}", "");
                    println!("{:58} root={root:?}", "");
                }
            }
        }

        // The first line is deliberately not phrased as "N of {seen} are signed
        // by a recognised authority", which is how it read and what it is not.
        // `assess_verified` runs before `assess_signature` and *replaces* it, so
        // a file whose chain verifies never reaches the authority list at all —
        // see that function's documentation for why the replacement is right.
        // On a stock installation every signed file takes the verified path, so
        // this counter is structurally zero and a reader who took it for a
        // failure would be reading a real number as a broken mechanism. What it
        // actually measures is the fallback: signed files whose chain did *not*
        // verify, which are the only ones the list still decides.
        println!(
            "\n{signed_by_authority} of {seen} fell back to the authority list \
             (a verified chain replaces it, so a signed file only appears here \
             when verification failed)"
        );
        println!("{verified} of {seen} carry a cryptographically verified signature");
        // Advisory rather than an assertion: what this machine's binaries are
        // signed with is a fact about the machine and not about the policy. The
        // number is printed so that a change in it is visible.
        //
        // `verified` is the one worth reading as a pass or a fail. It is
        // expected to be most of `seen` on a stock installation, because every
        // one of these binaries ships signed by Microsoft with a chain to a
        // root Windows trusts; a zero means the verified path is not reaching
        // the files it was written for, which is a defect and not a fact about
        // the machine.
    }

    /// Which authority names actually appear in the installed operating system.
    ///
    /// `KNOWN_AUTHORITIES` is a list of issuer names matched as substrings, and
    /// a list like that is only as good as the evidence behind it. This prints
    /// the evidence: every certificate of every embedded-signed file in
    /// `System32`, by subject and by issuer, most common first.
    ///
    /// Two things it answers that cannot be guessed:
    ///
    /// * Whether a *root* is present in the blob. A chain that stops at an
    ///   intermediate has no self-signed certificate in it, so a policy that
    ///   only matched issuers would recognise nothing — the intermediate's
    ///   subject has to be matchable too.
    /// * Which names to put in the list. Microsoft's own CAs are the ones on
    ///   the operating system, and they are not the commercial ones a list
    ///   written from memory would contain.
    #[test]
    #[ignore = "reads the installed Windows binaries"]
    fn what_authorities_sign_the_installed_operating_system() {
        use std::collections::HashMap;

        let root = std::env::var_os("SystemRoot").expect("a Windows installation");
        let dir = PathBuf::from(&root).join("System32");
        let mut files = 0usize;
        let mut signed = 0usize;
        let mut certificates = 0usize;
        let mut self_signed = 0usize;
        let mut first_is_not_the_leaf = 0usize;
        let mut first_is_the_leaf_but_not_unique = 0usize;
        let mut subjects: HashMap<String, usize> = HashMap::new();
        let mut issuers: HashMap<String, usize> = HashMap::new();
        let mut signable: Vec<(String, usize, bool)> = Vec::new();

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                println!("cannot read {}: {error}", dir.display());
                return;
            }
        };
        // Counted rather than dropped. A file this account cannot open is not a
        // file that is not there, and the difference decides whether a name
        // missing from the tables below is absent from the operating system or
        // merely absent from what this run could see.
        let mut unreadable = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            // `av_fs::read`, for the reason this crate's manifest gives: the
            // standard library's version fails on exactly the files whose
            // permissions exclude the scanning account.
            let bytes = match av_fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            let Ok(image) = PeInput::parse(&bytes) else {
                continue;
            };
            files += 1;
            let chain = image.signatures();
            if chain.is_empty() {
                continue;
            }
            signed += 1;
            certificates += chain.len();
            let mut has_root = false;
            for certificate in chain {
                let subject = certificate
                    .subject()
                    .unwrap_or_else(|_| "<unreadable>".to_owned());
                let issuer = certificate
                    .issuer()
                    .unwrap_or_else(|_| "<unreadable>".to_owned());
                if subject == issuer {
                    has_root = true;
                    self_signed += 1;
                }
                *subjects.entry(subject).or_default() += 1;
                *issuers.entry(issuer).or_default() += 1;
            }

            // Whose certificate is first, and can it be told apart from the
            // rest? `assess_signature` reads the first one as the signer, which
            // is only right if the blob lists the leaf first — and the format
            // does not require it.
            //
            // A leaf is the certificate nothing else in the chain is issued by,
            // so the test is on how many members name each member as their
            // issuer. A self-signed root names itself, which is why the count
            // includes the certificate's own issuer rather than skipping it.
            let children: Vec<usize> = chain
                .iter()
                .map(|certificate| {
                    let subject = certificate.subject().unwrap_or_default();
                    chain
                        .iter()
                        .filter(|other| other.issuer().ok().as_deref() == Some(subject.as_str()))
                        .count()
                })
                .collect();
            let childless = children.iter().filter(|count| **count == 0).count();
            if children[0] != 0 {
                first_is_not_the_leaf += 1;
            } else if childless != 1 {
                first_is_the_leaf_but_not_unique += 1;
            }

            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            signable.push((name, chain.len(), has_root));
        }

        let mut subjects: Vec<(String, usize)> = subjects.into_iter().collect();
        subjects.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut issuers: Vec<(String, usize)> = issuers.into_iter().collect();
        issuers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        println!(
            "{signed} of {files} files in {} carry an embedded signature, \
             {certificates} certificates, {self_signed} of them self-signed",
            dir.display()
        );
        // Printed before the tables, because it is the denominator's caveat:
        // every count below is over the files this run could open, and a name
        // that is missing from them may be missing for either reason.
        println!("{unreadable} files in that directory could not be read at all");
        println!("\nsubjects, most common first:");
        for (name, count) in subjects.iter().take(25) {
            println!("  {count:5}  {name}");
        }
        println!("\nissuers, most common first:");
        for (name, count) in issuers.iter().take(25) {
            println!("  {count:5}  {name}");
        }
        let without_root = signable.iter().filter(|(_, _, root)| !root).count();
        println!("\n{without_root} of {signed} chains contain no self-signed certificate");
        println!(
            "{first_is_not_the_leaf} of {signed} chains do not list the leaf first, \
             and in {first_is_the_leaf_but_not_unique} the first certificate is \
             childless but still has children"
        );
        for (name, count, has_root) in signable.iter().take(8) {
            println!("  {count} certs, root={has_root}  {name}");
        }
    }
}
