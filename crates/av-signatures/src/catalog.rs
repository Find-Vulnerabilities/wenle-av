//! Catalog signatures — how Windows signs most of itself.
//!
//! # Why this exists, in one measurement
//!
//! [`crate::certificates`] reads the signature embedded in a file. Measured
//! against an installed `System32`, that path reaches almost nothing:
//!
//! ```text
//! Get-AuthenticodeSignature over System32\*.dll
//!     Catalog      3,331
//!     Authenticode    71
//! ```
//!
//! Embedded signatures in `System32\*.dll`: 71 of 3,402. Embedded signatures in
//! all 4,102 files of `System32`: 836. The rest are signed by *catalog* — a
//! `.cat` file in `C:\Windows\System32\CatRoot\{F750E6C3-…}\` (7,300 files,
//! 1.2 GB on this machine) that lists the hashes of the files it covers, and is
//! itself signed. There is no signature in the file; the signature is somewhere
//! else and names the file by hash.
//!
//! So without this module the trust layer is inert for exactly the population
//! it was written to protect: `AcLayers.dll` and its 3,330 neighbours come back
//! from [`crate::certificates`] with nothing, the trust policy sees `Unsigned`,
//! and the heuristics that fire on them cannot be discounted. That is a
//! measured consequence, not a hypothesis — see
//! [`crate::catalog`]'s measurement tests.
//!
//! # The format, as the files actually are
//!
//! A `.cat` is a PKCS#7 `SignedData` whose content type is not the
//! `SpcIndirectDataContent` of an Authenticode blob but `szOID_CTL`
//! (`1.3.6.1.4.1.311.10.1`), and whose content is a `CertificateTrustList`:
//!
//! ```text
//! CertificateTrustList ::= SEQUENCE {
//!     subjectUsage        SEQUENCE OF OBJECT IDENTIFIER,
//!     listIdentifier      OCTET STRING OPTIONAL,
//!     sequenceNumber      INTEGER OPTIONAL,
//!     thisUpdate          UTCTime,
//!     nextUpdate          UTCTime OPTIONAL,
//!     subjectAlgorithm    AlgorithmIdentifier,
//!     trustedSubjects     SEQUENCE OF TrustedSubject,
//!     ctlExtensions   [0] EXPLICIT SEQUENCE OF ... OPTIONAL }
//!
//! TrustedSubject ::= SEQUENCE {
//!     hash                OCTET STRING,
//!     attributes          SET OF ... OPTIONAL }
//! ```
//!
//! This layout was read off real catalogs rather than taken from a
//! specification, and two things about it are not what the shape suggests.
//!
//! **There is no version field.** Almost every structure in this crate can be
//! counted off from the front, because its first element is a version. This one
//! cannot: `subjectUsage` comes first, and the three fields after it are all
//! optional. So the field this module is after is located by shape, and
//! `trusted_subjects` documents why the shape test cannot pick the wrong
//! element.
//!
//! **One catalog holds two hash algorithms at once.** A real catalog was seen
//! carrying both 20-byte and 32-byte digests in the same `trustedSubjects`, so
//! a reader that decided the algorithm once for the whole file — from
//! `subjectAlgorithm`, or from the digest algorithms of the signature — would
//! fail to match the entries stored under the other one. The algorithm here is
//! read per entry, from the length of the digest itself.
//!
//! # What a match means, and what it does not
//!
//! A match means the file's own bytes digest to a value that appears in a
//! catalog in the catalog store. It does **not** mean a signature was verified:
//! nothing in this crate verifies a signature — see the crate documentation for
//! why that is a decision rather than an omission — and the catalog's own
//! signature is no more checked than an embedded one is.
//!
//! Two consequences are worth stating plainly, because a trust decision built
//! on this is only as good as they allow:
//!
//! - **The catalog store is writable by an administrator.** A `.cat` planted in
//!   `CatRoot` makes every file whose digest it lists look catalogued. This is
//!   why a match is routed through the same authority check an embedded
//!   certificate goes through — the signer is read from the catalog, with
//!   [`crate::pkcs7::certificates`] on the same blob — rather than being
//!   accepted as an anonymous "listed somewhere".
//! - **The digest is the only thing tying the catalog to the file.** The
//!   attribute for a file's *name* is present in a catalog and is deliberately
//!   not read: a name is not evidence, and matching on one would let a file
//!   claim a catalogued identity by being called the same thing.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use av_pe::PeFile;
use sha1::Digest as _;
use sha2::Sha256;

use crate::catalog_cache::{self, CacheMiss, CatalogStamp, Loaded, StoreState};
use crate::der::{self, OCTET_STRING, SEQUENCE};
use crate::error::SignatureError;
use crate::oid;

/// The `szOID_CTL` content type, `1.3.6.1.4.1.311.10.1`.
const CTL_CONTENT_TYPE: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 10, 1];

/// The `[0]` wrapper every PKCS#7 content field uses.
const CONTENT_TAG: u8 = der::context(0);

/// The hash a trusted subject's `OCTET STRING` is a digest of.
///
/// Named rather than left as a length, because the length is the *only* thing
/// the file states and a bare `20` at a call site reads as a constant somebody
/// measured once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-1: a 20-byte digest.
    Sha1,
    /// SHA-256: a 32-byte digest.
    Sha256,
}

impl HashAlgorithm {
    /// The length of a digest this algorithm produces.
    pub const fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
        }
    }

    /// The algorithm a digest of `len` bytes is taken to be.
    ///
    /// # Why this is a guess, and why it is a safe one
    ///
    /// A catalog states the algorithm for the list as a whole in
    /// `subjectAlgorithm`, and real catalogs contradict it: one was measured
    /// carrying 20-byte and 32-byte digests side by side. The entry states
    /// nothing. So the length is what is left, and it happens to be enough —
    /// SHA-1 and SHA-256 are the only two algorithms Windows has ever put in a
    /// catalog, and their widths are distinct.
    ///
    /// The guess is safe because of what a match is *for*: catalog membership
    /// is a positive trust signal that can only ever discount a score, never
    /// convict. Getting it wrong costs a missed discount, which is where the
    /// scanner already was. The one thing that could go wrong in the other
    /// direction is a 20-byte digest that is not a SHA-1 — and matching one of
    /// those requires a second-preimage against a digest already in a signed
    /// catalog, which is not a thing SHA-1's break gives an attacker.
    ///
    /// `None` for a length that is neither. A 16-byte digest is MD5, which no
    /// catalog uses, and an entry of a width this cannot name is skipped rather
    /// than carried as an unmatched mystery: it could never match a digest this
    /// crate computes.
    pub const fn from_digest_len(len: usize) -> Option<Self> {
        match len {
            20 => Some(HashAlgorithm::Sha1),
            32 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    /// The algorithm's name, as it is printed in a report.
    pub const fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "SHA-1",
            HashAlgorithm::Sha256 => "SHA-256",
        }
    }
}

/// One file digest a catalog lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry<'a> {
    /// Which algorithm the digest is of, decided by its length.
    pub algorithm: HashAlgorithm,
    /// The digest, borrowed from the catalog's bytes.
    pub digest: &'a [u8],
}

/// A catalog's list of file digests.
///
/// Borrows the catalog's bytes: the digests are slices of the file that was
/// mapped, and copying them would allocate 32 bytes per covered file across
/// thousands of catalogs for a lookup that only ever compares.
#[derive(Debug, Clone, Default)]
pub struct Catalog<'a> {
    entries: Vec<CatalogEntry<'a>>,
}

impl<'a> Catalog<'a> {
    /// Read a `.cat` file's list of file digests.
    ///
    /// Returns an error for a blob that is not a catalog at all — including an
    /// Authenticode signature, which is also `SignedData` and is rejected on
    /// its content type. A trust list with no trusted subjects is *not* an
    /// error at the outer level: an empty catalog is a legal catalog, and the
    /// caller will simply never match against it.
    pub fn parse(blob: &'a [u8]) -> Result<Self, SignatureError> {
        let ctl = trust_list(blob)?;
        Ok(Self {
            entries: read_entries(ctl)?,
        })
    }

    /// The digests the catalog lists, in file order.
    pub fn entries(&self) -> &[CatalogEntry<'a>] {
        &self.entries
    }

    /// How many digests it lists.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it lists none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a digest the caller computed appears in the list.
    ///
    /// The algorithm is passed rather than inferred, so that a caller holding a
    /// digest of a known algorithm never has a lookup depend on a guess. A
    /// caller that wants to try both — which is what the trust layer does,
    /// because a catalog may hold either — asks twice, and [`lists_file`] is
    /// that loop, returning the algorithm that answered.
    pub fn contains(&self, algorithm: HashAlgorithm, digest: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.algorithm == algorithm && entry.digest == digest)
    }

    /// Which algorithms this catalog stores digests under.
    ///
    /// A caller that is about to compute a digest wants to know whether
    /// computing it can possibly pay: hashing a 100 MB file for an algorithm
    /// the catalog has no entries for is a cost with no answer at the end of
    /// it. Both algorithms are named when both are present, which real
    /// catalogs do.
    pub fn algorithms(&self) -> Vec<HashAlgorithm> {
        let mut out = Vec::new();
        for entry in &self.entries {
            if !out.contains(&entry.algorithm) {
                out.push(entry.algorithm);
            }
        }
        out
    }
}

/// The `CertificateTrustList` inside a catalog file.
fn trust_list(blob: &[u8]) -> Result<der::Tlv<'_>, SignatureError> {
    let content_info = der::parse_one(blob)?;
    let mut fields = content_info.sequence()?;
    let content_type = fields.expect(der::OBJECT_IDENTIFIER)?;
    if !oid::is_signed_data(content_type.content) {
        return Err(SignatureError::NotPkcs7 {
            reason: "the content type is not signedData",
        });
    }
    let content = fields
        .expect(CONTENT_TAG)
        .map_err(|_| SignatureError::NotPkcs7 {
            reason: "signedData has no content",
        })?;
    let signed_data = der::parse_one(content.content)?;
    let mut signed_fields = signed_data.sequence()?;

    // version, digestAlgorithms, then encapContentInfo.
    signed_fields.skip_n(2)?;
    let encap = signed_fields.expect(SEQUENCE)?;
    let mut encap_fields = encap.sequence()?;
    let encap_type = encap_fields.expect(der::OBJECT_IDENTIFIER)?;
    if !oid::oid_matches(encap_type.content, CTL_CONTENT_TYPE) {
        return Err(SignatureError::NotCatalog {
            reason: "the content type is not a certificate trust list",
        });
    }
    let content = encap_fields
        .expect(CONTENT_TAG)
        .map_err(|_| SignatureError::NotCatalog {
            reason: "the trust list has no content",
        })?;
    let ctl = der::parse_one(content.content)?;
    if !ctl.is(SEQUENCE) {
        return Err(SignatureError::NotCatalog {
            reason: "the trust list is not a sequence",
        });
    }
    Ok(ctl)
}

/// The `trustedSubjects` field of a trust list.
///
/// # Why this is found by shape rather than by position
///
/// `CertificateTrustList` has no version field, and three of the five fields
/// between its start and `trustedSubjects` are optional. Counting elements off
/// the front therefore does not work: a catalog that omits `nextUpdate` gives a
/// different index from one that has it, and both are legal. The field is
/// instead identified by the shape the format gives it — a sequence of
/// sequences — and every element in front of it fails that test for a reason of
/// its own rather than by luck:
///
/// ```text
/// subjectUsage      SEQUENCE OF OBJECT IDENTIFIER
///                     -> first element is an OID, not a SEQUENCE
/// listIdentifier    OCTET STRING
/// sequenceNumber    INTEGER
/// thisUpdate        UTCTime
/// nextUpdate        UTCTime (optional)
/// subjectAlgorithm  SEQUENCE { OBJECT IDENTIFIER, ... }
///                     -> first element is an OID, not a SEQUENCE
/// ctlExtensions [0] context tag, not a SEQUENCE at all
/// ```
///
/// The one that matters is `subjectAlgorithm`: it is the only other `SEQUENCE`
/// among them, and it is separated from `trustedSubjects` only by being an
/// `AlgorithmIdentifier` — a sequence whose first element is an OID — where
/// `trustedSubjects` is a sequence whose first element is a sequence.
/// `the_subject_algorithm_is_not_mistaken_for_the_subject_list` pins that, and
/// `a_digest_shaped_extension_is_not_read_as_a_subject_list` pins the other
/// near miss, since `ctlExtensions` nests a sequence of sequences and a reader
/// that searched every descendant instead of the direct children would find it.
///
/// # The two things this test is deliberately loose about
///
/// An **empty** sequence is accepted as the subject list, because `SEQUENCE OF`
/// with nothing in it is a legal trust list covering nothing, and it has to
/// parse to an empty catalog rather than to an error. The cost of accepting it
/// is that a *malformed* catalog whose `subjectUsage` is empty would have that
/// field read as the subject list instead — which yields an empty catalog, and
/// therefore a miss. A miss costs a discount the scanner would not have got
/// anyway; the alternative, refusing a legal catalog, costs the same discount on
/// every file that catalog covers.
///
/// The **contents** of the first subject are not checked, only its being a
/// sequence. Checking them here would make a catalog whose first entry is
/// malformed unreadable in its entirety, and the entries are validated
/// individually in [`read_entries`] instead — where one bad entry loses one
/// entry.
fn trusted_subjects<'a>(ctl: der::Tlv<'a>) -> Result<der::Tlv<'a>, SignatureError> {
    for element in ctl.elements() {
        let element = element?;
        if !element.is(SEQUENCE) {
            continue;
        }
        let mut outer = element.elements();
        match outer.next() {
            // An empty sequence: a trust list covering nothing.
            None => return Ok(element),
            Some(Ok(first)) if first.is(SEQUENCE) => return Ok(element),
            // Either a field that is not the subject list, or an element of it
            // that is malformed. Both mean "not this one".
            _ => continue,
        }
    }
    Err(SignatureError::NotCatalog {
        reason: "the trust list has no trusted subjects",
    })
}

/// Every digest in the trust list's `trustedSubjects`.
fn read_entries(ctl: der::Tlv<'_>) -> Result<Vec<CatalogEntry<'_>>, SignatureError> {
    let subjects = trusted_subjects(ctl)?;
    let mut entries = Vec::new();
    for subject in subjects.elements() {
        let subject = subject?;
        if !subject.is(SEQUENCE) {
            continue;
        }
        let mut fields = subject.elements();
        let Some(Ok(hash)) = fields.next() else {
            continue;
        };
        if !hash.is(OCTET_STRING) {
            continue;
        }
        // A width no algorithm claims is skipped, not carried: see
        // `HashAlgorithm::from_digest_len`.
        let Some(algorithm) = HashAlgorithm::from_digest_len(hash.content.len()) else {
            continue;
        };
        entries.push(CatalogEntry {
            algorithm,
            digest: hash.content,
        });
    }
    Ok(entries)
}

/// The three runs of bytes a catalog digest covers.
///
/// # What is excluded, and why there are three runs rather than one
///
/// Authenticode's file digest is taken over the image with two fields cut out
/// of the optional header, because both of them change when a file is signed:
///
/// - `CheckSum` — recomputed over the signed image, so it cannot be hashed.
/// - the `IMAGE_DIRECTORY_ENTRY_SECURITY` entry — zero before signing and
///   pointing at the certificate table afterwards.
///
/// The attribute certificate table itself is excluded as well, since a file
/// that carries one would otherwise digest differently from the same file
/// without it. That is the whole reason a catalog is useful for a file with no
/// embedded signature: the digest is the same either way.
///
/// The result is three ranges rather than a set of excluded ranges because the
/// digest is over the *concatenation* of what remains, and a caller that built
/// the remaining bytes first would copy a file to hash it. Hashing three slices
/// in order is the same digest for none of the memory.
///
/// `pe.checksum_field_offset()` and `pe.security_directory_entry_offset()` are
/// where these two fields are; they exist in `av-pe` for this caller.
pub fn hashed_regions(pe: &PeFile<'_>) -> Result<[Range<usize>; 3], SignatureError> {
    let image = pe.data();
    let checksum = pe.checksum_field_offset();
    let checksum_end = checksum + 4;
    let security = pe.security_directory_entry_offset();
    let security_end = security + 8;

    // The header's own layout puts `CheckSum` before the directory array, so
    // one bound check covers both offsets: a file too short for the second is
    // too short for the first.
    if security_end > image.len() {
        return Err(SignatureError::Truncated { at: pe.pe_offset });
    }

    // Where the image stops. A file with an attribute certificate table ends at
    // that table, whose address is a file offset rather than an RVA — the one
    // place in the format where that is true. A file without one runs to the
    // end of the buffer, overlay included: an overlay is part of the file the
    // digest is of, even though nothing loads it.
    let end = {
        let entry = pe.security_directory();
        if entry.is_present() {
            (entry.virtual_address as usize).min(image.len())
        } else {
            image.len()
        }
    };

    Ok([0..checksum, checksum_end..security, security_end..end])
}

/// The digest a catalog lists a PE under, for one algorithm.
///
/// An error rather than a wrong answer when the file is too short to hold the
/// two header fields the computation skips: a digest of a file whose header is
/// truncated would be a digest of something other than what Windows hashed, and
/// a miss is the honest outcome.
pub fn file_digest(pe: &PeFile<'_>, algorithm: HashAlgorithm) -> Result<Vec<u8>, SignatureError> {
    let image = pe.data();
    let regions = hashed_regions(pe)?;
    match algorithm {
        HashAlgorithm::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            for region in regions {
                hasher.update(&image[region]);
            }
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for region in regions {
                hasher.update(&image[region]);
            }
            Ok(hasher.finalize().to_vec())
        }
    }
}

/// Whether a catalog lists this file, and under which algorithm.
///
/// Both algorithms are tried, and only the ones the catalog actually stores
/// digests for are computed — hashing a large file under an algorithm the
/// catalog has no entries for cannot match and would be paid for nothing.
pub fn lists_file(pe: &PeFile<'_>, catalog: &Catalog<'_>) -> Option<HashAlgorithm> {
    for algorithm in catalog.algorithms() {
        let Ok(digest) = file_digest(pe, algorithm) else {
            continue;
        };
        if catalog.contains(algorithm, &digest) {
            return Some(algorithm);
        }
    }
    None
}

// -- the index --------------------------------------------------------------
//
// The functions above answer "does *this* catalog list this file", which is the
// right question for one file and one catalog and the wrong one for a scanner.
// Measured on this machine: the store holds 7,300 catalogs totalling 1,145 MB,
// and reading them takes 1.2 s warm. A scan visits tens of thousands of files,
// so re-reading the store per file is 7,300 × 27,370 file reads, and even
// reading it once per *file* would put 1.2 s in front of every single one.
//
// So the store is read once and inverted: instead of "catalogs → digests", an
// index of "digest → the catalog that listed it". The build is the 1.2 s; a
// lookup after it is two hash computations and a binary search.

/// The directory Windows keeps its catalog store in.
///
/// `None` on a platform that has no catalog store — which is every platform but
/// Windows, and worth stating rather than returning a path that cannot exist,
/// because an empty index and a missing store are the same thing to a caller
/// and only one of them is a fact about the machine.
#[cfg(windows)]
pub fn store_directory() -> Option<std::path::PathBuf> {
    Some(std::path::PathBuf::from(
        r"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
    ))
}

/// The directory Windows keeps its catalog store in.
#[cfg(not(windows))]
pub fn store_directory() -> Option<std::path::PathBuf> {
    None
}

/// The largest catalog that will be read.
///
/// A bound, because the store directory is on disk and anything on disk can be
/// replaced by something larger. Measured on this machine: the largest of the
/// 7,300 catalogs is 11.13 MB and the median is 10.4 KB, so this is 5.7× the
/// largest real catalog — room for a future format to grow, and still small
/// enough that a hostile file cannot make the scanner allocate for minutes. A
/// catalog past it is counted in [`CatalogIndex::catalogs_oversized`] rather
/// than skipped silently, because "the store had a catalog we did not read" is
/// something a user asking why a file was not recognised needs to be able to
/// find out.
pub const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;

/// Who published a catalog, as the catalog's own chain spells it.
///
/// The same two facts the embedded-signature path reports about a signed file,
/// taken from the same place: the leaf's subject, and every issuer named
/// anywhere in the chain. The *issuers* are the list rather than the leaf's
/// alone for the reason [`crate::x509::signer_index`] gives — a Windows leaf's
/// issuer is an intermediate, and the name that identifies the authority is one
/// link further up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogIdentity {
    /// The signing certificate's subject, as the certificate spells it.
    pub subject: String,
    /// Every issuer named in the catalog's chain.
    pub issuers: Vec<String>,
}

impl CatalogIdentity {
    /// Read the publisher out of a catalog blob.
    ///
    /// Empty when the blob carries no readable chain, which is not an error:
    /// a catalog's signature is not parsed by this crate, and a caller that
    /// finds no authority in an empty identity reaches the correct conclusion
    /// (nothing vouches for this catalog) by the same path it reaches it for a
    /// chain it could read and did not recognise.
    fn of_blob(blob: &[u8]) -> Self {
        let Ok(chain) = crate::pkcs7::certificates(blob) else {
            return Self::default();
        };
        let subject = chain
            .get(crate::x509::signer_index(&chain))
            .and_then(|certificate| certificate.subject().ok())
            .unwrap_or_default();
        let issuers = chain
            .iter()
            .filter_map(|certificate| certificate.issuer().ok())
            .collect();
        Self { subject, issuers }
    }
}

/// A digest-to-catalogs lookup over a fixed-width key.
///
/// Sorted flat arrays rather than a `HashMap<Vec<u8>, Vec<u32>>`, which is the
/// shape the measurement chose: 214,820 digests in a hash map is an allocation
/// per key and a pointer to chase per probe, and the whole store fits in one
/// contiguous run of keys with one run of owners beside it — 6.5 MB, no
/// allocation at all after the build, and 17 cache-friendly comparisons per
/// answer.
///
/// # Every catalog, not the first one
///
/// A digest is routinely listed by more than one catalog — the same file is in
/// an operating-system catalog and in a cumulative-update one — and *all* of
/// them are kept. Keeping one and picking it by store order was the first
/// design here and it was wrong in a way worth recording: the question the trust
/// layer asks is "does anything vouch for this file", and answering it from one
/// arbitrarily-chosen catalog makes the answer depend on catalog numbering. A
/// file listed by both a Microsoft catalog and an OEM's would come back
/// unvouched whenever the OEM's file happened to sort first, which is a
/// silent loss of trust for the exact population this index exists to cover.
///
/// So the owners are a slice per digest, not an element: `owners` holds every
/// catalog that listed anything, grouped by key, and `starts` says where each
/// key's group begins.
#[derive(Debug, Default)]
pub(crate) struct DigestSet {
    /// The width of one key. 20 for SHA-1, 32 for SHA-256. Zero when empty.
    stride: usize,
    /// `starts.len().saturating_sub(1) * stride` bytes: every digest, sorted.
    keys: Vec<u8>,
    /// Every (digest, catalog) pair's catalog, grouped by digest.
    owners: Vec<u32>,
    /// `keys.len() / stride + 1` entries. The catalogs listing key `i` are
    /// `owners[starts[i]..starts[i + 1]]`.
    starts: Vec<u32>,
}

impl DigestSet {
    /// Build a set of the given width, discarding entries of any other width.
    pub(crate) fn build(stride: usize, mut entries: Vec<(Vec<u8>, u32)>) -> Self {
        entries.retain(|(digest, _)| digest.len() == stride);
        // Sorted by key then owner, so one digest's owner list comes out in the
        // same order on every run however the store happened to be read — and
        // so that a digest's entries are adjacent and the grouping below is a
        // single pass.
        entries.sort_unstable();
        // The same catalog listing the same digest twice, which a malformed
        // catalog can do. Two identical owners are one statement.
        entries.dedup();

        let mut keys = Vec::with_capacity(entries.len().saturating_mul(stride));
        let mut owners = Vec::with_capacity(entries.len());
        let mut starts: Vec<u32> = Vec::with_capacity(entries.len().saturating_add(1));
        let mut previous: Option<&[u8]> = None;
        for (digest, owner) in &entries {
            if previous != Some(digest.as_slice()) {
                keys.extend_from_slice(digest);
                // `u32` rather than `usize` because the whole store is a few
                // hundred thousand entries and halving the array is worth more
                // than the headroom above four billion.
                starts.push(u32::try_from(owners.len()).unwrap_or(u32::MAX));
                previous = Some(digest.as_slice());
            }
            owners.push(*owner);
        }
        starts.push(u32::try_from(owners.len()).unwrap_or(u32::MAX));

        Self {
            stride,
            keys,
            owners,
            starts,
        }
    }

    /// A set rebuilt from the four arrays, if they are consistent with each
    /// other.
    ///
    /// The parts arrive from a cache file, which is to say from a directory any
    /// local user can write — see [`crate::catalog_cache`], which measured that
    /// — and they are addressed by arithmetic rather than by index: `get`
    /// computes `keys.len() / stride` and reads `owners[starts[i]..starts[i+1]]`
    /// from it. So every invariant [`Self::build`] maintains is re-established
    /// here rather than assumed, and `None` means this is not a set this code
    /// wrote. Every caller treats it as a miss.
    ///
    /// This is not the check that makes a forged cache harmless — the *owner* of
    /// a digest is exactly what a forger gets to choose, and this accepts any
    /// owner that is a `u32`. It is the check that makes one non-fatal: the
    /// arrays are consistent, and it is
    /// `StoreIdentities::identity_listing` that refuses to let a catalog
    /// vouch for a digest it does not list.
    pub(crate) fn from_parts(
        stride: usize,
        keys: Vec<u8>,
        owners: Vec<u32>,
        starts: Vec<u32>,
    ) -> Option<Self> {
        if stride == 0 {
            // The empty set, as `default` and as `build` with nothing to keep
            // both produce it. Normalised, so that "holds nothing" has one
            // representation rather than two that compare unequal.
            return (keys.is_empty() && owners.is_empty() && starts.len() <= 1).then(Self::default);
        }
        // 20 or 32 and nothing else. `absorb` is the only thing that builds a
        // set with an entry in it, and it takes the width from `HashAlgorithm`,
        // so a third width is a file this code did not write.
        if stride != HashAlgorithm::Sha1.digest_len()
            && stride != HashAlgorithm::Sha256.digest_len()
        {
            return None;
        }
        if keys.len() % stride != 0 {
            return None;
        }
        let count = keys.len() / stride;
        // One start per key, plus the end of the last key's owners. Both ends of
        // every range are `get` calls in `get`, so a file that got this wrong
        // would answer nothing rather than panic — but it would answer nothing
        // *quietly*, for every file, and a cache that silently lists nothing is
        // worse than one that is discarded.
        if starts.len() != count + 1 {
            return None;
        }
        if starts.last().copied() != u32::try_from(owners.len()).ok() {
            return None;
        }
        if starts.windows(2).any(|pair| pair[0] > pair[1]) {
            return None;
        }
        Some(Self {
            stride,
            keys,
            owners,
            starts,
        })
    }

    /// The four arrays, for a writer that stores a whole set.
    ///
    /// Handed out as slices rather than cloned: this is 6.5 MB for the store on
    /// this machine, written to disk on the startup path of a scan.
    pub(crate) fn parts(&self) -> (usize, &[u8], &[u32], &[u32]) {
        (self.stride, &self.keys, &self.owners, &self.starts)
    }

    /// Every catalog that listed `digest`.
    fn get(&self, digest: &[u8]) -> &[u32] {
        if digest.len() != self.stride || self.starts.len() < 2 {
            return &[];
        }
        let count = self.keys.len() / self.stride;
        // Hand-rolled rather than `slice::binary_search_by` because the keys are
        // one flat array of fixed-width records, not a slice of comparable
        // elements: `chunks_exact` is not a slice and has no binary search, and
        // collecting it into one would allocate on every lookup.
        let mut low = 0usize;
        let mut high = count;
        while low < high {
            let mid = low + (high - low) / 2;
            let start = mid.saturating_mul(self.stride);
            // Cannot be out of range: `keys` is exactly `count` strides long and
            // only `build` writes it. Read checked anyway so that a future edit
            // breaking that pairing answers "not listed" rather than panicking
            // on a user's file.
            let Some(key) = self.keys.get(start..start + self.stride) else {
                return &[];
            };
            match key.cmp(digest) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => {
                    let from = self.starts.get(mid).copied().unwrap_or(0) as usize;
                    let to = self.starts.get(mid + 1).copied().unwrap_or(0) as usize;
                    return self.owners.get(from..to).unwrap_or(&[]);
                }
            }
        }
        &[]
    }

    fn is_empty(&self) -> bool {
        self.starts.len() < 2
    }

    /// How many distinct digests are held.
    fn len(&self) -> usize {
        self.starts.len().saturating_sub(1)
    }
}

/// A filesystem failure, named for the path it happened to.
fn filesystem(path: &Path, error: std::io::Error) -> SignatureError {
    SignatureError::CatalogStore {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// What one catalog contributes to the index.
#[derive(Debug)]
struct ReadCatalog {
    /// Its publisher.
    identity: CatalogIdentity,
    /// The digests it lists. The algorithm is not carried: the index sorts by
    /// width, which is the same thing, and carrying it would mean two fields
    /// that could disagree.
    digests: Vec<Vec<u8>>,
}

/// Every digest the catalog store lists, and the catalog that listed it.
///
/// # What this is, and what it deliberately is not
///
/// It is an inverted index over the store, built once. It is **not** a decision:
/// a digest being in here means a catalog names it, and whether that is worth
/// anything depends on whether anything vouches for *that catalog* — which is
/// what `CatalogIndex::identity` is for, and what the trust layer asks.
/// Keeping the decision out of this type is what lets the policy change without
/// the parser changing.
///
/// # Building it is not free, and the caller decides when
///
/// 1.2 s and 1.2 GB of reads on the machine this was measured on. That is far
/// too much to pay per file and entirely reasonable to pay once per scan, so
/// the caller builds it and hands it to whatever needs it. Nothing in this
/// crate builds one implicitly, because an implicit build inside a per-file
/// call is exactly the 1.2 s the index exists to avoid.
#[derive(Debug)]
pub struct CatalogIndex {
    sha1: DigestSet,
    sha256: DigestSet,
    /// One publisher per catalog, for an index built from the store.
    ///
    /// Empty for one built from a cache, and that emptiness is the security
    /// property rather than an omission: a cache holds no publisher, because a
    /// publisher a cache could forge is a publisher nothing should act on. See
    /// [`StoreIdentities`].
    identities: Vec<CatalogIdentity>,
    /// The store's catalogs, for an index built from a cache, which has to read
    /// the publisher out of the catalog it names before reporting it.
    store: Option<StoreIdentities>,
    read: usize,
    refused: usize,
    oversized: usize,
    /// Whether the digests came out of a cache file rather than out of the store.
    cached: bool,
}

impl CatalogIndex {
    /// An index over nothing, for a scan that has no store to consult.
    pub fn empty() -> Self {
        Self {
            sha1: DigestSet::default(),
            sha256: DigestSet::default(),
            identities: Vec::new(),
            store: None,
            read: 0,
            refused: 0,
            oversized: 0,
            cached: false,
        }
    }

    /// Build the index from the catalog store this machine has.
    ///
    /// An empty index on a platform with no store, which is indistinguishable
    /// from an empty store and is reported as such by [`Self::catalogs_read`].
    ///
    /// Every run pays the store's full parse — 1.7–6.2 s and 1.2 GB of reads on
    /// the machine this was measured on, depending on whether the store is in
    /// the page cache, against a scan of one five-byte file that takes 34 ms of
    /// anything else. [`Self::from_store_cached`] is the same index for the
    /// second and later runs, and is what a scan should call.
    pub fn from_store() -> Result<Self, SignatureError> {
        match store_directory() {
            Some(dir) => Self::from_directory(&dir),
            None => Ok(Self::empty()),
        }
    }

    /// Build the index from the catalog store, reusing a cache of it when the
    /// store has not changed.
    ///
    /// `cache_dir` is a directory the product owns. The file is written into it
    /// under [`cache_path`], and this is the entry point a scan should use: the
    /// first run reads the store and leaves the index behind, and every run
    /// after it reads one file instead of 7,300.
    ///
    /// Nothing about the answer changes. A cache that is absent, stale, damaged,
    /// or describes a different store is discarded and rebuilt from the store,
    /// which leaves the caller with exactly what [`Self::from_store`] would have
    /// given it and a log line saying so.
    pub fn from_store_cached(cache_dir: &Path) -> Result<Self, SignatureError> {
        match store_directory() {
            Some(dir) => Self::from_directory_cached(&dir, &cache_path(cache_dir)),
            None => Ok(Self::empty()),
        }
    }

    /// Build the index from every `.cat` in a directory.
    ///
    /// Fails only if the directory itself cannot be read. A single catalog that
    /// cannot be read, is not a catalog, or is larger than [`MAX_CATALOG_BYTES`]
    /// is counted and skipped — one unreadable file in a store of 7,300 is not a
    /// reason to have no catalog evidence at all, and the counters are how a
    /// caller finds out that it happened.
    pub fn from_directory(dir: &Path) -> Result<Self, SignatureError> {
        let (paths, _state) = catalog_store(dir)?;
        Ok(Self::from_paths(paths))
    }

    /// [`Self::from_directory`], with the store's parse saved to `cache` and
    /// read back from it when it is still the parse of *this* store.
    ///
    /// `cache` is the file, not the directory — [`cache_path`] names it — so
    /// that a caller can put it wherever it likes, including nowhere.
    ///
    /// # Why the store is enumerated before the cache is read
    ///
    /// The cache is keyed on the store, so the store's own state has to be
    /// measured first either way. What that buys is that the expensive half —
    /// reading and DER-parsing 1.2 GB — happens only when the state differs, and
    /// the cheap half — 7,300 `stat` calls, a few milliseconds — happens always.
    /// A cache that could be believed without looking at the store would be a
    /// cache that could not tell that the store had changed.
    pub fn from_directory_cached(dir: &Path, cache: &Path) -> Result<Self, SignatureError> {
        let (paths, state) = catalog_store(dir)?;
        // A store whose files cannot all be stamped is a store whose changes
        // cannot all be seen, and an index that cannot be invalidated is worse
        // than an index that costs 1.89 s. No state, no cache: not a read, and
        // not a write either — a cache nothing will ever trust is a file left on
        // disk for no reason.
        let Some(state) = state else {
            log::info!("catalog index: the store cannot be stamped, so it is not cached");
            return Ok(Self::from_paths(paths));
        };
        match catalog_cache::load(cache, &state) {
            Ok(loaded) => {
                log::info!(
                    "catalog index: {} digests and {} catalogs read from {}",
                    loaded.sha1.len() + loaded.sha256.len(),
                    loaded.read,
                    cache.display(),
                );
                return Ok(Self::from_cache(paths, loaded));
            }
            // Ordinary: the store changed, which on a machine that receives
            // updates is most weeks.
            Err(miss @ CacheMiss::Stale(_)) => log::info!("catalog index: {miss}"),
            // Worth a warning rather than an info line: the file is not merely
            // out of date, it is damaged or it was written by something other
            // than this code, and either is a reason for an operator to look at
            // the directory it lives in.
            Err(miss @ CacheMiss::Corrupt(_)) => log::warn!("catalog index: {miss}"),
            Err(CacheMiss::Absent) => log::debug!("catalog index: nothing cached yet"),
        }

        let index = Self::from_paths(paths);
        // A cache that cannot be written is a slower next run, and nothing else.
        // The scan in hand has the index either way, so this is logged and
        // dropped rather than returned: a read-only data directory is a
        // configuration a user is allowed to have.
        if let Err(error) = catalog_cache::store(cache, &state, &index) {
            log::warn!(
                "catalog index: {} could not be written: {error}",
                cache.display()
            );
        }
        Ok(index)
    }

    /// Build the index from catalogs already enumerated, in index order.
    ///
    /// Infallible where [`Self::from_directory`] is not: the enumeration is the
    /// only step that can fail on the store, and it has already happened.
    fn from_paths(paths: Vec<PathBuf>) -> Self {
        let mut out = Self::empty();
        let mut entries: Vec<(Vec<u8>, u32)> = Vec::new();
        for path in paths {
            match Self::read_catalog(&path) {
                Ok(Some(catalog)) => {
                    let id = u32::try_from(out.identities.len()).unwrap_or(u32::MAX);
                    out.identities.push(catalog.identity);
                    out.read += 1;
                    entries.extend(catalog.digests.into_iter().map(|digest| (digest, id)));
                }
                Ok(None) => out.oversized += 1,
                Err(_) => out.refused += 1,
            }
        }
        out.absorb(entries);
        out
    }

    /// The index a cache describes: its digests, and the store's catalogs left
    /// to be asked before any of them vouches for anything.
    ///
    /// The publishers are deliberately absent. A cache carries the digest →
    /// catalog mapping, which is the expensive half, and not the publisher,
    /// which is the half a forged cache would turn into a false reason to trust
    /// a file. Rebuilding it costs one catalog read the first time a scan
    /// consults that catalog, and the memo in [`StoreIdentities`] makes it one
    /// read per catalog per scan rather than one per file.
    fn from_cache(paths: Vec<PathBuf>, loaded: Loaded) -> Self {
        Self {
            sha1: loaded.sha1,
            sha256: loaded.sha256,
            identities: Vec::new(),
            store: Some(StoreIdentities::new(paths)),
            read: loaded.read,
            refused: loaded.refused,
            oversized: loaded.oversized,
            cached: true,
        }
    }

    /// Build the index from blobs already in memory, for tests and for a caller
    /// that has its own store.
    pub fn from_blobs(blobs: &[&[u8]]) -> Self {
        let mut out = Self::empty();
        let mut entries: Vec<(Vec<u8>, u32)> = Vec::new();
        for blob in blobs {
            let Ok(catalog) = Catalog::parse(blob) else {
                out.refused += 1;
                continue;
            };
            let id = u32::try_from(out.identities.len()).unwrap_or(u32::MAX);
            out.identities.push(CatalogIdentity::of_blob(blob));
            out.read += 1;
            entries.extend(
                catalog
                    .entries()
                    .iter()
                    .map(|entry| (entry.digest.to_vec(), id)),
            );
        }
        out.absorb(entries);
        out
    }

    /// Read one catalog once: its digests and its publisher.
    ///
    /// `Ok(None)` when it is past [`MAX_CATALOG_BYTES`], which is a refusal by
    /// policy rather than a fault and is counted separately for that reason.
    ///
    /// One read, not two. The blob is the thing both halves of the answer come
    /// out of — the digests are inside it and so is the certificate chain that
    /// published it — and the store is 1,145 MB, so reading it twice to produce
    /// two views of the same bytes would double the cost of the one expensive
    /// thing the index does.
    fn read_catalog(path: &Path) -> Result<Option<ReadCatalog>, SignatureError> {
        // Checked before the read rather than after, so that an oversized file
        // is never loaded into memory at all: the point of a bound is to not
        // allocate, and a check that runs after a 10 GB `fs::read` has already
        // lost.
        let size = fs::metadata(path)
            .map_err(|error| filesystem(path, error))?
            .len();
        if size > MAX_CATALOG_BYTES {
            return Ok(None);
        }
        let blob = fs::read(path).map_err(|error| filesystem(path, error))?;
        // A file that grew between the `metadata` call and the read — which is
        // ordinary for a store an update is rewriting — is caught here instead.
        if blob.len() as u64 > MAX_CATALOG_BYTES {
            return Ok(None);
        }
        let catalog = Catalog::parse(&blob)?;
        Ok(Some(ReadCatalog {
            identity: CatalogIdentity::of_blob(&blob),
            digests: catalog
                .entries()
                .iter()
                .map(|entry| entry.digest.to_vec())
                .collect(),
        }))
    }

    /// Split the collected entries into the two width-keyed sets.
    fn absorb(&mut self, entries: Vec<(Vec<u8>, u32)>) {
        let (sha1, sha256) = by_width(entries);
        self.sha1 = sha1;
        self.sha256 = sha256;
    }

    /// Every catalog that lists this file, in catalog order.
    ///
    /// All of them, not one: see `DigestSet` for why picking one is wrong.
    /// The caller asks whether *any* of them is vouched for, which is the
    /// question that does not depend on how the store was numbered.
    ///
    /// SHA-1 is tried first because it is the cheaper hash and the measured
    /// common case is a file listed under both — 742 of the 758 flagged files
    /// in an installed `System32` matched under both algorithms, which is
    /// Windows listing each file once per algorithm. The second lookup runs
    /// whenever the first misses, so a file listed under only one is still
    /// found; a digest matches under exactly one of the two, because their
    /// widths differ, so stopping at the first hit cannot lose a match.
    ///
    /// A file whose digest cannot be computed — no certificate table, a
    /// truncated image — is not listed by anything. It cannot be: [`file_digest`]
    /// has nothing to hash and no catalog can have been built over it.
    ///
    /// # Why the answer is owned, and why it comes from the store
    ///
    /// An index read from a cache holds no publisher at all: the file it was
    /// read from is in a directory any local user can write, so a publisher
    /// stored there would be a publisher anyone could invent. The publisher is
    /// therefore read here, out of the catalog the index names, *after* that
    /// catalog has been asked whether it really lists this digest — see
    /// `StoreIdentities::identity_listing`. A cache that names the wrong
    /// catalog therefore names a catalog that says no, and the file comes back
    /// as unvouched.
    ///
    /// That check is also why this cannot hand out a reference: there is no
    /// identity in the index to refer to, and none that could be handed out
    /// before the catalog behind it had answered.
    pub fn catalogs_listing(&self, pe: &PeFile<'_>) -> Vec<CatalogIdentity> {
        let Some((algorithm, digest, owners)) = self.matching_owners(pe) else {
            return Vec::new();
        };
        owners
            .iter()
            .filter_map(|owner| self.identity(*owner, algorithm, &digest))
            .collect()
    }

    /// The algorithm the file matched under, its digest, and every catalog the
    /// index says lists it.
    ///
    /// Split out because the digest is what the caller that has to ask a catalog
    /// needs: the containment check is `(catalog, algorithm, digest)`, and
    /// recomputing the digest there would hash the file a second time.
    fn matching_owners<'a>(
        &'a self,
        pe: &PeFile<'_>,
    ) -> Option<(HashAlgorithm, Vec<u8>, &'a [u32])> {
        if !self.sha1.is_empty() {
            if let Ok(digest) = file_digest(pe, HashAlgorithm::Sha1) {
                let owners = self.sha1.get(&digest);
                if !owners.is_empty() {
                    return Some((HashAlgorithm::Sha1, digest, owners));
                }
            }
        }
        if !self.sha256.is_empty() {
            if let Ok(digest) = file_digest(pe, HashAlgorithm::Sha256) {
                let owners = self.sha256.get(&digest);
                if !owners.is_empty() {
                    return Some((HashAlgorithm::Sha256, digest, owners));
                }
            }
        }
        None
    }

    /// The publisher of the catalog at `owner`, if that catalog lists `digest`.
    ///
    /// The two ways an index can hold a publisher, and the reason they cannot
    /// both be present: an index built from the store read each catalog and has
    /// its publisher in hand; an index built from a cache has none and asks the
    /// store. Nothing sets both, so there is no order to get wrong between them.
    fn identity(
        &self,
        owner: u32,
        algorithm: HashAlgorithm,
        digest: &[u8],
    ) -> Option<CatalogIdentity> {
        if let Some(identity) = self.identities.get(owner as usize) {
            return Some(identity.clone());
        }
        self.store
            .as_ref()?
            .identity_listing(owner, algorithm, digest)
    }

    /// Whether any catalog lists this file at all, and can say so.
    ///
    /// "And can say so" is the whole of the difference from the first version of
    /// this method: on an index read from a cache, a digest that the file names
    /// an owner for is not enough — the named catalog is asked, and a cache that
    /// named the wrong one answers `false` here. That makes this the same cost
    /// as [`Self::catalogs_listing`] rather than the digest lookup it used to
    /// be, which is the right trade: this is what a caller uses to decide
    /// whether anything vouches for a file, and an answer that a forged cache
    /// could turn into `true` is not a trust answer.
    pub fn lists(&self, pe: &PeFile<'_>) -> bool {
        !self.catalogs_listing(pe).is_empty()
    }

    /// Whether this index came out of a cache file rather than out of the store.
    ///
    /// A diagnostic, and the one that says whether the cache is earning its
    /// keep: a scan that reports `false` on every run has a store that changes
    /// between runs, or a cache that cannot be written.
    pub fn cache_hit(&self) -> bool {
        self.cached
    }

    /// The two digest sets, for a writer that stores the index.
    pub(crate) fn digest_sets(&self) -> (&DigestSet, &DigestSet) {
        (&self.sha1, &self.sha256)
    }

    /// How many catalogs were read into the index.
    pub fn catalogs_read(&self) -> usize {
        self.read
    }

    /// How many files were refused because they could not be read or parsed.
    pub fn catalogs_refused(&self) -> usize {
        self.refused
    }

    /// How many files were refused for exceeding [`MAX_CATALOG_BYTES`].
    pub fn catalogs_oversized(&self) -> usize {
        self.oversized
    }

    /// How many distinct digests the index holds.
    pub fn digest_count(&self) -> usize {
        self.sha1.len() + self.sha256.len()
    }

    /// Whether the index holds no digest at all.
    pub fn is_empty(&self) -> bool {
        self.sha1.is_empty() && self.sha256.is_empty()
    }
}

/// The cache file inside a cache directory.
///
/// A function rather than a constant, because the directory is the caller's: the
/// product's `cache_dir`, which the CLI passes and the console passes when it
/// has a layout at all.
pub fn cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(crate::catalog_cache::FILE_NAME)
}

/// The state a cache of `dir` would be keyed on, or `None` if the store cannot
/// be stamped.
///
/// Test-only, and it exists because the cache's tests write a cache file by hand
/// — a forged one, a damaged one — for a store they built themselves, and the
/// state they key it on has to be the state the loader will compare against.
/// Deriving it in the test instead would be a second implementation of the
/// enumeration order, and a test that reimplements what it is testing is a test
/// that agrees with the code rather than with the store.
#[cfg(test)]
pub(crate) fn store_state(dir: &Path) -> Result<Option<StoreState>, SignatureError> {
    Ok(catalog_store(dir)?.1)
}

/// Every catalog in a store directory, in index order, with the state a cache of
/// that store is keyed on.
///
/// One enumeration for both, because they have to agree: the cache records the
/// catalogs in the order the index numbers them, so an index read back from it
/// treats the `n`th catalog of the state as the owner numbered `n`. Enumerating
/// twice would be two chances for those orders to differ, and a difference would
/// point every digest at the wrong catalog.
///
/// The paths come back even when the state does not: an index can be built
/// without a cache, but a cache cannot be keyed without a state.
fn catalog_store(dir: &Path) -> Result<(Vec<PathBuf>, Option<StoreState>), SignatureError> {
    let entries = fs::read_dir(dir).map_err(|error| filesystem(dir, error))?;
    let mut files: Vec<(PathBuf, Option<CatalogStamp>)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            is_catalog(&path).then(|| (path, CatalogStamp::of(&entry)))
        })
        .collect();
    // Sorted so that catalog numbering — and therefore which catalog a report
    // names for a digest listed by several — is the same on every run.
    // `read_dir` order is whatever the filesystem feels like.
    files.sort_by(|left, right| left.0.cmp(&right.0));

    // All of them or none of them. A state that stamps some files and not others
    // cannot see a change to the ones it does not stamp, and a cache that cannot
    // see a change is the case this whole module refuses to risk — so one
    // unstampable file turns the cache off for this run rather than weakening
    // the key for every file.
    let stamped = files.iter().all(|(_, stamp)| stamp.is_some());
    let state = stamped.then(|| {
        StoreState::of(
            dir,
            files
                .iter()
                .filter_map(|(_, stamp)| stamp.clone())
                .collect(),
        )
    });
    Ok((files.into_iter().map(|(path, _)| path).collect(), state))
}

/// Whether a path is a catalog, by the extension Windows gives them.
fn is_catalog(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cat"))
}

/// Split collected entries into the two width-keyed sets.
///
/// The width is the algorithm: an entry states both, and the index sorts by
/// width alone, because a digest of a given length is one algorithm's and
/// carrying the name beside it would be a second field that could disagree.
fn by_width(entries: Vec<(Vec<u8>, u32)>) -> (DigestSet, DigestSet) {
    let mut sha1 = Vec::new();
    let mut sha256 = Vec::new();
    for (digest, owner) in entries {
        match digest.len() {
            len if len == HashAlgorithm::Sha1.digest_len() => sha1.push((digest, owner)),
            len if len == HashAlgorithm::Sha256.digest_len() => sha256.push((digest, owner)),
            // Neither width. A 16-byte entry is MD5, which no catalog uses, and
            // `HashAlgorithm::from_digest_len` already refuses it at parse time
            // — so this arm is unreachable through `Catalog::parse` and exists
            // because `from_blobs` is public.
            _ => {}
        }
    }
    (
        DigestSet::build(HashAlgorithm::Sha1.digest_len(), sha1),
        DigestSet::build(HashAlgorithm::Sha256.digest_len(), sha256),
    )
}

/// One catalog, read from the store and kept for the rest of the scan.
#[derive(Debug)]
struct Resolved {
    /// Its publisher, as its own chain spells it.
    identity: CatalogIdentity,
    /// Its digests under each width, so that "does this catalog list that file"
    /// is a binary search rather than a walk over every entry: its own index,
    /// built the same way the store's is, with one owner.
    sha1: DigestSet,
    sha256: DigestSet,
}

/// The store's catalogs, asked before they are believed.
///
/// # Why this type exists
///
/// An index read from a cache names, for each digest, the *number* of the
/// catalog that listed it, and nothing else — deliberately, because the cache
/// lives where any local user can write (the ACL was measured; see
/// [`crate::catalog_cache`]). A publisher a cache could forge is a publisher
/// nothing should act on, so the publisher is not in the cache. It is read here,
/// from the store, per catalog, and only after that catalog has been asked
/// whether it really lists the digest in question. A cache that names the wrong
/// catalog therefore vouches for nothing at all, which is the property the whole
/// arrangement exists to have.
///
/// What a forged cache can still do is leave a digest out, or point it at a
/// catalog that does not list it. Both make a catalogued file look uncatalogued,
/// and neither can make an uncatalogued file look vouched for — which is the
/// direction the trust policy is built to survive, since a catalog match only
/// ever discounts a score and never convicts.
///
/// # Why it memoises, and what that costs
///
/// A scan asks the same question thousands of times: every file in `System32`
/// that a cumulative-update catalog covers asks about the same catalog. A
/// catalog is 10.4 KB at the median and 11.13 MB at the largest, so the read,
/// the parse and the sets built from it are kept per catalog, and every lookup
/// after the first is a binary search. The whole store holds 214,820 digests, so
/// a scan that ends up consulting every catalog in it holds a few tens of
/// megabytes — less than the store itself, and far less than re-reading it per
/// file.
///
/// The lock is held across the first read of a catalog on purpose: eight
/// scanning threads that reach the same uncached catalog at the same moment
/// should read it once between them, not eight times.
#[derive(Debug)]
struct StoreIdentities {
    /// The store's catalogs, in the order the index numbers them.
    paths: Vec<PathBuf>,
    /// One entry per catalog consulted. `None` for a catalog that could not be
    /// read — memoised, so that an unreadable catalog is read once rather than
    /// once per file it is named by.
    memo: Mutex<HashMap<u32, Option<Resolved>>>,
}

impl StoreIdentities {
    /// A resolver over the store's catalogs, in index order.
    fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            memo: Mutex::new(HashMap::new()),
        }
    }

    /// The publisher of the catalog at `owner`, or `None` unless that catalog
    /// really lists `digest` under `algorithm`.
    ///
    /// The containment check is the point of the type: without it, an owner
    /// number taken from a file anyone can write would let the catalog a forger
    /// named vouch for a file it has never seen.
    ///
    /// A poisoned lock is not an error here. The memo is a cache of answers that
    /// are recomputed from disk, so the worst a panic elsewhere can cost is the
    /// work of reading a catalog again — and refusing to answer because some
    /// other thread panicked would turn a bug in the scanner into a silent loss
    /// of trust for every file.
    fn identity_listing(
        &self,
        owner: u32,
        algorithm: HashAlgorithm,
        digest: &[u8],
    ) -> Option<CatalogIdentity> {
        let mut memo = self
            .memo
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let resolved = match memo.entry(owner) {
            Entry::Occupied(slot) => slot.into_mut(),
            Entry::Vacant(slot) => slot.insert(self.read(owner)),
        };
        let resolved = resolved.as_ref()?;
        let lists = match algorithm {
            HashAlgorithm::Sha1 => &resolved.sha1,
            HashAlgorithm::Sha256 => &resolved.sha256,
        };
        if lists.get(digest).is_empty() {
            return None;
        }
        Some(resolved.identity.clone())
    }

    /// Read one catalog and index its digests, or `None` if it cannot be read.
    ///
    /// An unreadable catalog is a catalog nothing can be concluded from, which
    /// is the same answer this gives for a catalog that reads and does not list
    /// the digest: it does not vouch. The owner index is bounds-checked against
    /// the enumerated paths, so a file naming a catalog that does not exist
    /// answers `None` rather than reading something else.
    fn read(&self, owner: u32) -> Option<Resolved> {
        let path = self.paths.get(owner as usize)?;
        let catalog = CatalogIndex::read_catalog(path).ok()??;
        let (sha1, sha256) = by_width(
            catalog
                .digests
                .into_iter()
                .map(|digest| (digest, 0))
                .collect(),
        );
        Some(Resolved {
            identity: catalog.identity,
            sha1,
            sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    /// A 20-byte digest of a distinct byte, and a 32-byte one.
    fn sha1_digest(seed: u8) -> Vec<u8> {
        vec![seed; 20]
    }

    fn sha256_digest(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    #[test]
    fn the_digests_a_catalog_lists_come_back_with_their_algorithms() {
        let one = sha1_digest(0x11);
        let two = sha256_digest(0x22);
        let blob = catalog(&[&one, &two]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed.entries()[0],
            CatalogEntry {
                algorithm: HashAlgorithm::Sha1,
                digest: &one,
            }
        );
        assert_eq!(
            parsed.entries()[1],
            CatalogEntry {
                algorithm: HashAlgorithm::Sha256,
                digest: &two,
            }
        );
    }

    #[test]
    fn one_catalog_holds_both_algorithms_at_once() {
        // Measured, not assumed: a real catalog was seen with 20-byte and
        // 32-byte digests in the same `trustedSubjects`. A reader that decided
        // the algorithm once for the whole file would fail to match half of it.
        let blob = catalog(&[&sha1_digest(0x11), &sha256_digest(0x22)]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(
            parsed.algorithms(),
            vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256]
        );
    }

    #[test]
    fn a_digest_is_found_under_its_own_algorithm_and_no_other() {
        let one = sha1_digest(0x11);
        let two = sha256_digest(0x22);
        let blob = catalog(&[&one, &two]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert!(parsed.contains(HashAlgorithm::Sha1, &one));
        assert!(parsed.contains(HashAlgorithm::Sha256, &two));
        // The same bytes asked about under the other algorithm. Lengths differ
        // so this cannot match, and the test pins that the algorithm is
        // compared and not assumed from position.
        assert!(!parsed.contains(HashAlgorithm::Sha256, &one));
        assert!(!parsed.contains(HashAlgorithm::Sha1, &two));
    }

    #[test]
    fn a_digest_that_is_not_listed_is_not_found() {
        let blob = catalog(&[&sha1_digest(0x11)]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert!(!parsed.contains(HashAlgorithm::Sha1, &sha1_digest(0x12)));
        // A digest that shares a prefix with a listed one, to pin that this is
        // a whole-value comparison.
        let mut near = sha1_digest(0x11);
        near[19] = 0x12;
        assert!(!parsed.contains(HashAlgorithm::Sha1, &near));
    }

    #[test]
    fn the_subject_algorithm_is_not_mistaken_for_the_subject_list() {
        // `subjectAlgorithm` is the only other SEQUENCE before the subject list
        // and is separated from it only by holding an OID where the list holds
        // a digest. The fixture writes it exactly as Windows does, so an
        // implementation that took the first SEQUENCE it found would return an
        // empty catalog here rather than these two digests.
        let one = sha1_digest(0x11);
        let two = sha256_digest(0x22);
        let blob = catalog(&[&one, &two]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn a_digest_shaped_extension_is_not_read_as_a_subject_list() {
        // `ctlExtensions` nests a sequence of sequences. A reader that searched
        // every descendant rather than the direct children would find the
        // digest-shaped thing in there and list it as covered.
        let real = sha1_digest(0x11);
        let decoy = Vec::from([0xEEu8; 20]);
        let blob = catalog_with_extension(&[&real], &decoy);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains(HashAlgorithm::Sha1, &real));
        assert!(!parsed.contains(HashAlgorithm::Sha1, &decoy));
    }

    #[test]
    fn a_trust_list_with_no_subjects_is_refused() {
        // Not the same as an empty catalog: `trustedSubjects` is not optional,
        // so its absence is a structure this reader does not understand rather
        // than a catalog that covers nothing.
        let blob = catalog_without_subjects();
        assert!(matches!(
            Catalog::parse(&blob),
            Err(SignatureError::NotCatalog { .. })
        ));
    }

    #[test]
    fn an_empty_subject_list_parses_to_an_empty_catalog() {
        // `SEQUENCE OF` with nothing in it is legal, and the caller finds
        // nothing. Refusing would make an empty catalog an error the trust
        // layer had to learn about for no gain.
        let blob = catalog(&[]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.len(), 0);
        assert_eq!(parsed.algorithms(), Vec::new());
    }

    #[test]
    fn a_digest_of_a_width_no_algorithm_claims_is_skipped() {
        // 16 bytes is MD5, which no catalog uses. Carrying it as an entry with
        // no nameable algorithm would be carrying something that can never
        // match a digest this crate computes.
        let blob = catalog(&[&[0x33u8; 16], &sha1_digest(0x11)]);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.entries()[0].algorithm, HashAlgorithm::Sha1);
    }

    #[test]
    fn a_subject_whose_first_element_is_not_a_hash_is_skipped() {
        let one = sha1_digest(0x11);
        let blob = catalog_with_malformed_subject(&one);
        let parsed = Catalog::parse(&blob).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.entries()[0].digest, &one);
    }

    #[test]
    fn an_authenticode_signature_is_refused_as_a_catalog() {
        // Also a PKCS#7 SignedData, and the content type is the only thing that
        // tells the two apart. Reading one as a catalog would report a file's
        // own signature as a list of covered files.
        let blob = signed_data(&[certificate(
            &[0x01],
            "Leaf",
            "110616000000Z",
            "140615000000Z",
        )]);
        assert!(matches!(
            Catalog::parse(&blob),
            Err(SignatureError::NotCatalog { .. })
        ));
    }

    #[test]
    fn a_blob_that_is_not_pkcs7_is_refused() {
        assert!(Catalog::parse(&[0xFF, 0xFF, 0xFF]).is_err());
        assert!(Catalog::parse(&[]).is_err());
    }

    #[test]
    fn trailing_bytes_after_the_content_info_are_refused() {
        let mut blob = catalog(&[&sha1_digest(0x11)]);
        blob.push(0x00);
        assert!(Catalog::parse(&blob).is_err());
    }

    #[test]
    fn a_trust_list_truncated_inside_its_subjects_is_refused() {
        let blob = catalog(&[&sha1_digest(0x11), &sha256_digest(0x22)]);
        let cut = blob.len() - 4;
        assert!(Catalog::parse(&blob[..cut]).is_err());
    }

    #[test]
    fn the_algorithm_for_a_length_is_the_one_that_length_belongs_to() {
        assert_eq!(
            HashAlgorithm::from_digest_len(20),
            Some(HashAlgorithm::Sha1)
        );
        assert_eq!(
            HashAlgorithm::from_digest_len(32),
            Some(HashAlgorithm::Sha256)
        );
        for len in [0, 16, 19, 21, 31, 33, 64] {
            assert_eq!(HashAlgorithm::from_digest_len(len), None, "{len}");
        }
        assert_eq!(HashAlgorithm::Sha1.digest_len(), 20);
        assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(HashAlgorithm::Sha1.name(), "SHA-1");
        assert_eq!(HashAlgorithm::Sha256.name(), "SHA-256");
    }
}

/// Tests for the inverted index.
///
/// Separate from the tests of the parser above because these are about a
/// different object with a different failure mode: the parser can be right and
/// the index still answer the wrong question, and the interesting cases here are
/// all about *which* digest is found and *which* catalog is named for it.
#[cfg(test)]
mod index_tests {
    use super::*;
    use crate::testing::*;

    /// A PE and the SHA-1 digest a catalog would have to list to cover it.
    fn covered() -> (Vec<u8>, Vec<u8>) {
        let image = av_pe::testing::minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let digest = file_digest(&pe, HashAlgorithm::Sha1).unwrap();
        (image, digest)
    }

    /// A *different* PE with its SHA-1 digest.
    ///
    /// `minimal_pe32` returns the same bytes on every call, so a test that needs
    /// two distinct files cannot get them by calling it twice — the two digests
    /// come out equal and the test proves nothing. An import table is enough to
    /// make the images differ, and `add_imports` rewrites the headers around it
    /// so the result is still a well-formed image.
    fn covered_differently() -> (Vec<u8>, Vec<u8>) {
        let mut image = av_pe::testing::minimal_pe32();
        av_pe::testing::add_imports(&mut image, &[("OTHER.dll", &["SomethingElse"])]);
        let pe = PeFile::parse(&image).unwrap();
        let digest = file_digest(&pe, HashAlgorithm::Sha1).unwrap();
        (image, digest)
    }

    #[test]
    fn an_index_finds_a_file_its_catalog_lists() {
        let (image, digest) = covered();
        let blob = catalog(&[&digest]);
        let index = CatalogIndex::from_blobs(&[&blob]);

        assert_eq!(index.catalogs_read(), 1);
        assert_eq!(index.digest_count(), 1);
        let pe = PeFile::parse(&image).unwrap();
        assert!(index.lists(&pe), "the file the catalog names must be found");
    }

    #[test]
    fn a_file_no_catalog_lists_is_not_found() {
        // The differential that earns its keep. A lookup that answered "yes"
        // for everything would pass the test above; this is the one that says
        // the digest is actually compared.
        let (image, digest) = covered();
        let mut other = digest.clone();
        other[0] ^= 0xff;
        let blob = catalog(&[&other]);
        let index = CatalogIndex::from_blobs(&[&blob]);

        let pe = PeFile::parse(&image).unwrap();
        assert!(
            !index.lists(&pe),
            "a catalog listing a different digest must not match"
        );
        assert_eq!(index.digest_count(), 1, "the other digest is still indexed");
    }

    #[test]
    fn a_file_listed_only_under_sha256_is_still_found() {
        // SHA-1 is looked up first and a file listed only under SHA-256 misses
        // that lookup. An index that stopped at the first miss would be correct
        // for the measured common case and wrong for this one.
        let image = av_pe::testing::minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let digest = file_digest(&pe, HashAlgorithm::Sha256).unwrap();
        let blob = catalog(&[&digest]);
        let index = CatalogIndex::from_blobs(&[&blob]);

        assert_eq!(index.digest_count(), 1);
        assert!(
            index.lists(&pe),
            "a file listed only under SHA-256 must be found by the second lookup"
        );
    }

    #[test]
    fn a_file_listed_under_both_algorithms_is_found() {
        let image = av_pe::testing::minimal_pe32();
        let pe = PeFile::parse(&image).unwrap();
        let one = file_digest(&pe, HashAlgorithm::Sha1).unwrap();
        let two = file_digest(&pe, HashAlgorithm::Sha256).unwrap();
        // One catalog per algorithm, as Windows writes them: measured, the same
        // file appears once under each in the store.
        let index = CatalogIndex::from_blobs(&[&catalog(&[&one]), &catalog(&[&two])]);
        assert_eq!(index.digest_count(), 2);
        assert!(index.lists(&pe));
    }

    #[test]
    fn an_entry_of_a_width_no_algorithm_uses_is_not_indexed() {
        // A 16-byte entry is MD5, which no catalog uses. `Catalog::parse`
        // already refuses the width, so this pins the whole path rather than a
        // branch in this module: a width-agnostic index would count it and a
        // lookup for a 16-byte digest would then find it.
        let md5 = vec![0x33u8; 16];
        let blob = catalog(&[&md5]);
        let index = CatalogIndex::from_blobs(&[&blob]);
        assert_eq!(index.digest_count(), 0);
        assert!(index.is_empty());
    }

    #[test]
    fn the_index_names_the_catalog_that_listed_a_digest() {
        let (first_image, first) = covered();
        let (_second_image, second) = covered_differently();
        // Two different files, so the two digests differ and each catalog is
        // the only possible source of its own.
        assert_ne!(first, second, "the two fixtures must not be the same file");

        let publisher = vec![chain_link(
            b"\x01",
            "Contoso Publisher",
            "Contoso Root",
            "200101000000Z",
            "300101000000Z",
        )];
        let other = vec![chain_link(
            b"\x02",
            "Fabrikam Publisher",
            "Fabrikam Root",
            "200101000000Z",
            "300101000000Z",
        )];
        let index = CatalogIndex::from_blobs(&[
            &catalog_signed_by(&[&first], &publisher),
            &catalog_signed_by(&[&second], &other),
        ]);

        let pe = PeFile::parse(&first_image).unwrap();
        let listing = index.catalogs_listing(&pe);
        let identity = listing.first().expect("the first file is listed");
        assert!(
            identity.subject.contains("Contoso"),
            "the catalog that listed it must be the one named, got {:?}",
            identity.subject
        );
        assert!(
            identity.issuers.iter().any(|i| i.contains("Contoso Root")),
            "its issuers must come from the same chain, got {:?}",
            identity.issuers
        );
    }

    #[test]
    fn a_digest_listed_by_two_catalogs_always_names_the_same_one() {
        // The ordinary case: the same file is in an operating-system catalog
        // and a cumulative-update one. Which of them a report names has to be
        // the same on every run, or a report is not something anyone can check.
        let (image, digest) = covered();
        let one = catalog_signed_by(
            &[&digest],
            &[chain_link(
                b"\x01",
                "First Publisher",
                "First Root",
                "200101000000Z",
                "300101000000Z",
            )],
        );
        let two = catalog_signed_by(
            &[&digest],
            &[chain_link(
                b"\x02",
                "Second Publisher",
                "Second Root",
                "200101000000Z",
                "300101000000Z",
            )],
        );

        let pe = PeFile::parse(&image).unwrap();
        let forwards = CatalogIndex::from_blobs(&[&one, &two]);
        let backwards = CatalogIndex::from_blobs(&[&two, &one]);

        // Both catalogs, in both orders, and the same two either way. Naming
        // one of them would make the answer depend on store numbering, which is
        // what the first design here did and what the multi-owner shape exists
        // to stop.
        let mut named: Vec<String> = forwards
            .catalogs_listing(&pe)
            .into_iter()
            .map(|identity| identity.subject)
            .collect();
        let mut other: Vec<String> = backwards
            .catalogs_listing(&pe)
            .into_iter()
            .map(|identity| identity.subject)
            .collect();
        assert_eq!(named.len(), 2, "both catalogs listing it are reported");
        named.sort();
        other.sort();
        assert_eq!(
            named, other,
            "the catalogs reported must not depend on the order the store was read in"
        );
        assert_eq!(
            forwards.digest_count(),
            1,
            "one digest, however many list it"
        );
    }

    #[test]
    fn a_blob_that_is_not_a_catalog_is_counted_and_the_rest_still_index() {
        // One unreadable file in a store of thousands is not a reason to have no
        // catalog evidence at all, so this is the behaviour that keeps a scan
        // working on a machine where something in CatRoot is corrupt.
        let (image, digest) = covered();
        let good = catalog(&[&digest]);
        let index = CatalogIndex::from_blobs(&[b"not a catalog at all", &good]);

        assert_eq!(index.catalogs_read(), 1);
        assert_eq!(index.catalogs_refused(), 1);
        let pe = PeFile::parse(&image).unwrap();
        assert!(index.lists(&pe));
    }

    #[test]
    fn an_empty_index_matches_nothing_and_says_so() {
        // Differential: "no catalogs here" and "this file is not listed" are
        // different answers, and a caller that cannot tell them apart will
        // report a missing store as a clean file.
        let (image, _) = covered();
        let index = CatalogIndex::empty();
        assert!(index.is_empty());
        assert_eq!(index.digest_count(), 0);
        assert_eq!(index.catalogs_read(), 0);
        let pe = PeFile::parse(&image).unwrap();
        assert!(!index.lists(&pe));
    }

    #[test]
    fn a_catalog_carrying_no_chain_has_an_empty_publisher() {
        // `catalog()` writes an empty certificate set, which is every fixture
        // but the signed one. The publisher must come back empty rather than as
        // an error or as a fabricated name: the caller's job is to notice that
        // nothing vouches for this catalog, and it can only do that if the
        // emptiness survives.
        let (image, digest) = covered();
        let index = CatalogIndex::from_blobs(&[&catalog(&[&digest])]);
        let pe = PeFile::parse(&image).unwrap();
        let listing = index.catalogs_listing(&pe);
        let identity = listing.first().expect("the digest is listed");
        assert!(identity.subject.is_empty());
        assert!(identity.issuers.is_empty());
    }

    #[test]
    fn every_catalog_in_a_directory_is_read() {
        // The only test that touches a filesystem, and it is on a directory
        // this test makes rather than on the catalog store: what is being
        // pinned is the directory walk, the extension filter and the numbering,
        // none of which can be reached through `from_blobs`.
        let dir = std::env::temp_dir().join("wenle-catalog-index-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (first_image, first) = covered();
        let (second_image, second_sha1) = covered_differently();
        let second_pe = PeFile::parse(&second_image).unwrap();
        let second = file_digest(&second_pe, HashAlgorithm::Sha256).unwrap();
        assert_ne!(first, second_sha1, "the two fixtures must differ");

        fs::write(dir.join("one.cat"), catalog(&[&first])).unwrap();
        // Upper case, because the extension Windows writes is lower case and a
        // store restored from a backup case-insensitive filesystem is not.
        fs::write(dir.join("two.CAT"), catalog(&[&second])).unwrap();
        // Not a catalog, and must not be counted as a refused one: it is not a
        // catalog by name, so it was never a candidate.
        fs::write(dir.join("readme.txt"), b"hello").unwrap();
        // A directory named like a catalog, which a naive walk would try to
        // read as a file.
        fs::create_dir_all(dir.join("three.cat")).unwrap();

        let index = CatalogIndex::from_directory(&dir).unwrap();
        assert_eq!(index.catalogs_read(), 2, "one.cat and two.CAT");
        assert_eq!(index.catalogs_refused(), 1, "three.cat is a directory");
        assert_eq!(index.digest_count(), 2);

        let pe = PeFile::parse(&first_image).unwrap();
        assert!(index.lists(&pe));
        let pe = PeFile::parse(&second_image).unwrap();
        assert!(index.lists(&pe), "the upper-case one was read");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_does_not_exist_is_an_error_not_an_empty_index() {
        // The distinction the whole module turns on: no store is not the same
        // fact as an empty store, and a caller that conflated them would report
        // "nothing is catalog-signed" for a machine whose store it could not
        // open.
        let missing = std::env::temp_dir().join("wenle-no-such-catalog-store-42");
        let _ = fs::remove_dir_all(&missing);
        assert!(CatalogIndex::from_directory(&missing).is_err());
    }
}

/// Measurements against the catalog store this machine is actually running.
///
/// Separate from the tests above, and `#[ignore]`d, because they read
/// `C:\Windows` and a test suite that depends on the machine it runs on is a
/// test suite that fails for reasons that are not about the code. They are run
/// deliberately:
///
/// ```text
/// cargo test -p av-signatures --lib catalog::measurement:: -- --ignored --nocapture
/// ```
#[cfg(test)]
mod measurement {
    use super::*;
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    /// Where Windows keeps its catalogs.
    ///
    /// The GUID is the one the signed catalogs live in. Two sibling directories
    /// exist and are near-empty; neither holds a `.cat` worth reading.
    const CATROOT: &str = r"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";

    /// How many files of `System32` to measure against.
    const SAMPLE: usize = 500;

    /// Every digest in the catalog store, and how many catalogs were readable.
    fn catalog_store() -> (HashSet<Vec<u8>>, usize, Vec<String>) {
        let mut digests = HashSet::new();
        let mut parsed = 0;
        let mut refused = Vec::new();
        let Ok(entries) = std::fs::read_dir(Path::new(CATROOT)) else {
            return (digests, 0, refused);
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "cat") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            match Catalog::parse(&bytes) {
                Ok(catalog) => {
                    parsed += 1;
                    for item in catalog.entries() {
                        digests.insert(item.digest.to_vec());
                    }
                }
                Err(error) => refused.push(format!("{}: {error}", name_of(&path))),
            }
        }
        (digests, parsed, refused)
    }

    fn name_of(path: &Path) -> String {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string())
    }

    fn sample_files(limit: usize) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(r"C:\Windows\System32") else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let binary = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe"))
                .unwrap_or(false);
            if binary {
                out.push(path);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    /// The candidate digest definitions that were *rejected*, kept so that the
    /// accepted one is a choice between measured alternatives rather than the
    /// only thing ever tried.
    ///
    /// `Zeroed` writes the two header fields as zeros; `Cut` omits them
    /// entirely. Both are how a specification could plausibly have described
    /// the same intent, and they are not the same digest.
    #[derive(Debug, Clone, Copy)]
    enum Candidate {
        /// Cut the fields, stop hashing at the certificate table. **This is what
        /// [`hashed_regions`] does.**
        CutAtCertificateTable,
        /// Cut the fields, hash to the end of the file.
        CutAtEndOfFile,
        /// Zero the fields, hash to the certificate table.
        ZeroedAtCertificateTable,
        /// Zero the fields, hash to the end of the file.
        ZeroedAtEndOfFile,
        /// Ignore the fields entirely.
        WholeFile,
    }

    impl Candidate {
        const ALL: [Candidate; 5] = [
            Candidate::CutAtCertificateTable,
            Candidate::CutAtEndOfFile,
            Candidate::ZeroedAtCertificateTable,
            Candidate::ZeroedAtEndOfFile,
            Candidate::WholeFile,
        ];

        fn name(self) -> &'static str {
            match self {
                Candidate::CutAtCertificateTable => "cut, stop at certificate table",
                Candidate::CutAtEndOfFile => "cut, stop at end of file",
                Candidate::ZeroedAtCertificateTable => "zeroed, stop at certificate table",
                Candidate::ZeroedAtEndOfFile => "zeroed, stop at end of file",
                Candidate::WholeFile => "whole file, fields untouched",
            }
        }

        /// Whether this candidate writes the two fields as zeros.
        fn zeroes(self) -> bool {
            matches!(
                self,
                Candidate::ZeroedAtCertificateTable | Candidate::ZeroedAtEndOfFile
            )
        }

        /// Which algorithm's digest [`hashed_regions`] produces.
        fn implements_regions(self) -> bool {
            matches!(self, Candidate::CutAtCertificateTable)
        }
    }

    /// The ranges a candidate hashes, over a file of `len` bytes.
    fn ranges_for(candidate: Candidate, pe: &PeFile<'_>, len: usize) -> Vec<Range<usize>> {
        let checksum = pe.checksum_field_offset();
        let security = pe.security_directory_entry_offset();
        let entry = pe.security_directory();
        // A file with no attribute certificate table runs to the end of the
        // buffer; one with a table stops where the table begins, because the
        // table is not part of the image.
        let certificate_table = if entry.is_present() {
            (entry.virtual_address as usize).min(len)
        } else {
            len
        };
        match candidate {
            Candidate::CutAtCertificateTable => {
                vec![
                    0..checksum,
                    checksum + 4..security,
                    security + 8..certificate_table,
                ]
            }
            Candidate::CutAtEndOfFile => {
                vec![0..checksum, checksum + 4..security, security + 8..len]
            }
            Candidate::ZeroedAtCertificateTable => std::iter::once(0..certificate_table).collect(),
            Candidate::ZeroedAtEndOfFile | Candidate::WholeFile => std::iter::once(0..len).collect(),
        }
    }

    /// SHA-1 and SHA-256 of a file under one candidate definition.
    fn digests_for(candidate: Candidate, pe: &PeFile<'_>, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ranges = ranges_for(candidate, pe, data.len());
        let zeroed;
        let bytes: &[u8] = if candidate.zeroes() {
            zeroed = {
                let mut copy = data.to_vec();
                let checksum = pe.checksum_field_offset();
                let security = pe.security_directory_entry_offset();
                copy[checksum..checksum + 4].fill(0);
                copy[security..security + 8].fill(0);
                copy
            };
            &zeroed
        } else {
            data
        };

        let mut sha1 = sha1::Sha1::new();
        let mut sha256 = sha2::Sha256::new();
        for range in &ranges {
            let end = range.end.min(bytes.len());
            sha1.update(&bytes[range.start.min(end)..end]);
            sha256.update(&bytes[range.start.min(end)..end]);
        }
        (sha1.finalize().to_vec(), sha256.finalize().to_vec())
    }

    #[test]
    #[ignore = "reads the installed Windows catalog store"]
    fn every_catalog_windows_ships_can_be_read() {
        let (digests, parsed, refused) = catalog_store();
        println!("catalogs parsed: {parsed}");
        println!("digests listed:  {}", digests.len());
        for line in refused.iter().take(10) {
            println!("  refused {line}");
        }
        assert!(parsed > 1_000, "only {parsed} catalogs were found");
        // Measured at 7,300 parsed and 0 refused. A refusal here is a catalog
        // format this parser does not know about, which is exactly the thing
        // worth being told about rather than quietly missing.
        assert!(
            refused.is_empty(),
            "{} catalogs were refused",
            refused.len()
        );
    }

    #[test]
    #[ignore = "reads the installed Windows catalog store"]
    fn the_digest_definition_is_the_one_the_catalogs_were_built_with() {
        let (store, parsed, _) = catalog_store();
        assert!(parsed > 1_000, "only {parsed} catalogs were found");

        let files = sample_files(SAMPLE);
        assert!(files.len() > 100, "only {} files were found", files.len());

        // Hits per candidate, [sha1, sha256].
        let mut tally = [[0usize; 2]; Candidate::ALL.len()];
        let mut examined = 0usize;
        let mut signed = 0usize;
        for path in &files {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Ok(pe) = PeFile::parse(&data) else {
                continue;
            };
            examined += 1;
            if pe.security_directory().is_present() {
                signed += 1;
            }
            for (index, candidate) in Candidate::ALL.iter().enumerate() {
                let (sha1, sha256) = digests_for(*candidate, &pe, &data);
                if store.contains(&sha1) {
                    tally[index][0] += 1;
                }
                if store.contains(&sha256) {
                    tally[index][1] += 1;
                }
            }
        }

        println!("\nof {examined} files ({signed} with an embedded signature):");
        for (index, candidate) in Candidate::ALL.iter().enumerate() {
            println!(
                "  {:<34} sha1 {:>4}  sha256 {:>4}",
                candidate.name(),
                tally[index][0],
                tally[index][1]
            );
        }

        let index_of = |want: Candidate| {
            Candidate::ALL
                .iter()
                .position(|c| std::mem::discriminant(c) == std::mem::discriminant(&want))
                .expect("the candidate is in the list")
        };
        let implemented = index_of(Candidate::CutAtCertificateTable);
        let at_end = index_of(Candidate::CutAtEndOfFile);
        let hits = tally[implemented][0].max(tally[implemented][1]);

        // The positive claim: the definition this module implements is the one
        // the catalog store was built with. Measured at 497 of 500, the three
        // being files no installed catalog covers — not a definition that is
        // nearly right, which would score far lower than 99%.
        assert!(
            hits * 100 >= examined * 95,
            "only {hits} of {examined} files were found under {}",
            Candidate::ALL[implemented].name()
        );

        // The differential, and the reason the number above is evidence rather
        // than a coincidence: the three alternatives a specification could
        // plausibly have described instead are measured to match *nothing*.
        //
        // This is the assertion that earns its keep. Cutting the two fields out
        // and zeroing them are the same intent written two ways, they produce
        // different digests, and only one of them can be what Windows did.
        // Measured: zero, both. `CutAtEndOfFile` is deliberately *not* in this
        // group — see below.
        for (index, candidate) in Candidate::ALL.iter().enumerate() {
            if candidate.implements_regions() || matches!(candidate, Candidate::CutAtEndOfFile) {
                continue;
            }
            assert_eq!(
                tally[index],
                [0, 0],
                "{} should not match any file, but matched {:?} — the digest is being \
                 computed some other way than this module believes",
                candidate.name(),
                tally[index]
            );
        }

        // Where the certificate table boundary shows up.
        //
        // `CutAtEndOfFile` is not a disjoint alternative: on a file with no
        // attribute certificate table the two definitions hash the same bytes,
        // so it is a *subset*. Measured 386 of 500, and 500 - 386 = 114 is
        // exactly the number of sampled files carrying a signature — that
        // agreement is the evidence. It is arithmetic about the sample rather
        // than a literal because a machine with more uncatalogued files would
        // move both numbers together, and the test should survive that and fail
        // only on a real change of definition.
        let at_end_hits = tally[at_end][0];
        let carrying = signed;
        let without = examined - signed;
        assert!(
            at_end_hits * 10 >= without * 9,
            "hashing to the end of the file matched {at_end_hits} of the {without} files with \
             no certificate table, which is too few for the two definitions to agree on them"
        );

        // And the files that carry a table match *more* often when the table is
        // excluded. Measured 111 of 114.
        let matched_carrying = hits.saturating_sub(at_end_hits);
        assert!(
            matched_carrying * 100 >= carrying * 90,
            "only {matched_carrying} of the {carrying} files carrying a certificate table were \
             found when the table was excluded, so the boundary is not where this module \
             thinks it is"
        );
    }

    #[test]
    #[ignore = "reads the installed Windows catalog store"]
    fn the_regions_this_module_hashes_are_the_ones_the_measurement_chose() {
        // The measurement above is of the *definition*; this is of the function,
        // so that the two cannot drift. A real file, hashed both ways.
        let files = sample_files(20);
        let mut checked = 0usize;
        for path in &files {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Ok(pe) = PeFile::parse(&data) else {
                continue;
            };
            for algorithm in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
                let from_function = file_digest(&pe, algorithm).unwrap();
                let (sha1, sha256) = digests_for(Candidate::CutAtCertificateTable, &pe, &data);
                let from_measurement = match algorithm {
                    HashAlgorithm::Sha1 => sha1,
                    HashAlgorithm::Sha256 => sha256,
                };
                assert_eq!(from_function, from_measurement, "{}", name_of(path));
                assert_eq!(from_function.len(), algorithm.digest_len());
            }
            checked += 1;
        }
        assert!(checked > 5, "only {checked} files were checked");
        println!("{checked} files hashed identically by both paths");
    }

    /// Every PE under `System32`, to a generous cap.
    ///
    /// [`sample_files`] takes a directory's immediate entries and stops at a
    /// limit, which is right for a definition measurement and wrong for this
    /// one: the question here is how much of the installed operating system is
    /// covered, and a sample of the top level would miss every file in
    /// `System32\DriverStore` and every `.dll` in a subdirectory.
    fn system32_recursive(limit: usize, out: &mut Vec<PathBuf>) {
        let mut stack = vec![PathBuf::from(r"C:\Windows\System32")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.file_type() {
                    Ok(kind) if kind.is_dir() => stack.push(path),
                    Ok(kind) if kind.is_file() => {
                        let binary = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                            e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe")
                        });
                        if binary {
                            out.push(path);
                            if out.len() >= limit {
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// How much of the installed operating system the index actually covers.
    ///
    /// # Why this is the measurement that matters
    ///
    /// The index exists to answer one question for the trust layer: *is this
    /// file one Microsoft shipped?* Everything the policy does with the answer
    /// — the 60-point discount, and `clear_generic`'s move to `Clean` — is worth
    /// nothing if the answer is usually "no catalog lists it" for files that are
    /// plainly Microsoft's. A coverage number near zero would leave the trust
    /// layer inert while every unit test still passed, because every unit test
    /// builds its own catalog.
    ///
    /// # The number this was written against, and what it decides
    ///
    /// Measured on a clean Windows 11 installation: a full scan of `System32`
    /// produced 758 findings, 750 of them in the suspicious band, and 742 of
    /// those 758 files are listed by a catalog here. That is the population the
    /// index is for, and it is why the trust layer reads this and not the
    /// embedded-signature half alone — an embedded signature is a claim, and a
    /// catalog entry is a proof.
    ///
    /// The assertions are floors set well under the measured value, because the
    /// exact fraction is a fact about the machine. A coverage figure that fell
    /// off a cliff would mean a parse regression, and that is what this fails on.
    #[test]
    #[ignore = "reads the installed Windows catalog store and the installed System32"]
    fn the_index_covers_the_installed_operating_system() {
        let started = std::time::Instant::now();
        let index = match CatalogIndex::from_store() {
            Ok(index) => index,
            Err(error) => {
                println!("no catalog store: {error}");
                return;
            }
        };
        let built = started.elapsed();
        println!(
            "index: {} catalogs read, {} refused, {} oversized, {} digests, built in {built:?}",
            index.catalogs_read(),
            index.catalogs_refused(),
            index.catalogs_oversized(),
            index.digest_count(),
        );
        assert!(
            index.catalogs_read() > 1_000,
            "only {} catalogs were read",
            index.catalogs_read()
        );
        // Every catalog on this machine parses, and a refusal is a format this
        // reader does not know about — the thing worth being told rather than
        // quietly missing.
        assert_eq!(index.catalogs_refused(), 0, "a catalog was refused");
        assert_eq!(
            index.catalogs_oversized(),
            0,
            "a catalog was skipped as oversized"
        );
        assert!(
            index.digest_count() > 100_000,
            "{} digests",
            index.digest_count()
        );

        let mut files = Vec::new();
        system32_recursive(40_000, &mut files);
        assert!(files.len() > 5_000, "only {} files were found", files.len());

        let mut examined = 0usize;
        let mut listed = 0usize;
        let mut bytes = 0u64;
        let mut hashing = std::time::Duration::ZERO;
        for path in &files {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Ok(pe) = PeFile::parse(&data) else {
                continue;
            };
            examined += 1;
            bytes += data.len() as u64;
            let at = std::time::Instant::now();
            let found = index.lists(&pe);
            hashing += at.elapsed();
            if found {
                listed += 1;
            }
        }

        let per_file = hashing
            .checked_div(u32::try_from(examined).unwrap_or(1))
            .unwrap_or_default();
        println!(
            "\n{listed} of {examined} files ({:.1}%) are listed by a catalog, {} MiB hashed in \
             {hashing:?} ({per_file:?} per file)",
            percent(listed, examined),
            bytes / (1024 * 1024),
        );
        assert!(examined > 5_000, "only {examined} files were parsed");

        // Measured at 98.4% — 5293 of 5379 — over every `.dll` and `.exe` under
        // `System32` including the driver store. The floor is deliberately far
        // below it: this fails on a regression that makes the index stop
        // matching, not on a machine that ships a few more third-party binaries.
        // The 86 uncovered files are third-party: a Chinese input method, a
        // disk-encryption tool, a debug runtime from a Visual Studio install.
        assert!(
            percent(listed, examined) > 80.0,
            "only {listed} of {examined} files were covered by the index"
        );

        // A per-file cost, and the reason the index is built once rather than
        // consulted by re-reading the store per file: reading all 7,300 catalogs
        // takes seconds, and this is the same work spread over every file if it
        // were done per file. Measured at 0.94 ms per file in a *debug* build
        // over 6.6 GiB, so a release build scanning 27,370 files spends well
        // under the 640 s the rest of the pipeline takes.
        assert!(
            per_file < std::time::Duration::from_millis(5),
            "a catalog lookup took {per_file:?} per file, which is too slow to run per file"
        );
    }

    /// `part` as a percentage of `whole`.
    fn percent(part: usize, whole: usize) -> f64 {
        if whole == 0 {
            return 0.0;
        }
        (part as f64) * 100.0 / (whole as f64)
    }
}
