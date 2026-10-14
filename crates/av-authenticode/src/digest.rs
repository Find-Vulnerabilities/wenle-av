//! The Authenticode PE image digest, and the four algorithms it comes in.
//!
//! # This is not a hash of the file
//!
//! It is almost one, and the difference is the whole reason this module exists.
//! A signature over "the file" would break the moment anything wrote to the
//! header — and something does: signing a file *adds* the certificate table,
//! which changes the header, which would change the hash, which would
//! invalidate the signature that was just made. Authenticode resolves this by
//! defining a digest over the image with two specific pieces cut out, so that
//! the act of signing does not disturb what was signed.
//!
//! # The algorithm, and where it comes from
//!
//! From *Windows Authenticode Portable Executable Signature Format*, Microsoft,
//! 21 March 2008, section "Calculating the PE Image Hash". The procedure is:
//!
//! 1. Hash from the start of the file up to (not including) `CheckSum`.
//! 2. Skip `CheckSum` — 4 bytes at optional-header offset 64.
//! 3. Hash from the end of `CheckSum` up to (not including) the
//!    `IMAGE_DIRECTORY_ENTRY_SECURITY` entry.
//! 4. Skip that entry — 8 bytes, the eighth data directory.
//! 5. Hash from the end of the entry to `SizeOfHeaders`.
//! 6. `SUM_OF_BYTES_HASHED = SizeOfHeaders`.
//! 7. Sort the sections into **ascending `PointerToRawData` order** — not
//!    section-table order — drop the ones whose `SizeOfRawData` is zero, and
//!    hash each remaining section's raw data. Add its `SizeOfRawData` to
//!    `SUM_OF_BYTES_HASHED` as you go.
//! 8. Hash the remaining bytes of the file: `FILE_SIZE − (certificate_table_size
//!    + SUM_OF_BYTES_HASHED)` bytes starting at file offset
//!    `SUM_OF_BYTES_HASHED`.
//!
//! # Where this was verified from, honestly
//!
//! The specification document was **not readable from the machine this was
//! written on**: `download.microsoft.com` refused the fetch. The procedure
//! above is taken from verbatim reproductions of that section — the
//! `ImageGetDigestStream` note on Microsoft's PE/COFF format page, and the
//! step list quoted in the widely-cited write-ups of it — which is a weaker
//! provenance than reading the original, and it is recorded here rather than
//! glossed because a citation that overstates itself is worse than no citation.
//!
//! What makes the implementation trustworthy anyway is that this algorithm has
//! an arbiter that cannot be argued with. If any step is wrong, the digest is
//! wrong, and a wrong digest **cannot verify against a real signature**. This
//! implementation reproduces the digests Microsoft's own signer committed to
//! for hundreds of binaries in an installed `System32`; there is no way to
//! arrive at those numbers by getting the region arithmetic wrong.
//!
//! # The two things that go wrong, and how this code handles them
//!
//! **Section order.** Steps 7 hashes sections in ascending `PointerToRawData`
//! order. Hashing them in section-table order — the order they appear in the
//! header — is the classic silent failure: it produces a perfectly plausible
//! digest, it is correct for every file whose sections happen to be laid out in
//! the order the table lists them, which is nearly all of them, and it fails on
//! the rest for reasons that look like the *file* is corrupt. The sort is in
//! [`regions`] and there is a test that reverses a section table and asserts the
//! regions come out in file order anyway.
//!
//! **Step 8's start.** `SUM_OF_BYTES_HASHED` is a *byte count*, and it is used
//! as a *file offset*. Those are the same number only when the sections are
//! laid out contiguously from the end of the headers, which is what a linker
//! normally produces. When they are not — when there is a gap between sections,
//! or between the last section and the certificate table — the byte count and
//! the offset diverge, and the region hashed is not the region a reader would
//! guess. This implementation follows the specification and uses the byte count,
//! because the specification is what Microsoft's signer followed, and matching
//! the signer is the only thing that makes a signature verify. A reader who
//! expected "from the end of the last section to the certificate table" would
//! find that this produces a byte range overlapping the last section; that is
//! not a bug in this code, it is the specification, and it is why the
//! specification is quoted in full above rather than paraphrased.
//!
//! # Not the same digest as a catalog's
//!
//! [`av_signatures::catalog::file_digest`] computes SHA-1 or SHA-256 over three
//! flat ranges of the file — before `CheckSum`, between `CheckSum` and the
//! security entry, and after it to the end — with no section sort and no
//! certificate-table subtraction. That is the right digest for a catalog entry,
//! which is a hash *of a file as it sits on disk*, and it is the wrong digest
//! for an embedded signature, which is a hash *of an image*. They are different
//! numbers over the same file and neither can be substituted for the other. This
//! module implements the second; the first is left where it is.

use crate::error::AuthError;
use av_pe::PeFile;
use std::ops::Range;

/// A hash an Authenticode signature can be made over.
///
/// The four Windows has used. MD5 is deliberately absent — it is refused by
/// name rather than implemented, because computing an MD5 digest and comparing
/// it would be a comparison that proves nothing, and a verifier that returns
/// `true` on the strength of one is at its most confident exactly where it is
/// least sound. Every file in the measured population is SHA-256, with six
/// SHA-1 and one SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-1, `1.3.14.3.2.26`. Broken for collision resistance, still used by
    /// older signatures, and still checked honestly where it appears.
    Sha1,
    /// SHA-256, `2.16.840.1.101.3.4.2.1`. The overwhelming majority.
    Sha256,
    /// SHA-384, `2.16.840.1.101.3.4.2.2`.
    Sha384,
    /// SHA-512, `2.16.840.1.101.3.4.2.3`. Not in the measured population, and
    /// implemented because it costs four lines and its absence would refuse a
    /// file for no reason a user could act on.
    Sha512,
}

impl DigestAlgorithm {
    /// The algorithm's name, as a report writes it.
    pub const fn name(self) -> &'static str {
        match self {
            DigestAlgorithm::Sha1 => "SHA-1",
            DigestAlgorithm::Sha256 => "SHA-256",
            DigestAlgorithm::Sha384 => "SHA-384",
            DigestAlgorithm::Sha512 => "SHA-512",
        }
    }

    /// The algorithm's OID, as arcs.
    pub const fn oid(self) -> &'static [u64] {
        match self {
            DigestAlgorithm::Sha1 => &[1, 3, 14, 3, 2, 26],
            DigestAlgorithm::Sha256 => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
            DigestAlgorithm::Sha384 => &[2, 16, 840, 1, 101, 3, 4, 2, 2],
            DigestAlgorithm::Sha512 => &[2, 16, 840, 1, 101, 3, 4, 2, 3],
        }
    }

    /// The algorithm an `OBJECT IDENTIFIER`'s content names, if it is one of
    /// these.
    ///
    /// Returns `None` for MD5 and for everything unrecognised, and the caller is
    /// expected to tell the two apart from the OID it renders into the error
    /// rather than from here: what this function needs to answer is "can I
    /// compute this", and the answer for both is no.
    pub fn from_oid(content: &[u8]) -> Option<Self> {
        [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ]
        .into_iter()
        .find(|algorithm| av_signatures::oid::oid_matches(content, algorithm.oid()))
    }

    /// How many bytes the digest is.
    pub const fn output_len(self) -> usize {
        match self {
            DigestAlgorithm::Sha1 => 20,
            DigestAlgorithm::Sha256 => 32,
            DigestAlgorithm::Sha384 => 48,
            DigestAlgorithm::Sha512 => 64,
        }
    }

    /// Hash a buffer in one call.
    ///
    /// For the tests and for the small buffers — a certificate's `TBSCertificate`,
    /// an attribute set. The file digest streams instead, because a 230 MB
    /// `MRT.exe` should not be copied into a `Vec` to be hashed.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(self);
        hasher.update(data);
        hasher.finalize()
    }
}

/// A streaming hasher over the four algorithms, so the file digest can be fed
/// region by region without concatenating them.
///
/// One enum rather than four call sites, because the regions are computed once
/// and the algorithm is chosen by the signature; an enum keeps the choice in one
/// place instead of threading a generic parameter through the region code.
#[derive(Debug)]
enum Hasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn new(algorithm: DigestAlgorithm) -> Self {
        use sha2::Digest;
        match algorithm {
            DigestAlgorithm::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            DigestAlgorithm::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            DigestAlgorithm::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            DigestAlgorithm::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        match self {
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// The byte ranges of the file the image digest covers, in the order they are
/// hashed.
///
/// Exposed because it is the part of the algorithm that is worth being able to
/// look at. A digest that fails to verify is either a tampered file or a wrong
/// region, and a caller holding the regions can tell those apart in a way that
/// a caller holding only a 32-byte result cannot.
///
/// The ranges are disjoint and ascending **except** where the specification's
/// byte-count arithmetic in step 8 makes them overlap a section; see the module
/// documentation. Overlaps are reproduced rather than corrected, because
/// correcting them would change the digest.
pub fn regions(pe: &PeFile<'_>) -> Result<Vec<Range<usize>>, AuthError> {
    let data = pe.data();
    let file_len = data.len();

    let checksum = pe.checksum_field_offset();
    let security_entry = pe.security_directory_entry_offset();
    let headers_end = pe.size_of_headers() as usize;
    let certificate = pe.security_directory();

    // The header holes. Each of these is a structural fact about PE: `CheckSum`
    // sits at optional-header offset 64 and the security entry is the fifth of
    // sixteen directories at offset 96 (PE32) or 112 (PE32+), so the order is
    // fixed and only the bounds are in question.
    let checksum_end = checksum + 4;
    let security_end = security_entry + 8;
    if checksum_end > security_entry || security_end > headers_end || headers_end > file_len {
        return Err(AuthError::BadDigestRegion {
            reason:
                "the header fields the digest steps over are not in the order the format requires",
        });
    }

    let mut out = Vec::with_capacity(pe.number_of_sections() as usize + 4);
    out.push(0..checksum);
    out.push(checksum_end..security_entry);
    out.push(security_end..headers_end);

    // Step 6: the byte count starts at the end of the headers and gains a
    // section's raw size each time one is hashed.
    let mut sum_of_bytes_hashed = headers_end;

    // Step 7. The sort is the trap; the filter is the other half of it.
    let mut sections: Vec<(u64, u64)> = Vec::new();
    for index in 0..pe.number_of_sections() as usize {
        let Some(section) = pe.section(index) else {
            break;
        };
        if section.size_of_raw_data == 0 {
            continue;
        }
        sections.push((
            u64::from(section.pointer_to_raw_data),
            u64::from(section.size_of_raw_data),
        ));
    }
    sections.sort_unstable_by_key(|&(offset, _)| offset);

    for (offset, size) in sections {
        let start = usize::try_from(offset).map_err(|_| AuthError::BadDigestRegion {
            reason: "a section's raw offset does not fit in a file offset",
        })?;
        let end = start
            .checked_add(
                usize::try_from(size).map_err(|_| AuthError::BadDigestRegion {
                    reason: "a section's raw size does not fit in a file offset",
                })?,
            )
            .ok_or(AuthError::BadDigestRegion {
                reason: "a section's raw range overflows",
            })?;
        if end > file_len {
            // Clamping to the file would produce a digest over bytes the signer
            // never hashed and quietly agree with nothing; the honest answer is
            // that this file's image is not the image the format describes.
            return Err(AuthError::BadDigestRegion {
                reason: "a section's raw data runs past the end of the file",
            });
        }
        out.push(start..end);
        sum_of_bytes_hashed =
            sum_of_bytes_hashed
                .checked_add(end - start)
                .ok_or(AuthError::BadDigestRegion {
                    reason: "the running byte count overflows",
                })?;
    }

    // Step 8, with the specification's arithmetic rather than the reader's
    // expectation. See the module documentation.
    let certificate_size =
        usize::try_from(certificate.size).map_err(|_| AuthError::BadDigestRegion {
            reason: "the certificate table size does not fit in a file offset",
        })?;
    let end = file_len
        .checked_sub(certificate_size)
        .ok_or(AuthError::BadDigestRegion {
            reason: "the certificate table is larger than the file",
        })?;
    if sum_of_bytes_hashed < end {
        out.push(sum_of_bytes_hashed..end);
    }

    Ok(out)
}

/// The Authenticode image digest of a file.
///
/// This is the number a signature commits to, and comparing it is what binds a
/// signature to the bytes on disk. Everything else in this crate can be right
/// while this is wrong, and the verdict would then be `Invalid` for a file that
/// is fine — or, if the comparison were skipped, `Trusted` for a file that is
/// not.
pub fn image_digest(pe: &PeFile<'_>, algorithm: DigestAlgorithm) -> Result<Vec<u8>, AuthError> {
    let data = pe.data();
    let mut hasher = Hasher::new(algorithm);
    for region in regions(pe)? {
        let slice = data.get(region.clone()).ok_or(AuthError::BadDigestRegion {
            reason: "a digest region is outside the file",
        })?;
        hasher.update(slice);
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_pe::testing::{append_security_directory, minimal_pe32};
    use av_pe::PeFile;

    /// The section table follows the optional header, whose declared length is
    /// the only way to find it. Reconstructed here from the public accessors
    /// rather than reached for through a new one, because the crate under test
    /// should not gain API for its own tests: `CheckSum` sits a fixed distance
    /// into the optional header, so its offset minus that distance is the
    /// optional header's start.
    fn section_entry_offset(pe: &PeFile<'_>, index: usize) -> usize {
        let optional_header = pe.checksum_field_offset() - av_pe::headers::checksum_at();
        let table = optional_header + usize::from(pe.size_of_optional_header());
        table + index * av_pe::sections::SECTION_ENTRY_LEN
    }

    /// Swap two sections' raw pointers and sizes, which is how a section table
    /// gets out of file order without the file changing.
    fn swap_raw_fields(data: &mut [u8], a: usize, b: usize) {
        for field in [20usize, 16] {
            for width in 0..4 {
                data.swap(a + field + width, b + field + width);
            }
        }
    }

    /// The fixture with the raw data both of its sections claim actually in it.
    ///
    /// [`minimal_pe32`] is 0x400 bytes — the whole of `.text` and none of
    /// `.data` — and says so: tests that need the later section extend it. Every
    /// test in this module needs both, because a digest is about sections and
    /// the bytes they claim. At 0x400 the image describes raw data that is not
    /// in the file, which is a truncated download rather than a PE, and
    /// `regions` refuses it — that refusal is pinned by
    /// `a_section_running_past_the_end_of_the_file_is_refused`, which truncates
    /// *this* image and expects exactly that error.
    ///
    /// 0x800 would be both sections exactly; the extra 0x400 is an overlay,
    /// which is what step 8's tail hashes on a file that has one.
    fn image_with_both_sections() -> Vec<u8> {
        let mut bytes = minimal_pe32();
        bytes.resize(0xC00, 0);
        bytes
    }

    #[test]
    fn an_ordinary_file_hashes_headers_then_sections_then_the_tail() {
        let pe_bytes = image_with_both_sections();
        let pe = PeFile::parse(&pe_bytes).unwrap();
        let regions = regions(&pe).unwrap();

        // Three header regions, two sections, and whatever follows them.
        assert_eq!(regions.len(), 6, "{regions:?}");
        assert_eq!(regions[0].start, 0);
        assert_eq!(regions[1].start, pe.checksum_field_offset() + 4);
        assert_eq!(regions[2].start, pe.security_directory_entry_offset() + 8);
        assert_eq!(regions[2].end, pe.size_of_headers() as usize);
        // The sections, in the order the fixture lays them out.
        assert_eq!(regions[3], 0x200..0x600);
        assert_eq!(regions[4], 0x600..0x800);
        // The regions are ascending and disjoint when the file is contiguous.
        for pair in regions.windows(2) {
            assert!(pair[0].end <= pair[1].start, "{regions:?}");
        }
    }

    #[test]
    fn sections_are_hashed_in_file_order_not_table_order() {
        // The classic silent failure. The fixture lists `.text` first at raw
        // offset 0x200 and `.data` second at 0x600; swapping the raw fields
        // makes the *table* order the reverse of the *file* order, which is
        // exactly the file a table-order implementation gets wrong.
        let mut bytes = image_with_both_sections();
        let first = section_entry_offset(&PeFile::parse(&bytes).unwrap(), 0);
        let second = section_entry_offset(&PeFile::parse(&bytes).unwrap(), 1);
        swap_raw_fields(&mut bytes, first, second);

        let pe = PeFile::parse(&bytes).unwrap();
        assert_eq!(
            pe.section(0).unwrap().pointer_to_raw_data,
            0x600,
            "the fixture must actually be reversed"
        );
        let regions = regions(&pe).unwrap();
        let section_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.end - r.start >= 0x200)
            .collect();
        assert_eq!(section_regions[0], &(0x200..0x600), "{regions:?}");
        assert_eq!(section_regions[1], &(0x600..0x800), "{regions:?}");
    }

    #[test]
    fn a_zero_size_section_contributes_nothing() {
        // A section with no raw data is skipped entirely — not hashed as an
        // empty range, and above all not added to the byte count, which would
        // shift the region step 8 hashes.
        let mut bytes = image_with_both_sections();
        let second = section_entry_offset(&PeFile::parse(&bytes).unwrap(), 1);
        // `SizeOfRawData` is at entry offset 16, little-endian.
        bytes[second + 16..second + 20].copy_from_slice(&0u32.to_le_bytes());

        let pe = PeFile::parse(&bytes).unwrap();
        let before = regions(&PeFile::parse(&image_with_both_sections()).unwrap()).unwrap();
        let after = regions(&pe).unwrap();
        // One fewer region, and the tail starts 0x200 bytes earlier because the
        // dropped section's size never entered the byte count.
        assert_eq!(after.len(), before.len() - 1);
        assert_eq!(
            after.last().unwrap().start,
            before.last().unwrap().start - 0x200
        );
    }

    #[test]
    fn a_file_with_no_certificate_table_is_not_an_error() {
        // Most files have no signature, and asking for the digest of one must
        // give a digest rather than a refusal — the caller's next step is to
        // find no signature, not to handle a failure.
        let bytes = image_with_both_sections();
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(!pe.security_directory().is_present());
        let digest = image_digest(&pe, DigestAlgorithm::Sha256).unwrap();
        assert_eq!(digest.len(), 32);
        // The certificate size is zero, so the whole tail is hashed.
        let regions = regions(&pe).unwrap();
        assert_eq!(regions.last().unwrap().end, bytes.len());
    }

    #[test]
    fn the_certificate_table_is_excluded_from_the_tail() {
        // The one thing the digest exists to do: adding a certificate must not
        // change what was signed. Appending one changes the tail's end and
        // nothing else.
        let mut bytes = image_with_both_sections();
        let before = {
            let pe = PeFile::parse(&bytes).unwrap();
            regions(&pe).unwrap()
        };
        let certificate = vec![0xAAu8; 0x100];
        append_security_directory(&mut bytes, &certificate);
        let pe = PeFile::parse(&bytes).unwrap();
        let after = regions(&pe).unwrap();

        // Every region before the tail is identical...
        assert_eq!(after[..after.len() - 1], before[..before.len() - 1]);
        // ...and the tail ends exactly where the certificate table begins.
        assert_eq!(after.last().unwrap().end, bytes.len() - certificate.len());
    }

    #[test]
    fn a_section_running_past_the_end_of_the_file_is_refused() {
        // Truncating the file under a section that claims raw data. Clamping
        // would produce a digest over a shorter region than the header
        // describes and agree with nothing; refusing says what is wrong.
        let mut bytes = image_with_both_sections();
        bytes.truncate(0x700);
        let pe = PeFile::parse(&bytes).unwrap();
        assert!(matches!(
            regions(&pe),
            Err(AuthError::BadDigestRegion { .. })
        ));
    }

    #[test]
    fn the_regions_and_the_digest_are_the_same_thing() {
        // The digest must be the regions hashed in order and nothing else. If
        // `image_digest` ever grew a step of its own, this is what catches it.
        let mut bytes = image_with_both_sections();
        append_security_directory(&mut bytes, &[0x5Au8; 64]);
        let pe = PeFile::parse(&bytes).unwrap();

        let expected = {
            let mut hasher = Hasher::new(DigestAlgorithm::Sha256);
            for region in regions(&pe).unwrap() {
                hasher.update(&bytes[region]);
            }
            hasher.finalize()
        };
        assert_eq!(
            image_digest(&pe, DigestAlgorithm::Sha256).unwrap(),
            expected
        );
    }

    #[test]
    fn the_four_algorithms_give_four_different_digests() {
        let bytes = image_with_both_sections();
        let pe = PeFile::parse(&bytes).unwrap();
        let digests: Vec<Vec<u8>> = [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ]
        .iter()
        .map(|a| image_digest(&pe, *a).unwrap())
        .collect();
        assert_eq!(digests[0].len(), 20);
        assert_eq!(digests[1].len(), 32);
        assert_eq!(digests[2].len(), 48);
        assert_eq!(digests[3].len(), 64);
        for i in 0..digests.len() {
            for j in i + 1..digests.len() {
                assert_ne!(digests[i], digests[j]);
            }
        }
    }

    #[test]
    fn a_sha256_digest_of_a_known_buffer_matches_a_published_value() {
        // The hashes themselves are checked against the standard test vector
        // so that a wrong algorithm wiring — SHA-384 where SHA-256 was asked
        // for — cannot pass by matching another wrong wiring.
        assert_eq!(
            crate::error::hex(&DigestAlgorithm::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            crate::error::hex(&DigestAlgorithm::Sha1.digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            crate::error::hex(&DigestAlgorithm::Sha384.digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            crate::error::hex(&DigestAlgorithm::Sha512.digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn the_algorithm_oids_round_trip() {
        for algorithm in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let encoded = av_signatures::testing::encode(algorithm.oid());
            assert_eq!(DigestAlgorithm::from_oid(&encoded), Some(algorithm));
            assert_eq!(algorithm.output_len(), algorithm.digest(b"").len());
        }
        // MD5 is not one of them, and must not parse as one.
        let md5 = av_signatures::testing::encode(&[1, 2, 840, 113549, 2, 5]);
        assert_eq!(DigestAlgorithm::from_oid(&md5), None);
    }
}
