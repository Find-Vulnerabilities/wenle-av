//! Reading a zip, from the end backwards.
//!
//! # Why the reader starts at the end
//!
//! A zip is not read front to back. The authoritative description of a zip's
//! contents is its *central directory*, a table near the end of the file, and
//! the per-member headers scattered through the body are redundant copies that
//! a hostile archive is free to disagree with. A reader that walked the local
//! headers forwards would see whatever the archive wanted it to see; one that
//! reads the central directory and then seeks to each member sees the same list
//! a zip tool would show a user. That is the whole reason the format is built
//! this way — it is designed for random access, and reading it the way it was
//! designed is both faster and harder to lie to.
//!
//! # The records, and where they are
//!
//! ```text
//!   PK\x03\x04  local file header     name, then the member's bytes
//!   PK\x01\x02  central directory     the authoritative entry list
//!   PK\x06\x06  zip64 end of central  present only above 4 GiB / 65535 members
//!   PK\x06\x07  zip64 locator         a fixed 20 bytes before the EOCD
//!   PK\x05\x06  end of central dir    how many entries, where they start
//! ```
//!
//! The end record is found by scanning backwards for its signature, because
//! everything after it is an archive comment of arbitrary length and nothing
//! records where the comment begins. The scan is bounded at 65,557 bytes plus
//! the record itself, which is the largest a comment can be.
//!
//! # What this reader does not do
//!
//! It does not extract to disk, so the directory traversal a member name can
//! spell is not a risk — the name is a string in a report and
//! [`crate::name::sanitize`] is what makes it a safe one. It does not follow
//! the local headers' claims about size, using the central directory's instead,
//! and it does not trust either: every byte produced goes through
//! [`ExpansionBudget`], so a member that declares a kilobyte and decompresses
//! to a terabyte is stopped at the ceiling rather than after it.
//!
//! Two methods are read: `store` and `deflate`. Everything else — deflate64,
//! bzip2, LZMA, PPMd, zstd — is refused by name. That refusal is a
//! [`av_core::SkipReason::Unsupported`] on that member, which is a statement
//! about this build and not about the file, and it is what keeps a member this
//! product cannot read from being reported as one it read and found nothing in.

use std::ops::Range;

use crate::budget::ExpansionBudget;
use crate::error::ArchiveError;
use crate::name;
use crate::Result;
use crate::{Extracted, MemberInfo};

/// End of central directory.
const EOCD_SIG: &[u8] = b"PK\x05\x06";
/// The fixed part of an end-of-central-directory record, before its comment.
const EOCD_FIXED: usize = 22;
/// Largest archive comment the format permits, which bounds the backward scan.
const MAX_COMMENT: usize = 0xFFFF;
/// Central directory file header.
const CD_SIG: &[u8] = b"PK\x01\x02";
const CD_FIXED: usize = 46;
/// Local file header.
const LOCAL_SIG: &[u8] = b"PK\x03\x04";
const LOCAL_FIXED: usize = 30;
/// Zip64 end of central directory record and its locator.
const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
const ZIP64_EOCD_MIN: usize = 56;
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const ZIP64_LOCATOR_LEN: usize = 20;
/// The extra-field identifier that carries the 64-bit sizes.
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// A 32-bit field with this value means "look in the zip64 extra field".
const ZIP64_SENTINEL: u64 = 0xFFFF_FFFF;

/// The general-purpose flag that says the member is encrypted.
const FLAG_ENCRYPTED: u16 = 1 << 0;
/// The general-purpose flag that says the name is UTF-8 rather than CP437.
const FLAG_UTF8: u16 = 1 << 11;

/// One entry of the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// The member's name, sanitized for display. Empty when the archive stored
    /// no name at all.
    pub name: String,
    /// The name as the archive stored it, decoded but not sanitized. Kept
    /// because a support case occasionally needs to see what was really there,
    /// and because the two differ exactly when the archive is trying something.
    pub raw_name: String,
    /// Compression method: 0 store, 8 deflate, and the rest as the format
    /// assigns them.
    pub method: u16,
    /// General-purpose bit flags.
    pub flags: u16,
    /// CRC-32 of the member's uncompressed bytes, as the archive claims.
    pub crc32: u32,
    /// The size the member occupies inside the archive.
    pub compressed_size: u64,
    /// The size the member will be once decompressed, as the archive claims.
    ///
    /// A claim, not a fact: nothing enforces it, which is exactly why the
    /// expansion budget exists. It is used for the reserve hint and for
    /// deciding up front that a member is too large to attempt.
    pub uncompressed_size: u64,
    /// Offset of the member's local header.
    pub local_offset: u64,
    /// True when the entry is a directory: it carries no content and is not a
    /// member.
    pub directory: bool,
}

impl ZipEntry {
    /// True when the member is password-protected.
    pub const fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    /// True when the archive declared the name to be UTF-8.
    pub const fn is_utf8(&self) -> bool {
        self.flags & FLAG_UTF8 != 0
    }

    /// The compression method, spelled the way the format's own registry does.
    pub fn method_name(&self) -> &'static str {
        match self.method {
            0 => "store",
            1 => "shrink",
            6 => "implode",
            8 => "deflate",
            9 => "deflate64",
            12 => "bzip2",
            14 => "lzma",
            93 => "zstd",
            95 => "xz",
            98 => "ppmd",
            _ => "an unassigned method",
        }
    }

    /// True when this build has a decoder for the member's method.
    pub const fn is_readable_method(&self) -> bool {
        matches!(self.method, 0 | 8)
    }

    /// What a report should say about a member this build will not read.
    pub fn unsupported_method(&self) -> Option<String> {
        (!self.is_readable_method()).then(|| self.method_name().to_owned())
    }
}

/// A parsed zip: the central directory, and the bytes it points into.
#[derive(Debug, Clone)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
    /// True when the archive claims to be one part of a multi-part set. The
    /// other parts are not here, so some members are genuinely absent.
    pub spanned: bool,
}

impl<'a> ZipArchive<'a> {
    /// Parse the central directory out of `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let eocd = find_eocd(data)?;
        let (declared, directory) = read_directory_location(data, eocd)?;
        let entries = read_entries(data, directory, declared)?;
        Ok(Self {
            data,
            entries,
            spanned: le16(data, eocd + 4).unwrap_or(0) != 0,
        })
    }

    /// Every entry, in the order the central directory lists them.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// The members a scan would consider: everything that is not a directory.
    pub fn members(&self) -> Vec<MemberInfo> {
        self.entries
            .iter()
            .filter(|entry| !entry.directory)
            .map(|entry| MemberInfo {
                name: entry.name.clone(),
                declared_size: reported_size(entry.uncompressed_size),
                encrypted: entry.is_encrypted(),
                unreadable_method: entry.unsupported_method(),
            })
            .collect()
    }

    /// Read one member's contents.
    ///
    /// `index` is into [`ZipArchive::entries`], which is what
    /// [`ZipArchive::members`] filters. The budget is spent, not merely
    /// consulted: a caller that reads two members pays for both.
    pub fn read(&self, index: usize, budget: &mut ExpansionBudget) -> Result<Extracted> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "zip",
                detail: format!("there is no entry {index} in this archive"),
            })?;

        if entry.is_encrypted() {
            return Err(ArchiveError::Unsupported {
                format: "zip",
                detail: "the member is encrypted".to_owned(),
            });
        }
        if !entry.is_readable_method() {
            return Err(ArchiveError::Unsupported {
                format: "zip",
                detail: entry.method_name().to_owned(),
            });
        }
        budget.open_member()?;

        let range = self.data_range(entry)?;
        let raw = &self.data[range];
        let allowance = budget.allowance();

        let produced = match entry.method {
            0 => {
                // Stored: the bytes are the content, so the only thing that can
                // be lied about is the length, and the length is bounded by the
                // file itself.
                if raw.len() as u64 > allowance {
                    return Err(ArchiveError::Budget {
                        needed: raw.len() as u64,
                        remaining: allowance,
                    });
                }
                raw.to_vec()
            }
            _ => inflate(raw, allowance, entry.uncompressed_size)?,
        };

        budget.spend(produced.len() as u64)?;
        // The CRC is checked but not enforced: the bytes are really there, and
        // a detection found in them is a detection. What a mismatch means is
        // that the archive's directory and its body disagree, which is worth
        // telling the user and is not worth throwing away evidence over.
        let verified = entry.crc32 == crc32fast::hash(&produced);
        if !verified {
            log::debug!(
                "zip member `{}` failed its CRC-32 check: the body is not what the directory \
                 describes",
                entry.name
            );
        }

        Ok(Extracted {
            name: entry.name.clone(),
            bytes: produced,
            verified,
        })
    }

    /// Where a member's compressed bytes are, found through its local header.
    fn data_range(&self, entry: &ZipEntry) -> Result<Range<usize>> {
        let corrupt = |detail: String| ArchiveError::Member {
            member: entry.name.clone(),
            detail,
        };

        let offset = usize::try_from(entry.local_offset)
            .map_err(|_| corrupt("the member's header is past the end of the file".into()))?;
        if offset + LOCAL_FIXED > self.data.len() {
            return Err(corrupt(
                "the member's header is past the end of the file".into(),
            ));
        }
        if &self.data[offset..offset + 4] != LOCAL_SIG {
            return Err(corrupt(
                "the member's local header is missing or has the wrong signature".into(),
            ));
        }

        // The name and extra lengths come from the *local* header, not the
        // central directory. They are allowed to differ — a zip writer may put
        // a different extra field in each — and it is the local one that says
        // where the data starts.
        let name_len = usize::from(le16(self.data, offset + 26).unwrap_or(0));
        let extra_len = usize::from(le16(self.data, offset + 28).unwrap_or(0));
        let start = offset
            .checked_add(LOCAL_FIXED)
            .and_then(|o| o.checked_add(name_len))
            .and_then(|o| o.checked_add(extra_len))
            .ok_or_else(|| corrupt("the member's header lengths overflow".into()))?;

        let length = usize::try_from(entry.compressed_size)
            .map_err(|_| corrupt("the member declares more data than a file can hold".into()))?;
        let end = start.checked_add(length).ok_or_else(|| {
            corrupt("the member's data runs past the end of the address space".into())
        })?;
        if end > self.data.len() {
            return Err(corrupt(format!(
                "the member declares {length} bytes of data but only {} remain in the file",
                self.data.len().saturating_sub(start)
            )));
        }
        Ok(start..end)
    }
}

/// Where the central directory is and how many entries it holds.
fn read_directory_location(data: &[u8], eocd: usize) -> Result<(usize, usize)> {
    let mut count = u64::from(le16(data, eocd + 10).unwrap_or(0));
    let mut offset = u64::from(le32(data, eocd + 16).unwrap_or(0));

    // A field that holds its own maximum is the format's way of saying "the
    // real value is in the zip64 record", which is present only when something
    // in the archive exceeded 4 GiB or 65,535 members.
    if count == 0xFFFF || offset == ZIP64_SENTINEL {
        if let Some((zip64_count, _, zip64_offset)) = read_zip64(data, eocd) {
            count = zip64_count;
            offset = zip64_offset;
        }
    }

    let offset = usize::try_from(offset).map_err(|_| ArchiveError::Malformed {
        format: "zip",
        detail: "the central directory is said to start past the end of the address space".into(),
    })?;
    if offset > data.len() {
        return Err(ArchiveError::Malformed {
            format: "zip",
            detail: format!(
                "the central directory is said to start at {offset} in a file of {} bytes",
                data.len()
            ),
        });
    }
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    Ok((count, offset))
}

/// Read the zip64 end-of-central-directory record, if there is one.
fn read_zip64(data: &[u8], eocd: usize) -> Option<(u64, u64, u64)> {
    let locator = eocd.checked_sub(ZIP64_LOCATOR_LEN)?;
    if data.get(locator..locator + 4)? != ZIP64_LOCATOR_SIG {
        return None;
    }
    let record = usize::try_from(le64(data, locator + 8)?).ok()?;
    if data.get(record..record + 4)? != ZIP64_EOCD_SIG || record + ZIP64_EOCD_MIN > data.len() {
        return None;
    }
    // Total entries, size of the directory, and where it starts. The offsets
    // are from the start of the zip64 record, whose own layout is fixed.
    Some((
        le64(data, record + 32)?,
        le64(data, record + 40)?,
        le64(data, record + 48)?,
    ))
}

/// Walk the central directory.
fn read_entries(data: &[u8], start: usize, count: usize) -> Result<Vec<ZipEntry>> {
    let mut entries = Vec::new();
    let mut cursor = start;

    for index in 0..count {
        let Some(signature) = data.get(cursor..cursor + 4) else {
            // Running off the end while the directory still claims entries is a
            // truncated archive. What was read is still true, so it is kept and
            // the shortfall is reported by the caller through `declared`
            // exceeding `examined`.
            log::debug!("zip central directory ended after {index} of {count} entries");
            break;
        };
        if signature != CD_SIG {
            log::debug!("zip central directory entry {index} has the wrong signature");
            break;
        }
        if cursor + CD_FIXED > data.len() {
            break;
        }

        let flags = le16(data, cursor + 8).unwrap_or(0);
        let method = le16(data, cursor + 10).unwrap_or(0);
        let crc32 = le32(data, cursor + 16).unwrap_or(0);
        let mut compressed_size = u64::from(le32(data, cursor + 20).unwrap_or(0));
        let mut uncompressed_size = u64::from(le32(data, cursor + 24).unwrap_or(0));
        let name_len = usize::from(le16(data, cursor + 28).unwrap_or(0));
        let extra_len = usize::from(le16(data, cursor + 30).unwrap_or(0));
        let comment_len = usize::from(le16(data, cursor + 32).unwrap_or(0));
        let mut local_offset = u64::from(le32(data, cursor + 42).unwrap_or(0));
        let external_attributes = le32(data, cursor + 38).unwrap_or(0);

        let name_start = cursor + CD_FIXED;
        let name_end = name_start.saturating_add(name_len);
        let extra_end = name_end.saturating_add(extra_len);
        if extra_end > data.len() {
            log::debug!("zip central directory entry {index} runs past the end of the file");
            break;
        }

        let raw_bytes = &data[name_start..name_end];
        let utf8 = flags & FLAG_UTF8 != 0;
        if extra_len > 0 {
            apply_zip64_extra(
                &data[name_end..extra_end],
                &mut uncompressed_size,
                &mut compressed_size,
                &mut local_offset,
            );
        }

        let decoded = name::decode(raw_bytes, utf8);
        let name = name::sanitize(&decoded);
        // A directory entry is one whose name ends in a separator, or one whose
        // external attributes carry the MS-DOS directory bit. Both spellings
        // are in the wild and a reader that checked one would treat the other's
        // directories as zero-byte members.
        let directory = decoded.ends_with('/')
            || decoded.ends_with('\\')
            || (external_attributes & 0x10 != 0 && compressed_size == 0);

        entries.push(ZipEntry {
            name,
            raw_name: decoded,
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            local_offset,
            directory,
        });

        cursor = extra_end.saturating_add(comment_len);
        if cursor > data.len() {
            break;
        }
    }

    Ok(entries)
}

/// Fill 64-bit sizes in from a zip64 extra field.
///
/// The extra field carries only the values whose 32-bit counterparts are the
/// sentinel, in a fixed order, with the ones that are present packed together.
/// Reading them positionally is the only correct way: a field that is not a
/// sentinel is simply absent, and treating a missing one as zero would turn a
/// four-gigabyte member into an empty one.
fn apply_zip64_extra(extra: &[u8], uncompressed: &mut u64, compressed: &mut u64, offset: &mut u64) {
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[cursor], extra[cursor + 1]]);
        let size = usize::from(u16::from_le_bytes([extra[cursor + 2], extra[cursor + 3]]));
        let body_start = cursor + 4;
        let Some(body) = extra.get(body_start..body_start + size) else {
            return;
        };
        if id == ZIP64_EXTRA_ID {
            let mut field = 0usize;
            let mut take = |target: &mut u64, is_sentinel: bool| {
                if is_sentinel {
                    if let Some(bytes) = body.get(field..field + 8) {
                        let mut array = [0u8; 8];
                        array.copy_from_slice(bytes);
                        *target = u64::from_le_bytes(array);
                    }
                    field += 8;
                }
            };
            take(uncompressed, *uncompressed == ZIP64_SENTINEL);
            take(compressed, *compressed == ZIP64_SENTINEL);
            take(offset, *offset == ZIP64_SENTINEL);
            return;
        }
        cursor = body_start + size;
    }
}

/// Decompress a raw deflate stream, refusing to produce more than `limit` bytes.
///
/// A thin wrapper over [`crate::inflate::raw`], which owns the ceiling and the
/// accounting. It exists so that the zip path's error names the member it was
/// reading — a message saying "a compressed stream is malformed" with no member
/// attached is a message a support engineer cannot act on.
fn inflate(raw: &[u8], limit: u64, declared: u64) -> Result<Vec<u8>> {
    let hint = decompress_hint(limit, declared);
    crate::inflate::raw(raw, limit, hint)
        .map(|inflated| inflated.bytes)
        .map_err(|error| match error {
            ArchiveError::Malformed { detail, .. } => ArchiveError::Malformed {
                format: "zip",
                detail: format!("a member's {detail}"),
            },
            other => other,
        })
}

/// How much to reserve before decompressing.
///
/// The archive's own declared size is a good guess when it is plausible, and a
/// terrible one when it is not: a member that declares four gigabytes and
/// produces ten bytes would otherwise cause a four-gigabyte allocation for
/// nothing. So the hint is capped at a megabyte, past which the vector grows on
/// its own.
fn decompress_hint(limit: u64, declared: u64) -> usize {
    const HINT_CEILING: u64 = 1024 * 1024;
    usize::try_from(declared.min(limit).min(HINT_CEILING)).unwrap_or(0)
}

/// Find the end-of-central-directory record by scanning backwards.
///
/// The comment length is checked against the distance to the end of the file.
/// Without that check a `PK\x05\x06` appearing inside an archive comment — or
/// inside a member's data, which for a large archive is well within the scan
/// window — would be taken for the real record, and the reader would then
/// report whatever the bytes there happened to spell.
fn find_eocd(data: &[u8]) -> Result<usize> {
    if data.len() < EOCD_FIXED {
        return Err(ArchiveError::Malformed {
            format: "zip",
            detail: format!(
                "the file is {} bytes, shorter than the {} an empty archive needs",
                data.len(),
                EOCD_FIXED
            ),
        });
    }
    let lowest = data.len().saturating_sub(EOCD_FIXED + MAX_COMMENT);
    let mut offset = data.len() - EOCD_FIXED;
    loop {
        if &data[offset..offset + 4] == EOCD_SIG {
            let comment = usize::from(le16(data, offset + 20).unwrap_or(0));
            if offset + EOCD_FIXED + comment == data.len() {
                return Ok(offset);
            }
        }
        if offset == lowest {
            break;
        }
        offset -= 1;
    }
    Err(ArchiveError::Malformed {
        format: "zip",
        detail: "no end-of-central-directory record was found, so the archive is truncated or \
                 is not a zip"
            .into(),
    })
}

fn le16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Some(u64::from_le_bytes(array))
}

/// The size to report for a member.
///
/// A `0xFFFFFFFF` in these fields is not a size — it is the format's way of
/// saying "the real value is in the zip64 extra field", and a reader that
/// printed it would announce a four-gigabyte member where the archive meant
/// one of a few kilobytes. Zero stands in for "not stated", which is what the
/// report says.
fn reported_size(declared: u64) -> u64 {
    if declared == ZIP64_SENTINEL {
        0
    } else {
        declared
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{zip_deflate, zip_store, zip_with_comment};

    fn parse(data: &[u8]) -> ZipArchive<'_> {
        ZipArchive::parse(data).expect("a readable archive")
    }

    #[test]
    fn a_stored_member_comes_back_byte_for_byte() {
        let data = zip_store(&[("hello.txt", b"hello world")]);
        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.entries()[0].name, "hello.txt");
        assert!(!archive.entries()[0].is_encrypted());
        assert_eq!(archive.entries()[0].method_name(), "store");

        let mut budget = ExpansionBudget::default();
        let extracted = archive.read(0, &mut budget).expect("the member reads");
        assert_eq!(extracted.bytes, b"hello world");
        assert!(extracted.verified, "the CRC is the value the archive wrote");
        assert_eq!(budget.remaining(), 1024 * 1024 * 1024 - 11);
    }

    #[test]
    fn a_deflated_member_is_decompressed() {
        // Long and repetitive, so the compressed form is much smaller than the
        // content and a reader that returned the raw bytes would be caught.
        let content = "the same line over and over. ".repeat(200);
        let data = zip_deflate(&[("log.txt", content.as_bytes())]);
        let archive = parse(&data);
        assert_eq!(archive.entries()[0].method_name(), "deflate");
        assert!(archive.entries()[0].compressed_size < content.len() as u64);

        let mut budget = ExpansionBudget::default();
        let extracted = archive.read(0, &mut budget).expect("the member reads");
        assert_eq!(extracted.bytes, content.as_bytes());
        assert!(extracted.verified);
    }

    #[test]
    fn several_members_are_listed_in_directory_order() {
        let data = zip_store(&[("a.txt", b"a"), ("b/c.txt", b"b"), ("d.txt", b"d")]);
        let archive = parse(&data);
        let names: Vec<&str> = archive.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "b/c.txt", "d.txt"]);

        let mut budget = ExpansionBudget::default();
        for (index, expected) in [b"a".as_slice(), b"b", b"d"].into_iter().enumerate() {
            let extracted = archive.read(index, &mut budget).expect("reads");
            assert_eq!(extracted.bytes, expected);
        }
    }

    #[test]
    fn an_empty_archive_has_no_members_and_is_not_an_error() {
        let data = zip_store(&[]);
        let archive = parse(&data);
        assert!(archive.entries().is_empty());
        assert!(archive.members().is_empty());
    }

    #[test]
    fn an_archive_comment_does_not_hide_the_directory() {
        // The comment is where a `PK\x05\x06` inside the file would come from,
        // and the length check is what tells the two apart.
        let data = zip_with_comment(&[("a.txt", b"a")], b"PK\x05\x06 not really an end record");
        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.entries()[0].name, "a.txt");
    }

    #[test]
    fn directory_entries_are_not_members() {
        let data = zip_store(&[("dir/", b""), ("dir/a.txt", b"a")]);
        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 2);
        let members = archive.members();
        assert_eq!(members.len(), 1, "{members:?}");
        assert_eq!(members[0].name, "dir/a.txt");
    }

    #[test]
    fn the_budget_stops_a_member_that_expands_past_its_ceiling() {
        // The zip bomb, in miniature: one member of a megabyte of zeros,
        // compressed to almost nothing, on a budget that will not have it.
        let content = vec![0u8; 1024 * 1024];
        let data = zip_deflate(&[("bomb.bin", &content)]);
        let archive = parse(&data);
        assert!(
            archive.entries()[0].compressed_size < 4096,
            "the fixture must actually be a bomb: {} bytes",
            archive.entries()[0].compressed_size
        );

        let mut budget = ExpansionBudget::new(64 * 1024, 64 * 1024);
        let error = archive.read(0, &mut budget).expect_err("refused");
        assert_eq!(error.skip_reason(), av_core::SkipReason::Budget);
        // And nothing was charged to the budget for a read that produced
        // nothing usable.
        assert_eq!(budget.remaining(), 64 * 1024);
    }

    #[test]
    fn the_budget_stops_a_stored_member_before_it_is_copied() {
        let content = vec![7u8; 8192];
        let data = zip_store(&[("big.bin", &content)]);
        let archive = parse(&data);
        let mut budget = ExpansionBudget::new(1024, 1024);
        let error = archive.read(0, &mut budget).expect_err("refused");
        assert_eq!(error.skip_reason(), av_core::SkipReason::Budget);
    }

    #[test]
    fn a_member_with_an_unreadable_method_is_refused_by_name() {
        // A hand-built directory entry claiming LZMA. The reader must not
        // attempt it, and must say which method it was.
        let mut data = zip_store(&[("a.txt", b"a")]);
        // The method field is 10 bytes into the central directory entry; find
        // it and rewrite it.
        let cd = find_eocd(&data).expect("the fixture is a zip");
        let directory = usize::try_from(le32(&data, cd + 16).unwrap_or(0)).unwrap_or(0);
        data[directory + 10..directory + 12].copy_from_slice(&14u16.to_le_bytes());

        let archive = parse(&data);
        assert_eq!(archive.entries()[0].method_name(), "lzma");
        assert_eq!(
            archive.entries()[0].unsupported_method().as_deref(),
            Some("lzma")
        );
        let members = archive.members();
        assert_eq!(members[0].unreadable_method.as_deref(), Some("lzma"));

        let mut budget = ExpansionBudget::default();
        let error = archive.read(0, &mut budget).expect_err("refused");
        assert_eq!(
            error.skip_reason(),
            av_core::SkipReason::Unsupported {
                method: "lzma".into()
            }
        );
    }

    #[test]
    fn an_encrypted_member_is_refused_rather_than_read_as_noise() {
        let mut data = zip_store(&[("secret.doc", b"plaintext body")]);
        let cd = find_eocd(&data).expect("the fixture is a zip");
        let directory = usize::try_from(le32(&data, cd + 16).unwrap_or(0)).unwrap_or(0);
        data[directory + 8..directory + 10].copy_from_slice(&1u16.to_le_bytes());

        let archive = parse(&data);
        assert!(archive.entries()[0].is_encrypted());
        assert!(archive.members()[0].encrypted);
        let mut budget = ExpansionBudget::default();
        let error = archive.read(0, &mut budget).expect_err("refused");
        assert!(error.leaves_contents_unknown());
        assert!(error.to_string().contains("encrypted"), "{error}");
    }

    #[test]
    fn a_crc_mismatch_is_reported_but_the_bytes_are_still_returned() {
        // The archive's directory and its body disagree. The body is what is on
        // the disk, so those are the bytes a scan has to look at — but the
        // disagreement is worth saying.
        let mut data = zip_store(&[("a.txt", b"hello")]);
        let cd = find_eocd(&data).expect("the fixture is a zip");
        let directory = usize::try_from(le32(&data, cd + 16).unwrap_or(0)).unwrap_or(0);
        // Corrupt the stored CRC rather than the data, so the member is intact
        // and only the claim about it is wrong.
        data[directory + 16..directory + 20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let archive = parse(&data);
        let mut budget = ExpansionBudget::default();
        let extracted = archive.read(0, &mut budget).expect("still readable");
        assert_eq!(extracted.bytes, b"hello");
        assert!(!extracted.verified);
    }

    #[test]
    fn a_truncated_archive_is_an_error_and_not_an_empty_one() {
        let data = zip_store(&[("a.txt", b"a")]);
        let truncated = &data[..data.len() - 10];
        let error = ZipArchive::parse(truncated).expect_err("no directory");
        assert!(matches!(error, ArchiveError::Malformed { .. }));
        assert!(error.to_string().contains("truncated") || error.to_string().contains("no end"));
    }

    #[test]
    fn a_file_that_is_not_a_zip_at_all_is_an_error() {
        let error = ZipArchive::parse(b"MZ\x90\x00 this is an executable").expect_err("not a zip");
        assert!(matches!(error, ArchiveError::Malformed { .. }));
    }

    #[test]
    fn a_member_whose_data_runs_past_the_end_of_the_file_is_refused() {
        let mut data = zip_store(&[("a.txt", b"hello")]);
        let cd = find_eocd(&data).expect("the fixture is a zip");
        let directory = usize::try_from(le32(&data, cd + 16).unwrap_or(0)).unwrap_or(0);
        // Claim a megabyte of stored data for a five-byte member.
        data[directory + 20..directory + 24].copy_from_slice(&1_048_576u32.to_le_bytes());

        let archive = parse(&data);
        let mut budget = ExpansionBudget::default();
        let error = archive.read(0, &mut budget).expect_err("refused");
        assert!(error.to_string().contains("past the end") || error.to_string().contains("remain"));
    }

    #[test]
    fn the_readable_methods_are_exactly_store_and_deflate() {
        for method in 0u16..=110 {
            let readable = matches!(method, 0 | 8);
            let mut data = zip_store(&[("a.txt", b"a")]);
            let cd = find_eocd(&data).expect("zip");
            let directory = usize::try_from(le32(&data, cd + 16).unwrap_or(0)).unwrap_or(0);
            data[directory + 10..directory + 12].copy_from_slice(&method.to_le_bytes());
            let archive = parse(&data);
            assert_eq!(
                archive.entries()[0].is_readable_method(),
                readable,
                "method {method} ({})",
                archive.entries()[0].method_name()
            );
        }
    }

    #[test]
    fn a_name_that_is_not_utf8_is_decoded_from_the_archives_code_page() {
        let data = zip_store(&[("caf\u{e9}.txt", b"x")]);
        let archive = parse(&data);
        // 0xE9 is Θ in CP437. The point is that it decodes to *something*
        // rather than to a replacement character, and that the report carries a
        // name a user could recognise.
        assert_eq!(archive.entries()[0].raw_name, "cafΘ.txt");
        assert_eq!(archive.entries()[0].name, "cafΘ.txt");
    }

    #[test]
    fn read_offsets_are_taken_from_the_local_header_not_the_directory() {
        // The local header's name and extra lengths are what say where the data
        // begins. This archive has no extra field, so the two agree; the test
        // exists so that a change which started trusting the directory's
        // lengths would have to argue with it.
        let data = zip_store(&[("a.txt", b"content")]);
        let archive = parse(&data);
        let entry = &archive.entries()[0];
        let range = archive.data_range(entry).expect("a range");
        assert_eq!(&archive.data[range], b"content");
        assert_eq!(
            entry.local_offset as usize + LOCAL_FIXED + entry.name.len(),
            // The name in the local header is the raw one; for ASCII they are
            // the same length.
            entry.local_offset as usize + LOCAL_FIXED + entry.raw_name.len()
        );
    }
}
