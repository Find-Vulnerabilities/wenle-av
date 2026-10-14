//! Reading a tar.
//!
//! # The simplest container here, and the one with the most history
//!
//! A tar is a sequence of 512-byte blocks: a header, then the member's data
//! padded to a whole number of blocks, repeated, ending with two zero blocks.
//! Nothing is compressed and nothing is indexed — a tar is read front to back
//! and there is no directory to disagree with the body, which is why this
//! reader is a fraction of the size of the zip one.
//!
//! What makes it more than a loop is forty years of extensions. A 100-byte
//! name field cannot hold a modern path, so GNU tar writes a `././@LongLink`
//! member holding the real name and PAX writes a `PaxHeader` member holding
//! `key=value` records. Both are members as far as the format is concerned and
//! neither is content as far as a user is concerned: a scanner that reported
//! them would show a finding in `././@LongLink` for every archive with a deep
//! path, and one that ignored them would report members under names that are
//! wrong. So both are read, applied to the member that follows, and not
//! reported as members themselves.
//!
//! # Where the data is
//!
//! Tar stores no compression, so a member's bytes are a slice of the input and
//! no budget is spent producing them — there is nothing to expand. The budget
//! still applies, at the scan layer, to the total a nested expansion may
//! produce; a tar of a tar of a tar is where the bytes actually multiply.
//!
//! `.tar.gz` is not this reader's business. A gzip that decompresses to a tar
//! is a gzip member whose content happens to be a tar, and the caller reaches
//! this module by looking at what the gzip produced. That is one path for every
//! compressed container rather than one per combination.

use crate::budget::ExpansionBudget;
use crate::error::ArchiveError;
use crate::format::{parse_octal, tar_checksum_ok};
use crate::name;
use crate::Result;
use crate::{Extracted, MemberInfo};

/// Every tar structure is a whole number of these.
const BLOCK: usize = 512;
/// Length of a header block.
const HEADER_LEN: usize = 512;
/// Type flag offset, and the values this reader acts on.
const TYPE_OFFSET: usize = 156;
const TYPE_FILE: u8 = b'0';
/// The same, as a v7 writer spelled it: a NUL byte.
const TYPE_FILE_OLD: u8 = b'\0';
/// `1` is a hard link and `2` a symbolic one. Neither is named here, because
/// neither carries content and both are covered by the single case
/// [`TarEntry::has_content`] exists to exclude.
const TYPE_DIRECTORY: u8 = b'5';
/// GNU's long-name pseudo-member, and the two spellings of it in the wild.
const TYPE_GNU_LONG_NAME: u8 = b'L';
const TYPE_GNU_LONG_LINK: u8 = b'K';
/// PAX extended header.
const TYPE_PAX: u8 = b'x';
/// PAX global header. Applies to every member after it.
const TYPE_PAX_GLOBAL: u8 = b'g';

/// One member of a tar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    /// The member's name, sanitized for display.
    pub name: String,
    /// The name as stored, after any long-name extension has been applied.
    pub raw_name: String,
    /// Offset of the member's first data byte.
    pub data: usize,
    /// Length of the member's data.
    pub size: u64,
    /// The header's type flag.
    pub kind: u8,
}

impl TarEntry {
    /// True when the entry names a directory rather than a file.
    ///
    /// The type flag is the answer the format intends, but tar predates that
    /// being reliable: archives written by old tools, and by a few current
    /// ones, name a directory with the trailing slash and leave the flag as
    /// `'0'`. Both spellings are honoured, because a directory that is taken
    /// for an empty file is an entry a report counts as examined when there was
    /// nothing to examine.
    pub fn is_directory(&self) -> bool {
        self.kind == TYPE_DIRECTORY || (self.size == 0 && self.name.ends_with('/'))
    }

    /// True when the entry is a file whose content is worth scanning.
    ///
    /// A symbolic link has no content: its "data" is a target path, which is a
    /// name and not bytes a rule should be matched against. A hard link is the
    /// same. Neither is a member a scan can produce a verdict about, and
    /// reporting them as examined members with no content would be claiming to
    /// have looked at something there was nothing to look at.
    pub fn has_content(&self) -> bool {
        matches!(self.kind, TYPE_FILE | TYPE_FILE_OLD) && !self.is_directory()
    }
}

/// A parsed tar.
#[derive(Debug, Clone)]
pub struct TarArchive<'a> {
    data: &'a [u8],
    entries: Vec<TarEntry>,
    /// True when the archive ran out of blocks rather than ending with the two
    /// zero blocks the format requires. A tar truncated in transit still has
    /// readable members, and this is how the report says so.
    pub truncated: bool,
}

impl<'a> TarArchive<'a> {
    /// Walk the header chain.
    ///
    /// No budget is spent: tar expands nothing, and charging it for bytes that
    /// were already sitting in the buffer would make a tarball cost double what
    /// the same files cost on disk.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let malformed = |detail: String| ArchiveError::Malformed {
            format: "tar",
            detail,
        };
        if data.len() < HEADER_LEN {
            return Err(malformed(format!(
                "the file is {} bytes, shorter than the {HEADER_LEN}-byte header a tar starts \
                 with",
                data.len()
            )));
        }
        // What the caller handed over must actually be a tar. Without this, a
        // file whose first block is too short to be a header would parse as an
        // archive with no members — which is a report saying "looked inside,
        // found nothing" about something that was never a tar.
        if !tar_checksum_ok(&data[..HEADER_LEN]) && !data[..HEADER_LEN].iter().all(|&b| b == 0) {
            return Err(malformed(
                "the first block is neither a tar header nor the empty-archive marker".into(),
            ));
        }

        let mut entries = Vec::new();
        let mut cursor = 0usize;
        let mut truncated = false;

        // Pending extension state. A long name or a PAX header applies to the
        // member that follows it, and only to that one.
        let mut pending_name: Option<String> = None;
        let mut pending_pax: Option<String> = None;

        loop {
            let Some(header) = data.get(cursor..cursor + HEADER_LEN) else {
                truncated = cursor < data.len() || !entries.is_empty();
                break;
            };
            if header.iter().all(|&b| b == 0) {
                // The end-of-archive marker. Anything after it is padding, and
                // a format that allows padding is a format whose readers must
                // stop here rather than guess.
                break;
            }
            if !tar_checksum_ok(header) {
                return Err(ArchiveError::Malformed {
                    format: "tar",
                    detail: format!("the header at {cursor} fails its own checksum"),
                });
            }

            let kind = header[TYPE_OFFSET];
            let size = parse_octal(&header[124..136]).ok_or_else(|| ArchiveError::Malformed {
                format: "tar",
                detail: format!("the header at {cursor} has an unreadable size field"),
            })?;
            let stored = decode_name(header);
            let data_start = cursor + HEADER_LEN;
            let data_end = data_start
                .checked_add(usize::try_from(size).unwrap_or(usize::MAX))
                .ok_or_else(|| ArchiveError::Malformed {
                    format: "tar",
                    detail: format!("the member at {cursor} declares more data than fits"),
                })?;

            match kind {
                TYPE_GNU_LONG_NAME => {
                    pending_name = Some(read_text(data, data_start, data_end, &stored)?);
                }
                TYPE_GNU_LONG_LINK => {
                    // A long *link* target names where a hard link points, which
                    // is not a name this reader reports. The member is consumed
                    // so the walk stays in step, and nothing is recorded.
                }
                TYPE_PAX | TYPE_PAX_GLOBAL => {
                    // A local header's records apply to the member after it; a
                    // global header's apply to every member after it. Both are
                    // read the same way, because the only record this reader
                    // wants — `path` — means the same thing in both, and the
                    // difference between their scopes does not change what the
                    // next member is called.
                    let body = read_bytes(data, data_start, data_end, &stored)?;
                    if let Some(path) = parse_pax(&body, &stored) {
                        pending_pax = Some(path);
                    }
                }
                _ => {
                    // A real member. The name it is reported under is the PAX
                    // path when there is one, then the GNU long name, then
                    // whatever the header's own field held — which is the order
                    // of specificity, and the order tar itself resolves them in.
                    let raw = pending_pax
                        .take()
                        .or_else(|| pending_name.take())
                        .unwrap_or(stored);
                    entries.push(TarEntry {
                        name: name::sanitize(&raw),
                        raw_name: raw,
                        data: data_start.min(data.len()),
                        size,
                        kind,
                    });
                }
            }

            let padded = data_start.saturating_add(padded_length(size));
            if padded > data.len() {
                truncated = true;
                break;
            }
            cursor = padded;
        }

        Ok(Self {
            data,
            entries,
            truncated,
        })
    }

    /// Every entry, in the order the archive stores them.
    pub fn entries(&self) -> &[TarEntry] {
        &self.entries
    }

    /// The members a scan would consider: files, not directories or links.
    pub fn members(&self) -> Vec<MemberInfo> {
        self.entries
            .iter()
            .filter(|entry| entry.has_content())
            .map(|entry| MemberInfo {
                name: entry.name.clone(),
                declared_size: entry.size,
                // Tar has no encryption and no compression. Both statements are
                // made explicitly rather than left to be inferred from an
                // absent field.
                encrypted: false,
                unreadable_method: None,
            })
            .collect()
    }

    /// Hand back one entry's content.
    ///
    /// `index` is into [`TarArchive::entries`], which is what
    /// [`TarArchive::members`] filters. The budget is not spent: the bytes are
    /// a slice of the file already in memory, and there is nothing to expand.
    pub fn read(&self, index: usize, _budget: &mut ExpansionBudget) -> Result<Extracted> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "tar",
                detail: format!("there is no entry {index} in this archive"),
            })?;
        if !entry.has_content() {
            return Err(ArchiveError::Unsupported {
                format: "tar",
                detail: format!("`{}` is not a file with content", entry.name),
            });
        }
        let end = entry
            .data
            .checked_add(usize::try_from(entry.size).unwrap_or(usize::MAX))
            .ok_or_else(|| ArchiveError::Malformed {
                format: "tar",
                detail: "the member's length overflows the address space".into(),
            })?;
        let bytes = self
            .data
            .get(entry.data..end)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "tar",
                detail: format!("`{}` is truncated", entry.name),
            })?;
        // Tar has no per-member checksum: the header checksum covers the header
        // and nothing covers the body. So a member that is present is a member
        // that is intact as far as the format can say, and `verified` is true
        // rather than unknown — the alternative would be a field that means
        // "true" for every reader here and is therefore noise.
        Ok(Extracted {
            name: entry.name.clone(),
            bytes: bytes.to_vec(),
            verified: true,
        })
    }
}

/// Read a header's name field, joining the ustar prefix when there is one.
///
/// A ustar header splits a long path into a 155-byte prefix and a 100-byte
/// name. The magic distinguishes the two layouts: a plain v7 header has those
/// bytes as part of a longer name field, and joining them would corrupt a name
/// that was never split.
fn decode_name(header: &[u8]) -> String {
    let name = field(header, 0, 100);
    let magic = &header[257..263];
    if magic == b"ustar\0" {
        let prefix = field(header, 345, 155);
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

/// Read a NUL-terminated field as a string, decoding the bytes a tar stores.
fn field(header: &[u8], offset: usize, length: usize) -> String {
    let raw = &header[offset..offset + length];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    name::decode(&raw[..end], false)
}

/// A member's data, rounded up to a whole number of blocks.
fn padded_length(size: u64) -> usize {
    let blocks = (size as usize).div_ceil(BLOCK);
    blocks.saturating_mul(BLOCK)
}

/// Read a pseudo-member's data as bytes, refusing one that runs off the end.
fn read_bytes(data: &[u8], start: usize, end: usize, stored: &str) -> Result<Vec<u8>> {
    data.get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| ArchiveError::Malformed {
            format: "tar",
            detail: format!("the extension member `{stored}` is truncated"),
        })
}

/// Read a pseudo-member's data as text.
fn read_text(data: &[u8], start: usize, end: usize, stored: &str) -> Result<String> {
    let bytes = read_bytes(data, start, end, stored)?;
    let text = String::from_utf8_lossy(&bytes);
    // GNU writes a NUL after the name; the padding after it is zeros too.
    Ok(text.trim_end_matches('\0').to_owned())
}

/// Pull the `path` record out of a PAX extended header.
///
/// The format is a sequence of `LENGTH key=value\n` records, where the length
/// counts the whole record including itself. `path` is the one this reader
/// needs: it is how a PAX tar stores a name too long for the header, and the
/// other records — `size`, `uid`, `mtime` — are either already in the header or
/// of no interest to a scan.
///
/// A malformed record ends the parse rather than failing it. A PAX header that
/// does not parse is a PAX header whose `path` this reader does not have, and
/// the member then falls back to the header's own name field, which is exactly
/// what a tar reader that did not understand PAX at all would do. Refusing the
/// whole archive over it would be worse than the fallback.
fn parse_pax(body: &[u8], stored: &str) -> Option<String> {
    let mut cursor = 0usize;
    let mut path = None;

    while cursor < body.len() {
        let Some(space) = body[cursor..].iter().position(|&b| b == b' ') else {
            break;
        };
        let Ok(length) = std::str::from_utf8(&body[cursor..cursor + space])
            .unwrap_or("")
            .parse::<usize>()
        else {
            break;
        };
        if length <= space + 1 || cursor + length > body.len() {
            break;
        }
        // The record's content is `key=value`, with the trailing newline.
        let record = &body[cursor + space + 1..cursor + length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(equals) = record.iter().position(|&b| b == b'=') {
            let key = &record[..equals];
            let value = &record[equals + 1..];
            if key == b"path" {
                path = Some(String::from_utf8_lossy(value).into_owned());
            }
        }
        cursor += length;
    }

    if path.is_none() {
        log::trace!("the PAX header `{stored}` carries no path record");
    }
    path
}

/// True when the bytes at the start of `data` look like a tar.
///
/// The same check [`crate::format::ArchiveFormat::detect`] makes, exposed so
/// that a caller holding a decompressed buffer can ask the question the
/// format's own detector cannot — a gzip stream has no name to consult, and a
/// tar's signature is 257 bytes in.
pub fn looks_like_tar(data: &[u8]) -> bool {
    crate::format::ArchiveFormat::detect(data) == Some(crate::format::ArchiveFormat::Tar)
}

/// The name GNU gives its long-name pseudo-member, exposed so that a caller
/// filtering entries can recognise it.
pub const GNU_LONG_NAME: &str = "././@LongLink";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{tar, tar_header};

    fn parse(data: &[u8]) -> TarArchive<'_> {
        TarArchive::parse(data).expect("a readable archive")
    }

    /// A header with a type flag that is not a file's, and the checksum
    /// recomputed for it.
    ///
    /// The fixture helper writes plain file headers, and the type flag sits
    /// inside the checksummed region — so a test that changes it has to redo
    /// the sum or the header is one the reader is right to reject.
    fn pseudo_header(name: &str, size: u64, kind: u8) -> [u8; HEADER_LEN] {
        let mut header = tar_header(name, size);
        header[156] = kind;
        header[148..156].copy_from_slice(b"        ");
        let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    #[test]
    fn a_simple_archive_yields_its_members_in_order() {
        let data = tar(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
        let archive = parse(&data);
        let members = archive.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "a.txt");
        assert_eq!(members[1].name, "dir/b.txt");
        assert_eq!(members[0].declared_size, 5);
        assert!(!archive.truncated);

        let first = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(first.bytes, b"alpha");
        let second = archive
            .read(1, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(second.bytes, b"beta");
    }

    #[test]
    fn an_empty_archive_has_no_members() {
        let data = tar(&[]);
        let archive = parse(&data);
        assert!(archive.entries().is_empty());
        assert!(!archive.truncated);
    }

    #[test]
    fn a_member_longer_than_a_block_is_padded_and_the_next_one_still_lines_up() {
        // The padding rule, exercised at both sides of the boundary: 511 bytes
        // is one block plus padding, 512 is exactly two, 513 needs three.
        for size in [511usize, 512, 513, 1024] {
            let content = vec![b'x'; size];
            let data = tar(&[("a.bin", &content), ("b.txt", b"second")]);
            let archive = parse(&data);
            let members = archive.members();
            assert_eq!(members.len(), 2, "size {size}");
            let second = archive
                .read(1, &mut ExpansionBudget::default())
                .expect("reads");
            assert_eq!(second.bytes, b"second", "size {size}");
            let first = archive
                .read(0, &mut ExpansionBudget::default())
                .expect("reads");
            assert_eq!(first.bytes.len(), size);
        }
    }

    #[test]
    fn a_directory_is_not_a_member() {
        let mut data = tar_header("dir/", 0).to_vec();
        data[156] = b'5';
        // Re-checksum, because the type flag is part of the sum.
        data[148..156].copy_from_slice(b"        ");
        let sum: u64 = data.iter().map(|&b| u64::from(b)).sum();
        data[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        data.extend_from_slice(&[0u8; 1024]);

        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1);
        assert!(archive.entries()[0].is_directory());
        assert!(archive.members().is_empty(), "{:?}", archive.members());
    }

    #[test]
    fn a_symbolic_link_is_not_a_member_and_reading_it_is_refused() {
        let mut data = tar(&[("target.txt", b"content")]);
        // Turn the member into a symlink by editing its type flag and fixing
        // the checksum the edit invalidated.
        data[156] = b'2';
        data[148..156].copy_from_slice(b"        ");
        let sum: u64 = data[..512].iter().map(|&b| u64::from(b)).sum();
        data[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        let archive = parse(&data);
        assert!(archive.members().is_empty());
        let error = archive
            .read(0, &mut ExpansionBudget::default())
            .expect_err("a link has no content");
        assert!(
            error.to_string().contains("not a file with content"),
            "{error}"
        );
    }

    #[test]
    fn a_gnu_long_name_applies_to_the_member_after_it() {
        // A name too long for the 100-byte field, so GNU writes it as a
        // pseudo-member. The real member's own field holds a truncated copy,
        // which is the name a reader that ignored the extension would report.
        //
        // The length is chosen to sit past 100 — the point of the test — while
        // staying under the 160 the display cap allows, so that what is being
        // checked is the extension being applied and not the cap being applied.
        let long = "d/".repeat(60) + "payload.exe";
        assert!(long.len() > 100 && long.len() <= 160, "{}", long.len());
        let mut data = Vec::new();
        data.extend_from_slice(&pseudo_header(GNU_LONG_NAME, long.len() as u64, b'L'));
        data.extend_from_slice(long.as_bytes());
        data.extend(std::iter::repeat_n(
            0u8,
            padded_length(long.len() as u64) - long.len(),
        ));
        // The member itself, with a name field that holds only the first 100
        // bytes of the real one.
        data.extend_from_slice(&tar_header(&long[..100], 4));
        data.extend_from_slice(b"data");
        data.extend(std::iter::repeat_n(0u8, 508));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1, "{:?}", archive.entries());
        assert_eq!(archive.entries()[0].raw_name, long);
        assert_eq!(archive.members()[0].name, long);
    }

    #[test]
    fn a_pax_path_applies_to_the_member_after_it() {
        let long = format!("{}/deep.bin", "nested".repeat(15));
        let mut data = Vec::new();
        let record = format!("path={long}\n");
        let record = format!("{} {record}", record.len() + 4);
        data.extend_from_slice(&pseudo_header(
            "PaxHeader/deep.bin",
            record.len() as u64,
            b'x',
        ));
        data.extend_from_slice(record.as_bytes());
        data.extend(std::iter::repeat_n(
            0u8,
            padded_length(record.len() as u64) - record.len(),
        ));
        data.extend_from_slice(&tar_header("truncated-name", 3));
        data.extend_from_slice(b"abc");
        data.extend(std::iter::repeat_n(0u8, 509));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1, "{:?}", archive.entries());
        assert_eq!(archive.entries()[0].raw_name, long);
    }

    #[test]
    fn a_pseudo_member_is_never_reported_as_a_member() {
        // The failure this prevents: a finding in `././@LongLink` for every
        // archive with a deep path, and a member count inflated by one per long
        // name.
        let long = "x".repeat(150);
        let mut data = Vec::new();
        data.extend_from_slice(&pseudo_header(GNU_LONG_NAME, long.len() as u64 + 1, b'L'));
        data.extend_from_slice(long.as_bytes());
        data.push(0);
        data.extend(std::iter::repeat_n(
            0u8,
            padded_length(long.len() as u64 + 1) - (long.len() + 1),
        ));
        data.extend_from_slice(&tar_header("real.txt", 2));
        data.extend_from_slice(b"hi");
        data.extend(std::iter::repeat_n(0u8, 510));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.members().len(), 1);
        assert_eq!(archive.members()[0].name, long);
        assert!(!archive.members()[0].name.contains("@LongLink"));
    }

    #[test]
    fn a_header_failing_its_checksum_is_refused() {
        let mut data = tar(&[("a.txt", b"alpha")]);
        // Corrupt the name without fixing the checksum.
        data[0] = b'z';
        let error = TarArchive::parse(&data).expect_err("bad checksum");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn a_truncated_archive_reports_what_it_has_and_says_it_is_truncated() {
        let data = tar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        // Cut into the second member's data.
        let truncated = &data[..512 + 512 + 520];
        let archive = parse(truncated);
        assert!(archive.truncated);
        // The first member is intact and is reported.
        assert!(archive.entries().iter().any(|e| e.name == "a.txt"));

        let first = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(first.bytes, b"alpha");
    }

    #[test]
    fn something_that_is_not_a_tar_is_refused() {
        let error = TarArchive::parse(b"MZ\x90\x00 not a tar at all").expect_err("not a tar");
        assert!(matches!(error, ArchiveError::Malformed { .. }));
    }

    #[test]
    fn the_looks_like_tar_check_agrees_with_the_parser() {
        assert!(looks_like_tar(&tar(&[("a.txt", b"a")])));
        assert!(!looks_like_tar(b""));
        assert!(!looks_like_tar(&[0u8; 4096]));
        assert!(!looks_like_tar(b"MZ\x90\x00"));
    }

    #[test]
    fn a_ustar_prefix_is_joined_to_the_name() {
        // A path split the way a ustar writer splits it: 60 bytes of prefix,
        // then the file's own name.
        let mut header = tar_header("file.txt", 3);
        header[345..345 + 8].copy_from_slice(b"a/b/c/d\0");
        header[148..156].copy_from_slice(b"        ");
        let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        assert_eq!(decode_name(&header), "a/b/c/d/file.txt");
    }

    #[test]
    fn a_v7_header_does_not_have_its_name_field_split() {
        // The control: the same bytes with a v7 magic. The area that a ustar
        // header uses for a prefix is part of the name field, and joining it
        // would corrupt a name that was never split.
        let mut header = tar_header("file.txt", 3);
        header[345..345 + 8].copy_from_slice(b"a/b/c/d\0");
        header[257..263].copy_from_slice(b"ustar "); // v7, no version byte
        assert_eq!(decode_name(&header), "file.txt");
    }

    #[test]
    fn a_malformed_pax_record_falls_back_to_the_header_name() {
        // A PAX header whose length prefix is nonsense. The member must still be
        // reported, under the name in its own header field.
        let body = b"not a pax record at all";
        let mut header = tar_header("PaxHeader/x", body.len() as u64);
        header[156] = b'x';
        header[148..156].copy_from_slice(b"        ");
        let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        let mut data = header.to_vec();
        data.extend_from_slice(body);
        data.extend(std::iter::repeat_n(
            0u8,
            padded_length(body.len() as u64) - body.len(),
        ));
        data.extend_from_slice(&tar_header("fallback.txt", 2));
        data.extend_from_slice(b"hi");
        data.extend(std::iter::repeat_n(0u8, 510));
        data.extend_from_slice(&[0u8; 1024]);

        let archive = parse(&data);
        assert_eq!(archive.entries().len(), 1);
        assert_eq!(archive.entries()[0].name, "fallback.txt");
    }

    #[test]
    fn a_tar_spends_no_budget_because_it_expands_nothing() {
        let data = tar(&[("a.bin", &vec![7u8; 4096])]);
        let archive = parse(&data);
        let mut budget = ExpansionBudget::new(1024, 1024);
        let extracted = archive.read(0, &mut budget).expect("reads");
        assert_eq!(extracted.bytes.len(), 4096);
        assert_eq!(budget.remaining(), 1024, "nothing was expanded");
    }
}
