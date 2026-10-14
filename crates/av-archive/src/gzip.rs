//! Reading a gzip stream, and the tar that is usually behind it.
//!
//! # Why this reader decompresses everything when it is opened
//!
//! A gzip member is a header, a deflate stream, a CRC-32 and a length, and
//! nothing marks where the stream ends. The only way to find the trailer — and
//! therefore the next member, because the format permits several concatenated
//! into one file and some backup tools write them that way — is to decompress
//! and ask the decompressor how many input bytes it used.
//!
//! So there is no way to list a gzip's members without producing their content,
//! and listing them lazily would mean decompressing the ones before a member
//! every time it was asked for. This reader does the work once, at open, and
//! charges the expansion budget for all of it: the bytes really were produced,
//! and a scan that was told to allow a gigabyte of expansion has spent what it
//! produced whether or not it went on to look at it.
//!
//! # A gzip holds a tar, nearly always
//!
//! The format compresses a single byte stream and stores a name for it, so the
//! common `.tar.gz` is a tar archive that has been compressed whole. This
//! module does not know that and does not need to: it reports what came out,
//! and the caller looks at the result and decides whether it is itself a
//! container. That is the same path a `.zip` holding a `.tar` takes, and it
//! means the nesting limit and the expansion budget apply identically to both.
//!
//! # What is checked
//!
//! Both trailer fields, because they are the only integrity check the format
//! has: the CRC-32 must be that of the bytes that came out, and the length must
//! be their length modulo 2^32. A member failing either was damaged or
//! deliberately altered, and the caller is told rather than handed the bytes as
//! though they were what the file means.
//!
//! A gzip member is never encrypted — the format has no such concept — so
//! nothing here corresponds to the zip reader's encrypted-member path. A `.gz`
//! that will not decompress is a broken file, not a locked one, and the two
//! want different words in a report.

use crate::budget::ExpansionBudget;
use crate::error::ArchiveError;
use crate::name;
use crate::Result;
use crate::{Extracted, MemberInfo};

/// The two bytes every gzip stream starts with.
const MAGIC: [u8; 2] = [0x1f, 0x8b];
/// The only compression method the format defines.
const METHOD_DEFLATE: u8 = 8;
/// The fixed part of a header, before any optional field.
const HEADER_FIXED: usize = 10;
/// The CRC-32 and length that follow every member's deflate stream.
const TRAILER_LEN: usize = 8;

/// The optional-field flags, from the header's fourth byte.
const FLAG_HEADER_CRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;

/// One member of a gzip file, with its content already produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipMember {
    /// The name the header carried, sanitized. Empty when it carried none.
    pub name: String,
    /// The member's decompressed bytes.
    pub bytes: Vec<u8>,
    /// True when the trailer's CRC-32 and length both matched the bytes
    /// produced. False means the file was damaged or altered in transit.
    pub verified: bool,
}

impl GzipMember {
    /// The name to report, falling back to something a user can recognise.
    ///
    /// A gzip header's name field is optional and most writers omit it: the
    /// name a user knows is the one on disk, which the compressor had no way to
    /// know. Reporting an unnamed member as `data` rather than as an empty
    /// string keeps a report from having a blank where a name should be.
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            "data"
        } else {
            &self.name
        }
    }
}

/// A parsed gzip file: every member, already decompressed.
#[derive(Debug, Clone)]
pub struct GzipArchive {
    members: Vec<GzipMember>,
}

impl GzipArchive {
    /// Read every member of the file, spending `budget` as it goes.
    pub fn parse(data: &[u8], budget: &mut ExpansionBudget) -> Result<Self> {
        let mut members = Vec::new();
        let mut offset = 0usize;

        while offset < data.len() {
            budget.open_member()?;
            let header = read_header(data, offset)?;
            let allowance = budget.allowance();

            let rest = data
                .get(header.body..)
                .ok_or_else(|| ArchiveError::Malformed {
                    format: "gzip",
                    detail: "a member's header is past the end of the file".into(),
                })?;
            // No hint: the format has no length field in its header, and the
            // trailer's length is behind the stream it describes. The vector
            // grows on its own, which for a stream whose size is unknown is the
            // only honest option.
            let inflated = crate::inflate::raw(rest, allowance, 0)?;
            budget.spend(inflated.bytes.len() as u64)?;

            let trailer_at = header.body.checked_add(inflated.consumed).ok_or_else(|| {
                ArchiveError::Malformed {
                    format: "gzip",
                    detail: "a member's length overflows the address space".into(),
                }
            })?;
            let verified = check_trailer(data, trailer_at, &inflated.bytes);

            members.push(GzipMember {
                name: header.name,
                bytes: inflated.bytes,
                verified,
            });

            // The next member, if there is one, starts right after this one's
            // trailer. Trailing bytes that are not a member are not a member:
            // the loop below would fail on their header, and a file with junk
            // after its last member is a file whose last member is still the
            // one that matters.
            let next = trailer_at + TRAILER_LEN;
            if next >= data.len() {
                break;
            }
            if data.get(next..next + 2) != Some(MAGIC.as_slice()) {
                log::debug!(
                    "{} bytes follow the last gzip member at {next} and are not another member",
                    data.len() - next
                );
                break;
            }
            offset = next;
        }

        if members.is_empty() {
            return Err(ArchiveError::Malformed {
                format: "gzip",
                detail: "the file holds no gzip member".into(),
            });
        }
        Ok(Self { members })
    }

    /// The members.
    pub fn members_parsed(&self) -> &[GzipMember] {
        &self.members
    }

    /// The members a scan would consider.
    pub fn members(&self) -> Vec<MemberInfo> {
        self.members
            .iter()
            .map(|member| MemberInfo {
                name: member.display_name().to_owned(),
                declared_size: member.bytes.len() as u64,
                // A gzip member can never be encrypted, and deflate is the only
                // method the format defines. Both facts are stated rather than
                // left to the reader to infer from a missing field.
                encrypted: false,
                unreadable_method: None,
            })
            .collect()
    }

    /// Hand back one member's content.
    ///
    /// The budget is not consulted: everything a gzip holds was produced when
    /// it was opened, and charged then. See the module documentation.
    pub fn read(&self, index: usize, _budget: &mut ExpansionBudget) -> Result<Extracted> {
        let member = self
            .members
            .get(index)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "gzip",
                detail: format!("there is no member {index} in this file"),
            })?;
        Ok(Extracted {
            name: member.display_name().to_owned(),
            bytes: member.bytes.clone(),
            verified: member.verified,
        })
    }
}

/// A member's header, and where its deflate stream starts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    name: String,
    /// Offset of the member's first deflate byte.
    body: usize,
}

/// Read one member's header and check the fields that must be right.
fn read_header(data: &[u8], offset: usize) -> Result<Header> {
    let malformed = |detail: String| ArchiveError::Malformed {
        format: "gzip",
        detail,
    };

    let header = data
        .get(offset..offset + HEADER_FIXED)
        .ok_or_else(|| malformed("the file ends inside a member's header".into()))?;
    if header[0..2] != MAGIC {
        return Err(malformed(format!(
            "the member at {offset} does not start with the gzip magic"
        )));
    }
    if header[2] != METHOD_DEFLATE {
        return Err(ArchiveError::Unsupported {
            format: "gzip",
            detail: format!("compression method {}", header[2]),
        });
    }

    let flags = header[3];
    let mut cursor = offset + HEADER_FIXED;
    let mut name = String::new();

    if flags & FLAG_EXTRA != 0 {
        let length = read_u16(data, cursor, &malformed)?;
        cursor = cursor
            .checked_add(2 + usize::from(length))
            .ok_or_else(|| malformed("the extra field's length overflows".into()))?;
        if cursor > data.len() {
            return Err(malformed(
                "the extra field runs past the end of the file".into(),
            ));
        }
    }
    if flags & FLAG_NAME != 0 {
        let (field, next) = read_c_string(data, cursor, &malformed)?;
        // The name is ISO 8859-1 by the format's definition, which is the same
        // one-byte-per-character decoding the zip reader uses for a name
        // without the UTF-8 flag.
        name = name::sanitize(&name::decode(field, false));
        cursor = next;
    }
    if flags & FLAG_COMMENT != 0 {
        let (_, next) = read_c_string(data, cursor, &malformed)?;
        cursor = next;
    }
    if flags & FLAG_HEADER_CRC != 0 {
        cursor = cursor
            .checked_add(2)
            .ok_or_else(|| malformed("the header CRC overflows".into()))?;
        if cursor > data.len() {
            return Err(malformed(
                "the header CRC is past the end of the file".into(),
            ));
        }
    }

    Ok(Header { name, body: cursor })
}

/// Check a member's trailer against the bytes it produced.
fn check_trailer(data: &[u8], trailer_at: usize, produced: &[u8]) -> bool {
    let Some(bytes) = data.get(trailer_at..trailer_at + TRAILER_LEN) else {
        log::debug!("a gzip member has no trailer, so the file is truncated");
        return false;
    };
    let crc = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let ok = crc == crc32fast::hash(produced) && length == produced.len() as u32;
    if !ok {
        log::debug!(
            "a gzip member failed its trailer check: {} bytes produced, {length} declared",
            produced.len()
        );
    }
    ok
}

fn read_u16(data: &[u8], offset: usize, malformed: &dyn Fn(String) -> ArchiveError) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| malformed("a header field is past the end of the file".into()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a NUL-terminated header field, returning it and the offset after it.
fn read_c_string<'a>(
    data: &'a [u8],
    offset: usize,
    malformed: &dyn Fn(String) -> ArchiveError,
) -> Result<(&'a [u8], usize)> {
    let rest = data
        .get(offset..)
        .ok_or_else(|| malformed("a header field is past the end of the file".into()))?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| malformed("a header field is not terminated".into()))?;
    Ok((&rest[..end], offset + end + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::gzip;

    fn open(data: &[u8]) -> Result<(GzipArchive, ExpansionBudget)> {
        let mut budget = ExpansionBudget::default();
        let archive = GzipArchive::parse(data, &mut budget)?;
        Ok((archive, budget))
    }

    #[test]
    fn a_named_stream_reports_its_name() {
        let data = gzip(Some("notes.txt"), b"the contents");
        let (archive, _) = open(&data).expect("parses");
        assert_eq!(archive.members().len(), 1);
        assert_eq!(archive.members()[0].name, "notes.txt");
        assert_eq!(archive.members()[0].declared_size, 12);

        let extracted = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(extracted.bytes, b"the contents");
        assert_eq!(extracted.name, "notes.txt");
        assert!(extracted.verified);
    }

    #[test]
    fn an_unnamed_stream_is_called_data_rather_than_nothing() {
        let data = gzip(None, b"the contents");
        let (archive, _) = open(&data).expect("parses");
        assert_eq!(archive.members()[0].name, "data");
        let extracted = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(extracted.name, "data");
        assert!(extracted.verified);
    }

    #[test]
    fn a_corrupted_trailer_is_reported_rather_than_hidden() {
        let mut data = gzip(Some("a.bin"), b"the contents");
        let last = data.len() - 1;
        data[last] ^= 0xff;
        let (archive, _) = open(&data).expect("the header is intact");
        let extracted = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("the bytes are there");
        assert_eq!(extracted.bytes, b"the contents");
        assert!(!extracted.verified, "the length no longer matches");
    }

    #[test]
    fn a_bad_crc_alone_is_reported() {
        let mut data = gzip(None, b"the contents");
        let crc_at = data.len() - 8;
        data[crc_at] ^= 0xff;
        let (archive, _) = open(&data).expect("the header is intact");
        let extracted = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("the bytes are there");
        assert!(!extracted.verified);
    }

    #[test]
    fn a_truncated_trailer_is_reported_as_unverified_and_not_as_a_failure() {
        // The stream decompresses; what is missing is the eight bytes that
        // would have proved it was intact. That is a fact about the file worth
        // reporting, and not a reason to hand back nothing.
        let data = gzip(None, b"the contents");
        let (archive, _) = open(&data[..data.len() - 4]).expect("the stream is intact");
        let extracted = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(extracted.bytes, b"the contents");
        assert!(!extracted.verified);
    }

    #[test]
    fn the_budget_stops_a_stream_that_expands_past_it() {
        let content = vec![0u8; 4 * 1024 * 1024];
        let data = gzip(None, &content);
        assert!(
            data.len() < 8192,
            "the fixture must be a bomb: {}",
            data.len()
        );
        let mut budget = ExpansionBudget::new(64 * 1024, 64 * 1024);
        let error = GzipArchive::parse(&data, &mut budget).expect_err("refused");
        assert_eq!(error.skip_reason(), av_core::SkipReason::Budget);
    }

    #[test]
    fn a_truncated_stream_is_malformed() {
        let data = gzip(None, b"a reasonably long string of content to compress");
        let mut budget = ExpansionBudget::default();
        let error = GzipArchive::parse(&data[..data.len() - 20], &mut budget)
            .expect_err("the stream is cut short");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn something_that_is_not_a_gzip_is_refused() {
        let mut budget = ExpansionBudget::default();
        let error =
            GzipArchive::parse(b"MZ\x90\x00 not a gzip", &mut budget).expect_err("not a gzip");
        assert!(matches!(error, ArchiveError::Malformed { .. }));
    }

    #[test]
    fn a_header_ending_inside_an_optional_field_is_refused() {
        let mut data = gzip(Some("a.txt"), b"x");
        data.truncate(HEADER_FIXED + 2);
        let mut budget = ExpansionBudget::default();
        let error = GzipArchive::parse(&data, &mut budget).expect_err("the name never ends");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn a_concatenated_file_yields_every_member_in_order() {
        // Two members in one file. The second's header is found only by
        // decompressing the first, which is the reason this reader produces
        // everything at open.
        let mut data = gzip(Some("first.txt"), b"one");
        data.extend_from_slice(&gzip(Some("second.txt"), b"two"));

        let (archive, _) = open(&data).expect("parses");
        let names: Vec<String> = archive.members().iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, ["first.txt", "second.txt"]);

        let first = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(first.bytes, b"one");
        assert!(first.verified);
        let second = archive
            .read(1, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(second.bytes, b"two");
        assert!(second.verified);
    }

    #[test]
    fn junk_after_the_last_member_does_not_hide_it() {
        let mut data = gzip(Some("real.txt"), b"content");
        data.extend_from_slice(b"\x00\x00\x00\x00 not a member");
        let (archive, _) = open(&data).expect("the first member is intact");
        assert_eq!(archive.members().len(), 1);
        assert_eq!(archive.members()[0].name, "real.txt");
    }

    #[test]
    fn a_second_read_of_the_same_index_is_the_same_answer() {
        let data = gzip(Some("a"), b"same");
        let (archive, _) = open(&data).expect("parses");
        let first = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        let second = archive
            .read(0, &mut ExpansionBudget::default())
            .expect("reads");
        assert_eq!(first, second);
    }

    #[test]
    fn there_is_no_second_member_to_read_in_a_single_member_file() {
        let data = gzip(None, b"one");
        let (archive, _) = open(&data).expect("parses");
        let error = archive
            .read(1, &mut ExpansionBudget::default())
            .expect_err("no second member");
        assert!(error.to_string().contains("no member 1"), "{error}");
    }

    #[test]
    fn a_gzip_member_is_never_reported_as_encrypted() {
        // The format has no encryption. Reporting one as locked would invent a
        // fact and would make a report say "unexamined" about a stream the
        // product reads perfectly well.
        let data = gzip(None, b"x");
        let (archive, _) = open(&data).expect("parses");
        assert!(!archive.members()[0].encrypted);
        assert!(archive.members()[0].unreadable_method.is_none());
    }

    #[test]
    fn the_whole_file_is_charged_to_the_budget_when_it_is_opened() {
        // The accounting rule this reader has and the others do not, stated as
        // a test because a caller reading only the first member of a large
        // concatenated file would otherwise be surprised by the cost.
        let mut data = gzip(None, b"0123456789");
        data.extend_from_slice(&gzip(None, b"abcdefghij"));
        let mut budget = ExpansionBudget::default();
        let archive = GzipArchive::parse(&data, &mut budget).expect("parses");
        assert_eq!(archive.members().len(), 2);
        assert_eq!(budget.remaining(), 1024 * 1024 * 1024 - 20);
    }
}
