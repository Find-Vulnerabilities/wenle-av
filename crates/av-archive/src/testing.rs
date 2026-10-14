//! Builders for container fixtures, for the workspace's tests.
//!
//! # Why these exist rather than sample files
//!
//! A container reader has to be tested against containers, and a test that
//! reads a fixture must be able to describe *exactly* the archive it needs: a
//! member with an LZMA method, a directory entry with the MS-DOS attribute bit,
//! a CRC that disagrees with the body, a name in CP437. Sample files can only
//! ever be the archives somebody happened to have, and the interesting cases
//! are precisely the ones a well-behaved zip tool will not write.
//!
//! So these build archives byte by byte, from the format's own definition. They
//! are a writer, which means they are also an independent statement of what the
//! reader is supposed to be reading — a reader and a writer written from the
//! same understanding of the format, tested against each other, at least catch
//! the case where one of them drifts.
//!
//! Deliberately hand-written rather than taken from a zip crate: a test helper
//! that shares an implementation with the thing under test proves much less,
//! and the whole point of this crate is to depend on nothing but the
//! decompressor.
//!
//! # What they are not
//!
//! Not a general-purpose zip writer. No zip64, no encryption, no data
//! descriptors, no timestamps worth reading. Every one of those is a feature
//! the reader has to handle and a fixture for it belongs in a test, built by
//! editing the bytes these produce — which is what the module's callers do.
//!
//! # Why the panics are allowed here
//!
//! Building a fixture goes through an encoder, which returns a `Result`, and
//! these functions return the bytes directly because every caller is a test.
//! The alternative — returning a `Result`, or falling back to an empty buffer —
//! would either push an unwrap into every test or let a fixture that failed to
//! build be scanned as an empty archive, which is a test passing for a reason
//! its author never intended. The workspace denies `unwrap_used` in library
//! code; this is the one module that is scaffolding by design.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

/// Encode a member name the way a zip writer without the UTF-8 flag would:
/// one byte per character where the character fits in a byte, UTF-8 otherwise.
///
/// This is what makes a fixture able to say "this name is in CP437" — passing
/// `"caf\u{e9}.txt"` stores the single byte `0xE9`, which the reader decodes
/// back through the code page rather than through UTF-8.
fn encode_name(name: &str) -> Vec<u8> {
    name.chars()
        .flat_map(|c| {
            let code = u32::from(c);
            if code < 0x100 {
                vec![code as u8]
            } else {
                let mut buffer = [0u8; 4];
                c.encode_utf8(&mut buffer).as_bytes().to_vec()
            }
        })
        .collect()
}

/// One member of a fixture archive.
#[derive(Debug, Clone)]
pub struct FixtureMember {
    /// The name, encoded by `encode_name`.
    pub name: Vec<u8>,
    pub content: Vec<u8>,
    /// The compression method to store. `0` stores the content as it is, `8`
    /// deflates it, and any other value is written as a method with the content
    /// stored anyway — which is what makes a fixture for "the archive claims a
    /// method this build cannot read".
    pub method: u16,
    /// General-purpose bit flags.
    pub flags: u16,
    pub crc32: u32,
    /// External attributes, for the MS-DOS directory bit.
    pub external_attributes: u32,
}

impl FixtureMember {
    /// A member stored without compression.
    pub fn stored(name: &str, content: &[u8]) -> Self {
        Self {
            name: encode_name(name),
            content: content.to_vec(),
            method: 0,
            flags: 0,
            crc32: crc32fast::hash(content),
            external_attributes: 0,
        }
    }

    /// A member compressed with deflate.
    pub fn deflated(name: &str, content: &[u8]) -> Self {
        Self {
            method: 8,
            ..Self::stored(name, content)
        }
    }

    /// The bytes this member contributes after its local header.
    fn body(&self) -> Vec<u8> {
        match self.method {
            8 => deflate(&self.content),
            _ => self.content.clone(),
        }
    }

    /// Mark this member as a directory: a trailing separator and the MS-DOS
    /// directory attribute, which is how the two spellings appear in the wild.
    #[must_use]
    pub fn as_directory(mut self) -> Self {
        self.name.push(b'/');
        self.external_attributes = 0x10;
        self.content.clear();
        self.crc32 = 0;
        self
    }
}

/// Deflate a buffer with a raw deflate stream, which is what a zip member holds.
fn deflate(content: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing to a `Vec` cannot fail, so a failure here is a bug in the fixture
    // rather than a condition a test should have to handle.
    encoder.write_all(content).expect("deflating a fixture");
    encoder.finish().expect("finishing a fixture")
}

/// Assemble a zip from members, with an archive comment.
pub fn zip_with_comment(members: &[(&str, &[u8])], comment: &[u8]) -> Vec<u8> {
    let members: Vec<FixtureMember> = members
        .iter()
        .map(|(name, content)| FixtureMember::stored(name, content))
        .collect();
    zip_from_members(&members, comment)
}

/// Assemble a zip whose members are all stored.
pub fn zip_store(members: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with_comment(members, &[])
}

/// Assemble a zip whose members are all deflated.
pub fn zip_deflate(members: &[(&str, &[u8])]) -> Vec<u8> {
    let members: Vec<FixtureMember> = members
        .iter()
        .map(|(name, content)| FixtureMember::deflated(name, content))
        .collect();
    zip_from_members(&members, &[])
}

/// Assemble a zip from fully-specified members.
///
/// Laid out the way a zip is: every member's local header and data, then the
/// central directory that describes all of them, then the end record. The
/// offsets recorded in the directory are the positions the local headers
/// actually landed at, which is what makes the fixture usable for testing that
/// the reader seeks by the directory and not by guesswork.
pub fn zip_from_members(members: &[FixtureMember], comment: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::with_capacity(members.len());

    for member in members {
        let body = member.body();
        offsets.push(out.len() as u32);

        // Local file header. The version and timestamp fields are fixed: a
        // fixture has no creation time and a test that depended on one would be
        // a test with a clock in it.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&member.flags.to_le_bytes());
        out.extend_from_slice(&member.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&member.crc32.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(member.content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&member.name);
        out.extend_from_slice(&body);
    }

    let directory_offset = out.len() as u32;
    for (member, offset) in members.iter().zip(&offsets) {
        let body_len = match member.method {
            8 => deflate(&member.content).len(),
            _ => member.content.len(),
        };
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&member.flags.to_le_bytes());
        out.extend_from_slice(&member.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&member.crc32.to_le_bytes());
        out.extend_from_slice(&(body_len as u32).to_le_bytes());
        out.extend_from_slice(&(member.content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&member.external_attributes.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&member.name);
    }
    let directory_size = out.len() as u32 - directory_offset;

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

/// A gzip stream holding `content`.
///
/// Built by hand for the same reason the zip writer is: the header fields a
/// test needs to vary — the name, the optional flags — are exactly the ones a
/// library would set for you.
pub fn gzip(name: Option<&str>, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x1f, 0x8b, 0x08]);
    // Flags: the name field, when there is one.
    out.push(if name.is_some() { 0x08 } else { 0x00 });
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0); // no extra compression flags
    out.push(0xff); // unknown OS, which is what a portable writer says
    if let Some(name) = name {
        out.extend_from_slice(name.as_bytes());
        out.push(0);
    }
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(content).expect("deflating a fixture");
    out.extend_from_slice(&encoder.finish().expect("finishing a fixture"));
    out.extend_from_slice(&crc32fast::hash(content).to_le_bytes());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out
}

/// A tar archive holding `members`.
pub fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, content) in members {
        out.extend_from_slice(&tar_header(name, content.len() as u64));
        out.extend_from_slice(content);
        // Every member's data is padded to a whole block.
        let padding = (512 - content.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, padding));
    }
    // Two zero blocks end an archive.
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

/// One 512-byte tar header, with its checksum filled in.
pub fn tar_header(name: &str, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    let name_bytes = name.as_bytes();
    let length = name_bytes.len().min(100);
    header[..length].copy_from_slice(&name_bytes[..length]);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    // The checksum field reads as spaces while the sum is taken.
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..265].copy_from_slice(b"ustar\x0000");
    let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArchiveFormat, Container, ExpansionBudget};

    /// Open a fixture with a budget nothing in these tests comes close to
    /// reaching. Each test here is about the fixture being the format it claims
    /// to be, not about a ceiling — that is tested where the ceiling lives.
    fn open(data: &[u8]) -> Container<'_> {
        Container::open(data, &mut ExpansionBudget::default())
            .expect("opens without error")
            .expect("a container")
    }

    #[test]
    fn the_zip_fixture_is_a_zip_the_reader_opens() {
        // A fixture generator that produced something the reader could not
        // parse would make every test that used it pass for the wrong reason.
        let data = zip_store(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        assert_eq!(ArchiveFormat::detect(&data), Some(ArchiveFormat::Zip));
        assert_eq!(open(&data).members().len(), 2);
    }

    #[test]
    fn the_gzip_fixture_is_a_gzip_and_carries_its_name() {
        let data = gzip(Some("notes.txt"), b"contents");
        assert_eq!(ArchiveFormat::detect(&data), Some(ArchiveFormat::Gzip));
        let container = open(&data);
        let members = container.members();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "notes.txt");
    }

    #[test]
    fn the_gzip_fixture_without_a_name_still_opens() {
        let data = gzip(None, b"contents");
        assert_eq!(open(&data).members().len(), 1);
    }

    #[test]
    fn the_tar_fixture_is_a_tar() {
        let data = tar(&[("a.txt", b"hello"), ("dir/b.txt", b"world")]);
        assert_eq!(ArchiveFormat::detect(&data), Some(ArchiveFormat::Tar));
        assert_eq!(open(&data).members().len(), 2);
    }

    #[test]
    fn a_name_that_fits_in_a_byte_is_stored_as_one_byte() {
        // The property the CP437 tests depend on: `\u{e9}` is one stored byte,
        // not the two UTF-8 would use.
        assert_eq!(encode_name("caf\u{e9}"), vec![b'c', b'a', b'f', 0xe9]);
        // And a character that does not fit is stored as UTF-8.
        assert_eq!(encode_name("\u{6587}"), "\u{6587}".as_bytes().to_vec());
    }

    #[test]
    fn a_directory_member_gets_a_separator_and_the_directory_attribute() {
        let member = FixtureMember::stored("dir", b"").as_directory();
        assert_eq!(member.name, b"dir/");
        assert_eq!(member.external_attributes, 0x10);
    }
}
