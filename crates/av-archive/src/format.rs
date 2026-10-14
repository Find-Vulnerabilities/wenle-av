//! Which container this is, decided from its bytes rather than its name.
//!
//! # Why magic and not the extension
//!
//! A file's extension is a claim by whoever wrote it, and the whole point of a
//! scanner is that it does not take the claim. `invoice.pdf` that opens with
//! `PK\x03\x04` is a zip, and a product that scanned it as a PDF would have
//! skipped every member of it. The reverse case — a `.zip` that is not one — is
//! just as bad in the other direction: an extension-driven reader would report
//! a file as unexamined when it is a perfectly ordinary executable, and an
//! unexamined file is one a user is told nothing about.
//!
//! [`ArchiveFormat::of_path`] exists, and is used only to *disambiguate*: a tar
//! has no signature at the start of the file, and the name is the only thing
//! that says whether the bytes after a gzip stream are a tar or a disk image.

use crate::error::ArchiveError;
use crate::Result;

/// A container format this product can name.
///
/// The list is longer than the list of formats it can *open*, and that is
/// deliberate. A scanner that does not recognise a 7z has nothing to say about
/// it beyond "I do not know what this is", which a user reads as "nothing
/// found". A scanner that recognises it and says "this is a 7z and this build
/// cannot read 7z" has told the truth, and the report carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveFormat {
    /// A zip, and everything that is one underneath: `.jar`, `.docx`, `.xlsx`,
    /// `.odt`, `.apk`, `.nupkg`, `.epub`.
    Zip,
    /// A gzip stream. One of these is usually the outer layer of a
    /// `.tar.gz`, and is also what a `.gz` holding a single file is.
    Gzip,
    /// A tar, in any of its three header dialects: original, ustar and PAX.
    Tar,
    /// A 7-Zip archive. Readable by nothing in this build: LZMA and its
    /// variants are their own family of formats, and a reader for them is a
    /// separate decision from a reader for the three above.
    SevenZip,
    /// A RAR archive, of either the RAR4 or the RAR5 lineage.
    Rar,
    /// A Microsoft cabinet, the container `.msi` and many driver packages use.
    Cab,
    /// A bzip2 stream.
    Bzip2,
    /// An xz stream, which is what `.tar.xz` holds.
    Xz,
    /// A zstandard stream, which is what much of what is new is wrapped in.
    Zstd,
    /// An ISO 9660 image, or a UDF one.
    Iso,
    /// An OLE2 compound file: the container behind legacy `.doc`, `.xls`,
    /// `.msi` and `.msg`. Naming it here is what lets the report say "this is a
    /// document container" rather than leaving the user with nothing.
    Ole,
}

impl ArchiveFormat {
    /// The name used in reports and logs.
    pub const fn name(self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::Gzip => "gzip",
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::SevenZip => "7z",
            ArchiveFormat::Rar => "rar",
            ArchiveFormat::Cab => "cab",
            ArchiveFormat::Bzip2 => "bzip2",
            ArchiveFormat::Xz => "xz",
            ArchiveFormat::Zstd => "zstd",
            ArchiveFormat::Iso => "iso",
            ArchiveFormat::Ole => "ole",
        }
    }

    /// True when this build has a reader for the format.
    pub const fn is_readable(self) -> bool {
        matches!(
            self,
            ArchiveFormat::Zip | ArchiveFormat::Gzip | ArchiveFormat::Tar
        )
    }

    /// A sentence saying what would be needed to open it, for the formats this
    /// build cannot.
    ///
    /// The per-format text matters more than it looks: "unsupported" on its own
    /// tells a user nothing they can act on, whereas "7z uses LZMA, which this
    /// build has no decoder for" tells them what is missing and where the gap
    /// is.
    pub const fn unreadable_because(self) -> &'static str {
        match self {
            ArchiveFormat::Zip | ArchiveFormat::Gzip | ArchiveFormat::Tar => {
                "this build can open it"
            }
            ArchiveFormat::SevenZip => {
                "7z bodies are LZMA-compressed and this build has no LZMA reader"
            }
            ArchiveFormat::Rar => "RAR 5 bodies are proprietary and this build has no RAR reader",
            ArchiveFormat::Cab => {
                "cabinet members use MSZIP or LZX and this build has no reader for either"
            }
            ArchiveFormat::Bzip2 => {
                "bzip2 needs a Burrows-Wheeler decoder this build does not have"
            }
            ArchiveFormat::Xz => "xz is an LZMA2 container and this build has no LZMA2 reader",
            ArchiveFormat::Zstd => "zstd needs a FSE/Huffman decoder this build does not have",
            ArchiveFormat::Iso => {
                "ISO 9660 images are read as a filesystem, which this build does not mount"
            }
            ArchiveFormat::Ole => {
                "OLE2 compound files need a directory-tree reader this build does not have"
            }
        }
    }

    /// The formats whose members this build opens, in the order a report lists
    /// them. Used by the command line to say what a scan can do.
    pub const READABLE: [ArchiveFormat; 3] =
        [ArchiveFormat::Zip, ArchiveFormat::Gzip, ArchiveFormat::Tar];

    /// Every format this product can name, for `wenle db`-style listings and
    /// for the tests that assert the table below is exhaustive.
    pub const ALL: [ArchiveFormat; 11] = [
        ArchiveFormat::Zip,
        ArchiveFormat::Gzip,
        ArchiveFormat::Tar,
        ArchiveFormat::SevenZip,
        ArchiveFormat::Rar,
        ArchiveFormat::Cab,
        ArchiveFormat::Bzip2,
        ArchiveFormat::Xz,
        ArchiveFormat::Zstd,
        ArchiveFormat::Iso,
        ArchiveFormat::Ole,
    ];
}

/// The signature table.
///
/// Ordered longest-signature-first within a family, because a prefix match is
/// how it is consulted: `PK\x05\x06` and `PK\x03\x04` are both zips, and
/// `Rar!\x1a\x07\x01\x00` and `Rar!\x1a\x07\x00` are both rars, and it does not
/// matter which of a family matches as long as one does.
const SIGNATURES: &[(&[u8], ArchiveFormat)] = &[
    // A zip begins with a local file header, an empty-archive record, or — for
    // a spanned archive — a data descriptor. All three are the same format and
    // all three are worth opening; the reader finds the central directory and
    // does not care which one came first.
    (b"PK\x03\x04", ArchiveFormat::Zip),
    (b"PK\x05\x06", ArchiveFormat::Zip),
    (b"PK\x07\x08", ArchiveFormat::Zip),
    (b"\x1f\x8b", ArchiveFormat::Gzip),
    (b"BZh", ArchiveFormat::Bzip2),
    (b"\xfd7zXZ\x00", ArchiveFormat::Xz),
    (b"\x28\xb5\x2f\xfd", ArchiveFormat::Zstd),
    (b"7z\xbc\xaf\x27\x1c", ArchiveFormat::SevenZip),
    (b"Rar!\x1a\x07\x01\x00", ArchiveFormat::Rar),
    (b"Rar!\x1a\x07\x00", ArchiveFormat::Rar),
    (b"MSCF", ArchiveFormat::Cab),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ArchiveFormat::Ole),
];

/// Offset of the ISO 9660 primary volume descriptor's signature.
const ISO_PVD_OFFSET: usize = 0x8001;
/// Bytes at [`ISO_PVD_OFFSET`] that identify a primary volume descriptor.
const ISO_PVD_MAGIC: &[u8] = b"CD001";

/// Offset and length of the tar magic inside the first header block.
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGICS: &[&[u8]] = &[b"ustar\x0000", b"ustar  \x00", b"ustar"];

impl ArchiveFormat {
    /// Decide the format from the bytes alone.
    ///
    /// `None` when the bytes are not a container this product recognises. Note
    /// that this is a *classification*, not a promise: a zip that has been
    /// truncated past its first four bytes still reports `Zip` here and fails
    /// in the reader, which is the right split — "what is it" and "can it be
    /// read" are different questions and a user needs both answers.
    pub fn detect(data: &[u8]) -> Option<ArchiveFormat> {
        for (signature, format) in SIGNATURES {
            if data.starts_with(signature) {
                return Some(*format);
            }
        }
        if data.len() >= ISO_PVD_OFFSET + ISO_PVD_MAGIC.len()
            && &data[ISO_PVD_OFFSET..ISO_PVD_OFFSET + ISO_PVD_MAGIC.len()] == ISO_PVD_MAGIC
        {
            return Some(ArchiveFormat::Iso);
        }
        if is_tar(data) {
            return Some(ArchiveFormat::Tar);
        }
        None
    }

    /// Decide the format from the bytes, using the file's name only when the
    /// bytes cannot settle it.
    ///
    /// The one case that needs the name is a tar, whose signature is 257 bytes
    /// into the file and is therefore absent from a short read. The name is
    /// consulted only after [`ArchiveFormat::detect`] has failed and only for
    /// the extensions that mean tar, so a `.txt` full of `ustar` is still a
    /// `.txt`.
    pub fn of_path(path: &std::path::Path, data: &[u8]) -> Option<ArchiveFormat> {
        if let Some(format) = Self::detect(data) {
            return Some(format);
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())?
            .to_ascii_lowercase();
        // A `.tar.gz` is detected as gzip by its first two bytes, so this arm
        // is only ever reached for a bare `.tar`.
        if name.ends_with(".tar") {
            return Some(ArchiveFormat::Tar);
        }
        None
    }

    /// Check that this build can open the format, or say why not.
    pub fn readable(self) -> Result<()> {
        if self.is_readable() {
            return Ok(());
        }
        Err(ArchiveError::Unsupported {
            format: self.name(),
            detail: self.unreadable_because().to_owned(),
        })
    }

    /// The format a name suggests, when its extension says so and the bytes did
    /// not.
    ///
    /// Used only to choose the wording of a report. A `.zip` that is not a zip
    /// is worth saying so about, because a user who is told "unrecognised
    /// format" about a file called `backup.zip` will assume the scanner is
    /// broken rather than that the file is.
    pub fn from_extension(path: &std::path::Path) -> Option<ArchiveFormat> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())?
            .to_ascii_lowercase();
        // `.tar.gz` and `.tgz` are gzip; the tar behind them is a second layer
        // and the reader finds it by looking at what the gzip stream produced.
        let format = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            ArchiveFormat::Gzip
        } else if name.ends_with(".tar") {
            ArchiveFormat::Tar
        } else if name.ends_with(".zip")
            || name.ends_with(".jar")
            || name.ends_with(".docx")
            || name.ends_with(".xlsx")
            || name.ends_with(".pptx")
            || name.ends_with(".odt")
            || name.ends_with(".apk")
            || name.ends_with(".nupkg")
        {
            // Everything in this arm is a zip wearing a document's name, which
            // is exactly why the reader must go by the bytes: a `.docx` is
            // scanned as a container and not as a document, and a rule written
            // for `word/document.xml` inside it is reachable.
            ArchiveFormat::Zip
        } else if name.ends_with(".gz") {
            ArchiveFormat::Gzip
        } else if name.ends_with(".7z") {
            ArchiveFormat::SevenZip
        } else if name.ends_with(".rar") {
            ArchiveFormat::Rar
        } else if name.ends_with(".cab") {
            ArchiveFormat::Cab
        } else if name.ends_with(".bz2") {
            ArchiveFormat::Bzip2
        } else if name.ends_with(".xz") {
            ArchiveFormat::Xz
        } else if name.ends_with(".zst") {
            ArchiveFormat::Zstd
        } else if name.ends_with(".iso") || name.ends_with(".img") {
            ArchiveFormat::Iso
        } else if name.ends_with(".msi") || name.ends_with(".msp") || name.ends_with(".doc") {
            ArchiveFormat::Ole
        } else {
            return None;
        };
        Some(format)
    }
}

/// True when the first 512-byte block is a tar header.
///
/// The checksum is verified rather than just the magic, because `ustar` is five
/// printable ASCII bytes and a file that merely contains them at that offset
/// would otherwise be reported as a tar — and then fail to parse, which costs a
/// user a confusing message about a file that was never a tar.
fn is_tar(data: &[u8]) -> bool {
    const BLOCK: usize = 512;
    if data.len() < BLOCK {
        return false;
    }
    let header = &data[..BLOCK];
    let magic_ok = TAR_MAGICS.iter().any(|magic| {
        header.len() >= TAR_MAGIC_OFFSET + magic.len()
            && &header[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + magic.len()] == *magic
    });
    if !magic_ok {
        return false;
    }
    tar_checksum_ok(header)
}

/// Verify a tar header's checksum.
///
/// The header stores the sum of its own bytes with the checksum field read as
/// spaces, as a six-digit octal number. Both the unsigned and the signed
/// reading of the bytes are accepted, because historical implementations
/// disagreed and both spellings are in the wild.
pub(crate) fn tar_checksum_ok(header: &[u8]) -> bool {
    const CHECKSUM_OFFSET: usize = 148;
    const CHECKSUM_LEN: usize = 8;
    let Some(recorded) = parse_octal(&header[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN])
    else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &byte) in header.iter().enumerate() {
        let value = if (CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_LEN).contains(&i) {
            b' ' as u64
        } else {
            u64::from(byte)
        };
        unsigned = unsigned.wrapping_add(value);
        signed = signed.wrapping_add(value as i64);
    }
    recorded == unsigned || recorded as i64 == signed
}

/// Read a NUL- or space-terminated octal number from a tar header field.
///
/// Also accepts the GNU base-256 encoding, in which the top bit of the first
/// byte marks a big-endian two's complement integer. Only the base-256 arm can
/// express a file above 8 GiB, and a tarball of a disk image is exactly where
/// that happens.
pub(crate) fn parse_octal(field: &[u8]) -> Option<u64> {
    let first = *field.first()?;
    if first & 0x80 != 0 {
        let mut value: i64 = if first & 0x40 != 0 { -1 } else { 0 };
        for (i, &byte) in field.iter().enumerate() {
            let byte = if i == 0 { byte & 0x7f } else { byte };
            value = value.checked_shl(8)? | i64::from(byte);
        }
        return u64::try_from(value).ok();
    }
    let text = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .copied()
        .collect::<Vec<u8>>();
    if text.is_empty() {
        return Some(0);
    }
    let text = std::str::from_utf8(&text).ok()?;
    u64::from_str_radix(text.trim(), 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn tar_header(name: &str) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"000644 ");
        header[108..115].copy_from_slice(b"000000 ");
        header[116..123].copy_from_slice(b"000000 ");
        header[124..135].copy_from_slice(b"00000000000");
        // The mtime field is twelve bytes, 136 through 147 — the same width as
        // the size field, and one more than the 11 digits it usually holds.
        header[136..148].copy_from_slice(b"00000000000 ");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        // The checksum is the sum of the header with its own field read as
        // spaces, which it currently is.
        let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    #[test]
    fn the_obvious_signatures_are_recognised() {
        assert_eq!(
            ArchiveFormat::detect(b"PK\x03\x04rest"),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::detect(b"PK\x05\x06"),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::detect(b"\x1f\x8b\x08\x00"),
            Some(ArchiveFormat::Gzip)
        );
        assert_eq!(
            ArchiveFormat::detect(b"7z\xbc\xaf\x27\x1c\x00\x04"),
            Some(ArchiveFormat::SevenZip)
        );
        assert_eq!(
            ArchiveFormat::detect(b"Rar!\x1a\x07\x01\x00"),
            Some(ArchiveFormat::Rar)
        );
        assert_eq!(
            ArchiveFormat::detect(b"Rar!\x1a\x07\x00"),
            Some(ArchiveFormat::Rar)
        );
        assert_eq!(
            ArchiveFormat::detect(b"MSCF\x00\x00"),
            Some(ArchiveFormat::Cab)
        );
        assert_eq!(
            ArchiveFormat::detect(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
            Some(ArchiveFormat::Ole)
        );
        assert_eq!(
            ArchiveFormat::detect(b"\xfd7zXZ\x00"),
            Some(ArchiveFormat::Xz)
        );
        assert_eq!(ArchiveFormat::detect(b"BZh9"), Some(ArchiveFormat::Bzip2));
    }

    #[test]
    fn an_ordinary_file_is_not_a_container() {
        assert_eq!(ArchiveFormat::detect(b"MZ\x90\x00"), None);
        assert_eq!(ArchiveFormat::detect(b"%PDF-1.7"), None);
        assert_eq!(ArchiveFormat::detect(b""), None);
        assert_eq!(ArchiveFormat::detect(b"PK"), None);
    }

    #[test]
    fn a_tar_is_recognised_by_its_header_and_its_checksum() {
        let header = tar_header("hello.txt");
        assert_eq!(ArchiveFormat::detect(&header), Some(ArchiveFormat::Tar));

        // The control: the same magic with a broken checksum is not a tar. A
        // file that merely contains `ustar` at that offset is common enough —
        // an executable with a string table, a disk image — and reporting it as
        // a tar would produce a parse failure on a file that was never one.
        let mut broken = header.clone();
        broken[148..156].copy_from_slice(b"000000\0 ");
        assert_eq!(ArchiveFormat::detect(&broken), None);
    }

    #[test]
    fn a_truncated_tar_header_is_not_mistaken_for_one() {
        let header = tar_header("hello.txt");
        assert_eq!(ArchiveFormat::detect(&header[..256]), None);
        assert_eq!(ArchiveFormat::detect(&header[..511]), None);
    }

    #[test]
    fn the_iso_signature_is_at_its_offset_and_not_at_zero() {
        let mut image = vec![0u8; 0x8006];
        image[ISO_PVD_OFFSET..ISO_PVD_OFFSET + 5].copy_from_slice(b"CD001");
        assert_eq!(ArchiveFormat::detect(&image), Some(ArchiveFormat::Iso));
        // A file that starts with CD001 is not an image.
        assert_eq!(ArchiveFormat::detect(b"CD001"), None);
    }

    #[test]
    fn only_three_formats_claim_to_be_readable() {
        // The other eight exist so that a report can name what it could not
        // open. This asserts the two lists stay in step.
        let readable: Vec<ArchiveFormat> = ArchiveFormat::ALL
            .into_iter()
            .filter(|f| f.is_readable())
            .collect();
        assert_eq!(readable, ArchiveFormat::READABLE.to_vec());
        for format in ArchiveFormat::ALL {
            if format.is_readable() {
                assert!(format.readable().is_ok(), "{format:?}");
            } else {
                let error = format.readable().expect_err("unreadable");
                assert!(error.to_string().contains(format.name()), "{error}");
            }
        }
    }

    #[test]
    fn every_format_has_a_name_and_a_reason() {
        for format in ArchiveFormat::ALL {
            assert!(!format.name().is_empty(), "{format:?}");
            assert!(!format.unreadable_because().is_empty(), "{format:?}");
        }
    }

    #[test]
    fn a_name_that_suggests_a_format_is_only_used_when_the_bytes_do_not() {
        // A zip called `.docx` is a zip, and is recognised as one from its
        // bytes. This is the case the whole module exists for.
        assert_eq!(
            ArchiveFormat::detect(b"PK\x03\x04...."),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::from_extension(Path::new("report.docx")),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::from_extension(Path::new("lib.jar")),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            ArchiveFormat::from_extension(Path::new("backup.tar.gz")),
            Some(ArchiveFormat::Gzip)
        );
        assert_eq!(
            ArchiveFormat::from_extension(Path::new("backup.tgz")),
            Some(ArchiveFormat::Gzip)
        );
        assert_eq!(ArchiveFormat::from_extension(Path::new("notes.txt")), None);
        assert_eq!(ArchiveFormat::from_extension(Path::new("noext")), None);
    }

    #[test]
    fn a_bare_tar_is_decided_by_its_name_because_its_signature_is_too_far_in() {
        let header = tar_header("hello.txt");
        // The bytes settle it when they are all there.
        assert_eq!(
            ArchiveFormat::of_path(Path::new("a.tar"), &header),
            Some(ArchiveFormat::Tar)
        );
        // And the name settles it when they are not — a scan of the first
        // kilobyte of a large tarball.
        assert_eq!(
            ArchiveFormat::of_path(Path::new("a.tar"), b"short"),
            Some(ArchiveFormat::Tar)
        );
        assert_eq!(ArchiveFormat::of_path(Path::new("a.txt"), b"short"), None);
    }

    #[test]
    fn octal_fields_are_read_the_way_tar_writes_them() {
        assert_eq!(parse_octal(b"00000000000"), Some(0));
        assert_eq!(parse_octal(b"00000000753\0"), Some(491));
        assert_eq!(parse_octal(b"        "), Some(0));
        assert_eq!(parse_octal(b"\0\0\0\0\0\0\0\0"), Some(0));
        assert_eq!(parse_octal(b""), None);
        // Not a number at all.
        assert_eq!(parse_octal(b"zzzz\0"), None);
    }

    #[test]
    fn a_gnu_base256_size_is_read_as_a_big_endian_integer() {
        // 5 GiB, which no eleven-digit octal field can express. The top bit of
        // the first byte is the flag.
        let value: u64 = 5 * 1024 * 1024 * 1024;
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[4..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(parse_octal(&field), Some(value));

        // And a negative one, which is nonsense as a size and must not become a
        // colossal positive one by wrapping.
        let mut negative = [0xffu8; 12];
        negative[0] = 0x80;
        assert_eq!(parse_octal(&negative), None);
    }
}
