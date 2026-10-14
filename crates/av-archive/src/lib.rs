//! Container readers: what is inside a file, and what could not be read.
//!
//! # Why this is a crate and not a stage of the scanner
//!
//! The scan engine's contract is "bytes in, verdict out". An archive reader is
//! the opposite shape: it turns one buffer into several, and the several are
//! what get scanned. Putting that inside the engine would make every rule, every
//! heuristic and the trust layer each need to know about nesting, and would put
//! the one place in the product where untrusted data causes a large allocation
//! behind the same door as the scoring model, a door that gets opened for
//! reasons that have nothing to do with decompression.
//!
//! So this crate owns three things and nothing else:
//!
//! * **What the file is.** [`ArchiveFormat`] names eleven container formats
//!   from their magic bytes. Three of them (zip, gzip, tar) have readers here.
//!   The other eight are named so that a report can say *what* it could not
//!   open, because "unrecognised" and "recognised and unreadable" are different
//!   sentences and only the second one is true.
//! * **What is inside it.** [`Container`] is an enum over the three readers,
//!   with one shape: list the members, then read them one at a time.
//! * **How much of it may be produced.** [`ExpansionBudget`] is the ceiling
//!   that makes a zip bomb a refusal rather than a denial of service.
//!
//! # The one dependency this workspace takes for hostile input
//!
//! DEFLATE is decompressed by `flate2` over `miniz_oxide`, pure Rust with no
//! `unsafe` in its decoding path. Writing it here was considered and rejected:
//! a hand-rolled inflate would be several hundred lines of bit-twiddling over
//! bytes chosen by whoever wrote the archive, reachable before any rule has
//! judged the file, and it would be this product's attack surface alone.
//!
//! Everything else in this crate is written here: the zip central-directory
//! walk, the gzip member chain, the tar header chain with its GNU and PAX
//! extensions, the name decoding and sanitising, and every ceiling. What the
//! rule engine does is not delegated either (see `av-rules`), and the two facts
//! are separate: this is a decompressor, not a detector.
//!
//! # Three rules this crate keeps
//!
//! **A member that was not read is never reported as a member that was.** Every
//! way a member can go unexamined (encrypted, an unreadable method, past the
//! budget, nested too deeply, malformed) produces an
//! [`av_core::ArchiveSkip`] with a reason, and
//! [`av_core::ArchiveSummary::is_complete`] is false. A caller that wants to
//! refuse to call a partially examined archive clean asks that question; the
//! scan engine does.
//!
//! **Nothing is written to disk.** A member name can spell a path that escapes
//! the archive, and the defence is not to extract at all. Names are strings in
//! reports, and [`name::sanitize`] is what makes them safe strings.
//!
//! **A ceiling is enforced while the bytes are produced, not after.** Every
//! read goes through [`ExpansionBudget`], and the decompressor writes into a
//! buffer whose capacity the budget sets. The largest a hostile archive can make
//! this process allocate is one byte past the ceiling, the byte that proves the
//! ceiling was reached.
//!
//! # What it costs
//!
//! [`Extracted`] owns its bytes, so reading a member copies it. For zip that
//! copy is unavoidable (the bytes did not exist before the decompressor made
//! them); for tar and gzip it is not, and the two pay a `memcpy` per member
//! that a scratch buffer would avoid. It is bounded by the same ceiling that
//! bounds everything else, it is one buffer at a time, and the alternative,
//! lending out a slice of the container and taking `&mut self` to produce it,
//! makes every caller's loop a borrow-checker puzzle. If it ever shows up in a
//! profile, the fix is a reused buffer inside [`Container`] and it is contained
//! to this crate.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod budget;
pub mod error;
pub mod format;
pub mod gzip;
pub mod inflate;
pub mod name;
pub mod tar;
pub mod zip;

#[doc(hidden)]
pub mod testing;

pub use budget::ExpansionBudget;
pub use error::ArchiveError;
pub use format::ArchiveFormat;
pub use gzip::{GzipArchive, GzipMember};
pub use tar::{TarArchive, TarEntry};
pub use zip::{ZipArchive, ZipEntry};

/// Convenience alias for results from this crate.
pub type Result<T, E = ArchiveError> = std::result::Result<T, E>;

/// One member's content, produced and ready to scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The member's name, sanitized for display.
    pub name: String,
    /// The member's bytes.
    pub bytes: Vec<u8>,
    /// True when the container's own integrity check for this member passed,
    /// or when the format has none to check.
    ///
    /// False means the bytes are real but are not the bytes the container's
    /// directory describes — the file was damaged, or was altered after it was
    /// built. A scan still reads them, because they are what is on the disk,
    /// and the caller records the mismatch as a note rather than a verdict.
    pub verified: bool,
}

/// What a member is, before any of it has been produced.
///
/// This is what a caller decides from: a member that is encrypted, or that uses
/// a method this build has no reader for, or that is larger than the scan will
/// expand, is a member the caller records as skipped *without* the cost of
/// trying to read it. The three facts are separate fields rather than one
/// reason because they are decided at different times and a caller's response
/// to each is different — but all three mean the same thing about the contents,
/// which is that nothing is known about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    /// The member's name, sanitized for display.
    pub name: String,
    /// The size the container declares for the member, in bytes. Zero when the
    /// container does not say, which gzip never does.
    pub declared_size: u64,
    /// True when the member is password-protected.
    pub encrypted: bool,
    /// The member's compression method, when this build has no reader for it.
    pub unreadable_method: Option<String>,
}

impl MemberInfo {
    /// True when this build could produce the member's content.
    ///
    /// Not the only question a caller asks — the declared size and the budget
    /// matter too — but it is the one that is a property of the member rather
    /// than of the scan.
    pub const fn is_readable(&self) -> bool {
        !self.encrypted && self.unreadable_method.is_none()
    }
}

/// An open container.
///
/// The three readers have quite different shapes underneath — a random-access
/// directory, a decompressed chain, a linear header walk — and this enum is
/// what lets a caller treat them as one thing: list the members, then read them
/// by index.
#[derive(Debug)]
pub enum Container<'a> {
    /// A zip, including everything that is one: `.jar`, `.docx`, `.apk`,
    /// `.nupkg`.
    Zip(ZipArchive<'a>),
    /// A gzip stream, which may hold one member or several concatenated.
    Gzip(GzipArchive),
    /// A tar, including the extensions GNU and PAX add to it.
    Tar(TarArchive<'a>),
}

impl<'a> Container<'a> {
    /// Open `data` as a container, if it is one this build can read.
    ///
    /// `Ok(None)` when the bytes are not a container at all — most files are
    /// not, and this is not an error. `Err` when they are a container this
    /// build cannot open, or one that is malformed; both are things a report
    /// must say rather than pass over.
    ///
    /// `budget` is spent by the formats that must produce bytes to be
    /// understood. Only gzip does: a zip's directory and a tar's headers are
    /// readable as they lie. See [`gzip`] for why.
    pub fn open(data: &'a [u8], budget: &mut ExpansionBudget) -> Result<Option<Self>> {
        let Some(format) = ArchiveFormat::detect(data) else {
            return Ok(None);
        };
        format.readable()?;
        match format {
            ArchiveFormat::Zip => Ok(Some(Container::Zip(ZipArchive::parse(data)?))),
            ArchiveFormat::Gzip => Ok(Some(Container::Gzip(GzipArchive::parse(data, budget)?))),
            ArchiveFormat::Tar => Ok(Some(Container::Tar(TarArchive::parse(data)?))),
            // `readable()` above has already refused anything else, so this arm
            // is unreachable — and it is written as an error rather than a
            // panic because "unreachable" is a claim that stops being true the
            // first time somebody adds a format to one list and not the other.
            other => Err(ArchiveError::Unsupported {
                format: other.name(),
                detail: other.unreadable_because().to_owned(),
            }),
        }
    }

    /// The format this container is.
    pub const fn format(&self) -> ArchiveFormat {
        match self {
            Container::Zip(_) => ArchiveFormat::Zip,
            Container::Gzip(_) => ArchiveFormat::Gzip,
            Container::Tar(_) => ArchiveFormat::Tar,
        }
    }

    /// Every member a scan would consider.
    ///
    /// Directories, links and the pseudo-members that carry long names are not
    /// members and are absent. Every entry of the returned list can be passed
    /// to [`Container::read`], though not every one will succeed — see
    /// [`MemberInfo`].
    pub fn members(&self) -> Vec<MemberInfo> {
        match self {
            Container::Zip(archive) => archive.members(),
            Container::Gzip(archive) => archive.members(),
            Container::Tar(archive) => archive.members(),
        }
    }

    /// How many members the container declares, without building the list.
    ///
    /// The same number [`Container::members`] would return the length of, and
    /// deliberately so: `declared` in a report is "12 of 14 members examined",
    /// and the 14 a user reads is the number of files in the archive, not the
    /// number of files plus the directory entries the tool that built it
    /// happened to write. A count that included those would make almost every
    /// real archive report a member it never examined, and a scanner that cries
    /// wolf about ordinary zips is one whose warnings get ignored.
    pub fn declared_member_count(&self) -> u32 {
        let count = match self {
            Container::Zip(archive) => archive
                .entries()
                .iter()
                .filter(|entry| !entry.directory)
                .count(),
            Container::Gzip(archive) => archive.members_parsed().len(),
            Container::Tar(archive) => archive
                .entries()
                .iter()
                .filter(|entry| entry.has_content())
                .count(),
        };
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Read the member at `index`, which indexes the list
    /// [`Container::members`] returns.
    pub fn read(&self, index: usize, budget: &mut ExpansionBudget) -> Result<Extracted> {
        match self {
            Container::Zip(archive) => archive.read(self.zip_index(index)?, budget),
            Container::Gzip(archive) => archive.read(index, budget),
            Container::Tar(archive) => archive.read(self.tar_index(index)?, budget),
        }
    }

    /// Translate an index into `members()` back into one into the zip's
    /// `entries()`, which includes the directories `members()` filtered out.
    fn zip_index(&self, index: usize) -> Result<usize> {
        let Container::Zip(archive) = self else {
            return Ok(index);
        };
        archive
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.directory)
            .nth(index)
            .map(|(position, _)| position)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "zip",
                detail: format!("there is no member {index} in this archive"),
            })
    }

    /// The same, for a tar's non-file entries.
    fn tar_index(&self, index: usize) -> Result<usize> {
        let Container::Tar(archive) = self else {
            return Ok(index);
        };
        archive
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.has_content())
            .nth(index)
            .map(|(position, _)| position)
            .ok_or_else(|| ArchiveError::Malformed {
                format: "tar",
                detail: format!("there is no member {index} in this archive"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{gzip, tar, zip_deflate, zip_store};

    fn open(data: &[u8]) -> Option<Container<'_>> {
        Container::open(data, &mut ExpansionBudget::default()).expect("opens")
    }

    #[test]
    fn a_file_that_is_not_a_container_is_not_an_error() {
        // The common case by a wide margin: most files on a disk are not
        // archives, and a caller must be able to ask the question without
        // handling a failure for the ordinary answer.
        assert!(open(b"MZ\x90\x00 an executable").is_none());
        assert!(open(b"%PDF-1.7").is_none());
        assert!(open(b"").is_none());
    }

    #[test]
    fn a_recognised_container_this_build_cannot_open_is_an_error_with_a_reason() {
        // Not `None`, which would read as "not a container" and let a caller
        // conclude the file was scanned as a single file. It is a container, it
        // was not opened, and the reason names what is missing.
        let seven_zip = b"7z\xbc\xaf\x27\x1c\x00\x04";
        let error = Container::open(seven_zip, &mut ExpansionBudget::default())
            .expect_err("recognised and unreadable");
        assert!(error.skip_reason().leaves_contents_unknown());
        let text = error.to_string();
        assert!(text.contains("7z"), "{text}");
        assert!(text.contains("LZMA"), "{text}");
    }

    #[test]
    fn each_format_lists_and_reads_the_same_way() {
        // The contract the enum exists for: three quite different readers, one
        // shape at the call site.
        let zipped = zip_deflate(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let tarred = tar(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let gzipped = gzip(Some("a.txt"), b"alpha");

        for (data, expected) in [
            (zipped.as_slice(), vec!["a.txt", "b.txt"]),
            (tarred.as_slice(), vec!["a.txt", "b.txt"]),
            (gzipped.as_slice(), vec!["a.txt"]),
        ] {
            let container = open(data).expect("a container");
            let members = container.members();
            let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
            assert_eq!(names, expected, "{:?}", container.format());
            assert!(members.iter().all(|m| m.is_readable()));

            let extracted = container
                .read(0, &mut ExpansionBudget::default())
                .expect("reads");
            assert_eq!(extracted.name, expected[0]);
            assert_eq!(extracted.bytes, b"alpha");
            assert!(extracted.verified);
        }
    }

    #[test]
    fn an_index_past_the_last_member_is_refused_for_every_format() {
        let zipped = zip_store(&[("a.txt", b"a")]);
        let tarred = tar(&[("a.txt", b"a")]);
        let gzipped = gzip(None, b"a");
        for data in [zipped.as_slice(), tarred.as_slice(), gzipped.as_slice()] {
            let container = open(data).expect("a container");
            assert!(container.members().len() == 1);
            let error = container
                .read(1, &mut ExpansionBudget::default())
                .expect_err("no second member");
            assert!(error.to_string().contains("no member 1"), "{error}");
        }
    }

    #[test]
    fn a_zip_index_skips_the_directories_the_report_does_not_count() {
        // `members()` filters directories, so an index into it is not an index
        // into the zip's entries. Getting this wrong would read a directory as
        // the file after it, which is a scan reporting on the wrong member.
        let members = [
            testing::FixtureMember::stored("dir", b"").as_directory(),
            testing::FixtureMember::stored("dir/a.txt", b"alpha"),
            testing::FixtureMember::stored("dir/b.txt", b"beta"),
        ];
        let data = testing::zip_from_members(&members, &[]);
        let container = open(&data).expect("a container");
        assert_eq!(container.members().len(), 2);
        assert_eq!(
            container
                .read(0, &mut ExpansionBudget::default())
                .expect("reads")
                .bytes,
            b"alpha"
        );
        assert_eq!(
            container
                .read(1, &mut ExpansionBudget::default())
                .expect("reads")
                .bytes,
            b"beta"
        );
    }

    #[test]
    fn a_tar_index_skips_the_entries_that_are_not_files() {
        // A link is an entry with no content, so `members()` leaves it out and
        // an index into `members()` is not an index into `entries()`. Getting
        // this wrong would read the link and report its target path as if it
        // were the member after it.
        let mut data = tar(&[("link", b"")]);
        // Type flag 2 is a symbolic link. The flag sits inside the checksummed
        // region, so the sum is redone.
        data[156] = b'2';
        data[148..156].copy_from_slice(b"        ");
        let sum: u64 = data[..512].iter().map(|&b| u64::from(b)).sum();
        data[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        // The fixture archive ends with two zero blocks — the end marker.
        // Replace them with a real second member and a fresh end marker: the
        // link's header, then b.txt's header and data, then the marker.
        let mut second = tar(&[("b.txt", b"beta")]);
        second.truncate(1024);
        data.truncate(512); // the link's header, and nothing else
        data.extend_from_slice(&second);
        data.extend_from_slice(&[0u8; 1024]);

        let container = open(&data).expect("a container");
        let members = container.members();
        assert_eq!(members.len(), 1, "{members:?}");
        assert_eq!(members[0].name, "b.txt");
        assert_eq!(
            container
                .read(0, &mut ExpansionBudget::default())
                .expect("reads")
                .bytes,
            b"beta"
        );
    }

    #[test]
    fn the_declared_count_is_the_member_count_and_not_the_entry_count() {
        // A directory entry is structure, not a member. Counting it would make
        // the report read "1 of 2 members examined" for an archive where
        // everything was looked at — and a scan that flags ordinary archives is
        // one whose warnings stop being read.
        let members = [
            testing::FixtureMember::stored("dir", b"").as_directory(),
            testing::FixtureMember::stored("dir/a.txt", b"a"),
        ];
        let data = testing::zip_from_members(&members, &[]);
        let container = open(&data).expect("a container");
        assert_eq!(container.declared_member_count(), 1);
        assert_eq!(container.members().len(), 1);
    }

    #[test]
    fn the_format_of_an_open_container_is_the_one_it_was_opened_as() {
        assert_eq!(
            open(&zip_store(&[("a", b"a")])).expect("zip").format(),
            ArchiveFormat::Zip
        );
        assert_eq!(
            open(&gzip(None, b"a")).expect("gzip").format(),
            ArchiveFormat::Gzip
        );
        assert_eq!(
            open(&tar(&[("a", b"a")])).expect("tar").format(),
            ArchiveFormat::Tar
        );
    }

    #[test]
    fn a_malformed_container_of_a_readable_format_is_an_error() {
        // A zip signature with nothing behind it. The format is recognised, so
        // the answer is not `None` — the file claimed to be a zip and is not a
        // readable one, which is a fact a report has to carry.
        let error = Container::open(
            b"PK\x03\x04 and then nothing",
            &mut ExpansionBudget::default(),
        )
        .expect_err("malformed");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }
}
