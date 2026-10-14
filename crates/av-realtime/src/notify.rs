//! Reading the buffer `ReadDirectoryChangesW` fills.
//!
//! # What the kernel hands back
//!
//! The buffer is a run of `FILE_NOTIFY_INFORMATION` records. Each is three
//! `DWORD`s followed by a name:
//!
//! ```text
//! offset 0    NextEntryOffset   bytes from the start of *this* record to the next; 0 = last
//! offset 4    Action            a FILE_ACTION_* code
//! offset 8    FileNameLength    length of the name in BYTES
//! offset 12   FileName          UTF-16 code units, NOT NUL-terminated
//! ```
//!
//! Three details are the whole difficulty, and each is a way to write a parser
//! that works on the machine it was tested on and produces a wrong path
//! elsewhere:
//!
//! * **The name is not terminated and its length is in bytes.** A reader that
//!   scans for a NUL walks off the end of its record and into the next one; a
//!   reader that treats `FileNameLength` as a character count reads half a name.
//!   For a plain BMP name the two coincide, which is why the bug survives a
//!   casual test and shows up on the first file with an emoji in its name.
//! * **Records are walked by offset, not by size.** `NextEntryOffset` is
//!   relative to the record it sits in, so the walk is `offset += next` and
//!   never `offset += 12 + length`. The padding that keeps the next record
//!   `DWORD`-aligned is included in the offset and in nothing else, so a parser
//!   that recomputes the step reads the padding as a header.
//! * **A name is UTF-16 and a non-BMP character is two code units.** Casting
//!   each `u16` to a `char` — the obvious way to avoid thinking about it — turns
//!   one character into two wrong ones, and the path then names a file that does
//!   not exist. [`String::from_utf16`] is what resolves a surrogate pair, and
//!   `a_non_bmp_character_survives_as_one_character` is what keeps it that way.
//!
//! # Why this is a free function over `&[u8]`
//!
//! Because the buffer is the part that can be wrong, and none of the ways it can
//! be wrong need a filesystem, a handle or Windows to reproduce. [`parse`] takes
//! bytes and returns records or an error, so every malformed case is a unit test
//! instead of a machine-dependent integration test. It also reads its fields
//! byte by byte rather than casting the buffer to `*const FILE_NOTIFY_INFORMATION`,
//! which is why it has no alignment requirement to be lucky about.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The fixed part of a record: two offsets and a length, three `DWORD`s wide.
///
/// Not a `size_of` of anything, because the structure it describes ends in a
/// variable-length array. The next record's offset carries any padding.
pub const RECORD_HEADER_BYTES: usize = 12;

/// Where the name begins inside a record.
pub const RECORD_NAME_OFFSET: usize = RECORD_HEADER_BYTES;

/// `FILE_ACTION_ADDED`. The file did not exist and now does.
const ACTION_ADDED: u32 = 1;
/// `FILE_ACTION_REMOVED`. The file existed and now does not.
const ACTION_REMOVED: u32 = 2;
/// `FILE_ACTION_MODIFIED`. The file's contents, size or attributes changed.
const ACTION_MODIFIED: u32 = 3;
/// `FILE_ACTION_RENAMED_OLD_NAME`. The first half of a rename pair.
const ACTION_RENAMED_OLD_NAME: u32 = 4;
/// `FILE_ACTION_RENAMED_NEW_NAME`. The second half of a rename pair, and the
/// half that names a file which is now on disk under a new name.
const ACTION_RENAMED_NEW_NAME: u32 = 5;

/// What happened to the file a record names.
///
/// The codes are written as literals with their `FILE_ACTION_*` names above
/// rather than taken from the `windows` crate, because this type is part of the
/// platform-independent half of the crate: the parser's tests run wherever Rust
/// does, and importing a Windows binding to spell `1` would make the pure half
/// depend on the impure one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    /// The file was created.
    Added,
    /// The file was deleted.
    Removed,
    /// The file was written to, resized, or had its attributes changed.
    Modified,
    /// The file a rename moved *away from*. There is no longer a file here.
    ///
    /// Reported only when the kernel saw both ends of the rename, which means
    /// the source was inside the watched tree. A file moved *out* of a watched
    /// tree has no destination this watch can see, and a file moved *in* has no
    /// source — that one arrives as [`FileAction::Added`]. See the module
    /// documentation of `crate::filter` for the two measurements behind that.
    RenamedOldName,
    /// The file a rename moved *to*. This is a file that has just appeared.
    ///
    /// The mate of [`FileAction::RenamedOldName`], and it arrives in the same
    /// batch as it, so a reader that stops at the first record it recognises can
    /// lose this one.
    RenamedNewName,
    /// An action code this build does not know.
    ///
    /// Carried rather than dropped so that a caller can count it and notice that
    /// the system has learned a trick this crate has not. It is deliberately not
    /// treated as a scan candidate: every action code Microsoft has assigned is
    /// one of the five above, so a sixth is not evidence of a new file, and
    /// scanning on it would mean guessing what it means.
    Unknown(u32),
}

impl FileAction {
    /// Classify an action code from a notification record.
    pub const fn from_code(code: u32) -> Self {
        match code {
            ACTION_ADDED => FileAction::Added,
            ACTION_REMOVED => FileAction::Removed,
            ACTION_MODIFIED => FileAction::Modified,
            ACTION_RENAMED_OLD_NAME => FileAction::RenamedOldName,
            ACTION_RENAMED_NEW_NAME => FileAction::RenamedNewName,
            other => FileAction::Unknown(other),
        }
    }

    /// The `FILE_ACTION_*` code this came from.
    ///
    /// Round-trips [`FileAction::from_code`] for every value including the
    /// unknown ones, so a record can be logged in the vocabulary the
    /// documentation for this API is written in.
    pub const fn code(self) -> u32 {
        match self {
            FileAction::Added => ACTION_ADDED,
            FileAction::Removed => ACTION_REMOVED,
            FileAction::Modified => ACTION_MODIFIED,
            FileAction::RenamedOldName => ACTION_RENAMED_OLD_NAME,
            FileAction::RenamedNewName => ACTION_RENAMED_NEW_NAME,
            FileAction::Unknown(code) => code,
        }
    }

    /// The word used in logs and in the report.
    pub const fn as_str(self) -> &'static str {
        match self {
            FileAction::Added => "added",
            FileAction::Removed => "removed",
            FileAction::Modified => "modified",
            FileAction::RenamedOldName => "renamed_old_name",
            FileAction::RenamedNewName => "renamed_new_name",
            FileAction::Unknown(_) => "unknown",
        }
    }
}

/// One record, as it came out of the buffer.
///
/// The name is relative to whichever directory was being watched — the kernel
/// reports `sub\file.exe`, not the full path — and it is carried as a string
/// because the parser has no idea what the root is. [`Change`] is the same
/// record with the root joined on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyRecord {
    /// What happened.
    pub action: FileAction,
    /// The name, relative to the watched root, with backslash separators.
    pub name: String,
}

/// A record with the watched root resolved against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// What happened.
    pub action: FileAction,
    /// The full path, root included.
    pub path: PathBuf,
}

impl Change {
    /// Resolve a record against the root it was reported under.
    ///
    /// A plain join, because the name the kernel reports is relative and never
    /// leading-separated: `C:\Users\me\Downloads` plus `sub\a.txt` is
    /// `C:\Users\me\Downloads\sub\a.txt`. Prefixing a separator "to be safe"
    /// would turn an absolute name — which the kernel does not send, but a
    /// malformed buffer could — into a doubled one.
    pub fn resolve(root: &Path, record: NotifyRecord) -> Self {
        Self {
            action: record.action,
            path: root.join(record.name),
        }
    }

    /// The file name alone, when there is one.
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().and_then(|n| n.to_str())
    }
}

/// What one completed read produced.
///
/// The two arms are the two things the kernel can report, and the overflow arm
/// exists so that ignoring one requires deleting a `match` arm rather than
/// forgetting an `if`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyBatch {
    /// The records the kernel wrote, in the order it wrote them.
    Records(Vec<NotifyRecord>),
    /// The kernel had more to say than the buffer could hold and dropped it.
    ///
    /// There were changes in the watched tree that this crate will never be told
    /// about. The response is spelled out on
    /// [`WatchEvent::Lost`](crate::WatchEvent::Lost), and it is a
    /// re-scan, not a log line: an overflow that is logged and forgotten is a
    /// blind spot the user was never told about.
    Overflow,
}

/// A notification buffer that is not a sequence of well-formed records.
///
/// Every variant names an offset, because "the buffer is bad" is not a
/// diagnosable statement and "the record at offset 24 claims a 500-byte name in
/// a 64-byte remainder" is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// The buffer ends in the middle of a record's twelve-byte header.
    ///
    /// Reached when fewer than twelve bytes remain at the current offset — a
    /// truncated buffer, or an offset that walked into the last few bytes.
    #[error(
        "the notification buffer is truncated: a record header needs {RECORD_HEADER_BYTES} bytes \
         and only {remaining} remain at offset {offset}"
    )]
    TruncatedHeader {
        /// Where the incomplete header starts.
        offset: usize,
        /// How many bytes are left.
        remaining: usize,
    },

    /// `FileNameLength` is not a whole number of UTF-16 code units.
    ///
    /// Reached from a record whose name length is odd. Every name the kernel
    /// reports is UTF-16, so an odd length is a malformed record and not a
    /// name in some other encoding.
    #[error(
        "the record at offset {offset} declares a {length}-byte name, which is not a whole \
         number of UTF-16 code units"
    )]
    OddNameLength {
        /// Where the malformed record starts.
        offset: usize,
        /// The length it declared.
        length: u32,
    },

    /// A record's name runs past the end of the buffer.
    ///
    /// Reached from a record whose `FileNameLength` is larger than what is left,
    /// including one large enough that computing its end would overflow.
    #[error(
        "the record at offset {offset} declares a {length}-byte name but only {remaining} \
         bytes remain in the buffer"
    )]
    NameOutOfBounds {
        /// Where the malformed record starts.
        offset: usize,
        /// The length it declared.
        length: u32,
        /// How many bytes were left.
        remaining: usize,
    },

    /// A record declares a name of zero length.
    ///
    /// Reached from a record with `FileNameLength == 0` beyond the first one.
    /// The first is handled before the walk, as [`NotifyBatch::Overflow`],
    /// because that is a shape the kernel documents; a zero-length name anywhere
    /// else names no file and would otherwise be a change to `""`.
    #[error("the record at offset {offset} has a zero-length name")]
    EmptyName {
        /// Where the malformed record starts.
        offset: usize,
    },

    /// A record's name is not well-formed UTF-16.
    ///
    /// Reached from a name containing an unpaired surrogate. NTFS cannot store
    /// such a name, so this says something about the buffer rather than about a
    /// file — and it is an error rather than a lossy replacement because
    /// replacing the surrogate with `U+FFFD` would hand the scanner a path
    /// naming a *different* file. Scanning the wrong file is worse than
    /// reporting that the name could not be read.
    #[error("the name in the record at offset {offset} is not well-formed UTF-16")]
    UnpairedSurrogate {
        /// Where the malformed record starts.
        offset: usize,
    },

    /// `NextEntryOffset` points outside the buffer.
    ///
    /// Reached from a record whose offset, added to its own, lands past the end.
    #[error(
        "the record at offset {offset} points {next} bytes ahead, past the end of a \
         {total}-byte buffer"
    )]
    NextEntryOffsetOutOfBounds {
        /// Where the malformed record starts.
        offset: usize,
        /// The offset it declared.
        next: u32,
        /// The size of the whole buffer.
        total: usize,
    },

    /// `NextEntryOffset` does not move the walk past the record it sits in.
    ///
    /// Reached from a record that points into its own bytes, and from one that
    /// is not `DWORD`-aligned — the kernel pads each record so the next one
    /// starts on a four-byte boundary, which means every offset it reports is a
    /// multiple of four. Both are checked before the offset is advanced, because
    /// either one leaves the walk reading a name as a header: a parser that only
    /// checked "moves forward" would accept `next = 4` and invent a record out
    /// of the first two characters of the previous file's name.
    #[error(
        "the record at offset {offset} declares a next-record offset of {next}, which does not \
         move past that record"
    )]
    NextEntryOffsetNotForward {
        /// Where the malformed record starts.
        offset: usize,
        /// The offset it declared.
        next: u32,
    },
}

/// Read four bytes as a little-endian `u32`, or `None` if they are not there.
///
/// Returns an `Option` rather than indexing so that no arithmetic on an offset
/// that came out of an untrusted buffer can panic. Every caller below has
/// already proved the bytes exist, so the `None` arm is the belt to that braces
/// and not the primary check.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

/// Turn a notification buffer into records.
///
/// An empty buffer is [`NotifyBatch::Overflow`]: the kernel signals that it had
/// more to report than the buffer could hold by completing the read with no
/// bytes written, which is the one case where "nothing happened" and "too much
/// happened" are told apart by the size of the buffer rather than by its
/// contents.
///
/// `bytes` is exactly the number of bytes the kernel reported writing. Passing a
/// whole allocation instead of the filled prefix would read uninitialised tail
/// bytes as records, so the caller is responsible for that slice — see
/// `watch::checked_len`, which is what refuses a byte count larger than the
/// buffer it came from.
pub fn parse(bytes: &[u8]) -> std::result::Result<NotifyBatch, NotifyError> {
    if bytes.is_empty() {
        return Ok(NotifyBatch::Overflow);
    }

    // The other shape an overflow takes: a single twelve-byte record with both
    // the next-entry offset and the name length zero. It is checked here rather
    // than inside the walk so that the walk stays strict — a zero-length name
    // anywhere else is still an error, and this narrow test cannot be used to
    // excuse one.
    if bytes.len() >= RECORD_HEADER_BYTES {
        let next = u32_at(bytes, 0).unwrap_or(0);
        let name_length = u32_at(bytes, 8).unwrap_or(0);
        if next == 0 && name_length == 0 {
            return Ok(NotifyBatch::Overflow);
        }
    }

    let mut records = Vec::new();
    let mut offset = 0usize;

    loop {
        let remaining = bytes.len().saturating_sub(offset);
        if remaining < RECORD_HEADER_BYTES {
            return Err(NotifyError::TruncatedHeader { offset, remaining });
        }

        // Safe to unwrap: `remaining >= RECORD_HEADER_BYTES` puts all three
        // fields wholly inside the buffer.
        let (Some(next_entry_offset), Some(action_code), Some(name_length)) = (
            u32_at(bytes, offset),
            u32_at(bytes, offset + 4),
            u32_at(bytes, offset + 8),
        ) else {
            return Err(NotifyError::TruncatedHeader { offset, remaining });
        };

        if name_length % 2 != 0 {
            return Err(NotifyError::OddNameLength {
                offset,
                length: name_length,
            });
        }
        if name_length == 0 {
            return Err(NotifyError::EmptyName { offset });
        }

        let name_start = offset + RECORD_NAME_OFFSET;
        let name_end = usize::try_from(name_length)
            .ok()
            .and_then(|length| name_start.checked_add(length))
            .filter(|end| *end <= bytes.len())
            .ok_or(NotifyError::NameOutOfBounds {
                offset,
                length: name_length,
                remaining,
            })?;
        let raw_name = bytes
            .get(name_start..name_end)
            .ok_or(NotifyError::NameOutOfBounds {
                offset,
                length: name_length,
                remaining,
            })?;

        // `chunks_exact(2)` over an even length cannot leave a remainder, so
        // every code unit is complete. `from_utf16` and not a per-unit `as char`
        // cast: a surrogate pair is one character, and the cast would make it
        // two.
        let units: Vec<u16> = raw_name
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        let name =
            String::from_utf16(&units).map_err(|_| NotifyError::UnpairedSurrogate { offset })?;

        records.push(NotifyRecord {
            action: FileAction::from_code(action_code),
            name,
        });

        if next_entry_offset == 0 {
            break;
        }
        let next_offset = offset
            .checked_add(usize::try_from(next_entry_offset).unwrap_or(usize::MAX))
            .ok_or(NotifyError::NextEntryOffsetOutOfBounds {
                offset,
                next: next_entry_offset,
                total: bytes.len(),
            })?;
        if next_entry_offset % 4 != 0 || next_offset < name_end {
            return Err(NotifyError::NextEntryOffsetNotForward {
                offset,
                next: next_entry_offset,
            });
        }
        if next_offset > bytes.len() {
            return Err(NotifyError::NextEntryOffsetOutOfBounds {
                offset,
                next: next_entry_offset,
                total: bytes.len(),
            });
        }
        offset = next_offset;
    }

    Ok(NotifyBatch::Records(records))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one record, padded so the next one starts `DWORD`-aligned.
    ///
    /// `next` is filled in by [`buffer`]; this only writes the fields a test
    /// wants to control.
    fn record(action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes()); // next, patched later
        out.extend_from_slice(&action.to_le_bytes());
        out.extend_from_slice(&(units.len() as u32 * 2).to_le_bytes());
        for unit in &units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// Concatenate records, chaining `NextEntryOffset` and zeroing the last.
    fn buffer(records: Vec<Vec<u8>>) -> Vec<u8> {
        let count = records.len();
        let mut out = Vec::new();
        for (index, mut bytes) in records.into_iter().enumerate() {
            if index + 1 != count {
                let next = bytes.len() as u32;
                bytes[0..4].copy_from_slice(&next.to_le_bytes());
            }
            out.extend_from_slice(&bytes);
        }
        out
    }

    fn records_of(bytes: &[u8]) -> Vec<NotifyRecord> {
        match parse(bytes).expect("a well-formed buffer") {
            NotifyBatch::Records(records) => records,
            NotifyBatch::Overflow => panic!("expected records, got an overflow"),
        }
    }

    #[test]
    fn an_empty_buffer_is_an_overflow_and_not_an_empty_batch() {
        // This is the whole overflow signal. A parser that returned "no
        // records" here would make a dropped burst of changes indistinguishable
        // from a quiet directory, which is the failure the crate exists to
        // avoid.
        assert_eq!(parse(&[]).unwrap(), NotifyBatch::Overflow);
    }

    #[test]
    fn the_twelve_byte_zero_record_is_also_an_overflow() {
        assert_eq!(parse(&[0u8; 12]).unwrap(), NotifyBatch::Overflow);
        // And only that shape: a zeroed record with a name length is not an
        // overflow, it is a record whose action is zero — an unknown action —
        // carrying a name.
        let mut bytes = vec![0u8; 12];
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[b'a', 0]);
        assert!(matches!(parse(&bytes), Ok(NotifyBatch::Records(_))));
    }

    #[test]
    fn one_record_yields_its_action_and_name() {
        let bytes = buffer(vec![record(ACTION_ADDED, "dropper.exe")]);
        let records = records_of(&bytes);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, FileAction::Added);
        assert_eq!(records[0].name, "dropper.exe");
    }

    #[test]
    fn a_multi_record_buffer_is_walked_by_the_declared_offsets() {
        // The first name is deliberately a length that is not a multiple of
        // four, so the record is padded: a parser that stepped by
        // `12 + name_length` instead of by `NextEntryOffset` reads the padding
        // as the next header and produces garbage or an error here.
        let bytes = buffer(vec![
            record(ACTION_ADDED, "abc"),
            record(ACTION_MODIFIED, "de"),
            record(ACTION_RENAMED_NEW_NAME, "final.dll"),
        ]);
        let records = records_of(&bytes);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].name, "abc");
        assert_eq!(records[1].name, "de");
        assert_eq!(records[1].action, FileAction::Modified);
        assert_eq!(records[2].name, "final.dll");
        assert_eq!(records[2].action, FileAction::RenamedNewName);
    }

    #[test]
    fn a_trailing_record_with_no_successor_ends_the_walk() {
        let first = record(ACTION_ADDED, "one.txt");
        let bytes = buffer(vec![first.clone(), record(ACTION_ADDED, "two.txt")]);
        // The last record's own `NextEntryOffset` is zero, and the second
        // record's bytes are the end of the buffer.
        let last = first.len();
        assert_eq!(u32_at(&bytes, 0), Some(last as u32));
        assert_eq!(u32_at(&bytes, last), Some(0));
        assert_eq!(records_of(&bytes).len(), 2);

        // And a buffer holding only a last record is one record, not none.
        let single = buffer(vec![record(ACTION_ADDED, "only.txt")]);
        assert_eq!(u32_at(&single, 0), Some(0));
        assert_eq!(records_of(&single).len(), 1);
    }

    #[test]
    fn a_name_longer_than_the_remaining_buffer_is_an_error_and_not_a_panic() {
        // The declared name runs past the end. A parser that sliced to it —
        // `&bytes[12..12 + length]` — panics, and a parser that clamped would
        // scan a truncated path.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ACTION_ADDED.to_le_bytes());
        bytes.extend_from_slice(&1000u32.to_le_bytes());
        bytes.extend_from_slice(&[b'x', 0, b'y', 0]);
        match parse(&bytes) {
            Err(NotifyError::NameOutOfBounds {
                offset,
                length,
                remaining,
            }) => {
                assert_eq!(offset, 0);
                assert_eq!(length, 1000);
                assert_eq!(remaining, 16);
            }
            other => panic!("expected NameOutOfBounds, got {other:?}"),
        }

        // And a length whose end would overflow the address space is the same
        // error rather than a wrapped offset that looks in bounds. `u32::MAX - 1`
        // and not `u32::MAX`, because the latter is odd and would be refused a
        // check earlier for a different reason.
        let mut huge = Vec::new();
        huge.extend_from_slice(&0u32.to_le_bytes());
        huge.extend_from_slice(&ACTION_ADDED.to_le_bytes());
        huge.extend_from_slice(&(u32::MAX - 1).to_le_bytes());
        huge.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            parse(&huge),
            Err(NotifyError::NameOutOfBounds { .. })
        ));
        // The odd one reaches the odd-length check, which is also a refusal.
        let mut odd = Vec::new();
        odd.extend_from_slice(&0u32.to_le_bytes());
        odd.extend_from_slice(&ACTION_ADDED.to_le_bytes());
        odd.extend_from_slice(&u32::MAX.to_le_bytes());
        odd.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            parse(&odd),
            Err(NotifyError::OddNameLength { .. })
        ));
    }

    #[test]
    fn an_odd_name_length_is_an_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ACTION_ADDED.to_le_bytes());
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        match parse(&bytes) {
            Err(NotifyError::OddNameLength { offset, length }) => {
                assert_eq!(offset, 0);
                assert_eq!(length, 7);
            }
            other => panic!("expected OddNameLength, got {other:?}"),
        }
    }

    #[test]
    fn a_non_bmp_character_survives_as_one_character() {
        // U+1D11E MUSICAL SYMBOL G CLEF is D834 DD1E in UTF-16. Four bytes, two
        // code units, one character — so this also pins that the name length is
        // read as bytes: a parser that divided by two would cut the name off
        // after the high surrogate and fail to decode it at all, and one that
        // cast each `u16` to `char` would produce two characters that join to
        // something no path on the machine has.
        let name = "a\u{1D11E}b";
        let bytes = buffer(vec![record(ACTION_ADDED, name)]);
        let records = records_of(&bytes);
        assert_eq!(records[0].name, name);
        assert_eq!(records[0].name.chars().count(), 3);
        assert!(!records[0].name.contains('\u{FFFD}'));

        // The declaration is four bytes for the two-unit character, which is
        // what makes the byte/character confusion visible.
        assert_eq!(
            u32_at(&bytes, 8),
            Some(name.encode_utf16().count() as u32 * 2)
        );
    }

    #[test]
    fn an_unpaired_surrogate_is_an_error_rather_than_a_replacement_character() {
        // Hand-built, because no filesystem this runs on can hold such a name:
        // a lone high surrogate must not become U+FFFD, which would name a
        // different file.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&ACTION_ADDED.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0xD834u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 2]);
        match parse(&bytes) {
            Err(NotifyError::UnpairedSurrogate { offset }) => assert_eq!(offset, 0),
            other => panic!("expected UnpairedSurrogate, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_length_name_inside_the_walk_is_an_error() {
        // The first record is real and declares a successor, so the overflow
        // shortcut at the top does not apply and the walk reaches the second
        // record's empty name. `buffer` is what chains the offsets — building
        // this by hand without chaining the first record would leave
        // `NextEntryOffset` at zero, the walk would stop at the first record, and
        // the test would pass without ever reading the malformed one.
        let first = record(ACTION_ADDED, "real.txt");
        let second_offset = first.len();
        let bytes = buffer(vec![first, record(ACTION_ADDED, "")]);
        match parse(&bytes) {
            Err(NotifyError::EmptyName { offset }) => assert_eq!(offset, second_offset),
            other => panic!("expected EmptyName, got {other:?}"),
        }

        // And the same shape at the top of the buffer is the overflow, not this
        // error: the kernel reports "I had more than I could fit" by writing one
        // record with nothing in it, and that one statement must not be read as
        // a malformed buffer.
        let overflow = buffer(vec![record(ACTION_ADDED, "")]);
        assert_eq!(
            parse(&overflow).expect("an overflow"),
            NotifyBatch::Overflow
        );
    }

    #[test]
    fn a_truncated_header_is_an_error() {
        let bytes = buffer(vec![record(ACTION_ADDED, "a.txt")]);
        // Every prefix shorter than a header, and one that stops mid-header.
        for cut in 1..RECORD_HEADER_BYTES {
            let short = &bytes[..cut];
            assert!(
                matches!(parse(short), Err(NotifyError::TruncatedHeader { .. })),
                "a {cut}-byte buffer should be a truncated header"
            );
        }
    }

    #[test]
    fn a_next_entry_offset_that_does_not_move_past_its_own_record_is_an_error() {
        // `a.txt` is five code units, so its name ends at byte 22 and the next
        // record must start at 24. An offset of 4 is aligned and does move
        // forward, so a parser that only checked "did the offset grow" walks
        // into the name and reads `a\0.` as a header — inventing a record out of
        // the previous file's name. The check is against the end of the name,
        // not against the previous offset.
        let mut inside = buffer(vec![record(ACTION_ADDED, "a.txt")]);
        inside[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(matches!(
            parse(&inside),
            Err(NotifyError::NextEntryOffsetNotForward { offset: 0, next: 4 })
        ));

        // The kernel pads every record to a four-byte boundary, so an unaligned
        // offset is malformed even when it lands past the name.
        let mut misaligned = buffer(vec![record(ACTION_ADDED, "a.txt")]);
        misaligned[0..4].copy_from_slice(&25u32.to_le_bytes());
        assert!(matches!(
            parse(&misaligned),
            Err(NotifyError::NextEntryOffsetNotForward { next: 25, .. })
        ));

        // And one that lands past the buffer is a different error, because the
        // two are diagnosed differently: this one is a bad length, the other is
        // a bad step.
        let mut past_end = buffer(vec![record(ACTION_ADDED, "a.txt")]);
        past_end[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(matches!(
            parse(&past_end),
            Err(NotifyError::NextEntryOffsetOutOfBounds { next: 4096, .. })
        ));
    }

    #[test]
    fn the_action_code_round_trips_and_an_unknown_one_is_kept() {
        for action in [
            FileAction::Added,
            FileAction::Removed,
            FileAction::Modified,
            FileAction::RenamedOldName,
            FileAction::RenamedNewName,
        ] {
            assert_eq!(FileAction::from_code(action.code()), action);
            assert!(!action.as_str().is_empty());
        }
        // A code this build does not know survives as itself, so a caller can
        // count it rather than lose it.
        let unknown = FileAction::from_code(99);
        assert_eq!(unknown, FileAction::Unknown(99));
        assert_eq!(unknown.code(), 99);
        assert_eq!(unknown.as_str(), "unknown");
    }

    #[test]
    fn actions_come_from_the_codes_the_kernel_documents() {
        // Pinned by number because the numbers are the interface with the
        // kernel and a reordering of the enum would silently swap a create for
        // a delete.
        assert_eq!(FileAction::from_code(1), FileAction::Added);
        assert_eq!(FileAction::from_code(2), FileAction::Removed);
        assert_eq!(FileAction::from_code(3), FileAction::Modified);
        assert_eq!(FileAction::from_code(4), FileAction::RenamedOldName);
        assert_eq!(FileAction::from_code(5), FileAction::RenamedNewName);
    }

    #[test]
    fn a_record_resolves_against_its_root() {
        let root = Path::new(r"C:\Users\me\Downloads");
        let change = Change::resolve(
            root,
            NotifyRecord {
                action: FileAction::Added,
                name: r"sub\invoice.exe".into(),
            },
        );
        assert_eq!(
            change.path,
            PathBuf::from(r"C:\Users\me\Downloads\sub\invoice.exe")
        );
        assert_eq!(change.file_name(), Some("invoice.exe"));

        // A name in the root itself, and one that is a directory: both are a
        // plain join, because the kernel's name is always relative.
        let flat = Change::resolve(
            root,
            NotifyRecord {
                action: FileAction::Added,
                name: "a.txt".into(),
            },
        );
        assert_eq!(flat.path, PathBuf::from(r"C:\Users\me\Downloads\a.txt"));
    }

    #[test]
    fn a_root_with_a_trailing_separator_does_not_double_it() {
        // `Path::join` treats a trailing separator as part of the root, so this
        // is what stops `C:\Temp\` + `a.txt` from being `C:\Temp\\a.txt` — a
        // string that opens the same file but compares unequal to every path
        // the rest of the product builds.
        let change = Change::resolve(
            Path::new(r"C:\Temp\"),
            NotifyRecord {
                action: FileAction::Added,
                name: "a.txt".into(),
            },
        );
        assert_eq!(change.path, PathBuf::from(r"C:\Temp\a.txt"));
    }

    #[test]
    fn a_batch_of_records_serializes_for_the_report() {
        let records = records_of(&buffer(vec![record(ACTION_ADDED, "a.txt")]));
        let json = serde_json::to_string(&records).expect("records serialize");
        assert!(json.contains("\"added\""), "{json}");
        assert!(json.contains("a.txt"), "{json}");
    }
}
