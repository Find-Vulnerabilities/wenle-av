//! Listing a directory whose permissions say no.
//!
//! # Why reading is not enough
//!
//! [`mod@crate::read`] opens paths it is handed. A scan is handed its paths by a
//! directory walk, and the walk is where the files a scan never sees are
//! actually lost. `std::fs::read_dir` calls `FindFirstFileW`, which is subject
//! to the directory's DACL exactly as an open is: a directory that denies
//! `FILE_LIST_DIRECTORY` to this account produces an error, the walk skips it,
//! and the report says nothing. The result is the failure mode this crate exists
//! to prevent, one level up — `C:\Users\someone-else` cannot be *entered*, so
//! nothing inside it is ever *offered* to the reader, and "we found nothing" and
//! "we could not look" are once again the same line in the report.
//!
//! `C:\System Volume Information`, `C:\ProgramData\Microsoft\Windows Defender`,
//! `C:\$Recycle.Bin`, and every other user's profile are all in that category on
//! an ordinary account. On an attacker's machine, so is wherever they left
//! things.
//!
//! # The answer, and how it differs from the read path
//!
//! The same privilege, reached slightly differently. Two facts make directories
//! their own case rather than a copy of [`mod@crate::read`]:
//!
//! 1. **`FILE_FLAG_BACKUP_SEMANTICS` is mandatory here, not conditional.**
//!    `CreateFileW` refuses to open a directory at all without it, whatever
//!    account is asking. [`mod@crate::read`] passes it only when the privilege is
//!    enabled, because for a file it is exactly the flag that lets
//!    `SeBackupPrivilege` apply. For a directory it must always be passed, and
//!    that is not a weakening: the flag on its own grants nothing, and only
//!    *enabling* the privilege changes what the access check does.
//! 2. **The access right is `FILE_LIST_DIRECTORY`, not `FILE_GENERIC_READ`.**
//!    That is the directory's name for "read data", and it is the right the
//!    privilege bypasses.
//!
//! So the flags and the requested right are **identical in both modes**, and the
//! only difference between an ordinary walk and a privileged one is whether the
//! process token had the privilege turned on. That is a property worth having:
//! there is no configuration in which this code asks for less and then blames
//! the file.
//!
//! # What is deliberately not done here
//!
//! * **No recursion.** This lists one directory. Recursion, symlink policy,
//!   depth limits and the decision to cross a volume boundary are a scanner's
//!   policy, not a filesystem's, and `av-scan` already owns them. A walk that
//!   recursed would have to have an opinion about junctions and would put it
//!   somewhere nobody looks.
//! * **No filtering.** Everything the directory holds is returned, including
//!   `.` and `..` if the filesystem reports them. Callers decide.
//! * **No sorting.** The order is the filesystem's. A caller that wants a
//!   deterministic order sorts; a caller that wants to stream does not have to
//!   pay for one.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

// Only [`Reader::read_dir`]'s Windows arm converts a path to the UTF-16 form
// the extended-length API takes, so a non-Windows build has nothing to import.
#[cfg(windows)]
use crate::read::verbatim;
use crate::refusal::{Refused, Why};
use crate::Reader;

/// One thing inside a directory.
///
/// The name is a name, not a path: it is what the directory reported, with no
/// parent joined on. [`Entry::path_in`] joins, and it is a separate call because
/// a caller that is only counting, or only looking at sizes, should not be
/// building `PathBuf`s it will throw away — a scan of a large directory builds
/// hundreds of thousands of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The file's name within its directory, without any parent.
    pub name: String,
    /// The `FILE_ATTRIBUTE_*` bits the filesystem reported.
    pub attributes: u32,
    /// The logical size in bytes. Zero for a directory, which is what Windows
    /// reports rather than a sum of the contents.
    pub size: u64,
    /// The file identifier the volume assigned.
    ///
    /// Carried because it is free — it arrives in the same record — and because
    /// it is the only reliable way to tell a hard link from a copy, and to
    /// recognise a file that was renamed between being listed and being read.
    /// `0` when the filesystem does not provide one.
    pub id: u64,
}

impl Entry {
    /// Whether this is a directory rather than a file.
    ///
    /// Read from the attributes the filesystem reported rather than from a
    /// second call, so that a directory which changed between being listed and
    /// being asked about cannot give two different answers.
    pub const fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Whether this is a reparse point: a symlink, a junction, or a mount point.
    ///
    /// A caller that walks must check this before descending. A junction that
    /// points at its own parent is an infinite directory tree, and following one
    /// is how a scanner ends up scanning `C:\` forever. Nothing here follows
    /// anything — that is the caller's decision — but the caller cannot make it
    /// without this bit.
    pub const fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Whether the file is one Windows considers hidden or system.
    ///
    /// Not a reason to skip it — the interesting files are frequently both — but
    /// a reason to say so in a report, because a user who is told a scan looked
    /// everywhere deserves to know which of it was hidden.
    pub const fn is_hidden_or_system(&self) -> bool {
        self.attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0
    }

    /// This entry's full path, given the directory it came from.
    pub fn path_in(&self, parent: &Path) -> PathBuf {
        parent.join(&self.name)
    }
}

/// `FILE_ATTRIBUTE_DIRECTORY`, spelled here so that [`Entry`]'s predicates do
/// not drag a `windows` import into every caller on every platform.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// `FILE_ATTRIBUTE_HIDDEN`.
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
/// `FILE_ATTRIBUTE_SYSTEM`.
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The name, the size and the flags that change what a walk does with
        // it. Not the id: it is a number nobody reads and every scan report that
        // included one would be longer for it.
        write!(
            f,
            "{}{} ({} bytes{}{})",
            self.name,
            if self.is_dir() { "/" } else { "" },
            self.size,
            if self.is_reparse_point() { ", reparse" } else { "" },
            if self.is_hidden_or_system() {
                ", hidden"
            } else {
                ""
            }
        )
    }
}

impl Reader {
    /// List a directory, or say why not.
    ///
    /// Returns everything the directory holds, in the filesystem's order. An
    /// empty directory is `Ok(vec![])` and not an error; a directory this
    /// account may not list is a [`Refused`] whose [`Why`] distinguishes that
    /// from a directory that is not there.
    ///
    /// The refusal is the interesting return value, not the entries. A walk that
    /// reports "0 files" for `C:\System Volume Information` and "0 files" for an
    /// empty folder has told the user two identical things about two different
    /// situations, and only one of them is fine.
    pub fn read_dir(&self, path: &Path) -> Result<Vec<Entry>, Refused> {
        // Split by platform here rather than inside `list`, because the *name*
        // is the platform's: the Windows call is made with a UTF-16 path the
        // extended-length prefix has been applied to, and the non-Windows one
        // has no such conversion to make and no function to make it with. A
        // single call passing a name both platforms could produce would be a
        // name one of them had invented.
        #[cfg(windows)]
        {
            let name = verbatim(path)
                .map_err(|reason| Refused::new(path, Why::Unrepresentable { reason }))?;
            self.list(path, &name)
        }
        #[cfg(not(windows))]
        {
            self.list(path, &[])
        }
    }

    /// List a directory, or return an [`io::Error`] carrying the reason.
    ///
    /// The shape the existing walk wants: it already has an error path that
    /// turns a failed listing into a line in the report, and keeping the
    /// signature `io::Result<Vec<Entry>>` means that path did not have to change
    /// to gain the better wording.
    pub fn list_dir(&self, path: &Path) -> io::Result<Vec<Entry>> {
        self.read_dir(path).map_err(io::Error::from)
    }

    /// The platform half, so that the two public methods above read as policy.
    #[cfg(not(windows))]
    fn list(&self, path: &Path, _name: &[u16]) -> Result<Vec<Entry>, Refused> {
        // No privilege to reach for and no equivalent of the backup semantics
        // flag, so this is `read_dir` with the reason preserved. There is
        // deliberately no pretending otherwise: on a platform where the
        // operating system offers no way to list a directory this account may
        // not read, an honest refusal is the whole of what this crate can
        // contribute.
        let dir = std::fs::read_dir(path).map_err(|e| classify_io(path, &e))?;
        let mut out = Vec::new();
        for item in dir {
            let item = item.map_err(|e| classify_io(path, &e))?;
            // `symlink_metadata`, not `metadata`: a link is reported as a link
            // rather than as whatever it points at, which is what makes
            // `Entry::is_reparse_point` mean the same thing here as on Windows
            // and what stops a walk from descending through a symlink loop.
            let meta = std::fs::symlink_metadata(item.path())
                .map_err(|e| classify_io(&item.path(), &e))?;
            let mut attributes = 0u32;
            if meta.is_dir() {
                attributes |= FILE_ATTRIBUTE_DIRECTORY;
            }
            if meta.file_type().is_symlink() {
                attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
            }
            out.push(Entry {
                name: item.file_name().to_string_lossy().into_owned(),
                attributes,
                // A symlink's own length is the length of its target's path,
                // which is not the size of anything useful. Zero, so that a
                // caller applying a size filter does not silently drop a
                // directory symlink for being "long".
                size: if meta.file_type().is_symlink() {
                    0
                } else {
                    meta.len()
                },
                id: 0,
            });
        }
        Ok(out)
    }

    #[cfg(windows)]
    fn list(&self, path: &Path, name: &[u16]) -> Result<Vec<Entry>, Refused> {
        self.list_windows(path, name)
    }
}

/// Map a non-Windows `io::Error` onto a [`Why`], keeping the distinction that
/// matters: a refusal to look is not the same as nothing being there.
#[cfg(not(windows))]
fn classify_io(path: &Path, error: &io::Error) -> Refused {
    let why = match error.kind() {
        io::ErrorKind::NotFound => Why::Gone,
        io::ErrorKind::PermissionDenied => Why::Denied {
            backup_enabled: false,
            code: error.raw_os_error().unwrap_or(0) as u32,
        },
        io::ErrorKind::WouldBlock => Why::InUse { attempts: 1 },
        _ => Why::Os {
            code: error.raw_os_error().unwrap_or(0) as u32,
            message: error.to_string(),
        },
    };
    Refused::new(path, why)
}

#[cfg(windows)]
mod win {
    use std::path::Path;

    use super::{Entry, Reader, Refused, Why};
    use crate::read::{classify, code_of, verbatim};
    use windows::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_BOTH_DIR_INFO,
        FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    /// How much of a directory to read per call.
    ///
    /// `GetFileInformationByHandleEx` has no "how many entries" parameter: it
    /// fills a byte buffer and returns `ERROR_MORE_DATA` when the directory has
    /// more. 64 KiB holds a few hundred entries with their long names, so an
    /// ordinary directory is one call and a large one is a handful. Growing on
    /// demand was considered and rejected — a directory with a million entries
    /// would grow the buffer to tens of megabytes to save a few dozen calls, and
    /// a scanner's memory is better spent on the files it is reading.
    const BUFFER: usize = 64 * 1024;

    /// An absolute ceiling on how many times the enumeration may be continued.
    ///
    /// Not a limit on how many entries may be listed — the loop continues until
    /// the filesystem says it is done, however long that takes, and a directory
    /// of a million files is a million records and not a million rounds. This is
    /// the backstop for a filter driver that produces records forever, which
    /// would otherwise be an unbounded loop in a scanner. Reaching it is
    /// reported rather than absorbed.
    const MAX_ROUNDS: usize = 1_000_000;

    /// How many consecutive rounds may produce nothing before the walk stops.
    ///
    /// One, not zero, because the round after `ERROR_MORE_DATA` may legitimately
    /// produce nothing on a filesystem whose index node boundary fell exactly on
    /// the buffer's end — and stopping there would truncate a real listing by
    /// nothing at all, which looks like a clean result. Two consecutive silent
    /// rounds is a filesystem that has stopped talking.
    const BARREN_ROUNDS: u32 = 2;

    impl Reader {
        /// Open a directory handle, or say why not.
        ///
        /// Both flags are unconditional here, and that is the whole of this
        /// function's design. `FILE_FLAG_BACKUP_SEMANTICS` is not requested to
        /// gain the privilege — without the privilege enabled it grants nothing
        /// — it is requested because `CreateFileW` will not open a directory
        /// without it. `FILE_LIST_DIRECTORY` is the directory's word for
        /// "read data", and it is the right that `SeBackupPrivilege` bypasses
        /// when it is enabled. So an ordinary reader and a privileged one differ
        /// in the token, not in the request, and neither can ask for less and
        /// then report the refusal as the file's fault.
        fn open_dir(&self, path: &Path, name: &[u16]) -> Result<HANDLE, Why> {
            let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the
            // call; the remaining arguments are values or `None`, which the API
            // documents as "no security attributes" and "no template".
            let opened = unsafe {
                CreateFileW(
                    windows::core::PCWSTR(name.as_ptr()),
                    FILE_LIST_DIRECTORY.0,
                    share,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                    None,
                )
            };
            // The token's state rather than a flag chosen here: the flags above
            // are the same in both modes, so the only thing that can change the
            // answer is whether the privilege was enabled in the process.
            opened.map_err(|e| classify(path, e, self.privilege().is_enabled()))
        }

        /// One round of the enumeration.
        ///
        /// Returns whether the call itself said the directory has more. That
        /// value comes from *this call's* result and never from inspecting the
        /// buffer:
        ///
        /// * `ERROR_MORE_DATA` means the buffer filled with complete records and
        ///   the directory has more. The records are real; there are simply not
        ///   all of them here.
        /// * Success means this round is finished. It does **not** mean the
        ///   directory is — see [`Reader::list_windows`].
        ///
        /// Reading "is there more" off the buffer instead was the obvious first
        /// implementation and is wrong in the direction that matters: the record
        /// chain ends with `NextEntryOffset == 0` in *every* round, whether or
        /// not the directory has more, so a truncated listing looks exactly like
        /// a complete one.
        fn one_round(
            handle: HANDLE,
            buffer: &mut [u8],
            restart: bool,
        ) -> Result<bool, windows::core::Error> {
            let class: FILE_INFO_BY_HANDLE_CLASS = if restart {
                FileIdBothDirectoryRestartInfo
            } else {
                FileIdBothDirectoryInfo
            };
            // Cleared first, so that any region this call does not write is
            // zero. A zeroed record has `NextEntryOffset == 0` and a name length
            // of zero, which `parse` treats as the end of the chain — so the
            // worst a stale byte can do is stop the walk early within a round,
            // never produce a file that is not there.
            buffer.fill(0);
            // SAFETY: `buffer` is a live, writable allocation of exactly the
            // length passed alongside it, and the handle is open for the
            // duration of the call.
            let result = unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    class,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                )
            };
            match result {
                Ok(()) => Ok(false),
                Err(e) if code_of(&e) == ERROR_MORE_DATA.0 => Ok(true),
                Err(e) => Err(e),
            }
        }

        /// A directory's identity: which volume, and which file on it.
        ///
        /// The pair rather than the file id alone, because file ids are unique
        /// per volume and a junction can point at another one. Called only when
        /// links are being followed, so the extra open is not paid for by the
        /// ordinary walk.
        pub fn directory_id(&self, path: &Path) -> Result<(u32, u64), Refused> {
            use windows::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            };

            let name = verbatim(path)
                .map_err(|reason| Refused::new(path, Why::Unrepresentable { reason }))?;
            let handle = self
                .open_dir(path, &name)
                .map_err(|why| Refused::new(path, why))?;

            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: `handle` is open and `info` is a live local of the type
            // the API writes.
            let result = unsafe { GetFileInformationByHandle(handle, &mut info) };
            // SAFETY: the handle came from `CreateFileW`, is still open, and is
            // not used afterwards.
            unsafe {
                let _ = CloseHandle(handle);
            }
            result.map_err(|e| {
                Refused::new(path, classify(path, e, self.privilege().is_enabled()))
            })?;

            let id = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
            Ok((info.dwVolumeSerialNumber, id))
        }

        /// List a directory, paging until the filesystem says there is no more.
        ///
        /// # The thing this function exists to get right
        ///
        /// **`GetFileInformationByHandleEx` returning success does not mean the
        /// listing is complete.** Measured on this machine (NTFS, Windows 11
        /// build 26200) against a directory of 400 files with a 64 KiB buffer:
        ///
        /// ```text
        /// round 0: OK             records=283  total=283
        /// round 1: OK             records=119  total=402
        /// round 2: ERROR_NO_MORE_FILES       total=402
        /// ```
        ///
        /// Two successful calls, and the first of them returned less than
        /// three-quarters of the directory. The reason is that NTFS fills the
        /// caller's buffer from its own index nodes: it stops at a node boundary
        /// rather than at the buffer's end, and reports `STATUS_SUCCESS` because
        /// the call it was asked to perform succeeded. Only
        /// `ERROR_NO_MORE_FILES` means the directory has been enumerated.
        ///
        /// So the loop is driven by the error, not by the success. A walk that
        /// treated the first success as the end would report a directory of 400
        /// files as a directory of 281 — and it would report it as a *complete*
        /// listing, which is the failure this whole crate exists to prevent,
        /// arrived at from the other side.
        ///
        /// # Termination
        ///
        /// `ERROR_NO_MORE_FILES` is the normal end. It is backed by two stops
        /// that do not depend on the filesystem behaving: two consecutive rounds
        /// that produce no records and do not claim there is more, and
        /// [`MAX_ROUNDS`] as an absolute ceiling. Neither can truncate a real
        /// listing, because a round that produces records resets the counter.
        pub(super) fn list_windows(
            self: &Reader,
            path: &Path,
            name: &[u16],
        ) -> Result<Vec<Entry>, Refused> {
            let handle = self
                .open_dir(path, name)
                .map_err(|why| Refused::new(path, why))?;

            let mut out = Vec::new();
            let mut buffer = vec![0u8; BUFFER];
            let mut restart = true;
            let mut barren = 0u32;

            for _ in 0..MAX_ROUNDS {
                let outcome = Self::one_round(handle, &mut buffer, restart);
                let before = out.len();
                out.extend(parse(&buffer));

                let more = match outcome {
                    Ok(more) => more,
                    Err(e) if code_of(&e) == ERROR_NO_MORE_FILES.0 => {
                        // SAFETY: the handle came from `CreateFileW`, is still
                        // open, and is not used afterwards.
                        unsafe {
                            let _ = CloseHandle(handle);
                        }
                        return Ok(out);
                    }
                    Err(e) => {
                        // SAFETY: as above.
                        unsafe {
                            let _ = CloseHandle(handle);
                        }
                        return Err(Refused::new(
                            path,
                            classify(path, e, self.privilege().is_enabled()),
                        ));
                    }
                };

                // Progress is measured in records, not in rounds: a round that
                // claimed there was more is not barren however few records it
                // produced, and a round that produced records is not barren
                // whatever it claimed.
                if out.len() == before && !more {
                    barren += 1;
                    if barren >= BARREN_ROUNDS {
                        // SAFETY: as above.
                        unsafe {
                            let _ = CloseHandle(handle);
                        }
                        return Ok(out);
                    }
                } else {
                    barren = 0;
                }

                // Continuation: this round consumed as much as the filesystem
                // was willing to give, and the next one picks up from the last
                // record it wrote. `FileIdBothDirectoryInfo` rather than the
                // restart class is what asks for that.
                restart = false;
            }

            // SAFETY: as above. Reached only when the filesystem produced
            // records for a million consecutive rounds.
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(Refused::new(
                path,
                Why::Unrepresentable {
                    reason: "the directory produced entries for a million consecutive reads \
                             without ever reporting that it had ended",
                },
            ))
        }
    }

    /// Walk the record chain in one buffer.
    ///
    /// The records are a linked list laid out as byte offsets: each carries
    /// `NextEntryOffset`, the last carries zero, and each one's name is a
    /// variable-length UTF-16 array immediately after its fixed header. Three
    /// ways to get this wrong, all of which produce file names that are not on
    /// disk — which is a directory walk reporting files that do not exist, the
    /// worst failure available here:
    ///
    /// * using `size_of::<FILE_ID_BOTH_DIR_INFO>()` as the header length, when
    ///   the struct declares `FileName: [u16; 1]` and the real offset is
    ///   [`std::mem::offset_of`] — the same mistake that was a live bug in
    ///   `privilege.rs`;
    /// * reading a name that runs past the end of the buffer;
    /// * walking past the terminator into bytes the API never wrote.
    ///
    /// The last one is handled by the caller zeroing the buffer and by treating
    /// a zero-length name as the end: a file cannot be called nothing.
    ///
    /// The information class is `FileIdBothDirectoryInfo` and not
    /// `FileBothDirectoryInfo` for a reason that is exactly this hazard: on some
    /// filesystems the older class may return a *partially written* final record
    /// when the buffer is too small, so the last entry has to be discarded
    /// whenever the call reported more. The `Id` variant guarantees complete
    /// records, which is why the loop here can trust the stride without a
    /// "throw away the last one" rule that every later reader would have to
    /// rediscover the reason for.
    fn parse(buffer: &[u8]) -> Vec<Entry> {
        // The offset of the variable-length name array, not the size of the
        // struct. See this function's documentation.
        let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);

        let mut out = Vec::new();
        let mut offset = 0usize;
        loop {
            // A whole header has to fit before there is a record to read. This
            // is also the terminator condition when the buffer's tail is zero.
            if offset + header > buffer.len() {
                return out;
            }
            // SAFETY: `offset + header <= buffer.len()`, so a whole
            // `FILE_ID_BOTH_DIR_INFO` header lies within the buffer.
            // `read_unaligned` because the buffer is a `&[u8]` and the API makes
            // no promise about alignment within it.
            let record: FILE_ID_BOTH_DIR_INFO =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast()) };

            // Zero, or a length that would run past the buffer, is not a file
            // name. Both mean the chain has ended or was cut off, and in either
            // case there is nothing further to read here.
            let name_bytes = record.FileNameLength as usize;
            let name_at = offset + header;
            if name_bytes == 0 || name_at + name_bytes > buffer.len() {
                return out;
            }
            // SAFETY: the range is inside the buffer, and every `u16` in it was
            // written by the API before this call.
            let units: &[u16] = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().add(name_at).cast::<u16>(),
                    name_bytes / 2,
                )
            };
            let name = String::from_utf16_lossy(units);

            // `.` and `..` are not returned by this information class, so this
            // never fires in practice. It is here because being wrong about that
            // means a walk that recurses into its own parent forever, and one
            // comparison per entry is a cheap price for not having to be right.
            if name != "." && name != ".." {
                out.push(Entry {
                    name,
                    attributes: record.FileAttributes,
                    size: record.EndOfFile.max(0) as u64,
                    id: record.FileId as u64,
                });
            }

            if record.NextEntryOffset == 0 {
                // The end of the listing — as opposed to the end of the buffer,
                // which this round's `more` flag reports separately.
                return out;
            }
            let next = offset + record.NextEntryOffset as usize;
            if next <= offset || next >= buffer.len() {
                // A zero or backwards stride would spin forever; a stride past
                // the buffer means the next record is not in this round. Either
                // way this round is finished, and the caller's `more` flag
                // decides whether another round happens.
                return out;
            }
            offset = next;
        }
    }
}

/// List a directory with the process-wide reader.
///
/// The counterpart of [`mod@crate::read`], and privileged for the same reason: a
/// walk should not have to be told to look harder.
#[cfg(windows)]
pub fn read_dir(path: &Path) -> io::Result<Vec<Entry>> {
    crate::read::default_reader().list_dir(path)
}

/// List a directory, or say why not, with the process-wide reader.
#[cfg(windows)]
pub fn try_read_dir(path: &Path) -> Result<Vec<Entry>, Refused> {
    crate::read::default_reader().read_dir(path)
}

/// List a directory with the process-wide reader.
#[cfg(not(windows))]
pub fn read_dir(path: &Path) -> io::Result<Vec<Entry>> {
    crate::read::default_reader().list_dir(path)
}

// ---------------------------------------------------------------------------
// Recursive descent
// ---------------------------------------------------------------------------

/// How far to descend, and what to do about links.
///
/// Deliberately not a builder and deliberately without a `max_files`: the two
/// fields here are the two decisions a walk cannot make for the caller, and a
/// limit on how many files may be found is a policy about the *scan*, which
/// belongs to whatever is doing the scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescendOptions {
    /// How many levels below the root may be entered.
    ///
    /// `1` is the root's own entries and no deeper, which is the CLI's
    /// `--no-recursive`. Counted in *levels*, not in directories, so the value
    /// means the same thing whatever the tree looks like.
    pub max_depth: usize,
    /// Whether to descend through a reparse point — a symlink, a junction, a
    /// mount point.
    ///
    /// Off by default, and the default is the safe one. A junction that points
    /// at one of its own ancestors is an infinite tree, and following one is how
    /// a scan of `C:\` never finishes. When this is on, each directory's
    /// identity is tracked and a directory already visited on the current path
    /// is not entered twice.
    pub follow_links: bool,
}

impl Default for DescendOptions {
    fn default() -> Self {
        Self {
            max_depth: usize::MAX,
            follow_links: false,
        }
    }
}

impl DescendOptions {
    /// The root's own entries and nothing below them.
    pub const fn non_recursive() -> Self {
        Self {
            max_depth: 1,
            follow_links: false,
        }
    }
}

/// A file the walk found.
///
/// Carries what it cost to find — the size, so a caller can apply its own size
/// policy without a second `stat`, and the attributes and file id, which are
/// free with the listing and are the only cheap way to recognise a hard link, a
/// hidden file, or a file renamed between being listed and being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The full path, with the root's prefix already joined on.
    pub path: PathBuf,
    /// The logical size in bytes, as the directory reported it.
    pub size: u64,
    /// The `FILE_ATTRIBUTE_*` bits.
    pub attributes: u32,
    /// The file identifier the volume assigned, or `0`.
    pub id: u64,
}

impl Found {
    /// Whether the filesystem marks this as a link, junction or mount point.
    pub const fn is_reparse_point(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Whether Windows considers it hidden or a system file.
    pub const fn is_hidden_or_system(&self) -> bool {
        self.attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0
    }
}

/// What a descent found, and what it could not look at.
///
/// The second half is the point. A walk that returns only a file list cannot
/// distinguish a tree with nothing in it from a tree it was not allowed to
/// enter, and that ambiguity is exactly what this crate exists to remove — see
/// [`DescendOutcome::is_complete`], which is the one-line answer to "did this
/// walk actually look everywhere".
#[derive(Debug, Default, Clone)]
pub struct DescendOutcome {
    /// Every file found, in the walk's order.
    pub files: Vec<Found>,
    /// Directories that could not be listed, each with its reason.
    pub unreadable: Vec<Refused>,
    /// Reparse points that were not descended through, because
    /// [`DescendOptions::follow_links`] is off or because the target had already
    /// been visited.
    pub not_followed: Vec<PathBuf>,
    /// How many directories were encountered below the root.
    pub directories: u64,
    /// How many directories were not entered because of
    /// [`DescendOptions::max_depth`].
    ///
    /// Counted separately from `directories` so that a shallow walk reports the
    /// depth it stopped at rather than looking like a tree with nothing in it.
    pub depth_limited: u64,
}

impl DescendOutcome {
    /// Every file found.
    pub fn files(&self) -> &[Found] {
        &self.files
    }

    /// The total size of the files found.
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// Whether the walk looked at everything it was asked to.
    ///
    /// False when any directory refused to be listed, or when a reparse point
    /// was skipped, or when a depth limit stopped it. A caller that reports
    /// "clean" without checking this is reporting a clean scan of an unknown
    /// part of the tree.
    pub fn is_complete(&self) -> bool {
        self.unreadable.is_empty() && self.not_followed.is_empty() && self.depth_limited == 0
    }

    /// One sentence for a report, in the second person.
    pub fn sentence(&self) -> String {
        let files = self.files.len();
        if self.is_complete() {
            return format!(
                "looked at {files} {} in {} {}",
                if files == 1 { "file" } else { "files" },
                self.directories,
                if self.directories == 1 {
                    "directory"
                } else {
                    "directories"
                }
            );
        }
        let mut parts = Vec::new();
        if !self.unreadable.is_empty() {
            parts.push(format!("{} could not be listed", self.unreadable.len()));
        }
        if !self.not_followed.is_empty() {
            parts.push(format!("{} links were not followed", self.not_followed.len()));
        }
        if self.depth_limited > 0 {
            parts.push(format!(
                "{} were below the depth limit",
                self.depth_limited
            ));
        }
        format!(
            "looked at {files} {} and found {} it did not: {}",
            if files == 1 { "file" } else { "files" },
            if parts.len() == 1 { "one place" } else { "places" },
            parts.join(", ")
        )
    }
}

impl Reader {
    /// Walk a tree from `root`, listing every directory through this reader.
    ///
    /// `prune` is asked about each entry before it is used or descended into,
    /// and returning `true` drops it. That is where a caller's exclusions,
    /// protected-path rules and glob patterns go: what should be skipped is a
    /// property of the product, not of the filesystem, and this crate has no
    /// business having an opinion about it.
    ///
    /// The order is deterministic — each directory's entries sorted by name,
    /// case-insensitively, depth-first — so that two runs over one tree produce
    /// the same list and a diff of two reports means something.
    ///
    /// Nothing here panics, nothing recurses without a bound, and a directory
    /// that refuses to be listed is a line in the outcome rather than the end of
    /// the walk. A scan of `C:\` on an account that may not read half of it
    /// should still scan the half it can, and say which half it could not.
    pub fn descend<P>(&self, root: &Path, options: &DescendOptions, prune: P) -> DescendOutcome
    where
        P: Fn(&Path, &Entry) -> bool,
    {
        self.descend_reporting(root, options, prune, |_| {})
    }

    /// The same walk, calling `on_file` as each file is found.
    ///
    /// [`descend`](Reader::descend) is this with a callback that does nothing,
    /// and the difference is only ever about *when* a caller learns something.
    /// A tree of a million files takes long enough to enumerate that a front end
    /// showing progress needs to hear about files while the walk is running
    /// rather than after it — and a counter that stays at zero for thirty
    /// seconds and then jumps reads as a hung scan.
    ///
    /// `on_file` is called once per file, in the walk's order, before the walk
    /// moves on. It cannot stop the walk and cannot change it: what is found is
    /// decided by `prune` and by the filesystem, so a caller that wants to drop
    /// a file does it by not keeping it, which is exactly what the console and
    /// the window do with the size limit and their own exclusions.
    pub fn descend_reporting<P, F>(
        &self,
        root: &Path,
        options: &DescendOptions,
        prune: P,
        on_file: F,
    ) -> DescendOutcome
    where
        P: Fn(&Path, &Entry) -> bool,
        F: FnMut(&Found),
    {
        let mut walk = Walk {
            reader: self,
            options,
            prune,
            on_file,
            visited: HashSet::new(),
            outcome: DescendOutcome::default(),
        };
        walk.step(root, 1);
        walk.outcome
    }

    /// A directory's identity, on a platform with no volume serial to read.
    ///
    /// The Windows implementation is in the child module below, beside the
    /// `open_dir` it needs. Inherent methods resolve across modules, so the
    /// walk above calls `self.directory_id(..)` and gets whichever one this
    /// platform compiled.
    #[cfg(unix)]
    pub fn directory_id(&self, path: &Path) -> Result<(u32, u64), Refused> {
        use std::os::unix::fs::MetadataExt as _;

        // `classify_io` already returns a `Refused` carrying the path and the
        // reason, so it is returned rather than wrapped in another one: the
        // wrapping version asks for a `Why` and would not compile, and it took
        // a check against a non-Windows target to find that out — the `unix`
        // arm is compiled out on the only platform this product ships for.
        let meta = std::fs::metadata(path).map_err(|e| classify_io(path, &e))?;
        // The volume serial is 32 bits and `dev_t` is wider on some systems;
        // truncating is what the Windows implementation's own `(u32, u64)` does
        // with the volume serial it reads, so the two agree on what the pair
        // means even though they get it from different places.
        Ok((meta.dev() as u32, meta.ino()))
    }

    /// A directory's identity, on a platform that offers neither.
    #[cfg(not(any(windows, unix)))]
    pub fn directory_id(&self, path: &Path) -> Result<(u32, u64), Refused> {
        Err(Refused::new(
            path,
            Why::Unrepresentable {
                reason: "this platform offers no way to identify a directory, so a walk that \
                         follows links cannot tell a cycle from a descent",
            },
        ))
    }
}

/// One walk in progress.
///
/// A struct rather than parameters on a recursive function, because a descent
/// carries six things down through every level and passes all of them back
/// unchanged: the reader doing the listing, the two decisions the caller made
/// (what to prune, what to hear about), the set of directories already entered,
/// and the accumulator. Threaded as parameters that is eight arguments on a
/// function whose recursion is the only interesting part, and eight arguments
/// is eight chances to hand the next level the wrong one.
///
/// The reader is a borrow rather than a clone so that the privilege state the
/// walk was started with is the privilege state it finishes with.
struct Walk<'a, P, F> {
    reader: &'a Reader,
    options: &'a DescendOptions,
    prune: P,
    on_file: F,
    /// Directory identities already entered, as `(volume serial, file id)`.
    /// Only filled when links are being followed, because it is only then that
    /// a directory can be reached twice.
    visited: HashSet<(u32, u64)>,
    outcome: DescendOutcome,
}

impl<P, F> Walk<'_, P, F>
where
    P: Fn(&Path, &Entry) -> bool,
    F: FnMut(&Found),
{
    /// One level, then the level below it.
    ///
    /// Recursion rather than an explicit stack, because the depth is bounded by
    /// [`DescendOptions::max_depth`] and by the filesystem's own limit on how
    /// deep a path may be — a directory tree cannot be arbitrarily deep on
    /// Windows, because a path cannot exceed about 32,767 characters and each
    /// level costs at least two of them.
    fn step(&mut self, dir: &Path, depth: usize) {
        if depth > self.options.max_depth {
            self.outcome.depth_limited += 1;
            return;
        }

        // Cycle detection, paid for only when links are being followed. A
        // directory already on the current path is a directory whose contents
        // have already been listed, and entering it again is how a walk that
        // follows junctions stops terminating.
        if self.options.follow_links {
            match self.reader.directory_id(dir) {
                Ok(identity) => {
                    if !self.visited.insert(identity) {
                        self.outcome.not_followed.push(dir.to_path_buf());
                        return;
                    }
                }
                Err(_) => {
                    // The identity could not be established, so a cycle through
                    // this directory could not be ruled out. Not entering it is
                    // the conservative answer, and it is recorded rather than
                    // silently skipped.
                    self.outcome.not_followed.push(dir.to_path_buf());
                    return;
                }
            }
        }

        let mut entries = match self.reader.read_dir(dir) {
            Ok(entries) => entries,
            Err(refused) => {
                // The whole reason `DescendOutcome` keeps a list rather than a
                // count: the user needs to know *which* directory was closed to
                // them, because that is where to look by hand.
                self.outcome.unreadable.push(refused);
                return;
            }
        };
        entries.sort_by(|a, b| {
            // Case-insensitive because Windows filenames are, so this is the
            // order a person reading the directory would give; the original
            // name breaks ties so that two names differing only in case still
            // have a fixed order.
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.name.cmp(&b.name))
        });

        for entry in entries {
            let path = entry.path_in(dir);
            if (self.prune)(&path, &entry) {
                continue;
            }
            // Checked before the directory branch, so that a link to a *file* is
            // declined on the same terms as a link to a directory. Reading one
            // follows the link, so yielding it would scan the target under a
            // second name — and would do so for a user who explicitly asked for
            // links not to be followed.
            if entry.is_reparse_point() && !self.options.follow_links {
                self.outcome.not_followed.push(path);
                continue;
            }
            if entry.is_dir() {
                self.outcome.directories += 1;
                self.step(&path, depth + 1);
            } else {
                let found = Found {
                    path,
                    size: entry.size,
                    attributes: entry.attributes,
                    id: entry.id,
                };
                // Reported before it is pushed, so that a caller reading the
                // count and a caller reading the list never disagree about how
                // many files the walk has reached.
                (self.on_file)(&found);
                self.outcome.files.push(found);
            }
        }
    }
}

/// Walk a tree with the process-wide reader.
///
/// The counterpart of [`read_dir`], and privileged for the same reason.
pub fn descend<P>(root: &Path, options: &DescendOptions, prune: P) -> DescendOutcome
where
    P: Fn(&Path, &Entry) -> bool,
{
    crate::read::default_reader().descend(root, options, prune)
}

/// Walk a tree, reporting each file as it is found, with the process-wide
/// reader.
///
/// The counterpart of [`Reader::descend_reporting`], and what a caller with a
/// progress bar wants.
pub fn descend_reporting<P, F>(
    root: &Path,
    options: &DescendOptions,
    prune: P,
    on_file: F,
) -> DescendOutcome
where
    P: Fn(&Path, &Entry) -> bool,
    F: FnMut(&Found),
{
    crate::read::default_reader().descend_reporting(root, options, prune, on_file)
}

/// List a directory, or say why not, with the process-wide reader.
#[cfg(not(windows))]
pub fn try_read_dir(path: &Path) -> Result<Vec<Entry>, Refused> {
    crate::read::default_reader().read_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    #[test]
    fn a_directory_lists_what_is_in_it() {
        let dir = tempdir();
        std::fs::write(dir.path().join("one.txt"), b"1").unwrap();
        std::fs::write(dir.path().join("two.txt"), b"22").unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();

        let mut entries = Reader::ordinary().read_dir(dir.path()).expect("listable");
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["nested", "one.txt", "two.txt"]);

        let one = &entries[1];
        assert_eq!(one.size, 1);
        assert!(!one.is_dir());
        assert!(!one.is_reparse_point());

        let nested = &entries[0];
        assert!(nested.is_dir(), "the directory bit comes from the attributes");
        assert_eq!(nested.path_in(dir.path()), dir.path().join("nested"));
    }

    #[test]
    fn an_empty_directory_is_empty_and_not_an_error() {
        // The distinction the whole module turns on: a directory with nothing
        // in it and a directory that could not be listed must not produce the
        // same answer.
        let dir = tempdir();
        let entries = Reader::ordinary().read_dir(dir.path()).expect("listable");
        assert!(entries.is_empty(), "{entries:?}");
    }

    #[test]
    fn a_file_is_not_a_directory() {
        let dir = tempdir();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();

        let refused = Reader::ordinary()
            .read_dir(&file)
            .expect_err("a file cannot be listed as a directory");
        // Not `Gone`, and not a permission answer. `CreateFileW` on a file with
        // `FILE_LIST_DIRECTORY` fails with `ERROR_ACCESS_DENIED`, which is
        // genuinely what happened, so a denial is the honest report here — what
        // matters is that it is *a* diagnosis rather than a panic or a silent
        // empty list.
        assert!(
            matches!(
                refused.why,
                Why::Denied { .. } | Why::NotAFile { .. } | Why::Os { .. }
            ),
            "{refused}"
        );
    }

    #[test]
    fn a_missing_directory_is_gone() {
        let dir = tempdir();
        let refused = Reader::ordinary()
            .read_dir(&dir.path().join("no-such-place"))
            .expect_err("nothing is there");
        assert_eq!(refused.why, Why::Gone);
        assert!(refused.to_string().contains("no such file"), "{refused}");
    }

    #[test]
    fn a_large_directory_is_paged_and_comes_back_whole() {
        // Bigger than one 64 KiB round, so the continuation path is exercised
        // rather than assumed. The names are long enough to make the arithmetic
        // real: 400 entries of ~60 characters each is well past one buffer.
        let dir = tempdir();
        let expected: Vec<String> = (0..400).map(|i| format!("{:0>56}.bin", i)).collect();
        for name in &expected {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }

        let mut entries = Reader::ordinary().read_dir(dir.path()).expect("listable");
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names, expected,
            "a paged listing must return every entry exactly once"
        );
    }

    #[test]
    fn a_name_is_not_a_path() {
        let dir = tempdir();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let entries = Reader::ordinary().read_dir(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sub");
        assert!(
            !entries[0].name.contains('\\'),
            "the entry carries the name the directory reported, not a joined path"
        );
    }

    #[test]
    fn a_junction_is_flagged_rather_than_followed() {
        // The attribute bit is what stops a walk from looping forever, so it is
        // worth proving that the filesystem really reports it — a `mklink /J`
        // junction is a reparse point and needs no privilege to create, unlike a
        // symbolic link.
        let dir = tempdir();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("cmd is on every Windows install");
        if !made.status.success() {
            // Not a failure of the code under test: a filesystem or policy that
            // will not make a junction is a reason to skip, and saying so is
            // better than an assertion that means nothing on such a machine.
            eprintln!(
                "skipped: mklink /J failed: {}",
                String::from_utf8_lossy(&made.stdout)
            );
            return;
        }

        let entries = Reader::ordinary().read_dir(dir.path()).unwrap();
        let link = entries
            .iter()
            .find(|e| e.name == "link")
            .expect("the junction is listed");
        assert!(
            link.is_reparse_point(),
            "a junction must be flagged: {link}"
        );
        assert!(link.is_dir(), "a junction to a directory reports as one");
        assert!(link.to_string().contains("reparse"), "{link}");
    }

    #[test]
    fn a_hidden_file_is_listed_and_flagged() {
        // Listed, not skipped. The interesting files are frequently hidden, and
        // a walk that quietly dropped them would be reporting a clean directory
        // it had not really looked at.
        let dir = tempdir();
        let file = dir.path().join("hidden.txt");
        std::fs::write(&file, b"x").unwrap();
        let attrs = std::process::Command::new("attrib")
            .arg("+H")
            .arg(&file)
            .output()
            .expect("attrib is on every Windows install");
        assert!(attrs.status.success());

        let entries = Reader::ordinary().read_dir(dir.path()).unwrap();
        let hidden = entries
            .iter()
            .find(|e| e.name == "hidden.txt")
            .expect("a hidden file is still listed");
        assert!(hidden.is_hidden_or_system(), "{hidden}");
    }

    #[test]
    fn the_entry_display_names_the_things_a_walk_cares_about() {
        let dir = Entry {
            name: "thing.dll".to_string(),
            attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            size: 4096,
            id: 7,
        };
        let text = dir.to_string();
        assert!(text.contains("thing.dll/"), "{text}");
        assert!(text.contains("4096 bytes"), "{text}");
        assert!(text.contains("reparse"), "{text}");
        assert!(!text.contains('7'), "the id is not worth printing: {text}");
    }

    // -- descent ----------------------------------------------------------

    /// Build a tree and return its root, kept alive by the guard.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a").join("deep").join("deeper")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::write(root.join("top.txt"), b"0").unwrap();
        std::fs::write(root.join("a").join("one.txt"), b"1").unwrap();
        std::fs::write(root.join("a").join("deep").join("two.txt"), b"22").unwrap();
        std::fs::write(root.join("a").join("deep").join("deeper").join("three.txt"), b"333").unwrap();
        std::fs::write(root.join("b").join("four.txt"), b"4444").unwrap();
        dir
    }

    /// The discovered paths, relative to the root, in the walk's order.
    fn names(outcome: &DescendOutcome, root: &Path) -> Vec<String> {
        outcome
            .files()
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(root)
                    .unwrap_or(&f.path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn the_reporting_walk_names_every_file_once_and_in_the_same_order() {
        // The contract a progress bar depends on: every file is reported, each
        // exactly once, in the walk's own order, and the list and the callback
        // agree. A callback that fired twice for one file would double-count a
        // front end's "files found" while the list stayed right, which is the
        // kind of disagreement nobody notices until the numbers are compared.
        let dir = tree();
        let root = dir.path();

        let mut reported: Vec<PathBuf> = Vec::new();
        let outcome = descend_reporting(root, &DescendOptions::default(), |_, _| false, |found| {
            reported.push(found.path.clone());
        });

        let listed: Vec<PathBuf> = outcome.files().iter().map(|f| f.path.clone()).collect();
        assert_eq!(reported, listed);
        assert_eq!(reported.len(), 5, "{reported:?}");
        assert_eq!(
            names(&outcome, root),
            vec![
                "a/deep/deeper/three.txt",
                "a/deep/two.txt",
                "a/one.txt",
                "b/four.txt",
                "top.txt"
            ]
        );
    }

    #[test]
    fn the_reporting_walk_says_nothing_about_a_pruned_file() {
        // Pruning is a decision about the filesystem, made before a file is a
        // result, so a pruned file is not reported either. A front end that
        // counted files it went on to discard would show a total the scan would
        // never reach.
        let dir = tree();
        let mut reported = 0usize;
        let outcome = descend_reporting(
            dir.path(),
            &DescendOptions::default(),
            |path, _| path.extension().is_some_and(|e| e == "txt"),
            |_| reported += 1,
        );
        assert_eq!(reported, 0);
        assert!(outcome.files().is_empty());
    }

    #[test]
    fn a_descent_finds_every_file_and_is_deterministic() {
        let dir = tree();
        let outcome = descend(dir.path(), &DescendOptions::default(), |_, _| false);

        assert_eq!(
            names(&outcome, dir.path()),
            [
                "a/deep/deeper/three.txt",
                "a/deep/two.txt",
                "a/one.txt",
                "b/four.txt",
                "top.txt",
            ],
            "depth-first, each directory in case-insensitive name order"
        );
        assert_eq!(outcome.bytes(), 1 + 2 + 3 + 4 + 1);
        assert!(outcome.is_complete(), "{}", outcome.sentence());
        assert_eq!(outcome.directories, 4, "a, a/deep, a/deep/deeper, b");
    }

    #[test]
    fn the_order_does_not_depend_on_what_the_filesystem_returns() {
        // The property that makes two reports diffable. Asserted by walking
        // twice and by walking a freshly built copy of the same tree, because
        // the failure this guards against is order coming from the directory
        // index rather than from the sort.
        let first = tree();
        let second = tree();
        let a = descend(first.path(), &DescendOptions::default(), |_, _| false);
        let b = descend(first.path(), &DescendOptions::default(), |_, _| false);
        let c = descend(second.path(), &DescendOptions::default(), |_, _| false);
        assert_eq!(names(&a, first.path()), names(&b, first.path()));
        assert_eq!(names(&a, first.path()), names(&c, second.path()));
    }

    #[test]
    fn a_depth_limit_stops_the_walk_and_says_so() {
        let dir = tree();
        let outcome = descend(dir.path(), &DescendOptions::non_recursive(), |_, _| false);
        assert_eq!(names(&outcome, dir.path()), ["top.txt"]);
        assert_eq!(
            outcome.depth_limited, 2,
            "a and b were not entered; a/deep is not counted because a was never entered, so \
             the walk never had the chance to skip it"
        );
        assert!(
            !outcome.is_complete(),
            "a walk that stopped at a depth limit has not looked everywhere, and must not \
             report that it has"
        );
        assert!(outcome.sentence().contains("depth limit"), "{}", outcome.sentence());
    }

    #[test]
    fn a_pruned_directory_is_not_entered_at_all() {
        let dir = tree();
        let outcome = descend(dir.path(), &DescendOptions::default(), |path, entry| {
            entry.is_dir() && path.file_name().is_some_and(|n| n == "a")
        });
        assert_eq!(
            names(&outcome, dir.path()),
            ["b/four.txt", "top.txt"],
            "pruning a directory must drop its whole subtree, not just the directory"
        );
        assert_eq!(outcome.directories, 1, "only b was entered");
    }

    #[test]
    fn a_directory_that_cannot_be_listed_is_a_line_and_not_the_end() {
        // The claim the whole crate makes, one level up from reading. A walk
        // that stops at the first refusal is a walk that reports a clean tree
        // whenever the tree is protected.
        let dir = tree();
        let locked = dir.path().join("b");
        let locked_file = locked.join("four.txt");
        let output = std::process::Command::new("icacls")
            .arg(&locked)
            .args(["/deny", "*S-1-1-0:(RD)"])
            .output()
            .expect("icacls is on every Windows install");
        assert!(
            output.status.success(),
            "icacls failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );

        let outcome = descend(dir.path(), &DescendOptions::default(), |_, _| false);

        // Restore before asserting, so a failed assertion does not leave a
        // directory the user cannot open in their own temp folder.
        let _ = std::process::Command::new("icacls")
            .arg(&locked)
            .args(["/remove:d", "*S-1-1-0"])
            .output();

        assert_eq!(
            names(&outcome, dir.path()),
            [
                "a/deep/deeper/three.txt",
                "a/deep/two.txt",
                "a/one.txt",
                "top.txt",
            ],
            "the rest of the tree is still walked"
        );
        assert_eq!(outcome.unreadable.len(), 1, "{}", outcome.sentence());
        let refused = &outcome.unreadable[0];
        assert_eq!(refused.path(), locked);
        assert!(
            matches!(refused.why, Why::Denied { .. }),
            "a directory that was refused must be reported as refused, not as missing: {refused}"
        );
        assert!(!outcome.is_complete());
        assert!(outcome.sentence().contains("could not be listed"), "{}", outcome.sentence());
        let _ = locked_file;
    }

    #[test]
    fn a_junction_is_not_followed_by_default_and_does_not_loop_when_it_is() {
        // A junction pointing at its own parent is the classic infinite tree.
        // The default is not to follow it; with following on, the identity
        // tracking has to stop it.
        let dir = tree();
        let link = dir.path().join("a").join("loop");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(dir.path())
            .output()
            .expect("cmd is on every Windows install");
        if !made.status.success() {
            eprintln!(
                "skipped: mklink /J failed: {}",
                String::from_utf8_lossy(&made.stdout)
            );
            return;
        }

        let outcome = descend(dir.path(), &DescendOptions::default(), |_, _| false);
        assert!(
            outcome.not_followed.iter().any(|p| p == &link),
            "the junction is recorded as not followed: {outcome:?}"
        );
        assert_eq!(
            names(&outcome, dir.path()).len(),
            5,
            "not following it means each file is found once"
        );

        // With following on, the junction points back at the root, whose
        // identity is already in the visited set — so it is skipped rather
        // than entered, and the walk terminates.
        let followed = descend(
            dir.path(),
            &DescendOptions {
                follow_links: true,
                ..DescendOptions::default()
            },
            |_, _| false,
        );
        assert!(
            followed.not_followed.iter().any(|p| p == &link),
            "a junction back to an already-visited directory is a cycle and is not entered"
        );
        assert_eq!(names(&followed, dir.path()).len(), 5);
    }

    #[test]
    fn a_hidden_file_survives_the_walk_and_is_flagged() {
        let dir = tree();
        let hidden = dir.path().join("b").join("hidden.dll");
        std::fs::write(&hidden, b"x").unwrap();
        assert!(std::process::Command::new("attrib")
            .arg("+H")
            .arg(&hidden)
            .output()
            .unwrap()
            .status
            .success());

        let outcome = descend(dir.path(), &DescendOptions::default(), |_, _| false);
        let found = outcome
            .files()
            .iter()
            .find(|f| f.path == hidden)
            .expect("a hidden file is found");
        assert!(found.is_hidden_or_system(), "{found:?}");
    }

    #[test]
    fn a_complete_walk_says_so_and_an_incomplete_one_says_what_it_missed() {
        let dir = tree();
        let complete = descend(dir.path(), &DescendOptions::default(), |_, _| false);
        assert!(complete.is_complete());
        assert!(complete.sentence().contains("looked at 5 files"), "{}", complete.sentence());
        assert!(!complete.sentence().contains("did not"), "{}", complete.sentence());

        let shallow = descend(dir.path(), &DescendOptions::non_recursive(), |_, _| false);
        assert!(!shallow.is_complete());
        assert!(shallow.sentence().contains("did not"), "{}", shallow.sentence());
    }

    #[test]
    fn the_options_carry_the_two_decisions_and_nothing_else() {
        assert_eq!(DescendOptions::non_recursive().max_depth, 1);
        assert!(!DescendOptions::non_recursive().follow_links);
        assert_eq!(DescendOptions::default().max_depth, usize::MAX);
        assert!(
            !DescendOptions::default().follow_links,
            "following links is opt-in: a junction loop is the walk that never ends"
        );
    }
}
