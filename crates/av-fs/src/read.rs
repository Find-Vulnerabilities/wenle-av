//! Opening and reading a file, using every means this process has.
//!
//! # The order of operations, and why it is this order
//!
//! One handle, opened once, and everything asked of that handle:
//!
//! 1. **Build the name.** A path longer than `MAX_PATH` needs a `\\?\` prefix
//!    or `CreateFileW` fails with `ERROR_PATH_NOT_FOUND` on a file that is
//!    plainly there. The prefix turns off Win32's path normalisation, so it can
//!    only be applied to a name that needs no normalising — see `verbatim`,
//!    which refuses rather than guesses.
//! 2. **Open once**, with `FILE_FLAG_SEQUENTIAL_SCAN` because a scan reads the
//!    whole file front to back and telling the cache that is worth real
//!    throughput, and with `FILE_FLAG_BACKUP_SEMANTICS` when the caller holds
//!    the privilege, which is the flag that makes the DACL stop mattering.
//! 3. **Ask that handle what it is** — `GetFileInformationByHandle`. The
//!    attributes say whether this is a directory, and opening a directory
//!    *succeeds* under backup semantics, so without this check a directory named
//!    as a scan target would be read as a stream of bytes.
//! 4. **Ask that handle how big it is** — `GetFileSizeEx`, not the
//!    `std::fs::metadata` that would be a second open and a second chance to be
//!    refused, and a race with a file being written between the two.
//! 5. **Read from that handle** until it is exhausted or the size measured in
//!    step 4 is reached, whichever comes first.
//!
//! The alternative — `std::fs::metadata` for the length, then `std::fs::read`
//! — is three opens where one will do, and each open is a separate permission
//! decision that can be answered differently.
//!
//! # The ceiling
//!
//! [`Reader::DEFAULT_CEILING`] is four gibibytes. Past that, the read is
//! *refused* rather than truncated, and the reasoning is in [`Why::TooLarge`]:
//! a scanner that reads the first two gigabytes of a five-gigabyte file and
//! reports the result against the file is answering a question nobody asked,
//! and reporting the wrong length in the same structure as the right one is
//! worse than reporting nothing.
//!
//! # What this cannot do, stated plainly
//!
//! These are real limits of reading files on Windows, not gaps in this
//! implementation, and a product that claims "scans every file" without naming
//! them is claiming something untrue:
//!
//! * **A file another process holds without sharing it cannot be read at all.**
//!   `SeBackupPrivilege` bypasses *access checks*; it does not bypass sharing.
//!   The three attempts with a short backoff catch the common case of a file
//!   being written at the moment it is scanned, and nothing catches a file that
//!   is held open for the lifetime of a process. Reaching those means reading
//!   the volume's raw clusters and parsing the filesystem, which is a different
//!   program.
//! * **EFS-encrypted files need the key.** A file encrypted with `cipher /e` is
//!   readable only by an account holding the certificate, and the backup
//!   privilege does not decrypt it.
//! * **Files on a network share are subject to the server's answer**, not this
//!   machine's. The server decides, and a server that refuses this account
//!   refuses it whatever the local token holds.
//! * **A file that is offline or dehydrated** — a cloud placeholder with
//!   `FILE_ATTRIBUTE_OFFLINE` or `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` — can
//!   only be read by asking the cloud provider to fetch it, which this reader
//!   does not do. Reading it here would cause the recall, which is a network
//!   operation and a bill, and doing that as a side effect of a scan is not a
//!   decision a scanner gets to make on a user's behalf.
//!
//! None of these are detectable by trying harder; all of them are reported as
//! their own reason so that a scan's "could not read" list is a list of *known*
//! causes rather than a shrug.

use std::io;
use std::path::{Path, PathBuf};

use crate::budget::{self, Reservation};
use crate::privilege::{Privilege, Presence};
use crate::refusal::{Refused, Why};

/// A file's bytes, and the scan-memory budget they were reserved against.
///
/// # Why this is not a `Vec<u8>`
///
/// Because the reservation has to outlive the read. A file costs two times its
/// size while it is being scanned — the buffer here and the prefilter's
/// ASCII-folded copy of it — and the folded copy is made *after* this function
/// returns and lives until the scan of that file is over. A `Vec<u8>` released
/// the reservation at the end of the read, which is the moment the budget stops
/// describing what the process is holding; holding it in the return value is
/// what makes the number mean something. See [`mod@crate::budget`] for the
/// measurement that put this here.
///
/// It dereferences to the bytes, so a caller that wants `&[u8]`, a length, or an
/// iterator does not have to know this type exists.
#[derive(Debug)]
pub struct Held {
    data: Vec<u8>,
    /// Released when this value is dropped, which is the whole of its job.
    ///
    /// Never read: a caller that wants to know how much was reserved reads
    /// [`Budget::free`](crate::budget::Budget::free) instead.
    _held: Reservation<'static>,
}

impl Held {
    /// The bytes, as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// How many bytes were read.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the file was empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::ops::Deref for Held {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

/// The longest path, in UTF-16 code units, that Win32 will accept without
/// being told to stop counting.
///
/// `MAX_PATH` is 260 including the terminating NUL, but the documented safe
/// boundary is lower than that: a name at the limit can still be rejected once
/// a caller appends an 8.3 alias or a suffix of its own, which is why
/// `MAX_PATH - 12` is the number Microsoft's own guidance uses. A 248-unit path
/// is short enough to hand to `CreateFileW` unmodified in every case that
/// matters, and a longer one is given the `\\?\` prefix.
const MAX_UNPREFIXED: usize = 248;

/// One open-and-read, with everything that decides how it goes.
///
/// A reader is a *policy*: how large a file it will accept, how many times it
/// will retry a locked one, and whether it may use the backup privilege. It
/// holds no state between reads, so one can be shared across threads.
///
/// Build one with [`Reader::privileged`] or [`Reader::ordinary`] rather than a
/// `Default`, because the difference between those two is the whole point and a
/// default would hide which one a call site got.
#[derive(Debug, Clone, Copy)]
pub struct Reader {
    ceiling: u64,
    attempts: u32,
    backup: Presence,
}

impl Reader {
    /// The point past which a file is not read into memory at all.
    ///
    /// Four gibibytes. Chosen as the boundary of "a file a scan should hold in
    /// memory", not as a technical limit: the allocation would work on a
    /// 64-bit machine with room, and it would also be the largest thing the
    /// process ever does, on a machine where a scan is running alongside
    /// whatever the user is doing. See the module documentation for why this
    /// refuses rather than truncates.
    pub const DEFAULT_CEILING: u64 = 4 * 1024 * 1024 * 1024;

    /// How many times an open is attempted when the file is in use.
    ///
    /// Three, with 25 ms and then 50 ms between them. The case this exists for
    /// is a file being written at the moment the realtime watcher notices it:
    /// the writer holds it without sharing for a few milliseconds, and a single
    /// attempt would report a file that is perfectly readable a moment later as
    /// unreadable. The case it deliberately does not chase is a file held open
    /// for the lifetime of a process, where 75 ms of waiting buys nothing and
    /// three attempts keeps the cost of finding that out bounded.
    pub const DEFAULT_ATTEMPTS: u32 = 3;

    /// How long to wait before the second attempt, doubling for each one after.
    const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

    /// A reader that uses the backup privilege if this process can be given it.
    ///
    /// This **enables `SeBackupPrivilege` in the process token** on the way, and
    /// never turns it off again — see [`crate::privilege`] for what that costs
    /// and why it is per-process rather than per-call. An unelevated process
    /// does not have the privilege to enable, and this returns a reader that
    /// still works for every file the account can already read; the difference
    /// is visible in [`Reader::privilege`] and in the reason a refused read
    /// carries.
    pub fn privileged() -> Self {
        let backup = crate::privilege::enable(Privilege::Backup).unwrap_or(Presence::Unknown);
        Self {
            ceiling: Self::DEFAULT_CEILING,
            attempts: Self::DEFAULT_ATTEMPTS,
            backup,
        }
    }

    /// A reader that leaves the token alone.
    ///
    /// For a caller that has no business reading files whose permissions
    /// exclude it — the tests in this crate, a configuration reader, anything
    /// running inside a process whose privileges are somebody else's decision.
    pub fn ordinary() -> Self {
        Self {
            ceiling: Self::DEFAULT_CEILING,
            attempts: Self::DEFAULT_ATTEMPTS,
            backup: crate::privilege::query(Privilege::Backup).unwrap_or(Presence::Unknown),
        }
    }

    /// The same reader with a different ceiling.
    ///
    /// Takes `self` rather than `&mut self` so that the configured reader can
    /// be built in one expression, and so that a reader can never be changed
    /// out from under a thread that is using it.
    pub fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// The same reader with a different number of attempts at a locked file.
    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts.max(1);
        self
    }

    /// Whether this reader holds the privilege that makes a DACL stop mattering.
    pub const fn privilege(&self) -> Presence {
        self.backup
    }

    /// The ceiling currently in force.
    pub const fn ceiling(&self) -> u64 {
        self.ceiling
    }

    /// Read a file, or say why not.
    ///
    /// The structured form. Every reason in [`Why`] is a distinct state, and a
    /// caller that wants to branch on them — to retry, or to tell a user to
    /// elevate — needs this one rather than [`Reader::read`].
    #[cfg(windows)]
    pub fn try_read(&self, path: &Path) -> Result<Vec<u8>, Refused> {
        // The reservation is dropped here, at the end of the read, because this
        // caller has no way to hold it any longer — it asked for a `Vec<u8>`.
        // That still bounds the read itself; the scan path, which also holds the
        // prefilter's copy, goes through `read_capped` and keeps the
        // reservation. See `Held`.
        let (data, _held) = self.read_limited(path, None)?;
        Ok(data)
    }

    /// The body of both reads, with an optional caller-set limit.
    ///
    /// `limit` is `Some` only from [`Reader::read_capped`], where it means "the
    /// walk measured this file as fitting" — which is why exceeding it is
    /// [`Why::Grew`] rather than [`Why::TooLarge`]. See that variant.
    ///
    /// Returns the scan-memory reservation alongside the bytes rather than
    /// releasing it, because the caller that reads a file in order to scan it
    /// goes on to hold a second copy of it. See [`Held`].
    #[cfg(windows)]
    fn read_limited(&self, path: &Path, limit: Option<u64>) -> Result<(Vec<u8>, Reservation<'static>), Refused> {
        let name = verbatim(path).map_err(|reason| Refused::new(path, Why::Unrepresentable { reason }))?;

        let mut last: Why = Why::Gone;
        for attempt in 1..=self.attempts {
            match self.open_with(path, &name) {
                Ok(handle) => return self.read_handle(path, handle, limit),
                Err(why @ Why::InUse { .. }) => {
                    last = why;
                    if attempt < self.attempts {
                        // Linear-ish backoff: 25 ms, then 50 ms. Sleep is not a
                        // yield to the scanner's own threads, but a locked file
                        // is a wait on another *process*, which no amount of
                        // yielding here would shorten.
                        std::thread::sleep(Self::RETRY_BACKOFF * attempt);
                    }
                }
                Err(why) => return Err(Refused::new(path, why)),
            }
        }
        // Only reachable when every attempt was a lock, because every other
        // reason returns above. `last` carries the count so the message can say
        // how hard it tried.
        Err(Refused::new(
            path,
            match last {
                Why::InUse { .. } => Why::InUse {
                    attempts: self.attempts,
                },
                other => other,
            },
        ))
    }

    /// Read a file, or say why not, on a platform with no backup privilege.
    #[cfg(not(windows))]
    pub fn try_read(&self, path: &Path) -> Result<Vec<u8>, Refused> {
        // See the Windows one: this shape releases the reservation at the end of
        // the read, which is all this signature can offer.
        let (data, _held) = self.read_limited(path, None)?;
        Ok(data)
    }

    /// The portable body; see the Windows one for what `limit` means, and for
    /// why the reservation comes back with the bytes.
    #[cfg(not(windows))]
    fn read_limited(
        &self,
        path: &Path,
        limit: Option<u64>,
    ) -> Result<(Vec<u8>, Reservation<'static>), Refused> {
        let ceiling = limit.map_or(self.ceiling, |l| l.min(self.ceiling));
        let metadata = std::fs::metadata(path).map_err(|e| {
            Refused::new(
                path,
                if e.kind() == io::ErrorKind::NotFound {
                    Why::Gone
                } else {
                    Why::Os {
                        code: e.raw_os_error().unwrap_or(0) as u32,
                        message: e.to_string(),
                    }
                },
            )
        })?;
        if metadata.is_dir() {
            return Err(Refused::new(
                path,
                Why::NotAFile { attributes: 0x10 },
            ));
        }
        if metadata.len() > ceiling {
            return Err(Refused::new(
                path,
                over_reason(metadata.len(), limit, self.ceiling),
            ));
        }
        // As on Windows: the machine is asked first, so that a file it cannot
        // afford is refused rather than attempted. See [`affordable`].
        affordable(metadata.len()).map_err(|why| Refused::new(path, why))?;
        // Reserved before the read rather than after it, because the read is
        // the allocation: a reservation taken once the bytes are in hand has
        // nothing left to prevent.
        let held = budget::shared().reserve(metadata.len());
        // Read into a buffer whose capacity is reserved fallibly, and bounded by
        // `take` so that a file which grew since it was measured cannot make the
        // buffer grow again — `std::fs::read` would do both infallibly and abort
        // the process on a full machine. See the Windows path for the full
        // argument.
        let size = metadata.len();
        let mut data = Vec::new();
        if size > usize::MAX as u64 || data.try_reserve_exact(size as usize).is_err() {
            return Err(Refused::new(
                path,
                Why::OutOfMemory {
                    size,
                    available: budget::available_commit_bytes(),
                },
            ));
        }
        let file = std::fs::File::open(path).map_err(|e| {
            Refused::new(
                path,
                Why::Os {
                    code: e.raw_os_error().unwrap_or(0) as u32,
                    message: e.to_string(),
                },
            )
        })?;
        // Fully qualified rather than a `use` of the trait: this whole function
        // is `cfg(not(windows))`, and an import that only it needs would be an
        // unused import on the platform the product ships on.
        let mut bounded = io::Read::take(file, size);
        io::Read::read_to_end(&mut bounded, &mut data).map_err(|e| {
                Refused::new(
                    path,
                    Why::Os {
                        code: e.raw_os_error().unwrap_or(0) as u32,
                        message: e.to_string(),
                    },
                )
            })?;
        Ok((data, held))
    }

    /// Read a file, or return an [`io::Error`] carrying the reason as its
    /// message.
    ///
    /// The engine's error path turns a failed read into an `Unknown` verdict
    /// with the reason attached, and keeping the signature `io::Result<Vec<u8>>`
    /// means that path did not have to change to gain the better wording.
    ///
    /// The scan path uses [`Reader::read_capped`] instead, because it needs the
    /// memory reservation to outlive the read. This one releases it at the end
    /// of the read, which bounds the read and nothing after it.
    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.try_read(path).map_err(io::Error::from)
    }

    /// Read at most `ceiling` bytes, whatever this reader's own ceiling is.
    ///
    /// A lower ceiling only. Asking for a higher one gets this reader's, with a
    /// debug assertion saying so, because a caller that wants to read more than
    /// the configured maximum should build a reader that says so rather than
    /// passing a number to a call that quietly ignores it.
    pub fn read_up_to(&self, path: &Path, ceiling: u64) -> io::Result<Vec<u8>> {
        debug_assert!(
            ceiling <= self.ceiling,
            "read_up_to({ceiling}) is larger than this reader's own ceiling ({})",
            self.ceiling
        );
        let tighter = Self {
            ceiling: ceiling.min(self.ceiling),
            ..*self
        };
        tighter.read(path)
    }

    /// Read a file, refusing one that is larger than `cap`.
    ///
    /// `cap` is the size the caller believes the file to be — the size the
    /// directory walk measured. `None` means the caller set no limit, and this
    /// is then exactly [`Reader::read`].
    ///
    /// The difference from [`Reader::read_up_to`] is what being over the limit
    /// *means*, and it is the reason both exist. A ceiling is a policy: this
    /// product will not hold a four-gigabyte file in memory. A cap is a
    /// measurement: somebody looked at this file a moment ago and it fitted, so
    /// a file that does not fit now has changed, and that is worth saying in
    /// those words — see [`Why::Grew`]. Callers that walked a directory and
    /// then read what they found want this one.
    ///
    /// This is the one reader that returns [`Held`] rather than a bare
    /// `Vec<u8>`, because it is the one the scan path calls: the caller here
    /// goes on to have the rule engine build a second, folded copy of these
    /// bytes, and the memory budget has to be charged for that copy too. A
    /// caller that only wants the bytes gets them through `Deref` and notices
    /// nothing.
    pub fn read_capped(&self, path: &Path, cap: Option<u64>) -> io::Result<Held> {
        let (data, held) = match cap {
            None => self.read_limited(path, None),
            Some(cap) => {
                let tighter = Self {
                    ceiling: cap.min(self.ceiling),
                    ..*self
                };
                tighter.read_limited(path, Some(cap))
            }
        }
        .map_err(io::Error::from)?;
        Ok(Held {
            data,
            _held: held,
        })
    }

}

/// What the path names, asked before opening it, where that is knowable.
///
/// Three answers, and only one of them is a decision:
///
/// * a directory → [`Why::NotAFile`], because that is settled and the open
///   would report it as a permission problem for an ordinary reader;
/// * nothing at all → [`Why::Gone`], which saves an open that can only fail;
/// * anything else, **including the case where the attributes cannot be read**
///   → `None`, meaning "not established, let the open decide".
///
/// The last one is the important one. `GetFileAttributesW` is subject to the
/// same access checks as anything else, so a file this account may not stat
/// returns an error — and treating that error as a refusal here would replace
/// the open's precise reason with a guess made before trying.
#[cfg(windows)]
pub(crate) fn inspect(_path: &Path, name: &[u16]) -> Option<Why> {
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, INVALID_FILE_ATTRIBUTES,
    };

    // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the call.
    let attributes = unsafe { GetFileAttributesW(windows::core::PCWSTR(name.as_ptr())) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        // The call failed. Which failure it was is deliberately not read: this
        // function is a shortcut, and a shortcut that reports a reason the open
        // has not confirmed is worse than no shortcut. `Gone` is the one
        // exception, and it is taken below only when the operating system says
        // so specifically.
        let code = (unsafe { windows::Win32::Foundation::GetLastError() }).0;
        if code == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.0 {
            return Some(Why::Gone);
        }
        return None;
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Some(Why::NotAFile { attributes });
    }
    None
}

/// How much commit the read must leave behind for the process to keep running
/// on, beyond the file it is about to hold.
///
/// # Why a read reserves memory it is not going to use
///
/// Because the failure path allocates. Refusing a file builds a [`Refused`],
/// formats a sentence, and pushes both into a report the caller is assembling —
/// and every one of those is an allocation. A read that takes the last byte of
/// commit does not fail politely; it fails *while reporting that it failed*, and
/// the allocator aborts. That is measurable rather than theoretical: the crash
/// log that prompted this check held three lines, the first for a 4,193,376-byte
/// request and the two after it for 10,016 and 32,768 bytes — the first failure,
/// and then the two attempts to describe it.
///
/// 64 MiB is chosen to be absurdly more than a sentence needs, because the
/// number it has to beat is not "enough for a `String`" but "enough for the
/// dozen other threads that are about to run the same failure path at the same
/// moment".
const HEADROOM: u64 = 64 * 1024 * 1024;

/// Refuse a file the machine cannot afford to have read, before asking for it.
///
/// # Why this exists on top of the scan budget
///
/// The budget bounds how much file content one scan holds, and it is re-sized
/// from the machine on every reservation — but it cannot guarantee the memory is
/// still there when the allocation happens, for two reasons that both come down
/// to "the budget is a share and the machine is the whole":
///
/// * Everything else on the machine is spending from the same pool while the
///   scan runs. The ceiling falls as they do, and a scan that was admitted at
///   197 MiB is not told to give any of it back.
/// * The ceiling has a **floor** of 32 MiB, so a machine with 11 MB left to
///   commit is still granted a 32 MiB allowance. The floor is right — a budget
///   of zero would make every read wait for a release that can never come — but
///   it means the budget's answer and the machine's answer disagree on exactly
///   the machines where the difference matters.
///
/// So the machine is asked directly, with [`budget::available_commit_bytes`],
/// and the file is refused when the answer is that reading it would spend the
/// last of what is there. What the caller gets is a file reported as one that
/// could not be read and a sentence saying why — which is a worse answer than
/// scanning it, and a far better one than a process that disappears.
///
/// # Why it charges for two copies
///
/// Because two are resident at once, by the same accounting the budget uses —
/// see [`budget::COPIES_PER_FILE`]: the bytes this returns, and the ASCII-folded
/// copy the rule engine's prefilter builds from them. A check that counted one
/// copy would admit a file whose second copy cannot be allocated, and the second
/// copy is made by a `Vec::with_capacity` that aborts in exactly the same way.
fn affordable(size: u64) -> Result<(), Why> {
    affordable_for(size, budget::available_commit_bytes())
}

/// The decision [`affordable`] makes, for a known amount of free commit.
///
/// Split out so that it can be tested. A machine cannot be told to have 11 MB
/// left at a chosen moment, and the numbers this turns on are exactly the ones
/// that were wrong — so the arithmetic has to be checkable without one.
fn affordable_for(size: u64, free: Option<u64>) -> Result<(), Why> {
    let Some(free) = free else {
        // Not knowing is not a refusal. A machine that will not report its
        // commit is a machine whose reads are no worse than they were before
        // this check existed, and inventing a limit from a missing number would
        // refuse files on a machine that has plenty.
        return Ok(());
    };
    let needed = size.saturating_mul(budget::COPIES_PER_FILE);
    if needed.saturating_add(HEADROOM) <= free {
        return Ok(());
    }
    Err(Why::OutOfMemory {
        size,
        available: Some(free),
    })
}

/// Which "too big" reason a file that came out over the limit has earned.
///
/// Two situations look identical at the handle — a number larger than a limit —
/// and mean different things. When the caller set the limit, the file was
/// measured as fitting a moment ago and no longer does, which is a race worth
/// its own sentence. When nobody set one, the file is simply over this crate's
/// ceiling, which is a policy and not a surprise.
fn over_reason(size: u64, limit: Option<u64>, ceiling: u64) -> Why {
    match limit {
        Some(limit) if size > limit => Why::Grew { limit },
        _ => Why::TooLarge { size, ceiling },
    }
}

/// Whether a refusal should be read in the light of the backup privilege being
/// on, which changes what a [`Why::Denied`] means.
#[cfg(windows)]
pub(crate) fn backup_in_play(backup: Presence) -> bool {
    backup.is_enabled()
}

/// The Win32 error code inside a `windows`-crate error.
///
/// `Error::from_win32` builds an `HRESULT` with the original `GetLastError`
/// value in its low sixteen bits, so recovering it is a mask rather than a
/// lookup. One function rather than the mask spelled out at each of the six
/// call sites, because getting it wrong at one of them would mean a file
/// refused for a reason the code above then fails to recognise.
#[cfg(windows)]
pub(crate) fn code_of(error: &windows::core::Error) -> u32 {
    (error.code().0 & 0xFFFF) as u32
}

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE as RawHandle;

/// The operations that need the Win32 API, kept together so the portable
/// surface above reads as policy rather than as flag-juggling.
#[cfg(windows)]
impl Reader {
    /// Open the file, with or without backup semantics.
    ///
    /// Split from [`Reader::try_read`] so that the retry loop does not have to
    /// know which flags are in play, and so that the flag choice is in one
    /// place — the flags *are* the feature here, and scattering them would make
    /// the one thing that matters hardest to find.
    fn open_with(&self, path: &Path, name: &[u16]) -> Result<RawHandle, Why> {
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_SEQUENTIAL_SCAN,
            FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        // A directory is checked *before* the open, and this is not an
        // optimisation. Without `FILE_FLAG_BACKUP_SEMANTICS` — which an
        // ordinary reader does not pass — `CreateFileW` on a directory fails
        // with `ERROR_ACCESS_DENIED`, so the post-open attribute check below
        // would never get the chance to say "that is a directory" and the user
        // would be told their permissions were the problem. Asking the
        // attributes first costs one call and gives the right answer in both
        // modes. It can only improve the answer: when `GetFileAttributesW`
        // itself fails, for a file this account may not even stat, the open
        // still happens and its refusal is the one reported.
        if let Some(why) = inspect(path, name) {
            return Err(why);
        }

        // `FILE_FLAG_BACKUP_SEMANTICS` is not optional decoration when the
        // privilege is held: it is the flag that tells the object manager this
        // open is a backup, and without it `SeBackupPrivilege` grants nothing.
        // See `CreateFileW`'s documentation on backup and restore.
        let mut flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
        if backup_in_play(self.backup) {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }

        // The most permissive share mode there is. A scanner reads files other
        // processes are using, and asking for less would turn every file
        // another program happens to have open into an unreadable one — for no
        // benefit, because this handle is only ever read from.
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the
        // call; every other argument is a plain value; and the `Option`
        // arguments are `None`, which the API documents as "no security
        // attributes" and "no template file".
        let opened = unsafe {
            CreateFileW(
                windows::core::PCWSTR(name.as_ptr()),
                FILE_GENERIC_READ.0,
                share,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        };

        opened.map_err(|e| classify(path, e, backup_in_play(self.backup)))
    }

    /// Ask the open handle what it is, and how much of it there is.
    ///
    /// The reservation is taken inside the closure so that it is released on
    /// every path out of it — an error return drops it just as a success return
    /// hands it to the caller.
    fn read_handle(
        &self,
        path: &Path,
        handle: RawHandle,
        limit: Option<u64>,
    ) -> Result<(Vec<u8>, Reservation<'static>), Refused> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, GetFileSizeEx, ReadFile, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY,
        };

        let outcome = (|| -> Result<(Vec<u8>, Reservation<'static>), Refused> {
            // What is it? A directory opens successfully under backup
            // semantics, so this is not a theoretical check: without it,
            // `wenle scan C:\Users` would read a directory's metadata as if it
            // were the file's contents.
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: `handle` is open and was opened for reading, and `info`
            // is a correctly sized, correctly aligned output structure.
            unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|e| {
                Refused::new(
                    path,
                    Why::Os {
                        code: code_of(&e),
                        message: e.to_string(),
                    },
                )
            })?;
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                return Err(Refused::new(
                    path,
                    Why::NotAFile {
                        attributes: info.dwFileAttributes,
                    },
                ));
            }

            // How big is it? From the handle, not from a second open.
            // `GetFileSizeEx` writes a signed 64-bit count. `LARGE_INTEGER` is not
            // needed and, in this version of the bindings, is not in the module a
            // reader would look in.
            let mut size: i64 = 0;
            // SAFETY: `handle` is open and `size` is a correctly sized output.
            unsafe { GetFileSizeEx(handle, &mut size) }.map_err(|e| {
                Refused::new(
                    path,
                    Why::Os {
                        code: code_of(&e),
                        message: e.to_string(),
                    },
                )
            })?;
            let size = size.max(0) as u64;
            let ceiling = limit.map_or(self.ceiling, |l| l.min(self.ceiling));
            if size > ceiling {
                return Err(Refused::new(path, over_reason(size, limit, self.ceiling)));
            }
            // A `Vec<u8>` of this length has to be addressable, which is not
            // implied by the ceiling: on a 32-bit build the ceiling above is
            // larger than `usize` can express, and `vec![0; n]` would truncate
            // the length rather than fail.
            if size > usize::MAX as u64 {
                return Err(Refused::new(
                    path,
                    Why::TooLarge {
                        size,
                        ceiling: usize::MAX as u64,
                    },
                ));
            }
            if size == 0 {
                return Ok((Vec::new(), budget::shared().reserve(0)));
            }

            // Asked before the budget is, and refused before either the
            // reservation or the allocation happens. See [`affordable`]: the
            // budget bounds a scan's share of what the machine had, and this
            // asks what it has now.
            affordable(size).map_err(|why| Refused::new(path, why))?;

            // Reserved before the allocation, never after: the allocation is
            // the thing being bounded, and this is the line that stops twelve
            // workers each asking for a quarter of a gigabyte in the same
            // instant. Charged for the prefilter's copy as well as this one —
            // see `COPIES_PER_FILE` — because both are resident while this file
            // is being scanned.
            let held = budget::shared().reserve(size);

            // Read until the handle is exhausted or the measured size is
            // reached. Reading exactly the measured size rather than to EOF
            // means a file that grows while it is being scanned is read as the
            // file that was measured, which is the coherent answer; a file that
            // shrinks reports fewer bytes and is truncated to what was really
            // there rather than being padded with zeroes.
            //
            // `try_reserve_exact` rather than `vec![0u8; size]`, and the
            // difference is the whole reason this function has a `Why` to
            // return. `vec!` allocates infallibly: if the pages are not there,
            // Rust aborts the process, and a process that aborts cannot report
            // that it skipped a file. The reservation above makes this failure
            // unlikely; it cannot make it impossible, because the machine's
            // commit is spent by everything running on it and not only by this
            // scan. A file that cannot be afforded is refused, with a sentence
            // the user can act on, and the scan carries on.
            let mut data = Vec::new();
            if data.try_reserve_exact(size as usize).is_err() {
                return Err(Refused::new(path, Why::OutOfMemory {
                    size,
                    available: budget::available_commit_bytes(),
                }));
            }
            // Cannot allocate: the capacity is reserved, and `resize` only
            // writes zeroes into it. The memset is the price of not handing the
            // reader a slice of uninitialised memory.
            data.resize(size as usize, 0);
            let mut filled = 0usize;
            while filled < data.len() {
                let mut got = 0u32;
                // SAFETY: `handle` is open for reading, the slice starts inside
                // `data` and runs to its end, and `got` is a valid output.
                let result = unsafe {
                    ReadFile(
                        handle,
                        Some(&mut data[filled..]),
                        Some(&mut got),
                        None,
                    )
                };
                if let Err(e) = result {
                    return Err(Refused::new(
                        path,
                        Why::Os {
                            code: code_of(&e),
                            message: e.to_string(),
                        },
                    ));
                }
                if got == 0 {
                    break;
                }
                filled += got as usize;
            }
            data.truncate(filled);
            Ok((data, held))
        })();

        // SAFETY: `handle` came from `CreateFileW`, is still open, and is not
        // used after this point. Closed on the success and the failure path
        // alike, because a leaked handle in a scanner is a file that can never
        // be deleted for the life of the process.
        unsafe {
            let _ = CloseHandle(handle);
        }
        outcome
    }
}

/// Turn a failed `CreateFileW` into the reason it failed.
///
/// The codes are named rather than numeric at the call site because each one is
/// a different answer for the user, and `os error 32` is not an answer.
#[cfg(windows)]
pub(crate) fn classify(_path: &Path, error: windows::core::Error, backup: bool) -> Why {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_LOCK_VIOLATION, ERROR_PATH_NOT_FOUND,
        ERROR_SHARING_VIOLATION,
    };

    let code = code_of(&error);

    if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0 {
        // Both are `Gone`, and the second one is the honest approximation in
        // this list: `ERROR_PATH_NOT_FOUND` is also what comes back when a
        // *parent* directory refuses this process traverse. Telling those two
        // apart needs a second failed call and a guess, and the case it would
        // improve — a file inside a directory the scanner may not traverse —
        // is already reported by the directory walk, which fails on the parent
        // by name. So the leaf says "not there" and the parent says "denied",
        // and between them the user has the whole story.
        return Why::Gone;
    }
    if code == ERROR_ACCESS_DENIED.0 {
        return Why::Denied {
            backup_enabled: backup,
            code,
        };
    }
    if code == ERROR_SHARING_VIOLATION.0 || code == ERROR_LOCK_VIOLATION.0 {
        return Why::InUse { attempts: 1 };
    }
    Why::Os {
        code,
        message: error.message(),
    }
}

/// A path in the form `CreateFileW` needs, verbatim where that is required.
///
/// Returns the UTF-16 buffer *without* applying the `\\?\` prefix unless the
/// name is long enough to need it, because the prefix is not free: it turns off
/// the normalisation that turns `/` into `\`, strips trailing dots and spaces,
/// and resolves `.` and `..`, so a name carrying any of those must not be given
/// it. This function therefore *refuses* such a name rather than prefixing it
/// and producing a path to something that does not exist.
///
/// The threshold is [`MAX_UNPREFIXED`], and it is a real boundary rather than a
/// rounding: at or above it the name is rebuilt from its components in verbatim
/// form, below it the name is passed through exactly as the caller wrote it.
#[cfg(windows)]
pub(crate) fn verbatim(path: &Path) -> Result<Vec<u16>, &'static str> {
    use std::os::windows::ffi::OsStrExt as _;

    let plain: Vec<u16> = path.as_os_str().encode_wide().collect();
    if plain.len() < MAX_UNPREFIXED {
        let mut out = plain;
        out.push(0);
        return Ok(out);
    }

    let built = verbatim_string(path)?;
    let mut wide: Vec<u16> = std::ffi::OsStr::new(&built).encode_wide().collect();
    wide.push(0);
    Ok(wide)
}

/// Rebuild a long path in `\\?\` form, or say why it cannot be rebuilt.
///
/// Separate from `verbatim` and returning a `String` so that it can be tested
/// without a Windows API call and without a file that is 248 characters long:
/// the failure modes here — a relative path, a `.` component, a device name —
/// are the ones worth testing, and they are all decided before any system call.
#[cfg(windows)]
pub(crate) fn verbatim_string(path: &Path) -> Result<String, &'static str> {
    use std::path::{Component, Prefix};

    let mut head: Option<String> = None;
    let mut parts: Vec<String> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                head = Some(match prefix.kind() {
                    // Already verbatim, so it is left alone rather than being
                    // given a second prefix.
                    Prefix::VerbatimDisk(letter) => format!(r"\\?\{}:", letter as char),
                    Prefix::VerbatimUNC(server, share) => format!(
                        r"\\?\UNC\{}\{}",
                        server.to_string_lossy(),
                        share.to_string_lossy()
                    ),
                    Prefix::Verbatim(_) => return Err("it is a device path, not a filesystem path"),
                    Prefix::Disk(letter) => format!(r"\\?\{}:", letter as char),
                    Prefix::UNC(server, share) => format!(
                        r"\\?\UNC\{}\{}",
                        server.to_string_lossy(),
                        share.to_string_lossy()
                    ),
                    Prefix::DeviceNS(_) => {
                        return Err("it names a device rather than a file on a volume")
                    }
                });
            }
            Component::RootDir => {}
            // `Path::components` has already removed every `.` that is not
            // leading, and removing it is the *right* normalisation rather
            // than a loss: `C:\a\.\b` and `C:\a\b` name the same file, so a
            // rebuilt path without it still names that file under the prefix.
            // A leading `.` — a relative path — is caught by the missing
            // prefix below rather than here.
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(
                    "it contains a `..` component, which the \\\\?\\ prefix would not resolve",
                )
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
        }
    }

    let head = head.ok_or(
        "it is longer than MAX_PATH and is not an absolute path, so it has no \\\\?\\ form",
    )?;
    if parts.is_empty() {
        return Err("it names a volume and no file on it");
    }
    let mut out = head;
    for part in parts {
        out.push('\\');
        out.push_str(&part);
    }
    Ok(out)
}

/// The reader every scan uses unless a caller says otherwise.
///
/// # This enables a privilege in the process token
///
/// The first call enables `SeBackupPrivilege` if the token holds it, and the
/// privilege stays on for the life of the process — every thread, and every
/// module loaded into it. That is a deliberate decision and it is the reason
/// this is a named function rather than something that happens inside a read:
///
/// * It is what makes "scan every file" true rather than approximately true.
///   Without it, an unelevated service or an administrator's console scan
///   reports every file belonging to another account as unreadable, and those
///   are exactly the files a scanner is asked about.
/// * The alternative — enabling and disabling per file — costs two token calls
///   per file on a disk with a million of them, and gains a window measured in
///   microseconds that no attacker is inconvenienced by.
/// * The privilege only *bypasses access checks*. It grants no ability to write
///   and no ability to change a permission, so what a compromise of this
///   process gains is a read of files this account could not otherwise read.
///   That is a real gain for an attacker, and it is why the process that holds
///   it is the one this product hardens (`av-guard`), keeps small, and never
///   runs untrusted code in.
///
/// A caller that does not want this — a configuration reader, a test — builds
/// [`Reader::ordinary`] and gets a reader that leaves the token exactly as it
/// found it.
pub fn default_reader() -> &'static Reader {
    use once_cell::sync::Lazy;
    static DEFAULT: Lazy<Reader> = Lazy::new(|| {
        let reader = Reader::privileged();
        match reader.privilege() {
            Presence::Enabled => log::debug!(
                "scanning with SeBackupPrivilege enabled: files whose permissions exclude this \
                 account will be read"
            ),
            Presence::Disabled | Presence::Absent | Presence::Unknown => log::info!(
                "scanning without SeBackupPrivilege ({}): files whose permissions exclude this \
                 account will be reported as unreadable rather than skipped silently",
                reader.privilege()
            ),
        }
        reader
    });
    &DEFAULT
}

/// Read a file with the process-wide reader.
///
/// See [`default_reader`] for what that reader does to the process token. This
/// is the function the scan engine calls; a caller that wants to control the
/// privilege, the ceiling or the retry count builds its own [`Reader`].
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    default_reader().read(path)
}

/// Read a file with the process-wide reader, or say why not.
pub fn try_read(path: &Path) -> Result<Vec<u8>, Refused> {
    default_reader().try_read(path)
}

/// Read a file with the process-wide reader, refusing one larger than `cap`.
///
/// See [`Reader::read_capped`]; this is the console front end's path, which
/// knows from its own walk how big each file was. It returns [`Held`] rather
/// than a `Vec<u8>` for the reason given there: the reservation has to survive
/// until the scan of this file is over, and only the caller knows when that is.
pub fn read_capped(path: &Path, cap: Option<u64>) -> io::Result<Held> {
    default_reader().read_capped(path, cap)
}

/// Whether a path can be handed to the operating system at all.
///
/// Exposed because the file walk can use it to *skip* a name it could never
/// open, rather than making a system call per file to find out the same thing.
pub fn is_representable(path: &Path) -> bool {
    #[cfg(windows)]
    {
        verbatim(path).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        true
    }
}

/// A path in the form the reader will use, for a caller that wants to log or
/// compare it.
///
/// `None` when the path cannot be represented — the same condition
/// [`is_representable`] answers, for a caller that wants the form as well as
/// the yes.
pub fn represented_path(path: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let wide = verbatim(path).ok()?;
        // Drop the terminating NUL before converting back.
        let trimmed = wide.strip_suffix(&[0]).unwrap_or(&wide);
        Some(PathBuf::from(String::from_utf16_lossy(trimmed)))
    }
    #[cfg(not(windows))]
    {
        Some(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn a_file_the_machine_cannot_afford_is_refused_rather_than_attempted() {
        // The defect this was written for, as arithmetic. The machine in the
        // crash log had 11,193,360 bytes left to commit and the read asked for
        // 4,193,376 — which fits, twice over, and that is the point: it is not
        // the file that has to fit, it is the file plus the headroom, because
        // the refusal itself allocates. The request failed anyway, and the
        // process aborted.
        let refused = affordable_for(4 * MIB, Some(11 * MIB));
        match refused {
            Err(Why::OutOfMemory { size, available }) => {
                assert_eq!(size, 4 * MIB);
                assert_eq!(available, Some(11 * MIB));
            }
            other => panic!("a machine with 11 MiB free must refuse a 4 MiB file: {other:?}"),
        }
    }

    #[test]
    fn the_headroom_is_charged_beyond_the_two_copies() {
        // The boundary, exactly: two copies of 1 MiB is 2 MiB, plus the 64 MiB
        // headroom is what has to be free.
        let just_enough = 2 * MIB + 64 * MIB;
        assert!(affordable_for(MIB, Some(just_enough)).is_ok());
        assert!(
            affordable_for(MIB, Some(just_enough - 1)).is_err(),
            "one byte short of the headroom is short of the headroom"
        );
    }

    #[test]
    fn an_ordinary_file_on_a_machine_with_room_is_admitted() {
        // The other direction, and the one that matters more often: this check
        // must not refuse anything on a machine that is merely busy. A 200 MB
        // file with 1 GiB free needs 400 MB plus headroom, which fits.
        assert!(affordable_for(200 * MIB, Some(1024 * MIB)).is_ok());
    }

    #[test]
    fn a_machine_that_will_not_report_its_commit_refuses_nothing() {
        // Not knowing is a different fact from knowing there is no room, and
        // only one of them justifies turning a scan away.
        assert!(affordable_for(u64::MAX / 2, None).is_ok());
    }

    #[test]
    fn the_two_copies_are_counted_so_that_the_folded_copy_fits_too() {
        // A file whose own bytes fit but whose folded copy does not is a file
        // that would be read and then abort the process building the copy: the
        // prefilter allocates with `Vec::with_capacity`, which is infallible in
        // the same way `vec!` is. So the check charges for both.
        let ten = 10 * MIB;
        assert!(
            affordable_for(ten, Some(2 * ten + 64 * MIB - 1)).is_err(),
            "one copy plus headroom is not enough for a file that needs two"
        );
        assert!(affordable_for(ten, Some(2 * ten + 64 * MIB)).is_ok());
    }

    #[test]
    fn the_default_ceiling_is_the_documented_one() {
        assert_eq!(Reader::DEFAULT_CEILING, 4 * 1024 * 1024 * 1024);
        assert_eq!(Reader::DEFAULT_ATTEMPTS, 3);
        let ordinary = Reader::ordinary();
        assert_eq!(ordinary.ceiling(), Reader::DEFAULT_CEILING);
        assert_eq!(ordinary.with_ceiling(1024).ceiling(), 1024);
    }

    #[test]
    fn a_zero_attempt_reader_still_tries_once() {
        // `with_attempts(0)` would make the retry loop run zero times and
        // return the initial `Gone` for a file that is sitting right there.
        // Clamping to one is the difference between a configuration mistake and
        // a scanner that reads nothing.
        let reader = Reader::ordinary().with_attempts(0);
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("present.txt");
        std::fs::write(&path, b"hello").expect("write");
        assert_eq!(reader.read(&path).expect("read"), b"hello");
    }

    #[test]
    fn an_ordinary_reader_reads_a_file_the_account_can_read() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("file.txt");
        std::fs::write(&path, b"the quick brown fox").expect("write");
        assert_eq!(
            Reader::ordinary().read(&path).expect("read"),
            b"the quick brown fox"
        );
    }

    #[test]
    fn an_empty_file_reads_as_no_bytes_and_not_as_an_error() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("empty.bin");
        std::fs::File::create(&path).expect("create");
        let data = Reader::ordinary().read(&path).expect("read");
        assert!(data.is_empty());
    }

    #[test]
    fn a_missing_file_is_not_found_rather_than_a_refusal() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("nothing-here");
        let refused = Reader::ordinary().try_read(&path).expect_err("no such file");
        assert_eq!(refused.why, Why::Gone, "{refused}");
        assert!(!refused.why.needs_elevation());
    }

    #[test]
    fn a_directory_is_refused_as_not_a_file() {
        // This is the check that stops `wenle scan <a directory>` from reading
        // a directory's metadata as if it were a file's contents. Under backup
        // semantics `CreateFileW` on a directory *succeeds*, so the guard is
        // the attribute test rather than the open.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let refused = Reader::ordinary()
            .try_read(dir.path())
            .expect_err("a directory is not a file");
        assert!(
            matches!(refused.why, Why::NotAFile { .. }),
            "{refused}"
        );
    }

    #[test]
    fn a_file_bigger_than_the_ceiling_is_refused_rather_than_truncated() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("big.bin");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(&vec![0x41u8; 4096]).expect("write");
        drop(file);

        let reader = Reader::ordinary().with_ceiling(1024);
        let refused = reader.try_read(&path).expect_err("over the ceiling");
        match refused.why {
            Why::TooLarge { size, ceiling } => {
                assert_eq!(size, 4096);
                assert_eq!(ceiling, 1024);
            }
            other => panic!("{other:?}"),
        }
        // And the same file under a ceiling it fits in is read whole.
        let reader = Reader::ordinary().with_ceiling(8192);
        assert_eq!(reader.read(&path).expect("read").len(), 4096);
    }

    #[test]
    fn read_up_to_tightens_and_never_loosens() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("medium.bin");
        std::fs::write(&path, vec![0u8; 2048]).expect("write");

        let reader = Reader::ordinary().with_ceiling(4096);
        // A tighter ceiling is applied. The number in the message is grouped
        // into thousands, so the needle is too: `2,048` and not `2048`.
        let refused = reader.read_up_to(&path, 1024).expect_err("over the limit");
        assert!(refused.to_string().contains("2,048"), "{refused}");
        // The reader's own ceiling is enough on its own.
        assert_eq!(reader.read_up_to(&path, 4096).expect("read").len(), 2048);
    }

    #[test]
    fn read_capped_refuses_a_file_that_grew_past_the_walk_s_measurement() {
        // The console front end walks a directory, records each file's size,
        // and then reads the ones it found. A file that is bigger by the time
        // it is read has changed under the scan, and the reason says *that*
        // rather than calling it a ceiling — which is the whole difference
        // between `read_capped` and `read_up_to`.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("grew.bin");
        std::fs::write(&path, vec![0u8; 4096]).expect("write");

        let reader = Reader::ordinary();
        let refused = reader
            .read_capped(&path, Some(1024))
            .expect_err("it grew past the measurement");
        let text = refused.to_string();
        assert!(text.contains("grew past"), "{text}");
        assert!(text.contains("1,024"), "{text}");

        // And a cap that is right is not a refusal.
        assert_eq!(
            reader.read_capped(&path, Some(4096)).expect("read").len(),
            4096
        );
        // A cap of `None` is the ordinary read, and does not invent a limit.
        assert_eq!(reader.read_capped(&path, None).expect("read").len(), 4096);
    }

    #[test]
    fn read_capped_never_loosens_the_readers_own_ceiling() {
        // A caller passing a cap larger than the reader's ceiling gets the
        // smaller of the two. A cap is a promise the caller can keep; the
        // ceiling is the product's own limit and a caller cannot talk it up.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("medium.bin");
        std::fs::write(&path, vec![0u8; 2048]).expect("write");
        let reader = Reader::ordinary().with_ceiling(1024);
        let refused = reader
            .read_capped(&path, Some(65536))
            .expect_err("the ceiling still applies");
        assert!(refused.to_string().contains("2,048"), "{refused}");
    }

    #[test]
    fn a_file_the_scan_engine_would_meet_reads_correctly_through_the_reader() {
        // Not a synthetic buffer: real bytes with a NUL inside, because a
        // reader that stops at the first zero byte would pass every test above
        // and fail on every executable.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("with-nuls.bin");
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        std::fs::write(&path, &payload).expect("write");
        assert_eq!(Reader::ordinary().read(&path).expect("read"), payload);
    }

    #[test]
    fn a_path_cannot_be_represented_relative_and_long() {
        // A relative path longer than MAX_PATH has no `\\?\` form, because the
        // prefix requires a fully qualified name. The honest answer is a
        // refusal naming that, not a prefix on a name that has no drive.
        let long = "d/".repeat(200) + "file.txt";
        let path = PathBuf::from(&long);
        let refused = Reader::ordinary()
            .try_read(&path)
            .expect_err("relative and long");
        assert!(
            matches!(refused.why, Why::Unrepresentable { .. }),
            "{refused}"
        );
        assert!(!is_representable(&path));
    }

    #[test]
    fn an_ordinary_path_is_passed_through_unchanged() {
        // Short paths are not prefixed, because the prefix would change what
        // Win32 does with them.
        let path = Path::new(r"C:\Windows\System32\kernel32.dll");
        assert!(is_representable(path));
        assert_eq!(represented_path(path).as_deref(), Some(path));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn a_long_absolute_path_is_rebuilt_in_verbatim_form() {
        let long = format!(r"C:\{}\file.txt", "sub\\".repeat(100));
        let path = PathBuf::from(&long);
        let rebuilt = verbatim_string(&path).expect("rebuildable");
        assert!(rebuilt.starts_with(r"\\?\C:\"), "{rebuilt}");
        assert!(rebuilt.ends_with(r"\file.txt"), "{rebuilt}");
        // And the reader takes it: the name is representable even though it is
        // far past MAX_PATH.
        assert!(is_representable(&path));
    }

    #[test]
    fn a_long_unc_path_uses_the_unc_form_and_not_a_drive_letter() {
        let path = PathBuf::from(format!(r"\\server\share\{}\file.txt", "a\\".repeat(100)));
        let rebuilt = verbatim_string(&path).expect("rebuildable");
        assert!(rebuilt.starts_with(r"\\?\UNC\server\share\"), "{rebuilt}");
    }

    #[test]
    fn a_parent_component_is_refused_rather_than_prefixed() {
        // The prefix turns off normalisation, so `..` inside it would name a
        // literal directory called `..` — a path to nothing, discovered only as
        // a mystifying "file not found". Refusing is the honest answer.
        let parent = PathBuf::from(format!(r"C:\{}\..\file.txt", "sub\\".repeat(100)));
        assert!(verbatim_string(&parent).is_err());
    }

    #[test]
    fn a_current_directory_component_is_dropped_because_that_names_the_same_file() {
        // `Path::components` removes every non-leading `.` for us, and removing
        // it is correct rather than lossy: `C:\a\.\b` and `C:\a\b` are the same
        // file, so the rebuilt name still names it. The test asserts the
        // rebuilt path, not merely that it succeeded, because "it did not
        // error" would also be true of a rebuild that dropped a real component.
        let path = PathBuf::from(format!(r"C:\{}\.\file.txt", "sub\\".repeat(100)));
        let rebuilt = verbatim_string(&path).expect("rebuildable");
        assert!(rebuilt.starts_with(r"\\?\C:\"), "{rebuilt}");
        assert!(rebuilt.ends_with(r"\file.txt"), "{rebuilt}");
        assert!(!rebuilt.contains(r"\."), "{rebuilt}");
        // And a leading `.` — a relative path, which has no verbatim form —
        // is still refused, one component earlier than before.
        assert!(verbatim_string(Path::new("./file.txt")).is_err());
    }

    #[test]
    fn a_device_name_is_refused() {
        assert!(verbatim_string(Path::new(r"\\.\PhysicalDrive0")).is_err());
    }

    #[test]
    fn a_volume_with_no_file_on_it_is_refused() {
        assert!(verbatim_string(Path::new(r"C:\")).is_err());
    }

    #[test]
    fn a_short_verbatim_path_is_not_prefixed_twice() {
        let path = Path::new(r"C:\Windows\notepad.exe");
        let rebuilt = verbatim_string(path).expect("rebuildable");
        assert_eq!(rebuilt, r"\\?\C:\Windows\notepad.exe");
        assert!(!rebuilt.contains(r"\\?\\\?\"), "{rebuilt}");
    }

    #[test]
    fn a_relative_path_short_enough_to_need_no_prefix_is_left_alone() {
        // Relative paths under MAX_PATH are fine: Win32 resolves them against
        // the process's current directory, and that is the documented
        // behaviour a caller passing a relative path expects.
        let path = Path::new(r"target\debug\wenle.exe");
        assert!(is_representable(path));
        assert_eq!(represented_path(path).as_deref(), Some(path));
    }
}
