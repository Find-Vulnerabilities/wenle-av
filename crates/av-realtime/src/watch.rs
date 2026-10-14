//! The Win32 half: one directory handle and one thread per watched root.
//!
//! # The call this crate is built on
//!
//! `ReadDirectoryChangesW` on a directory handle opened with `FILE_LIST_DIRECTORY`
//! and `FILE_FLAG_BACKUP_SEMANTICS`. The second flag is the one that is easy to
//! miss: without it `CreateFileW` refuses to open a *directory* at all, because
//! the default semantics are for files.
//!
//! The handle is opened `FILE_FLAG_OVERLAPPED`, and that choice is what makes a
//! clean shutdown possible. A synchronous `ReadDirectoryChangesW` blocks until
//! something changes in the tree, which can be minutes, and the only ways out of
//! it are a cancellation from another thread or closing the handle underneath it.
//! With an overlapped read the thread owns an event handle, waits on it with a
//! timeout of [`POLL_MS`], and checks a stop flag each time it wakes. The price
//! is a thread that wakes four times a second to read one atomic; the benefit is
//! a watcher that stops when it is told to rather than when the user's Downloads
//! folder next changes.
//!
//! # Why the `OVERLAPPED` is a local of the watch function and not a field
//!
//! Because the kernel writes into it when the read completes, and it does not
//! know when this thread's frame goes away. Keeping it on the watch thread's own
//! stack, in the same function that issues and reaps every read, means its
//! address is fixed for as long as any read can be outstanding. A struct that
//! owned it would be a struct that could be moved while a read was pending,
//! which is a use-after-free that shows up under load and nowhere else.
//!
//! Both ways out of the loop therefore cancel the read and reap it before
//! returning, so the frame is never left holding a live completion.
//!
//! # What the kernel does not report
//!
//! Only changes made while a read is outstanding. A directory handle with no
//! pending `ReadDirectoryChangesW` accumulates nothing, so a file created
//! between `CreateFileW` and the first issue is never mentioned by this watch —
//! measured, not assumed: `a_change_made_before_the_watch_starts_is_never_reported`
//! writes a file into a directory, starts a watch on it, and gets silence. That
//! is why [`DirectoryWatch::start`] does not return until every root's first
//! read is live, and why the same window, reappearing in miniature between
//! reaping one read and issuing the next, is part of what
//! [`crate::service`]'s re-scan machinery exists to cover rather than something
//! this crate claims never happens.
//!
//! It is worth being precise about what that costs, because it is the honest
//! limit of a user-mode watcher and not a bug to be found in production: a file
//! that is created into a watched tree while the watch is live *is* reported,
//! and a file that was already there is not — which is the opposite of the
//! guarantee a full scan gives, and the reason the two are run together.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::error::{RealtimeError, Result};
use crate::notify::{parse, Change, NotifyBatch, NotifyError};
use crate::plan::{WatchPlan, BUFFER_BYTES};

/// How often a blocked watch thread wakes to notice a stop request.
///
/// This one is not measured, and does not need to be: it is a straight trade
/// between shutting down promptly and waking up for nothing, and both sides are
/// known without an experiment — 250 ms means `stop()` takes at most a quarter
/// of a second, and the cost is four wakeups a second per watched root, each of
/// which reads one atomic and goes back to sleep. Zero would be a spin loop; a
/// second and up would make stopping the watcher feel like a hang.
///
/// Contrast [`crate::debounce::SETTLE_FLOOR_MS`], which *is* measured, because
/// there the question is how long the machine takes to report a file creation
/// and nothing but a measurement answers it.
pub const POLL_MS: u32 = 250;

/// How long [`DirectoryWatch::start`] waits for one root to become live.
///
/// The work being waited for is one `CreateFileW`, one `CreateEventW` and one
/// `ReadDirectoryChangesW` — three local calls with no device I/O. The bound is
/// not a measurement of those; it is the point at which a root that is *never*
/// going to arm stops being worth waiting for, so that a directory that has been
/// disconnected or made unreadable delays the caller by a fixed small amount
/// instead of forever. By the time it expires the failure has already been
/// reported as a [`WatchEvent::Failed`].
pub const ARM_DEADLINE: Duration = Duration::from_secs(2);

/// Something happened under a watched root.
#[derive(Debug)]
pub enum WatchEvent {
    /// The kernel reported one or more changes.
    Changed {
        /// The root the changes are relative to.
        root: PathBuf,
        /// The changes, in the order the kernel reported them.
        changes: Vec<Change>,
    },
    /// Changes happened that this crate was not told about.
    ///
    /// **The response is a re-scan of `root`.** Both causes below mean the same
    /// thing to a caller — there are files in this tree whose creation was never
    /// examined — and a caller that logs this and carries on has left a gap in
    /// the protection it is reporting as running.
    Lost {
        /// The root whose events were lost.
        root: PathBuf,
        /// Why they were lost.
        because: Lost,
    },
    /// A root is no longer being watched at all.
    ///
    /// The thread that watched it has ended. Nothing under this root will be
    /// scanned again until the watcher is restarted, which is why this is
    /// reported on the same channel as the events rather than written to a log
    /// file nobody reads.
    Failed {
        /// The root that is no longer watched.
        root: PathBuf,
        /// What went wrong.
        error: RealtimeError,
    },
}

/// Why changes were lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lost {
    /// More happened than the buffer could hold.
    ///
    /// The kernel says so by completing the read with no bytes written. Raising
    /// [`BUFFER_BYTES`] makes this rarer; nothing makes it impossible, because
    /// the burst that produces it is by definition unbounded.
    BufferOverflow,
    /// The kernel wrote a buffer that is not a valid sequence of records.
    ///
    /// Distinguished from the overflow because it is a different kind of
    /// problem: an overflow is a capacity limit that was reached, and this is
    /// the notification format not being what this code believes it is. Both
    /// leave the same hole in the coverage, so both cause the same re-scan, but
    /// only one of them is worth investigating.
    Malformed(NotifyError),
}

/// The sentence a client shows for each kind of loss.
///
/// Here rather than at the two call sites that need it — a log line and the
/// status a client reads — because the variant list is this module's, and a
/// second spelling of it elsewhere is the copy that goes stale when a variant is
/// added. Written for a user rather than for a developer: what they need to know
/// is whether the hole in the coverage is a limit that was reached or a fault
/// worth investigating, which is the distinction [`Lost`] itself draws.
impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow => f.write_str(
                "more changes arrived at once than the notification buffer could hold",
            ),
            Self::Malformed(_) => f.write_str(
                "the notification buffer was not a valid sequence of records",
            ),
        }
    }
}

/// Signals exactly once, when a root's watch becomes live.
///
/// A guard rather than a bare send, because both halves of the contract matter
/// to the caller waiting in [`DirectoryWatch::start`]: a root that never arms —
/// one whose directory cannot be opened — must still release that wait, and a
/// root that does arm must not release it twice. Two signals from one root would
/// let the caller stop waiting for a second root that has not started yet, which
/// is the whole guarantee being given up to make the happy path simpler.
#[derive(Debug)]
struct Arming {
    /// Taken by the first [`Arming::signal`], which is what makes the send
    /// single-shot.
    armed: Option<Sender<()>>,
}

impl Arming {
    /// A guard holding the sender that releases one waiter.
    fn new(armed: Sender<()>) -> Self {
        Self { armed: Some(armed) }
    }

    /// Report that this root is live, if it has not been reported already.
    fn signal(&mut self) {
        if let Some(tx) = self.armed.take() {
            // A send that fails means `start` has stopped waiting, which happens
            // when a previous root's arm timed out. Nothing is left to tell.
            let _ = tx.send(());
        }
    }
}

/// A running set of directory watches.
///
/// Owns one thread per root, each with its own directory handle. Dropping the
/// watcher without calling [`DirectoryWatch::stop`] still stops it — the threads
/// see the stop flag within [`POLL_MS`] and end — but `stop` is what waits for
/// them, so a caller that is about to delete the watched tree should call it.
///
/// That first claim is a promise only because of the `Drop` below. It was
/// written before the `Drop` existed and was false for as long as that lasted:
/// the threads hold their own `Arc` clone of the flag, so dropping the struct
/// dropped one reference to a flag nobody had set, left every thread spinning on
/// `wait_for`, and detached the `JoinHandle`s so that nothing could ever join
/// them. A watcher dropped on the floor kept its threads and its directory
/// handles for the life of the process, silently, with the documentation saying
/// the opposite.
#[derive(Debug)]
pub struct DirectoryWatch {
    events: Receiver<WatchEvent>,
    stop: Arc<AtomicBool>,
    threads: Vec<(PathBuf, std::thread::JoinHandle<()>)>,
}

impl Drop for DirectoryWatch {
    /// Set the stop flag, and deliberately do **not** wait.
    ///
    /// This is the half of the pair that has to run unconditionally, including
    /// on the paths that never reach [`DirectoryWatch::stop`] — an early return,
    /// a `?`, a panic, or the value simply going out of scope. Setting the flag
    /// is bounded work; waiting is not, and cannot be, because a thread sitting
    /// inside a `CreateFileW` on a disconnected share does not see the flag until
    /// that call returns. See [`DirectoryWatch::start`] for why that case is real
    /// enough to have shaped the arming deadline.
    ///
    /// `stop` is the one that waits, for the caller that needs the threads gone
    /// before the next statement runs.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl DirectoryWatch {
    /// Start watching every root in `plan`.
    ///
    /// A root that cannot be opened is reported as a [`WatchEvent::Failed`] on
    /// the event stream and does not stop the others: one unreadable directory —
    /// a disconnected network drive, a permissions change — must not cost the
    /// user the watches that are working.
    ///
    /// # This returns only once every root is armed
    ///
    /// `ReadDirectoryChangesW` reports changes from the moment it is issued and
    /// not before. Between opening a directory and issuing that first read there
    /// is therefore a window in which a file can appear and never be mentioned
    /// again by this watch — the record is not buffered for a handle that has no
    /// read pending, which
    /// `a_change_made_before_the_watch_starts_is_never_reported` demonstrates
    /// against a real filesystem. If `start` returned inside that window, the
    /// window would be the caller's own next few instructions, and the first
    /// thing a caller does after starting a watcher is look at what is already
    /// there.
    ///
    /// So the wait is moved into `start`, where it costs one signal per root,
    /// and the guarantee handed back is the useful one: **anything that happens
    /// in a watched tree after `start` returns will be reported.** A root that
    /// cannot arm at all releases the wait by failing, which it has already
    /// reported on the event stream.
    ///
    /// The wait is bounded by [`ARM_DEADLINE`], counted once for the whole set
    /// rather than once per root. The bound is not decoration: a watched
    /// directory on a disconnected network share can sit inside `CreateFileW`
    /// for a long time, and a startup that blocked on it would be a startup that
    /// never finishes. What that costs is exact and worth stating — a root whose
    /// thread is still in that call when the deadline passes is **not** covered
    /// by the guarantee above, and no event from it is expected until the open
    /// returns, at which point it either arms or reports [`WatchEvent::Failed`].
    /// Every root whose signal *was* read is covered, and a root that fails
    /// quickly is read rather than waited for.
    pub fn start(plan: &WatchPlan) -> Result<Self> {
        let (tx, events) = unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        // One `()` per root, and no payload: the signal means "my first read is
        // live", and there is nothing else to say about it.
        let (armed_tx, armed) = unbounded();
        let mut threads = Vec::with_capacity(plan.roots.len());

        for root in &plan.roots {
            let arming = Arming::new(armed_tx.clone());
            let spawned = std::thread::Builder::new()
                .name(format!("av-watch {}", root.display()))
                .spawn({
                    let plan = plan.clone();
                    let root = root.clone();
                    let tx = tx.clone();
                    let stop = Arc::clone(&stop);
                    move || run_root(&root, &plan, &tx, &stop, arming)
                });
            let thread = match spawned {
                Ok(thread) => thread,
                Err(source) => {
                    // The roots already spawned are running, and this function is
                    // about to return without a `DirectoryWatch` to hold them —
                    // so no `Drop` will run and nothing would ever set the flag
                    // they are all waiting on. Setting it here is the whole of
                    // what keeps a failed start from leaving watchers behind;
                    // they are not joined, because a thread in `CreateFileW` on a
                    // dead share would make this failure path hang, and they end
                    // on their own the moment they look.
                    stop.store(true, Ordering::SeqCst);
                    return Err(RealtimeError::Spawn {
                        root: root.clone(),
                        source,
                    });
                }
            };
            threads.push((root.clone(), thread));
        }
        // The original sender belongs to no thread, so the channel would never
        // disconnect when the last watcher ends. Dropping it here is what makes
        // a reader's `recv` return `Disconnected` and the service shut down.
        drop(tx);
        // And the same for the arming channel: with the per-thread clones, a
        // `recv_timeout` below returns `Disconnected` when every thread has
        // ended without arming, which is faster than waiting out the deadline.
        drop(armed_tx);

        // One deadline for the whole set, not one per root. A deadline per root
        // would multiply a stall by the number of watched directories, and the
        // roots here are between one and a handful: `start` should take as long
        // as the slowest root and not as long as their sum.
        let deadline = Instant::now() + ARM_DEADLINE;
        for _ in &plan.roots {
            let left = deadline.saturating_duration_since(Instant::now());
            if armed.recv_timeout(left).is_err() {
                // No signal left to read and no time left to wait for one: every
                // root that was going to arm has armed. A root that did not is
                // either one whose thread has already reported `Failed` or one
                // still inside a `CreateFileW` that has not returned — on a
                // disconnected share that can take a long time, which is exactly
                // the case this bound exists for.
                break;
            }
        }

        Ok(Self {
            events,
            stop,
            threads,
        })
    }

    /// The stream of events from every watched root.
    ///
    /// One channel for all of them, because the events are unordered with
    /// respect to each other anyway — they come from separate threads reading
    /// separate buffers — and a caller that needs to know which tree an event
    /// belongs to is told by the event itself.
    pub fn events(&self) -> &Receiver<WatchEvent> {
        &self.events
    }

    /// The roots being watched, in the order they were started.
    pub fn roots(&self) -> Vec<&Path> {
        self.threads
            .iter()
            .map(|(root, _)| root.as_path())
            .collect()
    }

    /// Stop every watch and wait for the threads to end.
    ///
    /// The waiting half of the pair with the `Drop` above, which sets the same
    /// flag and returns. `mem::take` is what makes moving the handles out legal
    /// at all: a type that implements `Drop` cannot have its fields moved out of
    /// it, so the handles are taken and the value left empty for the `Drop` that
    /// runs at the end of this function to find nothing in.
    pub fn stop(mut self) {
        let threads = std::mem::take(&mut self.threads);
        self.stop.store(true, Ordering::SeqCst);
        for (root, thread) in threads {
            if thread.join().is_err() {
                // A watch thread that panicked has already reported itself as
                // failed on the event stream if it got that far; there is
                // nothing left to do about it here, and a second panic inside a
                // teardown would take the process down.
                log::warn!("the watch thread for {} ended abnormally", root.display());
            }
        }
    }
}

/// The body of one watch thread.
///
/// A failure is sent as [`WatchEvent::Failed`] and the thread ends. A send that
/// fails means the consumer is gone, which means the process is shutting down,
/// so there is nobody left to tell.
#[cfg(windows)]
fn run_root(
    root: &Path,
    plan: &WatchPlan,
    tx: &Sender<WatchEvent>,
    stop: &AtomicBool,
    mut arming: Arming,
) {
    let outcome = watch_root(root, plan, tx, stop, &mut arming);
    // Every path out of `watch_root` releases the caller waiting in
    // `DirectoryWatch::start`, including the ones where the watch never became
    // live. A root that cannot be opened is a root nobody should keep waiting
    // for, and the failure that explains it goes out below.
    arming.signal();
    if let Err(error) = outcome {
        log::warn!("no longer watching {}: {error}", root.display());
        let _ = tx.send(WatchEvent::Failed {
            root: root.to_path_buf(),
            error,
        });
    }
}

/// Non-Windows builds have no `ReadDirectoryChangesW`, and this crate has no
/// second implementation of it.
///
/// Reported rather than silently watching nothing, so that a caller built on
/// another platform learns its protection is not running instead of believing it
/// is.
#[cfg(not(windows))]
fn run_root(
    root: &Path,
    plan: &WatchPlan,
    tx: &Sender<WatchEvent>,
    stop: &AtomicBool,
    mut arming: Arming,
) {
    let _ = (plan, stop);
    arming.signal();
    let _ = tx.send(WatchEvent::Failed {
        root: root.to_path_buf(),
        error: RealtimeError::Unsupported,
    });
}

/// Watch one directory until told to stop or until it cannot be watched.
#[cfg(windows)]
fn watch_root(
    root: &Path,
    plan: &WatchPlan,
    tx: &Sender<WatchEvent>,
    stop: &AtomicBool,
    arming: &mut Arming,
) -> Result<()> {
    use windows::Win32::System::IO::OVERLAPPED;

    let handle = open_directory(root)?;
    let event = create_event()?;

    // The kernel writes into this on completion and does not know when this
    // frame ends. It is a local of the function that issues and reaps every
    // read, so its address cannot change while a read is outstanding.
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..Default::default()
    };
    let mut buffer = vec![0u8; BUFFER_BYTES as usize];
    let filter = change_filter(plan.scan_on_write);

    loop {
        if stop.load(Ordering::Relaxed) {
            return cancel_pending(&handle, &overlapped);
        }

        issue_read(&handle, &event, &mut buffer, &mut overlapped, filter)?;
        // The read is live from here, which is the moment
        // [`DirectoryWatch::start`] is waiting to hear about. Signalling after
        // the call rather than before it is what makes the guarantee true: a
        // change made once this line has run is in the buffer the wait below
        // will collect.
        arming.signal();

        match wait_for(&event, stop)? {
            Wait::Signalled => {}
            Wait::Stopped => return cancel_pending(&handle, &overlapped),
        }

        match complete(&handle, &overlapped)? {
            Completed::Cancelled => return Ok(()),
            Completed::Overflow => {
                if tx
                    .send(WatchEvent::Lost {
                        root: root.to_path_buf(),
                        because: Lost::BufferOverflow,
                    })
                    .is_err()
                {
                    return Ok(());
                }
            }
            Completed::Bytes(written) => {
                let filled = checked_len(written, buffer.len())?;
                match parse(&buffer[..filled]) {
                    Ok(NotifyBatch::Overflow) => {
                        if tx
                            .send(WatchEvent::Lost {
                                root: root.to_path_buf(),
                                because: Lost::BufferOverflow,
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Ok(NotifyBatch::Records(records)) => {
                        if records.is_empty() {
                            continue;
                        }
                        let changes = records
                            .into_iter()
                            .map(|record| Change::resolve(root, record))
                            .collect();
                        if tx
                            .send(WatchEvent::Changed {
                                root: root.to_path_buf(),
                                changes,
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(error) => {
                        // A buffer we cannot read is a buffer whose changes we
                        // never see, which is the hole an overflow leaves.
                        // Refusing the whole batch and re-scanning is the same
                        // response for the same reason.
                        if tx
                            .send(WatchEvent::Lost {
                                root: root.to_path_buf(),
                                because: Lost::Malformed(error),
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// The categories of change to ask the kernel for.
///
/// Files and directories always, writes only when writes are scanned.
///
/// Asking for a category costs kernel work on every matching operation, so a
/// configuration with `scan_on_write` off is cheaper *at the source* rather than
/// by filtering the same events away afterwards.
/// `FILE_NOTIFY_CHANGE_LAST_ACCESS` is deliberately never asked for: it fires
/// when a file is *read*, including by the scan this crate is about to perform,
/// which would make it a generator of events about our own work.
///
/// Directory names are asked for even though a directory is not itself a scan
/// target, because of how a move is reported: `MoveFile` on a *directory* inside
/// a watched tree produces one `RENAMED_NEW_NAME` for the directory and nothing
/// at all for the files in it. A filter for file names only would let a whole
/// tree of samples be dragged into `Downloads` and see none of it — which is why
/// the service walks a directory that appears. See `crate::service`.
#[cfg(windows)]
fn change_filter(scan_on_write: bool) -> windows::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE {
    use windows::Win32::Storage::FileSystem as fs;

    let mut filter = fs::FILE_NOTIFY_CHANGE_FILE_NAME | fs::FILE_NOTIFY_CHANGE_DIR_NAME;
    if scan_on_write {
        filter |= fs::FILE_NOTIFY_CHANGE_LAST_WRITE | fs::FILE_NOTIFY_CHANGE_SIZE;
    }
    filter
}

/// What `WaitForSingleObject` ended with, in the two terms the loop cares about.
#[cfg(windows)]
enum Wait {
    /// The read completed.
    Signalled,
    /// The stop flag was set while we were waiting.
    Stopped,
}

/// What a completed read produced.
#[cfg(windows)]
enum Completed {
    /// The kernel wrote this many bytes into the buffer.
    Bytes(u32),
    /// The kernel had more to report than the buffer could hold.
    Overflow,
    /// The read was cancelled, which is what a stop looks like from here.
    Cancelled,
}

/// Open a directory handle that can be watched.
#[cfg(windows)]
fn open_directory(root: &Path) -> Result<OwnedHandle> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    // `encode_wide` and not `to_string_lossy`: a Windows path is WTF-16, and a
    // lossy conversion could open a directory with a different name than the one
    // the user configured.
    let wide: Vec<u16> = root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call.
    // Every other argument is a constant or an explicit null:
    //   * `FILE_LIST_DIRECTORY` is the access a directory watch needs. Asking
    //     for less is not enough for `ReadDirectoryChangesW`, and `GENERIC_READ`
    //     would demand read access this crate does not use.
    //   * All three share modes are granted, so that opening a watch does not
    //     stop another process from writing, renaming or deleting inside the
    //     directory — a watcher that made `Downloads` read-only would be a worse
    //     bug than any sample it caught.
    //   * `OPEN_EXISTING` with no template: the directory must already be there,
    //     because creating a directory in order to watch it would put a path on
    //     the user's disk that they did not ask for.
    //   * `FILE_FLAG_BACKUP_SEMANTICS` is what permits a *directory* handle at
    //     all, and `FILE_FLAG_OVERLAPPED` is what makes the read cancellable.
    // The returned handle is owned from here on and closed by `OwnedHandle`.
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None,
        )
    }
    .map_err(|error| RealtimeError::win32("CreateFileW", error))?;

    Ok(OwnedHandle::from_valid(handle))
}

/// A manual-reset event, for the overlapped reads to signal completion on.
#[cfg(windows)]
fn create_event() -> Result<OwnedHandle> {
    // SAFETY: a null `SECURITY_ATTRIBUTES` asks for the default descriptor; a
    // manual reset is what lets this thread clear the signal before each read
    // rather than race the kernel to consume it; no initial signal, so the first
    // wait blocks as it should; and a null name, because a named event would be
    // a cross-process object nobody asked for.
    let handle = unsafe {
        windows::Win32::System::Threading::CreateEventW(
            None,
            true,
            false,
            windows::core::PCWSTR::null(),
        )
    }
    .map_err(|error| RealtimeError::win32("CreateEventW", error))?;

    Ok(OwnedHandle::from_valid(handle))
}

/// Issue one overlapped `ReadDirectoryChangesW`.
///
/// The caller waits afterwards whether or not the call completed inline, because
/// a completed read has signalled the event and the wait then returns at once.
fn issue_read(
    handle: &OwnedHandle,
    event: &OwnedHandle,
    buffer: &mut [u8],
    overlapped: &mut windows::Win32::System::IO::OVERLAPPED,
    filter: windows::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE,
) -> Result<()> {
    use windows::Win32::Storage::FileSystem::ReadDirectoryChangesW;
    use windows::Win32::System::Threading::ResetEvent;

    // Clear the signal before issuing. The event is manual-reset, so a signal
    // left over from the previous round would make the wait below return at once
    // and hand the next `GetOverlappedResult` a completion that is not there.
    //
    // SAFETY: `event` is a live event handle owned by this thread's frame.
    unsafe { ResetEvent(event.raw()) }
        .map_err(|error| RealtimeError::win32("ResetEvent", error))?;

    let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let mut written: u32 = 0;

    // SAFETY: every pointer handed over points at memory owned by this frame and
    // alive for the duration of the call:
    //   * `buffer` is the allocation the kernel writes records into. It is not
    //     read or reallocated until the read completes, because the loop always
    //     waits and reaps before touching it.
    //   * `written` is an out-parameter the API fills when the call completes
    //     inline. When the call is pending, `GetOverlappedResult` fills it
    //     instead, which is why its value is never read here.
    //   * `overlapped` is the frame local described in the module docs, with its
    //     `hEvent` pointing at the event above.
    // A null completion routine is the documented way to say "signal the event
    // and ask me nothing".
    let issued = unsafe {
        ReadDirectoryChangesW(
            handle.raw(),
            buffer.as_mut_ptr().cast(),
            length,
            crate::plan::WATCH_SUBTREE,
            filter,
            Some(&mut written),
            Some(overlapped),
            None,
        )
    };

    match issued {
        Ok(()) => Ok(()),
        // The ordinary outcome of an overlapped request: the operation is
        // running and the event will be signalled when it finishes. Treating it
        // as a failure is the classic way to write an overlapped loop that never
        // reads anything.
        Err(error) if error.code() == hresult_of(windows::Win32::Foundation::ERROR_IO_PENDING) => {
            Ok(())
        }
        Err(error) => Err(RealtimeError::win32("ReadDirectoryChangesW", error)),
    }
}

/// Wait for the read to complete, or for a stop request.
///
/// The wait is repeated rather than treated as one shot: the read stays pending
/// across poll intervals, and a timeout only means it is time to check whether
/// anyone has asked this thread to stop.
#[cfg(windows)]
fn wait_for(event: &OwnedHandle, stop: &AtomicBool) -> Result<Wait> {
    use windows::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::WaitForSingleObject;

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(Wait::Stopped);
        }
        // SAFETY: `event` is a live event handle owned by this frame, and the
        // wait has no other preconditions.
        match unsafe { WaitForSingleObject(event.raw(), POLL_MS) } {
            WAIT_OBJECT_0 => return Ok(Wait::Signalled),
            // Waking for nothing is the point of the interval: it is the only
            // moment at which a blocked thread can notice it was asked to stop.
            WAIT_TIMEOUT => continue,
            WAIT_FAILED => {
                return Err(RealtimeError::win32(
                    "WaitForSingleObject",
                    windows::core::Error::from_thread(),
                ))
            }
            other => {
                return Err(RealtimeError::Win32 {
                    call: "WaitForSingleObject",
                    code: other.0,
                    message: format!("the wait ended with an unexpected result 0x{:08X}", other.0),
                })
            }
        }
    }
}

/// Collect what a completed read produced.
///
/// The overflow signal is a completion with zero bytes: the kernel reports "I
/// had more than I could fit" by writing nothing at all, which is why an empty
/// buffer is not the same statement as "nothing happened".
#[cfg(windows)]
fn complete(
    handle: &OwnedHandle,
    overlapped: &windows::Win32::System::IO::OVERLAPPED,
) -> Result<Completed> {
    use windows::Win32::Foundation::{ERROR_NOTIFY_ENUM_DIR, ERROR_OPERATION_ABORTED};
    use windows::Win32::System::IO::GetOverlappedResult;

    let mut written: u32 = 0;
    // SAFETY: `handle` is the handle the read was issued on and `overlapped` is
    // the structure it was issued with, both alive in this frame. The call does
    // not block (`bwait` is false) because the event has already been signalled.
    // `written` is a local out-parameter.
    let outcome = unsafe { GetOverlappedResult(handle.raw(), overlapped, &mut written, false) };

    match outcome {
        Ok(()) if written == 0 => Ok(Completed::Overflow),
        Ok(()) => Ok(Completed::Bytes(written)),
        Err(error) if error.code() == hresult_of(ERROR_NOTIFY_ENUM_DIR) => Ok(Completed::Overflow),
        // The read was cancelled. That is what a stop or a closed handle looks
        // like from here, and the caller is on its way out either way.
        Err(error) if error.code() == hresult_of(ERROR_OPERATION_ABORTED) => {
            Ok(Completed::Cancelled)
        }
        Err(error) => Err(RealtimeError::win32("GetOverlappedResult", error)),
    }
}

/// Cancel any outstanding read and wait for it to be reaped.
///
/// This is what makes it safe for the watch function to return: the kernel
/// writes completion data into the `OVERLAPPED` that lives in that function's
/// frame, and a frame that goes away underneath a pending read is a
/// use-after-free. Cancelling and then reaping with `bwait = true` means no
/// completion can arrive after this returns.
#[cfg(windows)]
fn cancel_pending(
    handle: &OwnedHandle,
    overlapped: &windows::Win32::System::IO::OVERLAPPED,
) -> Result<()> {
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult};

    // SAFETY: `handle` is a live handle, and a null `OVERLAPPED` means "every
    // outstanding request on this handle", of which there is at most one. A
    // failure is not fatal — the read may have completed between the last wait
    // and this call — so the result is discarded; the reap below is what
    // establishes the invariant that matters.
    unsafe { CancelIoEx(handle.raw(), None) }.ok();

    let mut written: u32 = 0;
    // SAFETY: as above, and `bwait` is true so this returns only once the
    // cancelled read has completed and the `OVERLAPPED` is no longer being
    // written to.
    unsafe { GetOverlappedResult(handle.raw(), overlapped, &mut written, true) }.ok();
    Ok(())
}

/// Narrow a byte count the kernel reported to something that can index the
/// buffer it was reported for.
///
/// A kernel that wrote more bytes than it was offered is either not the kernel
/// this code was written for or has been corrupted, and slicing to the larger
/// number would panic while trusting it would read memory that was never
/// written. Both are worse than saying so.
pub(crate) fn checked_len(reported: u32, buffer: usize) -> Result<usize> {
    let reported = usize::try_from(reported).unwrap_or(usize::MAX);
    if reported > buffer {
        return Err(RealtimeError::LengthOverrun {
            reported: u32::try_from(reported).unwrap_or(u32::MAX),
            buffer,
        });
    }
    Ok(reported)
}

/// The `HRESULT` a Win32 error code takes when it arrives through
/// `windows_core::Error`.
///
/// `GetLastError` values are carried as `HRESULT`s with the `FACILITY_WIN32`
/// prefix, so comparing a raw code against `Error::code()` without this
/// conversion is a comparison that is never true — a check that silently never
/// fires, which is the worst way for a check to fail.
#[cfg(windows)]
fn hresult_of(code: windows::Win32::Foundation::WIN32_ERROR) -> windows::core::HRESULT {
    windows::core::HRESULT::from_win32(code.0)
}

/// A Win32 handle that closes itself.
///
/// The same ownership model the quarantine vault uses for its handles: one
/// newtype with a `Drop`, so there is exactly one place a handle is released and
/// no early return that forgets to. That matters more here than usual because
/// `HANDLE` is `Copy` — passing one into a helper is a copy, not a borrow, so
/// the compiler cannot stop a second close. This type is what makes the
/// ownership visible instead.
#[cfg(windows)]
#[derive(Debug)]
struct OwnedHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl OwnedHandle {
    /// Take ownership of a handle known to be valid.
    ///
    /// Callers reach this only with the result of a `windows` call that returned
    /// `Ok`, which is the same thing as "not null and not `INVALID_HANDLE_VALUE`".
    fn from_valid(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self(handle)
    }

    /// The handle, for passing to another Win32 call.
    fn raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the field is a handle this type owns, it is not closed
        // anywhere else, and `CloseHandle` is the documented way to release it.
        // The result is discarded because there is nothing useful to do about a
        // failure to close a handle while dropping, and a panic in a destructor
        // would be worse than the leak.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_count_from_the_kernel_is_bounded_by_the_buffer_it_came_from() {
        // The ordinary cases, including exactly-full, which is legal.
        assert_eq!(checked_len(0, 64).unwrap(), 0);
        assert_eq!(checked_len(64, 64).unwrap(), 64);
        assert_eq!(checked_len(0, 0).unwrap(), 0);

        // One more than the buffer is refused rather than trusted: a slice to it
        // would panic, and reading to it would read memory nobody wrote.
        match checked_len(4096, 64) {
            Err(RealtimeError::LengthOverrun { reported, buffer }) => {
                assert_eq!(reported, 4096);
                assert_eq!(buffer, 64);
            }
            other => panic!("expected LengthOverrun, got {other:?}"),
        }
        assert!(checked_len(1, 0).is_err());
        // And a count that does not fit the local `usize` cannot be used to index
        // anything, on any width.
        assert!(matches!(
            checked_len(u32::MAX, 64),
            Err(RealtimeError::LengthOverrun { .. })
        ));
    }

    #[test]
    fn a_lost_batch_records_why_it_was_lost() {
        use crate::notify::NotifyError;
        // The two causes are distinguishable, which is the point of carrying
        // them: one says "that burst was too big", the other says "the
        // notification format is not what this code thinks it is".
        let malformed = Lost::Malformed(NotifyError::EmptyName { offset: 12 });
        assert_ne!(malformed, Lost::BufferOverflow);
        assert!(format!("{malformed:?}").contains("EmptyName"));
    }

    // -- the tests that touch a real filesystem ---------------------------
    //
    // Everything above is a decision or a pure function. What follows cannot be:
    // whether `ReadDirectoryChangesW` reports a creation is a fact about this
    // machine's kernel, and the only way to test it is to create a file and see
    // what arrives. Each of these builds its own directory under the system temp
    // directory, watches it, performs one filesystem operation, and asserts on
    // the event — the `TempDir` removes the directory when the test ends,
    // including when the test fails, and the watch is stopped before it does so
    // that no handle is still open on a directory being deleted.
    //
    // Run them with:
    //
    //     cargo test -p av-realtime -- --ignored --nocapture

    #[cfg(windows)]
    mod filesystem {
        use super::*;
        use crate::notify::FileAction;
        use crate::testing::{plan_for, same_path};
        use std::time::{Duration, Instant};

        /// How long a filesystem test waits for an event before calling it a
        /// failure.
        ///
        /// Far longer than it should ever need: the measurement in
        /// `debounce::tests::measure_time_to_observe_a_created_file` puts the
        /// observation of a creation in single-digit milliseconds on this
        /// machine, and this bound exists to fail in seconds rather than to hang
        /// the test run when something is wrong.
        const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

        /// The changes the kernel reported for any of `paths`, waiting until at
        /// least one arrives and then until nothing more does.
        ///
        /// A slice of paths rather than one, because the two halves of a rename
        /// arrive in a *single* batch: a helper that filtered one batch down to
        /// one name and returned would throw the other half away, and the test
        /// that then asked for it would wait for a batch that is never coming.
        /// Both are read here and the caller asserts on whichever it needs.
        ///
        /// Collecting past the first batch is the other half of the same
        /// problem. One filesystem operation produces more than one batch — a
        /// create and its first write are two records, sometimes in one batch
        /// and sometimes in two — and returning at the first batch would hand
        /// the second one to the *next* assertion in the test. A leftover batch
        /// read as the answer to the wrong operation is exactly how the delete
        /// test failed the first time it was run.
        ///
        /// Changes to other paths are ignored, so a busy temp directory cannot
        /// confuse an assertion.
        fn changes_for(watch: &DirectoryWatch, paths: &[&Path]) -> Vec<Change> {
            let deadline = Instant::now() + EVENT_TIMEOUT;
            let settle = Duration::from_millis(500);
            let wanted = || {
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
            };
            let mut found = Vec::new();
            let mut quiet_until = deadline;
            loop {
                let left = quiet_until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    if found.is_empty() {
                        panic!(
                            "no event naming any of {:?} arrived within {EVENT_TIMEOUT:?}",
                            wanted()
                        );
                    }
                    return found;
                }
                match watch.events().recv_timeout(left) {
                    Ok(WatchEvent::Changed { changes, .. }) => {
                        let mut matched = false;
                        for change in changes {
                            if paths.iter().any(|path| same_path(&change.path, path)) {
                                found.push(change);
                                matched = true;
                            }
                        }
                        if matched {
                            // Keep reading until the operation stops producing.
                            quiet_until = Instant::now() + settle;
                        }
                    }
                    Ok(WatchEvent::Failed { root, error }) => {
                        panic!("the watch on {} failed: {error}", root.display())
                    }
                    Ok(WatchEvent::Lost { root, because }) => {
                        panic!("events were lost for {}: {because:?}", root.display())
                    }
                    Err(_) => {
                        if found.is_empty() {
                            panic!(
                                "no event naming any of {:?} arrived within {EVENT_TIMEOUT:?}",
                                wanted()
                            );
                        }
                        return found;
                    }
                }
            }
        }

        /// The actions in a collected set of changes, for the assertions that do
        /// not care which name each one carried.
        fn actions(changes: &[Change]) -> Vec<FileAction> {
            changes.iter().map(|change| change.action).collect()
        }

        /// The actions reported for one path.
        fn actions_for(watch: &DirectoryWatch, path: &Path) -> Vec<FileAction> {
            actions(&changes_for(watch, &[path]))
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_change_made_before_the_watch_starts_is_never_reported() {
            // The measurement behind `DirectoryWatch::start`'s wait, and the
            // reason a watched tree's existing contents are the full scanner's
            // job. The file is written *before* the watch exists, and the
            // assertion is silence: not "no event arrived yet", but "the watch
            // will never mention this file", because a directory with no
            // outstanding `ReadDirectoryChangesW` accumulates no records.
            let temp = tempfile::tempdir().expect("a temp directory");
            let file = temp.path().join("already-here.bin");
            std::fs::write(&file, b"this file predates the watch").expect("the file is written");

            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let outcome = watch.events().recv_timeout(Duration::from_millis(500));

            assert!(
                matches!(outcome, Err(crossbeam_channel::RecvTimeoutError::Timeout)),
                "a file that predates the watch was reported: {outcome:?}"
            );
            // And the watch is live all the same: the same path changing *after*
            // it was armed is reported, so the silence above is about timing and
            // not about a watch that failed to start.
            std::fs::write(&file, b"and this write does not").expect("the second write");
            let actions = actions_for(&watch, &file);
            assert!(
                actions.contains(&FileAction::Modified),
                "the kernel reported {actions:?} for a write to a watched file"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_created_file_arrives_as_an_added_change() {
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let file = temp.path().join("created.bin");

            std::fs::write(&file, b"a file that appeared").expect("the file is written");

            let actions = actions_for(&watch, &file);
            // Printed rather than only asserted on, because what the kernel says
            // for a create-then-write is the fact the whole debounce floor is
            // set against, and a doc comment quoting it needs a run to quote.
            println!("writing a new file reported {actions:?}");
            assert!(
                actions.contains(&FileAction::Added),
                "the kernel reported {actions:?} for a created file"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_write_to_an_existing_file_arrives_as_a_modification() {
            // The other half of the create: this is what `scan_on_write` turns
            // into a scan candidate, and a dropped file that is written in two
            // goes needs it, because the second write is the whole payload.
            let temp = tempfile::tempdir().expect("a temp directory");
            let file = temp.path().join("existing.bin");
            std::fs::write(&file, b"the first version").expect("the file is written");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");

            std::fs::write(&file, b"the second version, which is longer").expect("the rewrite");

            let actions = actions_for(&watch, &file);
            assert!(
                actions.contains(&FileAction::Modified),
                "the kernel reported {actions:?} for a rewritten file"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_file_moved_into_the_tree_arrives_as_a_new_name() {
            // The case the filter exists for: a dropper staged outside the
            // watched tree and then moved in. The kernel is free to report this
            // as either the new half of a rename or as a plain addition — the
            // source of the rename is not in the watched directory, so there is
            // no `RENAMED_OLD_NAME` to pair it with — and this asserts the
            // property that matters rather than the spelling: the moved file is
            // reported as something that makes it a scan candidate.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watched = temp.path().join("watched");
            std::fs::create_dir(&watched).expect("the watched directory");
            let staging = temp.path().join("staging.bin");
            std::fs::write(&staging, b"a file that was written elsewhere").expect("the source");
            let watch = DirectoryWatch::start(&plan_for(&watched, true)).expect("a watch");

            let moved = watched.join("moved.bin");
            std::fs::rename(&staging, &moved).expect("the rename");

            let actions = actions_for(&watch, &moved);
            println!("moving a staged file into the tree reported {actions:?}");
            assert!(
                actions.contains(&FileAction::Added)
                    || actions.contains(&FileAction::RenamedNewName),
                "the kernel reported {actions:?} for a file moved into the tree, which names no \
                 file that this crate would scan"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_rename_inside_the_tree_arrives_as_both_names() {
            // The pair, which is what a rename is reported as when the kernel can
            // see both ends of it. The old half matters as much as the new one:
            // the name that is gone is the name a scan may already have been
            // queued under, and the new half is a file that has just appeared
            // under a name nothing has looked at.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let before = temp.path().join("before.bin");
            let after = temp.path().join("after.bin");
            std::fs::write(&before, b"a file about to change its name").expect("the file");
            assert!(actions_for(&watch, &before).contains(&FileAction::Added));

            std::fs::rename(&before, &after).expect("the rename");

            // One read, both names. The pair arrives together, so asking for
            // them in two calls would consume the batch with the first.
            let changes = changes_for(&watch, &[&before, &after]);
            println!("renaming inside the tree reported {changes:?}");
            assert!(
                changes.iter().any(|change| same_path(&change.path, &before)
                    && change.action == FileAction::RenamedOldName),
                "the kernel reported {changes:?} for the old name of a rename inside the tree"
            );
            assert!(
                changes.iter().any(|change| same_path(&change.path, &after)
                    && change.action == FileAction::RenamedNewName),
                "the kernel reported {changes:?} for the new name of a rename inside the tree"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_deleted_file_arrives_as_a_removal() {
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let file = temp.path().join("doomed.bin");
            std::fs::write(&file, b"written to be deleted").expect("the file is written");
            // Wait for the creation first, so that the removal below is not
            // reported in the same batch as the creation and read as one event.
            assert!(actions_for(&watch, &file).contains(&FileAction::Added));

            std::fs::remove_file(&file).expect("the delete");

            let actions = actions_for(&watch, &file);
            assert!(
                actions.contains(&FileAction::Removed),
                "the kernel reported {actions:?} for a deleted file"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn a_subdirectory_creation_is_reported_because_a_directory_move_is_one_event() {
            // `FILE_NOTIFY_CHANGE_DIR_NAME` is asked for on purpose: moving a
            // directory into a watched tree reports the directory and nothing
            // about its contents, so a filter that only understood file names
            // would see a whole tree arrive and notice none of it.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let directory = temp.path().join("dragged-in");

            std::fs::create_dir(&directory).expect("the directory");

            let actions = actions_for(&watch, &directory);
            assert!(
                actions.contains(&FileAction::Added),
                "the kernel reported {actions:?} for a created directory"
            );
            watch.stop();
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn dropping_a_watch_stops_its_threads() {
            // The claim in the type's own documentation, measured. `stop` is
            // never called here, so the only thing that can end the threads is
            // the `Drop` — and before that `Drop` existed this test failed, which
            // is what makes it worth having rather than being a restatement of
            // the comment.
            //
            // The observable is the channel, and it is the right one: each thread
            // holds a `Sender` clone, so the channel reports `Disconnected`
            // exactly when the last thread has dropped its own. That is the only
            // proof available once the value is gone, because the `JoinHandle`s
            // went with it — which is the whole shape of the bug this covers.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            let events = watch.events().clone();
            drop(watch);

            let deadline = Instant::now()
                + Duration::from_millis(u64::from(POLL_MS) * 4 + 1_000);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match events.recv_timeout(left) {
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => panic!(
                        "the watch was dropped and its threads are still running: the event \
                         channel is still connected well past the poll interval"
                    ),
                    // A thread that reported a failure before ending is still a
                    // thread that ended; the loop is what is being waited on.
                    Ok(event) => println!("while waiting: {event:?}"),
                }
            }
        }

        #[test]
        #[ignore = "touches the real filesystem"]
        fn stopping_a_watch_takes_less_than_one_poll_interval() {
            // `POLL_MS` is the shutdown latency, and this is the measurement that
            // says so rather than the argument in its doc comment. The bound is
            // generous — two intervals — because a loaded machine can delay a
            // wake-up; what it rules out is a watch that only stops when the
            // watched directory next changes, which is the failure a synchronous
            // `ReadDirectoryChangesW` produces.
            let temp = tempfile::tempdir().expect("a temp directory");
            let watch = DirectoryWatch::start(&plan_for(temp.path(), true)).expect("a watch");
            std::thread::sleep(EVENT_TIMEOUT / 50);

            let started = Instant::now();
            watch.stop();
            let elapsed = started.elapsed();

            assert!(
                elapsed < Duration::from_millis(u64::from(POLL_MS) * 2 + 500),
                "stopping took {elapsed:?}, which is longer than two poll intervals"
            );
        }
    }
}
