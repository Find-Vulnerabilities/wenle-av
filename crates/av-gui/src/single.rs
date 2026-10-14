//! One window, however many times the user asks for one.
//!
//! # The problem this solves
//!
//! The window is a file on the desktop, so a user double-clicks it. Nothing
//! about a second launch is unusual — the second double-click, the pinned
//! taskbar entry, and the Explorer verb all start the same executable — and
//! without this module each one opens another identical window over the same
//! state. Two windows over one rule database, one configuration and one
//! quarantine vault is two answers to every question the product asks, and the
//! user has no way to know which one they are looking at.
//!
//! # Why the second launch is not merely refused
//!
//! Because the Explorer verb passes an argument. `wenle-gui.exe --scan "%1"`
//! run against a window that is already open has to *scan*, not merely come to
//! the front — a right-click that raises a window and does nothing is worse than
//! one that opens a second window, because the user has been shown the answer
//! and the answer is nothing. So the second process hands its request to the
//! first and exits.
//!
//! # Why a pipe, and not the two obvious alternatives
//!
//! `WM_COPYDATA` to the existing window is the classic answer and it does not
//! work here: `eframe` does not expose the window procedure, so there is nowhere
//! for the message to arrive. `FindWindowW` plus `SetForegroundWindow` works
//! without a channel but can only raise the window — there is no way to hand it
//! a path — and it makes the second process responsible for finding a window
//! whose title is a string this program is free to change.
//!
//! A pipe inverts that. The second process does not find anything; it says what
//! it wants to the name the first process is listening on, and the first process
//! raises itself. That is also why there is no `FindWindowW` here at all: the
//! process that owns the window is the one that knows it has one.
//!
//! # Why the name is derived from the data directory
//!
//! Because two installations are two products. `--data-dir` is what makes a
//! portable copy a directory somebody can move, and a portable copy beside the
//! installed one shares no configuration, no rules and no vault with it, so
//! refusing to let both run would be enforcing a rule about nothing. The name is
//! the data directory's path, folded and lowercased: folded so that the name is
//! a fixed length, lowercased because Windows paths are case-insensitive and
//! `C:\ProgramData\WenleAV` and `c:\programdata\wenleav` are one directory that
//! must not produce two names.
//!
//! The `Local\` prefix scopes both names to the logon session, which is the
//! narrower thing and the one meant: a second user signed in at the same time
//! is running their own window against their own state, and neither should be
//! able to raise or write into the other.

use std::path::{Path, PathBuf};

/// What a later launch asked the running window to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wake {
    /// Come to the front. What a double-click with no arguments means.
    Focus,
    /// Come to the front, and scan this.
    Scan(PathBuf),
}

/// Whether this process is the one that owns the window.
#[derive(Debug)]
pub enum Claim {
    /// This process owns it, and holds the name that says so for as long as it
    /// lives. Dropping the [`Owner`] gives up the claim.
    Only(Owner),
    /// Another process owns it and has been told what this launch wanted.
    AlreadyRunning,
}

/// The first instance's claim, and the channel its requests arrive on.
///
/// The mutex handle is held rather than only checked, and that is the whole
/// mechanism: the claim lasts exactly as long as the handle exists. A process
/// that checked the name and let the handle go would have proved nothing about
/// the next process to look.
#[derive(Debug)]
pub struct Owner {
    /// The kernel object whose existence is the claim. Never read; held.
    #[cfg(windows)]
    mutex: windows::Win32::Foundation::HANDLE,
    /// What later launches have asked for. Drained by the window.
    wakes: crossbeam_channel::Receiver<Wake>,
}

impl Owner {
    /// The requests that have arrived, for the window to drain each frame.
    pub fn receiver(&self) -> &crossbeam_channel::Receiver<Wake> {
        &self.wakes
    }
}

#[cfg(windows)]
impl Drop for Owner {
    fn drop(&mut self) {
        // A null handle is the case where the name could not be created at all
        // and this process is the window by default rather than by claim. There
        // is nothing to release, and `CloseHandle(null)` would report a failure
        // that is not one.
        if self.mutex.is_invalid() {
            return;
        }
        // Closing the last handle to the mutex destroys it, which is what makes
        // the next launch the first one again. Failure is not actionable at this
        // point — the process is going away either way — but the handle is not
        // leaked silently if this ever runs while the process lives on.
        //
        // SAFETY: `self.mutex` is a live handle this value owns, and it is not
        // used again after this call: `Drop` runs once.
        if let Err(error) = unsafe { windows::Win32::Foundation::CloseHandle(self.mutex) } {
            log::warn!("the single-instance name could not be released: {error}");
        }
    }
}

/// The longest wake body this will accept, in bytes of its encoding.
///
/// A Windows path is at most 32,767 wide characters, which is 65,534 bytes of
/// UTF-16 — so this is deliberately larger than any path the shell can hand a
/// context menu, and no message a real launch produces is ever refused for its
/// length. What the ceiling is for is the other direction: a sender that is not
/// this program, or a build that disagrees about the format, must not be able to
/// make the listener allocate whatever it likes. A message longer than this is
/// not truncated and acted on — scanning a *shortened* path would be scanning
/// something the user did not name — it is refused whole. The four bytes of
/// length prefix ride outside this figure.
const MAX_WAKE_BYTES: usize = 64 * 1024;

/// How long a second launch keeps trying to reach the first.
///
/// The first process takes the name before it creates the pipe, so there is a
/// window of a few milliseconds in which the name is held and nothing is
/// listening. Without this a second click landing in that gap would exit having
/// told nobody, and the scan it asked for would be lost with no sign that
/// anything had been dropped.
const CONNECT_ATTEMPTS: u32 = 40;

/// How long to wait between those attempts.
const CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Ask to be the window, or tell the window that already exists what is wanted.
///
/// `scan` is the `--scan` argument, and it is passed here rather than forwarded
/// by the caller because only this function knows whether there is anyone to
/// forward it to.
pub fn claim(data_dir: &Path, scan: Option<&Path>) -> Claim {
    #[cfg(windows)]
    {
        claim_on_windows(data_dir, scan)
    }
    #[cfg(not(windows))]
    {
        // No claim is made anywhere else, and the honest shape of that is to
        // hand back the owner rather than to pretend: a window on a platform
        // with no second-instance mechanism is a window that opens twice, and
        // nothing here is compiled to prevent it.
        let _ = (data_dir, scan);
        let (_sender, wakes) = crossbeam_channel::unbounded();
        Claim::Only(Owner { wakes })
    }
}

/// The folded name of the data directory, as sixteen lowercase hex digits.
///
/// FNV-1a, written out rather than taken from a hasher in the standard library,
/// because this name has to be the same in two processes built at different
/// times: `DefaultHasher` is documented as unstable across releases, and a
/// window that stopped recognising its own predecessor after a rebuild would be
/// exactly the second window this module exists to prevent.
///
/// Folded to a fixed width because a pipe name is limited to 256 bytes and a
/// data directory is not. A collision would mean two installations sharing one
/// window, which is why the value is compared as a whole rather than truncated
/// further.
pub fn key(data_dir: &Path) -> String {
    // Lowercased first: Windows paths are case-insensitive, so two spellings of
    // one directory must not be two names. This is the lossy conversion's
    // correct use — the name is only ever hashed, never used to open anything.
    let text = data_dir.to_string_lossy().to_lowercase();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The mutex name for a data directory.
pub fn mutex_name(data_dir: &Path) -> String {
    format!(r"Local\WenleAV.Gui.{}", key(data_dir))
}

/// The pipe name for a data directory.
pub fn pipe_name(data_dir: &Path) -> String {
    format!(r"\\.\pipe\wenleav-gui-{}", key(data_dir))
}

/// A wake, as it goes over the pipe.
///
/// A four-byte little-endian length followed by that many bytes of the path, or
/// a length of zero for "just come to the front". Framed rather than sent as a
/// bare path because the two cases have to be told apart, and because a reader
/// that took the message as a path could not tell a path it received in full
/// from one that was cut off at the buffer's end.
///
/// The path is the platform's own bytes rather than UTF-8, so that a directory
/// whose name is not valid Unicode survives the trip. A path that cannot be
/// represented is not invented into one that can.
pub fn encode(wake: &Wake) -> Vec<u8> {
    let body = match wake {
        Wake::Focus => Vec::new(),
        Wake::Scan(path) => os_bytes(path),
    };
    let mut out = Vec::with_capacity(4 + body.len());
    // The length is the body's, taken after the body exists rather than
    // predicted, so a prefix and a payload cannot disagree by construction.
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// The wake a message carries, or `None` if it is malformed or too long.
///
/// `None` is not an error the caller reports: a message this end cannot read is
/// a message from a build that disagrees about the format, and the safe reading
/// of that is the one that asks for nothing. The window still comes to the
/// front, which is what a launch with no arguments would have asked for.
pub fn decode(message: &[u8]) -> Option<Wake> {
    // The prefix is part of the message, so the ceiling is the body's plus the
    // four bytes that say how long it is.
    if message.len() > MAX_WAKE_BYTES + 4 || message.len() < 4 {
        return None;
    }
    let (head, body) = message.split_at(4);
    let length = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    // The length has to match what arrived. A prefix that claims more than the
    // message holds is a truncated message, and a prefix that claims less is a
    // message with something appended — neither is a path this end was sent.
    if length != body.len() {
        return None;
    }
    if length == 0 {
        return Some(Wake::Focus);
    }
    path_from_os_bytes(body).map(Wake::Scan)
}

/// A path's bytes, as the platform stores them.
///
/// UTF-16 on Windows rather than UTF-8, so that a file whose name is not valid
/// Unicode survives the trip. A Windows path is a sequence of wide units and
/// nothing here is entitled to assume it is text.
#[cfg(windows)]
fn os_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// A path from the platform's own bytes, or `None` if they are not a path.
#[cfg(windows)]
fn path_from_os_bytes(bytes: &[u8]) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    let mut wide = Vec::with_capacity(bytes.len() / 2);
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        wide.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    // An odd number of bytes cannot be a sequence of wide units, so it is a
    // message this build did not write rather than a path with a byte missing.
    // Checked after the loop rather than before it so that the units already
    // decoded are not decoded twice; nothing is done with them either way.
    if !pairs.remainder().is_empty() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
}

/// A path's bytes, as the platform stores them.
#[cfg(not(windows))]
fn os_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().to_vec()
}

/// A path from the platform's own bytes.
#[cfg(not(windows))]
fn path_from_os_bytes(bytes: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(windows)]
fn claim_on_windows(data_dir: &Path, scan: Option<&Path>) -> Claim {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS};

    let name = to_wide(&mutex_name(data_dir));
    // Cleared first because `CreateMutexW` succeeding says nothing about whether
    // the object already existed, and the only signal for that is this error
    // code. A stale code left by an earlier call would be read as somebody
    // else's claim.
    //
    // SAFETY: both are plain kernel32 calls taking a value argument.
    unsafe { windows::Win32::Foundation::SetLastError(ERROR_SUCCESS) };
    // SAFETY: `name` is NUL-terminated and outlives the call. A null security
    // descriptor asks for the default DACL, so the set of principals that can
    // open this name is the set that can already open the logon session's
    // objects.
    let mutex = match unsafe {
        windows::Win32::System::Threading::CreateMutexW(None, false, PCWSTR(name.as_ptr()))
    } {
        Ok(handle) => handle,
        Err(error) => {
            // Not fatal, and deliberately not reported to the user: a machine
            // where this fails is a machine where the window still works, and
            // the failure mode is a second window rather than no window.
            log::warn!("no single-instance name: {error}");
            return Claim::Only(spawn_owner(data_dir));
        }
    };

    // SAFETY: a call with no arguments and no preconditions.
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if !already {
        return Claim::Only(Owner {
            mutex,
            wakes: spawn_listener(data_dir),
        });
    }

    // Somebody else owns the window. This handle is a second reference to the
    // same object and closes with the process either way, but it is closed here
    // so that the claim's lifetime is not accidentally extended by this process
    // holding it.
    //
    // SAFETY: a live handle this process owns, not used again.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(mutex);
    }
    wake_existing(data_dir, scan);
    Claim::AlreadyRunning
}

/// Tell the running window what this launch wanted.
#[cfg(windows)]
fn wake_existing(data_dir: &Path, scan: Option<&Path>) {
    use windows::core::PCWSTR;
    // `GENERIC_WRITE` is in `Foundation` beside the other access masks, not in
    // `Storage::FileSystem` with the call that takes it.
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
    };

    let wake = match scan {
        Some(path) => Wake::Scan(path.to_path_buf()),
        None => Wake::Focus,
    };
    let message = encode(&wake);
    let name = to_wide(&pipe_name(data_dir));

    for attempt in 0..CONNECT_ATTEMPTS {
        // SAFETY: `name` is NUL-terminated and outlives the call; every other
        // argument is a constant. The handle is closed below on every path.
        let opened = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match opened {
            Ok(pipe) => {
                let mut written = 0u32;
                // SAFETY: `pipe` is a live handle from the call above and
                // `message` outlives this call. Failure is handled below rather
                // than being left to the close.
                let result = unsafe {
                    WriteFile(pipe, Some(&message), Some(&mut written), None)
                };
                // SAFETY: a live handle this function owns, not used again.
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(pipe);
                }
                match result {
                    Ok(()) if written as usize == message.len() => return,
                    Ok(()) => log::warn!(
                        "the running window read {written} of {} bytes of this launch's request",
                        message.len()
                    ),
                    Err(error) => log::warn!("the running window could not be told: {error}"),
                }
                return;
            }
            Err(error) => {
                // `ERROR_FILE_NOT_FOUND` is the expected answer inside the gap
                // between the first process taking the name and its listener
                // existing, which is the whole reason this loop exists.
                if attempt + 1 == CONNECT_ATTEMPTS {
                    log::warn!(
                        "the running window did not answer after {} attempts: {error}",
                        CONNECT_ATTEMPTS
                    );
                } else {
                    std::thread::sleep(CONNECT_BACKOFF);
                }
            }
        }
    }
}

/// The first instance's listener, with the channel its requests arrive on.
#[cfg(windows)]
fn spawn_owner(data_dir: &Path) -> Owner {
    Owner {
        mutex: windows::Win32::Foundation::HANDLE::default(),
        wakes: spawn_listener(data_dir),
    }
}

/// Start the thread that accepts wake messages.
#[cfg(windows)]
fn spawn_listener(data_dir: &Path) -> crossbeam_channel::Receiver<Wake> {
    let (sender, receiver) = crossbeam_channel::unbounded();
    let name = pipe_name(data_dir);
    // A detached thread for the life of the process, which is the life of the
    // window. Nothing joins it: the only way it ends is the process ending, and
    // a join handle the window never uses would be a value that says otherwise.
    std::thread::Builder::new()
        .name("wenle-gui-wake".to_owned())
        .spawn(move || listen(&name, &sender))
        .map(|_| ())
        .unwrap_or_else(|error| {
            // A thread that cannot be started means a second launch will not be
            // heard. The window still opens — that is the trade, and it is named
            // here rather than being allowed to fail the program.
            log::warn!("no listener for later launches: {error}");
        });
    receiver
}

/// Accept wake messages until the process ends.
#[cfg(windows)]
fn listen(name: &str, sender: &crossbeam_channel::Sender<Wake>) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, WIN32_ERROR};
    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let wide = to_wide(name);
    loop {
        // SAFETY: `wide` is NUL-terminated and outlives the call; the security
        // descriptor is null for the default DACL, as above. `PIPE_ACCESS_INBOUND`
        // because this end only ever reads and a second launch only ever writes.
        // `PIPE_REJECT_REMOTE_CLIENTS` for the reason `av-service`'s pipe gives:
        // without it the name is reachable over SMB by anyone who can
        // authenticate to this machine.
        //
        // **Message mode rather than byte mode**, and this is not a detail. A
        // byte-mode pipe is a stream: `ReadFile` returns as soon as *any* bytes
        // are there, so a message is not guaranteed to arrive in one read even
        // though one `WriteFile` sent it. A split message fails to decode, and
        // `decode`'s refusal is by design the same answer as a message from a
        // build that disagrees about the format — so a split would present as a
        // right-click that silently did nothing, which is the one outcome this
        // module exists to prevent. In message mode one write is one message and
        // one read returns it whole, so a failed decode really does mean a
        // disagreement rather than a race.
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                // No outbound buffer: this end never writes, and asking for one
                // would be asking the kernel to hold bytes that cannot arrive.
                0,
                MAX_WAKE_BYTES as u32,
                0,
                None,
            )
        };
        if pipe.is_invalid() {
            log::warn!(
                "no listener on {name}: {}",
                windows::core::Error::from_thread()
            );
            return;
        }

        // SAFETY: a live pipe handle this iteration owns. Blocks until a second
        // launch connects, which is what makes this loop cost nothing while
        // there is no second launch.
        //
        // `ERROR_PIPE_CONNECTED` is a **success** and is treated as one, which
        // is the whole reason this is not `is_ok()`. A client can connect in the
        // gap between `CreateNamedPipeW` and this call — a second launch retries
        // every 50 ms, so landing in that gap is ordinary rather than exotic —
        // and Windows reports that case as a failure of this call even though
        // somebody is there and has already written. Treating it as a failure
        // would disconnect without reading, and the message would be dropped:
        // a right-click that opened nothing and scanned nothing, intermittently,
        // which is the worst shape a defect like this can have.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        let connected = match connected {
            Ok(()) => true,
            Err(error) if WIN32_ERROR::from_error(&error) == Some(ERROR_PIPE_CONNECTED) => true,
            Err(error) => {
                log::warn!("a second launch could not be accepted: {error}");
                // The next iteration creates a fresh instance and blocks in the
                // same call. The pause is here so that a failure which is not
                // transient — a handle that has gone bad, say — retries at the
                // rate of a second launch rather than spinning a core.
                std::thread::sleep(CONNECT_BACKOFF);
                false
            }
        };
        if connected {
            // The body's ceiling plus the four bytes that say how long it is,
            // because a message at the ceiling is legal and a buffer one word
            // short of it would fail the read with `ERROR_MORE_DATA` — a message
            // this end refused for being exactly the size it allows.
            let mut buffer = vec![0u8; MAX_WAKE_BYTES + 4];
            let mut read = 0u32;
            // SAFETY: `pipe` is connected and `buffer` outlives the call. An
            // error here is the ordinary end of a message — the client closes
            // after writing, and the read that follows reports a broken pipe.
            let result = unsafe { ReadFile(pipe, Some(&mut buffer), Some(&mut read), None) };
            if result.is_ok() {
                buffer.truncate(read as usize);
                match decode(&buffer) {
                    Some(wake) => {
                        // A closed channel means the window is gone, which is the
                        // process ending. Nothing to report.
                        let _ = sender.send(wake);
                    }
                    // What `decode` documents: a message this end cannot read is
                    // a message from a build that disagrees about the format, and
                    // the safe reading of that is the one that asks for nothing.
                    // The window still comes to the front — that is what a launch
                    // with no arguments would have asked for, and it is a better
                    // answer than the click doing nothing at all.
                    None => {
                        log::warn!(
                            "a launch sent {} bytes this build could not read; the window will \
                             be raised without acting on it",
                            buffer.len()
                        );
                        let _ = sender.send(Wake::Focus);
                    }
                }
            }
            // SAFETY: a live connected handle this iteration owns, and it is not
            // read again after this.
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
            }
        }
        // SAFETY: a live handle this iteration owns and is finished with. The
        // next iteration creates its own.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(pipe);
        }
    }
}

/// A NUL-terminated UTF-16 copy of `text`.
#[cfg(windows)]
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_directory_always_gives_the_same_name() {
        // The property the whole mechanism rests on: two processes, started at
        // different times, have to arrive at one name. Anything unstable here —
        // a randomised hasher, an address, a timestamp — is a second window.
        let dir = Path::new(r"C:\ProgramData\WenleAV");
        assert_eq!(key(dir), key(dir));
        assert_eq!(mutex_name(dir), mutex_name(dir));
        assert_eq!(pipe_name(dir), pipe_name(dir));
    }

    #[test]
    fn two_spellings_of_one_directory_are_one_name() {
        // Windows paths are case-insensitive, so this is not a hypothetical:
        // the Explorer verb and a shortcut can disagree about the case of a
        // path and still mean the same directory.
        assert_eq!(
            key(Path::new(r"C:\ProgramData\WenleAV")),
            key(Path::new(r"c:\programdata\wenleav"))
        );
    }

    #[test]
    fn two_installations_are_two_names() {
        // A portable copy beside the installed product shares no state with it,
        // so it must not be made to share a window either.
        assert_ne!(
            key(Path::new(r"C:\ProgramData\WenleAV")),
            key(Path::new(r"E:\portable\data"))
        );
    }

    #[test]
    fn the_names_are_the_shapes_windows_expects() {
        let dir = Path::new(r"C:\ProgramData\WenleAV");
        assert!(mutex_name(dir).starts_with(r"Local\"));
        assert!(pipe_name(dir).starts_with(r"\\.\pipe\"));
        // A pipe name is limited to 256 bytes, and `CreateNamedPipeW` silently
        // *truncates* one longer than that rather than refusing it — which would
        // put the listener at a name no client looks for, and present as "the
        // window never hears the second click". The limit is `av_ipc`'s
        // `MAX_PIPE_NAME_BYTES`; it is written out here rather than depended on,
        // because pulling a whole IPC crate in for one constant would be the
        // wrong trade. The prefix is 9 bytes, so the folded name has 247 to fit.
        assert!(pipe_name(dir).len() <= 256, "{}", pipe_name(dir));
        // Sixteen hex digits, so no name can collide with a prefix of another.
        assert_eq!(key(dir).len(), 16);
        assert!(key(dir).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_wake_survives_the_trip() {
        for wake in [
            Wake::Focus,
            Wake::Scan(PathBuf::from(r"C:\Users\me\Downloads\thing.exe")),
        ] {
            assert_eq!(decode(&encode(&wake)), Some(wake));
        }
    }

    #[test]
    fn a_focus_is_four_bytes_and_says_nothing_else() {
        assert_eq!(encode(&Wake::Focus), vec![0, 0, 0, 0]);
        assert_eq!(decode(&[0, 0, 0, 0]), Some(Wake::Focus));
    }

    #[test]
    fn a_message_that_is_not_whole_is_refused_rather_than_half_read() {
        // A path cut short by a buffer boundary must not be scanned: the window
        // would be acting on a file the user did not name, which is the one
        // outcome worse than acting on nothing.
        let full = encode(&Wake::Scan(PathBuf::from(r"C:\a\b.exe")));
        assert_eq!(decode(&full[..full.len() - 1]), None);
        // A prefix claiming more than arrived, which is what a truncated
        // message looks like.
        assert_eq!(decode(&[255, 0, 0, 0]), None);
        // A prefix claiming less than arrived, which is a message with
        // something appended to it.
        assert_eq!(decode(&[1, 0, 0, 0, b'x', b'y']), None);
        // Shorter than the four-byte prefix at all.
        assert_eq!(decode(&[1, 0]), None);
    }

    #[test]
    fn an_oversized_message_is_refused_rather_than_truncated() {
        let mut message = ((MAX_WAKE_BYTES + 1) as u32).to_le_bytes().to_vec();
        message.resize(MAX_WAKE_BYTES + 5, b'x');
        assert_eq!(decode(&message), None);
    }
}
