//! The pipe to the service, with a deadline on every call that can block.
//!
//! # Why this is not `av_service::PipeConnection`
//!
//! Because of what would come with it. `av-service` owns the engine, the vault,
//! the rule database and `crossbeam-channel`, and its pipe type is one module in
//! the middle of that. Depending on the crate to reach the type would put all of
//! it — and the linker would keep the reachable part — inside a DLL that Windows
//! loads into every `powershell.exe`, `wscript.exe`, `cscript.exe` and Office
//! process on the machine. A scripting host's memory is not where an antivirus
//! engine belongs, and the scanner is on the other end of this pipe anyway.
//!
//! What is repeated instead is forty lines of `CreateFileW` and its friends.
//! That is a real cost and it is the smaller one: the alternative is a shared
//! transport crate whose only two callers disagree about everything except the
//! four Win32 flags they have in common.
//!
//! # Why every call is overlapped, when a blocking one would be shorter
//!
//! Because *this* process does not get to block. `IAntimalwareProvider::Scan`
//! runs on the host's thread, before the host decides whether to run the script,
//! and a synchronous `ReadFile` parked on a service that is busy scanning a disk
//! is a `powershell.exe` that has stopped responding — a fault this product
//! would have caused, in somebody else's program, with no way for them to tell
//! why. So the handle is opened `FILE_FLAG_OVERLAPPED`, every operation carries
//! an `OVERLAPPED` and a manual event, and every wait is bounded.
//!
//! # What happens when the deadline passes
//!
//! The operation is cancelled and, crucially, *waited out*: `CancelIoEx` only
//! asks, and returning before the kernel has stopped writing to the
//! `OVERLAPPED` would leave it writing into a stack frame this function has
//! already given back. Then the connection is marked closed and dropped. There
//! is no attempt to resynchronise a pipe that has an unanswered request on it —
//! the next scan reconnects, and a service that cannot answer within the budget
//! twice is a service that is not answering.
//!
//! # The two Win32 idioms, copied rather than shared
//!
//! [`code`] and [`to_wide`] are the same two functions `av-service::win32`
//! holds, and the `HRESULT_FROM_WIN32` trap they exist for is documented there
//! in full: `Error::code()` is an `HRESULT`, so `ERROR_IO_PENDING` compared
//! against the whole value never matches and every overlapped operation would
//! look like a hard failure. Masking the low sixteen bits is the only place in
//! this crate that happens.

use std::time::{Duration, Instant};

use av_ipc::{Connection, IpcError, Read};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE, OPEN_EXISTING,
    ReadFile, WriteFile,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows::core::PCWSTR;

/// How long `WaitNamedPipeW` waits for a free instance of the pipe.
///
/// Shorter than a scan's budget and longer than the gap between one client
/// disconnecting and the service creating the next instance. A service that is
/// not running at all does not spend this: `WaitNamedPipeW` returns at once when
/// no instance of the name exists.
const CONNECT_TIMEOUT_MS: u32 = 1_000;

/// `ERROR_IO_PENDING`.
const ERROR_IO_PENDING: u32 = 997;
/// `ERROR_OPERATION_ABORTED`, which is what a cancelled operation reports.
const ERROR_OPERATION_ABORTED: u32 = 995;
/// `ERROR_IO_INCOMPLETE`, which is what `GetOverlappedResult` reports for an
/// operation that has not finished. Not a failure: something else signalled the
/// event, and the answer is to wait again inside the remaining budget.
const ERROR_IO_INCOMPLETE: u32 = 996;
/// `ERROR_PIPE_BUSY`.
const ERROR_PIPE_BUSY: u32 = 231;
/// `ERROR_BROKEN_PIPE`.
const ERROR_BROKEN_PIPE: u32 = 109;
/// `ERROR_NO_DATA`.
const ERROR_NO_DATA: u32 = 232;
/// `ERROR_PIPE_NOT_CONNECTED`.
const ERROR_PIPE_NOT_CONNECTED: u32 = 233;

/// The Win32 error code inside a `windows::core::Error`.
///
/// `HRESULT_FROM_WIN32(code)` is `0x8007_0000 | code`, so the code is the low
/// sixteen bits. See this module's documentation.
fn code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

/// True when `code` means the far end of the pipe has gone.
const fn is_peer_gone(code: u32) -> bool {
    code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA || code == ERROR_PIPE_NOT_CONNECTED
}

/// A NUL-terminated UTF-16 copy of `text`.
fn to_wide(text: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    wide.push(0);
    wide
}

/// One connection to the service, with a deadline on every blocking operation.
#[derive(Debug)]
pub struct DeadlineConnection {
    name: String,
    handle: HANDLE,
    /// The event every operation waits on. Auto-reset, and reset by hand before
    /// each operation — see [`DeadlineConnection::run_io`].
    event: HANDLE,
    /// How long one operation may take before the connection is abandoned.
    deadline: Duration,
    /// Set once the peer has gone or a deadline has passed, so a second call
    /// reports the same thing instead of starting a new operation on a handle
    /// this code has stopped trusting.
    closed: bool,
}

// A pipe handle is a kernel object handle: valid process-wide and usable from
// any thread. It is owned by exactly one `DeadlineConnection`, which is not
// `Sync`, because two threads reading one handle is the interleaving this
// transport must not allow.
unsafe impl Send for DeadlineConnection {}

impl DeadlineConnection {
    /// Open the pipe `name` and give every operation `deadline` to finish.
    pub fn connect(name: &str, deadline: Duration) -> Result<Self, IpcError> {
        let wide = to_wide(name);
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        let waited = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), CONNECT_TIMEOUT_MS) };
        if !waited.as_bool() {
            let error = windows::core::Error::from_thread();
            let c = code(&error);
            return Err(IpcError::Transport(match c {
                ERROR_PIPE_BUSY => format!(
                    "every instance of {name} is busy and none became free within \
                     {CONNECT_TIMEOUT_MS} ms"
                ),
                _ => format!("{name} could not be reached: {error} (win32 {c})"),
            }));
        }

        // SAFETY: `wide` is NUL-terminated and outlives the call; a null
        // security descriptor and template are what an existing pipe wants.
        // `FILE_FLAG_OVERLAPPED` is the whole point of this module.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                windows::Win32::Foundation::GENERIC_READ.0
                    | windows::Win32::Foundation::GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
        };
        let handle = match handle {
            Ok(handle) => handle,
            Err(error) => {
                return Err(IpcError::Transport(format!(
                    "{name} could not be opened: {error} (win32 {})",
                    code(&error)
                )))
            }
        };

        // Auto-reset (`false`), initially unsignalled (`false`), unnamed.
        // SAFETY: a null security attributes pointer and a null name are both
        // documented as "the default"; the returned handle is owned here and
        // closed in `Drop`.
        let event = match unsafe { CreateEventW(None, false, false, PCWSTR::null()) } {
            Ok(event) => event,
            Err(error) => {
                // SAFETY: `handle` came from `CreateFileW` and is owned here
                // alone. It has no other owner yet, so closing it here is the
                // only close.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(IpcError::Transport(format!(
                    "the completion event for {name} could not be created: {error}"
                )));
            }
        };

        Ok(Self {
            name: name.to_string(),
            handle,
            event,
            deadline,
            closed: false,
        })
    }

    /// Run one overlapped operation to completion, or give up at the deadline.
    ///
    /// `start` issues the call with the `OVERLAPPED` it is handed. It may
    /// succeed immediately, in which case the count it produced is read back
    /// through `GetOverlappedResult`, or report `ERROR_IO_PENDING`, in which
    /// case this waits on the event.
    ///
    /// The event is reset before the operation and is auto-reset, which
    /// together are what make the wait below meaningful: without the reset, a
    /// signal left over from a previous operation would be consumed here and
    /// the wait would return before this operation had finished.
    fn run_io<F>(&mut self, what: &str, start: F) -> Result<u32, IpcError>
    where
        F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
    {
        if self.closed {
            return Err(IpcError::PeerClosed);
        }
        // SAFETY: `event` is owned by this connection and is an event handle,
        // which is what this call takes.
        unsafe {
            let _ = ResetEvent(self.event);
        }

        // One initializer rather than `default()` plus an assignment: the struct
        // is passed to the call below by pointer, and a field written after the
        // value is constructed is a field that is briefly zero — the difference
        // matters here because a zeroed `hEvent` is a valid-looking handle that
        // would make `GetOverlappedResult` wait on nothing.
        let mut overlapped = OVERLAPPED {
            hEvent: self.event,
            ..Default::default()
        };

        if let Err(error) = start(&mut overlapped) {
            let c = code(&error);
            if is_peer_gone(c) {
                self.closed = true;
                return Err(IpcError::PeerClosed);
            }
            if c != ERROR_IO_PENDING {
                return Err(IpcError::Transport(format!("{what}: {error} (win32 {c})")));
            }
        }

        // One non-blocking look, which is the whole answer for an operation that
        // completed before the call returned.
        let mut transferred = 0u32;
        // SAFETY: `overlapped` is on this stack, outlives the call, and is the
        // same structure the operation was started with. `bwait = false`.
        if unsafe { GetOverlappedResult(self.handle, &overlapped, &mut transferred, false) }.is_ok()
        {
            return Ok(transferred);
        }

        let deadline = Instant::now() + self.deadline;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self.abandon(what, &overlapped));
            }
            // `WaitForSingleObject`'s `0` means "wait for ever", so a remaining
            // budget below a millisecond is rounded up rather than passed
            // through — the loop above is what makes the deadline exact.
            let millis = u32::try_from(remaining.as_millis().max(1)).unwrap_or(u32::MAX);
            // SAFETY: `event` is an event handle owned by this connection.
            match unsafe { WaitForSingleObject(self.event, millis) } {
                WAIT_OBJECT_0 => {
                    let mut transferred = 0u32;
                    // SAFETY: as above; the operation has signalled, so this
                    // reads its result rather than waiting.
                    match unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut transferred, false)
                    } {
                        Ok(()) => return Ok(transferred),
                        // Something other than this operation signalled the
                        // event. Waiting again inside the same budget is the
                        // only answer that is neither a guess nor a hang.
                        Err(error) if code(&error) == ERROR_IO_INCOMPLETE => continue,
                        Err(error) => {
                            let c = code(&error);
                            if is_peer_gone(c) || c == ERROR_OPERATION_ABORTED {
                                self.closed = true;
                                return Err(IpcError::PeerClosed);
                            }
                            return Err(IpcError::Transport(format!(
                                "{what}: {error} (win32 {c})"
                            )));
                        }
                    }
                }
                WAIT_TIMEOUT => return Err(self.abandon(what, &overlapped)),
                // SAFETY: as above. `WAIT_FAILED` is the only other documented
                // return, and its code is in `GetLastError`.
                other => {
                    let _ = unsafe { CancelIoEx(self.handle, Some(&overlapped)) };
                    self.closed = true;
                    return Err(IpcError::Transport(format!(
                        "{what}: waiting failed with {other:?}"
                    )));
                }
            }
        }
    }

    /// Give up on an operation that overran, and wait for the kernel to let go.
    ///
    /// The second half is not optional. `CancelIoEx` only requests
    /// cancellation; the `OVERLAPPED` lives on this function's caller's stack,
    /// and returning while the kernel might still write the transferred count
    /// into it is a use-after-free that presents as corruption somewhere else
    /// entirely. `GetOverlappedResult` with `bwait = true` is how the request
    /// becomes a fact.
    fn abandon(&mut self, what: &str, overlapped: &OVERLAPPED) -> IpcError {
        let mut discarded = 0u32;
        // SAFETY: `overlapped` is the structure the outstanding operation was
        // started with and outlives this call; `bwait = true` blocks until that
        // operation has finished cancelling, which is the point.
        unsafe {
            let _ = CancelIoEx(self.handle, Some(overlapped));
            let _ = GetOverlappedResult(self.handle, overlapped, &mut discarded, true);
        }
        self.closed = true;
        IpcError::Transport(format!(
            "{what} did not finish within {} ms, so {} was abandoned",
            self.deadline.as_millis(),
            self.name
        ))
    }
}

impl Connection for DeadlineConnection {
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), IpcError> {
        // Copied out before the loop so that the closure passed to `run_io`
        // borrows a local rather than `self`. `run_io` takes `&mut self`, and a
        // closure capturing `self.handle` would hold a second, immutable borrow
        // of the same value for as long as the call lasts.
        let handle = self.handle;
        let mut written_total = 0usize;
        while written_total < frame.len() {
            let chunk = &frame[written_total..];
            let mut written = 0u32;
            // SAFETY: `chunk` outlives the call and its length is what the
            // signature passes to the operating system; `written` is a `u32` on
            // this stack that outlives the call, and the `OVERLAPPED` is owned
            // by `run_io` for the duration.
            let count = self.run_io("writing to the service", |overlapped| unsafe {
                WriteFile(handle, Some(chunk), Some(&mut written), Some(overlapped))
            })?;
            if count == 0 {
                // A zero-length write on a pipe means the far end went, and
                // looping on it would spin.
                self.closed = true;
                return Err(IpcError::PeerClosed);
            }
            written_total += count as usize;
        }
        Ok(())
    }

    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<Read, IpcError> {
        if buf.is_empty() {
            return Ok(Read::Bytes(0));
        }
        // As in `write_frame`: the handle is copied out so the closure does not
        // borrow `self` while `run_io` borrows it mutably.
        let handle = self.handle;
        let mut read = 0u32;
        // SAFETY: `buf` outlives the call and its length is what the signature
        // passes to the operating system; `read` is a `u32` on this stack that
        // outlives the call.
        let count = self.run_io("reading from the service", |overlapped| unsafe {
            ReadFile(handle, Some(buf), Some(&mut read), Some(overlapped))
        })?;
        if count == 0 {
            // A zero-length read on a byte-mode pipe *is* the close
            // notification, and it is the answer `av_ipc::Read::Closed` exists
            // for.
            self.closed = true;
            return Ok(Read::Closed);
        }
        Ok(Read::Bytes(count as usize))
    }
}

impl Drop for DeadlineConnection {
    fn drop(&mut self) {
        // SAFETY: both handles were created here, are owned by this connection
        // alone, and are closed exactly once. A pending operation has already
        // been waited out by `abandon`, so nothing is outstanding at this point.
        unsafe {
            let _ = CloseHandle(self.handle);
            let _ = CloseHandle(self.event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_win32_code_is_the_low_half_of_the_hresult() {
        // The trap this module's copy of `code` exists for. Without the mask,
        // `ERROR_IO_PENDING` never matches what `WriteFile` reports and every
        // overlapped write reads as a hard failure — which would make this
        // transport fail every single time, on a machine where everything is
        // fine.
        let error = windows::core::Error::from_hresult(
            windows::Win32::Foundation::WIN32_ERROR(ERROR_IO_PENDING).to_hresult(),
        );
        assert_eq!(code(&error), ERROR_IO_PENDING);
        assert_ne!(error.code().0, ERROR_IO_PENDING as i32);
        // And the mask does not collide one code with another.
        assert_ne!(code(&error), ERROR_IO_INCOMPLETE);
    }

    #[test]
    fn every_way_a_pipe_peer_can_go_reads_as_gone() {
        for gone in [ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED] {
            assert!(is_peer_gone(gone), "{gone}");
        }
        // `ERROR_IO_PENDING` in particular must not: treating it as a close is
        // the same failure as the missing mask, from the other direction, and
        // it is the code an overlapped transport sees most often.
        assert!(!is_peer_gone(ERROR_IO_PENDING));
        assert!(!is_peer_gone(ERROR_IO_INCOMPLETE));
        assert!(!is_peer_gone(0));
    }

    #[test]
    fn a_wide_pipe_name_is_terminated_and_the_terminator_is_not_counted() {
        let wide = to_wide(r"\\.\pipe\wenleav-control");
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(wide.len(), r"\\.\pipe\wenleav-control".len() + 1);
        assert_eq!(to_wide("").len(), 1);
    }
}
