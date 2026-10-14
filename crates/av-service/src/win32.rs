//! The two Win32 idioms this crate needs in more than one module.
//!
//! # Why these two, and why here
//!
//! Everything else that calls the operating system in this crate does so from
//! one module and stays there. These two do not: the single-instance guard, the
//! driver presence check and the named-pipe transport all have to turn a
//! `windows::core::Error` into the integer a Win32 programmer recognises, and
//! all three have to build a NUL-terminated UTF-16 buffer. Three copies of
//! either is three places for the masking to be wrong.
//!
//! # The `HRESULT` trap
//!
//! `windows::core::Error::code()` returns an `HRESULT`, not a Win32 error code.
//! A Win32 failure arrives as `HRESULT_FROM_WIN32(code)`, which is
//! `0x8007_0000 | code` — so comparing the whole value against `32` for
//! `ERROR_SHARING_VIOLATION` never matches, and the guard would report a
//! sharing violation as a generic IO failure while looking entirely correct.
//! [`code`] masks the low sixteen bits and is the only place that happens.
//!
//! The masking is `cfg(windows)`-free: an `HRESULT` is a plain integer whatever
//! platform this is compiled for, and a non-Windows build never produces one to
//! mask.

/// The Win32 error code inside a `windows::core::Error`.
///
/// `HRESULT_FROM_WIN32(code)` is `0x8007_0000 | code`, so the code is the low
/// sixteen bits. Win32 codes are all below `0x1_0000`, which is what makes the
/// mask exact rather than a guess.
pub fn code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

/// `ERROR_FILE_NOT_FOUND`.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_PATH_NOT_FOUND`.
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_SHARING_VIOLATION`, which is what a second `CreateFileW` with an
/// incompatible share mode gets.
pub const ERROR_SHARING_VIOLATION: u32 = 32;
/// `ERROR_PIPE_BUSY`, which is what a client gets when every instance of a pipe
/// is connected and the creator has not created another.
pub const ERROR_PIPE_BUSY: u32 = 231;
/// `ERROR_PIPE_CONNECTED`, which `ConnectNamedPipe` reports when a client
/// arrived between the create and the connect. It is success, not failure.
pub const ERROR_PIPE_CONNECTED: u32 = 535;
/// `ERROR_BROKEN_PIPE`, which is how both ends learn the other has gone.
pub const ERROR_BROKEN_PIPE: u32 = 109;
/// `ERROR_NO_DATA`, the other spelling of the same thing on a closing pipe.
pub const ERROR_NO_DATA: u32 = 232;
/// `ERROR_PIPE_NOT_CONNECTED`.
pub const ERROR_PIPE_NOT_CONNECTED: u32 = 233;

/// `ERROR_NO_TOKEN`, which `OpenThreadToken` returns for a thread that is not
/// impersonating.
///
/// In [`crate::peer`] this is not a failure: a thread with no token is a thread
/// that has reverted, and the test that the impersonation ends before the answer
/// comes back is written as this code rather than as "the call failed", because
/// a failure with any other code would mean the thread is still impersonating
/// somebody and the token simply could not be opened as this process.
pub const ERROR_NO_TOKEN: u32 = 1008;

/// `ERROR_CALL_NOT_IMPLEMENTED`.
///
/// The `windows` crate keeps this in `Win32::Foundation` rather than in the
/// service module that needs it, and the service module is the only one that
/// does: it is what a control handler returns for a control it does not
/// implement, which is the documented answer and a different one from silence.
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, which is what
/// `StartServiceCtrlDispatcherW` returns when the process was not started by
/// the Service Control Manager.
///
/// The code that matters most in [`crate::scm`], because it is the difference
/// between "this is a service" and "this is a program a user double-clicked",
/// and a program that reported the second as a fault would put an error in the
/// event log every time anybody ran it.
pub const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

/// True when `code` means the far end of a pipe has gone.
///
/// Three codes for one fact, and all three occur: a clean close gives
/// `ERROR_BROKEN_PIPE`, a close while a write is in flight gives `ERROR_NO_DATA`
/// on some paths, and `PeekNamedPipe` on a disconnected instance gives
/// `ERROR_PIPE_NOT_CONNECTED`. Treating only the first as a close is how a
/// service ends up logging a fault every time a client exits.
pub const fn is_peer_gone(code: u32) -> bool {
    code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA || code == ERROR_PIPE_NOT_CONNECTED
}

/// A NUL-terminated UTF-16 copy of `text`.
///
/// Every `...W` Win32 call wants one. An interior NUL would truncate the string
/// silently — a guard holding a different file from the one it reported, a pipe
/// created under a different name from the one a client connects to — and an
/// interior NUL cannot occur in a path or a pipe name this process built, so
/// there is nothing to defend against and nothing to lose by not defending.
///
/// The terminating NUL is *not* counted in the returned length, which is the
/// convention every caller here wants: `PCWSTR` reads to the NUL, and a
/// `length` argument that wanted the NUL would say so.
pub fn to_wide(text: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = text.encode_wide().collect();
    wide.push(0);
    wide
}

/// [`to_wide`] for a `&str`.
pub fn to_wide_str(text: &str) -> Vec<u16> {
    to_wide(std::ffi::OsStr::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_win32_code_is_the_low_half_of_the_hresult() {
        // The trap this module exists for: `HRESULT_FROM_WIN32(32)` is
        // `0x8007_0020`, and comparing *that* against 32 is false while looking
        // like it should be true.
        let error = windows::core::Error::from_hresult(
            windows::Win32::Foundation::WIN32_ERROR(ERROR_SHARING_VIOLATION).to_hresult(),
        );
        assert_eq!(code(&error), ERROR_SHARING_VIOLATION);
        assert_ne!(error.code().0, ERROR_SHARING_VIOLATION as i32);
    }

    #[test]
    fn every_way_a_pipe_peer_can_go_reads_as_gone() {
        for gone in [ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED] {
            assert!(is_peer_gone(gone), "{gone}");
        }
        // And a code that is not about the peer at all does not.
        assert!(!is_peer_gone(ERROR_PIPE_BUSY));
        assert!(!is_peer_gone(0));
    }

    #[test]
    fn a_wide_string_is_terminated_and_the_terminator_is_not_counted() {
        let wide = to_wide_str(r"\\.\pipe\wenleav-control");
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(wide.len(), r"\\.\pipe\wenleav-control".len() + 1);
        assert_eq!(to_wide_str("").len(), 1);
    }
}
