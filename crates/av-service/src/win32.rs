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

// ---------------------------------------------------------------------------
// A started process's command line
// ---------------------------------------------------------------------------

/// `ProcessCommandLineInformation`, from `ntddk.h`'s `PROCESSINFOCLASS`.
///
/// Not in the `windows` crate's `Win32` surface — it is an NT call and the
/// `Win32` bindings do not carry it — so the declaration below is hand-written,
/// the same way `av-driver` declares the kernel calls it uses.
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: *mut core::ffi::c_void,
        process_information_class: u32,
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// The command line a process was started with, read from the process itself.
///
/// # Why the service reads this and not the driver
///
/// `PS_CREATE_NOTIFY_INFO` carries the image and the parent process and no
/// arguments, and a driver that read another process's `PEB` to find them would
/// be touching user-mode memory from a kernel callback. The service can open the
/// process and ask, which is an ordinary user-mode call with an ordinary failure
/// mode.
///
/// # What it cannot do
///
/// A process that has already exited cannot be opened, so the answer is `None`
/// for exactly the programs that run and finish fastest — and `None` is not the
/// empty command line: a rule with a command-line condition treats it as
/// "unknown" and does not fire. That is the honest reading, and it is why the
/// behaviour rules that use this are written as pairs with a path or a parent.
#[cfg(windows)]
pub fn command_line(process_id: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: the handle is opened for query access, every call below is given
    // a buffer this function owns, and the handle is closed on every path
    // through it — including the two early returns.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id).ok()?;
        let mut needed = 0u32;
        // The first call is for the size and is expected to fail with
        // STATUS_INFO_LENGTH_MISMATCH; its status is not interesting, its
        // `needed` is.
        NtQueryInformationProcess(
            handle.0,
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 || needed > 0x1_0000 {
            let _ = CloseHandle(handle);
            return None;
        }
        let mut buffer = vec![0u8; needed as usize + 2];
        let status = NtQueryInformationProcess(
            handle.0,
            PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut needed,
        );
        let _ = CloseHandle(handle);
        if status < 0 {
            return None;
        }
        parse_command_line(&buffer, buffer.as_ptr() as usize)
    }
}

/// Pull the text out of the `UNICODE_STRING` that
/// `ProcessCommandLineInformation` leaves at the front of the buffer.
///
/// `base` is the address the buffer starts at, which is what the `Buffer` field
/// is an absolute pointer to. Every field is checked against the buffer rather
/// than trusted: this parses a kernel-written structure from a process that is
/// not ours.
fn parse_command_line(buffer: &[u8], base: usize) -> Option<String> {
    if buffer.len() < 16 {
        return None;
    }
    let length = u16::from_le_bytes([buffer[0], buffer[1]]) as usize;
    let pointer = u64::from_le_bytes(buffer[8..16].try_into().ok()?) as usize;
    if length == 0 || length % 2 != 0 || pointer == 0 {
        return None;
    }
    let offset = pointer.checked_sub(base)?;
    let end = offset.checked_add(length)?;
    if end > buffer.len() {
        return None;
    }
    let units: Vec<u16> = buffer[offset..end]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_end_matches('\0').trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod command_line_tests {
    use super::parse_command_line;

    /// A buffer shaped like the one `ProcessCommandLineInformation` returns:
    /// a `UNICODE_STRING` whose `Buffer` points into the same allocation, and
    /// the text after it.
    fn buffer_with(text: &str) -> Vec<u8> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let length = (units.len() * 2) as u16;
        let mut buffer = vec![0u8; 16 + units.len() * 2 + 2];
        buffer[0..2].copy_from_slice(&length.to_le_bytes());
        buffer[2..4].copy_from_slice(&length.to_le_bytes());
        let base = buffer.as_ptr() as usize;
        // The pointer is filled in after the allocation is made; this is the
        // address the text will live at, which is `base + 16`.
        let pointer = (base + 16) as u64;
        buffer[8..16].copy_from_slice(&pointer.to_le_bytes());
        for (index, unit) in units.iter().enumerate() {
            let at = 16 + index * 2;
            buffer[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        buffer
    }

    #[test]
    fn a_command_line_is_read_out_of_the_buffer() {
        let buffer = buffer_with(r#""C:\Windows\System32\vssadmin.exe" delete shadows /all"#);
        let base = buffer.as_ptr() as usize;
        assert_eq!(
            parse_command_line(&buffer, base).as_deref(),
            Some(r#""C:\Windows\System32\vssadmin.exe" delete shadows /all"#)
        );
    }

    #[test]
    fn a_pointer_outside_the_buffer_is_refused_rather_than_followed() {
        // The shape a hostile or stale answer would have: a length and a
        // pointer that disagree with the allocation. Following it would read
        // memory this process does not own, which is the reason the check is
        // here rather than in a comment.
        let mut buffer = buffer_with("benign");
        let base = buffer.as_ptr() as usize;
        let far = (base + 0x10_0000) as u64;
        buffer[8..16].copy_from_slice(&far.to_le_bytes());
        assert_eq!(parse_command_line(&buffer, base), None);
    }

    #[test]
    fn a_length_past_the_end_of_the_buffer_is_refused() {
        let mut buffer = buffer_with("benign");
        let base = buffer.as_ptr() as usize;
        buffer[0..2].copy_from_slice(&0xFFFEu16.to_le_bytes());
        assert_eq!(parse_command_line(&buffer, base), None);
    }

    #[test]
    fn an_empty_command_line_is_none_and_not_an_empty_string() {
        let buffer = buffer_with("");
        let base = buffer.as_ptr() as usize;
        assert_eq!(parse_command_line(&buffer, base), None);
    }

    #[test]
    fn a_truncated_buffer_is_refused() {
        assert_eq!(parse_command_line(&[0u8; 8], 0), None);
    }

    // ---------------------------------------------------------------- live
    //
    // The four tests above prove the *parsing*. These two prove the call: the
    // structure is only worth parsing if `NtQueryInformationProcess` really
    // fills it, and that question cannot be answered by a synthetic buffer.
    #[cfg(windows)]
    #[test]
    fn the_command_line_of_this_process_is_readable() {
        let line = super::command_line(std::process::id()).expect("read this process's command line");
        let folded = line.to_ascii_lowercase();
        assert!(
            folded.contains("av_service"),
            "the command line does not name the test binary: {line}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_command_line_of_another_process_is_readable() {
        // A process given an argument the test chose, so the assertion is about
        // the argument and not about the executable's name.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 6 127.0.0.1 >nul"])
            .spawn()
            .expect("spawn a child to read");
        let mut line = None;
        // The child has to exist *and* have its command line committed; the loop
        // is short and the child lives for about five seconds.
        for _ in 0..40 {
            if let Some(read) = super::command_line(child.id()) {
                line = Some(read);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        let line = line.expect("read the child's command line");
        let folded = line.to_ascii_lowercase();
        assert!(
            folded.contains("ping -n 6") && folded.contains("127.0.0.1"),
            "the child's arguments are not in what was read: {line}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_process_that_does_not_exist_yields_none_rather_than_an_error() {
        // An id that cannot be running: the pid space is far larger than any
        // possible process, and the answer has to be "unknown", not a panic.
        assert_eq!(super::command_line(0xFFFF_FFF0), None);
    }
}
