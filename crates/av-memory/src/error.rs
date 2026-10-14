//! What can go wrong when reading another process, and what each failure means
//! for whoever reads the report.
//!
//! # Why these are outcomes and not errors
//!
//! Almost every failure here is *expected*. Windows refuses a handle to most of
//! the processes on a machine — measured on the development machine this crate
//! was written on, 151 to 155 of the 270 to 296 processes running at the time
//! could not be opened for reading, and every one of them was refused with the
//! same code. A scan that treated that
//! as an error would report failure on every machine it ran on; a scan that
//! treated it as "nothing found" would be lying. So the variants below are not
//! exceptional conditions to propagate, they are *findings about coverage*, and
//! the report keeps them.
//!
//! The three distinctions that matter, and why each is a separate variant:
//!
//! * [`MemoryError::Denied`] and [`MemoryError::Gone`] are separated because
//!   they call for opposite responses. A denied process is one this scan will
//!   never see and the user should be told; a gone process is a process that
//!   exited while we were walking the list, which happens on every scan of a
//!   live machine and means nothing. Measuring them apart is not cosmetic:
//!   on this machine a nonexistent PID is refused with `ERROR_INVALID_PARAMETER`
//!   (87) and an existing protected one with `ERROR_ACCESS_DENIED` (5), so the
//!   two are told apart by the code Windows returns and not by a guess.
//! * [`MemoryError::ReadRefused`] is separate from the process-level failures
//!   because it is about one region. A region that could not be read and a
//!   region that was read and held nothing are different answers, and
//!   collapsing the first into the second is the specific bug this crate is
//!   written to avoid.
//! * [`MemoryError::RegionWalk`] is separate from both because a walk that
//!   stopped halfway says the *whole* per-process picture is partial, whereas a
//!   refused read says one region is missing. The report has to be able to
//!   withhold a completeness claim for the first reason and not the second.
//!
//! # The error codes, and where the numbers come from
//!
//! The constants below are written out rather than imported from the `windows`
//! crate so that the classifier is one piece of ordinary logic on every
//! platform. Each names the measurement that produced it; none is a guess.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Convenience alias for results from this crate.
pub type Result<T, E = MemoryError> = std::result::Result<T, E>;

/// `ERROR_ACCESS_DENIED`. What Windows returns when the caller does not hold
/// the right being asked for, whether because the process belongs to another
/// user, because it is a protected process, or because it is a system process
/// that refuses everybody. Windows does not distinguish those cases and neither
/// does this crate: the report says what it was told.
pub const ERROR_ACCESS_DENIED: u32 = 5;

/// `ERROR_INVALID_PARAMETER`. What `OpenProcess` returns for a PID that is not
/// a running process — measured for two never-allocated PIDs and for PID 0.
pub const ERROR_INVALID_PARAMETER: u32 = 87;

/// `ERROR_PARTIAL_COPY`. What `ReadProcessMemory` returns when any part of the
/// requested range is not readable — measured by reading sixteen bytes past the
/// end of a committed region.
pub const ERROR_PARTIAL_COPY: u32 = 299;

/// Every failure this crate reports.
///
/// `Clone` and `PartialEq` are derived rather than left off because a failure
/// here is a value a report carries and a test compares: [`crate::UnreadableRegion`]
/// holds one, an outcome full of them is compared in both the unit tests and
/// the live ones, and a refusal that could only be inspected by printing it
/// would make the tests assert on prose.
///
/// `Serialize` and `Deserialize` are here because a failure is part of a
/// report, and a report is a thing that gets written to a file and read back —
/// a list of regions that could not be read is exactly the part of a memory
/// scan a support case would want to send. That is also why
/// [`MemoryError::Platform`] names its API as a `String` rather than a
/// `&'static str`: a `&'static str` cannot be deserialized, and an error type
/// that is `Serialize` but not `Deserialize` is an error type that cannot be
/// read back from the report it was written into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum MemoryError {
    /// Windows refused a handle to the process.
    ///
    /// Reached from `OpenProcess` failing with anything other than
    /// [`ERROR_INVALID_PARAMETER`] — in practice [`ERROR_ACCESS_DENIED`] for
    /// most processes on a real machine. The process was listed and could not
    /// be looked at, which is a gap in the scan rather than a failed scan.
    #[error("process {pid} refused a handle: {message} (error {code})")]
    Denied {
        /// The process that was refused.
        pid: u32,
        /// The Win32 error code, kept as a number for reporting and for the
        /// caller that wants to switch on the common ones.
        code: u32,
        /// Windows' own message for the code, so the report does not have to
        /// carry a copy of the system's error table.
        message: String,
    },

    /// The PID does not name a running process.
    ///
    /// Reached when `OpenProcess` fails with [`ERROR_INVALID_PARAMETER`], which
    /// measured for a PID that was never allocated, for PID 0, and for a
    /// process that exited between being listed and being opened. The last of
    /// those is the ordinary case on a live machine.
    #[error("process {pid} does not name a running process")]
    Gone {
        /// The PID that named nothing.
        pid: u32,
    },

    /// The region walk stopped before the end of the address space.
    ///
    /// Reached when `VirtualQueryEx` fails for a reason other than the ordinary
    /// end of the walk. The walk's end is itself a failure — the API has no
    /// other way to say "there is nothing at this address" — so the two are
    /// told apart by the error code, and this variant is what is left when the
    /// code is not [`ERROR_INVALID_PARAMETER`].
    #[error("the region walk of process {pid} stopped at {address:#x}: {message} (error {code})")]
    RegionWalk {
        /// The process being walked.
        pid: u32,
        /// Where the walk stopped. Every address below it was examined.
        address: usize,
        /// The Win32 error code.
        code: u32,
        /// Windows' own message for the code.
        message: String,
    },

    /// A region could not be read.
    ///
    /// Reached from `ReadProcessMemory` failing: the region was freed, or
    /// re-protected to something unreadable, or guarded, or it lies in a part
    /// of the address space this process may not touch. Any of those can happen
    /// between the query that reported the region and the read that fetches it,
    /// which is why the failure is recorded rather than prevented.
    #[error(
        "reading {length} bytes at {address:#x} of process {pid} was refused: {message} \
         (error {code})"
    )]
    ReadRefused {
        /// The process the read was aimed at.
        pid: u32,
        /// Where the read started.
        address: usize,
        /// How many bytes were asked for. Never more than the region reported
        /// holding, because a read that crosses the end of a region fails
        /// wholesale — measured at [`ERROR_PARTIAL_COPY`].
        length: usize,
        /// The Win32 error code.
        code: u32,
        /// Windows' own message for the code.
        message: String,
    },

    /// A Win32 call failed in a way that is not about a particular process.
    ///
    /// Reached from `EnumProcesses` failing, which needs enough memory for
    /// four bytes per process on the machine and can be refused when there is
    /// not.
    #[error("{operation} failed: {message} (error {code})")]
    Platform {
        /// The API that failed, named as the crate calls it.
        operation: String,
        /// The Win32 error code.
        code: u32,
        /// Windows' own message for the code.
        message: String,
    },

    /// This platform cannot scan process memory.
    ///
    /// Reached only on a target that is not Windows. Every function that
    /// reaches it is behind `cfg(windows)` on Windows, so this variant exists
    /// for the build that has no implementation at all.
    #[error("this product scans process memory on Windows only")]
    Unsupported,
}

impl MemoryError {
    /// True when the failure means the process could not be looked at at all,
    /// as opposed to one region of it being unreadable.
    pub fn is_process_level(&self) -> bool {
        matches!(
            self,
            MemoryError::Denied { .. }
                | MemoryError::Gone { .. }
                | MemoryError::RegionWalk { .. }
                | MemoryError::Unsupported
        )
    }

    /// True when Windows refused for want of a right, which is the case the
    /// user can sometimes do something about — the report says so.
    pub fn is_denied(&self) -> bool {
        match self {
            MemoryError::Denied { code, .. } => *code == ERROR_ACCESS_DENIED,
            MemoryError::ReadRefused { code, .. } => *code == ERROR_ACCESS_DENIED,
            _ => false,
        }
    }

    /// The Win32 error code, when the failure came from one.
    pub fn code(&self) -> Option<u32> {
        match self {
            MemoryError::Denied { code, .. }
            | MemoryError::RegionWalk { code, .. }
            | MemoryError::ReadRefused { code, .. }
            | MemoryError::Platform { code, .. } => Some(*code),
            MemoryError::Gone { .. } => Some(ERROR_INVALID_PARAMETER),
            MemoryError::Unsupported => None,
        }
    }
}

/// The Win32 code inside an error from the `windows` crate.
///
/// The crate wraps a Win32 failure as `HRESULT_FROM_WIN32(code)`, which is
/// `0x8007_0000 | code`. A code that is *not* of that form means the value came
/// from somewhere else — a COM failure, or a bug on our side — and is passed
/// through unchanged rather than being masked down to a small number that would
/// name a different error than the one that happened.
///
/// Written as a plain function over `u32` rather than taking the error type, so
/// that the decoding is testable on every platform without a live Win32 call.
pub(crate) fn win32_code(hresult: u32) -> u32 {
    if hresult & 0xFFFF_0000 == 0x8007_0000 {
        hresult & 0xFFFF
    } else {
        hresult
    }
}

/// Classify a failed `OpenProcess`.
///
/// Split out from the call site because it is the one place the crate decides
/// between "this process is not there" and "this process is not for us", and
/// the report's honesty depends on getting it right.
#[cfg(windows)]
pub(crate) fn from_open_process(pid: u32, error: &windows::core::Error) -> MemoryError {
    let code = win32_code(error.code().0 as u32);
    if code == ERROR_INVALID_PARAMETER {
        MemoryError::Gone { pid }
    } else {
        MemoryError::Denied {
            pid,
            code,
            message: error.message(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_from_win32_hresult_yields_the_underlying_code() {
        // The two codes this crate switches on, as Windows actually spells them.
        assert_eq!(win32_code(0x8007_0005), ERROR_ACCESS_DENIED);
        assert_eq!(win32_code(0x8007_0057), ERROR_INVALID_PARAMETER);
        assert_eq!(win32_code(0x8007_012B), ERROR_PARTIAL_COPY);
    }

    #[test]
    fn an_hresult_that_is_not_from_win32_is_not_chopped_to_its_low_bits() {
        // A plausible-wrong implementation masks the low sixteen bits
        // unconditionally, which turns every non-Win32 failure into a small
        // number that names some unrelated Win32 error. `E_FAIL` would become
        // 0x80004005 & 0xFFFF == 16389 and be reported as a Win32 code it is
        // not.
        assert_eq!(win32_code(0x8000_4005), 0x8000_4005);
        assert_eq!(win32_code(0), 0);
    }

    #[test]
    fn a_process_level_failure_is_not_confused_with_a_single_region() {
        let denied = MemoryError::Denied {
            pid: 4,
            code: ERROR_ACCESS_DENIED,
            message: "Access is denied.".into(),
        };
        assert!(denied.is_process_level());
        assert!(denied.is_denied());

        let refused = MemoryError::ReadRefused {
            pid: 4,
            address: 0x1000,
            length: 4096,
            code: ERROR_PARTIAL_COPY,
            message: "Only part of a ReadProcessMemory request was completed.".into(),
        };
        // The distinction the report turns on: one region missing is not the
        // whole process missing.
        assert!(!refused.is_process_level());
        assert!(!refused.is_denied());
        assert_eq!(refused.code(), Some(ERROR_PARTIAL_COPY));
        // The message names the address and the length, because a user reading
        // it needs to know which hole this was.
        let text = refused.to_string();
        assert!(text.contains("0x1000"), "{text}");
        assert!(text.contains("4096"), "{text}");
    }

    #[test]
    fn a_missing_process_reports_the_code_windows_gave_it() {
        let gone = MemoryError::Gone { pid: 999_999 };
        assert_eq!(gone.code(), Some(ERROR_INVALID_PARAMETER));
        assert!(gone.is_process_level());
        assert!(!gone.is_denied());
    }

    #[test]
    fn the_unsupported_variant_has_no_code_to_report() {
        assert_eq!(MemoryError::Unsupported.code(), None);
        assert!(MemoryError::Unsupported.is_process_level());
    }
}
