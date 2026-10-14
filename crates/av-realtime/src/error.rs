//! Everything this crate can fail at, and the input that reaches each failure.
//!
//! Two of these are worth more than the rest, because each one describes a
//! *blind spot* rather than a transient problem:
//!
//! * [`RealtimeError::LengthOverrun`] — the kernel said it wrote more bytes than
//!   the buffer we handed it. Nothing sane does that, so the buffer is not
//!   trusted, and the alternative to this error is a slice that panics or a
//!   silently truncated path.
//! * [`RealtimeError::Win32`] on a watched root — the tree is no longer being
//!   watched. The watcher reports it on its event stream rather than logging it
//!   and carrying on, because "protection is running" and "protection is running
//!   over three of the four directories you asked for" are different promises
//!   and the user is entitled to the second one.

use std::path::PathBuf;

use crate::notify::NotifyError;

/// A failure in the realtime watcher.
#[derive(Debug, thiserror::Error)]
pub enum RealtimeError {
    /// The buffer `ReadDirectoryChangesW` filled is not a sequence of well-formed
    /// records.
    ///
    /// Reached from the bytes the kernel wrote, and from nothing else: this is
    /// the only error in this crate that untrusted input can cause.
    #[error("the directory-change notification buffer is malformed: {0}")]
    Notify(#[from] NotifyError),

    /// A Win32 call returned a failure.
    ///
    /// `call` names the function so the message says what was being attempted.
    /// Reached when the system refuses the call — a root that has been deleted
    /// between the check and the open, a machine out of handles, a directory the
    /// account cannot read.
    #[error("{call} failed: {message} (0x{code:08X})")]
    Win32 {
        /// The Win32 function that failed, e.g. `CreateFileW`.
        call: &'static str,
        /// The `GetLastError` value, widened to `u32` so it prints unsigned.
        code: u32,
        /// The system's own description of the code.
        message: String,
    },

    /// A watch thread could not be started.
    ///
    /// Reached when the process is out of threads, or out of memory for the
    /// thread's stack — a machine under enough pressure that the protection is
    /// not going to run anyway.
    #[error("the watch thread for {root} could not be started: {source}")]
    Spawn {
        /// The root that would have been watched by that thread.
        root: PathBuf,
        /// The operating system's reason.
        #[source]
        source: std::io::Error,
    },

    /// A completed read reported more bytes than the buffer it was given.
    ///
    /// Reached from `GetOverlappedResult`'s byte count. A kernel that returns
    /// more than it was offered is either not the kernel this code was written
    /// for or has been corrupted, and in neither case is the excess meaningful.
    /// Refusing it is the only answer that is not a guess.
    #[error(
        "the kernel reported {reported} bytes written into a {buffer}-byte buffer, \
         so the notification buffer cannot be trusted"
    )]
    LengthOverrun {
        /// What `GetOverlappedResult` reported.
        reported: u32,
        /// How large the buffer handed to `ReadDirectoryChangesW` was.
        buffer: usize,
    },

    /// The quarantine vault could not be opened.
    ///
    /// Reached when the vault directory cannot be created, or its index cannot be
    /// read or unsealed — a permissions problem, a full disk, a vault written by
    /// a different Windows account. It ends the whole start, and that is the
    /// point: a watcher that finds a malicious file and cannot take it tells the
    /// user about a file it then leaves where it is, which is worse than not
    /// having started.
    #[error("the quarantine vault at {root} could not be opened: {source}")]
    Vault {
        /// The vault root that was handed to `QuarantineVault::open`.
        root: PathBuf,
        /// The vault's own reason.
        #[source]
        source: av_quarantine::QuarantineError,
    },

    /// The scanning thread could not be started.
    ///
    /// Reached when the process is out of threads or out of memory for the
    /// thread's stack. Distinct from [`RealtimeError::Spawn`], which names a
    /// watched root: this thread has none, and a message that named a directory
    /// would name the wrong thing.
    #[error("the realtime scanning thread could not be started: {source}")]
    WorkerSpawn {
        /// The operating system's reason.
        #[source]
        source: std::io::Error,
    },

    /// A worker thread ended without handing back what it owned.
    ///
    /// Reached when the scanning thread panicked. The quarantine vault it held
    /// is gone with it, which is why this is an error and not a silent `None`.
    #[error("the realtime worker thread ended without returning its state")]
    WorkerLost,

    /// This platform has no `ReadDirectoryChangesW`, and this crate has no
    /// second implementation of it.
    ///
    /// Reached on every call to [`crate::DirectoryWatch::start`] on a
    /// non-Windows target.
    #[error("realtime directory watching is implemented for Windows only")]
    Unsupported,
}

impl RealtimeError {
    /// Wrap a failed Win32 call.
    ///
    /// `windows_core::Error` is not carried directly so that this message does
    /// not depend on which of `windows`' conversion traits is in scope at the
    /// call site: the code and the text are copied out at the point of failure,
    /// where they are known to be about the call that just failed.
    #[cfg(windows)]
    pub(crate) fn win32(call: &'static str, error: windows::core::Error) -> Self {
        Self::Win32 {
            call,
            code: error.code().0 as u32,
            message: error.message(),
        }
    }
}

/// The result type this crate uses.
pub type Result<T> = std::result::Result<T, RealtimeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_win32_failure_names_the_call_and_keeps_the_code_unsigned() {
        let e = RealtimeError::Win32 {
            call: "CreateFileW",
            // A `GetLastError` value read as a signed `i32` would print as
            // `-2147024891`; the message is for a human reading a log line, and
            // the documentation of every one of these codes is written unsigned.
            code: 0x8007_0005,
            message: "Access is denied.".into(),
        };
        let text = e.to_string();
        assert!(text.contains("CreateFileW"), "{text}");
        assert!(text.contains("0x80070005"), "{text}");
        assert!(text.contains("Access is denied."), "{text}");
    }

    #[test]
    fn a_notify_error_is_reported_as_the_cause_of_a_notify_failure() {
        let e: RealtimeError = NotifyError::OddNameLength {
            offset: 12,
            length: 7,
        }
        .into();
        assert!(matches!(e, RealtimeError::Notify(_)));
        // The wrapped error is the source, so a caller logging the chain prints
        // both what failed and why.
        let source = std::error::Error::source(&e).map(|s| s.to_string());
        assert!(
            source.as_deref().is_some_and(|s| s.contains("7-byte name")),
            "the cause did not carry the declared length: {source:?}"
        );
        // And the outer message says which kind of failure it was, so a caller
        // that only prints the top of the chain still knows what happened.
        assert!(e.to_string().contains("malformed"), "{e}");
    }
}
