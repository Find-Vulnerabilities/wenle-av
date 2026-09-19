//! Error types shared across the workspace.
//!
//! Every fallible operation in the antivirus funnels through [`AvError`]. The
//! scanner deliberately keeps scanning after a per-file error: one unreadable
//! file must never abort a whole scan, so most call sites downgrade an
//! [`AvError`] into a recorded per-target failure instead of propagating it.

use std::path::{Path, PathBuf};

/// Convenience alias used throughout the workspace.
pub type AvResult<T> = Result<T, AvError>;

/// Everything that can go wrong inside the antivirus.
#[derive(Debug, thiserror::Error)]
pub enum AvError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// I/O error carrying the path that caused it — far more useful in logs
    /// than a bare `std::io::Error`.
    #[error("I/O error on `{}`: {source}", path.display())]
    IoAt {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid configuration: {0}")]
    Config(String),

    /// A rule file could not be parsed.
    #[error("rule syntax error in {file}:{line}:{column}: {message}")]
    RuleSyntax {
        file: String,
        line: u32,
        column: u32,
        message: String,
    },

    /// A rule parsed but refers to something the engine cannot evaluate.
    #[error("rule compilation failed: {0}")]
    RuleCompile(String),

    /// A compiled rule database is corrupt or was built by an incompatible
    /// engine version.
    #[error("rule database `{}` is unusable: {reason}", path.display())]
    RuleDatabase { path: PathBuf, reason: String },

    #[error("malformed or unsupported binary: {0}")]
    Binary(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("the operation was cancelled")]
    Cancelled,

    #[error("serialization error: {0}")]
    Serde(String),

    /// A Win32 call returned a failure status.
    #[error("Windows API `{call}` failed with code {code:#010X}")]
    Win32 { call: &'static str, code: u32 },

    #[error("{0}")]
    Other(String),
}

impl AvError {
    /// Attach a path to a bare I/O error.
    pub fn io_at(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        AvError::IoAt {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    /// Build a [`AvError::Win32`] from a `windows` crate `Result`.
    #[cfg(windows)]
    pub fn win32(call: &'static str, result: windows::core::Result<()>) -> Self {
        match result {
            Ok(()) => AvError::Other(format!("{call} unexpectedly reported failure")),
            Err(e) => AvError::Win32 {
                call,
                code: e.code().0 as u32,
            },
        }
    }

    pub fn win32_code(call: &'static str, code: u32) -> Self {
        AvError::Win32 { call, code }
    }

    /// True when the failure is transient and retrying the same operation
    /// could plausibly succeed (a file lock held by another process, a
    /// temporarily unmounted volume, ...).
    pub fn is_transient(&self) -> bool {
        match self {
            AvError::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            ),
            AvError::IoAt { source, .. } => matches!(
                source.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            ),
            AvError::Win32 { code, .. } => matches!(
                *code,
                // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_BUSY
                0x20 | 0x21 | 0xAA
            ),
            _ => false,
        }
    }
}

impl From<serde_json::Error> for AvError {
    fn from(e: serde_json::Error) -> Self {
        AvError::Serde(e.to_string())
    }
}

impl From<toml::de::Error> for AvError {
    fn from(e: toml::de::Error) -> Self {
        AvError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for AvError {
    fn from(e: toml::ser::Error) -> Self {
        AvError::Config(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_at_includes_path_in_message() {
        let err = AvError::io_at(
            r"C:\Windows\notepad.exe",
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        );
        assert!(err.to_string().contains(r"C:\Windows\notepad.exe"));
    }

    #[test]
    fn sharing_violation_is_transient() {
        assert!(AvError::win32_code("CreateFileW", 0x20).is_transient());
        assert!(AvError::win32_code("CreateFileW", 0x02).is_transient() == false);
    }
}
