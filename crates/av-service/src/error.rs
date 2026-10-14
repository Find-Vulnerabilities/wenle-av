//! Everything this service can fail at, named.
//!
//! One enum rather than `anyhow::Error` at the boundaries, for the same reason
//! `av-driver-proto` names its refusals: the caller that has to *decide*
//! something — retry, stop, tell the user which of the two happened — cannot
//! decide anything from a formatted string. `anyhow` is used inside a single
//! function where the answer is always "log it and stop", and never crosses
//! this crate's own boundaries.

use std::path::PathBuf;

use av_ipc::IpcError;

/// A failure in the service.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A filesystem operation failed.
    #[error("{action} {}: {source}", path.display())]
    Io {
        /// What was being done, as a verb phrase that reads after the subject:
        /// "reading", "creating", "writing".
        action: &'static str,
        /// What it was being done to.
        path: PathBuf,
        /// The operating system's own error.
        source: std::io::Error,
    },

    /// The configuration file could not be read or parsed.
    ///
    /// A named variant rather than a converted `io::Error` because this is the
    /// one failure that does *not* stop the service: a service that refused to
    /// start because a user mistyped a key would leave the machine unprotected,
    /// which is a worse outcome than running on defaults and saying so. The
    /// caller reports this through `av_ipc::ConfigReport::load_error`.
    #[error("{}: {message}", path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        message: String,
    },

    /// The rule database could not be read.
    #[error("{path}: {message}")]
    Database {
        /// The file, when one was tried.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// Another instance of this service already holds the lock.
    ///
    /// The failure the single-instance guard exists for. Two services over one
    /// quarantine vault is a corrupted vault — the vault keeps its index in
    /// memory and rewrites the whole file on every change, so the second writer
    /// silently discards the first's entries — and two services answering one
    /// control pipe is two answers to one question.
    #[error("another instance of this service already holds {}", path.display())]
    AlreadyRunning {
        /// The lock file the other instance holds.
        path: PathBuf,
    },

    /// The quarantine vault could not be opened.
    #[error("the quarantine vault at {} could not be opened: {message}", path.display())]
    Vault {
        /// The vault directory.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// The named pipe could not be created or connected.
    #[error("the control pipe {name}: {message}")]
    Pipe {
        /// The pipe name.
        name: String,
        /// What went wrong.
        message: String,
    },

    /// The realtime watcher could not be started.
    #[error("the filesystem watcher could not be started: {message}")]
    Realtime {
        /// What went wrong.
        message: String,
    },

    /// The protocol failed on one connection.
    ///
    /// Carried rather than converted, so that the caller can ask
    /// [`IpcError::poisons_connection`] and decide between closing the
    /// connection and answering an error.
    #[error(transparent)]
    Protocol(#[from] IpcError),

    /// The service control manager refused something.
    #[error("the service control manager: {message}")]
    Scm {
        /// What went wrong.
        message: String,
    },

    /// The binary was run in a way that has no defined meaning.
    #[error("{0}")]
    Usage(String),

    /// Anything else, with a sentence.
    #[error("{0}")]
    Other(String),
}

impl ServiceError {
    /// An IO failure, with the action and the path filled in.
    pub fn io(action: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }

    /// True when this failure means the process has no business carrying on.
    ///
    /// `AlreadyRunning` is the one the caller acts on differently: it is not a
    /// bug and not a fault, it is the guard doing its job, and the correct
    /// response is to exit without an error dialog.
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            ServiceError::AlreadyRunning { .. } | ServiceError::Scm { .. }
        )
    }
}
