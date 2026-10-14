//! What can go wrong in the vault, and what each failure means for the caller.
//!
//! The variants are split by *who can fix them*, because the three callers of
//! this crate need different responses and a single `Other(String)` would force
//! each of them to re-derive it by matching on a message:
//!
//! * [`QuarantineError::Io`] and [`QuarantineError::TargetExists`] are the
//!   user's problem — a file is open, a directory is read-only, a restore
//!   destination is occupied. The real-time path retries these and the GUI
//!   shows them.
//! * [`QuarantineError::Decrypt`], [`QuarantineError::Index`] and
//!   [`QuarantineError::Verify`] mean the vault itself is damaged or was
//!   tampered with. Nothing retries these; they are raised to the user, because
//!   a quarantined sample that no longer decrypts is either a disk fault or
//!   something deliberately editing our storage.
//! * [`QuarantineError::WrongState`] and [`QuarantineError::NotFound`] are
//!   ordinary races — the GUI listed an item, something else purged it, and the
//!   user clicked restore. They are reported, never retried.

use std::path::PathBuf;

use thiserror::Error;

use crate::id::QuarantineId;

/// Convenience alias for results from this crate.
pub type Result<T, E = QuarantineError> = std::result::Result<T, E>;

/// Every failure the vault reports.
#[derive(Debug, Error)]
pub enum QuarantineError {
    /// A filesystem operation failed.
    #[error("{operation} failed for {}: {source}", path.display())]
    Io {
        /// What was being attempted, in the active voice: `"read"`,
        /// `"delete the original of"`.
        operation: &'static str,
        /// The path the operation was performed on.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The index exists but could not be decoded, which in practice means it
    /// was written by a newer version or has been edited.
    #[error("the quarantine index is unreadable: {0}")]
    Index(String),

    /// A sealed payload did not open. Either the key changed, the file was
    /// truncated, or the ciphertext was modified — GCM cannot tell those apart
    /// and neither can this error.
    #[error("the vault could not be decrypted: {0}")]
    Decrypt(String),

    /// The master key could not be created, wrapped or unwrapped.
    #[error("the quarantine master key is unusable: {0}")]
    Key(String),

    /// No item carries this identifier. Almost always a race with a purge.
    #[error("there is no quarantine item {0}")]
    NotFound(QuarantineId),

    /// The item exists but is in the wrong state for the requested operation —
    /// restoring something already deleted, deleting something already
    /// restored.
    #[error("cannot {action} quarantine item {id}: it is {status}")]
    WrongState {
        /// The item.
        id: QuarantineId,
        /// Its current state, as a word that fits the sentence above.
        status: &'static str,
        /// The refused operation, as a bare verb: `"restore"`, `"delete"`.
        /// The message supplies the grammar, so this must not be inflected —
        /// `"deleted"` would read as "cannot deleted".
        action: &'static str,
    },

    /// The restore destination was rejected before anything was written.
    #[error("refusing to restore {id} to {}: {reason}", path.display())]
    UnsafeRestore {
        /// The item.
        id: QuarantineId,
        /// The destination that was refused.
        path: PathBuf,
        /// Why, phrased to follow the colon.
        reason: &'static str,
    },

    /// The destination exists and the caller did not ask for it to be replaced.
    #[error("{} already exists; pass `overwrite` to replace it", .0.display())]
    TargetExists(PathBuf),

    /// The file is larger than the vault is configured to hold.
    #[error("the file is {size} bytes, above the {limit} byte quarantine limit")]
    TooLarge {
        /// Size of the file.
        size: u64,
        /// The configured ceiling.
        limit: u64,
    },

    /// An integrity check found the stored bytes differ from the bytes that
    /// were quarantined.
    #[error("integrity check failed for {id}: {detail}")]
    Verify {
        /// The item.
        id: QuarantineId,
        /// What did not match.
        detail: String,
    },

    /// A serialization step failed. Only reachable through a bug in the
    /// structures being written, since every one of them is a plain data type.
    #[error("could not serialize {what}: {detail}")]
    Serialize {
        /// Which structure.
        what: &'static str,
        /// The encoder's message.
        detail: String,
    },

    /// Anything that does not fit above. Kept for the paths that would
    /// otherwise have to invent a variant.
    #[error("{0}")]
    Other(String),
}

impl QuarantineError {
    /// Build an [`QuarantineError::Io`] with the path attached.
    pub(crate) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        QuarantineError::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    /// True when retrying the same operation later could plausibly succeed.
    ///
    /// The real-time scanner asks this after a failed quarantine: a file held
    /// open by another process is worth another attempt once that process
    /// exits, a payload that will not decrypt never is.
    pub fn is_transient(&self) -> bool {
        match self {
            QuarantineError::TargetExists(_) => true,
            QuarantineError::Io { source, .. } => matches!(
                source.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }

    /// True when the failure means the vault's contents can no longer be
    /// trusted, as opposed to a single operation having failed.
    pub fn is_corruption(&self) -> bool {
        matches!(
            self,
            QuarantineError::Decrypt(_)
                | QuarantineError::Index(_)
                | QuarantineError::Verify { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_file_is_transient_and_a_bad_tag_is_not() {
        let busy = QuarantineError::io(
            "read",
            r"C:\a.exe",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(busy.is_transient());
        assert!(!busy.is_corruption());

        let tampered = QuarantineError::Decrypt("tag mismatch".into());
        assert!(!tampered.is_transient());
        assert!(tampered.is_corruption());
    }

    #[test]
    fn the_io_message_names_the_operation_and_the_path() {
        let e = QuarantineError::io(
            "delete the original of",
            r"C:\Users\me\Downloads\bad.exe",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        let text = e.to_string();
        assert!(
            text.starts_with("delete the original of failed for"),
            "{text}"
        );
        assert!(text.contains(r"C:\Users\me\Downloads\bad.exe"), "{text}");
    }
}
