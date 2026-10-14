//! What can go wrong reading a container, and what each failure means.
//!
//! The split is by *whose fault it is*, because that is what the caller does
//! with it. A container that is malformed or that uses a method this build has
//! no reader for is a fact about the file, and the scan reports it against the
//! file — the archive is not clean, it is unexamined. A budget refusal is a
//! fact about the *scan*, and the scan says so about itself rather than about
//! the file. A caller that confused the two would either blame a file for a
//! limit the operator set or blame the operator for a file that is simply
//! broken.

use thiserror::Error;

/// Convenience alias for results from this crate.
pub type Result<T, E = ArchiveError> = std::result::Result<T, E>;

/// Every failure a container reader reports.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// The bytes are not a container this build recognises.
    ///
    /// Not a failure in any interesting sense — most files are not archives —
    /// and callers normally reach it through [`crate::Container::open`]
    /// returning `None` rather than as an error.
    #[error("not a container format this build recognises")]
    NotAContainer,

    /// Recognised, and this build has no reader for it.
    ///
    /// This is a statement about the product, not the file, and it is the
    /// honest answer for the formats a commercial scanner is expected to name
    /// but which this build does not yet open. A caller must report the file as
    /// unexamined; it must never report it clean.
    #[error("{format} is not a format this build can open: {detail}")]
    Unsupported {
        /// The format, as [`crate::ArchiveFormat::name`] spells it.
        format: &'static str,
        /// What would be needed, phrased to follow the colon.
        detail: String,
    },

    /// The container's own structures are inconsistent.
    #[error("the {format} container is malformed: {detail}")]
    Malformed {
        /// The format.
        format: &'static str,
        /// What was wrong with it.
        detail: String,
    },

    /// One member's header or data could not be read.
    #[error("the member `{member}` could not be read: {detail}")]
    Member {
        /// The member's name, as far as it could be recovered.
        member: String,
        /// What went wrong.
        detail: String,
    },

    /// The expansion budget refused to produce more bytes.
    ///
    /// Distinguished from the failures above because it is not the file's
    /// fault: a perfectly ordinary large archive hits this on a scan configured
    /// with a small ceiling. See [`crate::ExpansionBudget`].
    #[error(
        "reading this member would exceed the expansion budget: {needed} more bytes against \
         {remaining} remaining"
    )]
    Budget {
        /// How many bytes the read wanted.
        needed: u64,
        /// How many the budget had left.
        remaining: u64,
    },
}

impl ArchiveError {
    /// True when the failure means the file was not examined, as opposed to
    /// examined and found unremarkable.
    ///
    /// Always true — every variant here is a reason the product did not look,
    /// which is why the method reads oddly and is still worth having: it is the
    /// one place a future variant that *is* a conclusion would have to argue
    /// its case.
    pub const fn leaves_contents_unknown(&self) -> bool {
        true
    }

    /// The reason to record against a member in an
    /// [`av_core::ArchiveSummary`], when this failure is about one member.
    ///
    /// Note that a budget refusal maps to [`av_core::SkipReason::Budget`] and
    /// not to `TooLarge`. The two are different claims: `TooLarge` is about the
    /// member, and is chosen up front from its declared size; `Budget` is about
    /// the scan, and is what a member becomes when the ceiling was reached by
    /// everything before it. A caller that wants the first must decide it
    /// before calling, because by the time this error exists the size that
    /// caused it is no longer the only candidate.
    pub fn skip_reason(&self) -> av_core::SkipReason {
        match self {
            ArchiveError::Budget { .. } => av_core::SkipReason::Budget,
            ArchiveError::Unsupported { detail, .. } => av_core::SkipReason::Unsupported {
                method: detail.clone(),
            },
            ArchiveError::Member { detail, .. } | ArchiveError::Malformed { detail, .. } => {
                av_core::SkipReason::Corrupt {
                    detail: detail.clone(),
                }
            }
            ArchiveError::NotAContainer => av_core::SkipReason::Unsupported {
                method: "an unrecognised container".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_says_the_contents_are_unknown() {
        let all = [
            ArchiveError::NotAContainer,
            ArchiveError::Unsupported {
                format: "7z",
                detail: "no reader for LZMA".into(),
            },
            ArchiveError::Malformed {
                format: "zip",
                detail: "no end-of-central-directory record".into(),
            },
            ArchiveError::Member {
                member: "a.exe".into(),
                detail: "the local header is truncated".into(),
            },
            ArchiveError::Budget {
                needed: 100,
                remaining: 10,
            },
        ];
        for error in all {
            assert!(error.leaves_contents_unknown(), "{error:?}");
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
    }

    #[test]
    fn a_budget_refusal_is_not_blamed_on_the_member() {
        // A large member on a small budget is a fact about the scan, and the
        // reason says so. `TooLarge` is the other claim, and is only ever
        // chosen up front from a declared size.
        let error = ArchiveError::Budget {
            needed: 1 << 30,
            remaining: 0,
        };
        assert_eq!(error.skip_reason(), av_core::SkipReason::Budget);
        assert_ne!(
            error.skip_reason(),
            av_core::SkipReason::TooLarge { declared: 1 << 30 }
        );
    }

    #[test]
    fn an_unsupported_method_names_the_method() {
        let error = ArchiveError::Unsupported {
            format: "zip",
            detail: "deflate64".into(),
        };
        assert_eq!(
            error.skip_reason(),
            av_core::SkipReason::Unsupported {
                method: "deflate64".into()
            }
        );
    }

    #[test]
    fn a_malformed_container_becomes_a_corrupt_member() {
        let error = ArchiveError::Malformed {
            format: "zip",
            detail: "the central directory runs past the end of the file".into(),
        };
        assert!(matches!(
            error.skip_reason(),
            av_core::SkipReason::Corrupt { .. }
        ));
    }
}
