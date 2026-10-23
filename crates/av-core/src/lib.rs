//! Foundation types for the Wenle Antivirus workspace.
//!
//! This crate holds everything that more than one component needs to agree on:
//! the error type, the threat-naming scheme, the detection/verdict scoring
//! model, the filesystem layout and the configuration document. It deliberately
//! depends on almost nothing, so it can be linked into the kernel-adjacent
//! user-mode helpers, the GUI and the command-line tools alike.
//!
//! # The verdict model in one paragraph
//!
//! Detectors do not vote yes/no. Each produces a [`Detection`] carrying a
//! severity and a score, and the accumulated score is compared against
//! [`VerdictThresholds`] to produce a [`Verdict`]. Indicators that have no
//! realistic false-positive rate (an exact known-bad hash) are marked decisive
//! and short-circuit the score. Trust signals (a valid Authenticode signature
//! from a reputable publisher, a known-good path) subtract from the score but
//! can never override a decisive detection. This is what keeps the
//! false-positive rate low without blinding the engine to real threats.

// Lint policy is defined once in the workspace manifest. Tests opt out of the
// panic-family lints, where unwrapping is how an assertion is written.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod alloc;
pub mod archive;
pub mod config;
pub mod error;
pub mod hash;
pub mod paths;
pub mod scan;
pub mod stats;
pub mod threat;
pub mod verdict;

pub use alloc::{crash_log_installed, set_crash_log, MemoryStatus, Reporting};
pub use archive::{ArchiveSkip, ArchiveSummary, SkipReason};
pub use config::{AvConfig, Theme};
pub use error::{AvError, AvResult};
pub use hash::{HashKind, Hasher};
pub use paths::AvPaths;
pub use scan::{
    Digests, FileKind, FileScanReport, ScanFailure, ScanOptions, ScanProgress, ScanReport,
    ScanStats, ScanTarget, FLOOR_BYTES_PER_SEC,
};
pub use stats::{count, entropy, histogram, mean, region};
pub use threat::{Platform, ThreatCategory, ThreatName};
pub use verdict::{
    render_preview, Assessment, Detection, DetectionSource, MatchLocation, Severity, Verdict,
    VerdictThresholds,
};

/// Product version, taken from the crate version so there is exactly one place
/// to bump it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable product name used in window titles and log headers.
pub const PRODUCT_NAME: &str = "Wenle Antivirus";

/// Name of the NT service, the minifilter altitude owner and the install
/// directory. Kept in one place because the installer, the service host and the
/// driver client must all agree.
pub const SERVICE_NAME: &str = "WenleAV";

/// The *AppUserModelID* a Windows notification is posted under.
///
/// Windows identifies the sender of a toast by a string, and three places have
/// to agree on it: the process that posts one (`av-gui`), the key
/// `wenle integrate notifications` registers under
/// `HKCU\Software\Classes\AppUserModelId`, and the per-application notification
/// settings Windows writes for the user once an app has posted.
///
/// A disagreement is an error nowhere. A toast posted under an identifier
/// Windows has never heard of is accepted, is shown, and simply carries a name
/// and an icon that are not this product's — which is precisely the shape of
/// failure the port name below was spelled once to avoid: a wrong string that
/// nothing validates and nothing reports.
///
/// It is the same string as [`SERVICE_NAME`] because it is the same product. A
/// user who sees "WenleAV" in the service list and "WenleAV" in notification
/// settings is looking at one thing, and the display name that goes beside it
/// is [`PRODUCT_NAME`].
pub const APP_USER_MODEL_ID: &str = SERVICE_NAME;

// There is deliberately no port name here.
//
// There was one -- `DRIVER_PORT_NAME`, documented as "the port the user-mode
// scanner connects to" -- and it said `\WenleAVPort` while the driver created
// `\WenleAvFilterPort`. Nothing read it but its own test, so the disagreement
// was invisible, and the client that was going to read it would have connected
// to a port that does not exist: a failure with no error anywhere, because a
// driver with no service attached is a supported state rather than a fault.
//
// The name now lives in `av_driver_proto::port`, the crate the driver and the
// user-mode client both already link, and it is spelled exactly once.

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_not_empty() {
        assert!(!super::VERSION.is_empty());
    }

    #[test]
    fn the_service_name_is_not_empty_and_has_no_spaces() {
        // The one name this crate still owns, and the one an SCM call takes.
        // `SERVICE_NAME` reaches `CreateServiceW` and `OpenServiceW`, where a
        // space is legal and a name that differs by one is a service that
        // cannot be opened.
        assert!(!super::SERVICE_NAME.is_empty());
        assert!(!super::SERVICE_NAME.contains(char::is_whitespace));
    }
}
