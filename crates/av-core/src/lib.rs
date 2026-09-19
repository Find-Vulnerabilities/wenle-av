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
//! and short-circuit the score. Trust signals — a valid Authenticode signature
//! from a reputable publisher, a known-good path — subtract from the score but
//! can never override a decisive detection. This is what keeps the
//! false-positive rate low without blinding the engine to real threats.

// Lint policy is defined once in the workspace manifest. Tests opt out of the
// panic-family lints, where unwrapping is how an assertion is written.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod error;
pub mod paths;
pub mod scan;
pub mod threat;
pub mod verdict;

pub use config::{AvConfig, Theme};
pub use error::{AvError, AvResult};
pub use paths::AvPaths;
pub use scan::{
    Digests, FileKind, FileScanReport, ScanFailure, ScanOptions, ScanProgress, ScanReport,
    ScanStats, ScanTarget,
};
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

/// Communication port the minifilter exposes and the user-mode scanner
/// connects to.
pub const DRIVER_PORT_NAME: &str = r"\WenleAVPort";

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_not_empty() {
        assert!(!super::VERSION.is_empty());
    }

    #[test]
    fn driver_port_is_a_valid_nt_path() {
        assert!(super::DRIVER_PORT_NAME.starts_with('\\'));
    }
}
