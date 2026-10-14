//! Catching a file when it appears, rather than when someone asks.
//!
//! # What "realtime" means here, exactly
//!
//! Three different things are called realtime protection, and the difference
//! between them is what a user is actually promised:
//!
//! 1. **Notice after the fact.** The filesystem is watched, a new file is
//!    scanned, and if it is malicious it is quarantined. The file may already
//!    have run.
//! 2. **Block before execution.** The creation of an executable is intercepted,
//!    the scanner's answer is returned to the kernel, and the file never runs.
//! 3. **Block on write.** Every write to every file is inspected. This is what
//!    "on-access" means in a product that says it, and it is the only one that
//!    catches a malicious *modification* of an otherwise-trusted file.
//!
//! This crate implements **(1)**, and does it in user mode with
//! `ReadDirectoryChangesW`. That is a real capability and it is worth having:
//! it needs no driver, no administrator and no kernel code, so it works on the
//! machine as it is. What it cannot do is stop a file from running, and the
//! product must not claim otherwise: the report says the file was quarantined
//! *after* it appeared, and [`av_quarantine::EntrySource`] already
//! distinguishes a pre-execution block from a post-hoc find. The console says
//! which one happened; this crate must not blur it.
//!
//! **(2) and (3) need the driver**, which is where a minifilter callback returns
//! a verdict to the kernel before the operation completes. That is the kmod
//! crate's job, and the seam between the two is the IPC protocol: this crate's
//! watcher and the driver's filter both end up asking the same scanner the same
//! question, and only one of them can refuse. Keeping the watcher useful on its
//! own, rather than stubbing it until the driver exists, buys a feature that
//! works without administrator rights, which is the one most machines will
//! actually get.
//!
//! # The two failure modes that matter
//!
//! **A missed event.** The buffer `ReadDirectoryChangesW` fills is finite, and a
//! burst of activity larger than it overflows. Windows reports the overflow
//! rather than dropping silently, and the correct response is to re-scan the
//! tree rather than to carry on as though nothing happened. An overflow that
//! was ignored is a blind spot the user was never told about.
//!
//! **A storm.** A scan writes to the quarantine vault, the vault is inside the
//! watched tree, and the scan of the file that was just written triggers
//! another scan. The loop is real and the guard against it is a decision this
//! crate has to make explicitly, not a bug to be found in production.

//! # How this crate is put together
//!
//! The split is between what can be tested without Windows and what cannot, and
//! it is the first thing to know when reading the tree:
//!
//! | Module | What it is | Touches the system |
//! |---|---|---|
//! | [`notify`] | `FILE_NOTIFY_INFORMATION` records, parsed as a pure function over `&[u8]` | no |
//! | [`filter`] | which actions are worth scanning, which trees are not ours | no |
//! | [`debounce`] | coalescing a burst of writes into one scan | no |
//! | [`plan`] | turning a configuration into roots, exclusions and refusals | paths only |
//! | [`finding`] | what a caller is told, and what it may claim | no |
//! | [`watch`] | `ReadDirectoryChangesW`, one thread per root | Windows |
//! | [`service`] | the scanning loop: events in, findings out | yes |
//!
//! Everything above `watch` is a pure function or a pure decision, which is where
//! the tests are. The two impure modules are thin on purpose, and what they do
//! that cannot be tested without a filesystem is tested with it, behind
//! `#[ignore = "touches the real filesystem"]`.
//!
//! # What was measured, and what was chosen
//!
//! [`debounce::SETTLE_FLOOR_MS`] is the one *constant* here that is a
//! measurement rather than a trade-off: it is how long the watcher waits before
//! deciding that a file has finished being written, and it is set from a
//! measurement of how long this machine takes to report a file creation. See
//! that constant's documentation and
//! `debounce::tests::measure_time_to_observe_a_created_file`, which is the test
//! that produced the number. Every other constant is a choice stated in its own
//! doc comment.
//!
//! The crate's *claims about the platform* are measured the same way, and the
//! ignored filesystem tests are where the measurements live. Four of them are
//! load-bearing enough to be named here, because each one is a case where the
//! intuitive answer is wrong:
//!
//! * A file created and written arrives as `[Added, Modified]`, in that order.
//! * A *write* to a file that already exists arrives as `Modified` alone, which
//!   is what makes `scan_on_write` a function of something rather than a
//!   formality.
//! * A file moved *into* a watched tree from outside it arrives as `Added`, not
//!   as `RenamedNewName`: the kernel can pair a rename's two halves only when
//!   it watched both. A rename *inside* the tree arrives as the pair, in one
//!   batch. See [`filter`].
//! * A change made before the watch's first `ReadDirectoryChangesW` is issued is
//!   never reported at all, which is why [`DirectoryWatch::start`] does not
//!   return until every root is armed and why the files already in a watched
//!   tree are the full scanner's job. See [`watch`].
//!
//! Each of those is asserted by a test that prints what the kernel sent, so the
//! sentence in the doc comment and the behaviour on the machine cannot drift
//! apart without a failing test.

#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod debounce;
pub mod error;
pub mod filter;
pub mod finding;
pub mod notify;
pub mod plan;
pub mod service;
pub mod watch;

pub use debounce::{effective_window, Debouncer, SETTLE_FLOOR_MS};
pub use error::{RealtimeError, Result};
pub use filter::{is_reportable, is_scan_candidate, ExclusionSet};
pub use finding::{disposition, Disposition, Finding, Phase};
pub use notify::{parse, Change, FileAction, NotifyBatch, NotifyError, NotifyRecord};
pub use plan::{
    standard_paths, DisabledBy, SkipReason, SkippedRoot, Unhonoured, WatchPlan, BUFFER_BYTES,
    RESCAN_FILE_LIMIT,
};
pub use service::{RealtimeEvent, RealtimeService, Rescan, ServiceStats};
pub use watch::{DirectoryWatch, Lost, WatchEvent};

/// Helpers for the tests that touch a real filesystem.
///
/// Kept here rather than copied into each module's test block because the three
/// of them need the same two things, and a plan built slightly differently in
/// each would make a failure look like a difference between the modules.
#[cfg(test)]
pub(crate) mod testing {
    use std::path::Path;

    use crate::filter::ExclusionSet;
    use crate::plan::WatchPlan;

    /// A plan whose only root is `root`, with nothing excluded.
    pub(crate) fn plan_for(root: &Path, scan_on_write: bool) -> WatchPlan {
        WatchPlan {
            roots: vec![root.to_path_buf()],
            exclusions: ExclusionSet::default(),
            scan_on_write,
            window: crate::debounce::effective_window(0),
            skipped: Vec::new(),
            unhonoured: Vec::new(),
            disabled_by: None,
        }
    }

    /// True when two paths name the same file for the purposes of an assertion.
    ///
    /// Case-insensitive and tolerant of the extended-length prefix, because a
    /// failure message that says the paths differ when they do not is worse than
    /// no assertion.
    pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
        let norm = |p: &Path| {
            let text = p.to_string_lossy().to_lowercase();
            text.strip_prefix(r"\\?\")
                .unwrap_or(&text)
                .trim_end_matches('\\')
                .to_string()
        };
        norm(a) == norm(b)
    }
}

