//! Noticing when the vault's index changed underneath this window.
//!
//! # Why the window has to ask at all
//!
//! The vault is one directory with one index file, and this process is not its
//! only writer: the service quarantines what realtime protection catches, the
//! command line quarantines what a scan finds, and both of them write the same
//! file. A window that reads the index once — when its Quarantine tab is first
//! drawn — shows the vault as it was at that moment and never again, so a file
//! the service took while the window was open appears nowhere: not in the list,
//! and not in the corner where a block is announced.
//!
//! # Why this is a poll and not a subscription
//!
//! `QuarantineVault::subscribe` appends a listener to a list on the vault
//! *value*, so it is called by whichever code holds that value. It cannot carry
//! an event across a process boundary, and nothing else can either: the service
//! serves one pipe client at a time and finishes with it before taking the next,
//! so a window that held the pipe open to receive notifications would lock out
//! `wenle service status` for as long as it was running.
//!
//! A file's identity is a cheaper and more honest signal. The index is written
//! atomically — a temporary file, flushed, renamed — so a reader either sees the
//! whole previous index or the whole next one, and the file's length and
//! modification time say which. Watching those costs one `stat` per interval and
//! a decrypt only when something actually moved.
//!
//! # What it cannot do
//!
//! It notices an index that *changed*, not one that was *overwritten by a stale
//! copy*. Two processes writing at the same instant is the same lost-update race
//! the vault itself documents, seen from the outside: the stamp moves either
//! way, this reads what is there, and an entry the other writer dropped is
//! reported by `reconcile` as absent rather than as deleted. Polling narrows the
//! window — the copy this process writes is at most one interval old — and does
//! not close it. A lock is what would close it, and there is none.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

/// How often a window with nothing else to do looks at the index.
///
/// One second is a compromise and not a measurement: the cost is a `stat` per
/// second, and what it buys is how long a user waits between a file being taken
/// by the service and being told. Longer would be cheaper and would make the
/// notification feel disconnected from the thing that caused it.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// What an index file looked like when it was last checked.
///
/// Length and modification time together, because either alone can repeat: two
/// writes in the same clock tick have the same time, and two vaults of the same
/// size have the same length — an index that took one item and dropped another
/// is exactly as long as it was.
///
/// This is a change *detector* and not a comparison: it says the bytes are not
/// the ones that were there, never that they are the same. The hole in it is
/// narrow and worth naming: a write that leaves the length unchanged and lands
/// inside the filesystem's own timestamp granularity shows the same stamp as the
/// write before it. It has not been measured on any filesystem, and what it
/// costs if it happens is one entry held back — every later write moves the
/// stamp again and the re-read that follows picks up everything, because each
/// write is the whole index and not a patch. It is the last write of a quiet
/// machine that would be the one missed, and a machine quiet enough for that has
/// nothing left to notify about until the next thing happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Size in bytes.
    len: u64,
    /// When it was last written, as the filesystem reports it.
    modified: Option<SystemTime>,
}

impl Stamp {
    /// The stamp of the file at `path`, or `None` when it cannot be read.
    ///
    /// `None` is not an error and not an empty vault: a file that is not there,
    /// or that this account may not stat, is a question this module does not
    /// answer. The caller keeps what it has — see [`VaultPoll::due`].
    pub fn of(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// What the index looked like at some point.
///
/// An enum rather than an `Option<Stamp>`, because "there was no file" and "no
/// look has happened yet" are different facts and the difference decides whether
/// the first entry a vault ever takes is announced. A fresh installation has an
/// empty vault directory and no index at all — the file appears with the first
/// quarantine — so collapsing the two would read that first index as a baseline
/// to be recorded rather than as a change to be reported, and the first block on
/// a new machine would be the one nobody was told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Baseline {
    /// The index file was not there.
    Absent,
    /// It was, looking like this.
    Present(Stamp),
}

impl Baseline {
    /// What the index looks like now.
    fn take(index: &Path) -> Self {
        match Stamp::of(index) {
            Some(stamp) => Self::Present(stamp),
            None => Self::Absent,
        }
    }
}

/// When to look next, and what the index looked like at the last look.
#[derive(Debug)]
pub struct VaultPoll {
    /// How long between looks.
    interval: Duration,
    /// When the next look is due. `None` until the first look records one,
    /// which makes that first look due immediately.
    next: Option<Instant>,
    /// What the index looked like at the last look, or `None` until a baseline
    /// has been taken at all.
    baseline: Option<Baseline>,
}

impl VaultPoll {
    /// A poll that looks every [`POLL_INTERVAL`].
    pub fn new() -> Self {
        Self::with_interval(POLL_INTERVAL)
    }

    /// A poll with a stated interval. Tests use this to run without waiting.
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            interval,
            next: None,
            baseline: None,
        }
    }

    /// Record what the index looks like now, without reporting it as a change.
    ///
    /// Called when the vault is opened, and it is what closes the gap between
    /// opening and the first look. A vault that was just opened holds exactly
    /// what the file holds, so what is recorded here is the baseline the first
    /// look compares against, and a write that lands in between is a change
    /// rather than part of the baseline.
    ///
    /// A vault directory with no index in it yet gets [`Baseline::Absent`], and
    /// the first index to appear is a change — which is the case a fresh
    /// installation is in for its first quarantine.
    pub fn prime(&mut self, index: &Path) {
        self.baseline = Some(Baseline::take(index));
    }

    /// Whether the index has moved and it is time to act on it.
    ///
    /// A caller may ask this every frame; the filesystem is read at most once
    /// per interval, and the answer is `false` more often than not. Each of the
    /// reasons is deliberate:
    ///
    /// - **Not yet due.** The interval is about how often the filesystem is
    ///   asked, and asking records that it was asked — a look that was due and
    ///   found nothing is not due again on the next frame.
    /// - **The first look, when nothing has primed it.** It records what the
    ///   file looks like and reports nothing. A window that had just opened the
    ///   vault and immediately re-read it would announce the vault's whole
    ///   history on startup, which is the one thing a first look must not do.
    ///   [`VaultPoll::prime`] is how a caller that already knows the baseline
    ///   skips this.
    /// - **An index that is not there.** A `stat` that fails leaves the previous
    ///   baseline in place rather than clearing it, so a file that blinks is not
    ///   read as a change and the next successful look compares against the last
    ///   thing that was actually there. An absent index is not an empty vault,
    ///   and handing one to the caller to adopt is the failure the vault's own
    ///   documentation says must never happen.
    pub fn due(&mut self, now: Instant, index: &Path) -> bool {
        if let Some(next) = self.next {
            if now < next {
                return false;
            }
        }
        self.next = Some(now + self.interval);

        let now_baseline = Baseline::take(index);
        let Some(baseline) = self.baseline else {
            self.baseline = Some(now_baseline);
            return false;
        };
        if baseline == now_baseline {
            return false;
        }
        match now_baseline {
            // The file went away. Reported as nothing, and the baseline is not
            // moved: what the file held before it vanished is still the last
            // thing that was known to be there.
            Baseline::Absent => false,
            // The file is there and differs from what was recorded. Whether
            // there was one before or not: an index appearing where none was is
            // a vault's first item.
            Baseline::Present(_) => {
                self.baseline = Some(now_baseline);
                true
            }
        }
    }
}

impl Default for VaultPoll {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file whose contents, and therefore whose stamp, can be moved on demand.
    fn index_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("index.sealed");
        std::fs::write(&path, b"first").expect("the index");
        (dir, path)
    }

    /// A vault directory that has never held an index, which is what a fresh
    /// installation looks like.
    fn empty_vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("index.sealed");
        (dir, path)
    }

    #[test]
    fn the_first_look_establishes_a_baseline_and_reports_nothing() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);

        // The vault's whole history is already in it. Reporting a change here
        // would announce every entry the vault holds the moment a window opens,
        // which is why this is the one look that answers `false`.
        assert!(
            !poll.due(Instant::now(), &index),
            "the first look reports nothing"
        );
    }

    #[test]
    fn a_second_look_with_no_write_reports_nothing() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();
        assert!(!poll.due(now, &index));

        assert!(
            !poll.due(now + Duration::from_secs(1), &index),
            "nothing wrote to it, so nothing moved"
        );
    }

    #[test]
    fn priming_records_a_baseline_so_a_write_after_the_open_is_still_a_change() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();

        // The vault has just been opened over this file: what is in memory is
        // what is on disk, so this is the baseline and not news.
        poll.prime(&index);
        assert!(!poll.due(now, &index), "nothing has been written since");

        std::fs::write(&index, b"a second, longer index").expect("rewrite");

        assert!(
            poll.due(now + Duration::from_secs(1), &index),
            "a write between the open and the first look is exactly the one a \
             baseline taken at the first look instead would swallow"
        );
    }

    #[test]
    fn the_first_index_a_fresh_vault_ever_writes_is_a_change() {
        // A new installation has a vault directory and no index: the file is
        // created by the first quarantine. Recording "no file" as a baseline and
        // then treating the first file as the baseline to be set would lose the
        // notification for the very first thing this product ever took.
        let (_dir, index) = empty_vault();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();
        poll.prime(&index);
        assert!(!poll.due(now, &index), "there is still nothing there");

        std::fs::write(&index, b"the first entry this vault ever held").expect("the index");

        assert!(
            poll.due(now + Duration::from_secs(1), &index),
            "an index appearing where there was none is a vault's first item"
        );
    }

    #[test]
    fn a_look_at_an_absent_index_records_that_it_was_absent() {
        // The same property as the test above, for a caller that never primes:
        // nothing has looked yet, and the first look finds no file. What it
        // records has to be "there was no file" — a fact — and not "no look has
        // happened yet", which is the absence of one. Collapsing the two makes
        // the index written by the first quarantine read as the baseline instead
        // of reported as a change, and loses the notification for the first
        // thing a new installation ever took. `prime` reaches this by a
        // different route, and both routes have to hold.
        let (_dir, index) = empty_vault();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();
        assert!(!poll.due(now, &index), "there is nothing there yet");

        std::fs::write(&index, b"the first entry this vault ever held").expect("the index");

        assert!(
            poll.due(now + Duration::from_secs(1), &index),
            "an index appearing where the first look found none is a change"
        );
    }

    #[test]
    fn a_write_is_noticed_on_the_next_look() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();
        assert!(!poll.due(now, &index));

        std::fs::write(&index, b"second, and longer than the first").expect("rewrite");

        assert!(
            poll.due(now + Duration::from_secs(1), &index),
            "the index was rewritten and the window must re-read it"
        );
        // And once it has been read, the same content is not a change again.
        assert!(!poll.due(now + Duration::from_secs(2), &index));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_not_a_change() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::ZERO);
        let now = Instant::now();
        assert!(!poll.due(now, &index));

        // A file that has gone is not an empty vault. Reading it as a change
        // would hand the caller an absent index to adopt, which is the one
        // direction the vault's own documentation says must never happen.
        //
        // Asked twice, because the failure this guards against is a baseline
        // *cleared* by the failed read: the second look would then find nothing
        // recorded, take the absent file as its baseline, and be quiet about a
        // file that had never come back.
        std::fs::remove_file(&index).expect("remove the index");
        assert!(!poll.due(now + Duration::from_secs(1), &index));
        assert!(
            !poll.due(now + Duration::from_secs(2), &index),
            "a file that is still not there is still not a change"
        );
    }

    #[test]
    fn the_interval_is_what_limits_how_often_the_filesystem_is_asked() {
        let (_dir, index) = index_file();
        let mut poll = VaultPoll::with_interval(Duration::from_secs(5));
        let now = Instant::now();
        assert!(!poll.due(now, &index), "the first look");
        std::fs::write(&index, b"changed").expect("rewrite");

        assert!(
            !poll.due(now + Duration::from_secs(1), &index),
            "a caller that asks every frame is not asking the filesystem every frame"
        );
        assert!(
            poll.due(now + Duration::from_secs(5), &index),
            "and it is asked, and answers, once the interval is up"
        );
    }

    #[test]
    fn a_stamp_is_the_size_and_the_time_together() {
        let (_dir, index) = index_file();
        let first = Stamp::of(&index).expect("a stamp");

        // Length alone is not enough, and this is the case that says so: a vault
        // that took one item and dropped another holds an index of exactly the
        // same size, and calling that unchanged would lose the notification for
        // whichever entry arrived.
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let later = base + Duration::from_secs(1);
        assert_ne!(
            Stamp {
                len: 5,
                modified: Some(base)
            },
            Stamp {
                len: 5,
                modified: Some(later)
            },
            "the same length at a different time is a different index"
        );

        // And the same length at the same time is the same index, which is what
        // stops every look from reading as a change.
        assert_eq!(
            Stamp {
                len: first.len,
                modified: first.modified
            },
            first
        );
        // A file whose length moved is a change whatever the clock says.
        assert_ne!(
            Stamp {
                len: first.len + 1,
                modified: first.modified
            },
            first
        );
    }
}
