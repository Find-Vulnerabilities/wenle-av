//! Scanning a file once, after the writing has stopped.
//!
//! # The decision: a trailing-edge window, measured from the last event
//!
//! A file that is being written produces a burst of events. `File::create`
//! followed by a write produces `ADDED` and then one or more `MODIFIED`s — one
//! `Added` and one `Modified`, measured, by
//! `crate::watch`'s `a_created_file_arrives_as_an_added_change`, which prints
//! the batch the kernel sent; a download produces a `MODIFIED` per chunk; a copy
//! produces a `MODIFIED` per buffer. Scanning on every one of them would scan a
//! file that is still arriving — three hundred times for a 300 MB download, each
//! scan seeing a prefix of the real thing, and the verdict that matters is the
//! one on the finished bytes.
//!
//! So an event does not cause a scan. It sets a deadline: "scan this path once
//! the writes have stopped for `window`". Further events for the same path push
//! the deadline out, and the file is scanned once, whole, when the burst ends.
//!
//! A *leading*-edge window — scan on the first event and ignore the rest for
//! `window` — was the obvious alternative and is wrong for exactly the case the
//! feature exists for: the first event for a freshly created file arrives while
//! it is zero bytes long, and that is the scan that would be kept.
//!
//! # What it costs
//!
//! **A file gains `window` milliseconds of unscanned life before it is looked
//! at.** A sample that is written, executed and deleted inside that window is
//! seen once, late, and by then it may already have run. This is stated rather
//! than minimised because this crate cannot block anything anyway: it is a
//! notice-after-the-fact watcher, so the window delays the *notice*, and the
//! only thing that would close it is the kernel-mode driver that can refuse the
//! write in the first place — which is a different crate's job and the reason
//! [`av_quarantine::EntrySource`] has a `Driver` variant next to `Realtime`.
//!
//! The window is the configured
//! [`debounce_ms`](av_core::config::RealtimeConfig::debounce_ms), floored at
//! [`SETTLE_FLOOR_MS`] so that a configuration of `0` cannot turn the watcher
//! into a scanner of empty files. The floor is not a guess; see its
//! documentation for the measurement behind it.
//!
//! # Why the window is keyed on the normalized path
//!
//! Because Windows paths are case-insensitive, and two spellings of one file are
//! one file. A window keyed on the literal string would scan
//! `C:\Temp\A.EXE` and `c:\temp\a.exe` separately, which is two scans of one
//! file — the same mistake the storm guard exists to prevent, one directory
//! over.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The shortest window the watcher will run with, whatever the configuration
/// says.
///
/// # The number, and where it comes from
///
/// The window has to be longer than the time between "the kernel created the
/// file" and "we hear about it", or the create and the first write arrive as two
/// separate bursts and the file is scanned twice: once empty, once whole. That
/// time is measurable and is measured, on this machine, by the ignored test
/// `debounce::tests::measure_time_to_observe_a_created_file`, which creates a
/// file with a watch already armed and times the round trip over twenty trials.
///
/// **The measured figures**, over five runs of that test on this machine, were
/// medians of 3.0, 3.5, 3.8, 4.2 and 4.3 ms, and a worst single trial across all
/// five of 8.4 ms; individual trials ranged from 2.8 ms to 8.4 ms. So 50 ms is
/// about six times the worst observation and thirteen times the median, which is
/// the headroom the create/write pairing needs: the burst only has to stay inside
/// one window, and it does so with room to spare even with three other `cargo`
/// builds sharing the machine. The spread across runs is the reason the floor is
/// not set closer to the number: the tail is what moves, and the tail is what
/// decides whether a create and its first write land in one window or two.
///
/// The floor is deliberately *not* set near the measurement. A window that sat
/// at 10 ms would be a window that stops coalescing the moment the machine is
/// loaded — which is exactly when a dropper is likeliest to be landing — and the
/// cost of the extra milliseconds is paid only by a file that would otherwise be
/// scanned twice, once of them empty.
///
/// Everything here is a floor and not a ceiling: a configuration that asks for
/// 200 ms gets 200 ms.
pub const SETTLE_FLOOR_MS: u64 = 50;

/// The window to use for a configured number of milliseconds.
///
/// Extracted from the watcher so that the floor is a testable decision rather
/// than a `max` buried in an expression at a call site: the interesting inputs
/// are `0`, which must not mean "no window at all", and a value above the floor,
/// which must be honoured rather than clamped down.
pub fn effective_window(configured_ms: u64) -> Duration {
    Duration::from_millis(configured_ms.max(SETTLE_FLOOR_MS))
}

/// One path waiting for its writes to stop.
#[derive(Debug, Clone)]
struct Pending {
    /// The path as it was first reported, which is the spelling a log and a
    /// report should use — not the lowercased key.
    path: PathBuf,
    /// The instant this path becomes due if nothing else happens to it.
    deadline: Instant,
}

/// Coalesces bursts of events for one path into a single scan.
///
/// The clock is passed in rather than read, so a test can drive a burst of
/// writes in microseconds and assert on the scan count that comes out. Nothing
/// in this type reads the time or the filesystem.
#[derive(Debug, Clone)]
pub struct Debouncer {
    window: Duration,
    /// Keyed on the normalized path, and a `BTreeMap` rather than a `HashMap`
    /// so that the paths due at one instant come out in the same order on every
    /// run. A scan order that varies with the hasher makes two logs of the same
    /// burst disagree.
    pending: BTreeMap<String, Pending>,
}

impl Debouncer {
    /// A debouncer with the given window.
    ///
    /// A zero window is honoured literally here — a due path is due at once —
    /// because this type is the mechanism and not the policy. The floor that
    /// keeps a zero out of the configuration lives in [`effective_window`].
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            pending: BTreeMap::new(),
        }
    }

    /// How long a path must be quiet before it is due.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record that `path` changed at `now`.
    ///
    /// Returns true when this started a new wait, and false when it extended one
    /// that was already running — which is the difference between "a file
    /// appeared" and "the file that appeared is still being written", and is
    /// what a caller counts to report how much work the window saved.
    pub fn observe(&mut self, path: &Path, now: Instant) -> bool {
        // A deadline that cannot be represented is treated as "already due"
        // rather than as an error or a panic: the failure mode is then an extra
        // scan, and an extra scan is the safe direction for this decision to
        // fail in.
        let deadline = now.checked_add(self.window).unwrap_or(now);
        let key = normalize(path);
        let started = !self.pending.contains_key(&key);
        if started {
            self.pending.insert(
                key,
                Pending {
                    path: path.to_path_buf(),
                    deadline,
                },
            );
        } else if let Some(pending) = self.pending.get_mut(&key) {
            // The deadline moves; the spelling does not. A report should name
            // the path the way it was first reported, so that the same file
            // written under two spellings does not produce two different
            // sentences depending on which write came last.
            pending.deadline = deadline;
        }
        started
    }

    /// Take every path whose window has closed, earliest deadline first.
    ///
    /// Ties are broken by path, because a burst of files created in the same
    /// millisecond is the ordinary case and their scan order should not depend
    /// on the order the kernel happened to report them in.
    pub fn due(&mut self, now: Instant) -> Vec<PathBuf> {
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(key, _)| key.clone())
            .collect();
        let mut out: Vec<(Instant, PathBuf)> = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push((pending.deadline, pending.path));
            }
        }
        out.sort();
        out.into_iter().map(|(_, path)| path).collect()
    }

    /// When the earliest pending path becomes due, if any is waiting.
    ///
    /// This is what lets the scanner sleep exactly as long as it has nothing to
    /// do, instead of polling: a receiver that wakes every hundred milliseconds
    /// to check would add its own interval to every scan's latency.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|p| p.deadline).min()
    }

    /// How many paths are waiting.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Stop waiting for a path, so that the next event for it starts a new
    /// window.
    pub fn forget(&mut self, path: &Path) {
        self.pending.remove(&normalize(path));
    }
}

/// Lowercase and strip the extended-length prefix, so two spellings of one
/// Windows path are one key.
///
/// Deliberately not `canonicalize`: the path may not exist yet, or any more, and
/// a key function that failed on either would collapse every deleted file into
/// no key at all.
fn normalize(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock a test can move by hand. Nothing here reads the wall clock, which
    /// is what makes a burst of writes testable in microseconds.
    fn base() -> Instant {
        Instant::now()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_file_written_twice_inside_the_window_is_scanned_once() {
        // The differential test for the whole module: a leading-edge
        // implementation scans at `observe` and would return two paths here, and
        // a no-debounce implementation returns two as well. Only a trailing-edge
        // window returns one.
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        assert!(d.observe(Path::new(r"C:\Temp\a.exe"), t0), "a new wait");
        assert!(
            !d.observe(Path::new(r"C:\Temp\a.exe"), t0 + ms(100)),
            "the same wait, extended"
        );
        assert!(d.due(t0).is_empty(), "nothing is due before the window");
        assert!(d.due(t0 + ms(150)).is_empty(), "nor mid-window");
        assert_eq!(d.due(t0 + ms(300)), vec![PathBuf::from(r"C:\Temp\a.exe")]);
        // And exactly once: the entry is gone.
        assert!(d.due(t0 + ms(400)).is_empty());
        assert_eq!(d.pending_len(), 0);
    }

    #[test]
    fn a_burst_that_keeps_going_is_scanned_once_at_the_end_of_it() {
        // Ten writes a tenth of a second apart with a 200 ms window is one
        // scan, and the scan happens 200 ms after the *last* one — not 200 ms
        // after the first, which is the difference between scanning a file and
        // scanning a file that is half written.
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        for i in 0..10 {
            d.observe(Path::new(r"C:\Temp\big.iso"), t0 + ms(i * 100));
        }
        assert!(d.due(t0 + ms(1000)).is_empty());
        assert_eq!(d.due(t0 + ms(1100)).len(), 1);
    }

    #[test]
    fn writes_further_apart_than_the_window_are_two_scans() {
        // The other half of the differential: the window must not merge a file
        // that was written now and again a second later, because the second
        // write is a second opportunity for the file to become malicious.
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\a.exe"), t0);
        assert_eq!(d.due(t0 + ms(250)).len(), 1);

        d.observe(Path::new(r"C:\Temp\a.exe"), t0 + ms(500));
        assert_eq!(d.due(t0 + ms(750)).len(), 1);
    }

    #[test]
    fn two_spellings_of_one_path_share_one_window() {
        // Windows paths are case-insensitive, so these are one file and must be
        // one scan. A window keyed on the literal string scans twice, and the
        // second scan is of a file nobody changed.
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\A.EXE"), t0);
        assert!(!d.observe(Path::new(r"c:\temp\a.exe"), t0 + ms(50)));
        let due = d.due(t0 + ms(300));
        assert_eq!(due.len(), 1);
        // The spelling reported is the first one seen, not the lowercased key,
        // so a report reads like the path the user has.
        assert_eq!(due[0], PathBuf::from(r"C:\Temp\A.EXE"));

        // The extended-length prefix is the same file too.
        let mut e = Debouncer::new(ms(200));
        e.observe(Path::new(r"C:\Temp\b.dll"), t0);
        assert!(!e.observe(Path::new(r"\\?\C:\Temp\B.DLL"), t0 + ms(10)));
        assert_eq!(e.due(t0 + ms(300)).len(), 1);
    }

    #[test]
    fn different_paths_do_not_share_a_window() {
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\a.exe"), t0);
        d.observe(Path::new(r"C:\Temp\b.exe"), t0);
        d.observe(Path::new(r"C:\Temp\sub\a.exe"), t0);
        assert_eq!(d.pending_len(), 3);
        assert_eq!(d.due(t0 + ms(300)).len(), 3);
    }

    #[test]
    fn due_paths_come_back_in_a_stable_order() {
        // Three files created in the same millisecond. Their order must be the
        // same on every run, or two logs of one burst disagree about what
        // happened first.
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        for name in ["c.exe", "a.exe", "b.exe"] {
            d.observe(&PathBuf::from(r"C:\Temp").join(name), t0);
        }
        let due = d.due(t0 + ms(300));
        assert_eq!(
            due,
            vec![
                PathBuf::from(r"C:\Temp\a.exe"),
                PathBuf::from(r"C:\Temp\b.exe"),
                PathBuf::from(r"C:\Temp\c.exe"),
            ]
        );
    }

    #[test]
    fn a_deadline_before_another_comes_out_first() {
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\late.exe"), t0 + ms(100));
        d.observe(Path::new(r"C:\Temp\early.exe"), t0);
        assert_eq!(
            d.due(t0 + ms(400)),
            vec![
                PathBuf::from(r"C:\Temp\early.exe"),
                PathBuf::from(r"C:\Temp\late.exe"),
            ]
        );
    }

    #[test]
    fn the_next_deadline_is_the_earliest_one_waiting() {
        let mut d = Debouncer::new(ms(200));
        assert_eq!(d.next_deadline(), None);
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\a.exe"), t0 + ms(50));
        d.observe(Path::new(r"C:\Temp\b.exe"), t0);
        assert_eq!(d.next_deadline(), Some(t0 + ms(200)));
    }

    #[test]
    fn a_zero_window_is_due_at_once() {
        // The mechanism honours zero; the floor that keeps zero out of the
        // configuration is `effective_window`'s job.
        let mut d = Debouncer::new(Duration::ZERO);
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\a.exe"), t0);
        assert_eq!(d.due(t0).len(), 1);
    }

    #[test]
    fn a_forgotten_path_starts_a_new_wait() {
        let mut d = Debouncer::new(ms(200));
        let t0 = base();
        d.observe(Path::new(r"C:\Temp\a.exe"), t0);
        d.forget(Path::new(r"c:\temp\A.EXE"));
        assert_eq!(d.pending_len(), 0);
        assert!(d.observe(Path::new(r"C:\Temp\a.exe"), t0 + ms(10)));
    }

    #[test]
    fn the_floor_keeps_a_zero_configuration_from_scanning_empty_files() {
        assert_eq!(effective_window(0), Duration::from_millis(SETTLE_FLOOR_MS));
        assert_eq!(effective_window(1), Duration::from_millis(SETTLE_FLOOR_MS));
        // A configured value above the floor is honoured, not clamped down to
        // it: the floor exists to stop a pathological configuration, not to
        // overrule a deliberate one.
        assert_eq!(effective_window(200), Duration::from_millis(200));
        assert_eq!(
            effective_window(SETTLE_FLOOR_MS + 1),
            Duration::from_millis(SETTLE_FLOOR_MS + 1)
        );
        // The default in `RealtimeConfig` is above the floor, so the floor is
        // not silently changing what the product ships with.
        let default = av_core::config::RealtimeConfig::default().debounce_ms;
        assert_eq!(effective_window(default), Duration::from_millis(default));
        assert!(default > SETTLE_FLOOR_MS);
    }

    /// How many trials the measurement below runs.
    const TRIALS: usize = 20;

    /// Measure how long this machine takes to report a file creation.
    ///
    /// # What it measures, exactly
    ///
    /// From immediately before `File::create` to the instant the change naming
    /// that file is received from a watching thread — the whole path, including
    /// the kernel's own reporting, the overlapped read completing, and this
    /// crate's wait on the completion event. That is the number
    /// [`SETTLE_FLOOR_MS`] is set against, and it is the number that matters
    /// because the floor's job is to be longer than it: a create and the first
    /// write that follow it must land inside one window, and they only do if the
    /// window outlasts the gap between the two events *as this crate sees them*.
    ///
    /// The wait is event-driven, not polled — the watch thread blocks on the
    /// completion event with [`POLL_MS`](crate::watch::POLL_MS) as an upper bound
    /// for the stop check, and wakes the moment the kernel signals — so what
    /// comes out is the machine's reporting latency and not the poll interval.
    ///
    /// Prints every trial, then the median, the 95th percentile and the worst,
    /// and asserts the claim the floor rests on: that the median is below the
    /// floor. A run that fails that assertion means the floor is too low on this
    /// machine, which is a fact the doc comment on the constant would then have
    /// to say.
    ///
    /// Twenty trials and a fresh file name for each: one file's events can be
    /// coalesced with the next one's otherwise, and the second trial would
    /// measure the first.
    #[test]
    #[ignore = "touches the real filesystem, and is a measurement rather than a test"]
    fn measure_time_to_observe_a_created_file() {
        use crate::testing::same_path;
        use crate::watch::{DirectoryWatch, WatchEvent};
        use std::io::Write;

        let temp = tempfile::tempdir().expect("a temp directory");
        let plan = crate::testing::plan_for(temp.path(), true);
        let watch = DirectoryWatch::start(&plan).expect("a watch");

        let mut samples = Vec::with_capacity(TRIALS);
        for trial in 0..TRIALS {
            let path = temp.path().join(format!("trial-{trial}.bin"));

            let started = Instant::now();
            {
                let mut file = std::fs::File::create(&path).expect("the file is created");
                file.write_all(b"a file that appears").expect("the write");
                file.sync_all().expect("the flush");
            }

            // Wait for the change that names this file. Anything else on the
            // channel is another trial's event and is left for its own turn.
            let deadline = started + Duration::from_secs(10);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match watch.events().recv_timeout(left) {
                    Ok(WatchEvent::Changed { changes, .. }) => {
                        if changes.iter().any(|c| same_path(&c.path, &path)) {
                            break;
                        }
                    }
                    Ok(other) => panic!("the watch reported {other:?}"),
                    Err(error) => panic!(
                        "no event for {} within ten seconds: {error}",
                        path.display()
                    ),
                }
            }
            samples.push(started.elapsed());
        }
        watch.stop();

        samples.sort();
        for (trial, sample) in samples.iter().enumerate() {
            println!(
                "trial {trial:>2}: {:>8.3} ms",
                sample.as_secs_f64() * 1000.0
            );
        }
        let median = samples[samples.len() / 2];
        let p95 = samples[(samples.len() * 95) / 100];
        let worst = samples[samples.len() - 1];
        println!(
            "create -> event over {TRIALS} trials: median {:.3} ms, p95 {:.3} ms, worst {:.3} ms",
            median.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            worst.as_secs_f64() * 1000.0
        );

        // Asserted on the *worst* trial and not the median, because that is the
        // claim `SETTLE_FLOOR_MS` makes: the floor has to cover every create and
        // not most of them, or the create and the first write land in two
        // windows and the file is scanned twice — the second scan being the one
        // that matters and the first being of a file that is still empty. A
        // median-only assertion would pass on a machine whose slow tail is
        // longer than the window.
        assert!(
            worst < Duration::from_millis(SETTLE_FLOOR_MS),
            "the worst observation was {worst:?}, which is not below SETTLE_FLOOR_MS \
             ({SETTLE_FLOOR_MS} ms): the floor does not cover the gap it exists to cover"
        );
    }
}
