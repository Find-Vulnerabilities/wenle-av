//! A ceiling on how much file content is in memory at once.
//!
//! # Why this exists, in one measurement
//!
//! A scan reads a file whole and then the prefilter makes a second, ASCII-folded
//! copy of it, so one file costs two times its size while it is being scanned.
//! Every worker does that at the same time. On a machine with no page file and
//! about 836 MB of commit headroom, three 200 MB files were enough:
//!
//! ```text
//! $ wenle scan <three 200 MB files>
//! memory allocation of 209715200 bytes failed
//! ```
//!
//! with peak working set 1,164 MB and no report printed at all — the process
//! aborted inside the allocator. The same three files, read one at a time,
//! complete at 751 MB peak. The difference is not the file, it is how many of
//! them are in flight, and nothing in the scanner was counting.
//!
//! So it counts here. A reservation is taken *before* the buffer is allocated,
//! sized by what the file will cost, and released when the scan of that file is
//! over. A worker that cannot fit waits, which turns an abort into a wait.
//!
//! # The wait is bounded
//!
//! Waiting for room can in principle never end — two reservations taken by one
//! thread would wait on each other for ever. Nothing in this crate nests: a
//! read takes one reservation and holds it no longer than the scan of that one
//! file. That is an invariant of the callers rather than of this type, so the
//! wait carries a deadline and gives up on it. Giving up means proceeding
//! unreserved and saying so in the log: a scan that is briefly over its memory
//! ceiling is a worse scan, and a scan that hangs is not a scan at all.
//!
//! How long the deadline is is `patience`'s business, and it is not a
//! constant: it scales with the size of the file being waited for, because what
//! a waiter is waiting for is that file's scan to finish.
//!
//! A release wakes every waiter rather than one of them, and that is what makes
//! the deadline mean what it says. Waking one is right when any waiter can use
//! the room; here the woken one is often the one that still does not fit —
//! a ceiling that admits a single large file makes "not enough" the common
//! answer — so everyone else would sleep through a release they could have used
//! and reach the deadline with the room they wanted sitting free.
//!
//! # The ceiling comes from the machine
//!
//! A quarter of what the machine can still commit, between 32 MiB and 256 MiB.
//! A quarter because the rule database is the other large resident and is not
//! negotiable; the clamps because a machine with almost nothing free must still
//! make progress and a large one should not be throttled by a constant chosen
//! for a small one. `WENLE_SCAN_BUDGET_MB` overrides it, in mebibytes.
//!
//! # A file too big for the ceiling takes the whole of it
//!
//! A file costing more than the ceiling is charged the ceiling — not its true
//! `2 x size` — and that is deliberate, because the cap is what makes it the
//! only thing in flight. Either charge leaves the file alone and holding
//! `2 x size`; the difference is only in the bookkeeping, and the uncapped
//! version makes `free()` reach zero for every waiter, so more of them queue
//! and more of them reach their deadline and proceed unreserved. Measured on
//! this machine, 816 MB of peak commit with the cap and 876 MB without it.
//!
//! This does mean the ceiling is not a hard bound on the peak: a single file
//! larger than half the ceiling is scanned alone at `2 x size`, which can
//! exceed it. That is what [`describe`] calls an *allowance*, and it is why the
//! line is worded that way rather than as "up to".
//!
//! # The ceiling is asked for again, not remembered
//!
//! This was a snapshot and that was a defect with the same shape as the one
//! above it. The number was taken once, at whichever moment the first read
//! happened to ask for it, and every reservation afterwards was measured
//! against it. But the process's own large resident — the rule database, about
//! 195 MB of live heap for the shipped ten-thousand-rule file — is committed by
//! the rule loader, which is not this crate and does not ask. A budget of a quarter of
//! what was free *before* that load is a budget that has already been spent, and
//! the allocator finds out.
//!
//! So the ceiling is recomputed on every reservation from the machine's live
//! answer. What the database took is then simply no longer free to commit, and
//! it is subtracted without this crate having to know the database exists. A
//! ceiling that falls takes the difference out of what is unreserved, which is
//! what makes a scan that is already running slow down rather than die when
//! something else on the machine grows.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// How many copies of a file a scan holds while it scans it.
///
/// Two, and the second is not obvious from this crate: the buffer
/// [`read`](mod@crate::read) returns, and the ASCII-folded copy the rule
/// engine's prefilter builds from it and keeps for the length of the file.
/// The budget is charged for both because both are resident at the same moment,
/// and a budget charged for one would permit exactly twice what it says.
pub const COPIES_PER_FILE: u64 = 2;

/// How long a reservation waits before proceeding without one.
///
/// Proportional to what is being waited for, because what is being waited for
/// is a scan finishing. A flat number cannot be right here: it would have to
/// exceed the slowest scan a file of the reserved size can take, and the
/// slowest rate this product measures for a large executable is about 1 MB/s
/// per core — so a file at the 256 MiB default cap is a scan of minutes, and a
/// flat thirty seconds would time out on it, proceed unreserved, and switch the
/// budget off on precisely the files it exists for.
///
/// # Why `held` and not only `want`
///
/// What the waiter is waiting for is the scan of whatever is *holding* the
/// budget — not the scan of the file it wants to reserve. Those are different
/// files and the holder is often the larger: a 90 MB file holds 180 MB for
/// ~90 seconds, and a 73 MB file asking for 146 MB of a 256 MiB ceiling has to
/// wait all of that out. Computing the deadline from `want` alone gave that
/// waiter 103 seconds against a 90-second job plus queueing, and it was
/// measured giving up twice in one run, proceeding unreserved both times and
/// taking the peak from 816 MB to 876 MB. So the deadline is the worst case for
/// *everything outstanding* — they are being scanned concurrently, and the last
/// of them finishing is what frees the room.
///
/// It is a backstop, not a throughput knob. Nothing in this crate nests
/// reservations, so a wait always ends with some other scan finishing and
/// releasing; what this bounds is a caller that holds a reservation while
/// blocking on something else, which no caller in this workspace does.
///
/// It was reached in practice for a different reason, and that reason was a
/// defect rather than a caller: the release signalled one waiter rather than
/// all of them, so a waiter could be left asleep across a release that would
/// have admitted it, and its only other chance was this deadline. That is fixed
/// where the release happens. What is left here is the backstop, and reaching it
/// now means the ceiling genuinely stayed too small for this waiter for the
/// whole of the longest scan outstanding.
///
/// The deadline is restarted by every notification, so what it bounds is time
/// *without progress* rather than total time in the wait. That is the useful
/// reading of it — a waiter that is told the state changed and still does not
/// fit has not been abandoned by the budget — and it is why this is safe to
/// leave generous.
///
/// The rate is [`av_core::FLOOR_BYTES_PER_SEC`] rather than a number of this
/// crate's own. It is the same measurement the per-file time budget is built
/// from, and the two faults it was extracted from were the same fault, so
/// there is one number for both.
fn patience(want: u64, held: u64) -> Duration {
    const SLACK: Duration = Duration::from_secs(30);
    // Both figures cover two copies of their file, so the bytes that actually
    // have to be read are half of the sum.
    let bytes = want.saturating_add(held) / COPIES_PER_FILE;
    SLACK + Duration::from_secs(bytes / av_core::FLOOR_BYTES_PER_SEC)
}

/// How much file content may be in memory at once.
pub struct Budget {
    /// Where the ceiling comes from, asked on every reservation.
    ///
    /// A closure rather than a stored number, because "ask the machine again"
    /// and "use this number" have to be the same shape for the code that
    /// consumes them, and because a ceiling that moves is then testable without
    /// a machine that moves it. The cost is one indirect call per reservation,
    /// against a file open and a file read in the same loop.
    ceiling: Box<dyn Fn() -> u64 + Send + Sync>,
    /// What is reserved, under one lock with nothing derived stored beside it.
    ///
    /// Outstanding rather than free, because the ceiling is recomputed and a
    /// stored free count would have to be adjusted every time it moved. Free is
    /// `ceiling - outstanding`, computed where it is asked for, so a ceiling
    /// that falls takes the difference out of what is unreserved without anyone
    /// having to remember that it did.
    state: Mutex<State>,
    /// Signalled whenever a reservation is released.
    released: Condvar,
}

/// What is currently held against the ceiling.
#[derive(Debug)]
struct State {
    outstanding: u64,
}

impl std::fmt::Debug for Budget {
    /// Prints the ceiling as it stands, not the closure that produces it.
    ///
    /// A `Box<dyn Fn>` has no useful representation and the closure for a
    /// machine budget is not `Debug` at all, so what a debugging session wants
    /// from this type is the two numbers.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("ceiling", &self.ceiling())
            .field(
                "outstanding",
                &self
                    .state
                    .lock()
                    .map(|state| state.outstanding)
                    .unwrap_or(0),
            )
            .finish()
    }
}

impl Budget {
    /// A budget of `total` bytes, whatever the machine says.
    ///
    /// Zero is rounded up to one byte rather than rejected: a budget that
    /// permits nothing would make every read wait for a release that cannot
    /// free anything, which is the hang this type exists to avoid.
    pub fn new(total: u64) -> Self {
        let total = total.max(1);
        Self::with_ceiling(move || total)
    }

    /// A budget sized from this machine, and re-sized from it as it changes.
    ///
    /// `WENLE_SCAN_BUDGET_MB` fixes it instead, and then it does not move: a
    /// number the user chose is an instruction, not a starting point the
    /// machine is free to lower.
    pub fn from_machine() -> Self {
        match configured_ceiling() {
            Some(fixed) => Self::with_ceiling(move || fixed),
            None => Self::with_ceiling(machine_ceiling),
        }
    }

    fn with_ceiling(ceiling: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            ceiling: Box::new(ceiling),
            state: Mutex::new(State { outstanding: 0 }),
            released: Condvar::new(),
        }
    }

    /// A budget whose ceiling is whatever `ceiling` says each time it is asked.
    ///
    /// The only way to test the property this type exists for. A machine cannot
    /// be told to have less memory at a chosen moment, and the defect this
    /// guards against was precisely a ceiling that was right when it was taken
    /// and wrong afterwards.
    #[cfg(test)]
    fn scripted(ceiling: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self::with_ceiling(ceiling)
    }

    /// The ceiling, in bytes.
    pub fn total(&self) -> u64 {
        self.ceiling()
    }

    /// What is not currently reserved, in bytes.
    pub fn free(&self) -> u64 {
        let outstanding = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .outstanding;
        self.ceiling().saturating_sub(outstanding)
    }

    /// The ceiling this reservation would be measured against, right now.
    fn ceiling(&self) -> u64 {
        (self.ceiling)()
    }

    /// Reserve `bytes`, waiting until they are free.
    ///
    /// A file larger than the whole budget proceeds alone, which is the only
    /// answer that is neither a deadlock nor a refusal: a scanner that will not
    /// scan a file because the file is big is a scanner that reports a big file
    /// as clean.
    pub fn reserve(&self, bytes: u64) -> Reservation<'_> {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        loop {
            // Asked for here rather than remembered, so that what the rule
            // database has committed since the last reservation is no longer
            // counted as available. See the module note.
            let total = self.ceiling();
            // Capped at the ceiling, and the cap is what makes an oversized
            // file take the whole budget and therefore be the only thing in
            // flight. Charging its true `2 x size` instead is the tempting
            // correction and it was tried: it changes nothing about memory --
            // either way the file is alone and holds `2 x size` -- while making
            // `free()` reach zero for every waiter, so more of them queue and
            // more of them time out and proceed unreserved. Measured on this
            // machine: 816 MB peak with the cap, 876 MB without it. The cap is
            // kept, and what was wrong was the *description* of the ceiling,
            // not the accounting. See the module note.
            let want = (bytes * COPIES_PER_FILE).min(total);
            // Nothing held means the file is admitted whatever it costs, and it
            // then holds the whole budget so that it is the only thing in
            // flight. That is what makes an oversized file serial rather than
            // fatal -- and that property comes from the cap above, not from the
            // charge being truthful. Anything else waits for room it can have.
            if state.outstanding == 0 || total.saturating_sub(state.outstanding) >= want {
                state.outstanding += want;
                return Reservation {
                    budget: self,
                    bytes: want,
                };
            }
            // What is outstanding right now is what has to be released before
            // this can proceed: the scans in flight are what the wait is for.
            // Read here, before the lock is given up, so that the deadline is
            // built from the state this waiter actually saw.
            let held = state.outstanding;
            let (guard, timeout) = self
                .released
                .wait_timeout(state, patience(want, held))
                .unwrap_or_else(|poison| poison.into_inner());
            state = guard;
            if timeout.timed_out() {
                // See the module note: the invariant that makes this
                // unreachable belongs to the callers, and this is what happens
                // when one of them breaks it. The machine's own numbers are in
                // the message because the interesting case is a ceiling that
                // fell while this waited, which is not a caller's fault and
                // cannot be told apart from one without them.
                log::warn!(
                    "waited {:?} for {want} bytes of scan memory and gave up; \
                     continuing without a reservation, which means this process may hold more \
                     file content than its budget allows. ceiling {total}, held {}, machine has {}",
                    patience(want, held),
                    state.outstanding,
                    match available_commit() {
                        Some(bytes) => format!("{bytes} bytes commit"),
                        None => "no answer".to_string(),
                    }
                );
                return Reservation {
                    budget: self,
                    bytes: 0,
                };
            }
        }
    }
}

/// A reservation, released when it is dropped.
///
/// Not `Clone`, and that is the point: the bytes are released once, by whoever
/// holds the reservation, and a copy would release them twice.
#[derive(Debug)]
pub struct Reservation<'a> {
    budget: &'a Budget,
    /// What was taken. Zero for a reservation that gave up waiting, which
    /// releases nothing because it took nothing.
    bytes: u64,
}

impl Reservation<'_> {
    /// How many bytes this holds.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.outstanding = state.outstanding.saturating_sub(self.bytes);
        drop(state);
        // All of them, not one.
        //
        // `notify_one` picks an arbitrary waiter, and the one it picks is often
        // the one that still does not fit: with a ceiling that admits a single
        // large file, a release of 119 MB does nothing for a waiter wanting 256
        // MiB. Every other waiter then sleeps through a release it could have
        // used, and its next chance is its own deadline.
        //
        // Measured on this machine, 2026-09-22, scanning six large system files
        // together with the product's own source tree (3,129 files, 2.6 GB):
        // four waiters gave up after 153-189 seconds, each one while the machine
        // still had 900 MB to 1.3 GB free to commit. The budget was not out of
        // memory, it had stopped being consulted, and the peak went to 1345 MB
        // against a 256 MiB allowance. The same scanner peaked at 816 MB on a
        // run that did not give up once.
        //
        // Waking everyone costs a lock re-check per waiter per release, and only
        // when there are waiters at all -- a release with an empty queue is
        // free. The releases that matter are one per scanned file, against a
        // file read and a rule pass in the same loop.
        self.budget.released.notify_all();
    }
}

/// The process's budget.
///
/// One for the process rather than one per scan, because the thing being
/// bounded is the process's memory and two scans running at once — a console
/// scan and the window's — are two writers to it.
pub fn shared() -> &'static Budget {
    static SHARED: once_cell::sync::OnceCell<Budget> = once_cell::sync::OnceCell::new();
    SHARED.get_or_init(Budget::from_machine)
}

/// The ceiling the environment asks for, if it asks for one.
///
/// Read once, at construction, rather than on every reservation: it is a
/// variable in this process and cannot change under a scan in any way that
/// matters, and the alternative is a `getenv` under the reservation lock.
fn configured_ceiling() -> Option<u64> {
    const MIB: u64 = 1024 * 1024;
    std::env::var("WENLE_SCAN_BUDGET_MB")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|mib| mib.saturating_mul(MIB).max(1))
}

/// The ceiling to use, from what the machine can still commit.
fn machine_ceiling() -> u64 {
    const MIB: u64 = 1024 * 1024;
    const FLOOR: u64 = 32 * MIB;
    const CEILING: u64 = 256 * MIB;
    match available_commit() {
        Some(free) => (free / 4).clamp(FLOOR, CEILING),
        // No answer from the operating system is not a reason to run
        // unbounded: this is the ceiling a scan would have picked before it
        // asked, and it is a quarter of what a small machine has.
        None => 128 * MIB,
    }
}

/// What this machine can still commit, if it will say.
///
/// The same number the ceiling is a quarter of, offered to a front end that
/// wants to say something before it starts. A user who is about to run a scan
/// on a machine with very little left is better served by a sentence naming the
/// number than by a silent abort — see [`advice`], which is that sentence.
pub fn available_commit_bytes() -> Option<u64> {
    available_commit()
}

/// A one-line description of the scan-memory situation, for a front end.
///
/// Both numbers, because either one alone is misleading: a large ceiling on a
/// machine with nothing free is a scan that will abort, and a small ceiling on a
/// machine with a great deal free is a scan that runs slowly for no reason.
///
/// "Allowance", not "up to": the ceiling is what the budget admits in total, and
/// a single file costing more than it is admitted alone and charged in full. The
/// line has to be readable against the number in an out-of-memory report, and a
/// figure that claims to be a hard bound would be the wrong one to compare to.
pub fn describe() -> String {
    let ceiling = shared().total() / (1024 * 1024);
    match available_commit() {
        Some(free) => format!(
            "scan memory: {ceiling} MiB of file buffer allowance, {} MiB left to commit on this machine",
            free / (1024 * 1024)
        ),
        None => format!(
            "scan memory: {ceiling} MiB of file buffer allowance, machine would not say what is left"
        ),
    }
}

/// How little commit is left before a scan is worth warning about.
///
/// The scan's own allowance is a quarter of what is free, so once the machine
/// is under this much that allowance has collapsed to its floor and a large
/// file is read alone, serially, at one core's worth of speed. A scan in that
/// state is not broken, it is slow — and a user who is told beforehand does not
/// conclude the product hung.
///
/// A warning and never a refusal. The budget exists so that a scan can run on a
/// full machine, and turning this into a refusal would make the product decline
/// to do the one thing it is for, on exactly the machines that need it most.
const TIGHT_COMMIT: u64 = 512 * 1024 * 1024;

/// A sentence about this machine being close to its commit limit, if it is.
///
/// `None` when there is room, and `None` when the machine will not say — not
/// knowing is not the same fact as knowing there is no room, and a warning
/// invented from a missing number is worse than no warning.
pub fn advice() -> Option<String> {
    advice_for(available_commit())
}

/// The advice for a known amount of free commit, so that it can be tested.
fn advice_for(free: Option<u64>) -> Option<String> {
    let free = free?;
    if free >= TIGHT_COMMIT {
        return None;
    }
    Some(format!(
        "only {} MiB is left to commit on this machine; the scan will run, but one large file \
         at a time -- close something, or lower the thread count with -j 2",
        free / (1024 * 1024)
    ))
}

/// How many more bytes this machine can commit, if it will say.
///
/// `ullAvailPageFile` is the commit limit minus what is committed — with no
/// page file the limit is physical memory, and what is left is exactly the
/// headroom an allocation of a file buffer has to fit into. That is the number
/// this budget is a fraction of, and it is the number that was 836 MB when the
/// three-file scan aborted.
#[cfg(windows)]
fn available_commit() -> Option<u64> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status` is a correctly sized, correctly aligned output structure
    // whose `dwLength` says so, which is what the call requires.
    unsafe { GlobalMemoryStatusEx(&mut status) }.ok()?;
    Some(status.ullAvailPageFile)
}

/// Nowhere else has an answer this crate can act on, so it uses the default.
#[cfg(not(windows))]
fn available_commit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_is_released_when_it_is_dropped() {
        let budget = Budget::new(1000);
        assert_eq!(budget.free(), 1000);
        {
            // Two copies of a 100-byte file.
            let held = budget.reserve(100);
            assert_eq!(held.bytes(), 200);
            assert_eq!(budget.free(), 800);
        }
        assert_eq!(budget.free(), 1000);
    }

    #[test]
    fn a_file_larger_than_the_budget_is_granted_the_whole_of_it() {
        // The alternative is waiting for room that cannot exist. The budget is
        // charged in full -- that is, the whole of it -- so the file goes alone
        // and the next one waits. The charge is capped at the ceiling rather
        // than being the file's true cost, which does not change what the file
        // holds; see the module note on why the cap is the right answer.
        let budget = Budget::new(1000);
        let held = budget.reserve(5000);
        assert_eq!(held.bytes(), 1000);
        assert_eq!(budget.free(), 0);
    }

    #[test]
    fn a_second_reservation_waits_for_the_first() {
        let budget = std::sync::Arc::new(Budget::new(1000));
        let held = budget.reserve(400); // 800 charged, 200 left
        let other = std::sync::Arc::clone(&budget);
        let waiter = std::thread::spawn(move || {
            // 600 charged, which does not fit in 200.
            let second = other.reserve(300);
            second.bytes()
        });
        // The waiter cannot proceed while the first is held. This is asserted by
        // releasing and then joining rather than by sleeping: a sleep would be a
        // test that passes because the machine is slow.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(budget.free(), 200);
        drop(held);
        assert_eq!(waiter.join().expect("the waiter finishes"), 600);
        assert_eq!(budget.free(), 1000);
    }

    #[test]
    fn the_deadline_grows_with_the_file_being_waited_for() {
        // The failure this guards against is a fixed deadline that a big file
        // outlives: at the measured floor of about 1 MB/s per core, a file at
        // the 256 MiB cap takes minutes to scan, and a waiter that gave up
        // after thirty seconds would proceed unreserved and defeat the budget.
        let small = patience(1024 * 1024, 0); // a 512 KiB file, nothing held
        let capped = patience(256 * 1024 * 1024, 0); // one at the default cap
        assert!(
            capped > small,
            "a larger file must be waited for longer: {capped:?} vs {small:?}"
        );
        // The wait has to be at least as long as the scan it is waiting on.
        let scanning = Duration::from_secs(
            (256 * 1024 * 1024 / COPIES_PER_FILE) / av_core::FLOOR_BYTES_PER_SEC,
        );
        assert!(
            capped >= scanning,
            "{capped:?} is shorter than the {scanning:?} scan it is waiting for"
        );
    }

    #[test]
    fn the_deadline_covers_what_is_held_and_not_only_what_is_wanted() {
        // Measured 2026-09-22, and the reason this term exists: a 90 MB file
        // held 180 MB, and a 73 MB file asking for 146 MB of a 256 MiB ceiling
        // computed its deadline from its own 146 MB alone. That came to 103
        // seconds against a scan that needed longer, so the budget logged
        // "gave up; continuing without a reservation" twice in one run and the
        // peak went from 816 MB to 876 MB.
        let want = 146_173_744; // a 73 MB file, two copies
        let held = 179_543_696; // a 90 MB file, two copies, already in flight
        let alone = patience(want, 0);
        let together = patience(want, held);
        assert!(
            together > alone,
            "what is held has to lengthen the wait: {together:?} vs {alone:?}"
        );
        // The wait must cover scanning both, because both are in memory and the
        // room is only free when the last of them finishes.
        let scanning = Duration::from_secs(
            ((want + held) / COPIES_PER_FILE) / av_core::FLOOR_BYTES_PER_SEC,
        );
        assert!(
            together >= scanning,
            "{together:?} is shorter than the {scanning:?} of scanning it waits for"
        );
        // And the case that actually failed has to be covered by a margin, not
        // squeaked past: 99 seconds of waiting was not enough.
        assert!(
            together >= Duration::from_secs(140),
            "{together:?} leaves no margin over the 99 s that was measured failing"
        );
    }

    #[test]
    fn one_release_wakes_every_waiter_and_not_only_the_first() {
        // The defect this test is named for. A release signalled a single
        // waiter, which is right only if any waiter can use the room; with a
        // ceiling that admits one large file, a release of part of it does
        // nothing for a waiter that wants all of it. The woken one re-waits and
        // the rest sleep on, with their own deadline as the only other chance.
        //
        // Measured on this machine, 2026-09-22: four waiters reached that
        // deadline while the machine had a gigabyte free to commit, and the peak
        // went from 816 MB to 1345 MB against a 256 MiB allowance.
        //
        // The waiters below fit together in the whole ceiling, so the release
        // admits both. With a single notification the second is not woken at
        // all, and its next chance is its deadline -- thirty seconds at the
        // smallest, against the ten allowed here.
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::thread;

        let budget = Arc::new(Budget::new(1000));
        let held = budget.reserve(500); // the whole ceiling: 1000 charged
        assert_eq!(budget.free(), 0);

        let (ready, queued) = mpsc::channel();
        let (resumed, watched) = mpsc::channel();
        let mut signals = Vec::new();
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let budget = Arc::clone(&budget);
            let ready = ready.clone();
            let resumed = resumed.clone();
            // Each waiter holds its reservation until the test is over, so that
            // neither can admit the other by releasing.
            let (signal, hold) = mpsc::channel::<()>();
            signals.push(signal);
            waiters.push(thread::spawn(move || {
                ready.send(()).expect("the test is still listening");
                // 100 charged each, so the two fit together in the ceiling.
                let reservation = budget.reserve(50);
                resumed.send(reservation.bytes()).expect("reported");
                let _ = hold.recv();
            }));
        }
        drop((ready, resumed));

        // Both have to be inside `reserve` before the release, or the test
        // passes without ever exercising a wait. The pause is for that queueing,
        // not for the assertion: what is asserted is the ten seconds below, and
        // waking a single waiter misses it by twenty.
        for _ in 0..2 {
            queued.recv().expect("both waiters reach the reservation");
        }
        thread::sleep(Duration::from_millis(100));

        drop(held);

        for _ in 0..2 {
            let bytes = watched
                .recv_timeout(Duration::from_secs(10))
                .expect("both waiters resume on the release, not at their deadline");
            assert_eq!(bytes, 100);
        }
        drop(signals);
        for waiter in waiters {
            waiter.join().expect("the waiters finish");
        }
        assert_eq!(budget.free(), 1000);
    }

    #[test]
    fn a_budget_of_zero_still_admits_one_file_at_a_time() {
        let budget = Budget::new(0);
        assert_eq!(budget.total(), 1);
        // Admitted despite the ceiling being a single byte: the alternative is
        // a scan that refuses to scan anything, and one file at a time is the
        // most a zero budget can honestly promise.
        let held = budget.reserve(10);
        assert_eq!(held.bytes(), 1);
        assert_eq!(budget.free(), 0);
    }

    #[test]
    fn the_machine_budget_is_within_its_clamps() {
        // Whatever this machine answers, the number is one a scan can run
        // under: a constant here would be a machine's answer imposed on every
        // other machine.
        let budget = Budget::from_machine();
        assert!(budget.total() >= 1);
        assert_eq!(budget.free(), budget.total());
    }

    /// A ceiling a test can move, and a handle to move it with.
    fn movable(start: u64) -> (std::sync::Arc<std::sync::atomic::AtomicU64>, Budget) {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;
        let ceiling = Arc::new(AtomicU64::new(start));
        let watched = Arc::clone(&ceiling);
        let budget = Budget::scripted(move || watched.load(std::sync::atomic::Ordering::SeqCst));
        (ceiling, budget)
    }

    #[test]
    fn a_ceiling_that_falls_takes_the_difference_out_of_what_is_unreserved() {
        // The defect this test is named for, in miniature. The ceiling used to
        // be taken once, at whichever moment the first read happened to ask,
        // and remembered. A scan that sized itself against memory the rule
        // database then committed was a scan that had already spent its budget
        // before it read a byte, and it died in the allocator rather than
        // waiting for room it did not have.
        use std::sync::atomic::Ordering;
        let (ceiling, budget) = movable(1000);
        assert_eq!(budget.total(), 1000);
        assert_eq!(budget.free(), 1000);

        // Something outside this crate commits most of it: loading the rules.
        ceiling.store(100, Ordering::SeqCst);

        // Asked again, so the answer moves. A remembered ceiling would still
        // say 1000 here and grant 1000 bytes that are not there.
        assert_eq!(budget.total(), 100);
        assert_eq!(budget.free(), 100);
    }

    #[test]
    fn a_file_larger_than_a_shrunken_ceiling_is_clamped_to_the_shrunken_one() {
        // The same property seen from the reservation rather than from the
        // count: what a big file is allowed to take is the ceiling as it stands
        // now, not the one that was standing when the budget was built.
        use std::sync::atomic::Ordering;
        let (ceiling, budget) = movable(1000);
        ceiling.store(200, Ordering::SeqCst);

        let held = budget.reserve(5000);
        assert_eq!(held.bytes(), 200, "clamped to the ceiling now, not the old one");
    }

    #[test]
    fn a_ceiling_that_falls_below_what_is_held_leaves_nothing_to_grant() {
        // Where the arithmetic has to saturate rather than wrap. A held
        // reservation larger than the new ceiling is memory already committed
        // and cannot be given back on demand, so the honest answer for what is
        // left is none of it -- not a negative number, and not the old total
        // minus the new one.
        use std::sync::atomic::Ordering;
        let (ceiling, budget) = movable(1000);
        let held = budget.reserve(400); // two copies, so 800 charged
        assert_eq!(held.bytes(), 800);
        assert_eq!(budget.free(), 200);

        ceiling.store(500, Ordering::SeqCst);

        assert_eq!(budget.free(), 0);
        drop(held);
        assert_eq!(budget.free(), 500);
    }

    #[test]
    fn a_machine_with_room_gets_no_advice() {
        assert_eq!(advice_for(Some(TIGHT_COMMIT)), None);
        assert_eq!(advice_for(Some(16 * 1024 * 1024 * 1024)), None);
    }

    #[test]
    fn a_machine_without_room_is_told_the_number_and_the_lever() {
        let advice = advice_for(Some(80 * 1024 * 1024)).expect("80 MiB is below the threshold");
        // The number, because "low on memory" without it is not actionable.
        assert!(advice.contains("80 MiB"), "{advice}");
        // The lever, and specifically the one this product has: the budget is
        // what serialises large files, and the thread count is what decides how
        // many of them ask at once.
        assert!(advice.contains("-j 2"), "{advice}");
    }

    #[test]
    fn a_machine_that_will_not_say_gets_no_advice() {
        // Not knowing is a different fact from knowing there is no room. A
        // warning built out of a missing number is one a user cannot act on and
        // will learn to ignore.
        assert_eq!(advice_for(None), None);
    }

    #[test]
    // The two sides are constants, so clippy is right that this is decided at
    // compile time. That is the point: the test is a tripwire for a later change
    // to one of the two constants, and a constant assertion is what makes the
    // relation between them impossible to break without a test saying so.
    #[allow(clippy::assertions_on_constants)]
    fn the_advice_threshold_is_the_ceiling_floor_writ_large() {
        // The two constants have to stay in a sane relation: the advice fires
        // while the ceiling is still above its floor, so that the warning
        // arrives before the scan is down to one large file at a time rather
        // than after. If a later change moves one and not the other, this says
        // so.
        assert!(
            TIGHT_COMMIT / 4 > 32 * 1024 * 1024,
            "the ceiling floor (32 MiB = a quarter of 128 MiB) must be reached \
             well below the advice threshold, or the warning is printed only \
             once the scan has already slowed to serial"
        );
    }
}
