//! The last few images the section gate refused, so that a creation the refusal
//! did not stop can still be stopped.
//!
//! # Why this exists, in one measured second
//!
//! On 2026-10-18 the section gate refused `C:\Samples\wannacry.exe` at
//! 12:32:53 — `STATUS_INSUFFICIENT_RESOURCES`, the only status the filter
//! manager honours for a created section — and the process running it was
//! walked at 12:32:54. In the same second, through the same gate, the refusal
//! of `C:\Samples\taskdl.exe` was followed by no process at all. **A logged
//! refusal can be followed by the program running**, and the section callback
//! has no way to say anything more: by the time it returns
//! `FLT_PREOP_COMPLETE` it has done everything that one operation allows.
//!
//! `PS_CREATE_NOTIFY_INFO.CreationStatus` is the second lever, and it is a
//! different one: it fails the creation itself rather than an operation on the
//! way to it, and the kernel documents it as the way a notify routine refuses a
//! process (`ntddk.h` declares the field `_Inout_` for exactly this). This table
//! is what connects the two — the path the section gate refused, and when —
//! because the process-notification callback runs after the gate and has no
//! other way to know what it said.
//!
//! # What it is not
//!
//! It is not a verdict cache, and it cannot refuse anything the engine has not
//! already refused: entries are written only on a `Block`, [`RefusalMemo::forget`]
//! removes one the moment the gate allows the same path, and the only question
//! it answers is "did this driver say no to this exact path a moment ago".
//!
//! # Concurrency
//!
//! Writers ([`RefusalMemo::remember`], [`RefusalMemo::forget`]) run in the
//! section gate's pre-operation, which has returned early above `APC_LEVEL`;
//! readers ([`RefusalMemo::refused_recently`]) run in the process-creation
//! callback. A reader must never accept a half-written path, because a torn one
//! could compare equal to a path it is not and refuse a process nothing ever
//! refused. Each slot therefore carries a sequence number — odd while a writer
//! holds it, even when it is stable — and a reader whose number moved discards
//! what it read. A writer claims a slot by compare-exchanging the number from
//! even to odd, which is what makes the claim exclusive.
//!
//! This is a seqlock and not a spinlock because the two ends have different
//! obligations: a reader never blocks (it runs in a process-creation callback,
//! on the thread doing the creating), and a writer is a callback that is already
//! about to block on the service and may not take a lock the reply path needs.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::path::eq_ignore_ascii_case;
use crate::wire::MAX_PATH_UNITS;

/// How many refused images the creation veto remembers.
///
/// Small on purpose. The creation a refusal is about follows it by milliseconds
/// — the parent is inside `CreateProcess` while the section gate waits for its
/// answer — so this has to cover one question and the call after it, not a
/// machine's worth of history.
pub const MAX_REFUSAL_MEMO: usize = 8;

/// How long a refusal authorises vetoing a creation of the same image.
///
/// The measurement this is written against, from the test VM on 2026-10-18:
/// `C:\Samples\wannacry.exe` was refused at 12:32:53 and the process running it
/// was first walked at 12:32:54. A second is the whole gap, and sixty is that
/// with room for a machine under load. It is not a verdict lifetime: the entry
/// only has to outlive the `CreateProcess` whose section gate caused it.
pub const REFUSAL_MEMO_WINDOW_100NS: u64 = 60 * 10_000_000;

/// One remembered refusal.
#[derive(Clone, Copy)]
struct RefusalSlot {
    /// Interrupt time, in the same 100-nanosecond units the caller passes to
    /// [`RefusalMemo::remember`], when the section gate refused it.
    at_100ns: u64,
    /// Meaningful length of `path`. Not an allocation size.
    units: u32,
    /// The refused image as a DOS path, which is the form both callbacks reach.
    path: [u16; MAX_PATH_UNITS],
}

const EMPTY_REFUSAL_SLOT: RefusalSlot = RefusalSlot {
    at_100ns: 0,
    units: 0,
    path: [0; MAX_PATH_UNITS],
};

/// The last few paths the section gate refused.
pub struct RefusalMemo {
    slots: UnsafeCell<[RefusalSlot; MAX_REFUSAL_MEMO]>,
    /// Per-slot sequence; see the module documentation.
    seq: [AtomicU32; MAX_REFUSAL_MEMO],
    /// Round-robin, so two refusals cannot fight over one slot forever.
    next: AtomicUsize,
}

// SAFETY: the only interior mutation goes through `slots`, and a slot is
// readable only inside a window that begins and ends with its sequence number
// being even and unchanged. Everything else is atomic. That is what `Sync`
// requires of this type.
unsafe impl Sync for RefusalMemo {}

impl Default for RefusalMemo {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for RefusalMemo {
    /// Names the type and dumps nothing.
    ///
    /// The table is interior-mutable and read without a lock by design, so a
    /// `Debug` that walked it would be a reader outside the sequence protocol —
    /// exactly the thing the module documentation says must not exist. What a
    /// diagnostic actually needs here is the answer, and
    /// [`RefusalMemo::refused_recently`] is the only reader allowed to give it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RefusalMemo")
    }
}

impl RefusalMemo {
    /// An empty memo. `const`, so a driver can hold one in a `static`.
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([EMPTY_REFUSAL_SLOT; MAX_REFUSAL_MEMO]),
            seq: [const { AtomicU32::new(0) }; MAX_REFUSAL_MEMO],
            next: AtomicUsize::new(0),
        }
    }

    /// Take exclusive use of `index`, or report that someone else has it.
    ///
    /// The compare-exchange is what makes the writer's claim exclusive: it only
    /// succeeds from an even value, so a slot can be held by one writer at a
    /// time and a reader can never see two writers' bytes mixed.
    fn begin_write(&self, index: usize) -> bool {
        let mut seen = self.seq[index].load(Ordering::Relaxed);
        loop {
            if seen & 1 != 0 {
                return false;
            }
            match self.seq[index].compare_exchange_weak(
                seen,
                seen.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => seen = actual,
            }
        }
    }

    /// Remember that `path` was refused at `now`.
    ///
    /// A path that is empty or longer than [`MAX_PATH_UNITS`] is not stored: it
    /// could not be compared against a path from the other callback, and a
    /// stored prefix of one would match nothing it should.
    pub fn remember(&self, path: &[u16], now: u64) {
        if path.is_empty() || path.len() > MAX_PATH_UNITS {
            return;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..MAX_REFUSAL_MEMO {
            let index = (start.wrapping_add(offset)) % MAX_REFUSAL_MEMO;
            if !self.begin_write(index) {
                continue;
            }
            // SAFETY: `begin_write` made the sequence number odd, so no reader
            // accepts this slot until the release below, and the slot is inside
            // the array by the modulo above.
            unsafe {
                let slot = &mut (*self.slots.get())[index];
                slot.path[..path.len()].copy_from_slice(path);
                slot.units = path.len() as u32;
                slot.at_100ns = now;
            }
            self.seq[index].fetch_add(1, Ordering::Release);
            return;
        }
    }

    /// Forget `path`, because the gate has just allowed it.
    ///
    /// An allow is the freshest word the driver has about a file, and a memo
    /// that outlived it would refuse a process the section gate had just said
    /// yes to. That is the one way this table could stop something innocent, and
    /// this is the line that closes it.
    pub fn forget(&self, path: &[u16]) {
        for index in 0..MAX_REFUSAL_MEMO {
            if !self.begin_write(index) {
                continue;
            }
            // The comparison happens **while this writer holds the slot**, not
            // before claiming it. Checking first and then clearing would leave a
            // window in which another writer could publish a different path into
            // the slot, and this function would then erase a refusal it had
            // never read.
            //
            // SAFETY: the sequence number is odd, so no other writer and no
            // reader touches this slot until the release below, and it is inside
            // the array by the loop bound.
            let matches = unsafe {
                let slot = &(*self.slots.get())[index];
                Self::same(slot, path)
            };
            if matches {
                // SAFETY: as above — the slot is held, and a reader that started
                // before this claim sees the sequence move and discards what it
                // read.
                unsafe {
                    (*self.slots.get())[index].units = 0;
                }
            }
            self.seq[index].fetch_add(1, Ordering::Release);
        }
    }

    /// Whether `path` was refused less than [`REFUSAL_MEMO_WINDOW_100NS`] ago.
    pub fn refused_recently(&self, path: &[u16], now: u64) -> bool {
        if path.is_empty() || path.len() > MAX_PATH_UNITS {
            return false;
        }
        for index in 0..MAX_REFUSAL_MEMO {
            let before = self.seq[index].load(Ordering::Acquire);
            if before & 1 != 0 {
                continue;
            }
            // SAFETY: the sequence number was even when it was read and is
            // re-read below; a slot whose number moved is discarded, so a read
            // that overlapped a writer is never trusted. The slot is inside the
            // array by the loop bound.
            let hit = unsafe {
                let slot = &(*self.slots.get())[index];
                let units = slot.units as usize;
                // A length no writer can have written is a torn read, not a
                // match; the guard also keeps the slice inside the array.
                units <= MAX_PATH_UNITS
                    && now.saturating_sub(slot.at_100ns) <= REFUSAL_MEMO_WINDOW_100NS
                    && Self::same(slot, path)
            };
            let after = self.seq[index].load(Ordering::Acquire);
            if before == after && hit {
                return true;
            }
        }
        false
    }

    /// Whether a slot holds exactly `path`.
    ///
    /// # Safety-adjacent contract
    ///
    /// The caller must hold the slot (a writer's odd sequence number) or have
    /// bracketed the read with equal even ones; the length guard is what keeps
    /// the slice inside the array in either case.
    fn same(slot: &RefusalSlot, path: &[u16]) -> bool {
        let units = slot.units as usize;
        units <= MAX_PATH_UNITS && units == path.len() && eq_ignore_ascii_case(&slot.path[..units], path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn an_empty_memo_refuses_nothing() {
        let memo = RefusalMemo::new();
        assert!(!memo.refused_recently(&units(r"C:\Samples\wannacry.exe"), 1));
    }

    #[test]
    fn a_refusal_is_remembered_inside_the_window() {
        let memo = RefusalMemo::new();
        let path = units(r"C:\Samples\wannacry.exe");
        memo.remember(&path, 1_000);
        assert!(memo.refused_recently(&path, 1_000));
        assert!(memo.refused_recently(&path, 1_000 + REFUSAL_MEMO_WINDOW_100NS));
    }

    #[test]
    fn a_refusal_expires_after_the_window() {
        let memo = RefusalMemo::new();
        let path = units(r"C:\Samples\wannacry.exe");
        memo.remember(&path, 1_000);
        assert!(!memo.refused_recently(
            &path,
            1_001 + REFUSAL_MEMO_WINDOW_100NS
        ));
    }

    #[test]
    fn the_match_ignores_ascii_case() {
        let memo = RefusalMemo::new();
        memo.remember(&units(r"C:\Samples\wannacry.exe"), 5);
        assert!(memo.refused_recently(&units(r"c:\samples\WANNACRY.EXE"), 5));
    }

    #[test]
    fn a_different_path_does_not_match() {
        let memo = RefusalMemo::new();
        memo.remember(&units(r"C:\Samples\wannacry.exe"), 5);
        assert!(!memo.refused_recently(&units(r"C:\Samples\taskdl.exe"), 5));
        // A prefix of the refused path is a different file.
        assert!(!memo.refused_recently(&units(r"C:\Samples\wannacry"), 5));
    }

    #[test]
    fn an_allow_forgets_the_refusal() {
        let memo = RefusalMemo::new();
        let path = units(r"C:\Samples\wannacry.exe");
        memo.remember(&path, 5);
        memo.forget(&path);
        assert!(!memo.refused_recently(&path, 5));
    }

    #[test]
    fn forgetting_one_path_leaves_the_others() {
        let memo = RefusalMemo::new();
        let kept = units(r"C:\Samples\a.exe");
        let dropped = units(r"C:\Samples\b.exe");
        memo.remember(&kept, 5);
        memo.remember(&dropped, 5);
        memo.forget(&dropped);
        assert!(!memo.refused_recently(&dropped, 5));
        assert!(memo.refused_recently(&kept, 5));
    }

    #[test]
    fn more_refusals_than_slots_keep_the_newest() {
        let memo = RefusalMemo::new();
        // One more than the table holds, so the first one is evicted.
        let paths: Vec<Vec<u16>> = (0..=MAX_REFUSAL_MEMO)
            .map(|i| units(&format!(r"C:\Samples\{i}.exe")))
            .collect();
        for path in &paths {
            memo.remember(path, 5);
        }
        assert!(!memo.refused_recently(&paths[0], 5), "the oldest is gone");
        for path in &paths[1..] {
            assert!(memo.refused_recently(path, 5));
        }
    }

    #[test]
    fn an_empty_path_is_never_stored_or_matched() {
        let memo = RefusalMemo::new();
        memo.remember(&[], 5);
        assert!(!memo.refused_recently(&[], 5));
        // Nothing was stored, so no query of a real path matches either.
        assert!(!memo.refused_recently(&units(r"C:\a.exe"), 5));
    }

    /// A concurrent remember/forget/query storm must not panic and must not
    /// report a match for a path that was never remembered.
    ///
    /// This is a smoke test and not a proof of the seqlock: it cannot observe a
    /// torn read that a later sequence check discards, which is the property the
    /// implementation is built on. What it can catch is a claim that is never
    /// released (the next remember would spin forever on a slot it never
    /// escapes) and a comparison that reads outside the slot.
    #[test]
    fn concurrent_writers_and_readers_stay_consistent() {
        use std::sync::Arc;

        let memo = Arc::new(RefusalMemo::new());
        let mut handles = Vec::new();
        for worker in 0..4u16 {
            let memo = Arc::clone(&memo);
            handles.push(std::thread::spawn(move || {
                let mine = units(&format!(r"C:\Samples\{worker}.exe"));
                let other = units(&format!(r"C:\Samples\{}.exe", (worker + 1) % 4));
                for _ in 0..2_000 {
                    memo.remember(&mine, 7);
                    let _ = memo.refused_recently(&other, 7);
                    memo.forget(&mine);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("a worker panicked");
        }
        // Every worker forgot its own path last, so nothing is left to match.
        for worker in 0..4u16 {
            assert!(!memo.refused_recently(&units(&format!(r"C:\Samples\{worker}.exe")), 7));
        }
    }
}
