//! A record of the crash that otherwise leaves none.
//!
//! # What an out-of-memory abort looks like from the outside
//!
//! Nothing. Rust's infallible allocation path, on failure, calls
//! [`handle_alloc_error`], which prints one line to stderr and then calls
//! `abort()`. On Windows that abort is `__fastfail(FAST_FAIL_FATAL_APP_EXIT)`,
//! so the event log gets exception `0xc0000409` with exception data `7`,
//! classified as `BEX64`, pointing at an address inside the allocator and
//! giving no reason whatsoever.
//!
//! In a console that one stderr line survives if somebody happens to be
//! watching it. In the window there is no stderr anybody reads, so the report
//! the user can actually make is *"the scan got slow and then it was gone"* —
//! with nothing anywhere saying what it asked for, or how much there was.
//!
//! # What this does about it
//!
//! It wraps the allocator, and the wrapper writes the report *before* it
//! returns null — while the process is still alive and can still write. The
//! report carries the size that was refused and what the machine had left to
//! commit, which is the pair of numbers that turns "it crashed" into
//! "it asked for 200 MB with 80 MB left".
//!
//! It cannot stop the abort. [`handle_alloc_error`] runs after the allocator
//! returns, `abort` cannot be caught, and `catch_unwind` never sees any of it.
//! This is a witness, not a fix: the fix is to not ask for the memory, which is
//! what the scan budget in `av-fs` is for.
//!
//! # Why the report path allocates nothing
//!
//! Because it runs at the moment allocation has already failed. Formatting a
//! `String` to describe the failure would be an allocation, that allocation
//! would fail the same way, and the report would never reach anybody. So the
//! message is built in a fixed stack buffer by `Line`, which writes decimal
//! digits by hand and drops anything that does not fit. The destination is
//! either a [`std::fs::File`] opened at startup — one syscall, no buffer — or
//! stderr, whose own buffer is the one thing that might not be allocatable.
//!
//! # Why it cannot recurse
//!
//! Writing to stderr goes through a `LineWriter`, which holds a `Vec`; a write
//! that has to grow that `Vec` is an allocation, and an allocation during a
//! report is another failure, which is another report. `REPORTING` breaks
//! that: the first failure through gets to write, everything it triggers on the
//! way out returns immediately. Since the file is written first and it is the
//! copy that survives, losing the stderr copy to the guard costs nothing.
//!
//! [`handle_alloc_error`]: std::alloc::handle_alloc_error

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// The process allocator: the system one, with a failure reporter in front.
///
/// Install it exactly once, in a binary crate — a library cannot declare the
/// global allocator, only the final artifact can:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: av_core::alloc::Reporting = av_core::alloc::Reporting;
/// ```
///
/// and give it somewhere to write with [`set_crash_log`] as soon as the
/// install paths are known. Without that call the report still goes to stderr,
/// which is the right behaviour for a CLI and useless for the window.
pub struct Reporting;

impl std::fmt::Debug for Reporting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reporting(system allocator + allocation-failure log)")
    }
}

/// Where failures are appended, if the product said where to write them.
static CRASH_LOG: OnceLock<std::fs::File> = OnceLock::new();

/// Set while a report is being written, so that a report cannot trigger itself.
static REPORTING: AtomicBool = AtomicBool::new(false);

/// How many reports have been attempted, against [`MAX_REPORTS`].
static ATTEMPTED: AtomicUsize = AtomicUsize::new(0);

/// The most reports one process writes.
///
/// A failed scan can fail the allocation on every one of a dozen worker
/// threads at once, and the first report is the informative one: it has the
/// size, the free commit, and the moment. What follows adds no fact and only
/// delays the abort that is already coming.
const MAX_REPORTS: usize = 8;

/// Point the reporter at a file to append to.
///
/// Called once, at startup, with something like `<data dir>/logs/crash.log`.
/// Opening it *here* rather than at the moment of failure is the whole point:
/// by then the process may not be able to open a file, but writing to one that
/// is already open is a single syscall.
///
/// The parent directory is created if it is missing. That is not tidiness: the
/// call is made once, at startup, and a crash log that was never installed
/// because the product's log directory did not exist yet is precisely the
/// failure this module exists to prevent.
///
/// Returns an error if the file cannot be opened; a caller that ignores it
/// still gets the stderr copy.
pub fn set_crash_log(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    // A second call is not an error, it just does nothing -- the first file is
    // the one the failures go to, and swapping it mid-run would lose the early
    // ones.
    let _ = CRASH_LOG.set(file);
    Ok(())
}

/// Whether a crash log has been installed.
///
/// The front ends use this to say so in the scan banner, so that a user
/// reporting a crash knows where to look before it happens.
pub fn crash_log_installed() -> bool {
    CRASH_LOG.get().is_some()
}

unsafe impl GlobalAlloc for Reporting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller of a `GlobalAlloc` method guarantees `layout` has
        // non-zero size, which is `System`'s contract too.
        let granted = unsafe { System.alloc(layout) };
        if granted.is_null() {
            report(layout.size());
        }
        granted
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`.
        let granted = unsafe { System.alloc_zeroed(layout) };
        if granted.is_null() {
            report(layout.size());
        }
        granted
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller guarantees `ptr` came from this allocator with
        // `layout` and is still live, which is `System`'s contract too.
        let granted = unsafe { System.realloc(ptr, layout, new_size) };
        if granted.is_null() {
            // `new_size`, not `layout.size()`: the number that mattered is the
            // one that could not be satisfied, and reporting the old size of a
            // buffer that grew into failure would name the wrong figure.
            report(new_size);
        }
        granted
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` came from this allocator with
        // `layout`. `dealloc` cannot fail and so has nothing to report.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Write the report for a refused allocation of `requested` bytes.
fn report(requested: usize) {
    // The guard is taken first and released last. Everything below it -- the
    // formatting, the file write, and above all the stderr write -- is allowed
    // to allocate, and none of it may re-enter this function.
    if REPORTING.swap(true, Ordering::SeqCst) {
        return;
    }

    let attempt = ATTEMPTED.fetch_add(1, Ordering::Relaxed);
    match attempt.cmp(&MAX_REPORTS) {
        std::cmp::Ordering::Less => {
            let mut line = Line::new();
            failure_line(&mut line, requested);
            emit(line.bytes());
        }
        std::cmp::Ordering::Equal => {
            let mut line = Line::new();
            line.text("wenle: further allocation-failure reports suppressed\n");
            emit(line.bytes());
        }
        // Everything past the cap is silent. The process is aborting; the
        // remaining reports can only make the exit slower.
        std::cmp::Ordering::Greater => {}
    }

    REPORTING.store(false, Ordering::SeqCst);
}

/// Write the bytes to the crash log and to stderr.
///
/// The file goes first because it allocates nothing, so it is the copy that
/// survives both a window with no stderr and a stderr whose buffer is itself
/// what could not be allocated.
fn emit(bytes: &[u8]) {
    if let Some(file) = CRASH_LOG.get() {
        // `&File` implements `Write` by delegating to a shared handle, so this
        // needs no `&mut` and no lock beyond the one inside the handle.
        let _ = (&*file).write_all(bytes);
    }
    // Ignored on purpose: if this is the write that fails, there is nowhere
    // left to report *that* to, and `report` is already guarded against being
    // re-entered by it.
    let _ = std::io::stderr().write_all(bytes);
}

/// The text of a failure report, built without allocating.
///
/// Kept separate from [`report`] so that it can be tested: a test can fill a
/// `Line` and read it back as a `String`, which allocates, and a `report` that
/// allocates is the one thing this module must never do.
fn failure_line(line: &mut Line, requested: usize) {
    line.text("wenle: memory allocation of ");
    line.number(requested as u64);
    line.text(" bytes failed");
    match memory_status() {
        Some(status) => {
            line.text("; commit available ");
            line.number(status.available_commit);
            line.text(" of ");
            line.number(status.commit_limit);
            line.text(", physical memory ");
            line.number(status.load_percent as u64);
            line.text("% in use");
        }
        // Worth distinguishing from "there was plenty free". Not knowing is a
        // different fact from knowing there was room, and only one of them
        // means the accounting is wrong rather than the machine being full.
        None => line.text("; the machine would not report what is left"),
    }
    line.text("\nwenle: this process is about to abort -- the scan budget in the line above is what should have stopped it\n");
}

/// What the machine had left, as of right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryStatus {
    /// Commit charge still available process-wide — RAM plus page file.
    pub available_commit: u64,
    /// The commit limit itself: how much can be committed in total.
    pub commit_limit: u64,
    /// Physical memory in use, as a percentage.
    pub load_percent: u32,
}

/// Read the machine's memory state, or `None` if it will not say.
///
/// # Why `ullAvailPageFile` and not `ullAvailPhys`
///
/// The allocation that just failed was a *commit*, not a demand for resident
/// pages. On a machine with no page file the two are the same number, and on a
/// machine with one the interesting figure is still the commit: a request can
/// be granted with no free physical page at all, and refused with plenty.
pub fn memory_status() -> Option<MemoryStatus> {
    platform_memory_status()
}

#[cfg(windows)]
fn platform_memory_status() -> Option<MemoryStatus> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    // Written out field by field rather than with `..Default::default()`, so
    // that a future `windows` release adding a member cannot silently leave
    // `dwLength` describing the old size.
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    // SAFETY: `status` is a live, fully initialised `MEMORYSTATUSEX` whose
    // `dwLength` is its own size, which is the entire contract of this call.
    // It writes only into that struct and touches no other memory.
    if unsafe { GlobalMemoryStatusEx(&mut status) }.is_err() {
        return None;
    }
    Some(MemoryStatus {
        available_commit: status.ullAvailPageFile,
        commit_limit: status.ullTotalPageFile,
        load_percent: status.dwMemoryLoad,
    })
}

#[cfg(not(windows))]
fn platform_memory_status() -> Option<MemoryStatus> {
    // No portable equivalent that means the same thing. `None` is honest here:
    // the report says the figure was unavailable rather than inventing one.
    None
}

/// A fixed-capacity byte buffer that formats without allocating.
///
/// Overflow is not an error and not a panic: the buffer is sized well past the
/// longest line this module writes, and anything beyond it is dropped rather
/// than allowed to turn a report about a memory failure into a second one.
struct Line {
    buf: [u8; 384],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Self {
            buf: [0; 384],
            len: 0,
        }
    }

    fn text(&mut self, text: &str) {
        for byte in text.as_bytes() {
            self.push(*byte);
        }
    }

    /// Append `value` in decimal, most significant digit first.
    fn number(&mut self, mut value: u64) {
        // Twenty digits is the most a `u64` can need.
        let mut digits = [0u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            self.push(digits[count]);
        }
    }

    fn push(&mut self, byte: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = byte;
            self.len += 1;
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// The only way to read a `Line` is to allocate a `String` from it, which
    /// is fine here and is exactly what the production path cannot do.
    fn text(line: &Line) -> String {
        String::from_utf8_lossy(line.bytes()).into_owned()
    }

    #[test]
    fn a_failure_report_names_the_size_that_was_refused() {
        let mut line = Line::new();
        failure_line(&mut line, 209_715_200);
        let text = text(&line);
        assert!(
            text.contains("209715200 bytes failed"),
            "the size asked for is the point of the report: {text}"
        );
    }

    #[test]
    fn a_failure_report_says_the_process_is_about_to_abort() {
        let mut line = Line::new();
        failure_line(&mut line, 1);
        let text = text(&line);
        assert!(text.contains("about to abort"), "{text}");
        // The scan budget line is printed before the scan starts; without
        // pointing at it the report reads as an unexplained crash.
        assert!(text.contains("scan budget"), "{text}");
    }

    #[test]
    fn a_report_never_exceeds_the_buffer_it_is_built_in() {
        // `u64::MAX` is twenty digits, and it appears three times along with
        // the prose, so this is the widest line the module can be asked for.
        let mut line = Line::new();
        line.text("wenle: memory allocation of ");
        line.number(u64::MAX);
        line.text(" bytes failed; commit available ");
        line.number(u64::MAX);
        line.text(" of ");
        line.number(u64::MAX);
        line.text(", physical memory ");
        line.number(u64::MAX);
        line.text("% in use\nwenle: this process is about to abort -- the scan budget in the line above is what should have stopped it\n");
        assert!(
            line.len < line.buf.len(),
            "a full-width report must still fit, or the tail is silently dropped"
        );
    }

    #[test]
    fn numbers_are_written_in_decimal_most_significant_first() {
        let mut line = Line::new();
        for value in [0u64, 7, 10, 99, 100, 1_000_000_000, u64::MAX] {
            line.number(value);
            line.push(b' ');
        }
        assert_eq!(
            text(&line),
            "0 7 10 99 100 1000000000 18446744073709551615 "
        );
    }

    #[test]
    fn text_past_the_buffer_is_dropped_rather_than_panicking() {
        let mut line = Line::new();
        for _ in 0..1000 {
            line.text("0123456789");
        }
        assert_eq!(line.len, line.buf.len());
        assert_eq!(text(&line).len(), 384);
    }

    #[test]
    fn the_crash_log_is_created_and_appended_to() {
        let dir = std::env::temp_dir().join("wenle-alloc-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("crash.log");

        // Not `set_crash_log` on the shared statics: this process's reporter
        // may already be pointed somewhere, and a test that repointed it would
        // change what every other test in the binary does. The open-and-append
        // behaviour is what is being checked.
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        assert!(path.exists());
        let _ = opened;

        std::fs::write(&path, b"first\n").unwrap();
        let mut again = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        again.write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_status_is_readable_or_honestly_absent() {
        // Non-Windows answers `None`, and the report says so rather than
        // inventing a figure — so the absence is not a failure and has nothing
        // to assert about it.
        if let Some(status) = memory_status() {
            assert!(
                status.commit_limit > 0,
                "a machine that reports a limit reports a real one"
            );
            assert!(
                status.available_commit <= status.commit_limit,
                "available commit {} must not exceed the limit {}",
                status.available_commit,
                status.commit_limit
            );
            assert!(status.load_percent <= 100);
        }
    }
}
