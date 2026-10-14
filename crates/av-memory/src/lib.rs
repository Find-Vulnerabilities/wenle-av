//! Scanning what a running process is holding, not just what is on disk.
//!
//! # Why this is a separate crate
//!
//! Because almost nothing about it is the same as scanning a file. A file scan
//! is handed a buffer that is the whole of its subject. A memory scan is handed
//! a *process*, has to ask the operating system which of its regions are worth
//! looking at, has to read them one at a time while the process is free to
//! change them underneath, and can be refused at any step by a permission it
//! does not hold. The rules are the same rules and the engine is the same
//! engine: that part is [`av_scan`] and is reused, because a second matcher
//! would be a second set of bugs. Everything around it is different, and the
//! difference is what this crate is.
//!
//! # The two questions a memory scan answers
//!
//! 1. **Is something running that should not be?** A region of committed,
//!    executable memory that is not backed by a file on disk is the shape of
//!    injected code. This is a structural observation, and it is what makes
//!    memory scanning worth doing at all: code that was never written to disk
//!    cannot be caught by a file scan, however good the file scan is.
//! 2. **Does what is in there match a rule?** The regions worth reading are read
//!    and handed to the engine. A match inside a process is attributed to the
//!    process and the address rather than to a path, and
//!    [`av_core::Detection::container`] is the field that already exists for
//!    exactly this kind of attribution: the archive walk uses it for a member
//!    name and this uses it for `process:address`. Reusing it is the point: the
//!    console, the JSON report and the graphical front end all already render
//!    that field, so a memory finding prints correctly without any of them
//!    learning a new shape.
//!
//!    One consumer does learn a field, and it is the one that matters most: when
//!    a finding crosses the service's pipe it arrives as an
//!    `av_ipc::Detection`, where the attribution is carried in `in_process`
//!    rather than in `container`. That is a decision: a client renders the path
//!    as "the file that was found" and needs a second field to say "and this is
//!    where it was running". It is spelled out here because this crate does
//!    not depend on `av-ipc` and so cannot link to the field it is describing.
//!
//! And a third question follows from the second, because a finding nobody can
//! act on is a log line: **which file on disk put those bytes there?** For
//! injected code the answer is "none", and that is the finding. For an image
//! mapped from a file the answer is a path, and that path is what has to be
//! dealt with: a process killed today runs the same file again tomorrow.
//! [`provenance`] answers it, and every [`scan::MemoryFinding`] carries the
//! answer.
//!
//! # The honest limits, stated here rather than discovered later
//!
//! Reading another process's memory requires `PROCESS_VM_READ`, which an
//! ordinary user does not have for a process owned by another user, and which
//! protected processes refuse to anybody. A memory scan is therefore **not** a
//! complete view of the machine and must never be reported as one: a region that
//! could not be read and a region that was read and held nothing are different
//! answers, and the report type keeps them apart rather than collapsing both
//! into "clean".
//!
//! Reading a region is also not atomic. It can be freed, re-protected or
//! rewritten between the query that found it and the read that fetches it. That
//! is not a reason not to scan; it is a reason for the report to say when a read
//! failed rather than to treat the failure as an absence.
//!
//! # The shape
//!
//! Three concerns, and they are worth separating because only the first is
//! platform-specific: enumerating processes, deciding which regions are worth
//! reading, and handing a region's bytes to [`av_scan`]. The second and third
//! are ordinary logic that can be tested without a live process, which is where
//! most of the tests are; the first is Win32 calls behind a trait so that the
//! tests can supply a fake instead of a machine.
//!
//! | Module | What it is |
//! |--------|------------|
//! | [`error`] | Every way a scan can be refused, and what each one means for the report |
//! | [`process`] | Listing the processes on the machine, and the string a finding is attributed to |
//! | [`provenance`] | Which file on disk the bytes in a region came from, which is what makes a finding actionable |
//! | [`region`] | The decision about one region, as a pure function |
//! | [`source`] | Where regions and bytes come from: a trait, a Win32 implementation, and a fake |
//! | [`scan`] | The driver, the per-process outcome, and the report |
//!
//! # The measured shape of a real machine
//!
//! Every number below came out of the Windows machine this crate was written
//! on, and every one of them is reproducible: they are printed by
//! [`scan`]'s live tests, which scan this machine's own processes when run with
//! `cargo test -p av-memory -- --ignored --nocapture`. Each is repeated in the
//! doc comment of the code that depends on it. Together they say what a memory
//! scan costs and what it can honestly claim:
//!
//! * Across six runs of the census test in one afternoon this machine listed
//!   **270 to 296** processes, of which **115 to 136** could be opened for
//!   reading and **151 to 155** could not, every refusal `ERROR_ACCESS_DENIED`,
//!   with 0 to 8 gone before they were reached. So a whole-machine memory scan
//!   sees **under half** of what is running, and the report's refusal counts are
//!   not a formality: they are the larger part of the answer. This is the
//!   number that shaped the whole report type: a scan that could not say "152
//!   processes were not looked at" would be a scan that called this machine
//!   clean. (The spread is the machine's load and not the scanner's behaviour:
//!   four other agents were building in this workspace throughout, so the
//!   process count moved by twenty-six between runs. The ratio did not: it was a
//!   refusal for a bit over half of everything running, every single time, and
//!   that ratio is what the report is built to carry.)
//! * That machine's whole address space was 190,000 to 205,000 regions, of
//!   which the predicate judged **319 to 329** worth reading (0.16% to 0.17%, in
//!   every run) and reading those cost between 54 and 77 megabytes. That is
//!   the trade the predicate makes: it discards more than 99.8% of the address
//!   space so that the reading is bounded by what is anomalous rather than by
//!   how much memory is installed. The predicate does not scale with the machine:
//!   a hundred thousand more regions of ordinary memory added about ten
//!   interesting ones, which is what a structural decision looks like and what a
//!   tuned threshold would not.
//! * A complete walk of one process's address space ends at `0x7fffffff0000`
//!   with `ERROR_INVALID_PARAMETER`, which is the only way the API says "there
//!   is nothing above here". A walk that ends any other way is a partial
//!   picture, and [`scan::ProcessOutcome::walk_complete`] records which.
//! * `explorer.exe` held between 4,527 and 4,634 committed regions, and in
//!   **every one of the six runs** the predicate judged exactly **22** of them
//!   worth reading, holding exactly **290,816** bytes, 0.5% of the process.
//!   Nothing else in this list was that stable, and the reason is worth stating:
//!   the processes are alive while they are measured. Explorer's guard-page count
//!   ran between 99 and 113, and its region count moved by a hundred, across the
//!   same six runs, because a running process grows stacks and commits heaps as
//!   it works. Every counter here that describes *what was read* moved; the
//!   interesting ones did not, because injected code does not appear and vanish
//!   between scans the way a stack does.
//! * A guard page can read as fully accessible in its protection word and still
//!   be the one region that must not be touched, which is why it is checked
//!   before anything else, and there are a hundred or so of them in one
//!   ordinary process, so the check is doing real work rather than guarding
//!   against a hypothetical.
//! * The other four processes scanned alongside explorer (this test binary,
//!   `sihost.exe`, `ipf_helper.exe`, `GameInputRedistService.exe`) had **zero**
//!   interesting regions between them, in every run. That is the ordinary answer
//!   on a healthy machine, and the reason a memory scan has to be cheap: the
//!   common case is that it finds nothing, so the work it does has to be
//!   affordable when it finds nothing.
//!
//! # What a caller does with it
//!
//! ```no_run
//! use av_memory::{MemoryScanConfig, MemoryScanner, Win32Source};
//!
//! # fn main() -> av_memory::Result<()> {
//! // A caller brings its own rule set; an empty one is enough to show the shape.
//! let database = av_rules::database::RuleDatabase::compile_or_warn("");
//! let engine = av_scan::ScanEngine::new(database);
//! let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
//! let mut source = Win32Source::current()?;
//! let scan = scanner.scan_process(&mut source);
//! let mut report = av_memory::MemoryScanReport::new();
//! report.record(scan);
//! let summary = report.summary();
//! if !summary.is_complete() {
//!     for gap in summary.gaps() {
//!         eprintln!("not examined: {gap}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
// Every way of reading another process's memory is an unsafe Win32 call, so the
// rule here is not "no unsafe" but "every unsafe block states what makes it
// sound" — the process handle is open, the address was just reported as
// committed by a query on that same handle, and the buffer is sized by the
// value that query returned.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod process;
pub mod provenance;
pub mod region;
pub mod scan;
pub mod source;

pub use error::{MemoryError, Result};
pub use process::{current_pid, identify, list_processes, ProcessRef};
pub use provenance::{DosDevices, Module, Origin};
pub use region::{
    classify, Access, Interest, MemoryRegion, Protection, RegionBytes, RegionInterest, RegionKind,
    RegionRead, RegionState, Skip,
};
pub use scan::{
    attribute, memory_scan_options, MemoryFinding, MemoryScanConfig, MemoryScanReport,
    MemoryScanner, MemorySummary, ProcessOutcome, ProcessScan, RefusalReason, SkipTally,
    UnreadableRegion, UnreadableRegionList, MAX_UNREADABLE_LISTED,
};
#[cfg(windows)]
pub use source::Win32Source;
pub use source::{MemorySource, RegionWalk};
