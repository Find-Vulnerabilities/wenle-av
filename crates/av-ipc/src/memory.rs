//! What a scan of one process's memory produced, as a client sees it.
//!
//! # Why this is not `av_memory::MemoryScanReport`
//!
//! For the same reason [`crate::ScanSummary`] is not `av_core::scan::ScanStats`:
//! the protocol's types are the wire contract, they are `Deserialize` as well as
//! `Serialize`, and they are what a client that is not this build has to be able
//! to parse. Handing a client the scanner's own report would make every field of
//! the scanner's internal accounting part of the protocol, and a change to how
//! the scanner counts would be a protocol break. So the report here carries what
//! a client acts on and nothing else, and the conversion from the scanner's
//! report is one function on the service side where the mapping can be tested.
//!
//! # What a client has to be able to tell apart
//!
//! Three facts, and a summary that collapsed them would be worse than no summary:
//!
//! * **The scan happened and found nothing.** The ordinary answer on a healthy
//!   machine — measured at zero interesting regions across four of five ordinary
//!   processes on this machine, in every one of six runs.
//! * **The scan could not look.** A process owned by another account, or a
//!   protected one, refuses `PROCESS_VM_READ`. Measured at over half of
//!   everything running on this machine. [`MemoryReport::refused`] is that, and
//!   it is not the same answer as "clean".
//! * **The scan looked at less than the whole address space.** A walk that
//!   stopped at the region or byte budget, or a read that failed partway.
//!   [`MemoryReport::is_complete`] is that.
//!
//! A report that said only "0 findings" would be claiming the first in all three
//! cases, which is the exact failure mode this crate's types exist to prevent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::detect::Detection;

/// How much of the process was looked at.
///
/// Every number here is a count of something that was *reached*, and the ones
/// that matter are the ones that were not: see [`MemoryReport::is_complete`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCoverage {
    /// Regions of the address space the walk produced.
    pub regions_walked: u64,
    /// Regions the predicate judged worth reading.
    pub regions_examined: u64,
    /// Bytes actually read out of the process and handed to the engine.
    pub bytes_read: u64,
    /// Regions that were worth reading and could not be.
    ///
    /// A nonzero value here is not a detail: each one is a place the scanner
    /// looked away from, and a report that listed only the regions it managed
    /// to read would present a partial scan as a whole one.
    pub regions_unreadable: u64,
    /// Regions the predicate kept but the byte budget stopped it reading.
    pub regions_over_budget: u64,
}

impl MemoryCoverage {
    /// True when the whole address space was looked at, within the budgets.
    ///
    /// False when the walk stopped early, when a region worth reading could not
    /// be, or when the byte budget ran out. The three are different reasons and
    /// [`MemoryReport::incomplete_reason`] names the one that applies; what this
    /// answers is the single question a client asks first.
    pub const fn is_complete(&self) -> bool {
        self.regions_unreadable == 0 && self.regions_over_budget == 0
    }
}

/// What one process's memory scan produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryReport {
    /// The process identifier that was scanned.
    pub pid: u32,
    /// The process, spelled the way [`crate::Detection::in_process`] spells it.
    ///
    /// The image name, the PID and the path when it could be read, so that a
    /// report says which process without the client having to open anything.
    pub process: String,
    /// Every finding, each already carrying what was done about it.
    ///
    /// The action is on the detection rather than beside it, because a list of
    /// findings and a list of actions that have to stay in step is two lists
    /// that can disagree.
    pub findings: Vec<Detection>,
    /// How much of the process was looked at.
    pub coverage: MemoryCoverage,
    /// True when the walk of the address space reached its end.
    ///
    /// Separate from [`MemoryCoverage::is_complete`], and the difference is
    /// real: a walk that reached the end of a process whose bytes were then only
    /// partly read is complete as a walk and incomplete as a scan. Both are
    /// reported because both are true.
    pub walk_complete: bool,
    /// Why the process could not be scanned at all, when it could not.
    ///
    /// `Some` means **no part of this process was examined** and `findings` is
    /// empty. A client that read the empty list as "clean" would be reporting a
    /// refusal as an all-clear, which is the single worst thing a scan report
    /// can do.
    pub refused: Option<String>,
    /// How many files the findings led to being taken into the vault.
    ///
    /// Carried as well as being derivable from `findings`, because it is the
    /// number a user is shown, and because a `u32` on a summary line is not the
    /// same claim as a filter over a list a client may have truncated.
    pub files_taken: u32,
    /// How many findings pointed at a file that was examined and left alone.
    pub files_left: u32,
    /// How many findings had no file behind them at all.
    ///
    /// The injected-code count. Every one of these is a region whose bytes no
    /// file on disk holds, which is a finding in its own right and not a failure
    /// to find the file.
    pub without_a_file: u32,
    /// When the scan ran.
    pub at: DateTime<Utc>,
}

impl MemoryReport {
    /// True when the whole process was looked at.
    pub fn is_complete(&self) -> bool {
        self.refused.is_none() && self.walk_complete && self.coverage.is_complete()
    }

    /// What was not examined, in a sentence, or `None` when everything was.
    ///
    /// Takes no arguments and returns an owned `String` rather than borrowing,
    /// following `av_memory`'s own `gaps`: the sentence is built from several
    /// facts and there is no one field to point at.
    pub fn incomplete_reason(&self) -> Option<String> {
        if let Some(reason) = &self.refused {
            return Some(format!("the process was not examined: {reason}"));
        }
        if !self.walk_complete {
            return Some(
                "the walk of the address space stopped before the end, so regions above where it \
                 stopped were never considered"
                    .to_string(),
            );
        }
        if self.coverage.regions_unreadable > 0 {
            return Some(format!(
                "{} region(s) worth reading could not be read, so what they hold was not examined",
                self.coverage.regions_unreadable
            ));
        }
        if self.coverage.regions_over_budget > 0 {
            return Some(format!(
                "{} region(s) were past the byte budget for one process and were not read",
                self.coverage.regions_over_budget
            ));
        }
        None
    }
}
