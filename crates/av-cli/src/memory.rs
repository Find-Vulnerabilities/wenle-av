//! Examining the memory of running processes, and reporting it.
//!
//! # Why this is not part of the file report
//!
//! A memory finding is about a *process*, not a file. Its subject is
//! `explorer.exe:0x7ff6a1b20000` — a name and an address — and there is no path
//! on disk that holds those bytes, which is the entire reason they were read:
//! nothing on disk holds them. Printing one in the file table would need either
//! a fake path (a lie a support engineer would chase) or a column of process
//! names under a heading that says "path" (a lie of shape rather than of content,
//! which is worse because nothing about the line looks wrong).
//!
//! So they get their own section in the text report and their own array in
//! `--json`, and the two are joined only where they must be: the exit code, and
//! the band counts in the result summary. A consumer reading the JSON can hand
//! the `findings` array to the code that already understands [`FileScanReport`]
//! and the `memory.findings` array to code that understands a process, and
//! neither has to filter the other out.
//!
//! # Why the printer is here and not in [`crate::output`]
//!
//! `output`'s unit is one finding about one path, and every decision it makes —
//! the member name before the offset, the path on the first line — follows from
//! that. A memory finding has no member and no path, shares only the verdict
//! word with it (which `output` still owns, and this module calls), and would
//! have to bend every one of those decisions. Keeping the second printer beside
//! the code that produces its input keeps the av-memory dependency in one file.
//!
//! # Why the region, and not the process, is the unit of a finding
//!
//! A rule matched a byte pattern somewhere in a region of memory. The process is
//! where it was, the region is *what* was matched, and the two together are what
//! a person needs to go and look. `av_memory::MemoryFinding` is that pair, and
//! this module reports it without collapsing either half — including the shape
//! of the region, because "executable, readable and private to the process" is
//! the reason it was read at all and "image" (a file on disk, loaded) is the
//! reason a different region was not.

use std::time::Duration;

use av_core::{AvPaths, Detection, FileScanReport, ScanOptions, Verdict};
use av_memory::{
    current_pid, list_processes, MemoryFinding, MemoryScanConfig, MemoryScanReport, MemoryScanner,
    Origin as BytesFrom, ProcessRef,
};
use av_quarantine::{EntrySource, QuarantineContext, QuarantineId, QuarantineVault};
use av_scan::ScanEngine;
use av_service::memory as chain;
use console::style;

use crate::output;
use crate::progress::{human_bytes, human_count};

/// What a `--memory` run produced, or why it produced nothing.
///
/// The two cases are different answers and the report says different things for
/// each. A scan that never ran is not a scan that found nothing, and the only
/// way to keep them apart is for the type they arrive in to keep them apart.
#[derive(Debug)]
enum Outcome {
    /// Every process the scan was allowed to examine was offered to it.
    Scanned(Box<MemoryScanReport>),
    /// The scan could not begin at all.
    Unavailable(String),
}

/// The memory half of a scan.
#[derive(Debug)]
pub struct MemoryReport {
    /// The process the scan ran in, which is never examined. See
    /// [`scan_machine`].
    own_pid: u32,
    outcome: Outcome,
}

impl MemoryReport {
    /// A report from a scan that already ran.
    ///
    /// Exists for callers that own their own `MemorySource` — a test driving a
    /// scripted one, or a caller scanning a single process it has already
    /// opened — so that the report they produce is printed and counted by
    /// exactly the code that prints and counts a whole-machine scan.
    pub fn from_report(own_pid: u32, report: MemoryScanReport) -> Self {
        Self {
            own_pid,
            outcome: Outcome::Scanned(Box::new(report)),
        }
    }

    /// A scan that could not run, and why.
    pub fn unavailable(own_pid: u32, reason: String) -> Self {
        Self {
            own_pid,
            outcome: Outcome::Unavailable(reason),
        }
    }

    /// The verdict this scan contributes to the run.
    ///
    /// # Why an incomplete scan is never `Clean`
    ///
    /// `Unknown` is the verdict for "the engine did not judge this", and it is
    /// what a scan that could not open half the processes on the machine has
    /// earned. Reporting `Clean` there would be the one failure a memory report
    /// cannot recover from: a user who reads "clean" and closes the window has
    /// been told the machine is well when what happened is that the product
    /// could not look. `Unknown` maps to exit code 2 — "the scan could not be
    /// completed" — which is the truth, and it is deliberately the same code an
    /// unreadable file produces, because it is the same fact.
    ///
    /// A detection outranks the gap in both directions. "There is malware in a
    /// running process" is the more urgent of the two things a caller needs to
    /// know, and a report that answered "could not complete" instead would bury
    /// it.
    pub fn verdict(&self) -> Verdict {
        match &self.outcome {
            Outcome::Unavailable(_) => Verdict::Unknown,
            Outcome::Scanned(report) => {
                let summary = report.summary();
                match summary.verdict() {
                    Verdict::Malicious | Verdict::Suspicious => summary.verdict(),
                    _ if summary.is_complete() => Verdict::Clean,
                    _ => Verdict::Unknown,
                }
            }
        }
    }

    /// Whether the scan examined everything it set out to.
    pub fn is_complete(&self) -> bool {
        match &self.outcome {
            Outcome::Unavailable(_) => false,
            Outcome::Scanned(report) => report.summary().is_complete(),
        }
    }

    /// Every reason the scan cannot claim to have seen everything.
    pub fn gaps(&self) -> Vec<String> {
        match &self.outcome {
            Outcome::Unavailable(reason) => {
                vec![format!("no running process was examined: {reason}")]
            }
            Outcome::Scanned(report) => report.summary().gaps(),
        }
    }

    /// The findings, in process order and then address order.
    pub fn findings(&self) -> Vec<&MemoryFinding> {
        match &self.outcome {
            Outcome::Unavailable(_) => Vec::new(),
            Outcome::Scanned(report) => report.findings().collect(),
        }
    }

    /// How many processes produced at least one finding.
    ///
    /// The number that answers "is this scanner crying wolf". A memory scanner
    /// that reports something in every process is one whose output nobody reads,
    /// and this is the count that says whether that has happened; the report
    /// prints it beside the number of processes examined so that the two can be
    /// compared without arithmetic.
    pub fn processes_with_findings(&self) -> u64 {
        match &self.outcome {
            Outcome::Unavailable(_) => 0,
            Outcome::Scanned(report) => report
                .results
                .iter()
                .filter_map(av_memory::ProcessScan::outcome)
                .filter(|outcome| !outcome.findings.is_empty())
                .count() as u64,
        }
    }

    /// The totals, for the summary and the JSON.
    pub fn summary(&self) -> av_memory::MemorySummary {
        match &self.outcome {
            Outcome::Unavailable(_) => av_memory::MemorySummary::default(),
            Outcome::Scanned(report) => report.summary(),
        }
    }
}

/// What became of the file each memory finding came from.
///
/// # The question this answers
///
/// A finding in a process is a fact about a running program, and killing it
/// would leave the file that started it on disk to run again tomorrow. So the
/// bytes' **origin** is what is dealt with: the file the loader mapped, examined
/// in its own right, and taken into the vault if it is malicious on its own
/// evidence. See [`av_service::memory`] for the decision itself, which is shared
/// with the service rather than written twice — the bar for acting on a file is
/// one rule, and a second implementation of it would be a second answer.
///
/// # Why a memory match does not quarantine the file by itself
///
/// Because a match in memory is not a match in the file. The loader relocates an
/// image as it maps it, so bytes at `libfoo.dll+0x1234` in memory are often not
/// at `0x1234` in the file; a process can patch its own image; and for a region
/// nothing on disk backs, there is no file at all — which is the case memory
/// scanning exists for. Acting on the address alone would quarantine files that
/// do not contain the matched bytes, and one of them would eventually be
/// `ntdll.dll`.
///
/// # Why the examination runs even when nothing may be taken
///
/// Because the answer is worth having either way. "A rule matched in
/// `chrome.exe`, the bytes came from this DLL, and the DLL is itself malicious"
/// is something a user needs to read whether or not this run was allowed to act
/// on it; and a report that said nothing about the file would leave the reader
/// unable to tell a finding that was acted on from one that was ignored. The
/// note under each finding says which of those happened.
#[derive(Debug)]
pub struct Chain {
    entries: Vec<Entry>,
}

/// One finding's origin, and what was done about it.
#[derive(Debug)]
struct Entry {
    action: chain::Action,
    /// The file's own scan, when it was examined.
    report: Option<FileScanReport>,
    /// The vault's answer, once it has been asked. `None` means it has not been.
    taken: Option<Result<QuarantineId, String>>,
}

impl Chain {
    /// Examine the origin of every finding, and decide about each one.
    ///
    /// Examines files and never writes anything: what the vault does is
    /// [`Chain::carry_out`], which is a separate call because the two have
    /// different preconditions. This one needs an engine, and that one needs a
    /// vault that this run may only open if there is something to put in it.
    pub fn build(
        report: &MemoryReport,
        engine: &ScanEngine,
        paths: &AvPaths,
        options: &ScanOptions,
    ) -> Self {
        let findings = report.findings();
        let mut entries = Vec::with_capacity(findings.len());
        for finding in findings {
            let mut report = None;
            let action = chain::decide(&finding.origin, paths, |path| {
                let examined = chain::examine(engine, path, options);
                report = examined.report;
                examined.outcome
            });
            if let BytesFrom::Unknown = finding.origin {
                // Not an error and not a silent skip: the address had no
                // provenance because the region it was in is not one the loader
                // maps, so there was nothing to look for. The note says so.
                log::debug!("{} has no established origin", finding.container());
            }
            entries.push(Entry {
                action,
                report,
                taken: None,
            });
        }
        log::info!(
            "{} memory finding(s): {} file(s) are malicious in their own right",
            entries.len(),
            entries
                .iter()
                .filter(|entry| entry.action.is_take())
                .count()
        );
        Self { entries }
    }

    /// How many files the chain ruled fit to take.
    ///
    /// The number a caller asks before opening a vault: a vault that is opened
    /// and then used for nothing creates a directory and, on a machine that has
    /// never quarantined anything, a master key. Neither belongs to a scan that
    /// had nothing to put in it.
    pub fn to_take(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.action.is_take())
            .count()
    }

    /// Ask the vault for every file the chain ruled fit to take.
    ///
    /// Returns how many ended up in it. One file failing does not stop the rest:
    /// the vault refuses for reasons about that file — it is too large, it is
    /// already there, it is open by another process — and abandoning the
    /// remaining findings because of one would leave malware in place over
    /// something that has nothing to do with it.
    pub fn carry_out(&mut self, vault: &mut QuarantineVault) -> usize {
        let mut quarantined = 0;
        for entry in &mut self.entries {
            let chain::Action::Take { file } = &entry.action else {
                continue;
            };
            let Some(report) = entry.report.as_ref() else {
                // Unreachable: a take is ruled only on a verdict, and a verdict
                // only comes back with the report it came from. Recorded as a
                // failure rather than an assertion, because a panic here would
                // abandon the files after this one.
                entry.taken = Some(Err(
                    "the file's own scan report was lost before it could be taken".to_string(),
                ));
                continue;
            };
            let context = QuarantineContext::from_report(report, EntrySource::Memory).with_note(
                format!("found running in memory, at {}", report.path.display()),
            );
            entry.taken = Some(match vault.quarantine_file(file, &context) {
                Ok(entry) => {
                    quarantined += 1;
                    Ok(entry.id)
                }
                Err(error) => Err(error.to_string()),
            });
        }
        quarantined
    }

    /// How many files are in the vault because of this run.
    pub fn quarantined(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.taken, Some(Ok(_))))
            .count()
    }

    /// The line to print under the finding at `index`, if there is one.
    ///
    /// Indexed rather than keyed, because the findings and these entries are
    /// built from one iteration of one list and are the same length by
    /// construction. An index past the end returns `None` instead of panicking:
    /// a report that crashed while printing would lose the findings that had not
    /// been printed yet, which are the ones a user most needs.
    pub fn note(&self, index: usize) -> Option<String> {
        let entry = self.entries.get(index)?;
        let text = match &entry.action {
            chain::Action::Take { file } => match &entry.taken {
                Some(Ok(id)) => format!("quarantined as {}", id.short()),
                Some(Err(reason)) => format!("could not be quarantined: {reason}"),
                // Ruled fit to take and the vault was never asked, which is
                // what a run without `--quarantine` does. Said plainly, because
                // the alternative is a report that looks as if the product had
                // dealt with it.
                None => format!(
                    "{} is malicious in its own right ({}), and nothing was taken: this run was \
                     not asked to quarantine anything. `--quarantine` takes it.",
                    file.display(),
                    report_verdict(entry.report.as_ref()),
                ),
            },
            chain::Action::Leave { .. } => entry.action.describe(),
        };
        Some(text)
    }

    /// The chain's answers, for the JSON report.
    pub fn json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.entries
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "subject": entry.action.file().map(|path| path.display().to_string()),
                        "verdict": entry.report.as_ref().map(|report| report.verdict().as_str()),
                        "reason": match &entry.action {
                            chain::Action::Take { .. } => "take",
                            chain::Action::Leave { why, .. } => left_name(why),
                        },
                        "detail": entry.action.describe(),
                        "quarantined": match &entry.taken {
                            Some(Ok(id)) => serde_json::json!(id.short()),
                            _ => serde_json::Value::Null,
                        },
                        "error": match &entry.taken {
                            Some(Err(reason)) => serde_json::json!(reason),
                            _ => serde_json::Value::Null,
                        },
                    })
                })
                .collect(),
        )
    }
}

/// The verdict of a file that was examined, as a word, for a sentence.
///
/// `Unreadable` when there is no report at all, which cannot happen for a take
/// — see [`Chain::carry_out`] — but which has to have an answer that is not a
/// panic and not the word "clean".
fn report_verdict(report: Option<&FileScanReport>) -> &'static str {
    match report {
        Some(report) => report.verdict().as_str(),
        None => "unexamined",
    }
}

/// The name of a [`chain::Left`], for the JSON.
///
/// Written out rather than derived from `Debug`, so that a machine reading the
/// report sees the same words every time and a variant renamed in `av-service`
/// does not silently change this document.
fn left_name(why: &chain::Left) -> &'static str {
    match why {
        chain::Left::NotMalicious { .. } => "not-malicious",
        chain::Left::Unreadable { .. } => "unreadable",
        chain::Left::Gone => "gone",
        chain::Left::OwnTree => "own-tree",
        chain::Left::NoFile => "no-file",
        chain::Left::Unestablished => "unestablished",
    }
}

/// Examine one process's memory.
///
/// The single-process form of [`scan_machine`], for a caller that already knows
/// which process it is asking about — a PID from a detection, from the driver,
/// or from a user who has just watched something misbehave.
///
/// # Why asking for this process by name is refused
///
/// [`scan_machine`] never examines its own process, and the reason is not
/// tidiness: the address space of the process running the scan holds the rule
/// database, the text of every rule compiled into it, and — in a test binary —
/// every marker string the fixtures were built around. Reading it would match
/// the rules against themselves and report the product as infected with whatever
/// it can detect. An explicit `--pid` does not change any of that, so a request
/// for this process's own PID is answered with the reason rather than with a
/// scan whose findings would be artifacts of the questioner.
pub fn scan_one(engine: &ScanEngine, pid: u32, config: MemoryScanConfig) -> MemoryReport {
    let own_pid = current_pid();
    if pid == own_pid {
        return MemoryReport::unavailable(
            own_pid,
            format!(
                "PID {pid} is the process running this scan. Its memory holds the rule database \
                 and the text of every rule in it, so examining it would match the rules against \
                 themselves and report this product as infected with whatever it can detect. \
                 Nothing was examined."
            ),
        );
    }
    if pid == 0 {
        // The idle process: no address space, no image, no thread. Windows
        // answers an attempt to open it with the same "no such process" error it
        // uses for a PID that was never allocated, and that answer would send
        // someone looking for a bug in the process list.
        return MemoryReport::unavailable(
            own_pid,
            "PID 0 is the idle process: it has no address space to scan and no image to name"
                .to_string(),
        );
    }
    match examine_one(engine, pid, config) {
        Ok(report) => MemoryReport::from_report(own_pid, report),
        Err(reason) => MemoryReport::unavailable(own_pid, reason),
    }
}

/// One process, opened and walked, or why not.
#[cfg(windows)]
fn examine_one(
    engine: &ScanEngine,
    pid: u32,
    config: MemoryScanConfig,
) -> Result<MemoryScanReport, String> {
    let process = av_memory::identify(pid);
    // A handle that will not open is reported as what it is. It is *not* turned
    // into a report with no findings: an empty finding list is the same value a
    // process with nothing in it produces, and a caller would read the two the
    // same way.
    let mut source = av_memory::Win32Source::open(process).map_err(|error| error.to_string())?;
    let mut report = MemoryScanReport::new();
    report.record(MemoryScanner::new(engine, config).scan_process(&mut source));
    Ok(report)
}

/// There is no process list on a platform this build cannot read memory on, and
/// no single process to open either.
#[cfg(not(windows))]
fn examine_one(
    _engine: &ScanEngine,
    _pid: u32,
    _config: MemoryScanConfig,
) -> Result<MemoryScanReport, String> {
    Err("this platform has no way to read another process's memory".to_string())
}

/// Run a whole-machine memory scan.
///
/// # Why the process running the scan is not examined
///
/// It is the one process whose contents the scanner already knows, and they are
/// the contents of a scanner: the rule database, the text of the rules that were
/// compiled into it, and every marker string a test binary was built around all
/// live in this process's address space. Reading it would match the rules
/// against themselves and report the product as infected with whatever it can
/// detect — and a test that planted a marker would find that marker by reading
/// its own heap rather than the process it meant to test. Both are false
/// positives of the purest kind, and the fix is not to look.
///
/// The exclusion is stated in the report rather than made silently: a user who
/// asked for "every running process" is owed the number of processes that means.
///
/// # Why the scan is sequential
///
/// `MemoryScanner::scan_processes` walks processes one after another, and the
/// work in each is kernel calls — open, walk, read — that a second thread would
/// contend on rather than overlap. The file scan next to it is parallel because
/// its work is CPU; this is not, and pretending otherwise would buy a longer
/// wall clock on a shared machine and a worse one on a quiet one.
pub fn scan_machine(engine: &ScanEngine, config: MemoryScanConfig) -> MemoryReport {
    let own_pid = current_pid();
    match examine(engine, config, own_pid) {
        Ok(report) => MemoryReport::from_report(own_pid, report),
        Err(reason) => MemoryReport::unavailable(own_pid, reason),
    }
}

/// The processes of this machine, minus the one asking, or why not.
#[cfg(windows)]
fn examine(
    engine: &ScanEngine,
    config: MemoryScanConfig,
    own_pid: u32,
) -> Result<MemoryScanReport, String> {
    let processes = list_processes().map_err(|error| error.to_string())?;
    let seen = processes.len();
    let targets: Vec<ProcessRef> = processes
        .into_iter()
        .filter(|process| process.pid != own_pid)
        .collect();
    log::info!(
        "memory scan: {} processes enumerated, {} to examine (this process, {own_pid}, is not \
         one of them)",
        seen,
        targets.len()
    );
    Ok(MemoryScanner::new(engine, config).scan_processes(&targets))
}

/// Memory scanning needs a process list, and a process list needs an operating
/// system that has one.
///
/// Not a `#[cfg]`-less fallback to an empty report: an empty report is the same
/// value as a machine with nothing running, and the caller would print a clean
/// answer for a scan that never happened.
#[cfg(not(windows))]
fn examine(
    _engine: &ScanEngine,
    _config: MemoryScanConfig,
    _own_pid: u32,
) -> Result<MemoryScanReport, String> {
    Err("this platform has no process list to walk, so no memory was examined".to_string())
}

/// The memory section of the report, for a person.
///
/// # What is printed under which flag
///
/// The findings are the answer and are printed always — `--quiet` suppresses the
/// running commentary and the totals, never the thing the user asked for. The
/// totals and the gaps are commentary in exactly the sense `--quiet` means, and
/// are skipped with it, which is also what the file side does with its
/// unreadable-file warnings: a caller who asked for silence gets findings and
/// errors, and is expected to read the exit code for the shape of the rest.
///
/// # Why the refusals are one line and not two hundred
///
/// A whole-machine scan on this machine cannot open 151 to 155 of about 280
/// processes — measured; Windows refuses a handle to anything running as another
/// account or protected as a system process. Printed individually that is a wall
/// of text larger than every other line of the report put together, all of it
/// saying the same thing, and none of it actionable: there is nothing a user can
/// do about a protected process. So the text report gives the count and the
/// reason, and the JSON gives every process by name, because a machine reading it
/// can total them up and a person cannot.
pub fn print_section(report: &MemoryReport, elapsed: Duration, quiet: bool, chain: Option<&Chain>) {
    for line in section_lines(report, elapsed, quiet, chain) {
        println!("{line}");
    }
    // The gaps go to standard error with the other warnings, so that a report
    // redirected to a file does not have to be read for the holes in it as well
    // as for the findings. The one exception is a scan that never ran: its
    // single gap is its entire section and is already above.
    if !quiet && matches!(report.outcome, Outcome::Scanned(_)) {
        for gap in report.gaps() {
            output::warn(&gap);
        }
    }
}

/// The memory section, as the lines a person reads.
///
/// A function returning lines rather than one printing them, so that what a user
/// sees can be asserted by a test: `println!` cannot be captured from inside the
/// process that wrote it, and a section whose exact text nobody can check is a
/// section that drifts. [`print_section`] is then three lines long and decides
/// nothing.
///
/// # Why the refusals are one line and not two hundred
///
/// A whole-machine scan on this machine cannot open 151 to 155 of about 280
/// processes — measured; Windows refuses a handle to anything running as another
/// account or protected as a system process. Printed individually that is a wall
/// of text larger than every other line of the report put together, all of it
/// saying the same thing, and none of it actionable: there is nothing a user can
/// do about a protected process. So the text report gives the count, the reasons
/// and the totals, and the JSON gives every process by name, because a machine
/// reading it can total them up and a person cannot.
pub fn section_lines(
    report: &MemoryReport,
    elapsed: Duration,
    quiet: bool,
    chain: Option<&Chain>,
) -> Vec<String> {
    let findings = report.findings();
    if quiet && findings.is_empty() && report.is_complete() {
        // Nothing to report and no licence to say it.
        return Vec::new();
    }
    let mut lines = vec![output::heading_line("Process memory")];

    if let Outcome::Unavailable(reason) = &report.outcome {
        // Printed even under `--quiet`: this is not commentary about a scan, it
        // is the reason there is no answer, which is the class of message
        // `--quiet` keeps.
        lines.push(format!("  No running process was examined: {reason}."));
        return lines;
    }

    for (index, finding) in findings.iter().enumerate() {
        lines.extend(finding_lines(finding));
        // What became of the file the bytes came from, on the finding's own
        // lines rather than in a list of its own: the user reading the finding
        // is the one asking what happened to it, and two lists would have to be
        // matched up by hand. Printed under `--quiet` as well — an action taken
        // on the machine is not commentary about the scan.
        if let Some(note) = chain.and_then(|chain| chain.note(index)) {
            lines.push(format!("              {note}"));
        }
    }
    if quiet {
        return lines;
    }

    let summary = report.summary();
    if findings.is_empty() {
        lines.push(if report.is_complete() {
            style("  Nothing was found in any process's memory.")
                .green()
                .bold()
                .to_string()
        } else {
            style(
                "  Nothing was found, but the scan could not examine every process it was \
                 given.",
            )
            .magenta()
            .to_string()
        });
    }

    // The totals, in the order the questions are asked: how much of the machine
    // was looked at, then what was looked at, then what was found.
    lines.push(format!(
        "  {} process(es) examined, {} refused, {} had already ended (this process, {}, is not \
         one of them)",
        human_count(summary.processes_examined),
        human_count(summary.processes_refused()),
        human_count(summary.processes_gone()),
        report.own_pid,
    ));
    lines.push(format!(
        "  {} region(s) walked, {} worth reading, {} read ({}) in {:.1}s",
        human_count(summary.regions_seen),
        human_count(summary.regions_interesting),
        human_count(summary.regions_read),
        human_bytes(summary.bytes_read),
        elapsed.as_secs_f64(),
    ));
    let found = report.processes_with_findings();
    if found > 0 {
        // Said as a fraction of what was examined, because that ratio is the
        // only thing that distinguishes "this scanner has a lead" from "this
        // scanner flags every process on the machine".
        lines.push(format!(
            "  {} of the {} process(es) examined produced a finding",
            human_count(found),
            human_count(summary.processes_examined),
        ));
    }
    // And what the findings led to. The count of what was *taken* is separated
    // from the count of findings because the two are different answers: a
    // finding whose bytes came from nowhere on disk has no file to take, and a
    // finding in a process running an innocuous file leaves that file alone.
    // A single "N findings" line would read as if N things had been dealt with.
    if let Some(chain) = chain {
        if !findings.is_empty() {
            lines.push(format!(
                "  {} of these findings took a file into the vault; the line under each finding \
                 says what became of the rest",
                human_count(chain.quarantined() as u64),
            ));
        }
    }
    lines
}

/// One memory finding, laid out like a file finding so the two sections read as
/// one report.
///
/// ```text
///   suspicious  explorer.exe:0x7ff6a1b20000
///               the marker this test planted
///               score 60 — 1 detection
///               unbacked-executable  r-x  private  82 bytes
///               0x0 (18 bytes)  cli_memory_marker  a marker this test planted
/// ```
///
/// The lines come from [`output::finding_lines`], which is the same printer the
/// file findings use — the verdict word, the indent and the offset line are one
/// decision in one place. What this function adds is the shape of the region, as
/// the `note` that printer takes: `unbacked-executable` means nothing on disk
/// holds these bytes, `image` means something does, and a user deciding what to
/// do about a finding needs to know which of those they are looking at. The size
/// is the region's, and a truncated read says how much of it was actually read —
/// otherwise the byte count would claim to describe bytes nobody looked at.
fn finding_lines(finding: &MemoryFinding) -> Vec<String> {
    let read = if finding.truncated {
        format!(", {} read", human_count(finding.bytes_read as u64))
    } else {
        String::new()
    };
    let shape = format!(
        "{}  {}  {}  {} bytes{}",
        finding.interest.as_str(),
        finding.protection.describe(),
        finding.kind.as_str(),
        human_count(finding.region_size as u64),
        read,
    );
    let region = finding.container();
    // The detections are shown with the region taken back off their containers.
    // `av_memory::attribute` puts it in front of whatever the detection already
    // carried, so leaving it there would print it a second time — on the offset
    // line, as `explorer.exe:0x7ff6a1b20000:0x0`, which reads as a container
    // nested inside itself. See [`inside`] for what is left when it is removed.
    let detections: Vec<Detection> = finding
        .detections
        .iter()
        .map(|detection| {
            let inner = inside(detection, &region);
            let mut rewritten = detection.clone();
            for location in &mut rewritten.locations {
                location.container = inner.clone();
            }
            rewritten.container = inner;
            rewritten
        })
        .collect();
    output::finding_lines(
        &region,
        finding.verdict,
        finding.score,
        &detections,
        Some(&shape),
    )
}

/// The container of a detection's first location, when it says something the
/// finding's own line does not.
///
/// `av_memory::attribute` puts the region in front of whatever container the
/// detection already had, so a match in a member of an archive a process was
/// holding reads `explorer.exe:0x7ff6a1b20000/payload/inner.exe`. The region is
/// already on the finding's first line; printing it again here would make the
/// offset line half repetition. What is left after removing it is the member
/// name, and that is exactly what a reader needs, because the offset under it is
/// an offset into the member and not into the region.
fn inside(detection: &Detection, region: &str) -> Option<String> {
    let container = detection
        .locations
        .first()
        .and_then(|location| location.container.as_deref())?;
    if container == region {
        return None;
    }
    match container.strip_prefix(region) {
        Some(rest) => {
            let stripped = rest.trim_start_matches('/');
            if stripped.is_empty() {
                None
            } else {
                Some(stripped.to_string())
            }
        }
        // Not the region at all. A caller built this detection by hand rather
        // than through `attribute`, and its container is all the information
        // there is, so it is shown as it stands.
        None => Some(container.to_string()),
    }
}

/// The memory half of the JSON report.
///
/// # Why every refused process is listed here and not in the text
///
/// Because a machine reading this can do what a person cannot: total up two
/// hundred refusals by reason, watch the rate across runs, and tell a machine
/// where half the processes are unreadable from one where none are. The list is
/// the honest record of what was skipped, and the reason is carried per process
/// rather than as a count so that "Windows refused a handle to `lsass.exe`" is
/// answerable without guessing which of six reasons it was.
///
/// # Why the findings are the library's own serialisation
///
/// [`MemoryFinding`] is serialised unchanged, the way a [`FileScanReport`] is in
/// the file half: a field added to the finding appears here without anyone
/// remembering to add it, and a consumer gets the same type the library's own
/// tests are written against.
///
/// [`FileScanReport`]: av_core::FileScanReport
pub fn json(report: &MemoryReport, elapsed: Duration, chain: Option<&Chain>) -> serde_json::Value {
    let summary = report.summary();
    let mut document = serde_json::json!({
        "ran": matches!(report.outcome, Outcome::Scanned(_)),
        "complete": report.is_complete(),
        "verdict": report.verdict().as_str(),
        "own_pid": report.own_pid,
        "own_process_examined": false,
        "duration_ms": elapsed.as_millis() as u64,
        "gaps": report.gaps(),
        "summary": summary,
        "findings": report.findings(),
        // What each finding led to, in the same order as `findings`, so that a
        // consumer can read the two arrays together. Null when the chain did not
        // run at all — which is a different answer from an empty array, and the
        // one a consumer would otherwise have to guess.
        "handling": match chain {
            Some(chain) => chain.json(),
            None => serde_json::Value::Null,
        },
        "files_quarantined": chain.map(Chain::quarantined).unwrap_or(0),
    });

    match &report.outcome {
        Outcome::Unavailable(reason) => {
            document["detail"] = serde_json::json!(reason);
        }
        Outcome::Scanned(scanned) => {
            document["skipped"] = serde_json::json!(scanned
                .results
                .iter()
                .filter_map(|result| {
                    let reason = result.refusal()?;
                    let process = result.process();
                    Some(serde_json::json!({
                        "pid": process.pid,
                        "label": process.label(),
                        "image": process.image,
                        "reason": reason.as_str(),
                        "detail": reason.describe(),
                    }))
                })
                .collect::<Vec<_>>());
        }
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{DetectionSource, Severity};
    use av_memory::{MemorySource, ProcessScan, RegionWalk};
    use av_rules::database::RuleDatabase;

    /// The marker every scripted region in these tests is built around.
    const MARKER: &str = "WENLE-CLI-MEMORY-MARKER";

    /// A process reference that is obviously not a real one.
    fn process() -> ProcessRef {
        ProcessRef::new(
            4242,
            Some(std::path::PathBuf::from(r"C:\victim\explorer.exe")),
        )
    }

    /// A source that hands back exactly the regions it was built with.
    ///
    /// The same shape as the fake in av-memory's own tests, written here because
    /// that one is `#[cfg(test)]` inside its crate and does not exist in a
    /// dependency. What it buys is the whole point of the `MemorySource`
    /// abstraction: this file's tests exercise the wiring — report, printing,
    /// JSON, verdict — without opening a real process, so they run on any
    /// machine, in parallel, and without depending on what happens to be running
    /// there.
    struct Scripted {
        process: ProcessRef,
        regions: Vec<av_memory::MemoryRegion>,
        bytes: Vec<u8>,
        /// What the source says backs the regions, for the tests that are about
        /// the chain rather than about the scan. [`av_memory::Origin::Unknown`]
        /// is the trait's own default and the honest answer for a source that
        /// has no way to ask — see `MemorySource::backing_file`.
        backing: av_memory::Origin,
    }

    impl MemorySource for Scripted {
        fn process(&self) -> &ProcessRef {
            &self.process
        }

        fn regions(&mut self, _limit: usize) -> av_memory::Result<RegionWalk> {
            Ok(RegionWalk::complete(self.regions.clone()))
        }

        fn read(&mut self, _base: usize, length: usize) -> av_memory::Result<Vec<u8>> {
            let mut data = self.bytes.clone();
            data.resize(length, 0);
            Ok(data)
        }

        fn backing_file(&self, _base: usize) -> av_memory::Origin {
            self.backing.clone()
        }
    }

    /// The bytes every scripted region holds: the marker, then padding.
    fn marked_bytes() -> Vec<u8> {
        [MARKER.as_bytes(), &[0u8; 64]].concat()
    }

    /// One committed, executable, private region holding the marker.
    fn scripted() -> Scripted {
        // A region big enough to be interesting, holding the marker at the front
        // of the buffer the engine will be given.
        let bytes = marked_bytes();
        Scripted {
            process: process(),
            regions: vec![av_memory::MemoryRegion {
                base: 0x7ff6_a1b2_0000,
                size: bytes.len(),
                state: av_memory::RegionState::Committed,
                // `PAGE_EXECUTE_READ`. The shape the scan exists for: private to
                // the process, executable, and readable.
                protection: av_memory::Protection::from_raw(0x20),
                kind: av_memory::RegionKind::Private,
            }],
            bytes,
            backing: av_memory::Origin::Unknown,
        }
    }

    /// An engine with one rule that matches [`MARKER`].
    ///
    /// The rule names no severity, which is deliberate: the default is
    /// [`Severity::Medium`], worth 60, and the default thresholds call 30
    /// suspicious and 100 malicious — so the fixture lands in the yellow band,
    /// which is where a rule like this one belongs. A test that wants red says
    /// so; see [`malicious_engine`].
    fn engine() -> ScanEngine {
        engine_from(&format!(
            "rule cli_memory_marker {{\n  strings:\n    $a = \"{MARKER}\"\n  condition:\n    $a\n}}"
        ))
    }

    /// The same rule, claiming enough to be malicious on its own.
    fn malicious_engine() -> ScanEngine {
        engine_from(&format!(
            "rule cli_memory_marker {{\n  meta:\n    severity = \"critical\"\n  strings:\n    \
             $a = \"{MARKER}\"\n  condition:\n    $a\n}}"
        ))
    }

    fn engine_from(source: &str) -> ScanEngine {
        let (database, report) = RuleDatabase::compile(source);
        assert_eq!(report.refusals.len(), 0, "the fixture rule must compile");
        assert_eq!(
            database.len(),
            1,
            "the fixture rule must be in the database"
        );
        ScanEngine::new(database)
    }

    /// A report built from one scripted process, under a named engine.
    ///
    /// The chain's tests need the engine that produced the finding to be the one
    /// that examines the file, which is why this takes it: a report built with
    /// one rule set and examined with another would be a shape no run produces.
    fn report_from_engine(engine: &ScanEngine, source: &mut Scripted) -> MemoryReport {
        let scanner = MemoryScanner::new(engine, MemoryScanConfig::default());
        let mut report = MemoryScanReport::new();
        report.record(scanner.scan_process(source));
        MemoryReport::from_report(99, report)
    }

    /// A report built from one scripted process.
    fn report_from(source: &mut Scripted) -> MemoryReport {
        report_from_engine(&engine(), source)
    }

    #[test]
    fn a_finding_in_a_process_is_a_memory_detection_and_is_not_clearable() {
        // The rule-text hazard, pinned. `av_scan`'s rule path builds *every*
        // match as `DetectionSource::Signature`, because the engine is handed
        // bytes and a path and has no way to know what produced them — so the
        // same rule matching the same bytes arrives labelled as a file signature
        // when it came off a disk, and has to be relabelled when it came out of
        // a process. This is the differential: one detection, one field changed,
        // and the question "can a valid signature clear this" flips.
        let mut source = scripted();
        let report = report_from(&mut source);
        let findings = report.findings();
        assert_eq!(findings.len(), 1, "one region, one marker, one finding");

        let detection = &findings[0].detections[0];
        assert_eq!(
            detection.source,
            DetectionSource::Memory,
            "a match in a region is a memory detection, not a file signature"
        );
        assert_eq!(
            detection.severity,
            Severity::Medium,
            "the fixture rule names no severity, so this is the default"
        );
        assert!(
            !av_scan::trust::is_generic(detection),
            "trust must have no standing to clear a memory detection: {}",
            detection.rule_id
        );

        // The identical detection, relabelled as a file match. Same rule, same
        // bytes, same severity, same locations — and trust is entitled to clear
        // it, because a signature *is* evidence about a file on disk. That is
        // why the label above is load-bearing rather than cosmetic.
        let mut as_file = detection.clone();
        as_file.source = DetectionSource::Signature;
        assert!(
            av_scan::trust::is_generic(&as_file),
            "this detection would be clearable if it claimed to be about a file"
        );
    }

    #[test]
    fn a_malicious_marker_lands_in_the_red_band_and_a_quiet_one_in_the_yellow() {
        // The question the three-band policy exists to answer: does a memory
        // scanner's output land where a user will act on it, or where they will
        // read it and move on? Both are legitimate; the point is that the band
        // is decided by the rule's own claim and not by the fact that the bytes
        // came out of a process.
        let engine = malicious_engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut source = scripted();
        let mut report = MemoryScanReport::new();
        report.record(scanner.scan_process(&mut source));
        let report = MemoryReport::from_report(99, report);
        assert_eq!(report.findings()[0].verdict, Verdict::Malicious);
        assert_eq!(report.verdict(), Verdict::Malicious);

        // And the same marker under a rule that claims less is suspicious, not
        // malicious: a memory finding is not promoted by where it was found.
        let mut source = scripted();
        let report = report_from(&mut source);
        assert_eq!(report.findings()[0].verdict, Verdict::Suspicious);
        assert_eq!(report.verdict(), Verdict::Suspicious);
    }

    #[test]
    fn a_rule_with_no_description_still_says_file_in_a_process_report() {
        // A cross-crate wart, pinned rather than papered over, because it is not
        // this crate's text to write.
        //
        // `av_scan::rules::describe` builds the fallback description for a rule
        // whose author wrote no `description` meta — and it is a *file*
        // sentence: "The rule `x` matched this file." The memory path reuses the
        // engine's detection unchanged, so a process report prints a line about a
        // file, under a heading that says `Process memory`, about bytes that are
        // in no file on this machine. It is cosmetic — the rule name and the
        // offsets are right, and nothing is decided from the text — but it is the
        // same class of error as giving a process a fake path, which is the one
        // thing this module's documentation says it will not do.
        //
        // The fix belongs in `av_scan::rules::describe` (which would have to know
        // the detection's source) or in `av-core::Detection` (which could carry a
        // neutral sentence the way it carries the source). Until one of those
        // happens, this test records what the text actually is, so the next person
        // to read it does not have to run a scan of a live machine to find out.
        let mut source = scripted();
        let report = report_from(&mut source);
        let text = section_lines(&report, Duration::from_millis(100), false, None).join("\n");
        assert!(
            text.contains("The rule `cli_memory_marker` matched this file."),
            "the fallback description changed; if it is now subject-neutral, this test \
             should be deleted and not adjusted: {text}"
        );

        // And the parts that *are* this crate's to get right, on the same line:
        // the rule that fired and the offset it fired at are both there.
        assert!(text.contains("cli_memory_marker"), "{text}");
        assert!(text.contains("0x0 ("), "{text}");
    }

    #[test]
    fn the_memory_section_names_the_process_and_the_address_and_no_path() {
        // What the user reads. The section has a heading of its own, the subject
        // of every line is a process and an address, and the region's shape is
        // there because that is what makes the finding interesting.
        let mut source = scripted();
        let report = report_from(&mut source);
        let text = section_lines(&report, Duration::from_millis(100), false, None).join("\n");

        assert!(text.contains("Process memory"), "its own section: {text}");
        assert!(
            text.contains("explorer.exe:0x7ff6a1b20000"),
            "the process and the address: {text}"
        );
        assert!(
            text.contains("unbacked-executable") && text.contains("private"),
            "why the region was read: {text}"
        );
        // The match offset is the marker's, taken from the marker so that the
        // number cannot drift away from the fixture. The line also names the
        // rule, and the region is *not* repeated on it — see [`inside`].
        let offset = format!("0x0 ({} bytes)", MARKER.len());
        assert!(text.contains(&offset), "where in it: {text}");
        assert!(
            text.contains("1 process(es) examined"),
            "how much was looked at: {text}"
        );
        let mut checked = 0;
        for line in section_lines(&report, Duration::from_millis(100), false, None) {
            if line.contains(&offset) {
                checked += 1;
                assert_eq!(
                    line.matches("explorer.exe:0x7ff6a1b20000").count(),
                    0,
                    "the offset line repeats the region: {line}"
                );
            }
        }
        assert_eq!(checked, 1, "the offsets are printed exactly once");
    }

    #[test]
    fn an_unreadable_process_is_a_gap_the_user_is_told_about() {
        // A process that could not be opened is a hole in the scan, and the
        // report says so rather than leaving the reader to notice that the
        // number examined is smaller than the number of processes they have.
        let report = MemoryReport::from_report(99, {
            let mut report = MemoryScanReport::new();
            report.record_refusal(
                process(),
                &av_memory::MemoryError::Denied {
                    pid: 4242,
                    code: 5,
                    message: "Access is denied.".to_string(),
                },
            );
            report
        });
        assert_eq!(report.verdict(), Verdict::Unknown);
        let gaps = report.gaps();
        assert_eq!(gaps.len(), 1);
        assert!(
            gaps[0].contains("refused a handle"),
            "the reason, not just the count: {}",
            gaps[0]
        );
        // The section says the same thing in its totals, and the exit code says
        // it to a script.
        let text = section_lines(&report, Duration::from_millis(1), false, None).join("\n");
        assert!(text.contains("1 refused"), "{text}");
        assert!(text.contains("could not examine every process"), "{text}");
    }

    #[test]
    fn a_quiet_run_prints_findings_and_says_nothing_else() {
        let mut source = scripted();
        let report = report_from(&mut source);
        let quiet = section_lines(&report, Duration::from_millis(100), true, None).join("\n");
        assert!(quiet.contains("Process memory"));
        assert!(quiet.contains("explorer.exe:0x7ff6a1b20000"));
        assert!(
            !quiet.contains("process(es) examined"),
            "the totals are commentary and `--quiet` means no commentary: {quiet}"
        );

        // A complete scan with nothing in it has nothing to say under `--quiet`
        // at all — not even a heading.
        let engine = engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut heap = Scripted {
            process: process(),
            regions: vec![av_memory::MemoryRegion {
                base: 0x1000,
                size: 4096,
                state: av_memory::RegionState::Committed,
                protection: av_memory::Protection::from_raw(0x04),
                kind: av_memory::RegionKind::Private,
            }],
            bytes: vec![0; 4096],
            backing: av_memory::Origin::Unknown,
        };
        let mut report = MemoryScanReport::new();
        report.record(scanner.scan_process(&mut heap));
        let report = MemoryReport::from_report(99, report);
        assert!(section_lines(&report, Duration::from_millis(1), true, None).is_empty());

        // And a scan that never ran is never silent, whatever the flags: it is
        // the reason there is no answer.
        let unavailable = MemoryReport::unavailable(99, "no process list".into());
        let text = section_lines(&unavailable, Duration::from_millis(0), true, None).join("\n");
        assert!(text.contains("No running process was examined"), "{text}");
        assert!(text.contains("no process list"), "{text}");
    }

    #[test]
    fn the_container_names_the_process_and_the_address_and_never_a_path() {
        // The design constraint, as an assertion. A memory finding's subject is
        // a process and an address; giving it a path would send a user looking
        // on disk for bytes that are not there.
        let mut source = scripted();
        let report = report_from(&mut source);
        let finding = report.findings()[0];
        assert_eq!(finding.container(), "explorer.exe:0x7ff6a1b20000");
        assert!(finding.process.image.is_some(), "the image is known");
        assert_eq!(
            finding.detections[0].container.as_deref(),
            Some("explorer.exe:0x7ff6a1b20000"),
            "the region, and not a path, is what the detection is attributed to"
        );
    }

    #[test]
    fn a_complete_scan_with_no_findings_is_clean_and_an_incomplete_one_is_not() {
        let engine = engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());

        // A region that is not executable, so nothing is worth reading: the walk
        // is complete, no region was refused, and the answer is genuinely clean.
        let mut quiet = Scripted {
            process: process(),
            regions: vec![av_memory::MemoryRegion {
                base: 0x1000,
                size: 4096,
                state: av_memory::RegionState::Committed,
                // `PAGE_READWRITE`: a heap, not code.
                protection: av_memory::Protection::from_raw(0x04),
                kind: av_memory::RegionKind::Private,
            }],
            bytes: vec![0; 4096],
            backing: av_memory::Origin::Unknown,
        };
        assert_eq!(
            scanner
                .scan_process(&mut quiet)
                .outcome()
                .map(|o| o.findings.len()),
            Some(0)
        );
        let complete = MemoryReport::from_report(99, {
            let mut report = MemoryScanReport::new();
            report.record(scanner.scan_process(&mut quiet));
            report
        });
        assert!(complete.is_complete());
        assert_eq!(complete.verdict(), Verdict::Clean);
        assert!(complete.gaps().is_empty());

        // A process that could not be opened at all. Nothing was examined, so
        // there is no answer to give, and `Clean` would be that answer given
        // wrongly.
        let error = av_memory::MemoryError::Denied {
            pid: 4,
            code: 5,
            message: "Access is denied.".to_string(),
        };
        let refused = MemoryReport::from_report(99, {
            let mut report = MemoryScanReport::new();
            report.record_refusal(process(), &error);
            report
        });
        assert!(!refused.is_complete());
        assert_eq!(refused.verdict(), Verdict::Unknown);
        assert_eq!(refused.summary().processes_refused(), 1);
        assert_eq!(refused.gaps().len(), 1, "the gap is stated, not implied");
        assert!(refused.gaps()[0].contains("refused a handle"));
    }

    #[test]
    fn a_scan_that_could_not_run_is_unknown_rather_than_clean() {
        let unavailable = MemoryReport::unavailable(99, "no process list".to_string());
        assert_eq!(unavailable.verdict(), Verdict::Unknown);
        assert!(!unavailable.is_complete());
        assert!(unavailable.findings().is_empty());
        assert_eq!(
            unavailable.gaps(),
            vec!["no running process was examined: no process list"]
        );
    }

    #[test]
    fn a_process_that_exited_is_counted_and_is_not_a_gap() {
        // A live machine ends processes while a scan runs. That is work that
        // turned out to be unnecessary, not a hole in what the scan saw, and the
        // two are counted separately so a reader can tell them apart.
        use av_memory::MemoryError;
        let report = MemoryReport::from_report(99, {
            let mut report = MemoryScanReport::new();
            report.record_refusal(ProcessRef::anonymous(7), &MemoryError::Gone { pid: 7 });
            report
        });
        let summary = report.summary();
        assert_eq!(summary.processes_gone(), 1);
        assert_eq!(summary.processes_refused(), 0);
        assert!(
            report.is_complete(),
            "a process that ended left nothing unexamined"
        );
        assert_eq!(report.verdict(), Verdict::Clean);
    }

    #[test]
    fn the_json_keeps_process_findings_out_of_the_file_findings() {
        let mut source = scripted();
        let report = report_from(&mut source);
        let document = json(&report, Duration::from_millis(1500), None);

        assert_eq!(document["ran"], serde_json::json!(true));
        assert_eq!(document["complete"], serde_json::json!(true));
        // The memory report's own verdict, in the memory object. It is not the
        // run's verdict and is not merged into the file findings: a consumer
        // reading `findings` gets files and a consumer reading `memory.findings`
        // gets processes, and the caller that owns the exit code is the one that
        // knows how to combine them.
        assert_eq!(document["verdict"], serde_json::json!("suspicious"));
        assert_eq!(document["own_process_examined"], serde_json::json!(false));
        assert_eq!(document["own_pid"], serde_json::json!(99));

        let findings = document["findings"].as_array().expect("an array");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["process"]["pid"], serde_json::json!(4242));
        assert_eq!(findings[0]["base"], serde_json::json!(0x7ff6_a1b2_0000u64));
        assert_eq!(
            findings[0]["detections"][0]["source"],
            serde_json::json!("memory"),
            "the JSON says where the bytes came from"
        );
        // The finding has no path field at all: a consumer cannot mistake it for
        // a file report, because there is nothing on it shaped like one.
        assert!(findings[0].get("path").is_none());
    }

    #[test]
    fn the_json_names_every_process_that_was_skipped_and_why() {
        use av_memory::MemoryError;
        let report = MemoryReport::from_report(99, {
            let mut report = MemoryScanReport::new();
            report.record_refusal(
                ProcessRef::new(
                    4,
                    Some(std::path::PathBuf::from(r"C:\Windows\System32\lsass.exe")),
                ),
                &MemoryError::Denied {
                    pid: 4,
                    code: 5,
                    message: "Access is denied.".to_string(),
                },
            );
            report.record_refusal(ProcessRef::anonymous(700), &MemoryError::Gone { pid: 700 });
            report
        });
        let document = json(&report, Duration::from_millis(20), None);
        let skipped = document["skipped"].as_array().expect("an array");
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped[0]["pid"], serde_json::json!(4));
        assert_eq!(skipped[0]["label"], serde_json::json!("lsass.exe"));
        assert_eq!(skipped[0]["reason"], serde_json::json!("access-denied"));
        assert_eq!(
            skipped[0]["detail"],
            serde_json::json!("Windows refused a handle: Access is denied. (error 5)")
        );
        assert_eq!(skipped[1]["reason"], serde_json::json!("gone"));

        // And the gap is in the JSON too, so a machine reading this does not
        // have to infer the incomplete verdict from the omitted processes.
        assert_eq!(document["complete"], serde_json::json!(false));
        assert_eq!(document["verdict"], serde_json::json!("unknown"));
        assert!(!document["gaps"].as_array().expect("an array").is_empty());
    }

    #[test]
    fn a_scan_that_never_ran_says_so_in_both_reports() {
        let report = MemoryReport::unavailable(99, "the process list could not be read".into());
        let document = json(&report, Duration::from_millis(0), None);
        assert_eq!(document["ran"], serde_json::json!(false));
        assert_eq!(
            document["detail"],
            serde_json::json!("the process list could not be read")
        );
        assert_eq!(document["verdict"], serde_json::json!("unknown"));
        assert_eq!(
            document["findings"].as_array().map(Vec::len),
            Some(0),
            "an empty list, not a missing one: a consumer can tell 'nothing' from 'no answer'"
        );
    }

    #[test]
    fn the_region_shape_is_reported_with_the_finding() {
        // The reason this finding exists at all is the shape of the region it was
        // found in, so the shape is part of the finding's own line.
        let mut source = scripted();
        let report = report_from(&mut source);
        let finding = report.findings()[0];
        assert_eq!(finding.interest, av_memory::Interest::UnbackedCode);
        assert_eq!(finding.kind, av_memory::RegionKind::Private);
        assert!(!finding.truncated);
        assert_eq!(finding.region_size, MARKER.len() + 64);
        assert_eq!(finding.bytes_read, finding.region_size);
    }

    #[test]
    fn a_finding_whose_bytes_came_from_a_malicious_file_puts_that_file_in_the_vault() {
        // The whole chain, on real files: a rule matched bytes in a running
        // process, the source named the file the loader mapped them from, that
        // file was examined in its own right and was malicious on its own
        // evidence, and the vault took it. Nothing in this test is a stub except
        // the process and the region: the engine, the file scan, the vault and
        // its index are the real ones.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let evil = dir.path().join("evil.exe");
        let payload = marked_bytes();
        std::fs::write(&evil, &payload).expect("the fixture file");

        let engine = malicious_engine();
        let mut source = scripted();
        source.backing = av_memory::Origin::File { path: evil.clone() };
        let report = report_from_engine(&engine, &mut source);
        assert_eq!(report.findings().len(), 1, "the marker is in the region");

        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        let options = ScanOptions::default();
        let mut chain = Chain::build(&report, &engine, &paths, &options);
        assert_eq!(
            chain.to_take(),
            1,
            "the file is malicious on its own evidence, so it is fit to take"
        );
        // Before the vault is asked, the note says what would happen and does
        // not claim it happened. This is the state a run without `--quarantine`
        // ends in, and the sentence is the one a user reads there.
        let planned = chain.note(0).expect("a note for the first finding");
        assert!(planned.contains("evil.exe"), "{planned}");
        assert!(planned.contains("malicious"), "{planned}");
        assert!(planned.contains("--quarantine"), "{planned}");
        assert!(
            chain.json()[0]["quarantined"].is_null(),
            "nothing was taken"
        );

        let mut vault = QuarantineVault::open(
            paths.quarantine_dir.clone(),
            av_quarantine::QuarantinePolicy::default(),
        )
        .expect("a vault");
        assert_eq!(chain.carry_out(&mut vault), 1);

        assert!(!evil.exists(), "the file left its original path");
        let entries = vault.list();
        assert_eq!(entries.len(), 1, "and it is in the vault");
        assert_eq!(
            entries[0].source,
            EntrySource::Memory,
            "recorded as found in memory rather than as a file the walker found"
        );
        let after = chain.note(0).expect("a note");
        assert!(after.starts_with("quarantined as "), "{after}");
        assert_eq!(chain.quarantined(), 1);
        assert_eq!(
            chain.json()[0]["quarantined"].as_str().map(str::len),
            Some(8)
        );
    }

    #[test]
    fn injected_code_has_no_file_to_take_and_the_note_says_so() {
        // The case memory scanning exists for, and the case where a naive
        // implementation would quarantine whatever process happened to be
        // running. Nothing on disk holds these bytes, so there is no file: the
        // finding is about the region, and the note says which.
        let engine = malicious_engine();
        let mut source = scripted();
        source.backing = av_memory::Origin::Nothing;
        let report = report_from_engine(&engine, &mut source);

        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        let chain = Chain::build(&report, &engine, &paths, &ScanOptions::default());

        assert_eq!(chain.to_take(), 0, "there is nothing to take");
        let note = chain.note(0).expect("a note");
        assert!(note.starts_with("no file was taken"), "{note}");
        assert!(note.contains("no file"), "{note}");
        // And the sentence is about the region, not about the process image:
        // this is the one finding where naming a path would be a lie.
        assert!(!note.contains("explorer.exe"), "{note}");
    }

    #[test]
    fn a_match_in_a_clean_file_leaves_that_file_alone() {
        // The relocation gap, and the false positive it would otherwise produce:
        // the bytes match in memory, the file they came from is examined, and the
        // file does not contain the rule's evidence. Acting on the address alone
        // would take a file that had done nothing — and on a real machine it
        // would eventually be `ntdll.dll`.
        let engine = malicious_engine();
        let dir = tempfile::tempdir().expect("a temporary directory");
        let innocent = dir.path().join("innocent.dll");
        std::fs::write(&innocent, b"an ordinary library, nothing like the marker")
            .expect("the fixture file");

        let mut source = scripted();
        source.backing = av_memory::Origin::Image {
            path: innocent.clone(),
        };
        let report = report_from_engine(&engine, &mut source);

        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        let chain = Chain::build(&report, &engine, &paths, &ScanOptions::default());
        assert_eq!(chain.to_take(), 0);
        let note = chain.note(0).expect("a note");
        assert!(note.contains("innocent.dll"), "{note}");
        assert!(
            note.contains("clean"),
            "the note says what the file itself is: {note}"
        );
        assert!(innocent.exists(), "the file was not touched");

        // A region whose origin could not be established is a different answer
        // and must not be read as "nothing on disk holds this".
        let mut unknown = scripted();
        unknown.backing = av_memory::Origin::Unknown;
        let report = report_from_engine(&engine, &mut unknown);
        let chain = Chain::build(&report, &engine, &paths, &ScanOptions::default());
        assert_eq!(chain.to_take(), 0);
        let note = chain.note(0).expect("a note");
        assert!(note.contains("never established"), "{note}");
        assert!(!note.contains("nothing on disk"), "{note}");
    }

    #[test]
    fn the_section_says_what_became_of_each_finding() {
        // What the user reads, with the chain in place: the finding, and under it
        // the sentence about its file. Without this the report would show a
        // finding and leave the reader unable to tell a finding that was acted on
        // from one that was ignored.
        let engine = malicious_engine();
        let dir = tempfile::tempdir().expect("a temporary directory");
        let evil = dir.path().join("evil.exe");
        std::fs::write(&evil, marked_bytes()).expect("the fixture file");

        let mut source = scripted();
        source.backing = av_memory::Origin::File { path: evil.clone() };
        let report = report_from_engine(&engine, &mut source);
        let paths = AvPaths::with_data_dir(dir.path().join("install"), dir.path().join("data"));
        let mut chain = Chain::build(&report, &engine, &paths, &ScanOptions::default());
        let mut vault = QuarantineVault::open(
            paths.quarantine_dir.clone(),
            av_quarantine::QuarantinePolicy::default(),
        )
        .expect("a vault");
        chain.carry_out(&mut vault);

        let text =
            section_lines(&report, Duration::from_millis(10), false, Some(&chain)).join("\n");
        assert!(text.contains("Process memory"), "{text}");
        assert!(text.contains("explorer.exe:0x7ff6a1b20000"), "{text}");
        assert!(text.contains("quarantined as "), "{text}");
        assert!(text.contains("took a file into the vault"), "{text}");

        // And under `--quiet` the note survives, because an action taken on the
        // machine is not commentary about the scan.
        let quiet =
            section_lines(&report, Duration::from_millis(10), true, Some(&chain)).join("\n");
        assert!(quiet.contains("quarantined as "), "{quiet}");
        assert!(!quiet.contains("took a file into the vault"), "{quiet}");

        // The JSON carries it per finding, in the same order, so a consumer can
        // read the two arrays together.
        let document = json(&report, Duration::from_millis(10), Some(&chain));
        assert_eq!(document["files_quarantined"], serde_json::json!(1));
        assert_eq!(
            document["handling"][0]["reason"],
            serde_json::json!("take"),
            "{document}"
        );
        assert_eq!(
            document["handling"][0]["verdict"],
            serde_json::json!("malicious")
        );
        assert!(!document["handling"][0]["quarantined"].is_null());
    }

    #[test]
    fn a_region_that_is_not_executable_is_never_a_finding() {
        // The false-positive guard, in the CLI's own tests: a marker sitting in
        // a readable, writable, non-executable region is a string on a heap, and
        // a string on a heap is not the code that is running.
        let engine = engine();
        let scanner = MemoryScanner::new(&engine, MemoryScanConfig::default());
        let mut heap = Scripted {
            process: process(),
            regions: vec![av_memory::MemoryRegion {
                base: 0x5000,
                size: MARKER.len() + 64,
                state: av_memory::RegionState::Committed,
                protection: av_memory::Protection::from_raw(0x04),
                kind: av_memory::RegionKind::Private,
            }],
            bytes: marked_bytes(),
            backing: av_memory::Origin::Unknown,
        };
        let scan = scanner.scan_process(&mut heap);
        assert!(matches!(scan, ProcessScan::Examined(_)));
        assert_eq!(
            scan.outcome().map(|outcome| outcome.findings.len()),
            Some(0),
            "the marker is there and the region is not executable, so it is not read"
        );
    }

    #[test]
    fn an_inner_container_is_shown_without_repeating_the_region() {
        let detection = Detection::new(
            "test/inner",
            "a match inside a member",
            Severity::High,
            DetectionSource::Memory,
        )
        .with_location(
            av_core::MatchLocation::new(0x10, 4, "$a", b"abcd")
                .within("explorer.exe:0x7ff6a1b20000/payload/inner.exe"),
        )
        .within("explorer.exe:0x7ff6a1b20000/payload/inner.exe");

        assert_eq!(
            inside(&detection, "explorer.exe:0x7ff6a1b20000").as_deref(),
            Some("payload/inner.exe")
        );
        // A detection attributed to the region alone has nothing extra to say.
        let plain = Detection::new("test/plain", "d", Severity::High, DetectionSource::Memory)
            .with_location(
                av_core::MatchLocation::new(0x10, 4, "$a", b"abcd").within("a.exe:0x1000"),
            );
        assert_eq!(inside(&plain, "a.exe:0x1000"), None);
    }
}
