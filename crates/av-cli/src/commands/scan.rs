//! `wenle scan` — walk a tree, scan every file, report what was found.
//!
//! # The shape of the parallelism, and why it is this shape
//!
//! One thread enumerates; every core scans. Enumeration is filesystem latency
//! and a parallel walk over one spindle is slower than a sequential one, while
//! scanning is CPU and is the entire cost of a large run. The workers are
//! `rayon`'s, one [`Scanner`] per worker built by `map_init`, and the results
//! come back in the walk's order because `par_iter().collect()` preserves it —
//! so two runs over one tree print the same report, which is the property that
//! makes a diff of two reports mean something.
//!
//! # One box, three gates
//!
//! The verdict model's middle band exists so that a scan can say "worth
//! mentioning" without saying "worth acting on". This command is the place
//! where that distinction becomes visible to a user: `malicious` and
//! `suspicious` are printed in different colours, exit with different codes,
//! and only the first is a reason for a script to intervene. Nothing here
//! touches a file — see [`av_scan::engine`] for why the engine will not either.
//!
//! # What a file above the size limit means here
//!
//! It is not opened. `--max-size` is applied by the walk, so the option means
//! one thing in this program, and the count of files it removed is printed
//! rather than left for the user to infer from a total. The alternative
//! reading — open it, hash all of it, examine the front — would have the same
//! option name mean two different things in two different layers, which is how
//! a file ends up unscanned by a user who believed otherwise.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use av_core::{FileScanReport, ScanOptions, Verdict, VerdictThresholds};
use av_memory::MemoryScanConfig;
use av_rules::scanner::Scanner;
use av_scan::heuristics::HeuristicConfig;
use av_scan::trust::TrustPolicy;
use av_scan::{DigestPolicy, ScanEngine};
use av_signatures::catalog::CatalogIndex;
use rayon::prelude::*;

use crate::cli::{Globals, OnError, ScanArgs};
use crate::commands::Context;
use crate::exit::Exit;
use crate::memory::{self, MemoryReport};
use crate::output;
use crate::progress::{human_bytes, human_count, Progress};
use crate::walk::{self, WalkOptions};

/// What happened to one file, in the order the walk produced it.
enum Outcome {
    /// Nothing worth saying, and how many rule sources the engine declined
    /// *inside* the file.
    ///
    /// The count rides on this variant rather than on a tally of its own because
    /// this is the only outcome whose report is dropped: a `Found` report
    /// reaches the loop intact, so its count is read off it there. A container
    /// holding a rule corpus and nothing else is exactly this case — it has no
    /// findings of its own — so a count that did not survive this variant would
    /// miss the case it was added for.
    ///
    /// `cleared` is the other thing that would otherwise be lost with the
    /// report, and it is a different fact from `declined_members`: the file was
    /// read and the rules *were* run against it, and what came back was thrown
    /// away because the file's identity is proven. See [`cleared_line`] for why
    /// the run says so rather than letting the file join the quiet majority.
    Clean {
        declined_members: usize,
        cleared: bool,
    },
    /// A file the engine recognised as this product's own data, which no rule
    /// was run against.
    ///
    /// Not folded into [`Outcome::Clean`], which is where it used to go and
    /// where the verdict alone would put it. `Clean` is a statement about a file
    /// that was read and had nothing in it; this is a statement about a file
    /// nothing was run against, and the two are the difference the whole product
    /// is built around. Merged, they make a run report a byte total for reading
    /// that did not happen — 17.5 MB of rule source, in the case that was
    /// measured — and a clean bill of health for a file nobody examined.
    Own(Box<FileScanReport>),
    /// A file the engine recognised as a rule source this product did not
    /// compile, and did not run a rule against either.
    ///
    /// A separate variant from [`Outcome::Own`] although the handling is
    /// identical, because the two are reported as different things and a variant
    /// is where that decision belongs — see [`Declined`].
    Source(Box<FileScanReport>),
    /// A non-clean verdict, to be printed.
    Found(Box<FileScanReport>),
    /// The file could not be read.
    Unreadable(String),
}

/// What a run put through the rules, in files and bytes.
///
/// # Why this is computed rather than read off the walk
///
/// The walk's own totals — [`walk::WalkOutcome::files`] and
/// [`walk::WalkOutcome::bytes`] — are the files it *found*. That was the same
/// number as the files scanned until the engine learned to recognise this
/// product's own data, and it is not any more: a rule source is found by the
/// walk, read off the disk, handed to the engine and declined. The walk's total
/// counts its 17.5 MB, and no byte of it was examined.
///
/// # The two measurements, and why they are subtracted from each other anyway
///
/// The sizes come from different places: the walk's total is the sum of the
/// sizes in the directory metadata, and each declined file's size is the length
/// of the buffer that was read. A file that grew between the two would make the
/// subtraction slightly wrong, which is why it saturates rather than wrapping.
/// The alternative — summing `scanned_bytes` over every report — is not
/// available here, because the reports that clean files produced are dropped as
/// the scan finishes and keeping one per file would mean holding every report of
/// a scan of a million files in memory to print one number.
#[derive(Debug, Clone)]
struct Coverage {
    /// Files the rules were actually run against.
    scanned: usize,
    /// The size of those files.
    ///
    /// Files that could not be read are inside this figure and inside
    /// [`Self::scanned`], because both were attempted; the summary names them
    /// separately.
    bytes: u64,
    /// The files the engine read, recognised and declined to run a rule against.
    declined: Declined,
    /// Entries the walk skipped by a filter, and what it could not look at. The
    /// two numbers above are about the files that got as far as the engine;
    /// these are about the ones that did not, and a report that dropped them
    /// would have no way to say a scan was narrower than the user asked for.
    skipped: u64,
    unreadable: Vec<String>,
}

/// The files the engine recognised and did not examine, by what it recognised
/// them as.
///
/// # Why two counts and not one
///
/// Because the two are different statements about the world and only one of them
/// is about this product. A digest match in [`Self::own`] says *these bytes are
/// this product's* — the corpus it was compiled from, or the database itself —
/// and that is checkable and true. A shape match in [`Self::sources`] says only
/// that the file is written in the rule language and was not one this product
/// compiled, which is a statement about a stranger's file. A summary that added
/// them together would tell the user that a corpus they downloaded from somebody
/// else is this product's own data, and the user would have no way to tell.
///
/// The distinction also survives into the JSON, where a script reading the two
/// fields can tell a scan of our own installation from a scan of a rule
/// repository.
#[derive(Debug, Clone, Default)]
struct Declined {
    /// Files recognised as this product's own data, by digest.
    own: usize,
    /// Their total size, as read.
    own_bytes: u64,
    /// Files recognised as rule sources this product did not compile, by shape.
    sources: usize,
    /// Their total size, as read.
    source_bytes: u64,
    /// Rule sources the engine declined *inside* files it did examine.
    ///
    /// # Why this is a count and has no byte column beside it
    ///
    /// Because the two numbers above are about files the walk found and read,
    /// and this one is about bytes inside them. A member's length is not the
    /// container's length, so adding it to the byte totals would be adding a
    /// number about a member to a column of numbers about files; and the note
    /// the engine writes for a member carries no size at all — see
    /// [`av_scan::own::declined_members`].
    ///
    /// # Why it is counted even though nothing is subtracted for it
    ///
    /// Nothing is: a container whose member was declined was itself opened,
    /// walked and scanned, so it stays in the examined totals where it belongs.
    /// The count is here so that the user is told the part of their file nobody
    /// read. Without it, `Rust-antivirus-main (1).zip` — 22.09 MiB, walked, one
    /// nested rule container declined — reports as a file that was read from end
    /// to end, and a rule corpus 7.79 MB inside it was never examined by
    /// anything.
    members: usize,
}

impl Declined {
    /// How many files were declined, of both kinds.
    fn files(&self) -> usize {
        self.own + self.sources
    }

    /// Their total size, as read.
    fn bytes(&self) -> u64 {
        self.own_bytes + self.source_bytes
    }

    /// Whether nothing was declined at all, which is the ordinary run.
    ///
    /// The member count is deliberately not part of this. It decides whether a
    /// line is printed and never whether a byte is subtracted, and a run that
    /// declined a member inside a file it did examine is not a run whose
    /// coverage needs accounting for.
    fn is_empty(&self) -> bool {
        self.files() == 0
    }

    /// What to call the declined files in a sentence, or `None` when there are
    /// none.
    ///
    /// The words matter more than the arithmetic. "This product's own data" and
    /// "rule sources this product did not write" are not interchangeable, and
    /// the second is the one a user who scanned a directory of downloaded
    /// corpora will recognise.
    fn phrase(&self) -> Option<&'static str> {
        match (self.own > 0, self.sources > 0) {
            (true, true) => Some(
                "a mix of this product's own data and rule sources this product did not write",
            ),
            (true, false) => Some("this product's own data"),
            (false, true) => Some("rule sources this product did not write"),
            (false, false) => None,
        }
    }
}

impl Coverage {
    /// The files a walk found, less the ones the engine declined to examine.
    ///
    /// The subtraction is not a formality: it is the whole point of the type.
    /// See the struct's documentation for why the walk's own totals cannot be
    /// printed as the scan's.
    fn of(walked: &walk::WalkOutcome, declined: Declined) -> Self {
        Self {
            scanned: walked.files.len().saturating_sub(declined.files()),
            bytes: walked.bytes.saturating_sub(declined.bytes()),
            declined,
            skipped: walked.skipped,
            unreadable: walked.unreadable.clone(),
        }
    }

    /// Whether the run was given files and examined none of them.
    ///
    /// The case the declined files create, and the one where every clean
    /// sentence the report can print is a claim about files that were not
    /// looked at.
    fn examined_nothing(&self) -> bool {
        !self.declined.is_empty() && self.scanned == 0
    }
}

/// The rule set a run put in force, and where it was read from.
///
/// # Why a scan reports this at all
///
/// Two databases can be on a machine at once — one built beside the binary, one
/// the installed product is using — and which one a given run reads is decided
/// by a search order nothing else in the output reveals. That makes a
/// difference a user can feel and cannot see: a rule they just added, or a
/// rebuild they just did, is either in force or not, and a scan that reports
/// "nothing found" without saying which rules it looked with is a scan whose
/// answer cannot be checked.
///
/// It is printed before the scan starts rather than with the results, because a
/// scan of a large tree runs for minutes and this is the one fact a user wants
/// while it runs rather than after. `--json` carries the same two facts, so a
/// support case can tell which database produced a report.
#[derive(Debug, Clone)]
struct RulesUsed {
    /// How many rules the database holds.
    count: usize,
    /// The file they were read from, as it was found — not a canonicalised
    /// path, because the point is to name the candidate that won the search.
    database: PathBuf,
}

impl RulesUsed {
    /// The line a person reads.
    fn line(&self) -> String {
        format!(
            "{} {} from {}",
            human_count(self.count as u64),
            // "1 rule from", not "1 rules from": a hand-built database during a
            // rule-authoring session is exactly when this line is read most.
            if self.count == 1 { "rule" } else { "rules" },
            self.database.display()
        )
    }

    /// The object the JSON report carries.
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.count,
            "database": self.database.display().to_string(),
        })
    }
}

/// The number of threads a scan will actually run on.
///
/// `0` from the command line means "whatever rayon's default pool is", and that
/// number is only knowable after the pool exists — so the banner asks rayon
/// rather than assuming one thread per core, which is the default but not a
/// promise. A `-j` that set the pool reports the size that was asked for.
fn scanning_threads(requested: usize) -> usize {
    if requested > 0 {
        requested
    } else {
        rayon::current_num_threads()
    }
}

/// The line that says how much memory this scan is allowed to hold, and how
/// many threads will be asking for it.
///
/// Both halves matter to whoever is reading a scan that has gone slow. The
/// thread count is the multiplier on everything the scan holds at once, so a
/// `-j 32` on a 12-core machine is a fact worth seeing before the run rather
/// than deducing from a crash; and the two memory numbers are the ones the
/// out-of-memory report in `logs/crash.log` is read against.
fn memory_line(threads: usize) -> String {
    format!(
        "{}, {threads} scanning {}",
        av_fs::budget::describe(),
        if threads == 1 { "thread" } else { "threads" }
    )
}

/// Run a scan.
pub fn run(args: &ScanArgs, globals: &Globals, context: &Context) -> Result<Exit> {
    let options = effective_options(args, context);
    let paths = expand(&args.paths, &context.config.general.exclusions);
    // Told what the run will do rather than what the configuration says, because
    // `--memory` and `--no-memory` override the configuration and the warning is
    // about the run.
    context.warn_about_gaps(options.memory);

    let progress = Progress::new(!globals.quiet && !args.no_progress);
    let walk_options = WalkOptions {
        recursive: options.recursive,
        follow_links: options.follow_links,
        max_file_size: options.max_file_size,
        exclude: args.exclude.clone(),
        protected: Some(context.paths.clone()),
    };

    // The database's header is checked here and the database itself is loaded
    // after the walk, and the split is the point rather than an accident.
    //
    // A mistyped path should say so in a second rather than after the rule set
    // has been read off a slow disk, which is why the load is not first. And a
    // database this build cannot read should say so before a tree is walked,
    // which is why the check is not after it: a user reported exactly that,
    // as a scan that ran for a while and then failed with a message about a
    // file in `%ProgramData%` they had never named. Twenty bytes of header
    // answer the second question at no cost to the first.
    context.check_database(args.db.as_deref())?;

    let outcome = walk::collect(&paths, &walk_options);
    report_walk_problems(&outcome, args.on_error, globals.quiet);

    // The early return is for a scan with nothing to do. `--memory` makes a run
    // with no files a run with something to do, so it does not take it — a user
    // who asks for a memory scan of a directory with no files in it asked for a
    // memory scan, and returning "nothing to scan" would be answering a question
    // nobody asked.
    if outcome.files.is_empty() && !options.memory {
        if !globals.quiet {
            output::summary("Nothing to scan.");
        }
        return Ok(Exit::from_verdicts(
            outcome
                .unreadable
                .iter()
                .map(|_| Verdict::Unknown)
                .collect::<Vec<_>>(),
            args.fail_on_suspicious,
        ));
    }

    let (database, database_path) = context.load_database(args.db.as_deref())?;
    let rules = RulesUsed {
        count: database.len(),
        database: database_path,
    };
    // The one line that says which rules are in force, printed before the first
    // file is opened so that it is on screen for the whole of a long run. Not
    // under `--json`, where the same two facts are fields of the report.
    if !globals.quiet && !args.json {
        output::summary(&rules.line());
    }
    let engine = build_engine(database, context, &options, args.json, !args.no_catalog);

    let workers = args.threads.unwrap_or(0);
    if workers > 0 {
        // A pool of exactly the size asked for. `None` would leave rayon's
        // global pool at one thread per core, which is the right default and
        // the wrong answer to an explicit `-j`.
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .context("building the thread pool")?;
    }

    // Printed here rather than beside the rules line, because this is the first
    // moment both of its numbers are true: the rule database is loaded, so what
    // it took out of the machine is already spent, and the pool is built, so
    // the thread count is the one the scan will actually use. The rules line
    // goes up first so that a long load is on screen with something to say.
    if !globals.quiet && !args.json {
        output::summary(&memory_line(scanning_threads(workers)));
        if let Some(advice) = av_fs::budget::advice() {
            output::warn(&advice);
        }
    }

    let started = Instant::now();
    let stop = AtomicBool::new(false);
    // The line is drawn by a thread that only reads the counters, and it is
    // joined before the report is printed so that the report cannot land on top
    // of a half-drawn line.
    let drawing = {
        let progress = Arc::clone(&progress);
        std::thread::spawn(move || progress.draw())
    };
    let outcomes = scan_all(&engine, &outcome.files, &options, &progress, args, &stop);
    let elapsed = started.elapsed();
    progress.finish();
    let _ = drawing.join();

    let mut findings = Vec::new();
    let mut unreadable = outcome.unreadable.len();
    let mut declined = Declined::default();
    // Files the rules matched and trust threw away, counted rather than listed.
    // See [`cleared_line`] for why the run says this at all.
    let mut cleared = 0usize;
    for entry in outcomes {
        match entry {
            Outcome::Clean {
                declined_members,
                cleared: trusted,
            } => {
                declined.members += declined_members;
                if trusted {
                    cleared += 1;
                }
            }
            Outcome::Own(report) => {
                declined.own += 1;
                declined.own_bytes += report.size;
            }
            Outcome::Source(report) => {
                declined.sources += 1;
                declined.source_bytes += report.size;
            }
            Outcome::Found(report) => {
                // Read here rather than only in the clean arm, because a file
                // that has a finding of its own can hold a declined member too:
                // a container with a rule corpus in it and something the rules
                // match beside it is a `Found` report whose note would otherwise
                // never be counted.
                declined.members += av_scan::own::declined_members(&report);
                findings.push(*report);
            }
            Outcome::Unreadable(reason) => {
                unreadable += 1;
                if args.on_error == OnError::Report && !globals.quiet {
                    output::warn(&reason);
                }
            }
        }
    }
    let coverage = Coverage::of(&outcome, declined);

    // The report reads strongest first, so the line a user is looking for is
    // the line at the top.
    findings.sort_by(|a, b| {
        rank(b.verdict())
            .cmp(&rank(a.verdict()))
            .then_with(|| b.assessment.score.cmp(&a.assessment.score))
            .then_with(|| a.path.cmp(&b.path))
    });

    // Quarantining runs before anything is printed, and outside the parallel
    // scan, for two reasons. The vault's index is a single file that every
    // operation rewrites, so two workers quarantining at once is two writers to
    // one file; and doing it here means the report can say what happened to each
    // file on the same line as the finding, rather than leaving the user to
    // match two lists up by path.
    //
    // `None` and `Some(vec![])` are different answers and the report says
    // different things for each: `None` is a scan that was not asked to act, and
    // `Some` with nothing in it is one that was asked and had nothing to act on.
    let quarantined = if args.quarantine {
        Some(quarantine_findings(&findings, context, globals)?)
    } else {
        None
    };
    let handled: &[Taken] = quarantined.as_deref().unwrap_or(&[]);

    // The memory sweep runs after the files and before anything is printed, and
    // it is not part of the parallel scan: its work is kernel calls over a
    // process list rather than CPU over a file list, the progress line counts
    // files, and the two reports are printed as two sections because they are
    // about two different kinds of thing. It is outside the `--stop-on-first`
    // contract on purpose: stopping a file scan early is about not spending time
    // on files nobody will act on, while a memory sweep that stopped at the
    // first hit would leave the machine half-examined and the report unable to
    // say so — every unvisited process would look like a process with nothing in
    // it.
    let memory_scan = if options.memory {
        let started = Instant::now();
        let report = memory::scan_machine(&engine, MemoryScanConfig::default());
        Some((report, started.elapsed()))
    } else {
        None
    };
    // The chain runs on every finding, whether or not this run may act, because
    // the answer is worth having either way: a finding in a process running a
    // file that is itself malicious is something a user needs to read even when
    // nothing was taken. What it costs is one file scan per finding, and
    // findings are rare by construction — see [`crate::memory::Chain`].
    //
    // The vault is opened only when there is something to put in it, which is
    // the same discipline `quarantine_findings` follows and for the same reason:
    // opening a vault creates a directory and, on a machine that has never
    // quarantined anything, a master key, and neither belongs to a scan that
    // merely *asked* to quarantine.
    let mut memory_chain = memory_scan
        .as_ref()
        .map(|(report, _)| memory::Chain::build(report, &engine, &context.paths, &options));
    if let Some(chain) = memory_chain.as_mut() {
        if args.quarantine && chain.to_take() > 0 {
            let mut vault = context.open_vault(None)?;
            let taken = chain.carry_out(&mut vault);
            log::info!("{taken} file(s) taken into the vault because of a memory finding");
        }
    }
    let remembered = memory_scan.as_ref().map(|(report, spent)| (report, *spent));
    let chain = memory_chain.as_ref();

    if args.json {
        print_json(
            &findings,
            &coverage,
            elapsed,
            quarantined.as_deref(),
            remembered,
            chain,
            &rules,
            cleared,
        )?;
    } else {
        // `--quiet` suppresses the running commentary and the summary, never
        // the answer: a scan whose findings were suppressed by the same flag
        // that silenced its progress line would be a scan that reports nothing
        // whether or not it found anything.
        for report in &findings {
            print_finding(report, handled);
        }
        if let Some((report, spent)) = remembered {
            memory::print_section(report, spent, globals.quiet, chain);
        }
        if !globals.quiet {
            print_summary(
                &findings,
                &coverage,
                elapsed,
                unreadable,
                quarantined.as_deref(),
                remembered,
                cleared,
            );
        }
    }

    Ok(overall_exit(
        &findings,
        remembered.map(|(report, _)| report),
        unreadable,
        args.fail_on_suspicious,
    ))
}

/// The exit code for a run, from both kinds of result.
///
/// # Why the memory verdict is a term in the same sum
///
/// A script calling this binary needs one number that answers "is this machine
/// well", and a run that examined files and processes has two answers that can
/// disagree. Reporting only the files' would let a run that found malicious code
/// in a running process exit 0 because the directory it was pointed at was
/// clean, which is the worst outcome a scanner can produce: the caller acts on
/// the answer and the answer was about something else.
///
/// The file verdicts are fed in unchanged, so the existing ladder — malicious
/// outranks everything, `--fail-on-suspicious` promotes the middle band, an
/// unreadable file is a failure unless something malicious was found — keeps its
/// meaning. The memory verdict joins that ladder rather than competing with it:
/// an incomplete memory scan is `Unknown`, and `Unknown` is a failure for the
/// same reason an unreadable file is, because in both cases the scan did not
/// look at something it set out to look at.
///
/// A function rather than four lines inside `run` so that it can be tested as
/// the thing it is. The alternative — leaving it inline and testing a copy of
/// it — is how the exit code and the report drift apart.
fn overall_exit(
    findings: &[FileScanReport],
    memory: Option<&MemoryReport>,
    unreadable: usize,
    fail_on_suspicious: bool,
) -> Exit {
    let mut verdicts: Vec<Verdict> = findings.iter().map(|r| r.verdict()).collect();
    if let Some(memory) = memory {
        verdicts.push(memory.verdict());
    }
    let mut exit = Exit::from_verdicts(verdicts, fail_on_suspicious);
    if unreadable > 0 && exit != Exit::Malicious {
        // A scan that could not read something has not proven anything about
        // it, and a script that treats code 0 as "this tree is clean" would be
        // reading more into the answer than the scan produced. A malicious
        // finding still outranks it, because "there was malware" is the more
        // urgent of the two things the caller needs to know.
        exit = Exit::Failure;
    }
    exit
}

/// Scan every file, in parallel, preserving the walk's order.
fn scan_all(
    engine: &ScanEngine,
    files: &[std::path::PathBuf],
    options: &ScanOptions,
    progress: &Progress,
    args: &ScanArgs,
    stop: &AtomicBool,
) -> Vec<Outcome> {
    let stop_early = args.stop_on_first;
    files
        .par_iter()
        .map_init(
            || engine.scanner(),
            |scanner, path| {
                // A worker checks the flag before opening a file and never
                // during: the files already in flight finish, which is what
                // makes `--stop-on-first` mean "stop soon" rather than "abandon
                // a half-read file". The count of files that run after the flag
                // is set is bounded by the number of workers.
                if stop_early && stop.load(Ordering::Relaxed) {
                    return Outcome::Clean {
                        declined_members: 0,
                        cleared: false,
                    };
                }
                let outcome = scan_one(engine, scanner, path, options, progress);
                if stop_early {
                    if let Outcome::Found(ref report) = outcome {
                        if report.verdict() == Verdict::Malicious {
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                }
                outcome
            },
        )
        .collect()
}

/// Scan one file.
fn scan_one(
    engine: &ScanEngine,
    scanner: &mut Scanner<'_>,
    path: &Path,
    options: &ScanOptions,
    progress: &Progress,
) -> Outcome {
    let cap = options.max_file_size;
    let data = match read_capped(path, cap) {
        Ok(data) => data,
        Err(e) => {
            let reason = format!("{}: {e}", path.display());
            // Counted as a file looked at, because it was: the walk found it and
            // the read was attempted. Leaving it out of the total would make the
            // summary's count disagree with the walk's.
            progress.file(&path.to_string_lossy(), 0);
            return Outcome::Unreadable(reason);
        }
    };
    let size = data.len() as u64;

    let mut options = options.clone();
    // The walk has already refused anything above the limit, so the engine's
    // own cap can only truncate a file that grew between the walk and the read
    // — and that file is reported by `read_capped` rather than scanned
    // partially. Clearing the cap makes that the only path.
    options.max_file_size = None;

    let report = engine.scan_with(scanner, path, &data, &options);
    progress.file(&path.to_string_lossy(), size);
    // Before the verdict is looked at, because a recognised file's verdict is
    // `Clean` and its one detection is informational: every test below this line
    // would file it as a file that was examined and had nothing in it.
    if av_scan::own::is_product_file(&report) {
        return Outcome::Own(Box::new(report));
    }
    if av_scan::own::is_foreign_rule_source(&report) {
        return Outcome::Source(Box::new(report));
    }
    if report.is_detection() {
        progress.finding();
        Outcome::Found(Box::new(report))
    } else {
        // An `Unknown` verdict is not a detection, and it is not clean either.
        // It is reported, because a file the engine could not vouch for is
        // exactly what a user needs to be told about.
        if report.verdict() == Verdict::Unknown {
            progress.finding();
            return Outcome::Found(Box::new(report));
        }
        // Nothing found in this file, and the two things about it that are
        // still worth the user's attention, both read here because the report
        // is about to be dropped: members that no rule was run against, and
        // whether trust is the reason the verdict is clean rather than the
        // absence of matches. The verdict is already known to be `Clean` at
        // this point — `Unknown` returned above and everything else is a
        // detection — so the flag alone is the answer.
        Outcome::Clean {
            declined_members: av_scan::own::declined_members(&report),
            cleared: report.assessment.remediation_withheld,
        }
    }
}

/// Read a file, refusing rather than truncating one that grew past the limit.
///
/// `cap` is `None` when the user set no limit, and nothing here invents one: a
/// scanner that quietly declines to read a large file is a scanner that
/// silently stops scanning, and the user who set no limit asked for the file.
///
/// # Why this is no longer `File::open` followed by `read_to_end`
///
/// It was, and it was wrong in a way that produced a clean-looking report.
/// `std::fs::File::open` obeys the file's DACL, so `wenle scan C:\` skipped
/// every file this account may not read — another user's profile, `System
/// Volume Information`, `C:\ProgramData\Microsoft\Windows Defender`, anything
/// quarantined — and skipped it as an `Err` that the caller above turns into an
/// unreadable-file line rather than a finding. On a machine where the account
/// is not elevated that is most of where a payload would be. See
/// [`av_fs::read_capped`], which reads through `SeBackupPrivilege` when the
/// token holds it and says exactly which of the two happened when it does not.
///
/// The cap keeps its meaning and gains precision: [`av_fs::Why::Grew`] still
/// distinguishes "it grew after the walk measured it" from "this product will
/// not hold a file this big", which is the distinction this comment used to
/// spell out by hand.
///
/// The return type carries a reservation against the process's scan-memory
/// budget, released when the value is dropped. This wrapper exists so the
/// reservation's lifetime is the scan of one file and nothing wider: the caller
/// below drops it when it drops the bytes, which is after the verdict is made.
fn read_capped(path: &Path, cap: Option<u64>) -> std::io::Result<av_fs::Held> {
    av_fs::read_capped(path, cap)
}

/// The scan options this run will actually use.
fn effective_options(args: &ScanArgs, context: &Context) -> ScanOptions {
    // `--deep` replaces the configuration's scanning section wholesale rather
    // than layering on it: "deep" has to mean the same thing on every machine,
    // and a machine whose configuration lowered the archive depth would
    // otherwise make it mean something else.
    let mut options = if args.deep {
        ScanOptions::deep()
    } else {
        context.config.scan_options()
    };

    if args.no_recursive {
        options.recursive = false;
    } else if args.recursive {
        options.recursive = true;
    }
    if args.follow_links {
        options.follow_links = true;
    }
    if let Some(max) = args.max_size {
        options.max_file_size = Some(max);
    }
    if let Some(seconds) = args.timeout {
        options.per_file_timeout = Some(Duration::from_secs(seconds));
    }
    if args.no_heuristics {
        options.heuristics = false;
    }
    if args.no_trust {
        options.trust = false;
    }
    if args.stop_on_first {
        options.stop_on_first = true;
    }
    // The one option here that the engine does not act on: `av-scan` cannot
    // honour `memory`, because it is handed bytes and cannot open a process, so
    // the field is read by the layer that owns a process list — which is this
    // one. It is still written into the options the run uses rather than kept in
    // a variable beside them, so that "what did this run ask for" has one answer
    // and the memory sweep cannot run in a state the options deny.
    //
    // Both directions, in the order written, the same as `--recursive` and
    // `--no-recursive`: a flag that could only turn the feature on would leave a
    // user whose configuration asked for it unable to run one scan without it,
    // and the configuration is read by the service and the graphical front end
    // as well as by this command.
    if args.no_memory {
        options.memory = false;
    } else if args.memory {
        options.memory = true;
    }
    options
}

/// Build the engine the flags and the configuration describe.
///
/// The two booleans are what the caller's own interface asked for rather than
/// fields of `ScanArgs`, because `wenle memory` builds an engine too: a file
/// examined because a memory finding pointed at it must be examined with the
/// same thresholds, the same heuristics and the same trust policy a file the
/// walker found gets, and the only way to be sure of that is for both callers to
/// go through here. See [`crate::commands::memory`].
pub(crate) fn build_engine(
    database: av_rules::database::RuleDatabase,
    context: &Context,
    options: &ScanOptions,
    all_digests: bool,
    use_catalog: bool,
) -> ScanEngine {
    let thresholds: VerdictThresholds = context.config.scanning.thresholds;
    let heuristics = if options.heuristics {
        HeuristicConfig::default()
    } else {
        HeuristicConfig::disabled()
    };
    let trust = TrustPolicy {
        enabled: options.trust,
        ..TrustPolicy::default()
    };
    let catalog = catalog_index(use_catalog, trust.enabled, &context.paths.cache_dir);
    // `--json` means the report is the deliverable, and a report whose hashes
    // are missing is a report a support case cannot use. Otherwise only the
    // digests some rule actually names are computed.
    let digests = if all_digests {
        DigestPolicy::All
    } else {
        DigestPolicy::Needed
    };
    ScanEngine::new(database)
        .with_thresholds(thresholds)
        .with_heuristics(heuristics)
        .with_trust(trust)
        .with_digests(digests)
        .with_catalog(catalog)
}

/// The catalog store's digests, when trust is on and they can be read.
///
/// # Why this is worth a second of startup on every scan
///
/// Measured on a clean installation: a scan of `System32` produces 758 findings,
/// 750 of them suspicious — and 742 of those files are catalog-signed. Microsoft
/// does not put its own binaries in its catalogs by accident; a file listed in
/// one is a file Microsoft shipped, and the heuristics firing on them are
/// correctly describing how Microsoft built them. Without this index the product
/// shows a user 750 warnings on an untouched machine, which teaches them to
/// dismiss all 750 including the one that matters.
///
/// # Why it is not an error when it fails
///
/// The store may be absent, unreadable, or on a machine that is not Windows at
/// all — this crate builds and runs on Linux for the differential tests. A scan
/// that refused to start because it could not read a catalog would be a scan
/// that does not run, and running with weaker evidence is strictly better than
/// not running. The counters are logged so that "why was nothing cleared" has an
/// answer that is not a guess.
///
/// # Why it is not built at all when trust is off
///
/// `--no-trust` means the user asked for the raw answer: what did the rules and
/// the heuristics say about these bytes, with nothing subtracted. Building an
/// index that nothing would consult would spend 1.1 GB of reads to honour a flag
/// by ignoring it.
///
/// # Why the build is the cached one
///
/// `from_store` re-reads and re-parses all 7,300 catalogs on every invocation —
/// measured at 1.7 s with the store in the page cache and 5.8 s without it,
/// against 34 ms of everything else a scan of one small file does.
/// [`CatalogIndex::from_store_cached`] reads the index the previous run left in
/// the cache directory when the store has not changed since, and falls back to
/// the full build when it has. The store is still enumerated every run, so a
/// catalog that was added, removed or rewritten is still noticed; only the DER
/// parse of 1.2 GB is skipped. `cache_dir` is where the file goes, and it is the
/// product's own directory — the `, from cache` suffix in the line below is how
/// an operator sees which of the two happened.
fn catalog_index(
    use_catalog: bool,
    trust_enabled: bool,
    cache_dir: &Path,
) -> Option<Arc<CatalogIndex>> {
    if !trust_enabled || !use_catalog {
        return None;
    }
    let started = Instant::now();
    match CatalogIndex::from_store_cached(cache_dir) {
        Ok(index) if !index.is_empty() => {
            log::info!(
                "catalog store: {} catalogs read ({} refused, {} oversized), {} digests, {:?}{}",
                index.catalogs_read(),
                index.catalogs_refused(),
                index.catalogs_oversized(),
                index.digest_count(),
                started.elapsed(),
                if index.cache_hit() {
                    ", from cache"
                } else {
                    ", rebuilt"
                },
            );
            Some(Arc::new(index))
        }
        Ok(_) => None,
        Err(error) => {
            // Not fatal, and not silent either. An operator who expected the
            // trust layer to clear Microsoft's binaries and sees them reported
            // needs this line to find out why.
            log::warn!("no catalog index: {error}");
            None
        }
    }
}

/// Add the configured exclusions to whatever the user named.
///
/// The configuration's exclusion list is applied here rather than in the walk
/// because it is a list of *paths*, not of patterns, and a path that does not
/// exist is not an error — it is an exclusion for a program that is not
/// installed.
fn expand(
    paths: &[std::path::PathBuf],
    excluded: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    paths
        .iter()
        .filter(|path| {
            !excluded
                .iter()
                .any(|skip| path.starts_with(skip) || *path == skip)
        })
        .cloned()
        .collect()
}

/// Say what the walk could not reach, according to `--on-error`.
fn report_walk_problems(outcome: &walk::WalkOutcome, on_error: OnError, quiet: bool) {
    if quiet || on_error == OnError::Ignore {
        return;
    }
    for problem in &outcome.unreadable {
        output::warn(problem);
        if on_error == OnError::Stop {
            break;
        }
    }
}

/// What the vault did with one finding.
#[derive(Debug)]
struct Taken {
    /// The file it is about, so the report can find the note by path.
    path: std::path::PathBuf,
    /// The line shown under the finding: `quarantined as 3f9ac1b0`, or why not.
    note: String,
    /// True when the bytes are in the vault, which is the only thing that
    /// counts as having done something about the file.
    sealed: bool,
}

/// The note for a finding, if the quarantine pass had anything to say about it.
fn note_for<'a>(taken: &'a [Taken], path: &Path) -> Option<&'a Taken> {
    taken.iter().find(|t| t.path == path)
}

/// Move every malicious finding into the vault, and remember what happened.
///
/// # Why only the malicious band
///
/// `Suspicious` means "worth telling you about, not worth acting on". That is
/// the contract the threshold model makes with the user, and a scan that
/// quarantined a suspicious file would be a scan that broke it — on a machine
/// with a compiler on it, that is a scan that removes a toolchain. The two
/// bands exist precisely so that this function can be written with one word in
/// the condition and no judgement calls.
///
/// # Why the failures are reported rather than returned
///
/// A file that could not be taken is still malicious and still on disk, and the
/// finding has already been printed as malicious either way. Turning that into a
/// command-level error would replace the report with one error message and lose
/// the other four hundred findings in the same run. The note under the finding
/// says what happened, and the exit code is already the one for "there was
/// malware here".
fn quarantine_findings(
    findings: &[FileScanReport],
    context: &Context,
    globals: &Globals,
) -> Result<Vec<Taken>> {
    // Nothing to do is settled before the vault is opened, and that ordering is
    // the point: opening a vault creates the directory and, on a machine that
    // has never quarantined anything, generates a master key. A scan of a clean
    // tree that was merely *asked* to quarantine should not leave a vault behind
    // as a side effect.
    if !findings.iter().any(|r| r.verdict() == Verdict::Malicious) {
        return Ok(Vec::new());
    }
    let mut vault = context.open_vault(None)?;
    let mut taken = Vec::new();

    for report in findings {
        if report.verdict() != Verdict::Malicious {
            continue;
        }
        let quarantine_context =
            av_quarantine::QuarantineContext::from_report(report, av_quarantine::EntrySource::Scan);
        match vault.quarantine_file(&report.path, &quarantine_context) {
            Ok(entry) => {
                if !globals.quiet {
                    // The identifier is printed because it is what the user
                    // types into `wenle quarantine restore` — the whole point of
                    // acting on the file is being able to undo it.
                    output::warn(&format!(
                        "{} was quarantined as {}; `wenle quarantine restore {}` puts it back",
                        report.path.display(),
                        entry.id.short(),
                        entry.id.short(),
                    ));
                }
                taken.push(Taken {
                    path: report.path.clone(),
                    note: format!("quarantined as {}", entry.id.short()),
                    sealed: true,
                });
            }
            Err(error) => {
                let reason = format!("could not be quarantined: {error}");
                output::error(&format!("{}: {reason}", report.path.display()));
                taken.push(Taken {
                    path: report.path.clone(),
                    note: reason,
                    sealed: false,
                });
            }
        }
    }
    Ok(taken)
}

/// A sortable rank for a verdict: the strongest first.
fn rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Unknown => 1,
        Verdict::Clean => 0,
    }
}

/// One finding, as a person reads it.
fn print_finding(report: &FileScanReport, taken: &[Taken]) {
    output::finding(
        &report.path.to_string_lossy(),
        report.verdict(),
        report.assessment.score,
        &report.assessment.detections,
    );
    // Why nothing will be done about it, when trust is the reason. A finding
    // that is in the suspicious band and will not be quarantined reads as a bug
    // in the report unless the report says which evidence held it there — and
    // the same lines are what make a `clean` verdict beside a nonzero score
    // legible instead of contradictory.
    for line in output::trust_lines(&report.assessment) {
        println!("{line}");
    }
    // A file that could not be looked at properly says why. Without this the
    // line reads like a detection with no detections under it.
    if let Some(error) = &report.error {
        println!("             {}", console::style(error).dim());
    }
    // What was done about it, on the finding's own line, in the colour that
    // matches what happened: green when the file is in the vault, yellow when it
    // is not and the user has to do something themselves.
    if let Some(taken) = note_for(taken, &report.path) {
        let style = if taken.sealed {
            console::style(&taken.note).green()
        } else {
            console::style(&taken.note).yellow().bold()
        };
        println!("             {style}");
    }
}

/// The totals, after the findings.
fn print_summary(
    findings: &[FileScanReport],
    coverage: &Coverage,
    elapsed: Duration,
    unreadable: usize,
    quarantined: Option<&[Taken]>,
    memory: Option<(&MemoryReport, Duration)>,
    cleared: usize,
) {
    let malicious = findings
        .iter()
        .filter(|r| r.verdict() == Verdict::Malicious)
        .count();
    let suspicious = findings
        .iter()
        .filter(|r| r.verdict() == Verdict::Suspicious)
        .count();
    let unknown = findings
        .iter()
        .filter(|r| r.verdict() == Verdict::Unknown)
        .count();

    let scanned = coverage.scanned;
    let seconds = elapsed.as_secs_f64();
    let rate = if seconds > 0.0 {
        human_count((scanned as f64 / seconds) as u64)
    } else {
        human_count(scanned as u64)
    };

    output::heading("Result");
    println!(
        "  {} scanned  {}  in {:.1}s ({rate}/s)",
        human_count(scanned as u64),
        human_bytes(coverage.bytes),
        seconds,
    );
    // The files taken out of the two totals above, named so that the arithmetic
    // adds up for a reader comparing the count against the files they pointed
    // the scan at. Without these lines a scan of a folder holding one rule
    // source prints `0 scanned  0 B` and leaves the user to work out where their
    // file went; with them, the run says what it did with it.
    //
    // Built by [`declined_lines`] rather than written out here so that the three
    // sentences are testable. Which words go in front of which number is the
    // part that has been wrong before: one identifier for two different declines
    // is how a run came to call a downloaded corpus this product's own data, and
    // how it came to report an archive it had walked as a file it never opened.
    for line in declined_lines(&coverage.declined) {
        println!("  {line}");
    }
    if coverage.skipped > 0 {
        println!(
            "  {} skipped by a filter (size limit or --exclude)",
            human_count(coverage.skipped)
        );
    }
    if unreadable > 0 {
        println!("  {} could not be read", human_count(unreadable as u64));
    }

    // The memory totals, in the one place both kinds of result meet. Deliberately
    // not folded into the file counts above: `N scanned` is files, and a reader
    // adding processes to it would be adding two different units. What the verdict
    // line does with these is in [`verdict_line`].
    if let Some((report, spent)) = memory {
        let summary = report.summary();
        let found = report.processes_with_findings();
        println!(
            "  {} process(es) examined in memory: {} region(s) read ({}), {} process(es) could \
             not be examined{}",
            human_count(summary.processes_examined),
            human_count(summary.regions_read),
            human_bytes(summary.bytes_read),
            human_count(summary.processes_refused()),
            if spent.as_secs_f64() >= 0.05 {
                format!(" — {:.1}s", spent.as_secs_f64())
            } else {
                String::new()
            },
        );
        if found > 0 {
            println!(
                "  {} process(es) produced a memory finding; see the section above",
                human_count(found)
            );
        }
    }

    let line = verdict_line((malicious, suspicious, unknown), memory, coverage);
    println!("{line}");
    // Before the sentence about the suspicious band, because it is the same kind
    // of fact about the same list of files and it explains the count above it.
    if let Some(line) = cleared_line(cleared) {
        println!("  {line}");
    }
    if suspicious > 0 && malicious == 0 {
        // The band's whole purpose, said in the place the user is looking. A
        // user who reads "suspicious" as "infected" quarantines a tool they
        // need; one who reads it as "nothing" ignores a warning they should
        // have read.
        println!(
            "  Suspicious files were reported and not acted on. That band means the file is \
             worth a look, not that it is malware."
        );
    }
    // The same explanation for the other kind of finding, and a separate
    // sentence rather than a general one, because the two are true about
    // different subjects and a shared sentence would have to say "target" to
    // cover both. A user who sees a yellow line under `Process memory` and no
    // note under it has read a colour with no key.
    if malicious == 0 && memory.is_some_and(|(report, _)| report.verdict() == Verdict::Suspicious) {
        println!(
            "  A process was reported as suspicious and nothing was done about it. Nothing is \
             done about a running process whatever the verdict, and the band means the region is \
             worth a look, not that it is malware."
        );
    }
    match quarantined {
        Some(taken) if !taken.is_empty() => {
            let sealed = taken.iter().filter(|t| t.sealed).count();
            let failed = taken.len() - sealed;
            // Said as two numbers rather than one because they mean opposite
            // things, and a user who reads "12 quarantined" when 3 of them
            // could not be taken has been told something false about 3 files.
            output::heading("Quarantine");
            println!("  {sealed} files moved into the vault");
            if failed > 0 {
                output::warn(&format!(
                    "{failed} could not be taken and are still on disk, in the same place \
                     they were; the errors above say why"
                ));
            }
        }
        Some(_) if suspicious > 0 => {
            // Asked to act, and the only thing found was in the band that is
            // never acted on. Said out loud because `--quarantine` on a run that
            // reports a yellow `suspicious` with no green note underneath looks
            // like the option failed, and the user's next move would be to go
            // looking for the files.
            output::warn(&format!(
                "nothing was quarantined: all {suspicious} findings are in the suspicious \
                 band, which is reported and never acted on. Those files are still where \
                 they were, and that is what this result means."
            ));
        }
        _ => {}
    }
}

/// The lines naming what the engine recognised and did not run a rule against.
///
/// # Why three lines and not one
///
/// Because they are three different claims, and a summary that merged them would
/// be telling the user something untrue:
///
/// * this product's own data, by digest — a checkable statement about bytes, and
///   the file is out of the examined totals;
/// * a rule source this product did not write — a statement about a stranger's
///   file, also out of those totals;
/// * a rule source inside a file that *was* examined — nothing is out of the
///   totals for this one, because the container it was found in was opened,
///   walked and scanned, and the count is there so that the part of it nobody
///   read is not silently passed over.
///
/// The third line is why the function exists at all. It has no byte figure and
/// says "inside archives" rather than "files", because it is a count of members
/// and the two lines above it are counts of files; a reader who took it for a
/// fourth file count would be reading a number about the inside of a file as a
/// number of files.
fn declined_lines(declined: &Declined) -> Vec<String> {
    let mut lines = Vec::new();
    if declined.own > 0 {
        lines.push(format!(
            "{} this product's own data, not examined ({})",
            if declined.own == 1 {
                "1 file is".to_owned()
            } else {
                format!("{} files are", human_count(declined.own as u64))
            },
            human_bytes(declined.own_bytes),
        ));
    }
    if declined.sources > 0 {
        lines.push(format!(
            "{} rule source(s) this product did not write, not examined ({})",
            human_count(declined.sources as u64),
            human_bytes(declined.source_bytes),
        ));
    }
    if declined.members > 0 {
        lines.push(format!(
            "{} rule source(s) inside archives, not examined",
            human_count(declined.members as u64),
        ));
    }
    lines
}

/// The line for the files the rules matched and trust cleared, or `None`.
///
/// # Why a run reports these at all
///
/// Because without the line the effect of trust is invisible, and invisibility
/// is the wrong property for it. A scan of `System32` on a clean installation
/// matches rules in 742 files; after trust, all 742 are clean and the run says
/// "Nothing found." — which is the right verdict and an incomplete report. A
/// user who changes a threshold, adds a rule, or wonders why a file they know
/// matched is not listed has no way to tell "no rule matched" from "rules
/// matched, and a catalogue entry overruled them".
///
/// A count and not a list, deliberately. The whole point of clearing these files
/// is that listing them is what trained users to ignore 750 warnings, and a run
/// that printed 742 paths under a "clean" summary would be that report again
/// with a different heading.
///
/// `None` rather than an empty string at zero, so that a run which cleared
/// nothing — every run on a machine with nothing signed on it — says nothing at
/// all about this.
fn cleared_line(cleared: usize) -> Option<String> {
    if cleared == 0 {
        return None;
    }
    // The pronoun agrees with the count, and it is spelled out rather than
    // reached for through `count_of_pair`, which puts the count in front of the
    // word and would render this one as `1 it`. The window's sentence is this
    // one word for word — see `av-gui`'s `format::cleared_line` — because two
    // front ends reporting one scan differently is a thing the user who ran both
    // is the one who notices.
    let pronoun = if cleared == 1 { "it" } else { "them" };
    Some(format!(
        "{} cleared rather than passed: the rules matched, the bytes are the ones a signed \
         catalogue lists, and everything found describes how the file was built rather than what \
         it is. Nothing was done about {pronoun}.",
        if cleared == 1 {
            "1 file was".to_owned()
        } else {
            format!("{} files were", human_count(cleared as u64))
        },
    ))
}

/// The one line that says what the whole run concluded.
///
/// # Why this is a function and not four arms inside `print_summary`
///
/// Because it is the line a user and a script both read, and it is the line with
/// the most ways to be wrong: it has to reconcile two kinds of result that are
/// counted in different units, and the failure mode is not a crash but a
/// sentence that is untrue — "Nothing found." printed directly beneath a section
/// that found something. A function that returns the line can be asserted as
/// text, which is how the contradiction above was caught; four arms inside a
/// printer can only be checked by running the program and looking.
///
/// The three facts about the memory half are separate because they are separate
/// answers: whether it ran at all (`memory` being `None`), whether it saw
/// everything it was given, and whether it found anything.
///
/// The coverage is a fourth input for the same reason: "nothing found" over a
/// run that examined no file is a true sentence about the findings and a false
/// one about the scan, and the line has to be able to tell those apart.
fn verdict_line(
    (malicious, suspicious, unknown): (usize, usize, usize),
    memory: Option<(&MemoryReport, Duration)>,
    coverage: &Coverage,
) -> String {
    let incomplete = memory.is_some_and(|(report, _)| report.verdict() == Verdict::Unknown);
    let found = memory.is_some_and(|(report, _)| report.processes_with_findings() > 0);

    // What the file half has to say, as a clause the memory half is appended to.
    //
    // One clause and not two, because the two sentences differ in their subject
    // rather than in their facts: "nothing found in the files" is a claim about
    // files that were looked at, and it is false of a run that examined none.
    // The case is a declined file — a user scans a folder holding a copy of the
    // rule corpus, the engine declines the only file in it, and the run arrives
    // here with a clean verdict over zero files — and it is the same false bill
    // of health the summary line above stopped printing. With the clause hoisted,
    // all three arms below say the true thing.
    //
    // The subject is named from what was declined rather than assumed, because
    // the two are not the same sentence: "this product's own data" is true of a
    // scan of our own rules and false of a scan of somebody else's, and a user
    // who scanned a folder of downloaded corpora is owed the second one.
    let files = match coverage.declined.phrase() {
        Some(what) if coverage.examined_nothing() => format!(
            "No file was examined: the ones here are {what}, and a rule source is not run \
             against itself"
        ),
        _ => "Nothing found in the files".to_owned(),
    };

    match (malicious, suspicious, unknown) {
        // Nothing in either half, and the memory scan saw everything it was
        // given. The only case in which a run can say "nothing" unqualified.
        (0, 0, 0) if !incomplete && !found => {
            if coverage.examined_nothing() {
                console::style(format!("  {files}."))
                    .magenta()
                    .bold()
                    .to_string()
            } else {
                console::style("  Nothing found.").green().bold().to_string()
            }
        }
        // The memory scan ran and could not examine everything. "Nothing found"
        // here would be the report answering a question it was never able to
        // ask, so the answer says what is actually known.
        (0, 0, 0) if incomplete => console::style(format!(
            "  {files}, and the memory scan could not examine every process."
        ))
        .magenta()
        .to_string(),
        // Nothing in the files, but something in a process. The findings are not
        // added to the file counts, because a process is not a file; the line
        // names the units instead.
        (0, 0, 0) => {
            let found = memory.map_or(0, |(report, _)| report.processes_with_findings());
            let examined = memory.map_or(0, |(report, _)| report.summary().processes_examined);
            let verdict = memory
                .map(|(report, _)| report.verdict())
                .unwrap_or(Verdict::Clean);
            output::verdict_style(verdict)
                .apply_to(format!(
                    "  {files}; the memory scan found something in {} of {} \
                     process(es) examined.",
                    human_count(found),
                    human_count(examined),
                ))
                .to_string()
        }
        (m, s, u) => {
            let mut parts = Vec::new();
            if m > 0 {
                parts.push(
                    console::style(format!("{m} malicious"))
                        .red()
                        .bold()
                        .to_string(),
                );
            }
            if s > 0 {
                parts.push(
                    console::style(format!("{s} suspicious"))
                        .yellow()
                        .bold()
                        .to_string(),
                );
            }
            if u > 0 {
                parts.push(
                    console::style(format!("{u} could not be completed"))
                        .magenta()
                        .to_string(),
                );
            }
            if incomplete {
                parts.push(
                    console::style("memory: not every process examined")
                        .magenta()
                        .to_string(),
                );
            }
            format!("  {}", parts.join("   "))
        }
    }
}

/// The whole scan as one JSON document.
///
/// Findings are the same [`FileScanReport`] the library produces, serialised
/// unchanged, so a machine reading this gets exactly what a person reading the
/// text output got — and a field added to the report appears here without
/// anyone remembering to add it.
///
/// # Why `memory` is a separate array and not more entries in `findings`
///
/// Because a consumer that walks `findings` expecting a `path` on every entry is
/// right to: every entry there is a file, and a scan that is not looking at
/// files does nothing. A memory entry has no path, cannot have one, and would
/// either break that consumer or force it to guess by shape. Two arrays, two
/// subjects, and `memory` is present only when `--memory` was asked for — the
/// same reason `quarantine` is only present when it was: a consumer has to be
/// able to tell "this run did not do that" from "it did that and found nothing".
// One argument per subject the document reports on, which is one more than
// clippy's threshold. Bundling them into a struct would be a second name for the
// document's own shape — every field would be a section, and the struct would
// exist only to be destructured again a few lines later — so the count is the
// honest shape here rather than something to hide.
#[allow(clippy::too_many_arguments)]
fn print_json(
    findings: &[FileScanReport],
    coverage: &Coverage,
    elapsed: Duration,
    quarantined: Option<&[Taken]>,
    memory: Option<(&MemoryReport, Duration)>,
    chain: Option<&memory::Chain>,
    rules: &RulesUsed,
    cleared: usize,
) -> Result<()> {
    let mut document = serde_json::json!({
        "tool": "wenle",
        "version": env!("CARGO_PKG_VERSION"),
        "scanned": coverage.scanned,
        "bytes": coverage.bytes,
        // Named rather than left out of the two figures above without a word,
        // because a consumer comparing `scanned` against the number of files it
        // asked about needs to know where the rest went, and "the scanner
        // silently ignored my files" is the wrong conclusion to draw from an
        // engine declining to run its own rules against themselves.
        "own_files": coverage.declined.own,
        "own_bytes": coverage.declined.own_bytes,
        // And separately, because a consumer that treats them as one number
        // would be reading a stranger's rule file as this product's own data.
        "rule_source_files": coverage.declined.sources,
        "rule_source_bytes": coverage.declined.source_bytes,
        // And a third, which is not a file count and is not the same claim as
        // either above: rule sources the engine declined inside files it did
        // examine. Those files are inside `scanned` and `bytes`, which is why
        // this number does not move either of them; it says that part of what
        // was read was not run past a rule.
        "rule_source_members": coverage.declined.members,
        "skipped": coverage.skipped,
        "unreadable": coverage.unreadable,
        // Files inside `scanned` whose rules matched and whose verdict trust
        // cleared. Counted here for the same reason the text report prints it:
        // a consumer that sees `scanned: 4426` and no findings cannot otherwise
        // tell a tree nothing matched from a tree where 742 files matched and
        // were overruled, and those are different facts about the rule set.
        "cleared": cleared,
        "duration_ms": elapsed.as_millis() as u64,
        // Which rules produced the findings above. A report is only usable by
        // whoever reads it if they can tell what it was produced with, and a
        // count on its own does not say that: two databases can hold the same
        // number of rules and differ in which ones.
        "rules": rules.json(),
        "findings": findings,
    });
    if let Some((report, spent)) = memory {
        document["memory"] = crate::memory::json(report, spent, chain);
    }
    // Only present when `--quarantine` was asked for, so that a consumer can
    // tell "this build did not act" from "it acted and took nothing" — the same
    // distinction the text output makes.
    if let Some(taken) = quarantined {
        let sealed = taken.iter().filter(|t| t.sealed).count();
        document["quarantine"] = serde_json::json!({
            "requested": true,
            "sealed": sealed,
            "failed": taken.len() - sealed,
            "items": taken
                .iter()
                .map(|t| serde_json::json!({
                    "path": t.path,
                    "sealed": t.sealed,
                    "detail": t.note,
                }))
                .collect::<Vec<_>>(),
        });
    }
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_core::{Assessment, Digests, FileKind};
    use av_memory::{
        Interest, MemoryError, MemoryFinding, MemoryScanReport, Origin, ProcessOutcome, ProcessRef,
        ProcessScan,
    };

    /// A run that was given files and declined none of them.
    ///
    /// The neutral coverage for the tests that are about the memory half: no
    /// file was recognised as the product's own, so every clean sentence the
    /// result line can print is true of this run.
    fn nothing_declined() -> Coverage {
        covered((100, 1_000_000), Declined::default())
    }

    /// A run's coverage, in the two things the summary distinguishes: what was
    /// examined, and what the engine declined.
    fn covered(examined: (usize, u64), declined: Declined) -> Coverage {
        Coverage {
            scanned: examined.0,
            bytes: examined.1,
            declined,
            skipped: 0,
            unreadable: Vec::new(),
        }
    }

    /// The engine declined one file of the given size as this product's own.
    fn declined_own(bytes: u64) -> Declined {
        Declined {
            own: 1,
            own_bytes: bytes,
            ..Declined::default()
        }
    }

    /// The engine declined one file of the given size as somebody else's rule
    /// source.
    fn declined_source(bytes: u64) -> Declined {
        Declined {
            sources: 1,
            source_bytes: bytes,
            ..Declined::default()
        }
    }

    /// The engine declined rule sources inside files it did examine.
    fn declined_members(count: usize) -> Declined {
        Declined {
            members: count,
            ..Declined::default()
        }
    }

    #[test]
    fn a_member_declined_inside_a_file_does_not_take_the_file_out_of_the_totals() {
        // The defect the member count was added for, as arithmetic. A 22.09 MiB
        // archive whose members were walked and whose own bytes were read: the
        // run examined one file and 22.09 MiB, and one rule source inside it was
        // not examined. A run that subtracted the archive — which is what
        // reading the member's note as a note about the file did — reported
        // `0 scanned  0 B` for a file it had read from end to end.
        let walk = walk::WalkOutcome {
            files: vec![PathBuf::from("Rust-antivirus-main (1).zip")],
            bytes: 23_161_231,
            skipped: 0,
            unreadable: Vec::new(),
        };
        let coverage = Coverage::of(&walk, declined_members(1));

        assert_eq!(coverage.scanned, 1);
        assert_eq!(coverage.bytes, 23_161_231);
        assert_eq!(coverage.declined.members, 1);
        assert!(
            !coverage.examined_nothing(),
            "a file was examined, so no clean sentence may say otherwise"
        );
    }

    #[test]
    fn the_member_line_is_a_count_of_members_and_not_a_count_of_files() {
        // The wording, which is the part a reader gets their arithmetic from.
        // The two lines above it end in a byte figure and count files; this one
        // has neither, and says where the members were found, so that a scan of
        // a folder of archives cannot be read as having skipped files.
        let lines = declined_lines(&declined_members(173));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("173 rule source(s) inside archives"), "{}", lines[0]);
        assert!(
            !lines[0].contains("not examined ("),
            "there is no size to put in brackets and a bracket invites one: {}",
            lines[0]
        );
    }

    #[test]
    fn a_run_that_cleared_nothing_says_nothing_about_clearing() {
        // The ordinary run on an ordinary machine, and it has to stay silent:
        // a line reading "0 files were cleared" would be a sentence about
        // something that did not happen, printed under every scan.
        assert_eq!(cleared_line(0), None);
    }

    #[test]
    fn a_run_that_cleared_files_says_how_many_and_why() {
        // The measured case: a scan of `System32` on a clean installation, where
        // 742 files match rules that describe how Microsoft built them. Without
        // this line the run reports "Nothing found." over 742 matches, which is
        // the right verdict and a report with a hole in it.
        let line = cleared_line(742).expect("a count above zero is a line");
        assert!(line.contains("742 files were"), "{line}");
        assert!(line.contains("catalogue"), "{line}");
        // What did *not* happen has to be in the sentence, because the reader's
        // alternative assumption is that they were quarantined.
        assert!(line.contains("Nothing was done"), "{line}");
        // The whole sentence at the count that reaches both traps in it at once,
        // `1 files were` and `about them`.
        assert_eq!(
            cleared_line(1).expect("one is a line"),
            "1 file was cleared rather than passed: the rules matched, the bytes are the ones a \
             signed catalogue lists, and everything found describes how the file was built rather \
             than what it is. Nothing was done about it."
        );
    }

    #[test]
    fn a_run_that_declined_nothing_prints_no_declined_line() {
        // The direction that keeps the ordinary run quiet. Every one of these
        // three lines is a sentence about something that did not happen unless
        // its count is above zero, and the overwhelmingly common run is the one
        // where none of them happened.
        assert!(declined_lines(&Declined::default()).is_empty());
    }

    #[test]
    fn the_three_declines_are_each_printed_and_stay_apart() {
        // All three at once, because the case a user hits is a folder holding
        // our corpus, a downloaded corpus, and an archive with one inside it.
        let mut declined = Declined::default();
        declined.own += 1;
        declined.own_bytes += 17_500_000;
        declined.sources += 2;
        declined.source_bytes += 900_000;
        declined.members += 4;

        let lines = declined_lines(&declined);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains("this product's own data"), "{}", lines[0]);
        assert!(
            lines[1].contains("rule source(s) this product did not write"),
            "{}",
            lines[1]
        );
        assert!(lines[2].contains("inside archives"), "{}", lines[2]);
        // And the one that must never be said about a stranger's corpus.
        assert!(!lines[1].contains("own data"), "{}", lines[1]);
    }

    /// A file report with the verdict asked for and nothing else.
    fn file(verdict: Verdict, path: &str) -> FileScanReport {
        let mut assessment = Assessment::clean();
        assessment.verdict = verdict;
        FileScanReport {
            path: std::path::PathBuf::from(path),
            kind: FileKind::Other,
            size: 1,
            digests: Digests::default(),
            assessment,
            duration: Duration::from_millis(1),
            scanned_bytes: 1,
            from_cache: false,
            error: None,
            archive: None,
        }
    }

    /// A memory scan that examined one process and found nothing in it.
    fn examined_nothing() -> MemoryReport {
        let mut report = MemoryScanReport::new();
        report.record(ProcessScan::Examined(Box::new(ProcessOutcome::new(
            ProcessRef::anonymous(4242),
        ))));
        MemoryReport::from_report(99, report)
    }

    /// A memory scan that found something of the given severity in one process.
    fn found(verdict: Verdict) -> MemoryReport {
        let process = ProcessRef::new(
            4242,
            Some(std::path::PathBuf::from(r"C:\victim\explorer.exe")),
        );
        let mut outcome = ProcessOutcome::new(process.clone());
        outcome.findings.push(MemoryFinding {
            process,
            base: 0x7ff6_a1b2_0000,
            region_size: 4096,
            bytes_read: 4096,
            truncated: false,
            interest: Interest::UnbackedCode,
            protection: av_memory::Protection::from_raw(0x20),
            kind: av_memory::RegionKind::Private,
            // The interest says nothing on disk backs these bytes, so the
            // origin has to agree: a fixture pairing `UnbackedCode` with a file
            // would be a shape the scanner cannot produce, and the rendering
            // tests below would then be testing against something impossible.
            origin: Origin::Nothing,
            verdict,
            score: 60,
            detections: Vec::new(),
        });
        let mut report = MemoryScanReport::new();
        report.record(ProcessScan::Examined(Box::new(outcome)));
        MemoryReport::from_report(99, report)
    }

    /// A memory scan whose only process could not be opened.
    fn refused() -> MemoryReport {
        let mut report = MemoryScanReport::new();
        report.record_refusal(
            ProcessRef::anonymous(4),
            &MemoryError::Denied {
                pid: 4,
                code: 5,
                message: "Access is denied.".to_string(),
            },
        );
        MemoryReport::from_report(99, report)
    }

    /// A rule set of the size asked for, read from a path.
    fn rules(count: usize, from: &str) -> RulesUsed {
        RulesUsed {
            count,
            database: PathBuf::from(from),
        }
    }

    #[test]
    fn the_line_says_which_database_the_rules_came_from() {
        // The whole point of printing it: the two candidates for a database are
        // a directory beside the binary and the installed product's, and this
        // is the only place a user can find out which one a run used. The path
        // is printed as it was found, so a test asserting the exact text is
        // asserting the exact claim the user reads.
        let line = rules(10_764, r"C:\ProgramData\WenleAV\db\rules.avdb").line();
        assert_eq!(
            line,
            r"10,764 rules from C:\ProgramData\WenleAV\db\rules.avdb"
        );
    }

    #[test]
    fn one_rule_is_not_printed_as_one_rules() {
        // Read most often during rule authoring, when the database holds the two
        // or three rules just written. "1 rules" is the kind of line that makes
        // a user doubt the count itself.
        assert_eq!(rules(1, "one.avdb").line(), "1 rule from one.avdb");
        assert!(rules(0, "empty.avdb").line().starts_with("0 rules from"));
    }

    #[test]
    fn the_json_report_names_the_database_and_the_count() {
        // A support case gets the report and nothing else, so the facts have to
        // be in it. A count alone does not identify a rule set: two databases
        // can hold the same number of rules and differ in which ones.
        let object = rules(42, r"D:\portable\data\db\rules.avdb").json();
        assert_eq!(object["count"], 42);
        assert_eq!(
            object["database"], r"D:\portable\data\db\rules.avdb",
            "the path reaches the report as a string, not as an array of \
             platform-specific path components"
        );
    }

    #[test]
    fn the_exit_code_follows_the_worst_verdict_across_files_and_processes() {
        let clean_files = vec![file(Verdict::Clean, "a.txt")];
        let malicious_file = vec![file(Verdict::Malicious, "b.exe")];

        // Nothing anywhere.
        assert_eq!(
            overall_exit(&clean_files, Some(&examined_nothing()), 0, false),
            Exit::Clean
        );
        // A process that could not be opened is a scan that could not be
        // completed — the same code an unreadable file produces, because it is
        // the same fact.
        assert_eq!(
            overall_exit(&clean_files, Some(&refused()), 0, false),
            Exit::Failure
        );
        // And a malicious file outranks that, because "there was malware" is the
        // more urgent of the two things the caller needs to know.
        assert_eq!(
            overall_exit(&malicious_file, Some(&refused()), 0, false),
            Exit::Malicious
        );
        // A malicious finding in a *process* exits 1 as well: the caller asked
        // about the machine, not about a directory.
        assert_eq!(
            overall_exit(&clean_files, Some(&found(Verdict::Malicious)), 0, false),
            Exit::Malicious
        );
        assert_eq!(
            overall_exit(&clean_files, Some(&found(Verdict::Malicious)), 0, true),
            Exit::Malicious
        );
        // The middle band keeps its meaning: reported, not acted on, and
        // promoted only when the caller asked to be strict about it.
        assert_eq!(
            overall_exit(&clean_files, Some(&found(Verdict::Suspicious)), 0, false),
            Exit::Clean
        );
        assert_eq!(
            overall_exit(&clean_files, Some(&found(Verdict::Suspicious)), 0, true),
            Exit::Suspicious
        );
        // A run that did not ask for memory scanning is the files' answer alone.
        assert_eq!(overall_exit(&clean_files, None, 0, false), Exit::Clean);
        assert_eq!(
            overall_exit(&malicious_file, None, 0, false),
            Exit::Malicious
        );
        // An unreadable file still fails a run whose memory half was complete.
        assert_eq!(
            overall_exit(&clean_files, Some(&examined_nothing()), 1, false),
            Exit::Failure
        );
    }

    #[test]
    fn the_result_line_never_says_nothing_found_over_a_memory_finding() {
        // The contradiction this function exists to prevent. A memory section
        // reporting a finding, followed by a green "Nothing found.", is the
        // report disagreeing with itself in two adjacent paragraphs — and the
        // green line is the one a user believes.
        let spent = Duration::from_millis(500);
        let clean_run = verdict_line((0, 0, 0), None, &nothing_declined());
        assert!(clean_run.contains("Nothing found."), "{clean_run}");

        let empty = examined_nothing();
        let quiet = verdict_line((0, 0, 0), Some((&empty, spent)), &nothing_declined());
        assert!(quiet.contains("Nothing found."), "{quiet}");

        let found = verdict_line(
            (0, 0, 0),
            Some((&found(Verdict::Suspicious), spent)),
            &nothing_declined(),
        );
        assert!(
            !found.contains("Nothing found."),
            "a run with a memory finding said nothing was found: {found}"
        );
        assert!(
            found.contains("the memory scan found something in 1 of 1 process(es) examined"),
            "the line must say where the answer came from: {found}"
        );

        // A gap is not a finding, and the two sentences are different because
        // the two facts are: one says "I could not see everything", the other
        // says "I saw something". A run that had a finding *and* a gap gets the
        // finding's sentence, because that is the more urgent of the two — the
        // gap is already on the totals line above it.
        let gap = verdict_line((0, 0, 0), Some((&refused(), spent)), &nothing_declined());
        assert!(gap.contains("could not examine every process"), "{gap}");
        assert!(
            !gap.contains("Nothing found."),
            "the unqualified sentence must not appear: {gap}"
        );
    }

    #[test]
    fn a_run_that_examined_no_file_does_not_say_nothing_was_found() {
        // The case this product's own data creates, measured on this machine: a
        // folder holding a copy of the rule corpus was scanned, the engine
        // recognised the only file in it and ran no rule against it, and the
        // result line said "Nothing found." over zero files. The sentence is
        // true about the findings and false about the scan, and the green line
        // is the one a user believes.
        let declined = covered((0, 0), declined_own(17_500_000));
        let line = verdict_line((0, 0, 0), None, &declined);
        assert!(
            !line.contains("Nothing found."),
            "a run that examined nothing claimed to have found nothing: {line}"
        );
        assert!(line.contains("No file was examined"), "{line}");
        assert!(
            line.contains("this product's own data"),
            "the line has to say why, or a user reads it as a failure: {line}"
        );
    }

    #[test]
    fn the_same_sentence_holds_when_the_memory_half_has_something_to_say() {
        // The file half examined nothing, and the memory half either found
        // something or could not see everything. Neither clause may carry the
        // words "nothing found in the files", which are a claim about files that
        // were looked at. The memory half's own facts still get said, because a
        // reader who loses them has been told less than the run knows.
        let declined = covered((0, 0), declined_own(17_500_000));
        let spent = Duration::from_millis(500);

        let line = verdict_line(
            (0, 0, 0),
            Some((&found(Verdict::Suspicious), spent)),
            &declined,
        );
        assert!(!line.contains("Nothing found in the files"), "{line}");
        assert!(line.contains("No file was examined"), "{line}");
        assert!(
            line.contains("the memory scan found something in 1 of 1"),
            "the memory finding is the more urgent fact and must survive: {line}"
        );

        let line = verdict_line((0, 0, 0), Some((&refused(), spent)), &declined);
        assert!(!line.contains("Nothing found in the files"), "{line}");
        assert!(line.contains("could not examine every process"), "{line}");
    }

    #[test]
    fn a_run_that_examined_files_still_says_nothing_found_plainly() {
        // The control. The sentence above is for the run that examined nothing,
        // and a run that examined files must not acquire it: an ordinary clean
        // scan of ordinary files is the one case where the unqualified answer is
        // the true one.
        let line = verdict_line((0, 0, 0), None, &nothing_declined());
        assert!(line.contains("Nothing found."), "{line}");
        assert!(!line.contains("No file was examined"), "{line}");
    }

    #[test]
    fn a_run_that_declined_a_strangers_corpus_does_not_call_it_our_own() {
        // The distinction [`Declined`] exists for. A user scans a folder of rule
        // sets they downloaded, the engine recognises them for what they are and
        // runs nothing against them, and the result line names them correctly. A
        // line that said "this product's own data" here would be false about a
        // file the user knows they downloaded from somewhere else.
        let declined = covered((0, 0), declined_source(4_000_000));
        let line = verdict_line((0, 0, 0), None, &declined);
        assert!(line.contains("No file was examined"), "{line}");
        assert!(
            line.contains("rule sources this product did not write"),
            "the line has to name the right subject: {line}"
        );
        assert!(
            !line.contains("this product's own data"),
            "a stranger's corpus is not our data: {line}"
        );
    }

    #[test]
    fn a_run_that_declined_both_kinds_names_both() {
        let mut declined = Declined::default();
        declined.own += 1;
        declined.own_bytes += 17_500_000;
        declined.sources += 2;
        declined.source_bytes += 900_000;
        let line = verdict_line((0, 0, 0), None, &covered((0, 0), declined));

        assert!(line.contains("a mix of this product's own data and rule sources"), "{line}");
    }

    #[test]
    fn the_two_declines_are_counted_apart_from_the_walk() {
        // Both kinds come out of the walk's totals, and they stay separate from
        // each other: three files found, two declined, one examined.
        let walk = walk::WalkOutcome {
            files: vec![
                PathBuf::from("corpus.yar"),
                PathBuf::from("downloaded.yar"),
                PathBuf::from("ordinary.txt"),
            ],
            bytes: 1_000,
            skipped: 0,
            unreadable: Vec::new(),
        };
        let mut declined = Declined::default();
        declined.own += 1;
        declined.own_bytes += 500;
        declined.sources += 1;
        declined.source_bytes += 200;

        let coverage = Coverage::of(&walk, declined);
        assert_eq!(coverage.scanned, 1);
        assert_eq!(coverage.bytes, 300);
        assert_eq!(coverage.declined.own, 1);
        assert_eq!(coverage.declined.sources, 1);
        assert!(!coverage.examined_nothing(), "one file was examined");
    }

    #[test]
    fn the_coverage_subtracts_the_declined_files_from_the_walks_totals() {
        // The arithmetic the summary prints, as a function rather than as a
        // sentence, because the failure it prevents is a plausible number rather
        // than a crash: 17.5 MB reported as scanned when nothing was examined.
        let walk = walk::WalkOutcome {
            files: vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")],
            bytes: 1_000,
            skipped: 7,
            unreadable: vec!["somewhere: refused".to_owned()],
        };
        let coverage = Coverage::of(&walk, declined_own(400));

        assert_eq!(coverage.scanned, 2);
        assert_eq!(coverage.bytes, 600);
        assert_eq!(coverage.declined.own, 1);
        assert_eq!(coverage.skipped, 7);
        assert_eq!(coverage.unreadable.len(), 1);
        assert!(!coverage.examined_nothing());
    }

    #[test]
    fn a_walk_whose_files_were_all_declined_reports_no_bytes_scanned() {
        // The whole point, at the boundary: every file recognised, so the scan
        // examined nothing and read nothing, whatever the walk totalled.
        let walk = walk::WalkOutcome {
            files: vec![PathBuf::from("corpus.yar")],
            bytes: 17_500_000,
            skipped: 0,
            unreadable: Vec::new(),
        };
        let coverage = Coverage::of(&walk, declined_own(17_500_000));

        assert_eq!(coverage.scanned, 0);
        assert_eq!(coverage.bytes, 0);
        assert!(coverage.examined_nothing());
    }

    #[test]
    fn a_memory_gap_is_named_beside_the_file_counts_and_never_folded_into_them() {
        // The two kinds are counted in different units, so the memory gap is
        // appended as its own clause rather than added to a number that counts
        // files. `2 suspicious` here is two files; nothing about the memory scan
        // changes it.
        let spent = Duration::from_millis(500);
        let empty = examined_nothing();
        let line = verdict_line((1, 2, 0), Some((&empty, spent)), &nothing_declined());
        assert!(line.contains("1 malicious"), "{line}");
        assert!(line.contains("2 suspicious"), "{line}");
        assert!(
            !line.contains("memory:"),
            "a complete scan says nothing: {line}"
        );

        let line = verdict_line((1, 2, 0), Some((&refused(), spent)), &nothing_declined());
        assert!(line.contains("1 malicious"), "{line}");
        assert!(line.contains("2 suspicious"), "{line}");
        assert!(
            line.contains("memory: not every process examined"),
            "the gap has to be on this line, because this is the line a reader \
             of a summary reads: {line}"
        );
    }

    #[test]
    fn memory_scanning_is_off_unless_it_is_asked_for() {
        // The performance and safety contract, as an assertion rather than as a
        // comment: a scan that was not asked for memory scanning must not
        // acquire it from a default. Every default a run can be built from is
        // checked, because a memory sweep that turned itself on would be
        // discovered by a user as a scan that suddenly takes a minute longer.
        assert!(!ScanOptions::default().memory);
        assert!(!ScanOptions::deep().memory);
        assert!(!ScanOptions::realtime().memory);
        assert!(!av_core::AvConfig::default().scanning.memory);
        // And the memory scan's *own* options ask for it, which is what makes
        // the field mean something at the one layer that reads it.
        assert!(av_memory::memory_scan_options().memory);
        // Trust is off for a memory scan, so a finding in a process never goes
        // through the discount a file's signature can earn. See
        // `av_scan::trust::is_generic`: it returns false for
        // `DetectionSource::Memory` as well, so this is belt and braces rather
        // than the only guard.
        assert!(!av_memory::memory_scan_options().trust);
    }

    /// A context with a configuration that does or does not ask for memory
    /// scanning.
    fn context(memory: bool) -> Context {
        // The paths are never read by `effective_options`; the data directory is
        // somewhere writable so that a context built here cannot fail.
        let dir = std::env::temp_dir();
        let paths = av_core::AvPaths::with_data_dir(dir.clone(), dir);
        let mut config = av_core::AvConfig::default();
        config.scanning.memory = memory;
        Context { paths, config }
    }

    /// Parsed `wenle scan .` arguments with the memory flags overwritten.
    fn scan_args(memory: bool, no_memory: bool) -> ScanArgs {
        let parsed = <crate::cli::Args as clap::Parser>::parse_from(["wenle", "scan", "."]);
        let crate::cli::Command::Scan(mut scan) = parsed.command else {
            unreachable!("the fixture asks for a scan")
        };
        scan.memory = memory;
        scan.no_memory = no_memory;
        *scan
    }

    #[test]
    fn the_flag_overrides_the_configuration_in_both_directions() {
        // The shape the option has to have. A configuration is written once and
        // read by the service and the graphical front end as well as by this
        // command, so a flag that could only turn the feature on would leave a
        // user whose configuration asked for it unable to run one scan without
        // it — and the reverse is the case that matters more, because the sweep
        // costs a minute and only one run is being asked about.
        assert!(
            !effective_options(&scan_args(false, false), &context(false)).memory,
            "nothing asked for it"
        );
        assert!(
            effective_options(&scan_args(true, false), &context(false)).memory,
            "`--memory` turns it on against a configuration that is quiet"
        );
        assert!(
            effective_options(&scan_args(false, false), &context(true)).memory,
            "a configuration that asks for it is enough on its own"
        );
        assert!(
            !effective_options(&scan_args(false, true), &context(true)).memory,
            "`--no-memory` turns it off against a configuration that asks for it"
        );
        // And `--no-memory` is not silently ignored when nothing asked for it
        // either: the pair is symmetric, so there is no state in which reading
        // one flag and not the other gives a different answer.
        assert!(!effective_options(&scan_args(false, true), &context(false)).memory);
    }
}
