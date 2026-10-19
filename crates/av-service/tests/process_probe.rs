//! Which running programs this machine's own rule database would convict.
//!
//! This is a probe, not a test: it asserts almost nothing and it needs a real
//! `rules.avdb`, so it is skipped unless `WENLE_PROBE_DATA` names an
//! installation's data directory. What it answers is the one question that
//! decides whether `realtime.terminate_malicious_process` may default to `true`:
//!
//! > If the service scanned every process on this machine at this moment, how
//! > many of them would it decide to kill?
//!
//! The answer has to be measured rather than argued. A file-scan false positive
//! is a line in a report; a memory false positive on a running program is a
//! program that disappears while its owner is using it, and the file probe that
//! scopes the file side of this cannot say anything about the memory side:
//! different bytes, different regions, a different set of rules that matter.
//!
//! # How it is faithful to the product
//!
//! Every step is the product's own code and not a copy of it:
//!
//! * The engine is built by [`av_service::engine::load`], catalog store and all,
//!   because trust evidence is one of the things that decides a conviction and a
//!   probe that skipped it would measure a different engine.
//! * The walk is [`av_memory::MemoryScanner`] with
//!   [`av_memory::MemoryScanConfig::default`] — the same scanner, the same caps,
//!   and no deadline, because this is the "a client asked" shape rather than the
//!   process-start shape that states one.
//! * Every finding goes through [`av_service::memory::rule_on`], the one
//!   function both memory callers use to decide, so a conviction here is the
//!   conviction the service would reach and not a re-implementation of it.
//!
//! Nothing is taken and nothing is killed: [`av_service::memory`] *decides*, and
//! [`av_service::host::Host`] is the half that acts. The probe never builds a
//! host, so it cannot quarantine a file or terminate a process even by mistake.
//!
//! # Run it
//!
//! ```text
//! $env:WENLE_PROBE_DATA = "C:\WenleAV\data"
//! cargo test -p av-service --release --test process_probe -- --nocapture
//! ```
//!
//! # Why it fails rather than reports when it cannot run
//!
//! The file scan's false-positive probe has silently produced nothing twice, and
//! both times the empty output read like a clean machine. So this one has no
//! quiet path: with `WENLE_PROBE_DATA` set, a database that will not load, a
//! machine where no process could be opened, or a scan that examined nothing are
//! all failures with a message, not reports of zero convictions. Zero
//! convictions is only meaningful next to the number of processes it was
//! computed from, which is why that number is asserted to be non-zero.

// An integration test target is a crate of its own, so the library's
// `cfg(test)` relaxation of these two lints does not reach it. Panicking is what
// a probe does when it cannot run — see "Why it fails rather than reports" above
// — so the lints are switched off here for the same reason they are in the
// library's tests. The sibling test binaries state this the same way.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use av_core::config::AvConfig;
use av_core::paths::AvPaths;
use av_memory::{list_processes, MemoryScanConfig, MemoryScanner, ProcessScan};
use av_service::{engine, memory};

/// What one conviction would be, reduced to the facts a reader can act on.
struct Conviction {
    process: String,
    address: usize,
    origin: String,
    verdict: String,
    score: u16,
    decision: String,
    rules: Vec<String>,
}

#[test]
fn which_processes_would_be_convicted() {
    let Some(data) = std::env::var_os("WENLE_PROBE_DATA") else {
        eprintln!(
            "skipped: set WENLE_PROBE_DATA to an installation's data directory \
             (the one holding db/rules.avdb) to run this probe"
        );
        return;
    };
    let data = PathBuf::from(data);
    assert!(
        data.is_dir(),
        "WENLE_PROBE_DATA is {data:?}, which is not a directory"
    );

    // The installation directory is the data directory here, because the live
    // deployment keeps `rules.avdb` under `data/db` and the fallback
    // `engine::database_path` takes is `install_dir/rules.avdb`. Naming both as
    // the same directory means the probe finds the database the deployed
    // product uses without this file having to know the layout twice.
    let paths = AvPaths::with_data_dir(&data, &data);
    let database = engine::database_path(&paths).unwrap_or_else(|| {
        panic!(
            "no rules.avdb under {:?} or {:?}: the probe cannot measure anything without the \
             database the product would scan with",
            paths.db_dir, paths.install_dir
        )
    });

    println!("\n=== process probe ===");
    println!("  database                 {}", database.display());

    // The deployed configuration, when there is one, rather than defaults: the
    // file size ceiling, the archive depth and the heuristics switch are all
    // inputs to a verdict, and a probe that measured a machine's convictions
    // under settings the machine does not use would be measuring the probe.
    let config = AvConfig::load_or_default(&paths.config_file)
        .expect("the deployed configuration parses");
    println!(
        "  config                   {}",
        if paths.config_file.is_file() {
            paths.config_file.display().to_string()
        } else {
            format!("none at {}: the built-in defaults", paths.config_file.display())
        }
    );

    let loaded = engine::load(&paths, &config.scanning);
    let Some(status) = &loaded.database else {
        panic!(
            "the database at {} did not load: {}",
            database.display(),
            loaded
                .load_error
                .as_deref()
                .unwrap_or("and no reason was recorded, which is itself a defect")
        );
    };
    println!(
        "  rules                    {} ({} bytes on disk)",
        status.rules, status.bytes
    );
    println!("  catalog                  {}", loaded.catalog.describe());

    let options = engine::options_from(&config.scanning);

    let processes = list_processes().expect("this machine can be asked for its processes");
    println!("  processes enumerated     {}", processes.len());

    let scanner = MemoryScanner::new(&loaded.engine, MemoryScanConfig::default());
    let started = Instant::now();
    let report = scanner.scan_processes(&processes);
    let elapsed = started.elapsed();

    let summary = report.summary();
    println!("  processes examined       {}", summary.processes_examined);
    println!("  refused (denied)         {}", summary.refused_denied);
    println!("  refused (gone)           {}", summary.refused_gone);
    println!("  refused (unreadable)     {}", summary.refused_unreadable);
    println!("  regions interesting      {}", summary.regions_interesting);
    println!("  regions read             {}", summary.regions_read);
    println!(
        "  bytes read               {:.1} MB",
        summary.bytes_read as f64 / (1024.0 * 1024.0)
    );

    // What the walk looked away from, and what it could not judge.
    //
    // Every one of these is a way "0 findings" could mean something other than
    // "this process was read and judged", and a probe that printed only the zero
    // would let a reader who wanted the answer to be good news take it that way.
    // The counts are the scanner's own, and `is_complete` / `gaps` below are the
    // scanner's own reading of them rather than a second opinion formed here.
    println!("  regions seen             {}", summary.regions_seen);
    println!(
        "  regions skipped          {} ({} not committed, {} below the floor, {} guard, \
         {} not readable, {} not executable, {} backed by a file)",
        summary.skipped.total(),
        summary.skipped.not_committed,
        summary.skipped.too_small,
        summary.skipped.guard,
        summary.skipped.not_readable,
        summary.skipped.not_executable,
        summary.skipped.backed_by_file,
    );
    println!("  regions refused          {}", summary.regions_refused);
    println!("  regions over budget      {}", summary.regions_over_budget);
    println!("  regions truncated        {}", summary.regions_truncated);
    println!("  regions unjudged         {}", summary.regions_unknown);
    println!("  bytes never examined     {}", summary.bytes_unread);
    println!("  walks stopped early      {}", summary.walks_incomplete);
    println!(
        "  machine-wide complete?   {} (false is expected: the processes this account could \
         not open are a gap in the population, not in any process's coverage)",
        summary.is_complete()
    );
    println!("  machine-wide gaps:");
    let gaps = summary.gaps();
    if gaps.is_empty() {
        println!("    (the scanner reports no gap at all)");
    }
    for gap in &gaps {
        println!("    gap: {gap}");
    }

    // The completeness that decides what the zero below means: how many of the
    // processes this probe *could* open were walked in full and had every byte of
    // every read region judged. `regions_unknown` is the term that matters most
    // here — a region the engine declined to judge is a region this probe read
    // and learned nothing from, and a report that folded it into "no finding"
    // would be describing an unexamined byte as an examined one.
    let fully_judged = report
        .results
        .iter()
        .filter_map(ProcessScan::outcome)
        .filter(|outcome| {
            outcome.walk_complete
                && outcome.regions_refused == 0
                && outcome.regions_over_budget == 0
                && outcome.regions_truncated == 0
                && outcome.regions_unknown == 0
        })
        .count();
    println!(
        "  fully walked and judged  {fully_judged} of {} examined",
        summary.processes_examined
    );

    // Printed before the convictions and not after, because the two zeroes this
    // probe can produce mean opposite things: "the engine looked at ninety
    // processes and found nothing at all" is a fact about the scanner, and "the
    // engine found plenty and none of it crossed the line" is a fact about the
    // rules. A report carrying only the second zero would be read as the first
    // by anybody who wanted the answer to be good news.
    println!("  findings (every verdict) {}", summary.findings);
    println!("  worst verdict            {:?}", summary.worst);
    println!("  took                     {:.2} s", elapsed.as_secs_f64());

    // The assertion that makes a silent success impossible. A machine with
    // Windows running has processes and this process can open some of them —
    // measured on the machine this was written on, 115 to 136 of about 280. Zero
    // examined means the probe measured nothing and a report of "no convictions"
    // from it would be a claim about an empty set.
    assert!(
        summary.processes_examined > 0,
        "no process on this machine could be examined, so there is nothing here to conclude: \
         {} were enumerated and every one was refused",
        processes.len()
    );

    // Every finding at or above the band the service acts on, put through the
    // product's own decision function. `memory::rule_on` reads the file behind
    // the finding and returns what the service would do about it.
    let mut convictions = Vec::new();
    let mut findings_above_the_line = 0usize;
    let mut rule_tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_verdict: BTreeMap<String, usize> = BTreeMap::new();

    for result in &report.results {
        let ProcessScan::Examined(outcome) = result else {
            continue;
        };
        for finding in &outcome.findings {
            *by_verdict.entry(format!("{:?}", finding.verdict)).or_default() += 1;
            if !finding.verdict.blocks() {
                continue;
            }
            findings_above_the_line += 1;

            for detection in &finding.detections {
                *rule_tally.entry(detection.rule_id.clone()).or_default() += 1;
            }

            let ruling = memory::rule_on(&finding.origin, &paths, &loaded.engine, &options);
            convictions.push(Conviction {
                process: finding.process.label(),
                address: finding.base,
                origin: finding
                    .origin
                    .path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "no file: the bytes came from nothing on disk".to_string()),
                verdict: format!("{:?}", finding.verdict),
                score: finding.score,
                decision: ruling.action.describe(),
                rules: finding
                    .detections
                    .iter()
                    .map(|detection| format!("{} ({} pts)", detection.rule_id, detection.score))
                    .collect(),
            });
        }
    }

    println!("\n  findings by verdict:");
    if by_verdict.is_empty() {
        println!("    (the engine recorded no finding of any verdict)");
    }
    for (verdict, count) in &by_verdict {
        println!("    {count:>6}  {verdict}");
    }

    println!("\n  findings at or above the acting band   {findings_above_the_line}");
    println!("  processes that would be convicted      {}", convictions.len());

    // The population, named exactly, and the hole in it named too. Whether a
    // process could be opened depends on the account this probe runs as, and the
    // processes it could not open are not a sample of the ones it could — they
    // are the elevated ones, which is to say the ones most likely to be worth
    // scanning. A sentence that said "no process on this machine was convicted"
    // about this run would be a claim about 247 processes supported by 90.
    println!(
        "\n  This account could open {} of the {} processes on this machine; {} were refused a \
         handle and are not covered by anything below.",
        summary.processes_examined,
        processes.len(),
        summary.processes_refused()
    );

    if convictions.is_empty() {
        println!(
            "\n  Of those {}, none would be convicted: {} region(s) read, {} finding(s) of any \
             verdict, worst {:?}, none at or above the band the service acts on. {} of the {} \
             examined processes were walked in full with every read region judged, and {} region(s) \
             across the whole scan were read and left unjudged. That is the result \
             `realtime.terminate_malicious_process` defaulting to true needs — scoped to the \
             processes this account can see, and to nothing more.",
            summary.processes_examined,
            summary.regions_read,
            summary.findings,
            summary.worst,
            fully_judged,
            summary.processes_examined,
            summary.regions_unknown,
        );
    } else {
        for conviction in &convictions {
            println!(
                "\n  {} at {:#x}\n    origin   {}\n    verdict  {} (score {})\n    decision {}\n    rules    {}",
                conviction.process,
                conviction.address,
                conviction.origin,
                conviction.verdict,
                conviction.score,
                conviction.decision,
                conviction.rules.join(", ")
            );
        }
        println!("\n  --- rules that fired ---");
        for (rule, count) in &rule_tally {
            println!("  {count:>5}  {rule}");
        }
    }

    // A last line that cannot be mistaken for a run that died early: it is
    // printed only after every process was walked and every finding decided, and
    // it carries the two numbers that decide what the conviction count is worth —
    // how many processes were walked in full with nothing left unjudged, and how
    // many regions were read and not judged at all.
    println!(
        "\n=== process probe complete: {} processes examined ({} fully judged), {} convictions, \
         {} regions unjudged, {:.2} s ===\n",
        summary.processes_examined,
        fully_judged,
        convictions.len(),
        summary.regions_unknown,
        elapsed.as_secs_f64()
    );
}

/// Plant `pattern` inside an executable, private page of this process and return
/// where the page starts.
///
/// The same shape as the page `control_pipe.rs` plants, with the fill replaced by
/// bytes that matter: the pattern is written into the middle of the page rather
/// than at its start, so a finding at the page's base is a finding about a region
/// the scanner read from its beginning and not a lucky first-64-bytes match.
///
/// # Why `VirtualAlloc` is declared rather than imported
///
/// This is an integration test, and an integration test can see the crate's
/// public API and its dev-dependencies — `windows` is neither, it is a target
/// dependency of the library. The signature is the one thing here that cannot be
/// got wrong quietly: a wrong `VirtualAlloc` returns null and the assert says so.
///
/// # Safety
///
/// The page is freed by the caller with [`free_page`]. It is committed for the
/// whole of the scan, which is exactly as long as it needs to be.
#[cfg(windows)]
fn plant_executable_page(pattern: &[u8]) -> *mut core::ffi::c_void {
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_SIZE: usize = 4096;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(
            address: *const core::ffi::c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
    }

    assert!(
        pattern.len() + 512 < PAGE_SIZE,
        "the pattern is {} byte(s), which will not sit inside one page with room around it",
        pattern.len()
    );

    // SAFETY: a null requested address asks the system to choose one, which is
    // the only safe thing to ask for; the size is one page; and the result is
    // checked before anything writes through it.
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    assert!(
        !page.is_null(),
        "VirtualAlloc failed: {}",
        std::io::Error::last_os_error()
    );

    // SAFETY: `page` is a freshly committed page of PAGE_SIZE bytes that nothing
    // else in this process refers to. `0x90` is `nop`, so the region is
    // executable throughout, and the pattern goes in the middle.
    unsafe {
        std::ptr::write_bytes(page as *mut u8, 0x90, PAGE_SIZE);
        std::ptr::copy_nonoverlapping(
            pattern.as_ptr(),
            (page as *mut u8).add(PAGE_SIZE / 2),
            pattern.len(),
        );
    }
    page
}

/// Hand a page from [`plant_executable_page`] back.
#[cfg(windows)]
fn free_page(page: *mut core::ffi::c_void) {
    const MEM_RELEASE: u32 = 0x8000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualFree(address: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
    }

    // SAFETY: `page` came from `VirtualAlloc` with `MEM_RESERVE` and has not
    // been freed; `MEM_RELEASE` requires a size of zero, which is what is passed.
    let freed = unsafe { VirtualFree(page, 0, MEM_RELEASE) };
    assert!(freed != 0, "VirtualFree failed: {}", std::io::Error::last_os_error());
}

/// The pattern these tests plant, assembled at run time.
///
/// # Why it is assembled rather than written out
///
/// A test binary carrying this byte-for-byte on disk is a test binary the host's
/// own antivirus quarantines, and it takes the whole integration-test suite with
/// it when it goes: the recorded failure is `os error 225` from there on, with
/// every later test in the binary failing for a reason that has nothing to do
/// with it. Three fragments joined at run time are the same bytes to the engine
/// and nothing recognisable to anything reading the executable.
///
/// EICAR rather than a pattern of our own because the point of a positive control
/// is to use a rule that is really in the database: `TRELLIX_ARC_Malw_Eicar` is
/// in the 10,764-rule file this probe measures against, and it matches this
/// string and nothing else.
fn known_pattern() -> Vec<u8> {
    let mut pattern = String::from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EI");
    pattern.push_str("CAR-STANDARD-ANTIVIRUS-");
    pattern.push_str("TEST-FILE!$H+H*");
    pattern.into_bytes()
}

/// A blob with `needle` in it, large enough that the host's antivirus does not
/// recognise the file as a copy of the test string.
///
/// The stored signature for that string is whole-file, so a file that contains it
/// among other bytes is not a file it acts on — while our engine, which matches
/// the string and not the file, convicts it decisively. That asymmetry is what
/// makes this usable as a fixture at all.
fn buried(needle: &[u8]) -> Vec<u8> {
    let mut blob = vec![0u8; 8192];
    blob[4096..4096 + needle.len()].copy_from_slice(needle);
    blob
}

/// That the engine convicts the pattern at all, in a file and then in memory.
///
/// # What this control is for
///
/// `which_processes_would_be_convicted` reports a count of zero, and a zero is
/// only worth reading if the pipeline that produced it can produce anything else.
/// Every existing memory test builds a *synthetic* engine, and the one test that
/// scans a real process — in `control_pipe.rs` — uses an *empty* rule set. So
/// nothing in this workspace has ever shown that `MemoryScanner` plus the real
/// 10,764-rule database reaches a conviction, and "0 findings" could in principle
/// mean "nothing in this pipeline can ever produce a finding".
///
/// So this plants bytes the real database is known to match, into a file and then
/// into an executable page of this process, and requires a conviction from each.
/// It is the difference between a measurement and a report of absence.
#[test]
fn the_pipeline_convicts_a_page_carrying_a_pattern_the_database_knows() {
    let Some(data) = std::env::var_os("WENLE_PROBE_DATA") else {
        eprintln!("skipped: set WENLE_PROBE_DATA to run this control against a real database");
        return;
    };
    let data = PathBuf::from(data);
    let paths = AvPaths::with_data_dir(&data, &data);
    let config = AvConfig::load_or_default(&paths.config_file)
        .expect("the deployed configuration parses");
    let loaded = engine::load(&paths, &config.scanning);
    let Some(status) = &loaded.database else {
        panic!(
            "the database did not load: {}",
            loaded.load_error.as_deref().unwrap_or("no reason recorded")
        );
    };
    let options = engine::options_from(&config.scanning);
    let pattern = known_pattern();

    println!("\n=== memory positive control ===");
    println!("  database                 {} rules", status.rules);
    println!("  pattern                  {} byte(s), assembled at run time", pattern.len());

    // --- the file half -----------------------------------------------------
    //
    // Isolates "the database does not match this pattern" from "the memory walk
    // did not reach it". If this half fails, the memory half says nothing.
    let file = std::env::temp_dir().join(format!(
        "wenle-probe-control-{}.bin",
        std::process::id()
    ));
    std::fs::write(&file, buried(&pattern)).expect("the control file is writable");
    let examined = memory::examine(&loaded.engine, &file, &options);
    let _ = std::fs::remove_file(&file);

    match &examined.outcome {
        memory::Examination::Verdict(verdict) => {
            println!("  file scan                {verdict:?}");
            assert!(
                verdict.blocks(),
                "the real database read a file containing the pattern and did not convict it: \
                 {verdict:?}. The pattern this control uses is not one this rule set matches, so \
                 the control proves nothing until it is changed"
            );
            if let Some(report) = &examined.report {
                println!("    score                  {}", report.assessment.score);
                for detection in &report.assessment.detections {
                    println!("    rule                   {} ({} pts)", detection.rule_id, detection.score);
                }
                for rule in &report.assessment.suppressed {
                    println!("    suppressed             {rule}");
                }
            }
        }
        other => panic!(
            "the control file could not be scanned at all ({other:?}), so this control cannot \
             say anything about the memory half"
        ),
    }

    // --- the memory half ---------------------------------------------------
    //
    // The real scanner, the real database, and the product's own decision
    // function on the finding it produces.
    let page = plant_executable_page(&pattern);
    let scanner = MemoryScanner::new(&loaded.engine, MemoryScanConfig::default());
    let mut source = av_memory::Win32Source::open(av_memory::identify(av_memory::current_pid()))
        .expect("this process can be opened for reading by itself");
    let outcome = scanner.scan_process(&mut source);
    free_page(page);

    let ProcessScan::Examined(outcome) = &outcome else {
        panic!("this process could not be examined: {outcome:?}");
    };
    println!(
        "  memory scan              {} region(s) read of {} seen, {} byte(s), {} unjudged",
        outcome.regions_read, outcome.regions_seen, outcome.bytes_read, outcome.regions_unknown
    );

    // The planted page and only it. A finding anywhere else in this process is
    // reported rather than asserted on — it would be a fact about this machine,
    // not about the pipeline — but a finding here is the pipeline working.
    let planted = page as usize;
    for finding in &outcome.findings {
        println!(
            "    finding                {:#x} {:?} score {} [{}]",
            finding.base,
            finding.verdict,
            finding.score,
            finding
                .detections
                .iter()
                .map(|detection| detection.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let hit = outcome
        .findings
        .iter()
        .find(|finding| finding.base == planted)
        .unwrap_or_else(|| {
            panic!(
                "the planted page at {planted:#x} was not convicted. The engine matched this \
                 pattern in a file one step ago, so what failed is the memory path: either the \
                 page was not read ({} region(s) read, {} unjudged, walk_complete {}, skipped \
                 {} backed by a file) or its bytes were not judged",
                outcome.regions_read,
                outcome.regions_unknown,
                outcome.walk_complete,
                outcome.skipped.backed_by_file,
            )
        });

    assert!(
        hit.verdict.blocks(),
        "the planted page produced a finding that does not act: {:?}",
        hit.verdict
    );

    // And the decision the service would reach about it, through the one
    // function both memory callers use. A page with no file behind it is one of
    // the cases `rule_on` exists to answer.
    let ruling = memory::rule_on(&hit.origin, &paths, &loaded.engine, &options);
    println!(
        "  decision                 {} (origin: {})",
        ruling.action.describe(),
        hit.origin
            .path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "no file: the bytes came from nothing on disk".to_string())
    );

    println!(
        "\n=== memory positive control complete: the real database convicts the pattern in a file \
         and in a planted page ===\n"
    );
}
