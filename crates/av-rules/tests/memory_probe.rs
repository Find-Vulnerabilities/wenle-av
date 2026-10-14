//! Where a loaded rule database's memory goes, measured rather than guessed.
//!
//! This is a probe, not a test: it asserts nothing about the database and it
//! needs one on disk, so it is skipped unless `WENLE_PROBE_DB` names a
//! `rules.avdb`. What it does is install a counting allocator, load the
//! database, and report the live bytes and the largest single allocations after
//! each step, so that the parts of the working set can be attributed to the
//! structures that hold them instead of to a hypothesis about them.
//!
//! Run it with the release profile, because that is the one that ships:
//!
//! ```text
//! $env:WENLE_PROBE_DB = "C:\path\to\rules.avdb"
//! cargo test -p av-rules --release --test memory_probe -- --nocapture
//! ```
//!
//! The allocator is deliberately blunt. It counts every allocation, records the
//! largest ones with their sizes, and buckets the rest by size class, which is
//! enough to tell a few large tables apart from hundreds of thousands of small
//! strings — the two shapes that call for opposite fixes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Size-class upper bounds in bytes; the last bucket is everything above the
/// final bound.
const BOUNDS: [usize; 8] = [64, 256, 1024, 4096, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];

struct Probe;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);

/// [count, bytes] per size class, plus one bucket above `BOUNDS`.
static HIST: Mutex<[[usize; 2]; 9]> = Mutex::new([[0; 2]; 9]);
/// The same, for allocations that are still live: the shape of what the process
/// is holding right now, rather than of everything it ever asked for.
static LIVE_HIST: Mutex<[[usize; 2]; 9]> = Mutex::new([[0; 2]; 9]);
/// The largest single allocations since the last [`take_top`].
static TOP: Mutex<Vec<usize>> = Mutex::new(Vec::new());

const TOP_N: usize = 8;

/// `try_lock` everywhere, and every critical section allocates nothing, so the
/// allocator can never deadlock against itself or recurse into itself.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        FREES.fetch_add(1, Ordering::Relaxed);
        unrecord(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, new_size) };
        if !out.is_null() {
            // A reallocation is a release of the old size and a request for the
            // new one, and the live histogram has to see both or it drifts.
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            unrecord(layout.size());
            record(new_size);
        }
        out
    }
}

fn size_class(size: usize) -> usize {
    BOUNDS.iter().position(|b| size <= *b).unwrap_or(BOUNDS.len())
}

/// The other half of [`record`]: an allocation that has gone away.
fn unrecord(size: usize) {
    let class = size_class(size);
    if let Ok(mut hist) = LIVE_HIST.try_lock() {
        hist[class][0] = hist[class][0].saturating_sub(1);
        hist[class][1] = hist[class][1].saturating_sub(size);
    }
}

fn record(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    TOTAL.fetch_add(size, Ordering::Relaxed);
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    PEAK.fetch_max(live, Ordering::Relaxed);

    let class = size_class(size);
    if let Ok(mut hist) = HIST.try_lock() {
        hist[class][0] += 1;
        hist[class][1] += size;
    }
    if let Ok(mut hist) = LIVE_HIST.try_lock() {
        hist[class][0] += 1;
        hist[class][1] += size;
    }
    if let Ok(mut top) = TOP.try_lock() {
        if top.len() < TOP_N {
            top.push(size);
            top.sort_unstable_by(|a, b| b.cmp(a));
        } else if size > top[TOP_N - 1] {
            top[TOP_N - 1] = size;
            top.sort_unstable_by(|a, b| b.cmp(a));
        }
    }
}

#[global_allocator]
static ALLOCATOR: Probe = Probe;

fn mb(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Live bytes right now. Read as a delta between phases.
fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// The size-class histogram since the last call, and clear it.
fn take_hist() -> [[usize; 2]; 9] {
    match HIST.try_lock() {
        Ok(mut hist) => std::mem::take(&mut *hist),
        Err(_) => [[0; 2]; 9],
    }
}

fn print_hist(label: &str, hist: &[[usize; 2]; 9]) {
    println!("  --- allocation size classes during {label} ---");
    for (i, [count, bytes]) in hist.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        let bound = if i == BOUNDS.len() {
            format!("> {:>7} B", BOUNDS[BOUNDS.len() - 1])
        } else {
            format!("<= {:>6} B", BOUNDS[i])
        };
        println!(
            "    {bound:<20} {count:>9} allocs {:>9.1} MB  (avg {} B)",
            mb(*bytes),
            bytes / count.max(&1),
        );
    }
}

/// The largest allocations since the last call, and clear the list.
fn take_top() -> Vec<usize> {
    match TOP.try_lock() {
        Ok(mut top) => std::mem::take(&mut *top),
        Err(_) => Vec::new(),
    }
}

/// A phase: the live bytes and the shape of what the phase allocated.
fn report(label: &str, before: usize) {
    let now = live();
    let top = take_top();
    println!(
        "  {label:<32} {:>7.1} MB live  (Δ {:>+7.1} MB)",
        mb(now),
        (now as f64 - before as f64) / (1024.0 * 1024.0),
    );
    let shapes: Vec<String> = top.iter().take(4).map(|b| format!("{}", mb(*b) as u32)).collect();
    if !shapes.is_empty() {
        println!("  {:<32} largest: {} MB", "", shapes.join(", "));
    }
}

#[test]
fn where_the_memory_goes() {
    let Some(path) = std::env::var_os("WENLE_PROBE_DB") else {
        eprintln!("skipped: set WENLE_PROBE_DB to a rules.avdb to run this probe");
        return;
    };
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!("\n=== memory probe ===");
    println!("  database on disk                 {:>7.1} MB", mb(bytes as usize));

    let _ = take_top();
    let base = live();
    report("baseline", base);

    let db = av_rules::database::RuleDatabase::load(&path).expect("the database loads");
    report("RuleDatabase::load", base);
    // The peak is not decoration: `RuleDatabase::afford` refuses a load on a
    // machine that cannot hold it, and what it has to bound is the highest
    // point the parse reaches, not where it settles. Printed here, before
    // anything else runs, and then reset so the end-of-run peak describes the
    // rest of the test rather than this phase.
    println!(
        "  {:<32} {:>7.1} MB, {:.1}x the file",
        "peak during the load",
        mb(PEAK.load(Ordering::Relaxed)),
        PEAK.load(Ordering::Relaxed) as f64 / bytes.max(1) as f64,
    );
    PEAK.store(live(), Ordering::Relaxed);
    print_hist("RuleDatabase::load", &take_hist());
    let rules = db.rules();
    println!("  {:<32} {:>7}", "rules", rules.len());

    #[cfg(feature = "memory-probe")]
    {
        // The same file, read the same way, in the same process, with only the
        // sharing switched off. Comparing this with the load above is the
        // measurement of what interning the regexes is worth; comparing it with
        // a number from an earlier run would not be.
        let before = live();
        let unshared = av_rules::probe::load_without_sharing(std::path::Path::new(&path))
            .expect("the database loads without sharing too");
        // Reported as a delta like every other phase, so this line and the one
        // after `RuleDatabase::load` are directly comparable: the difference
        // between them is what sharing the compiled regexes is worth.
        report("a second load, sharing off", before);
        drop(unshared);
    }

    #[cfg(feature = "memory-probe")]
    {
        let (parts, counts) = av_rules::probe::parts(&db);
        let live_now = live();
        println!("\n  --- field-by-field, out of {:.1} MB live ---", mb(live_now));
        for (label, value) in [
            ("rule headers", parts.rule_headers),
            ("names", parts.names),
            ("tags", parts.tags),
            ("metadata", parts.metadata),
            ("defs (headers + ids)", parts.defs),
            ("  of which hex token trees", parts.def_hex_tokens),
            ("  of which text bytes", parts.def_text),
            ("  of which regex body text", parts.def_regex_text),
            ("program code", parts.program_code),
            ("program constants", parts.program_constants),
            ("matcher headers", parts.matcher_headers),
            ("matcher ids", parts.matcher_ids),
            ("  of which literal bytes", parts.matcher_literal_bytes),
            ("  of which hex token trees", parts.matcher_hex_tokens),
            ("  of which regex parse trees", parts.matcher_hir),
            ("source names and digests", parts.sources),
        ] {
            println!("  {label:<34} {:>9.1} MB", mb(value));
        }
        println!(
            "  {:<34} {:>9.1} MB",
            "attributed",
            mb(parts.total())
        );
        println!(
            "  {:<34} {:>9.1} MB",
            "NOT attributed",
            mb(live_now.saturating_sub(parts.total())),
        );
        println!(
            "  counts: {} rules, {} strings ({} literal / {} hex / {} regex), {} literal forms",
            counts.rules,
            counts.strings,
            counts.literal_strings,
            counts.hex_strings,
            counts.regex_strings,
            counts.literal_forms,
        );
    }

    #[cfg(feature = "memory-probe")]
    {
        let before = live();
        let rebuilt = av_rules::probe::rebuilt_regexes(&db);
        let after = live();
        let all_bytes = after.saturating_sub(before);
        println!(
            "  {:<34} {:>9} rebuilt from the same parse trees, holding {:.1} MB ({} B each)",
            "regex programs (estimate)",
            rebuilt.len(),
            mb(all_bytes),
            all_bytes / rebuilt.len().max(1),
        );
        drop(rebuilt);

        for limit in [0usize, 1 << 16, 1 << 18, 1 << 20, 4 << 20] {
            let before = live();
            let rebuilt = av_rules::probe::rebuilt_regexes_with(&db, Some(limit));
            let after = live();
            println!(
                "  {:<34} dfa_size_limit {:>9} -> {:.1} MB ({} B each, {} built)",
                "regex programs at a limit",
                limit,
                mb(after.saturating_sub(before)),
                (after.saturating_sub(before)) / rebuilt.len().max(1),
                rebuilt.len(),
            );
            drop(rebuilt);
        }

        let (total, distinct) = av_rules::probe::distinct_regex_bodies(&db);
        println!(
            "  {:<34} {total} regex strings, {distinct} distinct expressions",
            "regex duplication",
        );

        let before = live();
        let shared = av_rules::probe::rebuilt_distinct_regexes(&db);
        let after = live();
        let distinct_bytes = after.saturating_sub(before);
        println!(
            "  {:<34} {:>9} distinct programs hold {:.1} MB, so sharing is worth {:.1} MB",
            "regex sharing",
            shared.len(),
            mb(distinct_bytes),
            mb(all_bytes.saturating_sub(distinct_bytes)),
        );
        drop(shared);

        const TRIVIAL: usize = 200;
        let before = live();
        let trivial = av_rules::probe::trivial_regexes(TRIVIAL);
        let after = live();
        println!(
            "  {:<34} {:>9} trivial patterns cost {:.1} MB ({} B each), which is {}% of the real ones",
            "regex fixed overhead",
            trivial.len(),
            mb(after.saturating_sub(before)),
            (after.saturating_sub(before)) / trivial.len().max(1),
            (after.saturating_sub(before)) / trivial.len().max(1) * 100 / 93_181,
        );
        drop(trivial);
    }

    let after_load = live();
    let filters: Vec<av_rules::prefilter::RuleFilter> = rules
        .iter()
        .map(|rule| av_rules::prefilter::RuleFilter {
            strings: rule.string_atoms(),
            required: rule.program.required_strings.clone(),
        })
        .collect();
    report("  the RuleFilter list alone", after_load);
    println!("  {:<32} {:?}", "prefilter stats", db.prefilter().stats());

    let after_filters = live();
    let prefilter = av_rules::prefilter::Prefilter::build(&filters);
    report("Prefilter::build (second copy)", after_filters);
    drop(prefilter);
    drop(filters);

    let after_prefilter = live();
    let sweep = av_rules::sweep::LiteralSweep::build(rules);
    report("LiteralSweep::build (second copy)", after_prefilter);
    drop(sweep);

    let after_sweep = live();
    let catalog = av_signatures::catalog::CatalogIndex::from_store();
    report("CatalogIndex::from_store", after_sweep);
    match &catalog {
        Ok(_index) => println!("  {:<32} built", "catalog"),
        Err(error) => println!("  {:<32} not built: {error}", "catalog"),
    }

    println!("\n  peak live                        {:>7.1} MB", mb(PEAK.load(Ordering::Relaxed)));
    println!(
        "  allocations                      {:>7} ({} still live)",
        ALLOCS.load(Ordering::Relaxed),
        ALLOCS.load(Ordering::Relaxed) - FREES.load(Ordering::Relaxed),
    );
    println!("  bytes allocated in total         {:>7.1} MB", mb(TOTAL.load(Ordering::Relaxed)));

    println!("\n  size class              count          bytes");
    if let Ok(hist) = HIST.lock() {
        for (i, [count, bytes]) in hist.iter().enumerate() {
            let label = if i == BOUNDS.len() {
                format!("> {:>7} B", BOUNDS[BOUNDS.len() - 1])
            } else {
                format!("<= {:>6} B", BOUNDS[i])
            };
            println!("  {label:<22} {count:>9}   {:>7.1} MB", mb(*bytes));
        }
    }

    println!("
  live allocation size classes (what is held now)");
    if let Ok(hist) = LIVE_HIST.lock() {
        let mut live_total = 0usize;
        for (i, [count, bytes]) in hist.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            live_total += bytes;
            let bound = if i == BOUNDS.len() {
                format!("> {:>7} B", BOUNDS[BOUNDS.len() - 1])
            } else {
                format!("<= {:>6} B", BOUNDS[i])
            };
            println!(
                "    {bound:<20} {count:>9} allocs {:>9.1} MB  (avg {} B)",
                mb(*bytes),
                bytes / count.max(&1),
            );
        }
        println!("    {:<20} {:>15}   {:>7.1} MB", "total requested", "", mb(live_total));
        println!(
            "    allocator live counter {:>7.1} MB, private bytes will be higher by the heap's own",
            mb(live()),
        );
    }

    let _ = db;
    println!();
}
