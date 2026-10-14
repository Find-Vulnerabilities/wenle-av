//! Development tool: how fast is the fixed-length atom matcher, and against
//! what.
//!
//! ```text
//! cargo run --release --example pattern_bench [-- buffer.bin] [--census]
//! ```
//!
//! # Why this lives in `av-rules` and not in `av-patterns`
//!
//! It measures `av-patterns`, and it is not in that crate. The reason is the
//! atom list: the number that means anything is the one taken over the real
//! rule set, and the real rule set only exists inside a compiled rule database
//! that `av-rules` knows how to read. Putting the benchmark beside its subject
//! meant `av-patterns` depending on `av-rules`, and once the prefilter began
//! searching with `av-patterns` the two depended on each other — a cycle Cargo
//! refuses before it compiles anything. `optional = true` does not help:
//! an optional dependency is still resolved, so the feature being off by
//! default would have left `cargo test --workspace --all-features` failing and
//! the cycle merely switched off rather than impossible.
//!
//! So the dependency runs one way, `av-rules -> av-patterns`, and the benchmark
//! sits at the top of it with the data it needs. That is also the honest place
//! for it: what it measures is the prefilter's workload, and the prefilter is
//! `av-rules`.
//!
//! # What it measures
//!
//! One buffer, two matchers, the same atom list, timed in the same process on
//! the same machine. The second matcher is Aho-Corasick, which is what the
//! prefilter used before this crate, so the number reported here has its
//! baseline sitting next to it rather than quoted from another program's run on
//! another day.
//!
//! The buffer defaults to `C:\Windows\System32\shell32.dll` — 8,009,440 bytes,
//! the file every previous measurement in this workspace used, and therefore the
//! one whose number is the one to beat. A path may be given instead. A mebibyte
//! of zeros is measured as well, and that second buffer is not decoration: it is
//! where an unconditional `O(size)` pass shows up as a cost rather than a
//! saving.
//!
//! # The atom list, exactly as the prefilter has it
//!
//! The list is built the way `Prefilter::build` builds it: every atom of every
//! string of every rule, deduplicated by the whole `Atom` — bytes, case rule and
//! trailer — and then split into two lists by case, because whether to fold is a
//! decision the search has to make at build time. That is what makes this a
//! measurement of the real workload rather than of something shaped like it: the
//! same patterns, in the same two groups, with the same duplicate byte strings
//! that a trailer keeps distinct.
//!
//! A case-insensitive list needs a folded buffer, since a matcher given folded
//! patterns cannot find `HTTP` unless the haystack is folded too. Aho-Corasick
//! folds inside the automaton as it goes; `av-patterns` is handed bytes and
//! compares them, so the fold is a pass of its own, and it is timed and reported
//! separately rather than hidden inside the scan.
//!
//! # Which atom source
//!
//! * **The real one**, whenever `C:\ProgramData\WenleAV\db\rules.avdb` can be
//!   read. This is the number that means something, and it is the default.
//! * **A generated one**, when there is no database: a machine that has never
//!   run `av-cli build --report`, or a checkout whose database is stale. The
//!   generator reproduces the *measured* shape of the real set — the same length
//!   distribution, the same first-byte distribution, tail bytes drawn from the
//!   same byte distribution — and `--census` prints both sets' shapes so the
//!   difference is visible rather than assumed away. The run says in words which
//!   source it used, because a generated set's numbers are not the ones to
//!   quote.
//!
//! # Reading the output
//!
//! `matches` is the number of matches found, and both matchers must report the
//! same one: they are given the same patterns and both report overlapping
//! matches, so a disagreement means one of them is wrong. The run says so in
//! words and exits non-zero rather than leaving two numbers to be compared by
//! eye.
//!
//! The census is not decoration either. The design under test is a two-level
//! gate over candidate offsets, and whether it pays depends entirely on the
//! distribution it is gating: how many first bytes can start an atom, how many
//! atoms share a first byte, and how many share a three-byte prefix.

// A development tool whose whole job is to fail loudly on bad input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use av_patterns::AtomSet;
use av_rules::database::RuleDatabase;

/// The file every measurement in this workspace has used.
const REFERENCE: &str = r"C:\Windows\System32\shell32.dll";

/// Where the compiled rule database lives.
const DATABASE: &str = r"C:\ProgramData\WenleAV\db\rules.avdb";

/// How many runs to time; the best is reported, so the first pass's page faults
/// and any background noise are left out.
const RUNS: usize = 5;

/// The size of the low-entropy buffer: the same one mebibyte the sibling
/// measurement of the sweep used, so the two can be put beside each other.
const ZEROS: usize = 1 << 20;

/// One group of atoms that a single matcher can be given at once.
struct Class {
    name: &'static str,
    /// The patterns, in the order the prefilter would put them in its
    /// automaton.
    atoms: Vec<Vec<u8>>,
    /// Whether the patterns have been folded to lower case, which means the
    /// buffer has to be folded too before this list can be searched with a
    /// byte-by-byte comparison.
    folded: bool,
}

fn main() -> ExitCode {
    let args = env::args().skip(1);
    let mut buffer = None;
    let mut census = false;
    for argument in args {
        match argument.as_str() {
            "--census" => census = true,
            other => buffer = Some(other.to_owned()),
        }
    }

    let classes = match real_classes() {
        Some(classes) => classes,
        None => {
            println!(
                "atom source: a generated set — {DATABASE} could not be read, so there is no \
                 real atom list on this machine; the generated set reproduces the measured \
                 shape of it, and `--census` prints both shapes. A generated set's numbers are \
                 not the ones to quote."
            );
            generated_classes()
        }
    };
    for class in &classes {
        report_census(class);
    }
    if census {
        print_histograms(&classes);
        return ExitCode::SUCCESS;
    }
    if classes.iter().all(|class| class.atoms.is_empty()) {
        eprintln!("no atoms to search for");
        return ExitCode::FAILURE;
    }

    let path = buffer.unwrap_or_else(|| REFERENCE.to_owned());
    let Ok(raw) = fs::read(&path) else {
        eprintln!("cannot read {path}: pass a file to scan as an argument");
        return ExitCode::FAILURE;
    };
    let zeros = vec![0u8; ZEROS];

    for (buffer_name, data) in [("shell32.dll", &raw[..]), ("zeros", &zeros[..])] {
        println!("\n=== {buffer_name}, {} bytes ===", data.len());
        let mut ours_total = Duration::ZERO;
        let mut theirs_total = Duration::ZERO;
        let mut ours_visit_total = Duration::ZERO;
        let mut theirs_visit_total = Duration::ZERO;

        for class in &classes {
            if class.atoms.is_empty() {
                continue;
            }
            let set = AtomSet::new(&class.atoms);
            // The buffer this class is searched in. For a case-insensitive list
            // that is a folded copy, and the fold gets a line of its own
            // because it is real work this design does not get for free.
            let folded_buffer;
            let haystack = if class.folded {
                let started = Instant::now();
                folded_buffer = fold(data);
                let elapsed = started.elapsed();
                println!(
                    "  {:<16} fold       {:>12}  {:>6.0} MB/s",
                    class.name,
                    format!("{elapsed:?}"),
                    mb_per_second(data.len(), elapsed)
                );
                &folded_buffer[..]
            } else {
                data
            };

            // Built once for both of its timings below: a third of a second for
            // a hundred thousand patterns, which is a load-time cost the scan
            // does not pay and which has nothing to do with what is compared.
            let automaton = build_automaton(&class.atoms, class.folded);

            let (ours, mut found_ours) = time_set(&set, haystack);
            let (theirs, mut found_theirs) = time_automaton(&automaton, haystack);
            found_ours.sort_unstable();
            found_theirs.sort_unstable();
            if found_ours != found_theirs {
                let first = found_ours
                    .iter()
                    .zip(&found_theirs)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                eprintln!(
                    "!! the two matchers disagree on {} over {buffer_name}: {} against {} \
                     matches, first difference at index {first}: {:?} against {:?} — one of them \
                     is wrong, so the timings below mean nothing",
                    class.name,
                    found_ours.len(),
                    found_theirs.len(),
                    found_ours.get(first),
                    found_theirs.get(first)
                );
                return ExitCode::FAILURE;
            }

            let (ours_visit, our_sum) = time_set_visiting(&set, haystack);
            let (theirs_visit, their_sum) = time_automaton_visiting(&automaton, haystack);
            if our_sum != their_sum {
                eprintln!(
                    "!! the two matchers visit different matches on {} over {buffer_name}: the \
                     aggregate of (pattern, offset) over every match is {our_sum:#x} against \
                     {their_sum:#x}",
                    class.name
                );
                return ExitCode::FAILURE;
            }

            for (label, mine, its) in [
                ("vector", ours, theirs),
                ("visit", ours_visit, theirs_visit),
            ] {
                println!(
                    "  {:<16} AtomSet    {:>12}  {:>6.0} MB/s   {label}",
                    class.name,
                    format!("{mine:?}"),
                    mb_per_second(data.len(), mine)
                );
                println!(
                    "  {:<16} AhoC       {:>12}  {:>6.0} MB/s   {label}, AtomSet is {:.2}x its \
                     speed",
                    class.name,
                    format!("{its:?}"),
                    mb_per_second(data.len(), its),
                    its.as_secs_f64() / mine.as_secs_f64(),
                );
            }
            println!(
                "  {:<16}            storing every match costs {:?} more than visiting it ({:.0}% \
                 of the visiting scan), {} matches, {} atoms",
                class.name,
                ours.saturating_sub(ours_visit),
                ours.saturating_sub(ours_visit).as_secs_f64() * 100.0 / ours_visit.as_secs_f64(),
                found_ours.len(),
                class.atoms.len()
            );
            ours_total += ours;
            theirs_total += theirs;
            ours_visit_total += ours_visit;
            theirs_visit_total += theirs_visit;
        }

        println!(
            "  {:<16} AtomSet    {:>12}  {:>6.0} MB/s   both groups, vector",
            "all",
            format!("{ours_total:?}"),
            mb_per_second(data.len(), ours_total)
        );
        println!(
            "  {:<16} AhoC       {:>12}  {:>6.0} MB/s   both groups, vector, the prefilter's \
             search as it stands: AtomSet is {:.2}x its speed",
            "all",
            format!("{theirs_total:?}"),
            mb_per_second(data.len(), theirs_total),
            theirs_total.as_secs_f64() / ours_total.as_secs_f64()
        );
        println!(
            "  {:<16} AtomSet    {:>12}  {:>6.0} MB/s   both groups, visited",
            "all",
            format!("{ours_visit_total:?}"),
            mb_per_second(data.len(), ours_visit_total)
        );
        println!(
            "  {:<16} AhoC       {:>12}  {:>6.0} MB/s   both groups, visited: AtomSet is {:.2}x \
             its speed",
            "all",
            format!("{theirs_visit_total:?}"),
            mb_per_second(data.len(), theirs_visit_total),
            theirs_visit_total.as_secs_f64() / ours_visit_total.as_secs_f64()
        );
    }
    ExitCode::SUCCESS
}

/// Time one run of this matcher over one buffer, best of [`RUNS`], and return
/// the best time together with the matches it found.
///
/// The matches are returned rather than only counted because the comparison
/// against the automaton has to be made on the match *set*, not on the count:
/// two matchers can agree on 10,787,610 and disagree about which ten million.
fn time_set(set: &AtomSet, data: &[u8]) -> (Duration, Vec<(u32, u32)>) {
    let mut out = Vec::new();
    let mut best = Duration::MAX;
    let mut found = Vec::new();
    for _ in 0..RUNS {
        let started = Instant::now();
        set.find_all(data, &mut out);
        best = best.min(started.elapsed());
        std::hint::black_box(&out);
    }
    found.extend_from_slice(&out);
    (best, found)
}

/// Build the automaton the prefilter builds, once, so that both of its timings
/// below can share it.
///
/// Building is not free — a third of a second for a hundred thousand four-byte
/// patterns — but it happens once per rule database at load time and the scan
/// pays only for the search, which is what is being compared.
fn build_automaton(atoms: &[Vec<u8>], folded: bool) -> AhoCorasick {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(folded)
        .build(atoms)
        .unwrap_or_else(|error| panic!("building the automaton: {error}"))
}

/// Time the automaton with the matches *materialised* into a vector of
/// `(pattern, offset)`, which is the same store [`AtomSet::find_all`] performs,
/// so that the two vector numbers are comparable.
fn time_automaton(automaton: &AhoCorasick, haystack: &[u8]) -> (Duration, Vec<(u32, u32)>) {
    let mut out = Vec::new();
    let mut best = Duration::MAX;
    let mut found = Vec::new();
    for _ in 0..RUNS {
        let started = Instant::now();
        // `find_overlapping_iter`, because that is what the prefilter uses and
        // because dropping overlaps is a false negative: `bcde` is in `abcde`
        // too.
        out.clear();
        out.extend(
            automaton
                .find_overlapping_iter(haystack)
                .map(|hit| (hit.pattern().as_u32(), hit.start() as u32)),
        );
        best = best.min(started.elapsed());
        std::hint::black_box(&out);
    }
    found.extend_from_slice(&out);
    (best, found)
}

/// The aggregate both visiting matchers compute per match, so that neither can
/// fold the loop away and the two are doing identical work with it.
///
/// A wrapping sum rather than a count, because a count is one instruction and
/// would make the comparison below a comparison of two matchers that are both
/// doing nothing.
#[inline(always)]
fn absorb(sum: u64, id: u32, at: u32) -> u64 {
    sum.wrapping_add(u64::from(id) | (u64::from(at) << 32))
}

/// Time this matcher handing each match to a closure instead of storing it.
///
/// This is the shape the prefilter actually uses: it walks the matches, sets a
/// bit per string and keeps the offsets in a window, and never builds the
/// 10,787,610-element vector that `find_all` would. It is timed because the
/// difference between the two was worth knowing and was not guessable: writing
/// all 86 MB of matches down costs only 4-6% more than visiting them.
fn time_set_visiting(set: &AtomSet, data: &[u8]) -> (Duration, u64) {
    let mut best = Duration::MAX;
    let mut sum = 0u64;
    for _ in 0..RUNS {
        let mut running = 0u64;
        let started = Instant::now();
        set.for_each_match(data, |id, at| running = absorb(running, id, at));
        best = best.min(started.elapsed());
        sum = running;
    }
    std::hint::black_box(sum);
    (best, sum)
}

/// The same, for the automaton: `find_overlapping_iter(...).for_each(...)`,
/// which is what the prefilter does with it today.
fn time_automaton_visiting(automaton: &AhoCorasick, haystack: &[u8]) -> (Duration, u64) {
    let mut best = Duration::MAX;
    let mut sum = 0u64;
    for _ in 0..RUNS {
        let mut running = 0u64;
        let started = Instant::now();
        automaton.find_overlapping_iter(haystack).for_each(|hit| {
            running = absorb(running, hit.pattern().as_u32(), hit.start() as u32);
        });
        best = best.min(started.elapsed());
        sum = running;
    }
    std::hint::black_box(sum);
    (best, sum)
}

/// The ASCII fold, the same one Aho-Corasick performs inside the automaton when
/// it is built case-insensitively, done here as a pass of its own.
fn fold(data: &[u8]) -> Vec<u8> {
    // A table rather than a branch or an arithmetic trick, so that it is one
    // load per byte and obviously right for all 256 values.
    let mut lower = [0u8; 256];
    for (byte, slot) in lower.iter_mut().enumerate() {
        *slot = (byte as u8).to_ascii_lowercase();
    }
    data.iter().map(|byte| lower[*byte as usize]).collect()
}

fn mb_per_second(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / elapsed.as_secs_f64() / 1e6
}

/// The shape of an atom set, which is what the design is fitted to.
fn report_census(class: &Class) {
    if class.atoms.is_empty() {
        return;
    }
    let set = AtomSet::new(&class.atoms);
    let stats = set.stats();
    let mut lengths: BTreeMap<usize, usize> = BTreeMap::new();
    let mut first_bytes: BTreeMap<u8, usize> = BTreeMap::new();
    let mut prefixes: BTreeMap<u32, usize> = BTreeMap::new();
    let mut distinct: BTreeSet<&[u8]> = BTreeSet::new();
    for atom in &class.atoms {
        distinct.insert(atom.as_slice());
        *lengths.entry(atom.len()).or_insert(0) += 1;
        if let Some(&first) = atom.first() {
            *first_bytes.entry(first).or_insert(0) += 1;
        }
        if atom.len() >= 3 {
            let prefix = ((atom[0] as u32) << 16) | ((atom[1] as u32) << 8) | atom[2] as u32;
            *prefixes.entry(prefix).or_insert(0) += 1;
        }
    }

    println!("\n=== census: {} ===", class.name);
    println!(
        "  {} atoms, {} of them distinct byte strings, {} distinct first bytes, \
         {} distinct three-byte prefixes",
        stats.atoms,
        distinct.len(),
        first_bytes.len(),
        prefixes.len()
    );
    println!(
        "  lengths: {};  longest {}",
        lengths
            .iter()
            .map(|(length, count)| format!("{length} bytes x {count}"))
            .collect::<Vec<_>>()
            .join(", "),
        stats.longest_atom
    );
    println!(
        "  gated {} ({:.2}%), short {} ({:.2}%)",
        stats.gated_atoms,
        percent(stats.gated_atoms, stats.atoms),
        stats.short_atoms,
        percent(stats.short_atoms, stats.atoms)
    );
    println!(
        "  prefix-only atoms (confirmed by the gate alone): {}",
        stats.prefix_only_atoms
    );
    println!(
        "  buckets: largest holds {} atoms; whole table {} KiB",
        stats.largest_bucket,
        stats.table_bytes / 1024
    );

    // The question the design turns on: how much work one first byte's group
    // carries, and how many distinct prefixes that work is spread over.
    let mut per_first: Vec<(u8, usize)> = first_bytes.iter().map(|(b, n)| (*b, *n)).collect();
    per_first.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let busiest: Vec<String> = per_first
        .iter()
        .take(8)
        .map(|(byte, count)| format!("{} x {count}", show(*byte)))
        .collect();
    println!("  busiest first bytes: {}", busiest.join(", "));
    println!(
        "  first-byte group sizes: busiest {}, median {}",
        per_first.first().map_or(0, |(_, count)| *count),
        per_first.get(per_first.len() / 2).map_or(0, |(_, n)| *n)
    );

    let mut buckets: Vec<usize> = prefixes.values().copied().collect();
    buckets.sort_unstable_by(|a, b| b.cmp(a));
    println!(
        "  prefix buckets: largest {}, tenth largest {}, median {}",
        buckets.first().copied().unwrap_or(0),
        buckets.get(9).copied().unwrap_or(0),
        buckets.get(buckets.len() / 2).copied().unwrap_or(0)
    );
}

/// A 256-entry table as source lines, 16 to a line, for a pasteable histogram.
fn numbers(counts: &[u32; 256]) -> String {
    let mut lines = Vec::new();
    for chunk in counts.chunks(16) {
        let entries: Vec<String> = chunk.iter().map(|count| count.to_string()).collect();
        lines.push(format!("    {},", entries.join(", ")));
    }
    lines.join(
        "
",
    )
}

/// The histograms the generator is built from, printed as Rust source so that a
/// re-measurement is pasted back into this file rather than transcribed.
fn print_histograms(classes: &[Class]) {
    let mut first = [0u32; 256];
    let mut tail = [0u32; 256];
    let mut lengths: BTreeMap<usize, u32> = BTreeMap::new();
    for atom in classes
        .iter()
        .filter(|class| !class.folded)
        .flat_map(|class| &class.atoms)
    {
        if let Some(&byte) = atom.first() {
            first[byte as usize] += 1;
        }
        for byte in &atom[1..] {
            tail[*byte as usize] += 1;
        }
        *lengths.entry(atom.len()).or_insert(0) += 1;
    }
    println!("\n=== the measured histograms, as source ===");
    let entries: Vec<String> = lengths
        .iter()
        .map(|(length, count)| format!("({length}, {count})"))
        .collect();
    println!(
        "const LENGTH_COUNTS: &[(usize, u32)] = &[{}];
const FIRST_BYTE_COUNTS: [u32; 256] = [
{}
];
const TAIL_BYTE_COUNTS: [u32; 256] = [
{}
];",
        entries.join(", "),
        numbers(&first),
        numbers(&tail)
    );
}

/// The measured histograms of the real atom set, pasted here from `--census`
/// output so that a run without the rule database generates a set with
/// the real set's shape rather than a guessed one.
///
/// Re-measure with `cargo run --release --example
/// pattern_bench -- --census` and paste what it prints over the three
/// declarations below; the assertion in `generated_classes` refuses to build a
/// generated set from empty ones.
const LENGTH_COUNTS: &[(usize, u32)] = &[(3, 4680), (4, 97114)];
const FIRST_BYTE_COUNTS: [u32; 256] = [
    2537, 539, 240, 645, 230, 138, 196, 169, 198, 171, 216, 269, 198, 196, 115, 1677, 178, 174,
    118, 170, 139, 116, 192, 146, 136, 129, 121, 150, 130, 110, 119, 154, 474, 192, 360, 281, 744,
    799, 383, 218, 328, 242, 286, 529, 179, 551, 925, 1017, 368, 585, 332, 1647, 265, 235, 248,
    213, 255, 351, 262, 534, 838, 326, 140, 167, 442, 1100, 457, 1015, 919, 885, 536, 679, 3367,
    1074, 204, 262, 1268, 765, 492, 365, 1588, 624, 874, 1723, 603, 849, 833, 947, 352, 758, 234,
    1060, 1039, 278, 321, 567, 131, 543, 443, 1018, 704, 680, 1322, 535, 627, 702, 829, 262, 663,
    816, 552, 549, 663, 130, 696, 1282, 1372, 849, 343, 501, 315, 232, 169, 236, 213, 164, 164,
    121, 290, 326, 104, 2219, 245, 1205, 106, 109, 384, 1890, 409, 4615, 106, 1938, 129, 106, 374,
    111, 104, 101, 105, 101, 103, 107, 138, 172, 106, 103, 134, 102, 101, 102, 108, 110, 331, 101,
    107, 129, 105, 103, 118, 102, 116, 136, 108, 105, 107, 103, 124, 103, 109, 103, 105, 105, 118,
    112, 210, 208, 185, 123, 106, 104, 122, 134, 262, 340, 186, 367, 174, 109, 486, 822, 139, 210,
    108, 118, 170, 111, 111, 119, 145, 200, 127, 167, 109, 112, 135, 140, 141, 123, 122, 119, 139,
    111, 123, 119, 110, 110, 155, 101, 109, 109, 104, 107, 207, 145, 113, 742, 148, 104, 110, 104,
    183, 123, 236, 372, 109, 110, 213, 332, 137, 128, 113, 122, 138, 118, 149, 1768,
];
const TAIL_BYTE_COUNTS: [u32; 256] = [
    18598, 1820, 1269, 1260, 2255, 1038, 1002, 898, 1981, 661, 781, 641, 1540, 768, 503, 2708,
    1422, 785, 487, 554, 888, 763, 607, 537, 801, 457, 431, 470, 695, 454, 426, 789, 3715, 509,
    614, 468, 3867, 1032, 414, 478, 1168, 498, 569, 865, 589, 984, 1306, 979, 1397, 1051, 1007,
    2004, 1015, 760, 741, 698, 928, 980, 1164, 990, 672, 710, 534, 642, 973, 1923, 963, 1612, 2646,
    3950, 1187, 1006, 3750, 1267, 499, 589, 1868, 1880, 978, 899, 2306, 1030, 1457, 2150, 1512,
    1514, 1728, 1651, 787, 715, 579, 715, 1283, 1140, 797, 1387, 488, 4452, 1346, 3256, 2632, 6482,
    1849, 1229, 2597, 3708, 1524, 985, 2562, 1883, 3459, 4361, 2639, 522, 3901, 3731, 5300, 3451,
    1150, 1166, 1100, 1117, 535, 455, 809, 821, 586, 481, 796, 759, 360, 2643, 1540, 3150, 463,
    412, 766, 4512, 590, 6622, 686, 4239, 424, 367, 610, 344, 347, 336, 582, 631, 352, 342, 406,
    376, 369, 330, 471, 466, 329, 340, 444, 446, 339, 383, 452, 475, 326, 325, 399, 319, 377, 447,
    447, 331, 410, 364, 473, 368, 334, 343, 485, 541, 810, 672, 728, 568, 536, 400, 517, 538, 585,
    418, 3393, 1332, 941, 1115, 1839, 494, 1189, 1641, 1064, 1034, 574, 528, 514, 418, 570, 536,
    1141, 654, 850, 662, 450, 421, 805, 673, 940, 500, 430, 719, 483, 380, 459, 449, 748, 467, 419,
    385, 528, 561, 393, 381, 1713, 665, 434, 875, 1159, 433, 391, 450, 1123, 558, 497, 576, 587,
    384, 840, 676, 1551, 687, 544, 552, 1004, 591, 889, 3928,
];

/// The real atom list, split the way the prefilter splits it.
///
/// `None` when the rule database is not there to read — a machine that has
/// never built one — and the caller falls back to the generated set and says so.
fn real_classes() -> Option<Vec<Class>> {
    let database = RuleDatabase::load(DATABASE).ok()?;
    // Deduplicated by the whole atom — bytes *and* trailer, which is what
    // `Prefilter::build` dedups by, and why two atoms with the same bytes can
    // both be here.
    let mut sensitive: Vec<Vec<u8>> = Vec::new();
    let mut insensitive: Vec<Vec<u8>> = Vec::new();
    let mut seen: BTreeSet<(Vec<u8>, Vec<u8>)> = BTreeSet::new();
    let mut iseen: BTreeSet<(Vec<u8>, Vec<u8>)> = BTreeSet::new();
    let mut rules = 0usize;
    for rule in database.rules() {
        rules += 1;
        for string in rule.string_atoms() {
            for group in &string.groups {
                for atom in group {
                    let key = (atom.bytes.to_vec(), atom.trailer.to_vec());
                    if atom.nocase {
                        if iseen.insert(key) {
                            insensitive.push(atom.bytes.to_vec());
                        }
                    } else if seen.insert(key) {
                        sensitive.push(atom.bytes.to_vec());
                    }
                }
            }
        }
    }
    println!(
        "atom source: the rule database, {rules} rules, {} case-sensitive atoms and {}          case-insensitive ones after dedup",
        sensitive.len(),
        insensitive.len()
    );
    Some(vec![
        Class {
            name: "case-sensitive",
            atoms: sensitive,
            folded: false,
        },
        Class {
            // Folded, because a matcher handed bytes cannot find `HTTP` in a
            // buffer unless the haystack is folded too. Aho-Corasick folds
            // inside its automaton instead; the fold below is what that costs
            // this design, and it is timed and printed.
            name: "case-insensitive",
            atoms: insensitive.iter().map(|atom| fold(atom)).collect(),
            folded: true,
        },
    ])
}

/// `part` as a percentage of `whole`, for the census.
fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

/// A byte, for the census: printable as a character, everything else as hex.
fn show(byte: u8) -> String {
    if byte.is_ascii_graphic() || byte == b' ' {
        format!("{:?}", byte as char)
    } else {
        format!("{byte:#04x}")
    }
}

/// One case-sensitive class with the measured shape of the real set. There is no
/// generated case-insensitive class: the real one is a small fraction of the
/// atoms and a generated stand-in for it would measure noise.
fn generated_classes() -> Vec<Class> {
    let total: u32 = LENGTH_COUNTS.iter().map(|(_, count)| *count).sum();
    assert!(
        FIRST_BYTE_COUNTS.iter().any(|count| *count > 0)
            && TAIL_BYTE_COUNTS.iter().any(|count| *count > 0),
        "the generator's histograms are empty — run once with \
         `--census` against the real database and paste the printed histograms into this file"
    );
    vec![Class {
        name: "generated",
        atoms: generated_atoms(total as usize),
        folded: false,
    }]
}

/// Atoms with the measured shape of the real set.
///
/// Deterministic, and drawn without replacement: a rule set's atoms are
/// deduplicated before they reach a matcher, so a list with duplicates in it
/// would not be the same workload and would not exercise the same thing.
///
/// What this cannot reproduce is the correlation between the bytes of one atom.
/// A real atom is a fragment of a real string — `http`, `softwar`, `MZ\x90\0` —
/// so its bytes are not independent and its three-byte prefixes cluster in a way
/// that sampling each byte from its own marginal distribution does not produce.
/// `--census` prints both bucket shapes so that cost is on the page, and the
/// number this crate is quoted for is the one from the real set.
fn generated_atoms(count: usize) -> Vec<Vec<u8>> {
    let first_table = cumulative(&FIRST_BYTE_COUNTS);
    let tail_table = cumulative(&TAIL_BYTE_COUNTS);
    let length_table = cumulative(&length_vector());

    let mut state = 0x2545_F491_4F6C_DD1D;
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut atoms = Vec::with_capacity(count);
    while atoms.len() < count {
        let length = pick(&mut state, &length_table).max(3);
        let mut atom = Vec::with_capacity(length);
        atom.push(pick(&mut state, &first_table) as u8);
        while atom.len() < length {
            atom.push(pick(&mut state, &tail_table) as u8);
        }
        if seen.insert(atom.clone()) {
            atoms.push(atom);
        }
    }
    atoms
}

/// The length counts as a 256-row table, so every histogram goes through the
/// same picker.
fn length_vector() -> [u32; 256] {
    let mut counts = [0u32; 256];
    for (length, count) in LENGTH_COUNTS {
        if *length < 256 {
            counts[*length] = *count;
        }
    }
    counts
}

/// Running totals, so one number drawn from the total picks a value and a
/// binary search finds it.
fn cumulative(counts: &[u32; 256]) -> Vec<u32> {
    let mut running = 0u32;
    counts
        .iter()
        .map(|count| {
            running += count;
            running
        })
        .collect()
}

/// Draw a value from a cumulative table, by its weight.
fn pick(state: &mut u64, table: &[u32]) -> usize {
    let Some(&total) = table.last() else {
        return 0;
    };
    if total == 0 {
        return 0;
    }
    let target = (next(state) % u64::from(total)) as u32;
    match table.binary_search(&target) {
        Ok(index) | Err(index) => index.min(table.len() - 1),
    }
}

/// xorshift64, the generator the other tools in this workspace use, so that two
/// runs of this comparison are the same run.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
