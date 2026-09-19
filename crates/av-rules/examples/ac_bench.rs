//! Development tool: how fast is the prefilter's automaton, and what sets the speed.
//!
//! The rule-set tool reports the *selectivity* of the prefilter — how much of
//! the rule set survives it. This reports its speed, and the two numbers
//! together decide whether the prefilter is doing its job: a filter that is fast
//! but passes everything has bought nothing, and so has a selective one that
//! takes longer than matching the rules directly would have.
//!
//! ```text
//! cargo run --release --example ac_bench
//! ```
//!
//! # What the measurements say
//!
//! Cost tracks the *size of the automaton*, not the number of matches — the
//! haystack is random and almost nothing matches it. Three things were ruled
//! out before that conclusion:
//!
//! - **The iterator.** `find_iter` and `find_overlapping_iter` are within noise
//!   of each other at every size, so the prefilter's choice of the overlapping
//!   one — which it needs, because dropping overlaps is a false negative; see
//!   the test in `prefilter.rs` — costs nothing.
//! - **The automaton's own prefilter.** `.prefilter(true)` scans for a rare byte
//!   with `memchr` and only runs the automaton near candidates, which is exactly
//!   the shape of this workload. It changes nothing, and the reason is visible in
//!   the rule set: with tens of thousands of atoms the union of their rare bytes
//!   is most of the alphabet, so there is no rare byte left to scan for.
//! - **Atom length.** Making the atoms longer narrows what they match and
//!   deepens the trie; making them shorter does the reverse. Neither is a lever
//!   worth pulling: 3 bytes through 8 all land between 20 and 24 MB/s, so the
//!   second table exists to close the question rather than because the answer
//!   was in doubt.
//!
//! What is left is the transition tables themselves. At a thousand patterns they
//! fit in cache and the loop runs at memory speed; by sixty-seven thousand they
//! do not, and every byte of the buffer pays for a miss. This is the range
//! signature engines live in, so it is not broken — but it is the thing to fix
//! first if scanning turns out to be the bottleneck, and the fix is a matcher
//! specialised for fixed-length atoms rather than a general automaton. Note that
//! it is the *state count* that costs, and state count comes from the number of
//! atoms, so the lever is how many atoms there are and not what they look like.

// A development tool whose job is to fail loudly on bad input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use aho_corasick::{AhoCorasickBuilder, MatchKind};

const BUFFER: usize = 1 << 20;

fn main() -> std::process::ExitCode {
    // The sizes bracket the real rule set: 67,218 atoms is what compiling the
    // 10,764-rule file produces, measured by `compile_ruleset`.
    println!("=== throughput against atom count (atoms are 4 bytes) ===");
    for count in [1_000usize, 10_000, 33_000, 67_218] {
        let patterns = atoms(count, 4);
        let haystack = random_buffer(0x9E37_79B9_7F4A_7C15);
        let (elapsed, hits) = measure(&patterns, &haystack);
        report(&format!("{count} atoms"), elapsed, hits);
    }

    println!("\n=== throughput against atom length (67,218 atoms) ===");
    // Shorter atoms make a *narrower* trie but match far more often; longer ones
    // make a deeper one. The sweet spot for a prefilter is set by which of those
    // costs more, and the answer is not obvious without measuring it.
    for length in [3usize, 4, 5, 6, 8] {
        let patterns = atoms(67_218, length);
        let haystack = random_buffer(0x9E37_79B9_7F4A_7C15);
        let (elapsed, hits) = measure(&patterns, &haystack);
        report(&format!("{length}-byte atoms"), elapsed, hits);
    }

    std::process::ExitCode::SUCCESS
}

/// Deterministic atoms of a fixed length, with the shape the real rule set has:
/// distinct from each other, and spread over the whole byte range.
fn atoms(count: usize, length: usize) -> Vec<Vec<u8>> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..count)
        .map(|_| next().to_le_bytes()[..length].to_vec())
        .collect()
}

/// The best of several runs, to leave out the first pass's page faults.
fn measure(patterns: &[Vec<u8>], haystack: &[u8]) -> (Duration, usize) {
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(patterns)
        .unwrap();
    let mut best = Duration::MAX;
    let mut hits = 0usize;
    for _ in 0..5 {
        let started = Instant::now();
        hits = ac.find_overlapping_iter(haystack).count();
        std::hint::black_box(hits);
        best = best.min(started.elapsed());
    }
    (best, hits)
}

fn report(name: &str, elapsed: Duration, hits: usize) {
    let throughput = BUFFER as f64 / elapsed.as_secs_f64() / 1e6;
    println!("  {name:<18} {elapsed:>12?}  {throughput:>7.0} MB/s  {hits} matches");
}

fn random_buffer(mut state: u64) -> Vec<u8> {
    (0..BUFFER)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}
