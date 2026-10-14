//! Fixed-length atom matching, for the rule engine's prefilter.
//!
//! # What this replaces, and why
//!
//! The prefilter compiles every atom of every string in a rule set into one
//! Aho-Corasick automaton and makes one pass over the file with it. That pass
//! is the bottleneck of the whole product: measured at 20 to 24 MB/s across atom
//! counts from a thousand to sixty-seven thousand, flat in the number of
//! matches and linear in the number of automaton *states*. Sixty-seven thousand
//! four-byte atoms is roughly 270,000 states, so the transition tables do not
//! fit in cache and every input byte pays for a miss. `examples/ac_bench.rs` in
//! `av-rules` ruled out the three explanations that were not it (the iterator
//! API, the automaton's own prefilter, and atom length), which is what leaves
//! the state count, and the state count is a consequence of using a general
//! automaton to search for patterns that are all the same short length.
//!
//! A fixed-length matcher need not carry state between bytes at all. Every
//! pattern is four bytes, so a match is a property of one four-byte window, and
//! the question "which atoms start here" can be answered by two tables keyed on
//! the window's own bytes. That is what this crate is.
//!
//! # The design
//!
//! Three levels, each one asking a smaller question than the last:
//!
//! ```text
//!   byte b0                    256-entry table, 512 bytes
//!     │  can any atom start with b0?
//!     ▼
//!   bytes b1 b2                per-first-byte bitmap, 8 KiB each
//!     │  is (b1, b2) a prefix of some atom starting with b0?
//!     ▼
//!   bytes b3..                 bucket of candidate atoms, confirmed byte by byte
//!     │  is this atom's tail here too?
//!     ▼
//!   (atom id, offset)
//! ```
//!
//! * **The first level** is a table indexed by the first byte. One load and one
//!   comparison reject a byte that starts no atom at all, which is most bytes
//!   in most files.
//! * **The second level** is the interesting one. For each first byte that can
//!   start an atom there is a bitmap of 65,536 bits covering the second and
//!   third byte together: 8 KiB, one shift and one bit test. The bitmap is
//!   *per first byte*, which is what bounds the working set: the working set of a scan
//!   inside a run of the file that shares a first byte is that byte's own
//!   8 KiB, and that fits in L1. A single shared bitmap over all three-byte
//!   prefixes would be 16 MiB and would miss cache on every byte instead.
//! * **The third level** is reached only when a three-byte prefix really is in
//!   the set, which is rare. The bitmap bit's rank among the set bits of its
//!   own group is the index of the prefix's bucket, so one popcount turns a
//!   bitmap hit into a short list of candidate atoms; their remaining bytes are
//!   compared directly. Only an atom whose bytes are all there is reported.
//!
//! A group with fewer than a handful of distinct prefixes is not given a bitmap
//! at all. The bitmap is read one word at a time and the words a file touches
//! are spread across all 8 KiB of it, so for four atoms a linear walk over four
//! entries in a few dozen bytes of L1 is cheaper than the cache lines.
//!
//! # Atoms shorter than three bytes
//!
//! Level two needs three bytes to work with, so a one- or two-byte atom cannot
//! use it. Those atoms go on a linear path: at every offset, each of them is
//! compared directly. That is `O(offsets × short atoms)` and would be a poor
//! way to search a rule set with a thousand of them. The crate reports
//! [`AtomSetStats::short_atoms`] so that a set which does have them says so
//! rather than hiding it, but it costs nothing at all when the count is zero
//! and it is one comparison per atom per offset, so a handful is free.
//!
//! **The rule set this is built for has none.** `av_rules::atoms::MIN_ATOM_LEN`
//! is 3 and `MAX_ATOM_LEN` is 4, so every atom the engine produces is three or
//! four bytes and the whole set takes the gated path. The short path exists for
//! the interface's sake ([`AtomSet::new`] takes the bytes it is given) and is
//! covered by tests rather than by the benchmark.
//!
//! # The measured distribution the design is fitted to
//!
//! Every constant above is a consequence of these numbers rather than of a
//! guess, so they are worth having in front of the code. Measured over the real
//! rule set (10,764 rules, 101,794 case-sensitive atoms and 1,740
//! case-insensitive ones after deduplication) by `cargo run --release
//! --example pattern_bench -- --census` in `av-rules`, which is where the
//! compiled rule database lives:
//!
//! ```text
//! case-sensitive    101,794 atoms   256 distinct first bytes   54,668 distinct prefixes
//!   lengths         3 bytes x 4,680        4 bytes x 97,114      longest 4
//!   gated           101,794 (100.00%)      short 0 (0.00%)
//!   prefix-only     4,680                 (confirmed by the gate alone)
//!   whole table     5,091 KiB             largest bucket 292
//!   busiest first   0x8b x 4,615, 'H' x 3,367, 0x00 x 2,537, 0x83 x 2,219
//!   group sizes     busiest 4,615         median 186
//!   prefixes        largest 292           tenth largest 156      median 1
//!
//! case-insensitive    1,740 atoms    68 distinct first bytes    1,003 distinct prefixes
//!   lengths         3 bytes x 9            4 bytes x 1,731       longest 4
//!   whole table     851 KiB               largest bucket 36
//! ```
//!
//! Four things in the design come straight out of that table:
//!
//! * **Every atom is gated.** `short_atoms` is zero for both sets, because
//!   `av_rules::atoms` cannot produce an atom shorter than three bytes. The
//!   linear path is dead code on this workload, which is why it is written for
//!   clarity rather than for speed and why its cost is reported rather than
//!   optimized away.
//! * **The median bucket holds one atom.** Half of the 54,668 prefixes are
//!   carried by a single atom, so the third level is reached rarely and is
//!   short when it is. This is what makes two levels of gate worth having: the
//!   work saved is at level two, and level three is nearly free.
//! * **The busiest bucket holds 292.** `WALK_LIMIT` is 8, so the handful of
//!   buckets a PE hits at every offset are the ones that take the binary search
//!   rather than the walk. Without it those offsets would pay 292 entry reads
//!   each, and they are exactly the offsets that occur most.
//! * **4,680 atoms end at their prefix.** Those are three-byte atoms, and the
//!   gate alone confirms them: every occurrence of such an atom's prefix *is* a
//!   match, so this number (4.6% of the set) is the floor on how many matches
//!   a scan must report whatever it does. It is one of the reasons the whole
//!   set's match count on `shell32.dll` is 10.8 million and not thousands.

// Tests opt out of the panic-family lints: unwrapping is how an assertion is
// written, and a panic in a test is the desired outcome, not a defect.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod atom_set;

pub use atom_set::{AtomSet, AtomSetStats, MIN_GATED_LEN};
