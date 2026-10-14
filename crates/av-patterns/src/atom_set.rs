//! The atom set itself: build the two-level gate, then run it over a buffer.
//!
//! The design and the measurements that justify it are in the crate
//! documentation; this module is the mechanism. Four things are worth knowing
//! before reading it:
//!
//! * Nothing here allocates during a scan. `find_all` writes into the caller's
//!   vector and reads only from `self` and `data`.
//! * Every table is indexed in a way that is true for *every* group, with no
//!   exceptions and no special cases. A group that skipped a table would shift
//!   every group after it, and the failure would be a silent missed match
//!   rather than a crash — see the test that pins this down.
//! * A gate hit is turned into a bucket with one popcount, and the bucket is
//!   then narrowed by the atom's *next* byte before any entry is confirmed. The
//!   buckets that cost anything are the ones a file hits most often, which are
//!   exactly the ones with the most entries, so the narrowing is what keeps a
//!   common three-byte prefix from being paid for at every offset.
//! * There is no `unsafe`. The loop is written so that the bounds checks the
//!   compiler must keep are the ones that are free, and the ones it cannot
//!   prove are behind a table index that a hit needs anyway.

use std::fmt;

/// Shortest atom the gate can search for.
///
/// Two levels need three bytes to work with: a first byte to choose the
/// bitmap, and the next two to index inside it. An atom shorter than that
/// cannot form a prefix and takes the path described at
/// [`AtomSet::short_atom_count`].
pub const MIN_GATED_LEN: usize = 3;

/// Bits in one group's prefix bitmap: the second and third byte of an atom.
///
/// Sixteen bits of prefix is why the bitmap is 8 KiB and not larger. A first
/// byte with a group of its own, an 8 KiB bitmap and the rank table beside it
/// come to 12 KiB, which is the whole reason a gate hit is cheap: it is one
/// byte value's working set, and it stays in L1 while the scan moves through a
/// run of the file that shares that byte value.
const PREFIX_BITS: usize = 1 << 16;

/// 64-bit words in one group's prefix bitmap.
const PREFIX_WORDS: usize = PREFIX_BITS / 64;

/// Bytes of an atom's tail the confirmation keeps inline, after the prefix.
///
/// The prefix proves three bytes. Everything from the fourth up to the
/// eleventh is packed into the entry's `tail` and compared with one masked
/// load. An atom longer than this re-checks its remainder as a slice, which
/// costs a call and is never taken on the rule sets this is built for — their
/// atoms are four bytes at most, and the crate documentation has the
/// measurement.
const INLINE_TAIL: usize = 8;

/// Longest atom that stays entirely inside its entry.
const INLINE_LEN: usize = MIN_GATED_LEN + INLINE_TAIL;

/// "No atom starts with this byte", in [`AtomSet::first`].
const NO_GROUP: u16 = u16::MAX;

/// How many entries a bucket may hold before looking inside it is worth more
/// than reading it from the front.
///
/// A bucket is `O(bucket)` to walk, and the buckets that matter are not the
/// average one — that holds two atoms — but the ones a file hits at every
/// offset. On `shell32.dll` the busiest bucket holds 292 atoms, and the offsets
/// that reach it are the ones whose three bytes are the most common three bytes
/// in a PE, so a walk of 292 entries per offset is paid again and again. Below
/// this many entries the walk is shorter than the search would be; above it the
/// entries are sorted by their next byte and looked up instead.
const WALK_LIMIT: usize = 8;

/// The gate's own view of one atom, after it has been sorted into a group.
///
/// The atom's three-byte prefix is not stored: the bucket an entry sits in *is*
/// the prefix, proved by the bitmap before the entry is ever read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// The atom's index in the slice the set was built from.
    id: u32,
    /// The atom's whole length, bytes.
    len: u32,
    /// Bytes [`MIN_GATED_LEN`] onwards, the first [`INLINE_TAIL`] of them,
    /// little-endian in the low bytes.
    tail: u64,
}

impl Entry {
    /// How many bytes of `tail` are real for an atom of this length.
    fn tail_len(&self) -> usize {
        (self.len as usize - MIN_GATED_LEN).min(INLINE_TAIL)
    }

    /// Whether the atom runs past the slice the entry describes.
    fn has_deep_tail(&self) -> bool {
        self.len as usize > INLINE_LEN
    }

    /// The atom's fourth byte, or zero when the atom ends at the prefix.
    ///
    /// This is the key a bucket's longer entries are sorted by, and the byte a
    /// bucket is looked up by. An atom that ends at its prefix has no fourth
    /// byte, and those entries are sorted into a run of their own at the front
    /// of the bucket so that this never has to be meaningful for them.
    #[inline(always)]
    fn fourth(&self) -> u8 {
        self.tail as u8
    }
}

/// Where a match goes as the scan finds it.
///
/// The gate is written against this rather than against `&mut Vec` so that a
/// caller who does not want the matches collected does not have to have them
/// collected, and so that the two ways of taking them are one loop rather than
/// two that could drift apart. The stores it saves are cheaper than they look —
/// see [`AtomSet::for_each_match`] — but an API that only came in the collecting
/// flavour would be the wrong shape for the prefilter, which walks matches.
///
/// Both implementations run the same loop with one store swapped for one call,
/// so the two produce the same matches in the same order.
trait Sink {
    fn found(&mut self, id: u32, at: u32);
}

impl Sink for Vec<(u32, u32)> {
    #[inline(always)]
    fn found(&mut self, id: u32, at: u32) {
        self.push((id, at));
    }
}

/// A [`Sink`] over a closure, so that `for_each_match` monomorphises to a call
/// rather than to a vector push.
struct Each<F>(F);

impl<F: FnMut(u32, u32)> Sink for Each<F> {
    #[inline(always)]
    fn found(&mut self, id: u32, at: u32) {
        (self.0)(id, at);
    }
}

/// An atom too short for the gate, with its bytes packed little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShortAtom {
    id: u32,
    len: u8,
    packed: u32,
}

/// What a set was built from, for reporting.
///
/// A rule-set tool wants these numbers: the count is what the matcher was built
/// for, and `short_atoms` is the honest measure of how much of the set fell off
/// the fast path. Zero is the number to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AtomSetStats {
    /// Atoms stored, which is the slice the set was built from, minus any
    /// zero-length atom that was dropped.
    pub atoms: usize,
    /// Atoms long enough to be gated, so `atoms - short_atoms`.
    pub gated_atoms: usize,
    /// Atoms shorter than [`MIN_GATED_LEN`], which take the linear path.
    pub short_atoms: usize,
    /// Atoms that end at the three-byte prefix, so the gate alone confirms
    /// them wherever the prefix occurs.
    ///
    /// This is the number that sets the floor on how many matches a scan can
    /// report: every occurrence of such an atom's prefix *is* a match, and no
    /// amount of confirming can avoid reporting it.
    pub prefix_only_atoms: usize,
    /// First bytes some atom starts with.
    pub distinct_first_bytes: usize,
    /// Distinct three-byte prefixes across the whole set.
    pub distinct_prefixes: usize,
    /// Entries in the largest single prefix bucket: how many atoms share their
    /// first three bytes.
    pub largest_bucket: usize,
    /// Longest atom in the set, bytes.
    pub longest_atom: usize,
    /// Approximate bytes the tables occupy, so a caller can see which level of
    /// cache the gate lives in. Exact except for `Vec` slack.
    pub table_bytes: usize,
}

/// A fixed set of short byte strings, matched at every offset.
///
/// # What it does
///
/// [`find_all`](AtomSet::find_all) reports every occurrence of every atom at
/// every starting offset, **overlapping ones included**. That is not a
/// convenience: the prefilter this replaces selects rules on the atoms present
/// in a file, and `abcde` contains both `abcd` and `bcde` — a matcher that
/// reported one and skipped the other would drop whichever rule depends on the
/// second, which is a missed detection rather than a slower scan.
///
/// # What it is not
///
/// It does not model case, and it does not model the trailer bytes the rule
/// engine carries beside its atoms. A case-insensitive string needs its own
/// set, over the folded atoms, exactly as the prefilter already builds two
/// automata; and an atom's trailer is checked by the caller at each reported
/// offset, which is where it is checked now.
///
/// Two atoms with the same bytes are two entries with two ids, and both are
/// reported. Merging them would make one id unreachable, and an id a caller
/// cannot see is a string it will never select a rule for.
#[derive(Clone)]
pub struct AtomSet {
    /// First byte to group, or [`NO_GROUP`]. One `u16` rather than a `bool`
    /// plus an index because the two answers are needed together, and a table
    /// of 512 bytes is still small enough to live in L1 beside the bitmaps.
    first: [u16; 256],
    /// Per-group prefix bitmaps, [`PREFIX_WORDS`] to a group.
    bitmaps: Vec<u64>,
    /// Per-group prefix ranks, [`PREFIX_WORDS`] plus a closing sentinel each.
    ///
    /// The rank is the number of distinct prefixes before this one in the whole
    /// set, which is exactly the index of the prefix's bucket — so a bitmap hit
    /// turns into a bucket with one popcount and no search. The array is
    /// pre-offset per group at build time rather than corrected at run time,
    /// which is one fewer load on the confirmation path.
    ///
    /// It is a separate array from `bitmaps` rather than a field of the same
    /// struct. Two loads from two arrays look like two cache misses where one
    /// struct field would be one, and merging them was tried and measured: the
    /// merged table is 4.2 MiB against 3.1 MiB, and on a mebibyte of zeros —
    /// where this crate's own numbers are reproducible to half a percent — it
    /// was 3% *slower*, while the automaton beside it did not move at all. The
    /// misses were not what the offset was paying for. See the crate
    /// documentation.
    ///
    /// Indexed at `group * (PREFIX_WORDS + 1)`, which is true of every group and
    /// has to stay that way: see the module documentation.
    ranks: Vec<u32>,
    /// Bucket start per distinct prefix, with a closing sentinel.
    bucket_start: Vec<u32>,
    /// Per bucket, where its entries that have a fourth byte begin, with a
    /// closing sentinel.
    ///
    /// A bucket's entries are in three runs: the atoms that end at the prefix,
    /// which match wherever the prefix does; then the atoms that carry on, in
    /// ascending order of their fourth byte. This is the boundary between them.
    /// Kept beside `bucket_start` rather than derived, because deriving it would
    /// mean a scan over the bucket — the thing the boundary exists to avoid.
    ///
    /// Merging this with `bucket_start` was measured together with the merge
    /// above, and reverted with it.
    long_start: Vec<u32>,
    /// Bucket entries, grouped by prefix.
    entries: Vec<Entry>,
    /// Atoms too short for the gate.
    shorts: Vec<ShortAtom>,
    /// The bytes past [`INLINE_LEN`] of atoms longer than it, and where each
    /// such atom's remainder starts, indexed by atom id. Empty when no atom is
    /// that long, which is the case for every rule set this is built for.
    deep: Vec<u8>,
    deep_off: Vec<u32>,
    stats: AtomSetStats,
}

impl AtomSet {
    /// Build from a set of atoms. This is the expensive half and happens once
    /// per rule database, not once per file.
    ///
    /// An atom of zero bytes is dropped rather than stored. It has no bytes
    /// that must be present, so there is no offset at which it is not present,
    /// and reporting it at every offset of every file would make this a
    /// false-positive generator rather than a matcher. Dropping it is also why
    /// [`AtomSetStats::atoms`] can be one less than the slice's length: it is
    /// the count of atoms the set can actually find. Ids are the input's
    /// indices either way, so dropping one shifts nothing.
    pub fn new(atoms: &[Vec<u8>]) -> Self {
        let mut shorts: Vec<ShortAtom> = Vec::new();
        // `(id, prefix, kind)`, where `kind` orders the atoms inside a bucket:
        // an atom that ends at the prefix is 0 and sorts first, and one that
        // carries on is its fourth byte plus one. Sorting on it is what makes a
        // bucket's longer entries a run per fourth byte, which is what the gate
        // looks up when it has a bucket too big to walk.
        let mut gated: Vec<(u32, u32, u32)> = Vec::with_capacity(atoms.len());
        let mut longest_atom = 0usize;
        let mut deep: Vec<u8> = Vec::new();
        // Asked once, before the loop, rather than per atom: a set with no long
        // atom in it would otherwise rescan the whole list for every atom.
        let mut deep_off: Vec<u32> = if atoms.iter().any(|a| a.len() > INLINE_LEN) {
            vec![u32::MAX; atoms.len()]
        } else {
            Vec::new()
        };

        for (index, bytes) in atoms.iter().enumerate() {
            if bytes.is_empty() {
                continue;
            }
            // A set with more than four billion atoms is not a rule set, and a
            // saturating id keeps a corrupt one from wrapping into another
            // atom's slot. The alternative — panicking — would turn a database
            // problem into a scanner that will not start.
            let id = u32::try_from(index).unwrap_or(u32::MAX);
            longest_atom = longest_atom.max(bytes.len());
            if bytes.len() < MIN_GATED_LEN {
                shorts.push(ShortAtom {
                    id,
                    len: bytes.len() as u8,
                    packed: pack(&bytes[..]),
                });
                continue;
            }
            if bytes.len() > INLINE_LEN {
                deep_off[index] = u32::try_from(deep.len()).unwrap_or(u32::MAX);
                deep.extend_from_slice(&bytes[INLINE_LEN..]);
            }
            let kind = if bytes.len() == MIN_GATED_LEN {
                0
            } else {
                1 + u32::from(bytes[MIN_GATED_LEN])
            };
            gated.push((id, prefix_of(bytes), kind));
        }

        // Group by first byte, then by prefix, then by what follows the prefix.
        // One sort gives all three, and the contiguity it produces is what lets
        // a bucket be a range rather than a list.
        gated.sort_unstable_by_key(|(id, prefix, kind)| (first_byte(*prefix), *prefix, *kind, *id));

        let mut bitmaps: Vec<u64> = Vec::new();
        let mut ranks: Vec<u32> = Vec::new();
        let mut bucket_start: Vec<u32> = Vec::new();
        let mut long_start: Vec<u32> = Vec::new();
        let mut entries: Vec<Entry> = Vec::with_capacity(gated.len());
        let mut first = [NO_GROUP; 256];

        let mut group_count = 0u16;
        let mut prefix_only_atoms = 0usize;
        let mut rank_base = 0u32;
        let mut at = 0usize;
        while at < gated.len() {
            let byte = first_byte(gated[at].1);
            let begin = at;
            while at < gated.len() && first_byte(gated[at].1) == byte {
                at += 1;
            }
            let group = &gated[begin..at];

            first[byte as usize] = group_count;
            group_count += 1;

            // One bitmap for the group, filled from the group's own prefixes.
            // Every group gets one, whatever its size: a group that skipped its
            // bitmap would shift the offset of every group after it.
            let mut words = vec![0u64; PREFIX_WORDS];
            for (_, prefix, _) in group {
                let second_and_third = (*prefix & 0xFFFF) as usize;
                words[second_and_third >> 6] |= 1u64 << (second_and_third & 63);
            }

            // The group's entries, one contiguous bucket per distinct prefix,
            // with the bucket starts recorded as they are found. Prefixes come
            // out in ascending order, which is the order the set bits below are
            // walked in — so the bucket list and the bitmap agree by
            // construction rather than by two passes over the same data.
            let mut starts: Vec<u32> = Vec::new();
            let mut seen = u32::MAX;
            // Where the bucket being built stops being prefix-only, once one of
            // its entries carries on past the prefix. Until then the answer is
            // the bucket's own end, which is only known when it closes — a
            // bucket of nothing but three-byte atoms has no long run at all and
            // must not be given one, or its atoms would be looked for behind a
            // fourth byte they do not have.
            let mut long_at = 0u32;
            let mut seen_long = false;
            for (id, prefix, kind) in group {
                if *prefix != seen {
                    if seen != u32::MAX {
                        // Close the bucket this one follows.
                        long_start.push(if seen_long {
                            long_at
                        } else {
                            entries.len() as u32
                        });
                    }
                    seen = *prefix;
                    starts.push(entries.len() as u32);
                    long_at = 0;
                    seen_long = false;
                }
                if *kind != 0 && !seen_long {
                    long_at = entries.len() as u32;
                    seen_long = true;
                }
                prefix_only_atoms += usize::from(*kind == 0);
                let bytes = &atoms[*id as usize];
                entries.push(Entry {
                    id: *id,
                    len: bytes.len() as u32,
                    tail: tail_of(bytes),
                });
            }
            long_start.push(if seen_long {
                long_at
            } else {
                entries.len() as u32
            });
            debug_assert_eq!(
                long_start.len(),
                bucket_start.len() + starts.len(),
                "one boundary per bucket, pushed in bucket order"
            );

            // Ranks, walked in the same ascending order: bit *n* of the bitmap
            // is the n'th smallest prefix, which is the n'th bucket.
            let mut next_bucket = 0usize;
            let mut running = rank_base;
            for word in &words {
                ranks.push(running);
                let mut bits = *word;
                while bits != 0 {
                    bucket_start.push(starts[next_bucket]);
                    next_bucket += 1;
                    running += 1;
                    bits &= bits - 1;
                }
            }
            debug_assert_eq!(next_bucket, starts.len());
            ranks.push(running);
            rank_base = running;

            bitmaps.extend_from_slice(&words);
        }

        // Closing sentinels, so that a bucket and a group are both a range.
        bucket_start.push(entries.len() as u32);
        long_start.push(entries.len() as u32);

        let stats = AtomSetStats {
            atoms: shorts.len() + gated.len(),
            gated_atoms: gated.len(),
            short_atoms: shorts.len(),
            prefix_only_atoms,
            distinct_first_bytes: usize::from(group_count),
            distinct_prefixes: bucket_start.len().saturating_sub(1),
            largest_bucket: largest_bucket(&bucket_start),
            longest_atom,
            table_bytes: table_bytes(
                &first,
                &bitmaps,
                &ranks,
                &entries,
                &bucket_start,
                &long_start,
            ),
        };

        Self {
            first,
            bitmaps,
            ranks,
            bucket_start,
            long_start,
            entries,
            shorts,
            deep,
            deep_off,
            stats,
        }
    }

    /// How many atoms are stored.
    pub fn len(&self) -> usize {
        self.stats.atoms
    }

    /// Whether the set is empty, in which case a scan finds nothing at all.
    pub fn is_empty(&self) -> bool {
        self.stats.atoms == 0
    }

    /// How many atoms fell off the fast path and take the linear one.
    pub fn short_atom_count(&self) -> usize {
        self.stats.short_atoms
    }

    /// What this set was built from. See [`AtomSetStats`].
    pub fn stats(&self) -> AtomSetStats {
        self.stats
    }

    /// Every occurrence of every atom in `data`.
    ///
    /// `out` is cleared first and receives `(atom id, offset)` in ascending
    /// offset order. It is a caller-owned vector rather than a returned one
    /// because a scan runs this once per file per case class and the vector is
    /// then walked to update per-atom state; clearing it here means the
    /// allocation happens once per thread rather than once per file.
    ///
    /// The tuple is `(u32, u32)` rather than a struct for the same reason the
    /// prefilter reports rule indices and not a type of its own: the two halves
    /// go straight into two different tables at the call site.
    pub fn find_all(&self, data: &[u8], out: &mut Vec<(u32, u32)>) {
        out.clear();
        self.scan(data, out);
    }

    /// Every match, handed to `visit` as it is found, in the same order
    /// [`find_all`](AtomSet::find_all) would have written them.
    ///
    /// This is the same scan with the output vector replaced by a call, so that
    /// a caller which only wants to know which atoms were present — the
    /// prefilter sets one bit per string — does not have to build a vector.
    ///
    /// What it is worth was measured rather than assumed, and the answer is
    /// less than it looks: on `shell32.dll` this rule set produces 10,787,610
    /// matches, 86 MB of `(u32, u32)`, and writing them all down costs 4-6% more
    /// than handing them to a closure as they are found. Sequential stores to a
    /// vector that is already large enough are that cheap. The visitor exists
    /// for the API's sake — a caller that does not want the vector should not
    /// have to allocate a large one — and not because it doubles the speed.
    ///
    /// The measurement is printed by `av-rules`'s `examples/pattern_bench.rs`,
    /// which is where the benchmark lives and why; the same two numbers for the
    /// automaton are printed beside it.
    pub fn for_each_match<F: FnMut(u32, u32)>(&self, data: &[u8], mut visit: F) {
        self.scan(data, &mut Each(&mut visit));
    }

    /// The scan itself, over whichever [`Sink`] the caller asked for.
    fn scan<S: Sink>(&self, data: &[u8], out: &mut S) {
        let len = data.len();
        // Offsets with three bytes left are the ones the gate can speak for;
        // an atom that would run off the end of the buffer is not present in
        // it, so the last two offsets need only the short path.
        let gated_end = len.saturating_sub(MIN_GATED_LEN - 1);

        if self.shorts.is_empty() {
            for at in 0..gated_end {
                self.gate(data, at, out);
            }
            return;
        }

        // With short atoms present the two paths are interleaved, so that the
        // offsets come out in ascending order whichever kind matched. A caller
        // that sorts offsets, or that derives a match position from them, must
        // not have to know which of the two paths found a given atom.
        for at in 0..gated_end {
            self.short_at(data, at, out);
            self.gate(data, at, out);
        }
        for at in gated_end..len {
            self.short_at(data, at, out);
        }
    }

    /// Every atom present in `data`, once each, ascending.
    ///
    /// The fall-out of [`find_all`](AtomSet::find_all) for a caller that wants
    /// the set rather than the occurrences: the prefilter's per-file state is
    /// exactly this question, and answering it here saves the caller the walk
    /// and the dedup. Duplicates are removed in place, so `out` is not
    /// required to be any particular size on entry.
    pub fn atoms_present(&self, data: &[u8], out: &mut Vec<u32>) {
        let mut found = std::mem::take(out);
        found.clear();
        let mut pairs = Vec::new();
        self.find_all(data, &mut pairs);
        found.extend(pairs.into_iter().map(|(id, _)| id));
        found.sort_unstable();
        found.dedup();
        *out = found;
    }

    /// The gate: one load to reject a byte, one bit test to reject a prefix,
    /// one popcount to reach the bucket.
    #[inline(always)]
    fn gate<S: Sink>(&self, data: &[u8], at: usize, out: &mut S) {
        // `at + 2` is inside the buffer for every offset the caller runs this
        // at, which is what lets the two loads below be plain indexing.
        let byte = data[at] as usize;
        let group = self.first[byte];
        if group == NO_GROUP {
            return;
        }
        let prefix = ((data[at + 1] as u32) << 8) | data[at + 2] as u32;
        let group = group as usize;

        let word_at = group * PREFIX_WORDS + (prefix as usize >> 6);
        let bit = 1u64 << (prefix & 63);
        let Some(word) = self.bitmaps.get(word_at).copied() else {
            return;
        };
        if word & bit == 0 {
            return;
        }

        // One popcount turns the bitmap hit into the bucket's index: the rank
        // of a bit is the number of distinct prefixes before it, and prefixes
        // are numbered in bitmap order.
        let rank = self.ranks[group * (PREFIX_WORDS + 1) + (prefix as usize >> 6)]
            + (word & (bit - 1)).count_ones();
        let rank = rank as usize;
        let (Some(&start), Some(&end), Some(&long)) = (
            self.bucket_start.get(rank),
            self.bucket_start.get(rank + 1),
            self.long_start.get(rank),
        ) else {
            return;
        };
        let start = start as usize;
        // A bucket's entries are one contiguous range, and the boundary inside
        // it is a build-time fact; the clamp is here so that a set built by a
        // future bug reports fewer matches rather than a slice that panics.
        let end = end as usize;
        let long = (long as usize).clamp(start, end);

        // The atoms that end at the prefix are all matches: the bitmap has just
        // proved the prefix, and there is nothing else to check.
        for entry in &self.entries[start..long] {
            self.confirm(entry, data, at, out);
        }

        // Everything else has a fourth byte, and the buffer might not — an atom
        // that would run past the end of the buffer is not in it. Returning here
        // is what stops the entries that carry on from being confirmed at the
        // last two offsets of a file, where they cannot possibly match.
        let Some(&fourth) = data.get(at + 3) else {
            return;
        };
        let rest = &self.entries[long..end];

        // A short run is cheaper to read than to search. This is the common
        // case by a wide margin: the median bucket holds one atom, and only a
        // few hundred of the real set's 54,668 prefixes hold more than a
        // handful.
        if rest.len() <= WALK_LIMIT {
            for entry in rest {
                if entry.fourth() == fourth {
                    self.confirm(entry, data, at, out);
                }
            }
            return;
        }

        // The run is sorted by fourth byte, so the atoms that can match here
        // are the ones in the run for this byte, found by its lower bound. The
        // walk after it stops at the first entry belonging to the next run.
        let mut lo = 0usize;
        let mut hi = rest.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if rest[mid].fourth() < fourth {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        for entry in &rest[lo..] {
            if entry.fourth() != fourth {
                break;
            }
            self.confirm(entry, data, at, out);
        }
    }

    /// Confirm a candidate whose prefix the gate has already proved.
    ///
    /// The prefix is three bytes of the atom and three bytes of the buffer, and
    /// they are equal by the time this is reached; what is checked here is the
    /// rest. A candidate that fails is not an occurrence of its atom, and is
    /// dropped exactly as if the gate had never selected it.
    #[inline(always)]
    fn confirm<S: Sink>(&self, entry: &Entry, data: &[u8], at: usize, out: &mut S) {
        let tail_len = entry.tail_len();
        let from = at + MIN_GATED_LEN;
        // Running off the end of the buffer is a failure to contain the atom,
        // not a reason to panic — and it is only reachable for the last few
        // offsets of an atom that ends near the end of the file.
        let Some(window) = data.get(from..from + tail_len) else {
            return;
        };
        if load_le(window) != entry.tail & low_mask(tail_len) {
            return;
        }
        if entry.has_deep_tail() {
            let Some(&offset) = self.deep_off.get(entry.id as usize) else {
                return;
            };
            let offset = offset as usize;
            let want = entry.len as usize - INLINE_LEN;
            let (Some(expected), Some(found)) = (
                self.deep.get(offset..offset + want),
                data.get(at + INLINE_LEN..at + INLINE_LEN + want),
            ) else {
                return;
            };
            if expected != found {
                return;
            }
        }
        out.found(entry.id, at as u32);
    }

    /// The path for atoms shorter than the gate's prefix.
    ///
    /// One comparison per short atom per offset, which is why the set reports
    /// how many took this path rather than hiding it: a rule set with a few
    /// hundred one-byte atoms would be better served by a 256-bit presence
    /// bitmap than by this walk, and the count is what would say so. The
    /// measured rule set has none.
    #[inline(always)]
    fn short_at<S: Sink>(&self, data: &[u8], at: usize, out: &mut S) {
        for short in &self.shorts {
            let len = short.len as usize;
            // An atom that would run past the end of the buffer is not in it.
            // `continue` and not `return`: the atoms after this one in the list
            // are in input order and a shorter one may still fit, so leaving
            // early would drop a match — the one failure this crate exists to
            // avoid.
            let Some(window) = data.get(at..at + len) else {
                continue;
            };
            if load_le(window) as u32 == short.packed {
                out.found(short.id, at as u32);
            }
        }
    }
}

/// Hand-written for the same reason the prefilter's is: the interesting thing
/// about an atom set is its shape, and a derived `Debug` would print sixty
/// thousand atoms into whatever log reached it.
impl fmt::Debug for AtomSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomSet")
            .field("atoms", &self.stats.atoms)
            .field("gated_atoms", &self.stats.gated_atoms)
            .field("short_atoms", &self.stats.short_atoms)
            .field("prefix_only_atoms", &self.stats.prefix_only_atoms)
            .field("distinct_first_bytes", &self.stats.distinct_first_bytes)
            .field("distinct_prefixes", &self.stats.distinct_prefixes)
            .field("largest_bucket", &self.stats.largest_bucket)
            .field("table_bytes", &self.stats.table_bytes)
            .finish()
    }
}

/// The first byte of a packed prefix.
#[inline(always)]
fn first_byte(prefix: u32) -> u8 {
    (prefix >> 16) as u8
}

/// The three-byte prefix of an atom, `b0 << 16 | b1 << 8 | b2`.
#[inline]
fn prefix_of(bytes: &[u8]) -> u32 {
    debug_assert!(bytes.len() >= MIN_GATED_LEN);
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

/// Bytes [`MIN_GATED_LEN`] onwards, the first [`INLINE_TAIL`] of them, packed
/// little-endian into the low bytes.
#[inline]
fn tail_of(bytes: &[u8]) -> u64 {
    let mut tail = 0u64;
    for (index, byte) in bytes[MIN_GATED_LEN..].iter().take(INLINE_TAIL).enumerate() {
        tail |= (*byte as u64) << (8 * index);
    }
    tail
}

/// Bytes packed little-endian into the low bytes, right-aligned at the bottom.
#[inline]
fn pack(bytes: &[u8]) -> u32 {
    let mut packed = 0u32;
    for (index, byte) in bytes.iter().take(4).enumerate() {
        packed |= (*byte as u32) << (8 * index);
    }
    packed
}

/// At most eight bytes packed little-endian into the low bytes.
#[inline]
fn load_le(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() <= 8);
    let mut packed = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        packed |= (*byte as u64) << (8 * index);
    }
    packed
}

/// A mask keeping the low `len` bytes.
#[inline]
const fn low_mask(len: usize) -> u64 {
    if len >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * len)) - 1
    }
}

/// The largest number of atoms sharing one three-byte prefix.
fn largest_bucket(bucket_start: &[u32]) -> usize {
    bucket_start
        .windows(2)
        .map(|pair| (pair[1] - pair[0]) as usize)
        .max()
        .unwrap_or(0)
}

/// Roughly what the tables occupy, which decides which cache they live in.
fn table_bytes(
    first: &[u16; 256],
    bitmaps: &[u64],
    ranks: &[u32],
    entries: &[Entry],
    bucket_start: &[u32],
    long_start: &[u32],
) -> usize {
    std::mem::size_of_val(first)
        + bitmaps.len() * 8
        + ranks.len() * 4
        + std::mem::size_of_val(entries)
        + bucket_start.len() * 4
        + long_start.len() * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The atoms these tests use, as owned vectors.
    fn atoms(list: &[&[u8]]) -> Vec<Vec<u8>> {
        list.iter().map(|bytes| bytes.to_vec()).collect()
    }

    /// Every match, as `(id, offset)` in the order they came out.
    fn find(set: &AtomSet, data: &[u8]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        set.find_all(data, &mut out);
        out
    }

    /// Every match, as a sorted set.
    fn found(set: &AtomSet, data: &[u8]) -> Vec<(u32, u32)> {
        let mut out = find(set, data);
        out.sort_unstable();
        out
    }

    // -- the two levels ----------------------------------------------------

    #[test]
    fn a_byte_that_starts_no_atom_is_rejected_by_the_first_table_alone() {
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        assert_eq!(set.stats().distinct_first_bytes, 1);
        assert_eq!(found(&set, b"xxxxabcdxxxx"), vec![(0, 4)]);
        assert!(found(&set, b"xxxxxxxxxx").is_empty());
    }

    #[test]
    fn a_prefix_the_bitmap_does_not_hold_is_rejected_without_a_confirmation() {
        // Same first byte, different second and third: the gate knows `abc` is
        // impossible and the atom's own bytes are never compared.
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        assert!(found(&set, b"abXabcd")
            .iter()
            .any(|(id, at)| *id == 0 && *at == 3));
        assert!(found(&set, b"abXd").is_empty(), "the prefix is not there");
    }

    #[test]
    fn every_atom_of_a_bucket_is_confirmed() {
        // One prefix, several atoms that differ only in the fourth byte. The
        // gate cannot tell them apart, so the bucket is read and exactly one of
        // them matches.
        let set = AtomSet::new(&atoms(&[
            b"abcd", b"abce", b"abcf", b"abcg", b"ab01", b"ab11", b"ab21",
        ]));
        assert_eq!(set.stats().distinct_prefixes, 4);
        assert_eq!(set.stats().largest_bucket, 4);
        assert_eq!(found(&set, b"abcg"), vec![(3, 0)]);
        assert!(found(&set, b"abch").is_empty());
    }

    #[test]
    fn a_bucket_too_big_to_walk_is_searched_by_the_fourth_byte() {
        // Every atom shares the first three bytes and differs in the fourth, so
        // the bucket is far over the walk limit and the run that can match has
        // to be found by searching for the fourth byte rather than by reading
        // all 160 entries.
        let list: Vec<Vec<u8>> = (0..160u8)
            .map(|index| vec![b'a', b'b', b'c', index])
            .collect();
        let set = AtomSet::new(&list);
        assert_eq!(set.stats().largest_bucket, 160);
        assert!(
            set.stats().largest_bucket > WALK_LIMIT,
            "the search must run"
        );
        for (index, atom) in list.iter().enumerate() {
            assert_eq!(found(&set, atom), vec![(index as u32, 0)], "{atom:?}");
        }
        assert!(found(&set, b"abc\xff").is_empty());
    }

    #[test]
    fn a_group_after_a_small_one_still_finds_its_matches() {
        // Every group's bitmap and rank table are placed by the group's own
        // number, so a group that kept no table of its own would put every
        // group after it at the wrong offset — and the failure would be a
        // missed match, not a crash. This is the shape that broke once, with
        // the small group first so that the second group's tables are the ones
        // that would be misplaced.
        let mut list: Vec<Vec<u8>> = vec![b"aqqq".to_vec()];
        for index in 0..8u8 {
            list.push(vec![b'z', b'z', b'0' + index, b'q']);
        }
        let set = AtomSet::new(&list);
        assert_eq!(set.stats().distinct_first_bytes, 2);
        assert_eq!(set.stats().distinct_prefixes, 9);
        assert_eq!(found(&set, b"aqqq"), vec![(0, 0)]);
        assert_eq!(found(&set, b"zz3q"), vec![(4, 0)]);
        assert_eq!(found(&set, b"zz7q"), vec![(8, 0)]);
        assert!(found(&set, b"zz8q").is_empty());
    }

    #[test]
    fn a_bucket_answers_the_same_way_however_big_it_is() {
        // The same atoms one at a time, one either side of the walk limit. Only
        // the mechanism changes; what is found must not.
        for size in [1usize, WALK_LIMIT, WALK_LIMIT + 1, 64] {
            let list: Vec<Vec<u8>> = (0..size as u8)
                .map(|index| vec![b'a', b'b', b'c', index])
                .collect();
            let set = AtomSet::new(&list);
            assert_eq!(set.stats().largest_bucket, size);
            for (index, atom) in list.iter().enumerate() {
                assert_eq!(found(&set, atom), vec![(index as u32, 0)], "{size} atoms");
            }
            assert!(found(&set, b"abc\xff").is_empty(), "{size} atoms");
        }
    }

    // -- the short path ----------------------------------------------------

    #[test]
    fn an_atom_shorter_than_the_gate_is_still_found() {
        let set = AtomSet::new(&atoms(&[b"a", b"bc", b"def"]));
        assert_eq!(set.short_atom_count(), 2);
        assert_eq!(set.stats().gated_atoms, 1);
        assert_eq!(found(&set, b"abcd"), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn a_two_byte_atom_is_not_found_one_past_its_last_offset() {
        let set = AtomSet::new(&atoms(&[b"ab"]));
        assert_eq!(found(&set, b"ab"), vec![(0, 0)]);
        assert!(found(&set, b"b").is_empty());
        assert_eq!(found(&set, b"xab"), vec![(0, 1)]);
    }

    #[test]
    fn a_one_byte_atom_matches_at_every_offset_it_occurs_at() {
        let set = AtomSet::new(&atoms(&[b"z"]));
        assert_eq!(
            found(&set, b"zzz"),
            vec![(0, 0), (0, 1), (0, 2)],
            "every offset, including the last"
        );
    }

    #[test]
    fn the_two_paths_report_in_offset_order() {
        // A short atom and a gated one in the same buffer. The offsets have to
        // come out ascending whichever path found them, or a caller deriving a
        // match position from them sees them out of order.
        let set = AtomSet::new(&atoms(&[b"abcd", b"xy"]));
        let out = find(&set, b"xyabcdxyxxabcd");
        let offsets: Vec<u32> = out.iter().map(|(_, at)| *at).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted, "{out:?}");
    }

    #[test]
    fn a_short_atom_in_a_buffer_shorter_than_the_gate_is_still_found() {
        // Two bytes of buffer, a two-byte atom: the gate never runs and the
        // short path has to carry the whole scan.
        let set = AtomSet::new(&atoms(&[b"ab"]));
        assert_eq!(found(&set, b"ab"), vec![(0, 0)]);
        assert_eq!(found(&set, b"ab"), vec![(0, 0)]);
        assert!(found(&set, b"a").is_empty());
        assert!(found(&set, b"").is_empty());
    }

    // -- the interface -----------------------------------------------------

    #[test]
    fn a_buffer_shorter_than_the_shortest_atom_finds_nothing() {
        let set = AtomSet::new(&atoms(&[b"abcdef"]));
        assert!(found(&set, b"").is_empty());
        assert!(found(&set, b"a").is_empty());
        assert!(found(&set, b"abcde").is_empty());
        assert_eq!(found(&set, b"abcdef"), vec![(0, 0)]);
    }

    #[test]
    fn an_empty_atom_list_finds_nothing_and_stores_nothing() {
        let set = AtomSet::new(&[]);
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.short_atom_count(), 0);
        assert!(found(&set, b"anything at all").is_empty());
        assert!(found(&set, b"").is_empty());
    }

    #[test]
    fn an_empty_atom_is_not_a_match_everywhere() {
        // A zero-length atom has no bytes that must be present, so there is no
        // offset at which it is not present. Stored, it would report a match at
        // every offset of every file — a false-positive generator. It is
        // dropped instead, and the id it would have had does not shift the
        // atoms after it.
        let set = AtomSet::new(&atoms(&[b"", b"abcd"]));
        assert_eq!(set.len(), 1, "the empty atom is not stored");
        assert_eq!(found(&set, b"abcd"), vec![(1, 0)], "and ids do not move");
        assert!(found(&set, b"xxxx").is_empty());
    }

    #[test]
    fn a_match_at_offset_zero_is_reported() {
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        assert_eq!(found(&set, b"abcd and more"), vec![(0, 0)]);
    }

    #[test]
    fn a_match_at_the_last_possible_offset_is_reported() {
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        assert_eq!(found(&set, b"xxxxabcd"), vec![(0, 4)]);
        assert_eq!(found(&set, b"xxabcd"), vec![(0, 2)]);
    }

    #[test]
    fn overlapping_matches_are_all_reported() {
        // The property the prefilter needs: `abcde` contains both `abcd` and
        // `bcde`, and dropping the second would drop the rule that depends on
        // it. `find_iter` would report only the first.
        let set = AtomSet::new(&atoms(&[b"abcd", b"bcde"]));
        assert_eq!(found(&set, b"abcde"), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn a_run_of_one_byte_reports_a_match_at_every_offset() {
        // Twelve bytes of buffer, a four-byte atom: nine offsets, 0 through 8,
        // and every one of them is a match. The count is the arithmetic that a
        // fencepost error in the last-offset handling gets wrong.
        let set = AtomSet::new(&atoms(&[b"aaaa"]));
        let expected: Vec<(u32, u32)> = (0..9).map(|at| (0, at)).collect();
        assert_eq!(find(&set, b"aaaaaaaaaaaa"), expected);
    }

    #[test]
    fn an_atom_that_occurs_many_times_is_reported_every_time() {
        let set = AtomSet::new(&atoms(&[b"needle"]));
        let mut data = Vec::new();
        for _ in 0..1000 {
            data.extend_from_slice(b"needle ");
        }
        assert_eq!(find(&set, &data).len(), 1000);
    }

    #[test]
    fn two_atoms_with_the_same_bytes_are_both_reported() {
        // Merging them would leave one id unreachable, and an id a caller
        // cannot see is a string it never selects a rule for.
        let set = AtomSet::new(&atoms(&[b"abcd", b"abcd"]));
        assert_eq!(found(&set, b"abcd"), vec![(0, 0), (1, 0)]);
        assert_eq!(set.len(), 2, "both are stored");
    }

    #[test]
    fn the_output_vector_is_cleared_rather_than_appended_to() {
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        let mut out = vec![(99, 99)];
        set.find_all(b"abcd", &mut out);
        assert_eq!(out, vec![(0, 0)]);
        set.find_all(b"nothing", &mut out);
        assert!(out.is_empty(), "the first scan's match must not survive");
    }

    #[test]
    fn atoms_present_names_each_atom_once_however_often_it_occurs() {
        let set = AtomSet::new(&atoms(&[b"abcd", b"xxx"]));
        let mut out = Vec::new();
        set.atoms_present(b"abcd abcd abcd", &mut out);
        assert_eq!(out, vec![0]);
        set.atoms_present(b"xxxabcdxxx", &mut out);
        assert_eq!(out, vec![0, 1], "and in ascending id order");
        set.atoms_present(b"nothing", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn a_scan_can_be_run_twice_with_the_same_set() {
        // Nothing in the set is state, which is what lets one thread share it
        // and every other thread scan with it at the same time.
        let set = AtomSet::new(&atoms(&[b"abcd", b"bcde"]));
        assert_eq!(found(&set, b"abcde"), vec![(0, 0), (1, 1)]);
        assert_eq!(found(&set, b"abcde"), vec![(0, 0), (1, 1)]);
        assert!(found(&set, b"xxxxx").is_empty());
    }

    // -- the atoms that do not fit the fast shape --------------------------

    #[test]
    fn an_atom_longer_than_the_inline_tail_is_still_confirmed() {
        // Two atoms that agree for longer than the entry can hold inline. The
        // deep tail is what tells the two apart, and getting it wrong would
        // report one as the other.
        let long = b"a-fairly-long-literal-string".to_vec();
        let set = AtomSet::new(&[
            long.clone(),
            b"a-fairly-other".to_vec(),
            b"a00".to_vec(),
            b"a11".to_vec(),
            b"a22".to_vec(),
            b"a33".to_vec(),
        ]);
        assert_eq!(set.stats().largest_bucket, 2, "both start `a-f`");
        assert_eq!(found(&set, &long), vec![(0, 0)]);
        assert_eq!(found(&set, b"a-fairly-other"), vec![(1, 0)]);
        assert!(found(&set, b"a-fairly-nothing").is_empty());
    }

    #[test]
    fn an_atom_one_byte_over_the_inline_boundary_is_confirmed_too() {
        // The boundary itself: `INLINE_LEN` bytes is inline, one more is not,
        // and an off-by-one there would compare the last byte of the first
        // against the last byte of the second.
        let mut first = vec![b'a'; INLINE_LEN + 1];
        first[INLINE_LEN] = b'1';
        let mut second = first.clone();
        second[INLINE_LEN] = b'2';
        assert_eq!(first.len(), INLINE_LEN + 1);
        let set = AtomSet::new(&[
            first.clone(),
            second.clone(),
            b"a01".to_vec(),
            b"a02".to_vec(),
            b"a03".to_vec(),
        ]);
        assert_eq!(found(&set, &first), vec![(0, 0)]);
        assert_eq!(found(&set, &second), vec![(1, 0)]);
    }

    #[test]
    fn a_long_atom_near_the_end_of_the_buffer_is_not_a_panic() {
        // The deep tail runs past the end of the buffer one byte short of a
        // match, which is a failure to contain the atom and not a panic.
        let long = b"a-fairly-long-literal-string".to_vec();
        let set = AtomSet::new(std::slice::from_ref(&long));
        let mut data = vec![b'x'; 4];
        data.extend_from_slice(&long[..long.len() - 1]);
        assert!(found(&set, &data).is_empty());
        assert_eq!(found(&set, &long), vec![(0, 0)]);
    }

    #[test]
    fn an_atom_of_every_length_from_none_to_twenty_is_found() {
        // Every path through the length arithmetic, end to end: the short
        // path, the empty inline tail, the full inline tail, and the deep one.
        for len in 1..=20usize {
            let atom: Vec<u8> = (0..len).map(|index| b'a' + index as u8).collect();
            let set = AtomSet::new(std::slice::from_ref(&atom));
            assert_eq!(found(&set, &atom), vec![(0, 0)], "length {len}");
            let mut data = b"xyz".to_vec();
            data.extend_from_slice(&atom);
            data.extend_from_slice(b"xyz");
            assert_eq!(found(&set, &data), vec![(0, 3)], "length {len} in context");
        }
    }

    // -- the reported shape ------------------------------------------------

    #[test]
    fn the_stats_count_what_was_built() {
        let set = AtomSet::new(&atoms(&[b"ab", b"abcd", b"abce", b"wxyz", b"wxy"]));
        let stats = set.stats();
        assert_eq!(stats.atoms, 5);
        assert_eq!(stats.short_atoms, 1);
        assert_eq!(stats.gated_atoms, 4);
        assert_eq!(stats.distinct_first_bytes, 2, "a and w");
        assert_eq!(stats.prefix_only_atoms, 1, "`wxy` ends at its prefix");
        assert_eq!(stats.longest_atom, 4);
        assert!(stats.table_bytes > 0);
    }

    #[test]
    fn an_atom_that_ends_at_its_prefix_matches_wherever_the_prefix_does() {
        // A three-byte atom has nothing after the gate, so every occurrence of
        // its prefix is a match. There is no fourth byte to narrow it by, and
        // it must not be narrowed by one either: the byte after it in the
        // buffer is part of the surrounding file and says nothing about it.
        let set = AtomSet::new(&atoms(&[b"abc", b"abcd"]));
        assert_eq!(found(&set, b"abcd"), vec![(0, 0), (1, 0)]);
        assert_eq!(found(&set, b"abcx"), vec![(0, 0)]);
        assert_eq!(found(&set, b"zabc"), vec![(0, 1)]);
        // At offset 0 the prefix is there but the byte after it is not a `d`,
        // so only the three-byte atom matches; at offset 3 both do.
        assert_eq!(found(&set, b"abcabcd"), vec![(0, 0), (0, 3), (1, 3)]);
    }

    #[test]
    fn a_prefix_only_atom_at_the_last_offsets_of_a_buffer_is_still_found() {
        // The gate stops two bytes before the end, but a three-byte atom
        // reaches it there, and the entry that carries on does not. Both halves
        // of that are checked by the offset arithmetic in `find_all` and the
        // return before the fourth-byte read.
        let set = AtomSet::new(&atoms(&[b"abc", b"abcd"]));
        assert_eq!(found(&set, b"xabc"), vec![(0, 1)]);
        let mut data = b"xa".to_vec();
        data.extend_from_slice(b"abc");
        assert_eq!(found(&set, &data), vec![(0, 2)]);
        // A four-byte atom ending exactly at the end of the buffer is a match.
        assert_eq!(found(&set, b"zabcd"), vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn the_length_boundaries_are_where_the_constants_say_they_are() {
        assert_eq!(INLINE_LEN, MIN_GATED_LEN + INLINE_TAIL);
        for len in MIN_GATED_LEN..=INLINE_LEN {
            let atom: Vec<u8> = vec![b'a'; len];
            let entry = Entry {
                id: 0,
                len: len as u32,
                tail: tail_of(&atom),
            };
            assert!(!entry.has_deep_tail(), "{len} is inline");
            assert_eq!(entry.tail_len(), len - MIN_GATED_LEN);
        }
        let long = vec![b'a'; INLINE_LEN + 1];
        let entry = Entry {
            id: 0,
            len: long.len() as u32,
            tail: tail_of(&long),
        };
        assert!(entry.has_deep_tail(), "one past the boundary is deep");
        assert_eq!(entry.tail_len(), INLINE_TAIL);
    }

    #[test]
    fn the_low_mask_keeps_exactly_the_bytes_it_is_asked_for() {
        assert_eq!(low_mask(0), 0);
        assert_eq!(low_mask(1), 0xFF);
        assert_eq!(low_mask(4), 0xFFFF_FFFF);
        assert_eq!(low_mask(8), u64::MAX);
        assert_eq!(low_mask(9), u64::MAX, "more than the word is all of it");
    }

    #[test]
    fn a_debug_impl_does_not_print_the_whole_set() {
        let set = AtomSet::new(&atoms(&[b"abcd"]));
        let printed = format!("{set:?}");
        assert!(printed.contains("atoms: 1"), "{printed}");
        assert!(printed.len() < 400, "{printed}");
    }
}
