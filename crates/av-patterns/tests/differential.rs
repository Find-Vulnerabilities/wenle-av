//! The matcher against a naive scan, over buffers generated several ways.
//!
//! Everything else in this crate's tests checks a case someone thought of. This
//! one checks the whole output against the only definition of a match that needs
//! no argument: for every atom, for every offset, compare the bytes.
//!
//! ```text
//! for (id, atom) in atoms.iter().enumerate() {
//!     for (at, window) in data.windows(atom.len()).enumerate() {
//!         if window == &atom[..] { report(id, at) }
//!     }
//! }
//! ```
//!
//! That is `O(size x atoms)`, has no tables in it, and cannot be wrong the way
//! the real matcher can be wrong. It is the reason this file exists: every bug
//! found in `AtomSet` so far — a group whose bitmap was missing from a table, a
//! bucket boundary left at the start of its bucket, a run of the gate that a
//! narrow group shifted — was a bug that produced *fewer* matches than the truth
//! rather than a panic. Sorted match sets are compared exactly, so a missing
//! match fails the test at the offset where it is missing, and a spurious one
//! fails it too.
//!
//! The buffers are generated several ways on purpose, because the matcher's
//! paths divide by the data as much as by the atoms: uniform noise exercises the
//! gate almost never, a run of one byte exercises it at every offset, and a
//! buffer stuffed with the atoms and their near misses exercises the
//! confirmation, the fourth byte and the overlapping reports hardest. The real
//! `shell32.dll` is searched too when it is there, because a synthetic buffer is
//! a shape someone chose and a DLL is not.
//!
//! `examples/pattern_bench.rs` runs the same comparison against Aho-Corasick
//! with the real 101,794-atom rule set; this file is what runs on every
//! `cargo test`, and it stops working the moment the matcher does.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use av_patterns::AtomSet;

/// The truth: every occurrence of every atom, at every offset.
///
/// The definition is `windows(n)` — the semantics the matcher promises,
/// overlapping matches included, since `abcd` and `bcde` are both occurrences
/// in `abcde` and `find_iter` would report the first and swallow the second.
///
/// Writing it as `data.windows(atom.len())` and comparing every window is the
/// version to hold in the head, and it is what this was. It is also `O(size x
/// atoms)` with a slice comparison per window, which on the atom sets below
/// came to several billion comparisons and seven minutes of `cargo test` — a
/// test slow enough that the thing it protects stops being run.
///
/// So the window is not constructed where it cannot match. A window can only
/// equal the atom if its *first* byte does, and `memchr` finds those offsets
/// with a vectorised scan rather than one at a time. What is left is the same
/// comparison at a subset of the same offsets, so the answer is the same
/// answer — and the loop still steps by one, which is what keeps the
/// overlapping occurrences in.
///
/// The one thing that must not change is the *set* of offsets considered, so
/// the search is bounded at `data.len() - atom.len()`: an atom that would run
/// off the end of the buffer has no offsets at all, and one that ends exactly
/// at the end has exactly one.
fn naive(atoms: &[Vec<u8>], data: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for (id, atom) in atoms.iter().enumerate() {
        // An empty atom would match at every offset of every buffer, which is
        // not what this matcher promises to do with one; `AtomSet` drops them
        // and the test that covers that is in the unit tests.
        let Some(&first) = atom.first() else {
            continue;
        };
        if atom.len() > data.len() {
            continue;
        }
        let last = data.len() - atom.len();
        let mut from = 0usize;
        while let Some(hit) = memchr::memchr(first, &data[from..=last]) {
            let at = from + hit;
            if data[at..at + atom.len()] == atom[..] {
                out.push((id as u32, at as u32));
            }
            // One past the hit, not past the atom: the next occurrence may
            // start inside this one. This single `+ 1` is the whole difference
            // between this and a `find_iter` that would miss `bcde`.
            from = at + 1;
        }
    }
    out.sort_unstable();
    out
}

/// Run both matchers over one buffer and one atom set, and fail on any
/// difference. Returns the number of matches, so that a caller can insist a case
/// was not vacuous.
#[must_use]
fn differential(atoms: &[Vec<u8>], data: &[u8], label: &str) -> usize {
    let set = AtomSet::new(atoms);
    // The oracle first, and the matcher into the vector that will hold it.
    // The two answer sets are the same size by construction, so holding a copy
    // of one of them while the other is built is a second allocation the size
    // of the answer — and the answer can be millions of pairs on the buffers
    // that contain every one-byte value. This test runs four threads deep on a
    // machine that other builds are competing with, which is how a copy that
    // looks free turns into `memory allocation of 1048576 bytes failed`.
    let theirs = naive(atoms, data);
    let mut ours = Vec::new();
    set.find_all(data, &mut ours);
    ours.sort_unstable();

    if ours != theirs {
        let first = ours
            .iter()
            .zip(&theirs)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| ours.len().min(theirs.len()));
        let ours_at = ours.get(first).copied();
        let theirs_at = theirs.get(first).copied();
        let missing: Vec<(u32, u32)> = theirs
            .iter()
            .copied()
            .filter(|pair| !ours.contains(pair))
            .take(4)
            .collect();
        let extra: Vec<(u32, u32)> = ours
            .iter()
            .copied()
            .filter(|pair| !theirs.contains(pair))
            .take(4)
            .collect();
        let mut message = format!(
            "{label}: {} matches against the naive scan's {}. First difference at {first}: \
             {ours_at:?} against {theirs_at:?}. {}",
            ours.len(),
            theirs.len(),
            if ours.len() == theirs.len() {
                "The sets differ in place, not in size."
            } else {
                "The sets differ in size."
            }
        );
        if !missing.is_empty() {
            message.push_str(&format!(" Missing from the matcher: {missing:?}."));
        }
        if !extra.is_empty() {
            message.push_str(&format!(" Reported but not present: {extra:?}."));
        }
        panic!("{message}");
    }

    // Every reported pair must name an atom that is really at that offset, and
    // the atom must really be that atom: an id is an index into `atoms`.
    for &(id, at) in &ours {
        let atom = atoms
            .get(id as usize)
            .unwrap_or_else(|| panic!("{label}: match names atom {id}, out of range"));
        let at = at as usize;
        assert!(
            at + atom.len() <= data.len(),
            "{label}: match at {at} runs past the end of the buffer"
        );
        assert_eq!(
            &data[at..at + atom.len()],
            &atom[..],
            "{label}: atom {id} reported at {at} is not there"
        );
    }

    // The buffer's own answer to "which atoms are present" is the dedup of the
    // offsets, and `atoms_present` claims to be that.
    //
    // The dedup is materialised before the call and `ours` is released first,
    // so the two answer-sized vectors do not overlap with the one inside
    // `atoms_present`. On the buffers whose answer is millions of pairs that is
    // the difference between two large allocations alive at once and three.
    let matched = ours.len();
    let mut expected: Vec<u32> = ours.iter().map(|(id, _)| *id).collect();
    drop(ours);
    expected.dedup();
    let mut present = Vec::new();
    set.atoms_present(data, &mut present);
    assert_eq!(
        present, expected,
        "{label}: atoms_present disagrees with the matches themselves"
    );

    matched
}

/// xorshift64*, so that the buffers are reproducible from a seed and no
/// dependency is needed to generate several megabytes of them.
fn next(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    *state = value;
    value.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn byte(state: &mut u64) -> u8 {
    (next(state) >> 33) as u8
}

/// Uniform noise: the gate almost never passes, so this is the case where a
/// wrong table index or a mis-set bit shows up as a *missing* match rather than
/// as a wrong one.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len).map(|_| byte(&mut state)).collect()
}

/// Long runs of one byte, and of a few bytes: the gate passes at every offset,
/// buckets are hit repeatedly, and the confirmation line runs at full rate.
fn runs(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let fill = byte(&mut state);
        let run = 1 + (byte(&mut state) as usize) * 7;
        out.extend(std::iter::repeat_n(fill, run.min(len - out.len())));
    }
    out.truncate(len);
    out
}

/// Text-ish ASCII, where a byte distribution is concentrated in letters,
/// spaces and newlines — the shape an atom taken from a string literal has.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let alphabet =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \r\n\t.,:;/\\%$_-\"()[]{}";
    (0..len)
        .map(|_| alphabet[(next(&mut state) >> 33) as usize % alphabet.len()])
        .collect()
}

/// A PE-shaped buffer: a DOS header, a stub string, a run of pointer-like
/// four-byte sequences, section padding, and an ASCII tail. This is what the
/// real workload looks like, and it is the buffer where level 1 of the gate
/// rejects the least.
fn pe_shaped(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00");
    out.extend_from_slice(b"This program cannot be run in DOS mode.\r\r\n$");
    while out.len() < len {
        match next(&mut state) % 4 {
            0 => out.extend_from_slice(b"\x8b\xff\x85\xc0\x74\x0e\x8b\x45\x08\x89\x45\xfc"),
            1 => out.extend(std::iter::repeat_n(
                0u8,
                16 + (byte(&mut state) as usize) * 4,
            )),
            2 => out.extend_from_slice(b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"),
            _ => {
                let text = text(64, next(&mut state));
                out.extend_from_slice(&text);
            }
        }
    }
    out.truncate(len);
    out
}

/// A buffer built out of the atoms themselves: each one placed whole, and each
/// one placed again with one byte changed. The atoms are the only source of
/// matches, and the near misses make sure the confirmation line is exercised
/// rather than short-circuited by the gate.
fn stuffed(atoms: &[Vec<u8>], len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = noise(len, seed);
    if atoms.is_empty() {
        return out;
    }
    let mut at = 0usize;
    while at + 16 < out.len() {
        let atom = &atoms[(next(&mut state) >> 33) as usize % atoms.len()];
        if atom.is_empty() || at + atom.len() > out.len() {
            at += 1;
            continue;
        }
        let whole = next(&mut state) & 1 == 0;
        out[at..at + atom.len()].copy_from_slice(atom);
        if !whole && atom.len() > 1 {
            // A near miss: one byte off, which the gate must select and the
            // confirmation must reject.
            let flip = (next(&mut state) >> 33) as usize % atom.len();
            out[at + flip] = out[at + flip].wrapping_add(1);
        }
        at += atom.len() + (next(&mut state) >> 40) as usize % 8;
    }
    out
}

/// Atoms of every length the matcher has a path for, with duplicates, with
/// atoms that are prefixes of each other, and with one that is longer than the
/// inline tail.
fn mixed_atoms() -> Vec<Vec<u8>> {
    let mut atoms: Vec<Vec<u8>> = Vec::new();
    // Every single byte, and every byte doubled: the short-atom path.
    for byte in 0u16..=255 {
        atoms.push(vec![byte as u8]);
    }
    for byte in 0u16..=255 {
        atoms.push(vec![byte as u8, byte as u8]);
    }
    // Lengths three through twelve, including one over the inline tail.
    atoms.extend(
        [
            &b"abc"[..],
            &b"abcd"[..],
            &b"abcde"[..],
            &b"abcdef"[..],
            &b"abcdefgh"[..],
            &b"abcdefghijkl"[..],
            &b"\x00\x00\x00"[..],
            &b"\x00\x00\x00\x00"[..],
            &b"MZ\x90\x00"[..],
            &b"This program cannot be run in DOS mode"[..],
        ]
        .into_iter()
        .map(<[u8]>::to_vec),
    );
    // Overlapping: each is a suffix of the one before it, so one offset can
    // carry several matches and `find_iter` would drop all but the first.
    atoms.extend(
        [&b"aaab"[..], &b"aab"[..], &b"ab"[..], &b"b"[..]]
            .into_iter()
            .map(<[u8]>::to_vec),
    );
    // The same bytes twice, which must be two ids and two reports.
    atoms.push(b"abcd".to_vec());
    atoms.push(b"abcd".to_vec());
    atoms.push(b"abcd".to_vec());
    atoms
}

/// Atoms shaped like the real rule set: mostly four bytes, a few three, with
/// first and tail bytes drawn from a PE's distribution rather than uniformly.
fn real_shaped_atoms(count: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut state = seed | 1;
    // From the measured first-byte histogram: the loaders, the ASCII letters and
    // the zeros carry most of the set.
    let firsts: &[u8] = &[
        0x00, 0x8b, 0x83, 0x8d, 0x89, 0xff, 0x48, 0x53, 0x68, 0x65, 0x63, 0x6c, 0x2e, 0x20,
    ];
    let tails: &[u8] = &[0x00, 0xff, 0x8b, 0xe8, 0x20, 0x65, 0x74, 0x6f, 0x61, 0x2e];
    let mut atoms = Vec::with_capacity(count);
    for index in 0..count {
        let len = if index % 20 == 0 { 3 } else { 4 };
        let mut atom = Vec::with_capacity(len);
        atom.push(firsts[(next(&mut state) >> 33) as usize % firsts.len()]);
        for _ in 1..len {
            if next(&mut state) & 1 == 0 {
                atom.push(tails[(next(&mut state) >> 33) as usize % tails.len()]);
            } else {
                atom.push(byte(&mut state));
            }
        }
        atoms.push(atom);
    }
    atoms
}

/// One mebibyte, the size the real rule set's measurement is taken at.
const MIB: usize = 1 << 20;

/// The generated buffers, by name, at a size the caller picks.
///
/// The size is a budget, and what sets it is the *match volume* rather than the
/// naive scan — which is no longer the expensive half. `mixed_atoms` contains
/// every one-byte value, so on any buffer with a repeated byte a large share of
/// the offsets is a match, and an answer set of millions of pairs costs more to
/// sort, verify and dedup than to find. A mebibyte put that into the millions
/// of matches per buffer and the suite at five minutes.
///
/// What this test varies is the *atom set* — every length, every byte value,
/// the overlapping family, duplicates — and the buffer only has to be long
/// enough for the offsets near its end to exist and short enough that the
/// answer is affordable. The shapes are what carry the coverage; the length is
/// not one of them, which is why the caller passes it rather than the generator
/// choosing.
fn generated_buffers(atoms: &[Vec<u8>], size: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("noise", noise(size, 0x5EED_1234)),
        ("runs", runs(size, 0x5EED_2345)),
        ("text", text(size, 0x5EED_3456)),
        ("pe", pe_shaped(size, 0x5EED_4567)),
        ("stuffed", stuffed(atoms, size, 0x5EED_5678)),
        ("noise, odd length", noise(size + 7, 0x5EED_6789)),
        ("runs, odd length", runs(size + 13, 0x5EED_789A)),
        ("one byte", vec![0x61]),
        ("one byte, no atom in it", vec![0x00]),
        ("empty", Vec::new()),
        ("shorter than every atom", noise(2, 0x5EED_89AB)),
        ("exactly one atom long", b"abcd".to_vec()),
        ("two atoms end to end", b"abcdabcd".to_vec()),
        ("overlapping copies", b"aaabaaabaaab".to_vec()),
        ("a run of one atom", vec![b'a'; 4096]),
        ("a run of a three-byte atom", vec![0u8; 4096]),
    ]
}

#[test]
fn the_matcher_agrees_with_a_naive_scan_on_every_buffer() {
    let atoms = mixed_atoms();
    let mut total = 0usize;
    for (label, data) in generated_buffers(&atoms, 64 * 1024) {
        total += differential(&atoms, &data, label);
    }
    // The empty atom set, against every buffer, because "no atoms" is the one
    // input where a matcher that reports something has nothing to compare it to.
    // The oracle answers with no matches for any buffer at all, so this is a
    // check that the answer is empty and not merely that it is small: the gate
    // tables are built from the atoms, and a set with none of them is where an
    // uninitialised first-byte table would show up as a match at every offset.
    // The unit tests cover the empty set directly; this runs it through the same
    // oracle as everything else, which is the point of the file.
    for (label, data) in generated_buffers(&atoms, 4096) {
        let found = differential(&[], &data, label);
        assert_eq!(
            found, 0,
            "{label}: an empty atom set reported {found} matches"
        );
    }

    // The suite has to be able to fail: if every buffer were empty of matches,
    // agreeing with the naive scan would prove nothing.
    assert!(
        total > 100_000,
        "the differential suite only found {total} matches in total, which is too few for the \
         agreement to mean anything"
    );
}

#[test]
fn the_matcher_agrees_on_atoms_shaped_like_the_real_rule_set() {
    // Two lengths and a skewed byte distribution, which is what the real set is:
    // the gate's levels and the bucket narrowing are fitted to these, so the
    // differential has to run on them and not only on the alphabet above.
    // A mebibyte here, unlike the test above: this set has no one-byte atoms,
    // so its answer sets are small however long the buffer is, and the naive
    // scan is the only thing that grows with the length.
    let atoms = real_shaped_atoms(512, 0xC0FF_EE01);
    let mut total = 0usize;
    for (label, data) in generated_buffers(&atoms, MIB) {
        total += differential(&atoms, &data, label);
    }
    assert!(total > 10_000, "only {total} matches in total");
}

#[test]
fn the_matcher_agrees_on_a_low_entropy_buffer_whose_every_offset_matches() {
    // A quarter of a mebibyte of one byte, with one-byte and two-byte atoms for
    // it: every offset is a match for several atoms, so this is the worst case
    // for the short path and for the run of reports that follows it.
    //
    // A quarter and not a whole mebibyte, which is what the "every offset
    // matches" property wants and does not need. The count is what costs: a
    // mebibyte is four million pairs, and four vectors that size are live at
    // once inside `differential` — the oracle's answer, the matcher's, and the
    // two `atoms_present` builds. That is a hundred-odd megabytes in a test
    // that runs alongside three others, on a machine where a concurrent rustc
    // can take the rest, which is exactly how this test first failed with
    // `memory allocation of 1048576 bytes failed` and a stack-buffer-overrun
    // exit code that says nothing about the matcher. The property under test —
    // every offset is a match, checked against the fencepost arithmetic below —
    // is identical at a quarter of the size.
    let atoms: Vec<Vec<u8>> = vec![
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00],
        vec![0x00, 0x00, 0x00, 0x00],
        vec![0x00, 0x00, 0x00, 0x00, 0x41],
    ];
    let data = vec![0u8; 256 * 1024];
    let matches = differential(&atoms, &data, "a quarter mebibyte of zeros");
    // Four of the five atoms fit at every offset they can reach — the fifth
    // needs an `A` that a buffer of zeros never has — so the count is the
    // number of offsets each of them has, which is the buffer's length less
    // its own length plus one. Spelled out rather than multiplied, because the
    // fenceposts are the arithmetic that a wrong answer gets wrong: an
    // off-by-one in the last-offset handling moves this by exactly one per
    // atom, and `data.len() * 4` would have hidden that.
    let expected = [1usize, 2, 3, 4]
        .iter()
        .map(|len| data.len() - len + 1)
        .sum::<usize>();
    assert_eq!(matches, expected, "one occurrence of each atom per offset");
}

#[test]
fn the_matcher_agrees_on_the_system_library() {
    // A real file, not a shape someone chose. 8,009,440 bytes if it is present,
    // which it is on any Windows this runs on; the test is skipped rather than
    // failed where it is not, because a matcher is not wrong for living on a
    // machine without shell32.dll.
    let path = r"C:\Windows\System32\shell32.dll";
    let Ok(data) = std::fs::read(path) else {
        eprintln!("skipping: {path} could not be read on this machine");
        return;
    };
    if data.len() < 8 {
        eprintln!("skipping: {path} is too short to take a four-byte atom from");
        return;
    }

    // Two halves, and they are testing opposite things.
    //
    // The first is the atom set the rest of this file uses: drawn from the
    // distribution the real rule set has, and mostly *absent* from the file.
    // That is the half that exercises the gate's rejection over eight
    // megabytes, which is where a wrong table index shows up.
    //
    // The second half is windows sliced out of the file itself. An atom taken
    // from the file is present at the offset it came from, by construction, so
    // the answer this test compares is known to be non-empty before the
    // comparison starts — which is the thing a threshold cannot give you. The
    // first version of this test asserted `matches > 1_000` and the true count
    // was 70; the threshold was wrong, not the matcher, and nothing about the
    // failure said so. An invariant cannot be miscalibrated that way.
    let mut atoms = real_shaped_atoms(256, 0xC0FF_EE02);
    let sliced = 256;
    let mut state = 0xC0FF_EE03u64;
    for _ in 0..sliced {
        // `data.len() - 4` and not `data.len() - 3`, so that the window is
        // always a whole four bytes and its own offset is one the oracle
        // considers.
        let at = (next(&mut state) >> 16) as usize % (data.len() - 4);
        atoms.push(data[at..at + 4].to_vec());
    }

    let matches = differential(&atoms, &data, "shell32.dll");
    assert!(
        matches >= sliced,
        "{sliced} atoms were sliced out of the file and every one of them is present, so at \
         least {sliced} matches exist; the matcher and the naive scan agree on {matches}, which \
         means they agree on a wrong answer"
    );
}
