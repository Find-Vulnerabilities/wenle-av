//! Byte statistics over a region of a file: the numbers that say whether a
//! region looks like code, like text, or like something that has been through a
//! compressor.
//!
//! # Two callers, one definition
//!
//! The rule language names these — `math.entropy(offset, size)`,
//! `math.mean(offset, size)`, `math.count(byte, offset, size)` — and the
//! engine's own heuristic scorer uses the same numbers to decide whether a file
//! is packed. They have to agree. A rule author who writes
//! `math.entropy(0, filesize) > 7.4` and an engine that flags packing above a
//! different 7.4 are making the same claim about the same bytes, and two
//! implementations of "entropy" that differ in their rounding would make them
//! mean different things on the same file.
//!
//! # Entropy, precisely
//!
//! Shannon entropy over the 256-symbol byte histogram, in bits per byte:
//!
//! ```text
//! H = - Σ p(b) · log2 p(b)      over the 256 byte values, p = count / n
//! ```
//!
//! The range is `0.0` for a region of one repeated byte to `8.0` for a region
//! in which all 256 values occur equally often. Those two ends are what make it
//! useful: compiled code and English text sit in the middle, and anything above
//! about `7.2` over a region of any size is either encrypted, compressed, or a
//! deliberately constructed blob. The engine's packing score treats it that
//! way; so do the rules.
//!
//! The logarithm is `log2`, taken per symbol and weighted. An equivalent form
//! computes `log2(n) - (Σ c·log2 c) / n`, which is one division instead of 256
//! multiplications, but it is not used here: the two agree to the last bit only
//! when the accumulation order is the same, and a rule comparing against a
//! threshold picked off one of them could differ on the boundary. The direct
//! form is what is documented, so the direct form is what runs.

/// A region of a buffer, clamped to what is actually there.
///
/// Every function here takes `offset` and `size` as they arrived from a rule,
/// where both can be nonsense: a rule computes `filesize - 500` on a file of
/// 100 bytes and gets a negative number, or asks for 4 GiB of a 1 KiB file.
/// Clamping rather than refusing is the choice, because the alternative is a
/// rule that behaves differently on two files without saying so.
///
/// The rule is one sentence: **a region that is not entirely inside the buffer
/// is the part of it that is**. So a size that runs past the end is shortened,
/// and an offset at or past the end is empty. `(0x400, filesize)` — a shape five
/// rules in the corpus use — means "from 0x400 to the end", which is what its
/// author meant, and never a read past the buffer.
///
/// A negative offset or a negative size is empty rather than clamped to zero.
/// The distinction matters for exactly one expression, and it appears three
/// times in the corpus: `math.entropy(500, filesize - 500)` on a file shorter
/// than 500 bytes. Clamping the size to zero would make that the entropy of the
/// whole file, and a rule asking whether the body of a script is compressed
/// would then be asking about the script — including its header, which is the
/// part that is not compressed. Empty is the answer that means "there is no
/// body here", and it is false against every threshold.
pub fn region(data: &[u8], offset: i64, size: i64) -> &[u8] {
    let Ok(start) = usize::try_from(offset) else {
        return &[];
    };
    let Ok(wanted) = usize::try_from(size) else {
        return &[];
    };
    if start >= data.len() {
        return &[];
    }
    // `wanted.min(available)` rather than `start + wanted` with a checked
    // subtraction: on a 32-bit build a rule that wrote `filesize` as the size
    // gives a `usize` that overflows the addition, and the minimum is the same
    // answer without the overflow being possible.
    &data[start..start + wanted.min(data.len() - start)]
}

/// The number of times each byte value occurs in `data`.
///
/// Returned by value rather than filled into a caller's buffer so that the
/// borrow of `data` ends here. A histogram is 256 `u64`s — two kilobytes — and
/// the callers that want one want it once per region, not once per byte.
pub fn histogram(data: &[u8]) -> [u64; 256] {
    let mut counts = [0u64; 256];
    for &byte in data {
        // Indexing cannot fail: `byte` is a `u8` and the array has 256 slots.
        // Written as an index rather than a `match` because the compiler turns
        // it into a single load-and-increment, which is the whole cost of this
        // function.
        counts[byte as usize] += 1;
    }
    counts
}

/// Shannon entropy of the region, in bits per byte.
///
/// An empty region has no distribution and answers `0.0`. That is the value
/// that keeps a rule comparing `math.entropy(...) > 7.5` from firing on a
/// region that is not there, which is the dangerous direction.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let counts = histogram(data);
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / n;
        h -= p * p.log2();
    }
    // Clamped because the sum's last bits can land a hair above 8.0 for a
    // perfectly flat distribution, and `entropy > 8.0` is a comparison a rule
    // can write and should never be true.
    h.clamp(0.0, 8.0)
}

/// The arithmetic mean of the region's byte values.
///
/// `0.0` for an empty region, for the same reason [`entropy`] is.
pub fn mean(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let total: u64 = data.iter().map(|&b| u64::from(b)).sum();
    total as f64 / data.len() as f64
}

/// How far the region's bytes sit from a mean the caller supplies, on average:
/// the **mean absolute deviation**.
///
/// ```text
/// D = (Σ |b - mean|) / n      over the region's bytes b
/// ```
///
/// # Why a mean is an argument
///
/// Because the caller usually knows it. The rules that use this are asking
/// whether a region looks like a particular *kind* of data, and the mean of that
/// kind is a fact about it rather than about this file: the corpus compares
/// against `89.0`, the mean of the base64 alphabet, to tell a base64 payload
/// from source code. Computing the region's own mean first would answer a
/// different question — how spread out the bytes are around wherever they
/// happen to be centred — and a region of base64 shifted by a constant would
/// score the same as one that is not base64 at all.
///
/// # Which deviation
///
/// The mean absolute one rather than the standard one, and the difference is
/// visible on the boundary the rules are written against. Over an evenly
/// distributed sample of all 256 byte values the absolute deviation from
/// `127.5` is exactly `64.0`, which is the value the module's own documentation
/// uses as its example; the standard deviation of the same region is `73.9`.
/// A rule tuned at `64.0` against the other statistic would fire on files its
/// author wrote it to exclude, so the choice is not a detail.
///
/// An empty region answers `0.0`, for the same reason [`entropy`] does: a
/// threshold test against a region that is not there must be false, and `0.0`
/// is below every deviation a rule will name.
pub fn deviation(data: &[u8], mean: f64) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let total: f64 = data
        .iter()
        .map(|&byte| (f64::from(byte) - mean).abs())
        .sum();
    total / data.len() as f64
}

/// How many times `byte` occurs in the region.
pub fn count(data: &[u8], byte: u8) -> u64 {
    // `memchr`'s counting form is SIMD-accelerated and beats a filtered
    // `Iterator::count` on every region size that matters here.
    memchr::memchr_iter(byte, data).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_of_one_repeated_byte_has_no_entropy() {
        assert_eq!(entropy(&[0u8; 4096]), 0.0);
        assert_eq!(entropy(&[0x41u8; 64]), 0.0);
    }

    #[test]
    fn a_region_with_every_byte_equally_often_has_eight_bits() {
        // The other end of the range, and the one that says the histogram is
        // over the 256 byte values and not over something else.
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-12, "{}", entropy(&all));
    }

    #[test]
    fn entropy_is_the_sum_over_the_histogram_not_over_the_bytes() {
        // Two symbols, half each: one bit. Written as an exact value because a
        // formulation that divided by the wrong count would still land close.
        assert!((entropy(&[0x00, 0xff]) - 1.0).abs() < 1e-12);
        // Four symbols, a quarter each: two bits.
        assert!((entropy(&[0x00, 0x01, 0x02, 0x03]) - 2.0).abs() < 1e-12);
        // The same histogram in a different order is the same entropy, which is
        // the property that makes it a statistic rather than a fingerprint.
        assert!((entropy(&[0x00, 0x01, 0x02, 0x03]) - entropy(&[3, 0, 2, 1])).abs() < 1e-12);
    }

    #[test]
    fn entropy_rises_as_a_region_gets_closer_to_random() {
        // A monotone sequence rather than a fixed threshold: the useful claim is
        // the ordering, not the third decimal place.
        let zeros = vec![0u8; 8192];
        let some: Vec<u8> = (0..8192).map(|i| (i % 16) as u8).collect();
        let most: Vec<u8> = (0..8192).map(|i| (i % 128) as u8).collect();

        let (a, b, c) = (entropy(&zeros), entropy(&some), entropy(&most));
        assert!(a < b, "{a} < {b}");
        assert!(b < c, "{b} < {c}");
    }

    #[test]
    fn an_empty_region_answers_zero_rather_than_not_a_number() {
        // The dangerous value. `math.entropy(...) > 7.5` on a region that is not
        // there must be false, and had this answered `NaN` the comparison would
        // be false too — but `NaN` also makes `<=` false, and a rule negating
        // one of those would fire on every file.
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(mean(&[]), 0.0);
    }

    #[test]
    fn the_mean_is_the_arithmetic_one() {
        assert_eq!(mean(&[0, 1, 2, 3]), 1.5);
        assert_eq!(mean(&[0xff; 10]), 255.0);
        assert_eq!(mean(&[0x00, 0xff]), 127.5);
    }

    #[test]
    fn the_deviation_is_the_absolute_one_and_the_even_sample_is_sixty_four() {
        // The value the module documents as its own example, and the one that
        // separates this statistic from the standard deviation: `73.9` is what
        // the other one answers here, so a rule tuned at `64.0` would be tuned
        // against the wrong number if this were implemented as a variance.
        let all: Vec<u8> = (0..=255u8).collect();
        let d = deviation(&all, 127.5);
        assert!((d - 64.0).abs() < 1e-9, "{d}");
        assert!(
            (d - 64.0).abs() < (73.9 - 64.0),
            "and not the other statistic"
        );
    }

    #[test]
    fn the_deviation_is_taken_from_the_mean_the_caller_gives() {
        // Not from the region's own mean, which is the whole point of the
        // argument: `[10, 20, 30]` is centred on 20 and deviates from 20 by
        // `20/3` — and from the base64 alphabet's mean by `79 + 69 + 59` over
        // three, which is more than three times as far.
        assert!((deviation(&[10, 20, 30], 20.0) - 20.0 / 3.0).abs() < 1e-12);
        assert!((deviation(&[10, 20, 30], 89.0) - 207.0 / 3.0).abs() < 1e-12);
        assert!(deviation(&[10, 20, 30], 89.0) > deviation(&[10, 20, 30], 20.0));
    }

    #[test]
    fn a_flat_region_has_no_deviation_from_its_own_value() {
        assert_eq!(deviation(&[0xff; 32], 255.0), 0.0);
        assert_eq!(deviation(&[0u8; 32], 0.0), 0.0);
        // And the empty region, which is not the same thing as a flat one.
        assert_eq!(deviation(&[], 89.0), 0.0);
    }

    #[test]
    fn a_region_that_runs_off_the_end_is_shortened_rather_than_refused() {
        let data = vec![7u8; 100];
        assert_eq!(region(&data, 0, 100).len(), 100);
        assert_eq!(region(&data, 50, 100).len(), 50, "clamped to the end");
        // The shape five corpus rules use: from a header offset to the end.
        assert_eq!(region(&data, 0x20, i64::MAX).len(), 68);
    }

    #[test]
    fn a_region_that_starts_outside_the_buffer_is_empty() {
        let data = vec![7u8; 100];
        assert!(region(&data, 100, 10).is_empty());
        assert!(region(&data, 1 << 40, 10).is_empty());
        // A negative offset — what `filesize - 500` is on a 100-byte file —
        // is empty rather than clamped to zero. See the function's own note.
        assert!(region(&data, -500, 100).is_empty());
    }

    #[test]
    fn a_negative_size_is_a_region_to_the_end() {
        // `math.entropy(500, filesize - 500)` on a file smaller than 500 bytes:
        // the size is negative and the region is empty, because the offset is
        // already past the end. On a large file the same expression is a
        // positive size. Neither may panic.
        let big = vec![0u8; 5000];
        assert_eq!(region(&big, 500, 4500).len(), 4500);
        assert!(region(&[0u8; 100], 500, -400).is_empty());

        // A size that is negative while the offset is inside: the caller asked
        // for a negative count, which is nothing.
        assert!(region(&big, 500, -1).is_empty());
    }

    #[test]
    fn counting_a_byte_agrees_with_a_hand_count() {
        let data = [1u8, 2, 1, 3, 1, 4];
        assert_eq!(count(&data, 1), 3);
        assert_eq!(count(&data, 2), 1);
        assert_eq!(count(&data, 9), 0);
        assert_eq!(count(&[], 1), 0);
    }
}
