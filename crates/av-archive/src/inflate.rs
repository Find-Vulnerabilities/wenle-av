//! The one decompressor, wrapped so that it cannot be made to overrun.
//!
//! # Why this is driven by hand rather than by `Read::read_to_end`
//!
//! Two of the three formats this crate reads need to know how many *input*
//! bytes the deflate stream consumed, not just what it produced. A gzip member
//! is a header, a deflate stream, and a trailer, and the trailer has no
//! signature — the only way to find it is to decompress and ask where the
//! stream ended. A zip member does not need that, but reading both paths
//! through one function means the ceiling is enforced in one place and a
//! change to it cannot apply to one format and not the other.
//!
//! `flate2::Decompress` exposes exactly the two counters this needs and writes
//! only into a slice the caller hands it. That slice is the whole defence: the
//! middle of this module is the only place in the product where untrusted data
//! causes an allocation proportional to something other than the file's own
//! size, and the slice is sized one byte past the ceiling so that reaching the
//! ceiling can be *detected* without ever exceeding it.
//!
//! # Why the output goes through a scratch buffer
//!
//! The obvious shape is to hand the decompressor the destination `Vec` and let
//! it fill the spare capacity. That is what this module did first, and it is
//! wrong: `Vec::reserve` is amortized, so the capacity it leaves behind can be
//! twice the length, and a decompressor filling "the spare capacity" writes to
//! that, not to the amount that was asked for. The ceiling then held only to
//! within a factor of two — measured, not theorised: a one-mebibyte ceiling let
//! two mebibytes through.
//!
//! So the decompressor writes into a fixed scratch buffer and the bytes are
//! copied out afterwards. The slice it is given is exactly the room that
//! remains, which makes the ceiling a property of the code rather than of the
//! allocator's growth strategy. The cost is one `memcpy` of the bytes produced,
//! against a decompression that just produced them.

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::ArchiveError;
use crate::Result;

/// The most that will be handed to the decompressor to write into at once.
///
/// Sixty-four kibibytes: large enough that a well-behaved stream is a handful
/// of calls, small enough that the last chunk before a ceiling is reached
/// wastes at most this much. It is also the size of the one scratch allocation
/// this module makes, which is reused for every chunk of every member.
const CHUNK: usize = 64 * 1024;

/// What a decompression produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inflated {
    /// The decompressed bytes.
    pub bytes: Vec<u8>,
    /// How many bytes of the input the stream actually consumed.
    ///
    /// Less than the input's length whenever the input holds something after
    /// the stream — a gzip trailer, or the next member of a concatenated set.
    pub consumed: usize,
}

/// Decompress a raw deflate stream, refusing to produce more than `limit`.
///
/// `hint` is the capacity to reserve up front, which the caller takes from
/// whatever the container declared. It is a hint and not a limit; the hard
/// ceiling is `limit` and it is enforced on every iteration.
pub fn raw(input: &[u8], limit: u64, hint: usize) -> Result<Inflated> {
    let mut out = Vec::with_capacity(hint);
    decompress(input, limit, &mut out).map(|consumed| Inflated {
        bytes: out,
        consumed,
    })
}

/// Decompress into a buffer the caller owns, so that a caller wanting to append
/// to something it already has does not pay for a copy.
///
/// `out`'s existing length counts against `limit`: the ceiling is on the total
/// produced, not on this call's contribution.
pub fn into(input: &[u8], limit: u64, out: &mut Vec<u8>) -> Result<usize> {
    decompress(input, limit, out)
}

fn decompress(input: &[u8], limit: u64, out: &mut Vec<u8>) -> Result<usize> {
    // `limit` is a ceiling on `out`'s whole length, not on this call's
    // contribution: a caller appending to a buffer it already has is bounded by
    // the same number, which is what makes the budget a property of the scan
    // rather than of the member being read.
    if out.len() as u64 > limit {
        return Err(ArchiveError::Budget {
            needed: out.len() as u64,
            remaining: limit,
        });
    }

    let mut decompress = Decompress::new(false);
    let mut scratch = vec![0u8; CHUNK];
    let mut consumed = 0usize;

    loop {
        let remaining = limit - out.len() as u64;
        // One byte of headroom, and it is deliberate. A decompressor told to
        // stop exactly at the ceiling cannot distinguish "the stream ended here
        // and happened to fill the buffer" from "there is more"; a stream that
        // has already produced the ceiling and has another byte in it must be
        // refused, and refusing requires having seen the byte. The extra byte
        // is never returned to the caller — it is dropped when the budget
        // error is built.
        let room = usize::try_from(remaining.saturating_add(1).min(CHUNK as u64)).unwrap_or(CHUNK);

        let before_in = decompress.total_in();
        let before_out = decompress.total_out();

        // The scratch slice is exactly `room` long, so this is the hard ceiling:
        // the decompressor has nowhere to put a byte more than it was given.
        let status = decompress
            .decompress(
                &input[consumed..],
                &mut scratch[..room],
                FlushDecompress::None,
            )
            .map_err(|error| ArchiveError::Malformed {
                format: "deflate",
                detail: format!("a compressed stream is malformed: {error}"),
            })?;

        consumed += usize::try_from(decompress.total_in() - before_in).unwrap_or(0);
        let grew = usize::try_from(decompress.total_out() - before_out).unwrap_or(0);
        out.extend_from_slice(&scratch[..grew]);

        if out.len() as u64 > limit {
            return Err(ArchiveError::Budget {
                needed: out.len() as u64,
                remaining: limit,
            });
        }

        match status {
            Status::StreamEnd => return Ok(consumed),
            Status::Ok if grew > 0 => {}
            // `BufError` is what a decompressor returns when it can make no
            // progress, and with room always available in the output that means
            // the input ran out. `Ok` without growth is the same situation
            // reached from the other side: an empty input slice, and a stream
            // that has not finished. Both are a truncated file.
            Status::Ok | Status::BufError => {
                if consumed >= input.len() {
                    return Err(ArchiveError::Malformed {
                        format: "deflate",
                        detail: "a compressed stream ends before its end marker".into(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate_bytes(content: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(content).expect("deflating");
        encoder.finish().expect("finishing")
    }

    #[test]
    fn a_stream_round_trips_and_reports_what_it_consumed() {
        let content = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let compressed = deflate_bytes(&content);
        let inflated = raw(&compressed, u64::MAX, 0).expect("inflates");
        assert_eq!(inflated.bytes, content);
        assert_eq!(inflated.consumed, compressed.len());
    }

    #[test]
    fn trailing_bytes_are_left_unconsumed() {
        // What a gzip trailer looks like to this function: four CRC bytes and
        // four length bytes the stream has nothing to do with.
        let content = b"payload".repeat(10);
        let mut input = deflate_bytes(&content);
        let stream_len = input.len();
        input.extend_from_slice(&[0xaa; 8]);

        let inflated = raw(&input, u64::MAX, 0).expect("inflates");
        assert_eq!(inflated.bytes, content);
        assert_eq!(inflated.consumed, stream_len);
    }

    #[test]
    fn the_ceiling_is_enforced_and_reaching_it_is_an_error() {
        // Ten megabytes of zeros, which deflate reduces to a few kilobytes.
        let content = vec![0u8; 10 * 1024 * 1024];
        let compressed = deflate_bytes(&content);
        assert!(compressed.len() < 32 * 1024, "{}", compressed.len());

        let error = raw(&compressed, 1024 * 1024, 0).expect_err("over the ceiling");
        match error {
            ArchiveError::Budget { needed, remaining } => {
                assert_eq!(remaining, 1024 * 1024);
                // Exactly one byte over, not "about". The scratch buffer is
                // sized to the room that remains plus one, so the only way past
                // the ceiling is by that single byte — and this assertion is
                // what would fail if a future change went back to handing the
                // decompressor a `Vec` and letting it fill the spare capacity
                // that `reserve` happened to leave behind.
                assert_eq!(
                    needed,
                    1024 * 1024 + 1,
                    "the overshoot must be exactly the one byte of headroom"
                );
            }
            other => panic!("expected a budget refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_stream_that_fits_exits_exactly_at_its_size() {
        // The control for the test above: a ceiling one byte above the content
        // must succeed, so that the ceiling is a real boundary and not an
        // off-by-one that refuses everything near it.
        let content = vec![7u8; 4096];
        let compressed = deflate_bytes(&content);
        let inflated = raw(&compressed, 4096, 0).expect("exactly fits");
        assert_eq!(inflated.bytes.len(), 4096);
    }

    #[test]
    fn a_truncated_stream_is_malformed_and_not_a_short_read() {
        let content = b"a reasonably long body so the stream is not a single block".repeat(10);
        let compressed = deflate_bytes(&content);
        let truncated = &compressed[..compressed.len() / 2];
        let error = raw(truncated, u64::MAX, 0).expect_err("truncated");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn nonsense_input_is_malformed() {
        let error = raw(&[0xff; 64], u64::MAX, 0).expect_err("not a deflate stream");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn an_empty_input_reports_a_stream_that_never_ended() {
        let error = raw(&[], u64::MAX, 0).expect_err("no stream");
        assert!(matches!(error, ArchiveError::Malformed { .. }), "{error:?}");
    }

    #[test]
    fn appending_counts_the_bytes_already_there_against_the_ceiling() {
        // The ceiling is on what the buffer ends up holding, not on what this
        // call adds. A caller that grew a buffer to within a kilobyte of the
        // budget and then hands it to a stream that expands to eight thousand
        // bytes has to be refused, or the budget is a per-member number that
        // says nothing about the scan's total.
        let content = vec![1u8; 8192];
        let compressed = deflate_bytes(&content);
        let mut out = vec![0u8; 8000];
        let error = into(&compressed, 8192, &mut out).expect_err("over the ceiling");
        assert!(matches!(error, ArchiveError::Budget { .. }), "{error:?}");

        // The control: the same buffer and the same stream, with a ceiling that
        // leaves room for both, and the answer is the exact sum.
        let mut out = vec![0u8; 100];
        into(&compressed, 100 + 8192, &mut out).expect("fits");
        assert_eq!(out.len(), 100 + 8192);
    }
}
