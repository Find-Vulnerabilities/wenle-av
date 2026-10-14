//! Why a PE file could not be read.
//!
//! Every variant here is reachable from a file on disk, which is the point:
//! the parser's contract is that a malformed file produces one of these rather
//! than a panic, an out-of-bounds read or an allocation the size of a field it
//! read out of the file. A scanner that crashes on a crafted sample has handed
//! the attacker the denial of service they wanted.

use std::fmt;

/// A file that could not be parsed as a PE.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeError {
    /// The file does not begin with `MZ`.
    #[error("not a PE file: no `MZ` at offset 0")]
    NoDosMagic,

    /// The `MZ` is there but `e_lfanew` does not point at `PE\0\0`.
    #[error("not a PE file: no `PE\\0\\0` signature at offset {at}")]
    NoPeSignature {
        /// The offset `e_lfanew` pointed at.
        at: u32,
    },

    /// A read ran past the end of the buffer.
    ///
    /// Carries all three numbers because the usual cause is a field claiming a
    /// size the file does not have, and knowing which size was believed is what
    /// makes it diagnosable.
    #[error(
        "read of {wanted} bytes at offset {offset} runs past the end of a {available}-byte buffer"
    )]
    Truncated {
        /// Where the read started.
        offset: usize,
        /// How many bytes it asked for.
        wanted: usize,
        /// How many the buffer had.
        available: usize,
    },

    /// The optional header's magic is neither PE32 nor PE32+.
    #[error("unknown optional header magic {magic:#06x}")]
    BadOptionalMagic {
        /// The value that was neither PE32 nor PE32+.
        magic: u16,
    },

    /// A count multiplied by a stride overflowed `usize`.
    ///
    /// Reachable from a crafted `NumberOfSections` or resource count. It is its
    /// own variant rather than a `Truncated` because the arithmetic is the
    /// problem, not the buffer, and `count * stride` saturating instead would
    /// allocate far more than the file could hold.
    #[error("{count} entries of {stride} bytes each do not fit in an address space")]
    CountOverflow {
        /// The number of entries the file claimed.
        count: u64,
        /// The size of one entry.
        stride: u64,
    },

    /// A named string had no terminating NUL inside the region it must live in.
    #[error("string at offset {offset} is not terminated within {limit} bytes")]
    UnterminatedString {
        /// Where the string started.
        offset: usize,
        /// How far the search for a NUL was allowed to run.
        limit: usize,
    },

    /// A structure that must be inside a section or the headers is not.
    #[error("{what} at offset {offset} is outside the file's mapped regions")]
    Unmapped {
        /// Which structure it was.
        what: &'static str,
        /// Where the file said it was.
        offset: u64,
    },

    /// The file is a valid PE but the part being read is absent — no resource
    /// directory, no signature, no rich header, no version info.
    ///
    /// Distinct from the errors above because it is not a defect: most files
    /// lack most of these, and every caller of the affected accessors has to
    /// handle it as an ordinary absence rather than a parse failure.
    #[error("this file has no {what}")]
    Absent {
        /// Which part of the file is missing.
        what: &'static str,
    },
}

impl PeError {
    /// Whether this means "the file does not have that", as opposed to "the
    /// file is malformed".
    ///
    /// The distinction decides whether a caller gives up on the whole file or
    /// just on one field of it, which is the difference between a scanner that
    /// reports `pe.sections` for a truncated sample and one that reports
    /// nothing at all.
    pub fn is_absence(&self) -> bool {
        matches!(self, PeError::Absent { .. })
    }
}

/// A string that could not be decoded as UTF-8.
///
/// Kept separate from [`PeError`] because PE strings are not required to be
/// UTF-8 and a rule comparing `pe.sections[0].name == ".text"` should not be
/// defeated by a section name that is not text at all: the bytes are kept, and
/// this only says how they were *also* interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotUtf8;

impl fmt::Display for NotUtf8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the bytes are not valid UTF-8")
    }
}

impl std::error::Error for NotUtf8 {}
