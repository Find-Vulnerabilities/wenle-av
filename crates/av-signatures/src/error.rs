//! Why a signature could not be read.
//!
//! Every variant is reachable from a file on disk. A certificate in a sample is
//! attacker-controlled bytes wrapped in three layers of attacker-controlled
//! lengths — the attribute certificate table, the `WIN_CERTIFICATE` record, and
//! the PKCS#7 blob inside it — so the failure mode to design against is the
//! same one `av-pe` designs against: a crafted file must produce one of these
//! rather than a panic or an allocation sized by a number the file supplied.

use std::fmt;

/// A certificate or signature that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The buffer ended in the middle of a header.
    #[error("truncated DER: element starting at offset {at} has no complete header")]
    Truncated {
        /// Where the element started.
        at: usize,
    },

    /// A length byte of `0x80`, which BER allows and DER forbids.
    #[error("indefinite length at offset {at}, which DER does not permit")]
    IndefiniteLength {
        /// Where the element started.
        at: usize,
    },

    /// A long-form length with more bytes than a slice can have.
    #[error("length at offset {at} is {count} bytes wide, which cannot describe a buffer")]
    LengthTooLong {
        /// Where the element started.
        at: usize,
        /// How many length bytes it claimed.
        count: usize,
    },

    /// The buffer held more than the one element that was asked for.
    #[error("{count} bytes follow the value")]
    TrailingBytes {
        /// How many bytes were left over.
        count: usize,
    },

    /// The buffer was empty.
    #[error("the buffer is empty")]
    Empty,

    /// An element had a different tag from the one the format requires.
    #[error("expected tag {wanted:#04x}, found {found:#04x}")]
    UnexpectedTag {
        /// The tag the format calls for.
        wanted: u8,
        /// The tag the file had.
        found: u8,
    },

    /// The buffer ended where an element was required.
    #[error("expected an element with tag {wanted:#04x} but the buffer ended")]
    UnexpectedEnd {
        /// The tag that was being looked for.
        wanted: u8,
    },

    /// A value that must be a `SEQUENCE` or `SET` had a primitive tag.
    #[error("tag {tag:#04x} is primitive, so it has no elements to read")]
    NotConstructed {
        /// The primitive tag that was found.
        tag: u8,
    },

    /// An `INTEGER` had no content bytes, which DER does not allow.
    #[error("an INTEGER has no content bytes")]
    EmptyInteger,

    /// An `INTEGER` was wider than the `u64` it was read into.
    #[error("an INTEGER of {len} bytes does not fit in a u64")]
    IntegerTooLarge {
        /// How many bytes it had after the sign byte.
        len: usize,
    },

    /// A `BIT STRING` had no unused-bits byte.
    #[error("a BIT STRING has no unused-bits byte")]
    EmptyBitString,

    /// An `OBJECT IDENTIFIER` was not a valid encoding.
    #[error("an OBJECT IDENTIFIER is not minimally encoded")]
    BadOid,

    /// A time was not one of the two forms a certificate uses.
    #[error("`{value}` is not a UTCTime or GeneralizedTime")]
    BadTime {
        /// The text that could not be read.
        value: String,
    },

    /// A distinguished name had a structure that is not an RDN sequence.
    #[error("a distinguished name is not a sequence of attribute sets")]
    BadName,

    /// The signature blob is not a PKCS#7 `SignedData`.
    #[error("the signature blob is not PKCS#7 SignedData: {reason}")]
    NotPkcs7 {
        /// Which part of the structure was wrong.
        reason: &'static str,
    },

    /// The `WIN_CERTIFICATE` record is malformed.
    #[error("the WIN_CERTIFICATE record is malformed: {reason}")]
    BadWinCertificate {
        /// Which part of the record was wrong.
        reason: &'static str,
    },

    /// The catalog store could not be read.
    ///
    /// The only variant here that is about the *filesystem* rather than about
    /// bytes a sample supplied, and it is deliberately not a
    /// [`std::io::Error`]: this type is `Clone + PartialEq`, because tests
    /// compare it and reports carry it, and `io::Error` is neither. The cost is
    /// the lost `source` chain on a variant whose callers log it verbatim, which
    /// is a smaller cost than making every other variant uncomparable.
    #[error("the catalog store at `{path}` could not be read: {reason}")]
    CatalogStore {
        /// The directory or file that could not be read.
        path: String,
        /// What the filesystem said, rendered.
        reason: String,
    },
    /// The blob is a PKCS#7 `SignedData` but not a catalog.
    ///
    /// Separate from [`SignatureError::NotPkcs7`] because the two are different
    /// things to a caller: a `.cat` file and a `.exe`'s Authenticode blob are
    /// both `SignedData`, and the difference is the *content type* inside. A
    /// reader that reached here was handed the wrong kind of file, not a
    /// malformed one.
    #[error("the blob is not a catalog: {reason}")]
    NotCatalog {
        /// Which part of the structure was wrong.
        reason: &'static str,
    },

    /// The file is a valid PE but carries no Authenticode signature.
    ///
    /// Separate from the errors above because it is not a defect. Most files
    /// have no signature, and a rule reading `pe.number_of_signatures` has to
    /// get a `0` for them rather than an error — the same distinction
    /// `PeError::Absent` makes, for the same reason.
    #[error("this file has no Authenticode signature")]
    Absent,
}

impl SignatureError {
    /// Whether this means "the file does not have that", as opposed to "what
    /// the file has is malformed".
    ///
    /// The distinction decides whether a rule's certificate block is skipped or
    /// the whole file is abandoned, and getting it backwards would make the
    /// scanner report a parse failure for the majority of files on disk — which
    /// have no signature at all.
    pub fn is_absence(&self) -> bool {
        matches!(self, SignatureError::Absent)
    }
}

/// A certificate field that could not be rendered as text.
///
/// Kept as its own type because the DN string and the thumbprint string are
/// compared with `contains`, and a value that cannot be rendered must produce a
/// string that *no* rule matches rather than a string that some rule matches by
/// accident. Callers get an empty string, and this records why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unrenderable;

impl fmt::Display for Unrenderable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the field cannot be rendered as text")
    }
}

impl std::error::Error for Unrenderable {}
