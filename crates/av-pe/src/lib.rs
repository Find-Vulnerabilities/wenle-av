//! PE parsing for the scanner's rule engine.
//!
//! This crate exists to answer one kind of question: *what does the `pe` module
//! say about this file?* It is not a general-purpose PE library and does not try
//! to be one. What it does try to be is a parser that cannot be made to read the
//! wrong bytes.
//!
//! # Why not an existing parser
//!
//! `pelite` is a fine crate and is not used here for three reasons.
//!
//! * **The input is hostile.** A file being scanned was written by whoever wrote
//!   the malware. Every offset, count and size in it is an attacker-chosen
//!   integer, and a parser that trusts one of them hands over an out-of-bounds
//!   read or an allocation the size of a field. Every read here goes through
//!   [`read::Reader`], which cannot return a value without saying whether the
//!   bytes for it were present.
//! * **The semantics are YARA's, not the format's.** The rules in this product's
//!   corpus were written against YARA's `pe` module, quirks included: an entry
//!   point reported as a file offset, an RVA outside every section returned
//!   unchanged, a section name trimmed at its first NUL. A general parser
//!   reports the format's truth, which is not the same thing, and the difference
//!   shows up as rules that silently stop matching.
//! * **The dependency tree is a liability in a scanner.** `pelite` is not
//!   needed to decode structures that are, in total, a few hundred lines of
//!   field offsets.
//!
//! # Layout
//!
//! | Module | What it is |
//! |---|---|
//! | [`read`] | bounds-checked little-endian reads |
//! | [`headers`] | DOS stub, COFF header, optional header, data directories |
//! | [`sections`] | the section table and the RVA-to-offset mapping |
//! | [`pe`] | the file as a whole, and the values a rule asks for |
//!
//! The split follows the file. [`headers`] and [`sections`] report what the
//! format records; [`pe`] is the module and does the conversions that turn those
//! into what a rule means.
//!
//! # Parsing a file
//!
//! ```
//! use av_pe::PeFile;
//!
//! # let data = av_pe::testing::minimal_pe32();
//! match PeFile::parse(&data) {
//!     Ok(pe) => {
//!         assert!(pe.is_pe());
//!         println!("{} sections, entry point at {:#x}", pe.number_of_sections(), pe.entry_point());
//!     }
//!     Err(e) if e.is_absence() => println!("a PE, but the part we wanted is not there"),
//!     Err(e) => println!("not a PE: {e}"),
//! }
//! ```
//!
//! The buffer is borrowed, not copied: a scan maps a file once and every layer
//! below reads from that same mapping.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
// The scanner's contract is that it does not panic on a hostile input, and every
// `unwrap` on a value that came out of a file is a place where it would. Denied
// rather than warned so that the next one is a build break and not a line in a
// list nobody reads.
//
// Indexing is not denied here even though it panics too: every use of it in this
// crate is a `[0]` after a length-checked [`read::Reader::slice`], and the lint
// cannot see that. The rule that matters — no field of the file is trusted — is
// enforced by the reader's signatures instead, which have no way to return a
// value without saying whether its bytes were there.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// In a test, unwrapping *is* the assertion: a `Result` that should have been
// `Ok` and was not has to fail the test, and a helper that quietly returned a
// default would turn a broken fixture into a passing one.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod debug;
pub mod dotnet;
pub mod error;
pub mod exports;
pub mod headers;
pub mod imports;
pub mod pe;
pub mod read;
pub mod resources;
pub mod rich;
pub mod sections;
pub mod testing;
pub mod version;

pub use debug::DebugDirectory;
pub use dotnet::{AssemblyRef, AssemblyVersion, DotNet, DotNetResource};
pub use error::PeError;
pub use exports::Exports;
pub use headers::{CoffHeader, DataDirectory, OptionalHeader};
pub use imports::{Import, Imports};
pub use pe::{Overlay, PeFile};
pub use read::Reader;
pub use resources::{Resource, Resources};
pub use rich::RichSignature;
pub use sections::Section;
pub use version::VersionInfo;
