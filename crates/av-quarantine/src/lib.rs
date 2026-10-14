//! The quarantine vault.
//!
//! When the engine decides a file is malicious the file has to go somewhere.
//! Deleting it outright is the wrong answer twice over: a false positive would
//! destroy something the user needs, and a true positive would destroy the only
//! evidence of the infection. So the bytes are taken into an encrypted store
//! that the user can open, list, restore from, and empty, and the original is
//! removed from where it was, which is the part that actually stops the
//! malware.
//!
//! # Two operations and one invariant
//!
//! Quarantining moves a file into the vault; restoring moves it back out.
//! Everything else (retention, eviction, the pending-deletion retry) is
//! maintenance around those two, and both are governed by one rule: **a file is
//! never deleted before its bytes are sealed and on disk**. [`vault`] spells out
//! the order the steps happen in and which state each intermediate crash leaves.
//!
//! # What is on disk
//!
//! ```text
//! <data>/quarantine/
//!     master.key      32 random bytes, wrapped by DPAPI so they are this
//!                     machine's alone
//!     index.enc       every entry, sealed with AES-256-GCM
//!     items/
//!         <id>.qtn    one sealed payload per entry, named after the entry's
//!                     random 128-bit identifier
//! ```
//!
//! The index is sealed even when the policy says payloads need not be, because
//! it is what a restore reads a destination path out of and it is small enough
//! that protecting it costs nothing.
//!
//! # Why the payloads are bound to their identifiers
//!
//! Each payload is sealed with its own identifier as associated data, so the
//! ciphertext is cryptographically tied to the name it is stored under. Someone
//! with write access to the vault directory cannot rename `a.qtn` to `b.qtn`
//! and have it open as `b`, cannot swap one quarantine for another, and cannot
//! edit an index entry to point a restore at a different path: the index is
//! sealed too. What that buys is the guarantee that a restore writes back the
//! bytes that were taken, which is the property a user relies on when they
//! click restore on a file they believe is innocent.
//!
//! # What is not defended
//!
//! A local administrator can call the same DPAPI unwrap this crate calls, and
//! so can anything that has got that far. [`key`] states this plainly rather
//! than implying more. The vault is a containment and recovery mechanism, not a
//! safe against an attacker who already owns the machine.
//!
//! # Example
//!
//! ```no_run
//! use av_quarantine::{EntrySource, QuarantineContext, QuarantinePolicy, QuarantineVault};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut vault = QuarantineVault::open(r"C:\ProgramData\WenleAV\quarantine", QuarantinePolicy::default())?;
//! vault.subscribe(av_quarantine::logging_listener());
//!
//! let context = QuarantineContext {
//!     source: EntrySource::Realtime,
//!     detection: Some("SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1".into()),
//!     ..QuarantineContext::default()
//! };
//! let entry = vault.quarantine_file(Path::new(r"C:\Users\me\Downloads\invoice.exe"), &context)?;
//! println!("took {} as {}", entry.file_name, entry.id);
//!
//! // And back again, if the user says it was a false positive.
//! vault.restore(entry.id, &av_quarantine::RestoreOptions::to_original())?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod attributes;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod events;
pub mod fsutil;
pub mod hardening;
pub mod id;
pub mod index;
pub mod key;
pub mod policy;
pub mod random;
pub mod vault;

pub use entry::{EntrySource, EntryStatus, QuarantineContext, QuarantineEntry};
pub use error::{QuarantineError, Result};
pub use events::{QuarantineEvent, QuarantineListener};
pub use hardening::Hardening;
pub use id::QuarantineId;
pub use index::PendingRemoval;
pub use policy::QuarantinePolicy;
pub use vault::{
    logging_listener, Eviction, MaintenanceOutcome, QuarantineVault, Reconciliation, RemovalSweep,
    RestoreOptions, VaultStats,
};
