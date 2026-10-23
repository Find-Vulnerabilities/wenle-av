//! Reading files a scanner would otherwise be refused.
//!
//! # The problem, in one paragraph
//!
//! A file scan is only as good as the bytes it reads, and on Windows a file's
//! DACL decides who may read it. A scanner run by one account therefore cannot
//! read another account's files, cannot read the directories `C:\System Volume
//! Information` and `C:\ProgramData\Microsoft\Windows Defender` at all, and
//! cannot read anything under a profile it is not, which is where an attacker
//! who has already gained a foothold leaves things. The result, for a scanner
//! that does not solve this, is a scan of `C:\` that reports clean while the
//! payload sits in a directory it was never allowed to open. That failure is
//! invisible: nothing in the report distinguishes "I looked and found nothing"
//! from "I could not look".
//!
//! There are two halves to it and this crate carries both. The first is reading
//! a file once its path is known ([`mod@read`]); the second is *obtaining* the path
//! at all, because the same DACL that stops a read also stops the directory
//! listing that would have produced it ([`walk`]). Solving only the first leaves
//! the scanner unable to see the files it has learned to read.
//!
//! Windows has a documented answer. `SeBackupPrivilege`, which administrators
//! and `LocalSystem` hold, lets a process open any file for reading regardless
//! of its DACL when the open also carries `FILE_FLAG_BACKUP_SEMANTICS`. It is
//! the same mechanism every backup product on the platform uses. This crate
//! obtains it, reads through it, and says what happened when it does not work.
//! That last part matters most.
//!
//! # What is in here
//!
//! | Module | What it is |
//! |---|---|
//! | [`privilege`] | Asking the process token whether it holds `SeBackupPrivilege` / `SeRestorePrivilege`, and turning them on. |
//! | [`mod@read`] | Opening a file once and reading it whole, with the long-path, backup-semantics and retry decisions in one place. |
//! | [`walk`] | Listing a directory whose DACL denies listing, and descending a tree without falling into a junction loop. |
//! | [`refusal`] | Why a read did not happen, as a type rather than as `Access is denied. (os error 5)`. |
//!
//! # The claim this crate makes, and the four it does not
//!
//! **It claims:** a process that holds `SeBackupPrivilege` and uses this crate
//! can read any file on a local volume that is not held open by another process
//! without sharing, whatever the file's permissions say. On this machine, as an
//! elevated administrator, that is every file that a scan has any reason to
//! look at.
//!
//! **It does not claim** any of the following, and each is a real limit of the
//! platform rather than a gap in this code:
//!
//! 1. **An unelevated process gains nothing.** The privilege is not in a
//!    standard user's token and cannot be added to it. [`privilege::enable`]
//!    reports [`privilege::Presence::Absent`] and the caller is expected to say
//!    so: see [`privilege::Privileges::sentence`], which is the sentence a
//!    user should be shown.
//! 2. **A file held open without sharing cannot be read.** The backup privilege
//!    bypasses access *checks*, not sharing. The reader retries a locked file
//!    briefly; a file locked for the lifetime of a process is out of reach
//!    without reading raw clusters and parsing the filesystem.
//! 3. **Encrypted and remote files are not covered.** An EFS-encrypted file
//!    needs its key; a file on a network share is subject to the server's
//!    answer; a cloud placeholder would have to be recalled, which is a network
//!    operation and a decision that is not a scanner's to make.
//! 4. **A file with no name in any directory is not found.** [`walk`] lists
//!    directories, so it finds what the filesystem's directory index can
//!    produce, which is every file a user or a program can open by name. A file
//!    whose last name has been removed while a handle to it stays open has no
//!    entry in any index, and the answer to it is a different one: reading the
//!    raw `$MFT` and comparing it against the index, which is a filesystem
//!    parser rather than a walk, and which is not here.
//!
//!    The adjacent failure, a directory this account may not list, is not a
//!    limit but a case the crate handles: [`walk::read_dir`] and
//!    [`Reader::descend`] use the same privilege the read path does, and
//!    they report a refusal as a value naming the directory instead of letting
//!    it disappear from the report. A walk that silently omits what it could not
//!    open is the failure mode this crate exists to prevent.
//!
//! # Where the boundary sits
//!
//! Nothing here decides anything about a file. This crate moves bytes and
//! reports access, and it is deliberately ignorant of what the bytes mean: the
//! verdict, the thresholds and the trust layer all belong to `av-scan`, and a
//! read that went through the backup privilege must produce exactly the same
//! verdict as a read that did not. That is why [`read::read`] returns
//! `io::Result<Vec<u8>>` rather than anything richer: a caller cannot tell,
//! and must not be able to tell, which route the bytes arrived by.
//!
//! The one exception is a caller that wants the reason: [`read::try_read`]
//! returns [`refusal::Refused`], whose [`refusal::Why`] distinguishes a file
//! that is not there from one this account may not read from one another
//! process is holding. A scan report that lists what it could not read is worth
//! far more when those three are three different lines.

// Lint policy comes from the workspace manifest; tests opt out of the
// panic-family lints, where unwrapping is how an assertion is written.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]

pub mod budget;
pub mod privilege;
pub mod read;
pub mod refusal;
pub mod walk;

pub use budget::{Budget, Reservation};
pub use privilege::{Privilege, Privileges, Presence};
pub use read::{
    default_reader, is_representable, read, read_capped, read_head, represented_path, try_read,
    Head, Held, Reader,
};
pub use refusal::{Refused, Why};
pub use walk::{
    descend, descend_reporting, read_dir, try_read_dir, DescendOptions, DescendOutcome, Entry,
    Found,
};
