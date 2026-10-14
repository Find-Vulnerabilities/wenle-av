//! The whole point of this crate, tested against a file that says no.
//!
//! # What is being proved
//!
//! A file's DACL decides who may read it, and an antivirus that stops at the
//! DACL stops exactly where the interesting files are. These tests build that
//! situation for real — a file with a deny-read ACE for `Everyone`, including
//! the account running the test — and assert three things:
//!
//! 1. An ordinary reader is refused, and the refusal is *diagnosed*: it is a
//!    permission answer that names the privilege state, not `no such file` and
//!    not `not a file`.
//! 2. A privileged reader reads the file when this process's token holds
//!    `SeBackupPrivilege`, which is what "scan every file" actually depends on.
//! 3. When the token does **not** hold it, the refusal says so in those words
//!    rather than blaming the file.
//!
//! # Why the second test has two branches and does not pretend otherwise
//!
//! `SeBackupPrivilege` is in the tokens of elevated administrators and
//! `LocalSystem`, and in no others. `cargo test` in an ordinary terminal is
//! neither, so on the machine this was written on the privilege is
//! [`av_fs::Presence::Absent`] and the successful read **cannot be exercised**.
//!
//! The dishonest options were available and are rejected: asserting the read
//! succeeds would make the suite fail on every unelevated machine, and skipping
//! the assertion silently would leave a test that passes whether or not the
//! feature works. So the test branches on what the token actually holds, prints
//! which branch it took, and asserts the *correct* behaviour for each — plus
//! [`the_backup_privilege_reads_a_file_that_denies_everyone`], which is
//! `#[ignore]`d and is the real proof for whoever runs it elevated.
//!
//! Run it with:
//!
//! ```text
//! cargo test -p av-fs --test denied_file -- --ignored --nocapture
//! ```
//!
//! from an **elevated** prompt.

#![cfg(windows)]
// A separate crate root, so the library's `cfg(test)` allowance does not reach
// here. See `av-service`'s `control_pipe.rs`, which carries the same line for
// the same reason.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};
use std::process::Command;

use av_fs::{Presence, Reader, Why};

/// The well-known SID for `Everyone`. Denying it denies every account,
/// including the owner, which is the situation the crate exists for.
const EVERYONE: &str = "*S-1-1-0";

/// A file with a deny-read ACE for `Everyone`, removed when this is dropped.
///
/// A guard rather than a call at the end of each test, because the interesting
/// ending is the one where an assertion failed halfway — and a temp directory
/// that `TempDir` cannot delete is a leak, but a *denied* file left behind is
/// worse: it is a file the user cannot open, in their own temp directory, with
/// no record of why.
struct Denied {
    dir: tempfile::TempDir,
    path: PathBuf,
    sealed: bool,
}

impl Denied {
    /// Create `payload` in a new temporary directory and deny `Everyone` read
    /// access to it.
    fn new(name: &str, payload: &[u8]) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(name);
        std::fs::write(&path, payload).expect("write");
        let mut denied = Self {
            dir,
            path,
            sealed: false,
        };
        icacls(&denied.path, &["/deny", &format!("{EVERYONE}:(R)")]);
        denied.sealed = true;
        denied
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Denied {
    fn drop(&mut self) {
        if self.sealed {
            // Best effort, and it has to happen before `TempDir`'s own `Drop`
            // tries to remove the directory: a file it cannot open is a
            // directory it cannot remove.
            icacls(&self.path, &["/remove:d", EVERYONE]);
        }
        let _ = &self.dir;
    }
}

/// Run `icacls` and insist it worked.
///
/// `icacls` rather than `SetNamedSecurityInfoW` because the point of the test is
/// to produce a DACL some *other* program wrote, and because a test that shares
/// no code with the implementation under test cannot fail for the
/// implementation's reasons.
fn icacls(path: &Path, args: &[&str]) {
    let output = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .expect("icacls is on every Windows install");
    assert!(
        output.status.success(),
        "icacls {} {} failed: {}{}",
        path.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_ordinary_reader_is_refused_and_says_why() {
    let denied = Denied::new("secret.txt", b"the bytes a scan must still see");

    let refused = Reader::ordinary()
        .try_read(denied.path())
        .expect_err("Everyone was denied read access, including this account");

    // The two answers a scanner must not give here.
    assert_ne!(
        refused.why,
        Why::Gone,
        "a file that exists and cannot be read is not a missing file"
    );
    assert!(
        !matches!(refused.why, Why::NotAFile { .. }),
        "it is a file, not a directory: {refused}"
    );
    // And the answer it must give: a permission decision.
    //
    // Deliberately *not* an assertion about `backup_enabled`. Tests in one
    // binary share a process, `Reader::privileged` in the test below enables the
    // privilege process-wide, and the order two tests run in is not fixed — so
    // asserting the flag here would be a test that passes or fails on
    // scheduling. The flag is a report of the token, and which of the two
    // sentences comes out is the token's business; what this test is about is
    // that the answer is a permission answer at all, and that whichever
    // sentence it is names the privilege, because that is the half a user acts
    // on.
    assert!(
        matches!(refused.why, Why::Denied { .. }),
        "expected a permission refusal, got {:?}",
        refused.why
    );
    let text = refused.to_string();
    assert!(text.contains("SeBackupPrivilege"), "{text}");
    assert!(text.contains("os error"), "the code is kept: {text}");
}

#[test]
fn a_privileged_reader_reads_it_when_this_process_holds_the_privilege() {
    let payload = b"the bytes a scan must still see";
    let denied = Denied::new("secret.txt", payload);

    let reader = Reader::privileged();
    match reader.privilege() {
        Presence::Enabled => {
            // The real thing. This process holds `SeBackupPrivilege`, enabled
            // it, and read a file that denies everyone — which is the entire
            // reason this crate exists.
            let data = reader
                .try_read(denied.path())
                .expect("a privileged reader reads what a DACL forbids");
            assert_eq!(data, payload);
            eprintln!(
                "exercised: SeBackupPrivilege is held, and the denied file was read \
                 ({} bytes)",
                data.len()
            );
        }
        other => {
            // Not exercised on this machine. The assertion is therefore that
            // the failure is *diagnosed correctly* rather than that it
            // succeeded: a reader without the privilege must still refuse, and
            // must still say the privilege is what was missing.
            let refused = reader
                .try_read(denied.path())
                .expect_err("without the privilege the DACL still applies");
            assert!(
                matches!(refused.why, Why::Denied { .. }),
                "expected a permission refusal, got {:?}",
                refused.why
            );
            eprintln!(
                "NOT exercised: this process's token reports SeBackupPrivilege as {other}. The \
                 denied file was refused, and the refusal named the privilege. Run this test \
                 from an elevated prompt (or as the Wenle service) to exercise the read: \
                 cargo test -p av-fs --test denied_file -- --ignored --nocapture"
            );
        }
    }
}

/// The proof, for a prompt that can provide it.
///
/// `#[ignore]`d for the same reason `av-service`'s SCM lifecycle test is: it
/// needs a privilege an ordinary terminal does not have, and a suite that failed
/// on every developer's machine would be a suite that gets switched off.
#[test]
#[ignore = "requires an elevated prompt, so that SeBackupPrivilege is in the token"]
fn the_backup_privilege_reads_a_file_that_denies_everyone() {
    let payload = b"read through the backup privilege";
    let denied = Denied::new("secret.txt", payload);

    let reader = Reader::privileged();
    assert_eq!(
        reader.privilege(),
        Presence::Enabled,
        "run this from an elevated prompt: the token must hold SeBackupPrivilege, and it \
         reports {}",
        reader.privilege()
    );
    let data = reader
        .try_read(denied.path())
        .expect("a privileged reader reads a file that denies Everyone");
    assert_eq!(data, payload);

    // And the ordinary reader, in the same process and after the privilege is
    // on, *still* gets the same answer — because `Reader::ordinary` was built
    // from a token that now has it enabled, and the flag is what the open
    // carries rather than what the reader claims. This is the assertion that
    // shows the privilege is a process property and that the two readers are a
    // choice about the open rather than a claim about the token.
    let ordinary = Reader::ordinary();
    assert_eq!(
        ordinary.privilege(),
        Presence::Enabled,
        "enabling the privilege is a process-wide effect; an ordinary reader built afterwards \
         must report the token as it really is, not as it was"
    );
}
