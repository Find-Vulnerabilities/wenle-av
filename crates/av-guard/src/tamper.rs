//! Noticing when the product's own files have been changed.
//!
//! # The threat this answers, and the one it does not
//!
//! [`crate::files`] stops an ordinary user writing to the product's directories,
//! and [`crate::process`] stops one taking the running process out. Both of those
//! are *prevention*, and both are enforced by the kernel against a DACL. This
//! module is the other half: what is true when prevention has already failed, or
//! was never applicable.
//!
//! Three cases where a DACL is not enough:
//!
//! * **An administrator replaced the binary.** Administrators have full control
//!   of the install directory by design (see `crate::files`), because they are
//!   the ones who install, upgrade and uninstall the product. A tamper check
//!   cannot stop that and does not try; it turns "somebody replaced the service
//!   binary" from an invisible fact into a reported one.
//! * **The permissions were undone.** A DACL lives on the object, and there are
//!   two ordinary ways it goes away: the object is deleted and recreated (the
//!   new one inherits its parent's permissions, not ours), and an installer or a
//!   restore puts back an older copy of the tree. Neither is an attack and both
//!   leave the product unprotected. Nothing *watches* for that here (the check
//!   is run on demand, by [`self_check`] and by `wenle protect verify`), and
//!   `crate::files::audit` is what answers the permission half of the question.
//! * **Something wrote and put it back.** A same-size edit of a binary (a
//!   patched jump, a replaced string) leaves the size and the timestamps
//!   looking right. Only a digest catches it, which is what this module is.
//!
//! # What a manifest is, and what it is not
//!
//! A [`Manifest`] is a list of the product's own files with their SHA-256 and
//! their size, taken at a moment the product chose, and stored where the product
//! can read it back. It is **a tripwire, not a signature**.
//!
//! That distinction decides what this module can claim. An attacker who can
//! write a binary *and* the manifest passes the check completely, because the
//! manifest is a file like any other and this crate does not sign it: there is
//! no key in this process that an attacker on the same machine could not also
//! read, and inventing one would be a false claim of a guarantee this code
//! cannot make. What the check does instead is make the *cheap* attacks loud:
//! replacing a binary, deleting a database, appending to a rule file, dropping a
//! new executable into the install directory. Those all need only write access,
//! and all of them are reported.
//!
//! The manifest is stored under the data directory rather than inside the
//! install directory, because the install directory is the one an attacker most
//! wants to write and the data directory is the one this crate hardens with
//! [`crate::files::DirRole::Data`]. That is defence in depth and not a boundary,
//! and it is written down so that nobody later reads the placement as a
//! guarantee.
//!
//! # Measured rather than assumed
//!
//! * **`av-authenticode` does not create a dependency cycle.** Verified by
//!   reading its manifest: it depends on `av-pe` and `av-signatures`, and on
//!   nothing else in this workspace. `av-guard` sits above it and below
//!   `av-service`, so the direction is `av-service` → `av-guard` →
//!   `av-authenticode`.
//! * **A locally built executable is [`av_authenticode::Verdict::Unsigned`], not
//!   [`av_authenticode::Verdict::Undetermined`].** Every file in this repository is unsigned, so
//!   an unsigned binary is the state a developer's machine is in all day, and it
//!   is the state the tests run against: see
//!   `an_unsigned_binary_is_recorded_as_unsigned_rather_than_unreadable`, which
//!   uses the test binary itself rather than a fixture.
//! * **A file that is not a PE is [`av_authenticode::Verdict::Undetermined`], with the reason
//!   `not_pe`.** A rule database is not a program and must not be reported as an
//!   unsigned one; [`Role::is_program`] is what stops the question being asked
//!   at all, and the reason is recorded rather than rounded to a word that would
//!   read as a finding.
//!
//! # The debugger check, and its honest limit
//!
//! [`debugger_present`] asks three independent questions (`IsDebuggerPresent`,
//! `CheckRemoteDebuggerPresent(GetCurrentProcess())`, and the `BeingDebugged`
//! byte in this process's own PEB, reached through
//! `NtQueryInformationProcess(ProcessBasicInformation)`) and ORs them.
//!
//! **All three are trivially defeatable and this must not be used as a security
//! decision.** The reason is structural rather than an implementation gap: all
//! three read state that lives *inside the process being asked*, so a program
//! that wants to hide clears `PEB.BeingDebugged` (one byte), hooks
//! `IsDebuggerPresent` (one import), or answers `NtQueryInformationProcess`
//! itself. An adversary who is already running code in this process has already
//! won, and no question this process asks about itself can change that.
//!
//! What it is for is the case in between: a person with a debugger attached, a
//! colleague with `x64dbg` open on the wrong window, an automated analysis
//! sandbox that is not trying very hard. It is a tripwire against casual
//! inspection: it catches the casual case and not the real one, and that is all
//! it can claim.
//!
//! Which also means: **never let it change behaviour.** A product that disables
//! real-time protection when a debugger is present has handed every attacker a
//! one-instruction switch that turns it off, and the switch is easier to use than
//! the DACL work in the rest of this crate is to defeat. The report goes into a
//! log and into a `status` command; nothing branches on it.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use av_core::paths::AvPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::service::{self, ServiceIntegrity};

/// The manifest format's version.
///
/// Stored in the file and checked on load. A manifest is written by one build of
/// the product and read by another — that is the point of a file that survives
/// an upgrade — and bincode will happily decode a struct that has lost or gained
/// a field into something plausible if the two versions disagree. Refusing a
/// version this build does not know turns that into a sentence instead of a
/// report full of nonsense.
///
/// # Why this is 3
///
/// [`Role::Driver`] was added after version 2 existed, and the argument is the
/// one that made this 2 rather than a new one. A version 2 manifest names no
/// file for the driver, so a check that read one would find the driver in the
/// install directory with no entry claiming it and report it as an unexpected
/// file. Of every file this product ships, that is the worst one to raise a
/// false alarm about: the driver is the only one Windows refuses to load unless
/// it is signed, so "there is a file here nobody recorded" reads as somebody
/// having replaced it, and the report would be produced by an upgrade.
///
/// # Why 2 was 2
///
/// [`Role::Amsi`] was added after version 1 existed. A version 1 manifest names
/// no file for the provider, so a check that read one would find `av_amsi.dll`
/// in the install directory with no entry claiming it and report it as an
/// unexpected file — a tamper alarm on the one binary Windows loads into every
/// scripting host, raised by an upgrade rather than by an attack. Refusing the
/// version is what turns that into a sentence naming the command that writes a
/// new manifest.
pub const MANIFEST_VERSION: u32 = 3;

/// The manifest's file name, under the data directory.
pub const MANIFEST_FILE: &str = "integrity.manifest";

/// How many unexpected files are listed per directory before the scan stops.
///
/// A directory that has been filled with junk — an attacker's, or a
/// misconfigured installer's — would otherwise produce a report with thousands
/// of lines in it, which is a report nobody reads and a report that hides the
/// one entry that matters. The count that was dropped is reported as a sentence
/// so that the truncation is visible rather than silent.
pub const MAX_ADDED_PER_DIRECTORY: usize = 64;

/// Where the manifest lives for a given layout.
pub fn manifest_path(paths: &AvPaths) -> PathBuf {
    paths.data_dir.join(MANIFEST_FILE)
}

/// Which of the product's files an entry describes.
///
/// A closed set with a name per variant, because the report has to say *what*
/// was changed and not only which path — "the service binary changed" is
/// actionable and `/Program Files/WenleAV/x.exe changed` is a puzzle.
///
/// # The declaration order is the wire order
///
/// bincode writes a variant as its index, so the order these are declared in is
/// the order a manifest on disk encodes them in. A variant *appended* is a new
/// index that leaves every earlier one alone, which is why new roles go at the
/// end; a variant *inserted* would renumber everything after it and turn a
/// manifest full of service-binary entries into a report about the AMSI
/// provider. Nothing here is ever reordered, and a change to the set at all
/// moves [`MANIFEST_VERSION`] with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    /// The Windows service's image: the process that runs as `LocalSystem`.
    Service,
    /// The command-line tool.
    Cli,
    /// The desktop application.
    Gui,
    /// The compiled rule database: the rules the scanner matches with.
    Database,
    /// The AMSI provider: the DLL Windows loads into every scripting host.
    ///
    /// The last variant rather than the first because the index is the wire
    /// format — see the type's own note. It is a [`Role::is_program`] like the
    /// three executables and not a data file like the database, and it is the
    /// one file here whose absence is silent: nothing in this product runs
    /// differently when the provider is missing, and the scripts that were
    /// supposed to be examined simply are not. That is what the entry is for.
    Amsi,
    /// The kernel driver: the minifilter that refuses an execution until the
    /// service has answered for the file.
    ///
    /// Appended for the same reason [`Role::Amsi`] was, and it is a
    /// [`Role::is_program`] for a stronger reason than any of the executables.
    /// Windows will not load a kernel-mode image that is not signed — this is
    /// the one file here whose signature is the difference between a working
    /// product and a driver the loader rejects — so a replaced driver is both
    /// the most valuable thing to swap and the thing a signature check is worth
    /// the most on.
    ///
    /// # The file it names is not the file cargo writes
    ///
    /// This crate's driver is a `cdylib`, because `wdk-build` emits its
    /// `/SUBSYSTEM:NATIVE` and `/ENTRY:FxDriverEntry` arguments as
    /// `rustc-cdylib-link-arg`, so cargo names the artifact `av_driver.dll`
    /// whatever the linker was told it is. What a machine ends up with is a
    /// `.sys` — the extension is the loader's convention, not the compiler's —
    /// so packaging renames it, and [`Role::paths_in`] names the renamed file
    /// because that is the one that exists on an installed machine.
    ///
    /// A build tree holds neither name: the driver is a cargo workspace of its
    /// own, under `crates/av-driver`, because it needs the WDK and a nightly
    /// toolchain that an ordinary build must not require, so its artifact is
    /// under a second `target` directory rather than beside `wenle.exe`. That
    /// is the state this role reports as a missing file, and it is why
    /// `wenle protect manifest` refuses to run from a build tree at all — a
    /// baseline taken there would name this file, and every other one, at paths
    /// an installation does not have.
    Driver,
}

impl Role {
    /// Every role, in the order a report lists them.
    ///
    /// The same order the variants are declared in, which is not required but is
    /// worth keeping: a reader who has the report and the source open should not
    /// have to discover that the two disagree.
    pub const ALL: [Role; 6] = [
        Role::Service,
        Role::Cli,
        Role::Gui,
        Role::Database,
        Role::Amsi,
        Role::Driver,
    ];

    /// One phrase for a report.
    pub const fn describe(self) -> &'static str {
        match self {
            Role::Service => "the service binary",
            Role::Cli => "the command-line tool",
            Role::Gui => "the desktop application",
            Role::Database => "the compiled rule database",
            Role::Amsi => "the AMSI provider",
            Role::Driver => "the kernel driver",
        }
    }

    /// Whether the file is a program, and therefore whether it is worth asking
    /// whether it is signed.
    ///
    /// Asked rather than inferred from the `av-authenticode` answer, because the
    /// answer for a database would be "this is not a PE file" — true, useless,
    /// and phrased in a way that reads as a finding. Reading a rule database to
    /// be told it is not a program is also hundreds of megabytes of I/O for
    /// nothing.
    pub const fn is_program(self) -> bool {
        match self {
            Role::Service | Role::Cli | Role::Gui | Role::Amsi | Role::Driver => true,
            Role::Database => false,
        }
    }

    /// Where this role's file lives, in the order the product looks for it.
    ///
    /// `Database` has two paths because the loader has always had a two-place
    /// lookup — `db_dir` first, then `install_dir` — and recording only one of
    /// them would mean a machine that had the database in the other place
    /// reported a missing file on every check. The names themselves are
    /// duplicated from `av-cli`, `av-gui` and `av-service`, which each define
    /// their own `DATABASE_FILE`; a rename that missed one of them shows up here
    /// as a `Missing` entry beside an `Added` one, which is a *visible* failure
    /// and the reason this duplication is tolerable where a silent one would not
    /// be. The AMSI provider's name is written out here for that same reason and
    /// with one more behind it: `av-amsi` is `#![cfg(windows)]` and its
    /// `DLL_NAME` does not exist anywhere else, so a reference to it could not
    /// be compiled for the platforms this crate is still built for.
    pub fn paths_in(self, paths: &AvPaths) -> Vec<PathBuf> {
        match self {
            Role::Service => vec![paths.install_dir.join("wenle-av-service.exe")],
            Role::Cli => vec![paths.install_dir.join("wenle.exe")],
            Role::Gui => vec![paths.install_dir.join("wenle-gui.exe")],
            Role::Database => vec![
                paths.db_dir.join("rules.avdb"),
                paths.install_dir.join("rules.avdb"),
            ],
            Role::Amsi => vec![paths.install_dir.join("av_amsi.dll")],
            // The installer's own name for the file, not a copy of it. This is
            // the one role whose name is not written out here, and the reason is
            // that two other places need it and can both name the constant:
            // `av-driver-proto` defines it and the installer reads it from
            // there, so this entry cannot drift from the file that gets
            // installed. The others are literals because the crates that build
            // them are the ones that own their names — see this function's note.
            Role::Driver => vec![paths.install_dir.join(av_driver_proto::DRIVER_FILE_NAME)],
        }
    }
}

/// What was found out about a file's Authenticode signature.
///
/// The variants are [`av_authenticode::Verdict`]'s, renamed where a rename makes
/// the report clearer, and kept apart because they mean different things: a file
/// that is [`Signature::Unsigned`] is a *finding* (every program this product
/// ships should be signed), while a file that is
/// [`Signature::NotAProgram`] is a database, and a file that is
/// [`Signature::Undetermined`] is one where the question could not be answered
/// at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    /// A signature verified and the chain reached a root this machine trusts.
    Trusted {
        /// The signer's subject.
        subject: String,
        /// The signer's SHA-1 thumbprint, lower-case hex.
        thumbprint: String,
    },
    /// A signature verified and the chain did not reach a trusted root.
    ///
    /// Reported as signed, and separately, because "signed by an account this
    /// machine cannot chain to a root" is normal for an in-house build and is
    /// exactly what an attacker with a self-signed certificate produces. The
    /// report says which; a caller that needs to tell those apart has the
    /// distinction to do it with.
    Untrusted {
        /// The signer's subject.
        subject: String,
        /// The signer's SHA-1 thumbprint, lower-case hex.
        thumbprint: String,
    },
    /// A signature is present and a comparison failed.
    ///
    /// The strong finding: the file was altered after signing, or the signature
    /// block was.
    Invalid {
        /// The label of the comparison that failed, from
        /// [`av_authenticode`]'s own code.
        reason: String,
    },
    /// The file carries no signature at all.
    Unsigned,
    /// The file is not a program, so it was not checked.
    ///
    /// See [`Role::is_program`].
    NotAProgram,
    /// The file could not be assessed.
    Undetermined {
        /// The label of what could not be established.
        reason: String,
    },
}

impl Signature {
    /// The signer, when there is one whose signature verified.
    ///
    /// `None` for every other state, including [`Signature::Undetermined`]: a
    /// comparison that treated "could not read the signature" as "no signer"
    /// would report a tampered file as unsigned rather than as unreadable, which
    /// is the one answer that must never be guessed at.
    pub fn signer(&self) -> Option<&str> {
        match self {
            Signature::Trusted { thumbprint, .. } | Signature::Untrusted { thumbprint, .. } => {
                Some(thumbprint)
            }
            _ => None,
        }
    }

    /// One phrase for a report.
    pub fn describe(&self) -> String {
        match self {
            Signature::Trusted {
                subject,
                thumbprint,
            } => format!("signed by {subject} ({thumbprint}), and the chain is trusted"),
            Signature::Untrusted {
                subject,
                thumbprint,
            } => format!(
                "signed by {subject} ({thumbprint}), and the chain does NOT reach a root this \
                 machine trusts"
            ),
            Signature::Invalid { reason } => format!("its signature is present and no longer \
                verifies ({reason}) — the file was altered after it was signed"),
            Signature::Unsigned => "unsigned".to_string(),
            Signature::NotAProgram => "not a program, so it has no signature to check".to_string(),
            Signature::Undetermined { reason } => {
                format!("its signature could not be assessed ({reason})")
            }
        }
    }
}

/// How a file's signature state differs from the one the manifest recorded.
///
/// The answer the brief asks for, and the reason it matters: a binary whose
/// digest changed and whose signature is *unchanged* is a rebuild by the same
/// publisher, while one that has become unsigned was replaced by something that
/// someone could not sign. Those two want different responses and the digest
/// alone cannot tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureChange {
    /// The signer is the same as the one recorded, or neither state is a finding.
    Unchanged,
    /// It was signed and is not any more.
    NowUnsigned,
    /// It is signed, by a different account.
    DifferentlySigned {
        /// The thumbprint the manifest recorded.
        from: String,
        /// The thumbprint the file has now.
        to: String,
    },
    /// It was not signed and now is.
    ///
    /// A change for the better, and reported rather than passed over, because it
    /// is a change and because on a service binary it is exactly what an
    /// attacker with a certificate would produce.
    NewlySigned {
        /// The thumbprint the file has now.
        to: String,
    },
    /// Its signature is present and no longer verifies.
    NowInvalid,
    /// One of the two states could not be read, so the comparison says nothing.
    ///
    /// Distinct from [`SignatureChange::Unchanged`] on purpose. Reporting
    /// "unchanged" for a file whose signature could not be read is the failure
    /// mode this whole module exists to avoid: a confident answer that is not
    /// known to be true.
    Unknown {
        /// The state the manifest recorded, in a phrase.
        before: String,
        /// The state the file is in now, in a phrase.
        after: String,
    },
}

impl SignatureChange {
    /// Compare a manifest entry's signature against the file's current one.
    pub fn between(before: &Signature, after: &Signature) -> Self {
        // Either side being unreadable makes the comparison meaningless, and it
        // is checked first so that no later arm can accidentally treat an
        // unknown state as a known one.
        if matches!(before, Signature::Undetermined { .. })
            || matches!(after, Signature::Undetermined { .. })
        {
            return SignatureChange::Unknown {
                before: before.describe(),
                after: after.describe(),
            };
        }
        // The *before* state is checked before the after state, and the order is
        // load-bearing rather than stylistic: a file that was already invalid
        // when the manifest was taken and is still invalid has not *become*
        // anything, and a report that called that "now invalid" would fire a
        // fresh alarm on every check for a state that was recorded as fact.
        if matches!(before, Signature::Invalid { .. }) {
            return SignatureChange::Unchanged;
        }
        if matches!(after, Signature::Invalid { .. }) {
            return SignatureChange::NowInvalid;
        }
        match (before.signer(), after.signer()) {
            (Some(from), Some(to)) if from == to => SignatureChange::Unchanged,
            (Some(from), Some(to)) => SignatureChange::DifferentlySigned {
                from: from.to_string(),
                to: to.to_string(),
            },
            (Some(_), None) if matches!(after, Signature::Unsigned) => {
                SignatureChange::NowUnsigned
            }
            (None, Some(to)) if matches!(before, Signature::Unsigned) => {
                SignatureChange::NewlySigned {
                    to: to.to_string(),
                }
            }
            _ => SignatureChange::Unchanged,
        }
    }

    /// One phrase for a report.
    pub fn describe(&self) -> String {
        match self {
            SignatureChange::Unchanged => "its signature is unchanged".to_string(),
            SignatureChange::NowUnsigned => {
                "it was signed and is NOT any more".to_string()
            }
            SignatureChange::DifferentlySigned { from, to } => {
                format!("it is now signed by a different account: was {from}, now {to}")
            }
            SignatureChange::NewlySigned { to } => {
                format!("it was unsigned and is now signed by {to}")
            }
            SignatureChange::NowInvalid => {
                "its signature is present and no longer verifies".to_string()
            }
            SignatureChange::Unknown { before, after } => format!(
                "its signature could not be compared: the manifest recorded \"{before}\" and the \
                 file is now \"{after}\""
            ),
        }
    }

    /// Whether this is the change the module documentation calls the loud one.
    pub fn is_alarming(&self) -> bool {
        !matches!(
            self,
            SignatureChange::Unchanged | SignatureChange::NewlySigned { .. }
        )
    }
}

/// One file the product expects to have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Which of the product's files this is.
    pub role: Role,
    /// Where it was expected. Absolute, and the same absolute path the check
    /// hashes back.
    pub path: PathBuf,
    /// Whether the file was there when the manifest was taken.
    ///
    /// The field that makes [`Change::Missing`] possible at all. A manifest that
    /// simply left out a file it could not read could never report that the file
    /// had gone — which is one of the two or three things it most needs to say —
    /// and the difference between "this file was here and had this digest" and
    /// "this file was already missing" has to be recorded rather than inferred
    /// from a zero.
    pub present: bool,
    /// Its size in bytes, or zero when it was not there.
    pub size: u64,
    /// Its SHA-256, or all zeros when it was not there.
    pub sha256: [u8; 32],
    /// Its signature state.
    pub signature: Signature,
}

impl Entry {
    /// The digest as lower-case hex, the form a person compares against
    /// `certutil -hashfile`.
    pub fn digest(&self) -> String {
        hex(&self.sha256)
    }

    /// One line for a report.
    pub fn describe(&self) -> String {
        if self.present {
            format!(
                "{} at {} — {} bytes, sha256 {}, {}",
                self.role.describe(),
                self.path.display(),
                self.size,
                self.digest(),
                self.signature.describe()
            )
        } else {
            format!(
                "{} at {} — was already missing when the manifest was taken",
                self.role.describe(),
                self.path.display()
            )
        }
    }
}

/// A digest as lower-case hex.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    text
}

/// The two directories a manifest was taken against.
///
/// Recorded so that a manifest from a different installation is refused rather
/// than reported. Without this, pointing the check at the wrong manifest — a
/// stale one from a previous install path, or one copied from another machine —
/// produces a report saying every file is missing and every file is an
/// unexpected addition, which is both scary and wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    /// The install directory the manifest was taken against.
    pub install_dir: PathBuf,
    /// The data directory it was taken against.
    pub data_dir: PathBuf,
}

impl Roots {
    /// Whether these are the roots `paths` names.
    ///
    /// Compared as normalised paths, not as strings: `C:\Program Files\WenleAV`
    /// and `c:\program files\wenleav\` are the same directory and a report that
    /// called them different would be refusing a manifest that is perfectly
    /// good.
    pub fn matches(&self, paths: &AvPaths) -> bool {
        same_dir(&self.install_dir, &paths.install_dir) && same_dir(&self.data_dir, &paths.data_dir)
    }

    /// One sentence naming the difference.
    pub fn describe_mismatch(&self, paths: &AvPaths) -> String {
        let mut parts = Vec::new();
        if !same_dir(&self.install_dir, &paths.install_dir) {
            parts.push(format!(
                "it was taken for the install directory {} and this layout is {}",
                self.install_dir.display(),
                paths.install_dir.display()
            ));
        }
        if !same_dir(&self.data_dir, &paths.data_dir) {
            parts.push(format!(
                "it was taken for the data directory {} and this layout is {}",
                self.data_dir.display(),
                paths.data_dir.display()
            ));
        }
        parts.join(", and ")
    }
}

/// Whether two paths name the same directory.
///
/// Lexical, and deliberately so: this compares a path that was recorded against
/// a path that was computed, and resolving either through the filesystem would
/// mean a check that changed its answer depending on whether the directory
/// happened to exist. `.` and `..` are folded textually and the comparison is
/// case-insensitive because Windows is.
fn same_dir(left: &Path, right: &Path) -> bool {
    fn fold(path: &Path) -> String {
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other.as_os_str()),
            }
        }
        let text = out.to_string_lossy().replace('/', "\\");
        text.trim_end_matches('\\').to_lowercase()
    }
    fold(left) == fold(right)
}

/// The product's own files, as they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// [`MANIFEST_VERSION`], checked on load.
    pub version: u32,
    /// The directories it was taken against.
    pub roots: Roots,
    /// When it was taken, in Unix seconds. `0` when the clock was unreadable.
    pub captured_at: i64,
    /// One entry per expected file, whether or not the file was there.
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Hash every file the product expects.
    ///
    /// Files that are not there are recorded as [`Entry::present`] `false` rather
    /// than skipped — see that field.
    ///
    /// # Errors
    ///
    /// Fails when a file exists and cannot be read. That is deliberate: a
    /// manifest taken while a file was locked would record it as missing and
    /// then report it as an unexpected addition for the rest of the
    /// installation's life. A partial manifest is worse than no manifest,
    /// because the check that reads it cannot tell the difference.
    pub fn capture(paths: &AvPaths) -> Result<Manifest, String> {
        let mut entries = Vec::new();
        for role in Role::ALL {
            for path in role.paths_in(paths) {
                entries.push(entry_for(role, &path)?);
            }
        }
        Ok(Manifest {
            version: MANIFEST_VERSION,
            roots: Roots {
                install_dir: paths.install_dir.clone(),
                data_dir: paths.data_dir.clone(),
            },
            captured_at: now(),
            entries,
        })
    }

    /// Write it out.
    ///
    /// Written to a temporary file in the same directory and then renamed, so
    /// that a check running while a capture is in flight sees either the old
    /// manifest or the new one and never a half-written one. The rename is the
    /// only atomic step available without a transaction, and it is enough here
    /// because both names are in the same directory and therefore the same
    /// volume.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let encoded = bincode::serialize(self).map_err(|error| {
            format!(
                "the manifest could not be encoded for writing to {}: {error}",
                path.display()
            )
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "the directory {} for the manifest could not be created: {error}. The data \
                     directory is normally created by the installer; if this is a portable \
                     installation, create it by hand.",
                    parent.display()
                )
            })?;
        }
        let temporary = path.with_extension("manifest.new");
        std::fs::write(&temporary, &encoded).map_err(|error| {
            format!(
                "the manifest could not be written to {}: {error}. Writing there needs \
                 administrator rights — the data directory is restricted to SYSTEM and \
                 Administrators. Run this from an elevated prompt.",
                temporary.display()
            )
        })?;
        std::fs::rename(&temporary, path).map_err(|error| {
            format!(
                "the manifest was written to {} but could not be moved into place as {}: {error}",
                temporary.display(),
                path.display()
            )
        })
    }

    /// Read one back.
    ///
    /// # Errors
    ///
    /// Named separately for each of the three ways this fails, because they need
    /// different things done about them: the file is not there (take a manifest),
    /// the file is not a manifest (it was truncated, or written by a build that
    /// used a different format), or it is a version this build does not know.
    pub fn load(path: &Path) -> Result<Manifest, String> {
        let bytes = std::fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "there is no manifest at {}, so there is nothing to check the product's files \
                     against. Take one with `wenle protect manifest`, which needs administrator \
                     rights.",
                    path.display()
                )
            } else {
                format!(
                    "the manifest at {} could not be read: {error}. It lives in the data \
                     directory, which is restricted to SYSTEM and Administrators, so reading it \
                     normally needs no elevation — a refusal here means the file's permissions \
                     have been changed.",
                    path.display()
                )
            }
        })?;
        let manifest: Manifest = bincode::deserialize(&bytes).map_err(|error| {
            format!(
                "the file at {} is not a manifest this build can read: {error}. If it is empty or \
                 truncated it was written by an interrupted capture; take a new one with `wenle \
                 protect manifest`.",
                path.display()
            )
        })?;
        if manifest.version != MANIFEST_VERSION {
            return Err(format!(
                "the manifest at {} is version {} and this build writes and reads version {}. An \
                 older manifest cannot be interpreted by a newer build — take a new one with \
                 `wenle protect manifest`.",
                path.display(),
                manifest.version,
                MANIFEST_VERSION
            ));
        }
        Ok(manifest)
    }

    /// Whether this manifest was taken against the layout `paths` names.
    pub fn matches_roots(&self, paths: &AvPaths) -> bool {
        self.roots.matches(paths)
    }

    /// The entry for a path, if the manifest has one.
    ///
    /// Compared with `same_dir`'s folding, so that a path recorded with a
    /// different but equivalent spelling still matches.
    pub fn entry_for(&self, path: &Path) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| same_dir(&entry.path, path))
    }

    /// Whether the manifest named any file that was actually there.
    pub fn has_present_entries(&self) -> bool {
        self.entries.iter().any(|entry| entry.present)
    }

    /// One line for a report.
    pub fn describe(&self) -> String {
        let present = self.entries.iter().filter(|entry| entry.present).count();
        let when = if self.captured_at > 0 {
            format!("taken at Unix time {}", self.captured_at)
        } else {
            "taken at a time this process could not read from the clock".to_string()
        };
        format!(
            "a manifest of {} files, of which {present} were there when it was {when}; it names \
             the install directory {} and the data directory {}",
            self.entries.len(),
            self.roots.install_dir.display(),
            self.roots.data_dir.display()
        )
    }

    /// Hash every file again and report what is different.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be read for a reason other than not being there.
    /// A file that has been replaced by a directory, or whose permissions have
    /// been changed so that this account cannot open it, is a change — but it is
    /// a change this function cannot describe, and describing it as "missing" or
    /// as "unreadable" without saying which is how a report loses its
    /// credibility.
    ///
    /// # Cost
    ///
    /// This reads every file in the manifest and hashes it, and for the four
    /// programs it also runs an Authenticode verification. On a large
    /// installation that is tens of megabytes of I/O and a chain build per
    /// binary, which is why it is a command a person runs and not something that
    /// happens on a timer in this crate.
    pub fn verify(&self) -> Result<Vec<Change>, String> {
        let mut changes = Vec::new();
        let mut known: BTreeSet<String> = BTreeSet::new();
        for entry in &self.entries {
            known.insert(fold_key(&entry.path));
            if let Some(change) = self.verify_entry(entry)? {
                changes.push(change);
            }
        }
        changes.extend(self.unexpected_files(&known)?);
        Ok(changes)
    }

    /// One entry, hashed again.
    fn verify_entry(&self, entry: &Entry) -> Result<Option<Change>, String> {
        let exists = entry.path.is_file();
        if !entry.present {
            // Recorded as missing. It was already gone when the manifest was
            // taken, so the only change worth reporting is that it has appeared.
            if !exists {
                return Ok(None);
            }
            return Ok(Some(Change::Added {
                path: entry.path.clone(),
                recorded_absent: true,
            }));
        }
        if !exists {
            return Ok(Some(Change::Missing {
                role: entry.role,
                path: entry.path.clone(),
            }));
        }
        let metadata =
            std::fs::metadata(&entry.path).map_err(|error| unreadable(&entry.path, &error))?;
        let size = metadata.len();
        if size != entry.size {
            let signature = signature_change(entry)?;
            return Ok(Some(Change::Resized {
                role: entry.role,
                path: entry.path.clone(),
                from: entry.size,
                to: size,
                signature,
            }));
        }
        let (digest, bytes) = hash_file(&entry.path)?;
        if digest == entry.sha256 {
            return Ok(None);
        }
        // The size matched and the digest did not: the same-size edit, which is
        // the case a size check alone would miss and the case a file infector
        // produces.
        let after = signature_of(entry.role, bytes.as_deref())?;
        Ok(Some(Change::Modified {
            role: entry.role,
            path: entry.path.clone(),
            from: hex(&entry.sha256),
            to: hex(&digest),
            signature: SignatureChange::between(&entry.signature, &after),
        }))
    }

    /// Files sitting in the manifest's own directories that no entry names.
    ///
    /// The scan is one level deep and covers only the directories the entries
    /// already occupy. That is a deliberate ceiling: the product's install and
    /// data directories hold a known, flat set of files, and walking a data
    /// directory recursively is the *scanner's* job — it is a different feature
    /// with a different cost model, and doing it here would make an integrity
    /// check that reads a quarantine vault.
    fn unexpected_files(&self, known: &BTreeSet<String>) -> Result<Vec<Change>, String> {
        let manifest_own = fold_key(&manifest_path_of(self));
        let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
        for entry in &self.entries {
            if let Some(parent) = entry.path.parent() {
                directories.insert(parent.to_path_buf());
            }
        }
        let mut changes = Vec::new();
        for directory in directories {
            let listing = match std::fs::read_dir(&directory) {
                Ok(listing) => listing,
                // A directory that is not there has already been reported, once
                // per entry inside it. Failing the whole check on it would mean
                // one missing directory hiding every other finding.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "the directory {} could not be listed, so this check cannot say whether \
                         anything unexpected was put in it: {error}",
                        directory.display()
                    ));
                }
            };
            let mut found = 0usize;
            let mut dropped = 0usize;
            for item in listing.flatten() {
                let path = item.path();
                if !path.is_file() {
                    continue;
                }
                let key = fold_key(&path);
                if known.contains(&key) || key == manifest_own {
                    continue;
                }
                if found >= MAX_ADDED_PER_DIRECTORY {
                    dropped += 1;
                    continue;
                }
                found += 1;
                changes.push(Change::Added {
                    path,
                    // Nothing here names this path — the loop above skipped
                    // every key the manifest knows and the manifest's own file.
                    recorded_absent: false,
                });
            }
            if dropped > 0 {
                log::warn!(
                    "{} holds {dropped} further files beyond the {MAX_ADDED_PER_DIRECTORY} this \
                     report lists; they are not shown so that the entries that matter are not \
                     buried",
                    directory.display()
                );
            }
        }
        Ok(changes)
    }
}

/// The manifest path belonging to a manifest, derived from its roots.
///
/// A manifest does not record where it was stored, because that is a property of
/// the installation rather than of the file. Deriving it from the roots is
/// enough for the one thing it is used for — not reporting the manifest as an
/// unexpected addition to its own directory.
fn manifest_path_of(manifest: &Manifest) -> PathBuf {
    manifest.roots.data_dir.join(MANIFEST_FILE)
}

/// A path folded into the key the added-file scan compares with.
fn fold_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

/// One of the product's files, hashed.
///
/// Streamed rather than read into memory: a rule database is the largest file
/// this product owns and there is no reason for a check that runs on a machine
/// under load to hold a whole copy of it in the address space. The bytes are
/// kept only when the role is one whose signature is worth checking and the file
/// is small enough to read twice — see [`MAX_SIGNATURE_BYTES`].
fn entry_for(role: Role, path: &Path) -> Result<Entry, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Entry {
                role,
                path: path.to_path_buf(),
                present: false,
                size: 0,
                sha256: [0u8; 32],
                signature: Signature::Undetermined {
                    reason: "the file was not there when the manifest was taken".to_string(),
                },
            });
        }
        Err(error) => return Err(unreadable(path, &error)),
    };
    if !metadata.is_file() {
        return Err(format!(
            "{} is not a file, so it cannot be hashed. Something has replaced one of the \
             product's own files with a directory or a device; that is itself a finding, and this \
             check cannot describe it as a digest.",
            path.display()
        ));
    }
    let (digest, bytes) = hash_file(path)?;
    let signature = signature_of(role, bytes.as_deref())?;
    Ok(Entry {
        role,
        path: path.to_path_buf(),
        present: true,
        size: metadata.len(),
        sha256: digest,
        signature,
    })
}

/// The largest file this module will read into memory to check a signature.
///
/// `av_authenticode` verifies from a byte slice, so asking it about a file means
/// holding the file. 256 MiB is far above any executable this product ships and
/// far below the point where a 32-bit build would fail to allocate; a file above
/// it is recorded as [`Signature::Undetermined`] rather than as unsigned,
/// because "too large to check" and "checked and there is no signature" are
/// different answers.
pub const MAX_SIGNATURE_BYTES: u64 = 256 * 1024 * 1024;

/// SHA-256 of a file, and its bytes when they were kept.
fn hash_file(path: &Path) -> Result<([u8; 32], Option<Vec<u8>>), String> {
    let mut file = std::fs::File::open(path).map_err(|error| unreadable(path, &error))?;
    let size = file
        .metadata()
        .map_err(|error| unreadable(path, &error))?
        .len();
    let keep = size <= MAX_SIGNATURE_BYTES;
    let mut hasher = Sha256::new();
    let mut kept = if keep {
        Some(Vec::with_capacity(size as usize))
    } else {
        None
    };
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| unreadable(path, &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if let Some(kept) = kept.as_mut() {
            kept.extend_from_slice(&buffer[..read]);
        }
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    Ok((digest, kept))
}

/// The signature state of a file whose bytes may or may not have been kept.
fn signature_of(role: Role, bytes: Option<&[u8]>) -> Result<Signature, String> {
    if !role.is_program() {
        return Ok(Signature::NotAProgram);
    }
    let Some(bytes) = bytes else {
        return Ok(Signature::Undetermined {
            reason: format!(
                "the file is larger than the {MAX_SIGNATURE_BYTES}-byte ceiling this check will \
                 read into memory to verify a signature"
            ),
        });
    };
    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
        // Not a PE image at all. Recorded as undetermined with the reason rather
        // than as unsigned, because a product binary that is not a PE file is a
        // finding and "unsigned" would read as an ordinary one.
        return Ok(Signature::Undetermined {
            reason: "the file does not begin with the MZ signature of a Windows program, so it \
                     is not something that can be signed"
                .to_string(),
        });
    }
    Ok(match av_authenticode::verify_bytes(bytes) {
        av_authenticode::Verdict::Trusted(proof) => Signature::Trusted {
            subject: proof.subject.clone(),
            thumbprint: proof.thumbprint.clone(),
        },
        av_authenticode::Verdict::Untrusted { proof, .. } => Signature::Untrusted {
            subject: proof.subject.clone(),
            thumbprint: proof.thumbprint.clone(),
        },
        av_authenticode::Verdict::Invalid { reason } => Signature::Invalid {
            reason: reason.code().to_string(),
        },
        av_authenticode::Verdict::Unsigned => Signature::Unsigned,
        av_authenticode::Verdict::Undetermined { reason } => Signature::Undetermined {
            reason: reason.code().to_string(),
        },
    })
}

/// The signature state of a file that already exists, read again.
///
/// Used by the resized path, which has not read the bytes for the digest. The
/// file is re-read here rather than threaded through, and the cost is only paid
/// on a file that has already turned out to be a finding.
fn signature_change(entry: &Entry) -> Result<SignatureChange, String> {
    if !entry.role.is_program() {
        return Ok(SignatureChange::Unchanged);
    }
    let (_, bytes) = hash_file(&entry.path)?;
    let after = signature_of(entry.role, bytes.as_deref())?;
    Ok(SignatureChange::between(&entry.signature, &after))
}

/// A read that failed for a reason other than the file being gone.
fn unreadable(path: &Path, error: &std::io::Error) -> String {
    format!(
        "{} could not be read: {error}. It is one of the product's own files and it is there, so \
         this is either a permissions problem — the file's permissions have been changed away \
         from the ones `wenle protect audit` expects — or something is holding it open.",
        path.display()
    )
}

/// Now, in Unix seconds, or zero when the clock could not be read.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// One difference between the manifest and the files on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A file the manifest recorded as present is not there any more.
    Missing {
        /// Which of the product's files it was.
        role: Role,
        /// Where it should have been.
        path: PathBuf,
    },
    /// A file is there that the manifest does not account for.
    ///
    /// Two cases, and the second is the one that is easy to miss: a path no
    /// entry names (something was dropped into the install directory), and a
    /// path an entry recorded as *absent* and that has since appeared. They are
    /// carried by one variant because they are the same finding — a file that
    /// is there and that the manifest does not name — and told apart by
    /// [`Change::is_alarming`], which is where the difference matters.
    Added {
        /// Where it is.
        path: PathBuf,
        /// Whether an entry named this path and recorded that nothing was
        /// there when the manifest was taken.
        ///
        /// `false` for a path no entry names at all.
        recorded_absent: bool,
    },
    /// A file's length changed.
    ///
    /// Reported separately from [`Change::Modified`] rather than folded into it,
    /// because the two are different attacks: appending to a binary or
    /// truncating a database changes the length, while a patched instruction or
    /// a swapped string does not. A reader who sees `Resized` knows the file was
    /// rebuilt or padded; a reader who sees `Modified` alone knows somebody
    /// edited it in place and kept the length, which is a more deliberate act.
    Resized {
        /// Which of the product's files it was.
        role: Role,
        /// Where it is.
        path: PathBuf,
        /// What the manifest recorded.
        from: u64,
        /// What it is now.
        to: u64,
        /// Whether it is still signed the way it was.
        ///
        /// Carried here as well as on [`Change::Modified`] even though the digest
        /// is already different, because a length change is the commonest way a
        /// binary is patched and leaving the signature answer off would make the
        /// commonest case the least informative one.
        signature: SignatureChange,
    },
    /// A file is the same length and its digest is different.
    Modified {
        /// Which of the product's files it was.
        role: Role,
        /// Where it is.
        path: PathBuf,
        /// The digest the manifest recorded, lower-case hex.
        from: String,
        /// The digest now, lower-case hex.
        to: String,
        /// Whether it is still signed the way it was.
        signature: SignatureChange,
    },
}

impl Change {
    /// The file this is about.
    pub fn path(&self) -> &Path {
        match self {
            Change::Missing { path, .. }
            | Change::Added { path, .. }
            | Change::Resized { path, .. }
            | Change::Modified { path, .. } => path,
        }
    }

    /// Whether this change is the kind that means somebody interfered.
    ///
    /// [`Change::Added`] is not, on its own: a new file in the install directory
    /// may be a leftover from an upgrade. Everything else is — a missing binary,
    /// a resized database or a rewritten executable is a change to something
    /// that was already the product's.
    ///
    /// **Except one kind of addition, and the distinction is the machine's own
    /// rule rather than a judgement call.** A file no entry names is a finding:
    /// an installation's directory also holds the uninstaller, a readme, and
    /// whatever the user keeps beside the program, and `verify` prints them all
    /// without failing on them. A file that appeared *where an entry records
    /// that nothing is* is a different thing, because the manifest made a claim
    /// about that path and the claim is now false. That is not hypothetical
    /// here: `Role::Database` names `%ProgramData%\WenleAV\db\rules.avdb` and
    /// `C:\WenleAV\rules.avdb` in that order, `av-cli`, `av-service` and
    /// `av-gui` each search them in that order — each with a test that says so —
    /// and a healthy machine has the database in one of the two and nothing in
    /// the other. A database appearing in the first place is the one every scan
    /// would then load.
    pub fn is_alarming(&self) -> bool {
        match self {
            Change::Added {
                recorded_absent, ..
            } => *recorded_absent,
            // Every other arm is a change to a file that was already the
            // product's, and the signature answer does not downgrade that: a
            // resized binary whose signature still matches is still a binary
            // that changed.
            _ => true,
        }
    }

    /// One sentence for a report.
    pub fn describe(&self) -> String {
        match self {
            Change::Missing { role, path } => format!(
                "MISSING: {role_desc} is gone from {}",
                path.display(),
                role_desc = role.describe()
            ),
            Change::Added {
                path,
                recorded_absent: false,
            } => format!(
                "UNEXPECTED: {} is not one of the product's files and is not named by the manifest",
                path.display()
            ),
            // The sentence says which of the two additions this is, because the
            // reader's next move differs: a stray file is a question to answer,
            // while a file where the manifest records that nothing is has
            // already replaced an answer this installation was relying on.
            Change::Added {
                path,
                recorded_absent: true,
            } => format!(
                "APPEARED: {} is there now, and the manifest records that nothing was at that path \
                 when it was taken",
                path.display()
            ),
            Change::Resized {
                role,
                path,
                from,
                to,
                signature,
            } => format!(
                "CHANGED: {role_desc} at {} is {to} bytes and the manifest recorded {from}; {}",
                path.display(),
                signature.describe(),
                role_desc = role.describe()
            ),
            Change::Modified {
                role,
                path,
                from,
                to,
                signature,
            } => format!(
                "CHANGED: {role_desc} at {} is the same length and a different file — sha256 \
                 {from} became {to}; {}",
                path.display(),
                signature.describe(),
                role_desc = role.describe()
            ),
        }
    }
}

/// This process's own view of whether it is being debugged, as three separate
/// answers.
///
/// Kept as three fields rather than reduced to one boolean because they do not
/// agree in practice — a debugger that hides from `IsDebuggerPresent` may still
/// leave `BeingDebugged` set, and a report that only had the OR could not say
/// which check had fired. See the module documentation for why the OR is
/// nevertheless the answer [`DebuggerReport::is_present`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebuggerReport {
    /// `IsDebuggerPresent()`. Always answers.
    pub api: bool,
    /// `CheckRemoteDebuggerPresent(GetCurrentProcess())`, or `None` when the
    /// call failed.
    pub remote: Option<bool>,
    /// `PEB.BeingDebugged` for this process, or `None` when the PEB could not be
    /// reached.
    pub peb: Option<bool>,
}

impl DebuggerReport {
    /// Whether any check that answered says yes.
    pub fn is_present(&self) -> bool {
        self.api || self.remote == Some(true) || self.peb == Some(true)
    }

    /// How many of the three checks returned an answer.
    ///
    /// A report where this is below two is a report about this process's
    /// inability to look at itself, not about a debugger — and that distinction
    /// is the difference between a useful line in a log and a misleading one.
    pub fn checks_that_answered(&self) -> usize {
        usize::from(true) + usize::from(self.remote.is_some()) + usize::from(self.peb.is_some())
    }

    /// One sentence for a report, including the limit.
    pub fn describe(&self) -> String {
        let verdict = if self.is_present() {
            "this process looks like it is being debugged"
        } else {
            "no debugger was detected"
        };
        format!(
            "{verdict} (IsDebuggerPresent: {}, CheckRemoteDebuggerPresent: {}, PEB.BeingDebugged: \
             {}; {} of the three checks answered). Every one of these is trivially defeatable by a \
             program that is already running inside this process, so this is a check for casual \
             inspection and not a security decision",
            self.api,
            match self.remote {
                Some(value) => value.to_string(),
                None => "could not be asked".to_string(),
            },
            match self.peb {
                Some(value) => value.to_string(),
                None => "could not be read".to_string(),
            },
            self.checks_that_answered(),
        )
    }
}

/// Ask the platform's three questions about this process.
pub fn debugger_report() -> DebuggerReport {
    platform::debugger_report()
}

/// Whether any of the three checks says a debugger is attached.
///
/// See the module documentation: this is a tripwire against casual inspection,
/// it is trivially defeated by anything already running in this process, and
/// **nothing may branch on it**.
pub fn debugger_present() -> bool {
    debugger_report().is_present()
}

/// The state of the manifest, which is not the same thing as the state of the
/// files it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestState {
    /// There is no manifest, so there is nothing to check against.
    ///
    /// The state of a fresh installation, and not an error: a product that
    /// refused to run a self-check until somebody had taken a manifest would
    /// report a problem on every new install.
    Absent,
    /// There is a manifest and it could not be read, with the reason.
    Unreadable(String),
    /// There is a manifest.
    Loaded(Box<Manifest>),
}

/// Everything [`self_check`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfCheck {
    /// Where the manifest was looked for.
    pub manifest_path: PathBuf,
    /// What was found there.
    pub manifest: ManifestState,
    /// The differences, empty when the manifest is absent or unreadable.
    pub changes: Vec<Change>,
    /// What the three debugger checks said.
    pub debugger: DebuggerReport,
    /// What the machine says about the service, or why it could not be read.
    pub service: Result<ServiceIntegrity, String>,
}

impl SelfCheck {
    /// Whether everything this check could look at was in order.
    ///
    /// A missing manifest is *not* clean: it means no check has been taken, and
    /// a report that called that healthy would be describing a machine where
    /// nobody has ever looked. An unreadable one is not clean either. Both say
    /// what to do about it in [`SelfCheck::describe`].
    ///
    /// The service half is [`ServiceIntegrity::is_hardened`] and not merely
    /// "the service could be read". It was the latter until 2026-10-10, and the
    /// gap was the one this product keeps finding: `wenle protect status` on a
    /// machine whose service was stopped, or which had no recovery policy,
    /// printed a line saying exactly that and then ended with "The machine is
    /// fully protected", because a service the SCM answers about is a service
    /// `is_ok()` says yes to. [`SelfCheck::has_alarming_changes`]'s own
    /// documentation had claimed the stronger meaning all along.
    ///
    /// The file half is [`SelfCheck::has_alarming_changes`] and not "there are
    /// no differences", which it was until 2026-10-10 as well. The two are the
    /// same question only if every difference is interference, and
    /// [`Change::is_alarming`] is the function that says which are — a stray
    /// file in the install directory is not, and `verify` has printed them
    /// without failing on them since the day it was written. Measured in the VM
    /// on 2026-10-10: a clean installation whose directory held `README.md`,
    /// `wenle-test-driver.cer` and the `.before-*` copies of earlier binaries
    /// reported "20 of the product's own files have changed" — none of which
    /// had changed — and a machine that is healthy cannot be one this check
    /// calls unprotected every time it is asked.
    pub fn is_clean(&self) -> bool {
        matches!(self.manifest, ManifestState::Loaded(_))
            && !self.has_alarming_changes()
            && self
                .service
                .as_ref()
                .is_ok_and(ServiceIntegrity::is_hardened)
    }

    /// Whether anything found is the kind that means interference.
    ///
    /// Narrower than [`SelfCheck::is_clean`], which also fails on a stopped
    /// service and on a missing manifest — states that need attention but that
    /// nothing in this product did to itself.
    pub fn has_alarming_changes(&self) -> bool {
        self.changes.iter().any(Change::is_alarming)
    }

    /// The report, as lines rather than one string, because a caller prints it.
    ///
    /// Lines rather than a paragraph so that the manifest's state, each change,
    /// the debugger answer and the service's are separate — which is what makes
    /// the output greppable, and what lets a caller show the debugger line
    /// without the rest.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.manifest {
            ManifestState::Absent => lines.push(format!(
                "No manifest at {}: nothing has been recorded to check the product's files \
                 against. Run `wenle protect manifest` from an elevated prompt to take one.",
                self.manifest_path.display()
            )),
            ManifestState::Unreadable(reason) => {
                lines.push(format!("The manifest could not be read. {reason}"))
            }
            ManifestState::Loaded(manifest) => {
                lines.push(format!("Manifest: {}.", manifest.describe()));
                if !manifest.has_present_entries() {
                    lines.push(
                        "  No file the manifest names was there when it was taken, which usually \
                         means it was captured for a different installation. Take a new one with \
                         `wenle protect manifest`."
                            .to_string(),
                    );
                }
            }
        }
        if self.changes.is_empty() {
            if matches!(self.manifest, ManifestState::Loaded(_)) {
                lines.push(
                    "Every file in the manifest is unchanged, and nothing unexpected is in the \
                     directories they live in."
                        .to_string(),
                );
            }
        } else {
            // The heading counts the two kinds apart, because a reader who sees
            // "20 difference(s)" over twenty `UNEXPECTED` lines has been told
            // that twenty of this product's files differ from the manifest, and
            // none of them does. `Change::describe` starts each line with which
            // kind it is; this is the same distinction one line earlier.
            let alarming = self.changes.iter().filter(|c| c.is_alarming()).count();
            let appeared = self.changes.len() - alarming;
            lines.push(match (alarming, appeared) {
                (0, appeared) => format!(
                    "{appeared} file(s) that are not the product's are in the directories the \
                     manifest's own files live in, and no file the manifest names is different:"
                ),
                (alarming, 0) => format!("{alarming} difference(s):"),
                (alarming, appeared) => format!(
                    "{alarming} difference(s), and {appeared} file(s) that are not the product's:"
                ),
            });
            for change in &self.changes {
                lines.push(format!("  {}", change.describe()));
            }
        }
        lines.push(format!("Debugger: {}.", self.debugger.describe()));
        match &self.service {
            Ok(integrity) => lines.push(format!("Service: {}.", integrity.describe())),
            Err(reason) => lines.push(format!("Service: could not be read. {reason}")),
        }
        lines
    }

    /// The report as one string.
    pub fn describe(&self) -> String {
        self.lines().join("\n")
    }
}

/// Assemble the manifest check, the debugger check and the service's own
/// integrity into one report.
///
/// `service_name` is passed rather than defaulted for the reason
/// [`crate::service`]'s documentation gives: a second copy of the service's name
/// in a second crate is a hazard, and a name is also what lets this check run
/// against an installation that named its service something else.
///
/// # Errors
///
/// Fails when the manifest exists and was taken against a *different*
/// installation — different install directory or different data directory — from
/// the one `paths` names. That is the one case where continuing would produce a
/// report that is worse than none: every file would be reported missing and
/// every file would be reported unexpected, and the reader would have no way to
/// tell that the manifest, not the machine, was the problem.
///
/// Everything else is a *finding* and not an error: no manifest, an unreadable
/// manifest, a changed file, a debugger, a service that will not answer. Each is
/// carried in the returned [`SelfCheck`] so that one bad answer does not hide
/// the others — which is the whole point of a check that runs on a machine
/// somebody is worried about.
pub fn self_check(paths: &AvPaths, service_name: &str) -> Result<SelfCheck, String> {
    let path = manifest_path(paths);
    let (manifest, changes) = match Manifest::load(&path) {
        Ok(manifest) => {
            if !manifest.matches_roots(paths) {
                return Err(format!(
                    "the manifest at {} was taken against a different installation, so checking \
                     these files against it would report every one of them as missing and every \
                     file here as unexpected. {} Take a new manifest with `wenle protect \
                     manifest`.",
                    path.display(),
                    manifest.roots.describe_mismatch(paths)
                ));
            }
            let changes = manifest.verify()?;
            (ManifestState::Loaded(Box::new(manifest)), changes)
        }
        Err(reason) => {
            let state = if reason.contains("there is no manifest at") {
                ManifestState::Absent
            } else {
                ManifestState::Unreadable(reason)
            };
            (state, Vec::new())
        }
    };
    Ok(SelfCheck {
        manifest_path: path,
        manifest,
        changes,
        debugger: debugger_report(),
        service: service::integrity(service_name),
    })
}

/// The three debugger checks, and the absence of them.
#[cfg(windows)]
mod platform {
    use super::DebuggerReport;

    use windows::core::BOOL;
    use windows::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, IsDebuggerPresent,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, PROCESS_BASIC_INFORMATION,
    };
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};

    /// Ask all three.
    pub(super) fn debugger_report() -> DebuggerReport {
        // SAFETY: `IsDebuggerPresent` takes no arguments, retains nothing and
        // cannot fail.
        let api = unsafe { IsDebuggerPresent() }.as_bool();

        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be
        // closed and is valid for the life of the process, and `present` is a
        // live, correctly typed out-parameter.
        let mut present = BOOL::default();
        let remote = unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present) }
            .ok()
            .map(|()| present.as_bool());

        DebuggerReport {
            api,
            remote,
            peb: peb_being_debugged(),
        }
    }

    /// `PEB.BeingDebugged` for this process.
    ///
    /// The reason this is a third check rather than a second: the byte is the
    /// one the Windows loader itself reads, so a tool that clears it has to
    /// clear it in a place the loader also looks — whereas `IsDebuggerPresent`
    /// is a single exported function that can simply be patched to return zero.
    /// Neither survives an adversary, and they do not fail together, which is the
    /// only claim worth making.
    ///
    /// `None` when the PEB could not be reached at all. That is not treated as
    /// "not being debugged": [`DebuggerReport::checks_that_answered`] counts it
    /// and the report says so.
    fn peb_being_debugged() -> Option<bool> {
        let mut info = PROCESS_BASIC_INFORMATION::default();
        let mut returned = 0u32;
        // SAFETY: `info` is a live, correctly typed out-parameter and its size
        // is passed; the call writes at most one
        // `PROCESS_BASIC_INFORMATION`. The process handle is the current-process
        // pseudo-handle, which is always valid for this information class.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessBasicInformation,
                (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut returned,
            )
        };
        // `NTSTATUS` of zero is `STATUS_SUCCESS`; the `windows` crate does not
        // give this one a `Result`, so the comparison is by hand.
        if status.0 != 0 {
            log::debug!(
                "`NtQueryInformationProcess(ProcessBasicInformation)` returned {:#x}, so this \
                 process cannot read its own PEB",
                status.0
            );
            return None;
        }
        if info.PebBaseAddress.is_null() {
            return None;
        }
        // SAFETY: the call succeeded and reported a non-null PEB for *this*
        // process, which stays mapped for as long as the process runs. The field
        // is read through the struct's own layout rather than by a hard-coded
        // offset, so a change in the struct's definition is a compile error and
        // not a read of the wrong byte.
        let being_debugged = unsafe { (*info.PebBaseAddress).BeingDebugged };
        Some(being_debugged != 0)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::DebuggerReport;

    /// No PEB and no `IsDebuggerPresent` to read.
    pub(super) fn debugger_report() -> DebuggerReport {
        DebuggerReport::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout in a temporary directory, with the three program names and the
    /// database filled in.
    ///
    /// The service binary is **this test's own executable**, copied into place.
    /// That is not a convenience: it makes the signature half of the check a
    /// measurement against a real PE file that this machine really has, rather
    /// than against a hand-written header that would only prove the parser runs.
    /// A locally built binary is unsigned, which is the state a developer's
    /// machine is in all day and the state the report has to get right.
    struct Layout {
        _directory: tempfile::TempDir,
        paths: AvPaths,
    }

    impl Layout {
        fn new() -> Layout {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let install = directory.path().join("install");
            let data = directory.path().join("data");
            std::fs::create_dir_all(&install).expect("creates the install directory");
            std::fs::create_dir_all(data.join("db")).expect("creates the database directory");
            let paths = AvPaths::with_data_dir(&install, &data);

            let me = std::env::current_exe().expect("this test knows where it is running from");
            std::fs::copy(&me, install.join("wenle-av-service.exe"))
                .expect("copies this test binary into place as the service");
            // The provider is a real PE here for the same reason the service is:
            // it is a program, so the manifest asks `av-authenticode` about it,
            // and a stand-in of text would test the not-a-program path instead
            // of the one a real installation takes.
            std::fs::copy(&me, install.join("av_amsi.dll"))
                .expect("copies this test binary into place as the AMSI provider");
            std::fs::write(install.join("wenle.exe"), b"# a stand-in for the command-line tool\n")
                .expect("writes the cli stand-in");
            std::fs::write(install.join("wenle-gui.exe"), b"# a stand-in for the desktop app\n")
                .expect("writes the gui stand-in");
            std::fs::write(
                paths.db_dir.join("rules.avdb"),
                b"AVDB\x01\x00\x00\x00 stand-in rule database",
            )
            .expect("writes the database stand-in");

            Layout {
                _directory: directory,
                paths,
            }
        }

        /// The path of the service binary, which is the one that is a real PE.
        fn service_binary(&self) -> PathBuf {
            self.paths.install_dir.join("wenle-av-service.exe")
        }
    }

    #[test]
    fn a_capture_of_a_clean_layout_verifies_with_nothing_to_report() {
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture hashes real files");
        assert!(
            manifest.has_present_entries(),
            "every file was written before the capture: {manifest:?}"
        );
        let changes = manifest.verify().expect("verify re-hashes the same files");
        assert!(
            changes.is_empty(),
            "a layout that has not been touched must verify clean, and it reported: {:?}",
            changes
                .iter()
                .map(Change::describe)
                .collect::<Vec<_>>()
        );
        // The install directory holds the five programs, and the database is in
        // the data directory, so nothing is unexpected either. The extra entry
        // is the database's two places, which is the one role that has more
        // than one.
        assert_eq!(manifest.entries.len(), Role::ALL.len() + 1);
    }

    #[test]
    fn an_unsigned_binary_is_recorded_as_unsigned_rather_than_unreadable() {
        // The measurement the module documentation quotes, taken against the
        // test binary itself: a locally built, unsigned PE file has to come back
        // as `Unsigned` — a finding — and not as `Undetermined`, which would
        // read as "this check could not tell" and would let a replaced binary
        // hide behind a hedge.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let service = manifest
            .entry_for(&layout.service_binary())
            .expect("the service binary is in the manifest");
        assert_eq!(
            service.signature,
            Signature::Unsigned,
            "a locally built binary has no signature, so the answer is `Unsigned`; anything else \
             means the signature check is not reaching a real PE file. Entry: {}",
            service.describe()
        );
        assert_eq!(service.signature.signer(), None);
        // And a file that is not a program is not asked at all.
        let database = manifest
            .entries
            .iter()
            .find(|entry| entry.role == Role::Database && entry.present)
            .expect("the database stand-in is present");
        assert_eq!(
            database.signature,
            Signature::NotAProgram,
            "a rule database is data: checking it for a signature would read the whole file to be \
             told it is not a PE file"
        );
        // A stand-in that is not a PE at all is not "unsigned" — it is a file
        // that cannot carry a signature, and the report has to say which.
        let cli = manifest
            .entries
            .iter()
            .find(|entry| entry.role == Role::Cli)
            .expect("the cli stand-in is in the manifest");
        assert!(
            matches!(cli.signature, Signature::Undetermined { .. }),
            "a text file standing in for a binary must not be reported as unsigned: {}",
            cli.describe()
        );
    }

    #[test]
    fn every_way_a_file_can_be_changed_is_reported_as_its_own_kind_of_change() {
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let database = layout.paths.db_dir.join("rules.avdb");

        // Deleted: `Missing`, and named by role.
        std::fs::remove_file(&database).expect("removes the database");
        // The same length and a different byte: `Modified`, the case a size
        // check alone would miss. Done to the *service binary*, which is a real
        // PE file, rather than to one of the text stand-ins — the comparison
        // this exercises is a PE file's digest and its signature state, and a
        // text file would exercise neither.
        let service = layout.service_binary();
        let original = std::fs::read(&service).expect("reads the service binary");
        let mut edited = original.clone();
        let last = edited.len() - 1;
        edited[last] ^= 0xFF;
        std::fs::write(&service, &edited).expect("writes the patched service binary");
        assert_eq!(
            edited.len(),
            original.len(),
            "the edit has to keep the length, or this is a `Resized` and not a `Modified`"
        );
        // A different length: `Resized`.
        let gui = layout.paths.install_dir.join("wenle-gui.exe");
        std::fs::write(&gui, b"# a stand-in for the desktop app\nand some more\n")
            .expect("appends to the gui stand-in");
        // Something that was never the product's: `Added`.
        let dropped = layout.paths.install_dir.join("payload.dll");
        std::fs::write(&dropped, b"not one of ours").expect("drops a file in");

        let changes = manifest.verify().expect("verify");
        let described: Vec<String> = changes.iter().map(Change::describe).collect();

        assert_eq!(
            changes
                .iter()
                .filter(|change| matches!(change, Change::Missing { .. }))
                .count(),
            1,
            "{described:?}"
        );
        assert_eq!(
            changes
                .iter()
                .filter(|change| matches!(change, Change::Modified { .. }))
                .count(),
            1,
            "{described:?}"
        );
        assert_eq!(
            changes
                .iter()
                .filter(|change| matches!(change, Change::Resized { .. }))
                .count(),
            1,
            "{described:?}"
        );
        // The unexpected file, and only it.
        let added: Vec<&Change> = changes
            .iter()
            .filter(|change| matches!(change, Change::Added { .. }))
            .collect();
        assert_eq!(added.len(), 1, "{described:?}");
        assert_eq!(added[0].path(), dropped);

        // The role is named, and the path, and the kind of change — in words a
        // person can act on.
        let missing = changes
            .iter()
            .find(|change| matches!(change, Change::Missing { .. }))
            .expect("the missing database");
        assert!(missing.describe().contains("rule database"), "{missing:?}");
        assert!(missing.describe().contains("rules.avdb"), "{missing:?}");
        assert!(missing.is_alarming());
        assert!(
            !added[0].is_alarming(),
            "an unexpected file is a finding but not on its own proof of interference"
        );
        // The patched binary is still unsigned, which is what the comparison has
        // to say: an edit that did not change the signature state is not a
        // signature finding, and only the digest is what changed.
        let modified = changes
            .iter()
            .find(|change| matches!(change, Change::Modified { .. }))
            .expect("the patched service binary");
        let Change::Modified { role, signature, .. } = modified else {
            unreachable!("just matched")
        };
        assert_eq!(*role, Role::Service);
        assert_eq!(
            *signature,
            SignatureChange::Unchanged,
            "the binary was unsigned before the patch and is unsigned after it: {}",
            modified.describe()
        );
        assert!(modified.describe().contains("same length"), "{modified:?}");
        assert!(modified.describe().contains("signature is unchanged"), "{modified:?}");
    }

    #[test]
    fn two_unreadable_signature_states_are_unknown_rather_than_unchanged() {
        // The distinction the module documentation calls the one that matters:
        // a comparison where either side could not be read says so, and does not
        // quietly report `Unchanged` for a file whose signature nobody managed to
        // look at.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let cli = layout.paths.install_dir.join("wenle.exe");
        let entry = manifest
            .entry_for(&cli)
            .expect("the cli stand-in is in the manifest");
        assert!(
            matches!(entry.signature, Signature::Undetermined { .. }),
            "the stand-in is not a PE file, which is the unreadable state this test needs: {}",
            entry.signature.describe()
        );

        let mut original = std::fs::read(&cli).expect("reads the cli stand-in");
        let last = original.len() - 1;
        original[last] ^= 0xFF;
        std::fs::write(&cli, &original).expect("edits the cli stand-in");

        let changes = manifest.verify().expect("verify");
        let change = changes
            .iter()
            .find(|change| matches!(change.path(), path if same_dir(path, &cli)))
            .expect("the edited stand-in is reported");
        let Change::Modified { signature, .. } = change else {
            panic!("a same-length edit is `Modified`: {change:?}")
        };
        assert!(
            matches!(signature, SignatureChange::Unknown { .. }),
            "both states are unreadable, so the comparison says nothing: {}",
            change.describe()
        );
    }

    #[test]
    fn a_resized_binary_carries_the_signature_answer_and_a_replaced_one_says_so() {
        // The case the brief asks about, built without needing a signed binary:
        // the manifest is edited by hand to claim the service binary was signed,
        // and the check then has to say that it is not any more. That is the same
        // comparison a real signed binary would go through, and it is the only
        // way to exercise it on a machine where nothing is signed.
        let layout = Layout::new();
        let mut manifest = Manifest::capture(&layout.paths).expect("capture");
        let service = layout.service_binary();
        let entry = manifest
            .entries
            .iter_mut()
            .find(|entry| same_dir(&entry.path, &service))
            .expect("the service binary is in the manifest");
        entry.signature = Signature::Trusted {
            subject: "CN=Wenle".to_string(),
            thumbprint: "00112233445566778899aabbccddeeff00112233".to_string(),
        };
        assert_eq!(
            entry.signature.signer(),
            Some("00112233445566778899aabbccddeeff00112233")
        );

        // Grow the binary so the size check fires before the digest is taken.
        let mut grown = std::fs::read(&service).expect("reads the service binary");
        grown.extend_from_slice(b"padding");
        std::fs::write(&service, &grown).expect("writes the padded binary");

        let changes = manifest.verify().expect("verify");
        let resized = changes
            .iter()
            .find(|change| matches!(change, Change::Resized { .. }))
            .expect("the padded service binary");
        let Change::Resized {
            signature, from, to, ..
        } = resized
        else {
            unreachable!("just matched")
        };
        assert!(*from < *to, "{resized:?}");
        assert_eq!(
            *signature,
            SignatureChange::NowUnsigned,
            "the manifest claimed a signer and the file has none, which is the answer that has to \
             be reported for a replaced binary: {}",
            resized.describe()
        );
        assert!(signature.is_alarming());
        assert!(resized.describe().contains("NOT any more"), "{resized:?}");
    }

    #[test]
    fn removing_the_amsi_provider_is_reported_by_name() {
        // The reason the role exists. Nothing in this product behaves
        // differently when the provider is gone — the scripts that were supposed
        // to be examined simply are not — so an entry here is the only thing on
        // the machine that says so. It is also the most valuable file in the
        // installation to replace, because Windows loads it into every scripting
        // host including elevated ones. The deletion is what is tested, rather
        // than the replacement, because a person can act on it: put it back.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let provider = layout.paths.install_dir.join("av_amsi.dll");
        assert!(provider.is_file(), "the fixture has to put it there");

        std::fs::remove_file(&provider).expect("removes the provider");
        let changes = manifest.verify().expect("verify");

        let missing = changes
            .iter()
            .find(|change| matches!(change, Change::Missing { role: Role::Amsi, .. }))
            .unwrap_or_else(|| panic!("the provider's removal must be reported: {changes:?}"));
        assert!(missing.describe().contains("AMSI"), "{}", missing.describe());
        assert!(missing.is_alarming());
        assert_eq!(
            changes.len(),
            1,
            "removing the provider is one change and not a report about the rest: {changes:?}"
        );
    }

    #[test]
    fn a_file_that_was_already_missing_is_only_reported_when_it_appears() {
        // The reason `Entry::present` exists. A manifest taken while a file was
        // absent must not report that file as missing for the rest of the
        // installation's life — and must report it when it turns up.
        let layout = Layout::new();
        let database_in_install = layout.paths.install_dir.join("rules.avdb");
        assert!(!database_in_install.exists());
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let absent = manifest
            .entry_for(&database_in_install)
            .expect("the second database location is recorded even though it is not there");
        assert!(!absent.present);
        assert_eq!(absent.size, 0);
        assert_eq!(
            absent.signature,
            Signature::Undetermined {
                reason: "the file was not there when the manifest was taken".to_string()
            },
            "a file that was never there has no signature, and saying `Unsigned` would be a claim \
             about a file that does not exist"
        );

        let changes = manifest.verify().expect("verify");
        assert!(
            !changes
                .iter()
                .any(|change| same_dir(change.path(), &database_in_install)),
            "a file that was absent and is still absent is not a change: {:?}",
            changes
                .iter()
                .map(Change::describe)
                .collect::<Vec<_>>()
        );

        // Now let it appear, which is the change that matters.
        std::fs::write(&database_in_install, b"a database in the other place")
            .expect("writes the second database location");
        let changes = manifest.verify().expect("verify");
        let appeared = changes
            .iter()
            .find(|change| same_dir(change.path(), &database_in_install))
            .expect("the file that appeared is reported");
        assert!(matches!(appeared, Change::Added { .. }), "{appeared:?}");

        // And this one is alarming where a stray file is not, which is the
        // distinction `Change::is_alarming` draws and the reason the field
        // exists. The manifest made a claim about this path — that nothing is
        // there — and the claim is now false.
        assert!(
            appeared.is_alarming(),
            "a file where an entry records that nothing is has to alarm, or a rule database \
             dropped in the first place the loader looks would be reported as a readme: {}",
            appeared.describe()
        );
        assert!(
            appeared.describe().starts_with("APPEARED:"),
            "and it must not be described in the words of the other kind of addition: {}",
            appeared.describe()
        );
    }

    #[test]
    fn a_manifest_survives_a_write_and_a_read_and_refuses_one_it_cannot_read() {
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let path = manifest_path(&layout.paths);

        manifest.save(&path).expect("saves");
        let loaded = Manifest::load(&path).expect("loads what it saved");
        assert_eq!(
            loaded, manifest,
            "a round trip through bincode has to give back the same manifest, or the digests it \
             compares are not the digests it recorded"
        );
        assert!(loaded.matches_roots(&layout.paths));
        assert!(loaded.describe().contains("install"), "{}", loaded.describe());
        // The manifest is not reported as an unexpected file in its own
        // directory, which is the one thing the derived path is for.
        assert!(
            loaded.verify().expect("verify").is_empty(),
            "saving the manifest must not make the next check report it"
        );

        // A file that is not a manifest, named as one.
        let broken = layout.paths.data_dir.join("broken.manifest");
        std::fs::write(&broken, b"this is not bincode").expect("writes a non-manifest");
        let error = Manifest::load(&broken).expect_err("refuses it");
        assert!(error.contains("not a manifest"), "{error}");
        assert!(error.contains("wenle protect manifest"), "{error}");

        // A manifest from a build that wrote a different version.
        let mut future = manifest.clone();
        future.version = MANIFEST_VERSION + 1;
        let future_path = layout.paths.data_dir.join("future.manifest");
        future.save(&future_path).expect("saves");
        let error = Manifest::load(&future_path).expect_err("refuses a version it does not know");
        assert!(error.contains("version"), "{error}");
        assert!(error.contains("protect manifest"), "{error}");

        // And nothing at all, which is the state of a fresh installation and
        // gets a sentence naming the command that fixes it.
        let error = Manifest::load(&layout.paths.data_dir.join("nothing.manifest"))
            .expect_err("there is nothing there");
        assert!(error.contains("there is no manifest"), "{error}");
    }

    #[test]
    fn a_manifest_from_another_installation_is_refused_rather_than_believed() {
        // Continuing would report every file missing and every file unexpected,
        // and the reader would have no way to tell that the manifest was the
        // problem. This is the one error `self_check` returns.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let elsewhere = AvPaths::with_data_dir(
            layout.paths.install_dir.join("moved"),
            layout.paths.data_dir.join("moved"),
        );
        assert!(!manifest.matches_roots(&elsewhere));
        let mismatch = manifest.roots.describe_mismatch(&elsewhere);
        assert!(mismatch.contains("install directory"), "{mismatch}");
        assert!(mismatch.contains("data directory"), "{mismatch}");
        // And the same layout in a different spelling is not a mismatch: Windows
        // paths are case-insensitive and a trailing separator is not a
        // difference.
        let shouty = AvPaths::with_data_dir(
            layout.paths.install_dir.to_string_lossy().to_uppercase(),
            format!("{}\\", layout.paths.data_dir.display()),
        );
        assert!(
            manifest.matches_roots(&shouty),
            "the comparison folds case and trailing separators, so a manifest is not refused for \
             how its paths were spelled"
        );
    }

    #[test]
    fn a_service_that_would_not_come_back_is_not_a_clean_check() {
        // The wiring this pins, found on 2026-10-10 by reading `wenle protect
        // status` output against its own exit code: `is_clean` asked only
        // whether the service *could be read*, so a machine whose service was
        // stopped, or was demand-start, or had no recovery policy at all,
        // printed a line saying exactly that and then reported the machine as
        // fully protected. The service half is the whole of what changed, so it
        // is replaced by hand here rather than depending on whatever service
        // this machine happens to have installed.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        manifest
            .save(&manifest_path(&layout.paths))
            .expect("saves");
        let mut check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("the manifest was taken for this layout");
        assert!(matches!(check.manifest, ManifestState::Loaded(_)));
        assert!(check.changes.is_empty());

        let harden = |start, recovery, running| {
            Ok(ServiceIntegrity {
                name: "WenleAvService".to_string(),
                start,
                recovery,
                account: "LocalSystem".to_string(),
                running,
                description: None,
            })
        };

        // The one the report called healthy while printing that it had no
        // recovery policy: running, automatic, and nothing to restart it.
        check.service = harden(service::StartKind::Automatic, None, true);
        assert!(
            !check.is_clean(),
            "a service with no recovery policy is not a machine that is protected: {}",
            check.describe()
        );

        // A policy that is there and would not restart anything is the same
        // finding, and this is the shape `Recovery::is_recoverable` refuses.
        check.service = harden(
            service::StartKind::Automatic,
            Some(service::Recovery {
                delays: [std::time::Duration::ZERO; 3],
                reset_after: std::time::Duration::from_secs(60),
                on_non_crash_failure: true,
            }),
            true,
        );
        assert!(!check.is_clean(), "a policy of three zero delays recovers nothing");

        // The two states that were already supposed to fail and did not, for
        // the same reason: neither of them is a service this product can rely
        // on, and `describe_why_not_protected` has had a clause for each all
        // along.
        check.service = harden(service::StartKind::Manual, Some(service::DEFAULT_RECOVERY), true);
        assert!(!check.is_clean(), "a demand-start service is not running after a reboot");
        check.service = harden(service::StartKind::Automatic, Some(service::DEFAULT_RECOVERY), false);
        assert!(!check.is_clean(), "a stopped service is not protecting anything now");

        // And the positive control, without which every assertion above would
        // pass for a check that never returns true at all.
        check.service = harden(service::StartKind::Automatic, Some(service::DEFAULT_RECOVERY), true);
        assert!(
            check.is_clean(),
            "a running, automatic, recoverable service over a clean manifest is the state this \
             check exists to recognise: {}",
            check.describe()
        );
    }

    /// A file that is not the product's is reported and is not a hole.
    ///
    /// The VM's own machine on 2026-10-10, as a test: `wenle protect status`
    /// there printed twenty `UNEXPECTED` lines and ended "This machine is not
    /// fully protected: 20 of the product's own files have changed" — over
    /// `README.md`, `WenleAV-vm.bat`, `wenle-test-driver.cer` and seventeen
    /// copies of earlier binaries that the user had made. Not one of them was
    /// ever a file of this product's, and not one of the product's files had
    /// changed.
    ///
    /// The two halves of the change are both asserted here: such a file must
    /// reach the report (`changes` is not empty, and the heading says what they
    /// are) and must not reach [`SelfCheck::is_clean`].
    #[test]
    fn a_file_that_is_not_the_products_is_reported_and_is_not_a_hole() {
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        manifest
            .save(&manifest_path(&layout.paths))
            .expect("saves");
        std::fs::write(layout.paths.install_dir.join("README.md"), b"notes beside the program")
            .expect("drops a file in");
        std::fs::write(
            layout.paths.install_dir.join("wenle.exe.before-yesterdays-change"),
            b"an older build kept in case the new one misbehaves",
        )
        .expect("drops the kept copy in");

        let mut check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("the manifest was taken for this layout");
        assert_eq!(check.changes.len(), 2, "{}", check.describe());
        assert!(
            !check.has_alarming_changes(),
            "neither of these was ever the product's: {}",
            check.describe()
        );

        // The heading says which kind of difference these are, because the
        // count alone would read as two of the product's files having changed.
        let text = check.describe();
        assert!(
            text.contains("2 file(s) that are not the product's"),
            "the heading has to name the kind: {text}"
        );
        assert!(
            !text.contains("difference(s)"),
            "and not call them differences, which is what they are not: {text}"
        );

        // The service half is replaced by hand for the reason the test above
        // gives: what this test is about is the file half.
        check.service = Ok(ServiceIntegrity {
            name: "WenleAvService".to_string(),
            start: service::StartKind::Automatic,
            recovery: Some(service::DEFAULT_RECOVERY),
            account: "LocalSystem".to_string(),
            running: true,
            description: None,
        });
        assert!(
            check.is_clean(),
            "files that were never the product's do not make a machine unprotected — the manifest \
             was compared and every file it names is intact: {}",
            check.describe()
        );

        // The positive control for the other direction: change one of the
        // product's own files as well and the same check fails, so what the
        // assertion above shows is `is_alarming` rather than a check that has
        // stopped looking.
        std::fs::write(layout.paths.install_dir.join("wenle.exe"), b"a different program\n")
            .expect("rewrites the cli stand-in");
        let check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("the manifest is still for this layout");
        assert!(check.has_alarming_changes());
        assert!(!check.is_clean());
        assert!(
            check.describe().contains("1 difference(s), and 2 file(s) that are not the product's"),
            "{}",
            check.describe()
        );
    }

    #[test]
    fn the_self_check_reports_every_answer_including_the_ones_that_failed() {
        // With no manifest: present, honest, and naming the command that fixes
        // it — and still reporting the debugger and the service, because the
        // point of the check is to be run on a machine somebody is worried
        // about, and one missing answer must not hide the others.
        let layout = Layout::new();
        let check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("a missing manifest is a state and not an error");
        assert!(matches!(check.manifest, ManifestState::Absent));
        assert!(check.changes.is_empty());
        assert!(!check.is_clean(), "no manifest is not clean");
        assert!(!check.has_alarming_changes());
        let text = check.describe();
        assert!(text.contains("No manifest"), "{text}");
        assert!(text.contains("wenle protect manifest"), "{text}");
        assert!(text.contains("Debugger:"), "{text}");
        assert!(
            text.contains("Service: could not be read"),
            "the service does not exist on this machine, and the report has to say so rather than \
             leaving the line out: {text}"
        );
        // The debugger answer is always produced, even when nothing else can be.
        assert!(
            check.debugger.checks_that_answered() >= 1,
            "`IsDebuggerPresent` always answers: {:?}",
            check.debugger
        );
        assert_eq!(check.debugger.is_present(), debugger_present());

        // With a manifest: clean, and say so.
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        manifest
            .save(&manifest_path(&layout.paths))
            .expect("saves");
        let check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("the manifest was taken for this layout");
        assert!(matches!(check.manifest, ManifestState::Loaded(_)));
        assert!(check.changes.is_empty());
        assert!(check.describe().contains("unchanged"), "{}", check.describe());

        // And with a manifest that has been invalidated: the change is reported
        // even though the service line still fails.
        std::fs::write(
            layout.paths.install_dir.join("wenle.exe"),
            b"# something else entirely now\n",
        )
        .expect("rewrites the cli stand-in");
        let check = self_check(&layout.paths, "WenleAvServiceGuardTestDoesNotExist")
            .expect("the manifest is still for this layout");
        assert!(check.has_alarming_changes());
        assert!(!check.is_clean());
        assert!(check.describe().contains("difference(s)"), "{}", check.describe());

        // And a manifest for another installation is the one error.
        let elsewhere = AvPaths::with_data_dir(
            layout.paths.install_dir.join("gone"),
            layout.paths.data_dir.clone(),
        );
        let error = self_check(&elsewhere, "WenleAvServiceGuardTestDoesNotExist")
            .expect_err("a manifest for another installation is refused");
        assert!(error.contains("different installation"), "{error}");
        assert!(error.contains("wenle protect manifest"), "{error}");
    }

    #[test]
    fn a_file_that_should_be_a_program_and_is_not_is_a_finding_not_a_shrug() {
        // `Undetermined` and `Unsigned` are different answers and the comparison
        // has to keep them apart: a replaced binary that reads as "could not
        // tell" would be a report that hedges about the one thing it must be
        // certain of.
        let trusted = Signature::Trusted {
            subject: "CN=A".to_string(),
            thumbprint: "aa".to_string(),
        };
        let other = Signature::Trusted {
            subject: "CN=B".to_string(),
            thumbprint: "bb".to_string(),
        };
        let untrusted = Signature::Untrusted {
            subject: "CN=B".to_string(),
            thumbprint: "bb".to_string(),
        };

        assert_eq!(
            SignatureChange::between(&trusted, &trusted),
            SignatureChange::Unchanged
        );
        assert_eq!(
            SignatureChange::between(&trusted, &other),
            SignatureChange::DifferentlySigned {
                from: "aa".to_string(),
                to: "bb".to_string(),
            }
        );
        assert_eq!(
            SignatureChange::between(&trusted, &Signature::Unsigned),
            SignatureChange::NowUnsigned
        );
        assert_eq!(
            SignatureChange::between(&Signature::Unsigned, &trusted),
            SignatureChange::NewlySigned {
                to: "aa".to_string()
            }
        );
        assert_eq!(
            SignatureChange::between(
                &trusted,
                &Signature::Invalid {
                    reason: "digest_mismatch".to_string()
                }
            ),
            SignatureChange::NowInvalid
        );
        // A chain that reaches no trusted root is still a signer, and a
        // replacement by a self-signed certificate is a *different signer* rather
        // than an unsigned file.
        assert_eq!(
            SignatureChange::between(&trusted, &untrusted),
            SignatureChange::DifferentlySigned {
                from: "aa".to_string(),
                to: "bb".to_string(),
            }
        );
        // Anything involving a state that could not be read says so.
        let unknown = Signature::Undetermined {
            reason: "not_pe".to_string(),
        };
        assert!(matches!(
            SignatureChange::between(&trusted, &unknown),
            SignatureChange::Unknown { .. }
        ));
        assert!(matches!(
            SignatureChange::between(&unknown, &trusted),
            SignatureChange::Unknown { .. }
        ));
        // The two "no signer" states are not confused with an unreadable one.
        assert_eq!(
            SignatureChange::between(&Signature::NotAProgram, &Signature::NotAProgram),
            SignatureChange::Unchanged
        );
        assert_eq!(
            SignatureChange::between(&Signature::Unsigned, &Signature::Unsigned),
            SignatureChange::Unchanged
        );
        // A file that was already invalid before the manifest was taken is not
        // reported as newly invalid: the digest changed, the signature did not.
        assert_eq!(
            SignatureChange::between(
                &Signature::Invalid {
                    reason: "digest_mismatch".to_string()
                },
                &Signature::Invalid {
                    reason: "digest_mismatch".to_string()
                }
            ),
            SignatureChange::Unchanged
        );

        // Every state and every change has a sentence.
        for state in [
            trusted.clone(),
            untrusted,
            Signature::Invalid {
                reason: "digest_mismatch".to_string(),
            },
            Signature::Unsigned,
            Signature::NotAProgram,
            unknown,
        ] {
            assert!(!state.describe().is_empty(), "{state:?}");
        }
        for change in [
            SignatureChange::Unchanged,
            SignatureChange::NowUnsigned,
            SignatureChange::NowInvalid,
            SignatureChange::DifferentlySigned {
                from: "aa".to_string(),
                to: "bb".to_string(),
            },
            SignatureChange::NewlySigned {
                to: "aa".to_string(),
            },
            SignatureChange::Unknown {
                before: "aa".to_string(),
                after: "bb".to_string(),
            },
        ] {
            assert!(!change.describe().is_empty(), "{change:?}");
        }
        assert!(!SignatureChange::Unchanged.is_alarming());
        assert!(SignatureChange::NowUnsigned.is_alarming());
    }

    #[test]
    fn every_role_names_its_file_and_says_whether_it_is_a_program() {
        let layout = Layout::new();
        assert_eq!(Role::ALL.len(), 6);
        // The database is the one role with two locations, because the loader
        // has always had a two-place lookup; every other role has exactly one.
        for role in Role::ALL {
            let paths = role.paths_in(&layout.paths);
            assert!(!paths.is_empty(), "{role:?}");
            assert!(!role.describe().is_empty(), "{role:?}");
            if role != Role::Database {
                assert_eq!(paths.len(), 1, "{role:?}");
                assert!(role.is_program(), "{role:?}");
                assert!(
                    paths[0].starts_with(&layout.paths.install_dir),
                    "{role:?} lives in the install directory: {:?}",
                    paths[0]
                );
            } else {
                assert_eq!(paths.len(), 2, "the loader looks in two places");
                assert!(!role.is_program(), "a rule database is not a program");
                assert!(paths[0].starts_with(&layout.paths.db_dir));
                assert!(paths[1].starts_with(&layout.paths.install_dir));
            }
        }
        // The names are the ones the rest of the workspace uses; a rename that
        // missed this list shows up as a missing entry beside an unexpected
        // file, which is visible rather than silent.
        assert_eq!(
            Role::Service.paths_in(&layout.paths)[0].file_name().unwrap(),
            "wenle-av-service.exe"
        );
        assert_eq!(
            Role::Cli.paths_in(&layout.paths)[0].file_name().unwrap(),
            "wenle.exe"
        );
        assert_eq!(
            Role::Gui.paths_in(&layout.paths)[0].file_name().unwrap(),
            "wenle-gui.exe"
        );
        assert_eq!(
            Role::Database.paths_in(&layout.paths)[0].file_name().unwrap(),
            "rules.avdb"
        );
        // The AMSI provider's name, and the reason this assertion is worth
        // having: this string is the second copy of `av-amsi`'s `DLL_NAME` — the
        // first is in `av-amsi/src/registration.rs` — and a rename that reached
        // only one of them would register a provider the manifest does not
        // check, or check a file nothing registers.
        assert_eq!(
            Role::Amsi.paths_in(&layout.paths)[0].file_name().unwrap(),
            "av_amsi.dll"
        );
    }

    /// The kernel's write gate and this crate's own statement of what the
    /// product ships name the same files.
    ///
    /// `av_driver_proto::PROTECTED_FILES` is the list the minifilter refuses a
    /// write to, and [`Role::paths_in`] is the list the manifest covers, the
    /// installer copies and `wenle protect` audits. They are two lists because
    /// the driver cannot depend on this crate — it compiles into a kernel and
    /// this one does not — and the failure they can drift into is the quiet
    /// kind: a file added to the product, covered by the manifest, and left
    /// writable by anyone because nobody added it to the second list.
    ///
    /// This test is that drift's alarm. It is the *only* thing tying the two
    /// lists together, which is why it compares sets in both directions rather
    /// than spot-checking names: a test that only asserted every role is in
    /// `PROTECTED_FILES` would still pass after a name was added to the gate
    /// that no role ships.
    #[test]
    fn the_kernels_write_gate_protects_exactly_the_files_this_product_ships() {
        let layout = Layout::new();
        let mut from_roles: Vec<String> = Role::ALL
            .iter()
            .flat_map(|role| role.paths_in(&layout.paths))
            .map(|path| {
                path.file_name()
                    .expect("every role's path names a file")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        // `Database` names `rules.avdb` twice, in the two places the loader
        // looks. The gate matches a file name inside the installation
        // directory, so one entry there covers both.
        from_roles.sort();
        from_roles.dedup();

        let mut from_gate: Vec<String> =
            av_driver_proto::PROTECTED_FILES.iter().map(|name| (*name).to_owned()).collect();
        from_gate.sort();

        assert_eq!(
            from_gate, from_roles,
            "the driver's write gate and the product's own file list disagree; \
             a file in one and not the other is either unprotected or \
             unaccounted for"
        );
    }

    #[test]
    fn the_added_file_scan_stops_at_the_ceiling_and_says_that_it_did() {
        // A directory filled with junk must not produce a report nobody can
        // read. The ceiling is what stops it, and the count that was dropped is
        // logged rather than silently discarded.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        for index in 0..MAX_ADDED_PER_DIRECTORY + 10 {
            std::fs::write(
                layout.paths.install_dir.join(format!("junk{index:04}.dll")),
                b"junk",
            )
            .expect("drops a file in");
        }
        let changes = manifest.verify().expect("verify");
        let added = changes
            .iter()
            .filter(|change| matches!(change, Change::Added { .. }))
            .count();
        assert_eq!(
            added, MAX_ADDED_PER_DIRECTORY,
            "the report lists the ceiling and no more, so that the entries that matter are not \
             buried"
        );
    }

    #[test]
    fn a_database_whose_length_changed_is_resized_rather_than_modified() {
        // The two kinds of change are told apart by whether the length moved, and
        // a rule database is the file where that distinction is most useful: a
        // truncated database is a broken product and an edited one of the same
        // length is somebody rewriting rules.
        let layout = Layout::new();
        let manifest = Manifest::capture(&layout.paths).expect("capture");
        let database = layout.paths.db_dir.join("rules.avdb");
        let mut bytes = std::fs::read(&database).expect("reads the database stand-in");
        bytes.truncate(bytes.len() / 2);
        std::fs::write(&database, &bytes).expect("truncates the database stand-in");

        let changes = manifest.verify().expect("verify");
        let change = changes
            .iter()
            .find(|change| same_dir(change.path(), &database))
            .expect("the truncated database is reported");
        assert!(
            matches!(change, Change::Resized { .. }),
            "a length change is `Resized` and not `Modified`: {change:?}"
        );
        let Change::Resized { role, signature, .. } = change else {
            unreachable!("just matched")
        };
        assert_eq!(*role, Role::Database);
        assert_eq!(
            *signature,
            SignatureChange::Unchanged,
            "a database is not a program, so there is no signature comparison to report — and \
             reporting `Unknown` here would be noise on the one file that is never signed"
        );
        assert!(change.describe().contains("rule database"), "{change:?}");
    }

    #[test]
    fn the_path_comparison_folds_case_and_separators_and_nothing_else() {
        // It is a comparison of two paths the product computed, not a filesystem
        // question, so it must be textual — and it must not fold so much that two
        // different directories compare equal.
        assert!(same_dir(Path::new(r"C:\A\B"), Path::new(r"c:/a/b")));
        assert!(same_dir(Path::new(r"C:\A\B\"), Path::new(r"C:\A\B")));
        assert!(same_dir(Path::new(r"C:\A\.\B"), Path::new(r"C:\A\B")));
        assert!(same_dir(Path::new(r"C:\A\C\..\B"), Path::new(r"C:\A\B")));
        assert!(!same_dir(Path::new(r"C:\A\B"), Path::new(r"C:\A\BC")));
        assert!(!same_dir(Path::new(r"C:\A\B"), Path::new(r"C:\AB")));
        assert!(!same_dir(
            Path::new(r"C:\Program Files\WenleAV"),
            Path::new(r"C:\Program Files\WenleAV2")
        ));
        // And the digest helper is the lower-case hex a person compares against
        // `certutil`, not the upper-case one.
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(
            hex(&[0u8; 32]),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
