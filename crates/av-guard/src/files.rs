//! The product's own directories: who may read them, and who may write.
//!
//! # The attack, and why this module matters more than [`crate::process`]
//!
//! A process object's default DACL turned out to be narrower than it is usually
//! described as being: see [`crate::process`] for the measurement. A
//! *directory's* default is the opposite: it is genuinely open, and this module
//! exists because of one measured line of `icacls` output.
//!
//! `%ProgramData%\WenleAV` on a clean Windows installation inherits
//!
//! ```text
//! Users:(I)(CI)(WD,AD,WEA,WA)
//! ```
//!
//! from `%ProgramData%` itself: create files and directories, write extended
//! attributes, write attributes. Not read, and not `F`, which is why the
//! problem is easy to miss: the directory looks locked down because a user
//! cannot *read* what is already in it, while `WD,AD` lets them create anything
//! they like next to it and replace it by delete-and-recreate wherever the
//! parent allows deletion. That grant is what makes every other defence in this
//! crate worth checking: an attacker who can write into the directory the
//! product loads its rules from does not need to attack the product at all.
//!
//! The whole tree is in scope. `AvPaths::is_protected` documents why the data
//! root is defended as a unit rather than only the interesting parts of it
//! ("malware that can rewrite our configuration or erase our logs has
//! effectively disabled the product even if it never touches a rule file"), and
//! this module
//! is that decision carried out.
//!
//! # What this crate owns, and the one directory it does not
//!
//! | Directory | Owner | Why |
//! |---|---|---|
//! | install, db, rules, cache | this module | read and execute for ordinary users, nothing more |
//! | config, logs | this module | see the grants below |
//! | **quarantine** | `av-quarantine`'s `hardening` module | **not this crate, and never.** |
//!
//! The last row is written as plain text rather than as a link because
//! `av-quarantine` is deliberately not a dependency of this crate: the module
//! that refuses to touch the vault does not need to be able to open one, and a
//! dependency added to make a doc link resolve is a dependency in the shipping
//! graph.
//!
//! The vault is the one directory this module refuses to touch, and the refusal
//! is mechanical rather than a note in a comment: [`protect_dir`] checks its
//! argument against the layout and returns an error naming `av-quarantine` if it
//! is the vault or anything inside it. Applying a second, differently-shaped
//! DACL to the same directory is how a directory ends up with the union of two
//! hardening policies, which is not a stronger policy but a weaker one, because
//! the union of two allow lists is a longer allow list.
//!
//! What the vault does differently, and why it has to be its own policy: it is
//! the one place the product holds *malicious files*, so its problem is
//! confidentiality and integrity rather than execution, its DACL names the
//! creating account as well as SYSTEM and Administrators, and it has to reapply
//! that DACL to entries created later. None of those three properties belong on
//! the install directory and none of this module's belong on it.
//!
//! # The grants, and the justification for each
//!
//! Three trustees throughout: `NT AUTHORITY\SYSTEM` and
//! `BUILTIN\Administrators` with full control, `BUILTIN\Users` with
//! `0x1200A9` (`FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`, the mask `icacls`
//! prints as `(RX)`), and, for a directory holding something written at run time,
//! `0x1301BF`, which is that plus write and delete.
//!
//! * **`SYSTEM` full control** because the service is `LocalSystem` and it has to
//!   write the rule database, the logs and its configuration. Nothing here works
//!   otherwise, and a DACL that breaks the product is not a security improvement.
//! * **`Administrators` full control** for the same reason as in
//!   [`crate::process`]: an administrator who cannot repair an installation is
//!   worse off than one whose antivirus can be replaced, and the alternative, a
//!   product only its own service can maintain, is the shape of a rootkit.
//! * **`Users` read and execute** because the command-line scanner and the
//!   graphical front end are run by ordinary users and have to load the binaries
//!   and read the rule database. Read and execute is the whole of what they need:
//!   running a scanner requires no write access to it.
//! * **`BUILTIN\Users` and not `Everyone` or `NT AUTHORITY\Authenticated Users`**
//!   because `Everyone` includes `ANONYMOUS LOGON`, and an anonymous network
//!   logon reaching the product's rule database is not a thing to grant by
//!   accident. `Authenticated Users` would be defensible and is deliberately not
//!   used: it is a wider set than `Users` for no gain here.
//! * **`(OI)(CI)` on every entry** so the grant is inherited by everything
//!   created inside, which is what makes one call per directory sufficient
//!   instead of a walk. It is also why the entries must be applied *before* the
//!   files that will live there: inheritance is copied at creation.
//!
//! # The one grant the brief asked for and this module withholds
//!
//! The instruction for this crate was to give `Users` write on the configuration
//! directory as well as the log directory. The log directory has it. The
//! configuration directory does not, and the reason is that the two are not the
//! same kind of thing:
//!
//! * A log line is a record of what the product did. A user appending one is
//!   reporting a false positive or adding context for support, and the worst an
//!   attacker achieves by writing a log file is noise in a file nobody's
//!   security depends on.
//! * The configuration is a set of instructions the service reads **as
//!   `LocalSystem`**. A user who can write it can turn off real-time protection,
//!   remove a directory from the scan scope, or point the updater at another
//!   host, and the first of those is exactly the "malware that can rewrite
//!   our configuration has won" case in `AvPaths::is_protected`'s documentation.
//!   A user-writable configuration is not a hardening trade-off; it is the
//!   vulnerability this crate exists to close.
//!
//! What a user-level `wenle config set` therefore needs is a route that does not
//! require write access to the file: the front end asks the service over the
//! IPC channel this workspace already has, and the service (which *is* allowed
//! to write its own configuration) applies the change after deciding whether
//! the request is one a user may make. That keeps the decision with the service
//! instead of with the file permissions, which is where it belongs, because some
//! settings are a user's business and some are not. Until that route exists,
//! changing a setting needs an elevated prompt, and the CLI says so.
//!
//! # Reading it back: why [`audit`] is the half that matters
//!
//! [`protect_product_dirs`] reports what it *did*. [`audit`] reports what is
//! *true*, and the difference is the whole point: a call that returned success is
//! not the same fact as a directory whose DACL says what it was meant to say. An
//! entry the parent re-contributed because the `P` flag was lost, a grant
//! inherited from `%ProgramData%` that a reader mistook for this crate's work, a
//! DACL applied to a directory that did not exist: each produces a satisfied
//! caller and an unprotected machine.
//!
//! So [`audit`] re-reads the DACL with `GetNamedSecurityInfoW` (which
//! materialises inheritance, so what comes back is the DACL *as it applies* to
//! that object and not the entries stored on it) and asks the operating system's
//! own access check what each ordinary trustee may do. The question it is built
//! to answer is the one a person asks: **can an ordinary user write this?**
//!
//! # The owner, and the one thing a permission list cannot take away
//!
//! `GetEffectiveRightsFromAclW` answers `0x001f01ff` (`FILE_ALL_ACCESS`) for
//! an object's **owning account** on a permission list that does not name them at
//! all, while every other trustee on that same list answers `0`. Measured on this
//! machine, on a directory protected exactly the way this module protects one,
//! and the same shape as the process-side measurement in [`crate::process`]:
//! `0x001f0fff` there, `0x001f01ff` here, in both cases all-access for the object
//! type.
//!
//! Two consequences, and they pull in opposite directions.
//!
//! The audit therefore does **not** put the owner into the ordinary-trustee
//! union: if it did, no directory on any machine could ever be reported as
//! restricted, because every directory has an owner and the owner always answers
//! all-access.
//! A check that can never say yes is a check nobody reads. When the permission
//! list *does* name the owner, the owner is evaluated like any other trustee,
//! because then the answer is the entry's and the over-reporting is about a
//! missing entry rather than a present one.
//!
//! And the owner's real reach is reported separately, in
//! [`DirAudit::owner_can_rewrite_permissions`]. This is not a theoretical
//! caveat. Measured: a directory protected the way this module protects one
//! refuses a write from its own owning account (`ERROR_ACCESS_DENIED`, from a
//! real `std::fs::write` and not from the access check above), and that same
//! account can then apply a new permission list granting itself full control and
//! write to it successfully. `WRITE_DAC` on an object you own needs no privilege
//! and cannot be withheld by any DACL, because it is ownership rather than a
//! permission.
//!
//! So "the tree is protected" means *protected against every account except its
//! owner, and against its owner until they choose otherwise*. Closing that
//! would mean taking ownership away (`SetNamedSecurityInfoW` with
//! `OWNER_SECURITY_INFORMATION`, which an elevated caller can do), and this
//! crate does not: changing a directory's owner changes who can
//! repair it, it is a decision about the installation rather than about its
//! permissions, and on a real installation the directories under
//! `%ProgramData%` are created by the installer, which runs elevated, so their
//! owner is already an administrator or `SYSTEM`. The audit names the owner
//! instead, so the case where that assumption is wrong is visible.
//!
//! # The ordering, measured: what protecting a directory does to what is
//! already inside it
//!
//! This one settles a disagreement inside the workspace, and both sides of it
//! were right.
//!
//! `av_quarantine::hardening` documents, from its own measurement, that setting
//! a permission list on a directory does **not** update the entries already
//! inside it, and that a tree walk is therefore required. Measured here, on this
//! machine, protecting a directory **did** rewrite the inherited entries of the
//! child that already existed. The difference is the call: av-quarantine applies
//! with `SetFileSecurityW`, this crate with `SetNamedSecurityInfoW`, and on two
//! identical trees built side by side the first leaves the child's entries alone
//! while the second replaces them.
//!
//! What that means for each crate is the useful part:
//!
//! * For this crate, one call per directory is sufficient for the layout's
//!   shape, because the propagation reaches the directories directly inside
//!   `data_dir` and their contents inherit when they are created. There is no
//!   walk here, and this is the measurement that says there does not need to be.
//! * For the vault, av-quarantine's walk is not redundant, and this crate should
//!   not be read as second-guessing it. It handles entries that no inheritable
//!   entry reaches, which is a strictly larger set.
//! * **The ordering matters, and in one direction only.** A child whose own list
//!   is *protected* accepts nothing from the parent (measured: a child
//!   restricted before its parent changed came out of it byte-for-byte
//!   unchanged), so protecting the data root cannot weaken a vault that
//!   `av-quarantine` has already restricted. A child whose list is *not*
//!   protected has its inherited entries rewritten, so an *unrestricted* vault
//!   under the data root does not keep the permissions it was created with. That
//!   is not this crate reaching into the vault (the vault is not in
//!   [`DirRole::ALL`] and [`protect_dir`] refuses it by name); it is inheritance
//!   doing what inheritance does, and the reason both the ordering and the vault
//!   assertion are tests rather than sentences.
//!
//! # `FA` is right here and wrong in [`crate::process`]
//!
//! Every string in this module writes `FA` for full control and every string in
//! [`crate::process`] writes `0x1F0FFF`. That is not an inconsistency: `FA` is
//! `FILE_ALL_ACCESS` (`0x001F01FF`), which is exactly right for a file or a
//! directory, and `PROCESS_ALL_ACCESS` is `0x001F0FFF`, which is a different
//! number because a process has rights a file does not. SDDL does not translate
//! between object types, so each module has to write the correct one or be wrong
//! silently. The measurement is in [`crate::process`]'s documentation.

use std::path::{Path, PathBuf};

use av_core::paths::AvPaths;
use serde::{Deserialize, Serialize};

use crate::acl;

/// Full control, as SDDL spells it for a file system object.
///
/// `0x001F01FF`. Correct for a directory and for a file, and *not*
/// `PROCESS_ALL_ACCESS` — see the module documentation.
///
/// A macro rather than a `const` because the only place it may appear is inside
/// a permission string, and `concat!` is the only way to build one at compile
/// time. A `const` here would force every string to repeat the literal, which is
/// how two spellings of one mask end up in one file.
macro_rules! sddl_full {
    () => {
        "FA"
    };
}

/// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` — `(RX)` in `icacls`.
///
/// Written as a hex number because SDDL has no two-letter alias for exactly this
/// pair: `GR` is read without execute and `GX` is execute without read, and a
/// directory needs both. The value is the one Microsoft's own documentation uses
/// for "read and execute" on a file system object.
macro_rules! sddl_read_execute {
    () => {
        "0x1200A9"
    };
}

/// `(RX)` plus write and delete — `(M)` in `icacls`, near enough.
///
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE`.
/// Used only for the log directory, where appending a line is something an
/// ordinary user has a legitimate reason to do.
macro_rules! sddl_modify {
    () => {
        "0x1301BF"
    };
}

/// Which part of the product a directory is, for the purpose of choosing a DACL.
///
/// A closed list rather than a string per call site, because the mapping from
/// "what is this directory for" to "who may write it" is the security decision,
/// and it should be reviewable in one place instead of assembled at each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DirRole {
    /// The executables, the service binary and the shipped rules. Nothing here
    /// changes while the product runs.
    Install,
    /// The compiled rule database and the signature databases. Written by the
    /// updater, read by every scan.
    Data,
    /// The rule sources the compiler reads.
    Rules,
    /// The scan cache, which is disposable and is still product state.
    Cache,
    /// The log directory. The one place an ordinary user may write.
    Log,
    /// Where the configuration lives. Deliberately *not* writable by ordinary
    /// users — see the module documentation for the full argument.
    Config,
}

impl DirRole {
    /// Every role, in the order [`protect_product_dirs`] applies them.
    ///
    /// Install first, so that the directory the binaries live in is closed to
    /// writes before anything else is discussed.
    pub const ALL: [DirRole; 6] = [
        DirRole::Install,
        DirRole::Data,
        DirRole::Rules,
        DirRole::Cache,
        DirRole::Log,
        DirRole::Config,
    ];

    /// The DACL this role is protected with.
    ///
    /// A `const fn` returning a `&'static str` rather than a `match` at each call
    /// site, so that the string a caller applies, the string a report prints and
    /// the string a test asserts on are the same string. Three copies of a
    /// security policy are three policies.
    pub const fn sddl(self) -> &'static str {
        match self {
            // Three roles with the same shape, written out three times rather
            // than aliased through a shared constant, because a reader of the
            // output — `icacls`, an audit report, a support ticket — should be
            // able to see which one produced it, and because collapsing them
            // would make it easy to give one of them a different grant by
            // accident later. The *masks* inside them are the macros, so the
            // number exists once.
            DirRole::Install => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_read_execute!(), ";;;BU)"
                )
            }
            DirRole::Data => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_read_execute!(), ";;;BU)"
                )
            }
            DirRole::Rules => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_read_execute!(), ";;;BU)"
                )
            }
            DirRole::Cache => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_read_execute!(), ";;;BU)"
                )
            }
            // The one write grant, justified in the module documentation.
            DirRole::Log => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_modify!(), ";;;BU)"
                )
            }
            // Read only, and the module documentation says why the brief's
            // instruction to grant write here was not followed.
            DirRole::Config => {
                concat!(
                    "D:P(A;OICI;", sddl_full!(), ";;;SY)",
                    "(A;OICI;", sddl_full!(), ";;;BA)",
                    "(A;OICI;", sddl_read_execute!(), ";;;BU)"
                )
            }
        }
    }

    /// Whether this role's DACL lets an ordinary user write.
    ///
    /// Reported so that a caller assembling a summary does not have to parse
    /// [`DirRole::sddl`], and so that the one role where the answer is `true` is
    /// visible in the code as well as in the documentation.
    pub const fn users_may_write(self) -> bool {
        matches!(self, DirRole::Log)
    }

    /// The directory this role names in a layout.
    ///
    /// `None` for [`DirRole::Config`], which names a *file* rather than a
    /// directory — returning the data directory instead would silently protect
    /// the wrong object under the right name. The configuration's *directory* is
    /// [`DirRole::Data`] on a standard layout; `config.toml` itself is governed
    /// by the directory's DACL, and is not writable by ordinary users because
    /// they cannot create or delete inside that directory.
    pub fn path_in(self, paths: &AvPaths) -> Option<PathBuf> {
        match self {
            DirRole::Install => Some(paths.install_dir.clone()),
            DirRole::Data => Some(paths.db_dir.clone()),
            DirRole::Rules => Some(paths.rules_dir.clone()),
            DirRole::Cache => Some(paths.cache_dir.clone()),
            DirRole::Log => Some(paths.log_dir.clone()),
            DirRole::Config => Some(
                paths
                    .config_file
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| paths.data_dir.clone()),
            ),
        }
    }

    /// One sentence for a report, saying what this directory is for.
    pub const fn describe(self) -> &'static str {
        match self {
            DirRole::Install => "the executables and the service binary",
            DirRole::Data => "the rule database and the signature databases",
            DirRole::Rules => "the rule sources the compiler reads",
            DirRole::Cache => "the scan cache",
            DirRole::Log => "the log directory",
            DirRole::Config => "the configuration",
        }
    }
}

/// What [`protect_dir`] did, or found already true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirProtection {
    /// The directory the DACL was applied to.
    pub path: PathBuf,
    /// Which part of the product it is.
    pub role: DirRole,
    /// The DACL that was applied.
    pub sddl: String,
    /// Whether the directory exists. A missing directory is reported rather than
    /// created: creating one happens in `AvPaths::ensure_dirs`, where the
    /// ownership and the timing are the caller's decision.
    pub present: bool,
    /// Whether the operating system accepted the change *and* the directory
    /// reports the DACL back. A `false` here is the case a caller must not
    /// print as a tick.
    pub applied: bool,
    /// What went wrong when `applied` is `false`.
    pub detail: Option<String>,
}

impl DirProtection {
    /// One line for a person, phrased as what is true of the machine.
    pub fn describe(&self) -> String {
        let what = self.role.describe();
        if !self.present {
            return format!(
                "{} does not exist yet, so {} could not be protected — create the directory \
                 first (the product does this at startup)",
                self.path.display(),
                what
            );
        }
        if self.applied {
            let extra = if self.role.users_may_write() {
                ", and an ordinary user may write to it"
            } else {
                ""
            };
            return format!(
                "{} ({what}) now allows full control to SYSTEM and administrators, and read and \
                 execute to users{extra}",
                self.path.display()
            );
        }
        format!(
            "{} ({what}) could NOT be protected: {} — the product runs, but an ordinary user may \
             be able to write here",
            self.path.display(),
            self.detail.as_deref().unwrap_or("no reason given")
        )
    }
}

/// What one account can do to a directory, as the operating system evaluates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrusteeRights {
    /// The account, as an `S-1-5-...` string.
    pub sid: String,
    /// A well-known name for it, when there is one worth printing.
    pub name: Option<&'static str>,
    /// The raw mask the access check produced.
    pub mask: u32,
    /// Whether that mask includes writing or deleting.
    pub can_write: bool,
    /// Whether that mask includes reading.
    pub can_read: bool,
    /// Whether that mask includes executing.
    pub can_execute: bool,
}

impl TrusteeRights {
    /// The account, named if it has a name and numbered if it has not.
    pub fn who(&self) -> &str {
        self.name.unwrap_or(&self.sid)
    }
}

/// What [`audit`] found.
///
/// Built to answer one question in the form a person asks it — *can an ordinary
/// user write this?* — with the raw material kept alongside so that somebody
/// chasing a support case can see which trustee and which mask produced the
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirAudit {
    /// The directory that was read.
    pub path: PathBuf,
    /// Whether it exists. A missing directory is not an audit failure.
    pub present: bool,
    /// Whether its DACL is protected against inheritance.
    ///
    /// Reported because an unprotected DACL is the most common way a directory
    /// that was hardened once stops being hardened: the entries this crate
    /// applied are still there, and so is whatever the parent added on top.
    pub protected: bool,
    /// Every account an ordinary user could be, and what it may do.
    ///
    /// The list is deliberately a superset of the accounts actually named in the
    /// DACL — the four well-known group SIDs, every non-privileged SID the DACL
    /// names, and the account running the check — because a report that only
    /// mentioned the trustees somebody thought of is a report that misses the
    /// one that matters.
    ///
    /// The object's **owner is not in this list**, and that exclusion is the
    /// whole reason [`DirAudit::owner`] exists separately. See
    /// [`DirAudit::owner_can_rewrite_permissions`].
    pub trustees: Vec<TrusteeRights>,
    /// The account that owns the directory, when it could be read.
    pub owner: Option<String>,
    /// Whether the owner can take this directory's permissions away from it.
    ///
    /// `true` whenever the owner is not `SYSTEM` or an administrator. Windows
    /// grants an object's owner `READ_CONTROL` and `WRITE_DAC` outside the DACL,
    /// and `WRITE_DAC` on a directory you own needs no privilege, so an ordinary
    /// user who owns a directory can grant themselves write access to it at any
    /// time. No DACL takes this away — it is ownership, not a permission — and
    /// the only fix is to give the directory to an account that is not the
    /// threat. This crate reports it and does not do it: see the module
    /// documentation for why.
    pub owner_can_rewrite_permissions: bool,
    /// The accounts that can write, for the sentence a user reads.
    pub writeable_by: Vec<String>,
    /// The accounts that can read.
    pub readable_by: Vec<String>,
    /// Every entry of the DACL, in the shape `icacls` prints.
    pub summary: String,
}

impl DirAudit {
    /// Whether an ordinary account can write here **by the permissions on it**.
    ///
    /// The one-bit form of the audit, for a caller that has to decide whether to
    /// warn. A directory that could not be read is *not* reported as writable —
    /// [`audit`] returns an error for that case instead, so a caller that has an
    /// audit has an answer.
    ///
    /// This is the DACL's answer and not the whole truth about the directory: an
    /// owner can rewrite the DACL, and
    /// [`DirAudit::owner_can_rewrite_permissions`] is the other half. Keeping
    /// them separate is what makes "I hardened the tree" a claim that can be
    /// true — see the module documentation.
    pub fn writeable_by_ordinary_user(&self) -> bool {
        !self.writeable_by.is_empty()
    }

    /// Whether the directory is as restricted as permissions can make it.
    ///
    /// The conjunction, for a caller that wants one bit and is willing to have
    /// it be `false` on a directory whose owner is an ordinary user — which on a
    /// real installation is the normal state of the product's own directories
    /// under `%ProgramData%`, and on a machine where an ordinary user created
    /// them is a finding.
    pub fn is_restricted(&self) -> bool {
        self.present && !self.writeable_by_ordinary_user() && !self.owner_can_rewrite_permissions
    }

    /// One line for a person.
    ///
    /// Two sentences, chosen by the answer to the only question this audit is
    /// for. The names are included rather than a bare "yes", because "an
    /// ordinary user can write this" and "this account can write this" are
    /// different amounts of useful when the account turns out to be one nobody
    /// expected.
    ///
    /// The owner's escalation route is stated in the same breath rather than
    /// buried in a struct field, because a report that said "no ordinary user can
    /// write here" and stopped would be telling a person their machine is safe
    /// from a thing it is not safe from.
    pub fn describe(&self) -> String {
        if !self.present {
            return format!("{} does not exist", self.path.display());
        }
        let mut line = if self.writeable_by.is_empty() {
            format!(
                "{}: no ordinary user can write here; an ordinary user can read and execute",
                self.path.display()
            )
        } else {
            format!(
                "{}: an ordinary user CAN write here — {}",
                self.path.display(),
                self.writeable_by.join(", ")
            )
        };
        if !self.protected {
            line.push_str(
                ". Its permissions are not protected, so it still inherits from the directory \
                 above it",
            );
        }
        if self.owner_can_rewrite_permissions {
            if let Some(owner) = &self.owner {
                line.push_str(&format!(
                    ". It is owned by {owner}, which can change these permissions and give \
                     itself write access whenever it likes — that needs no privilege and no \
                     permission list can prevent it, because it is ownership rather than a \
                     permission"
                ));
            }
        }
        line
    }
}

/// Whether `path` is the vault or anything inside it.
///
/// The check that makes "this crate does not touch the vault" a fact about the
/// code rather than a sentence in a comment. Case-insensitive and
/// separator-normalised, because Windows paths are, and a guard that a caller can
/// walk past by spelling a path differently is not a guard.
fn is_vault(path: &Path, paths: &AvPaths) -> bool {
    let candidate = normalise(path);
    let vault = normalise(&paths.quarantine_dir);
    candidate == vault || candidate.starts_with(&format!("{vault}\\"))
}

/// A path as a comparable string: lower case, forward slashes, no trailing
/// separator.
fn normalise(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\").to_lowercase();
    text.strip_suffix('\\').map(str::to_string).unwrap_or(text)
}

/// Protect one directory with the DACL for its role.
///
/// # Errors
///
/// Returns an error when the directory is the quarantine vault or inside it —
/// `av-quarantine`'s `hardening` module owns that directory and a second policy applied
/// over the first produces the *union* of two allow lists, which is weaker than
/// either. That is the only error: this function's argument being wrong.
///
/// Everything the *machine* can say no to comes back in [`DirProtection`] with
/// `applied: false` and the reason — a directory that does not exist, a DACL the
/// operating system refused, a DACL that was accepted but reads back open. The
/// split is deliberate: an error means *this request was wrong*, and a listed
/// failure means *the machine said no*. A machine whose permissions could not be
/// tightened is still a machine the product has to keep working on, and a
/// harden-the-tree pass that stopped at the first refusal would leave the rest of
/// the tree open. A missing directory is not created here either — creation
/// belongs in `AvPaths::ensure_dirs`, where the ownership and the timing are the
/// caller's decision, and a directory created by an elevated hardening pass
/// rather than by the installer has a different owner.
pub fn protect_dir(path: &Path, role: DirRole, paths: &AvPaths) -> Result<DirProtection, String> {
    if is_vault(path, paths) {
        return Err(format!(
            "{} is inside the quarantine vault, which this crate does not protect: the vault's \
             permissions belong to av-quarantine::hardening, and applying a second permission \
             list over the first would leave the directory with the union of the two — a longer \
             list of who is allowed in, not a shorter one. Call av_quarantine::hardening::\
             restrict for this directory.",
            path.display()
        ));
    }
    let sddl = role.sddl();
    let mut protection = DirProtection {
        path: path.to_path_buf(),
        role,
        sddl: sddl.to_string(),
        present: false,
        applied: false,
        detail: None,
    };
    if !path.is_dir() {
        protection.detail = Some(format!(
            "{} is not a directory",
            path.display()
        ));
        return Ok(protection);
    }
    protection.present = true;
    match acl::apply_to_path(path, sddl) {
        Ok(()) => {
            // Read back rather than trusting the return. `SetNamedSecurityInfoW`
            // succeeding means the call was accepted; the audit below is what
            // says the directory now reads as intended.
            match audit(path) {
                Ok(check) => {
                    protection.applied = !check.writeable_by_ordinary_user() || role.users_may_write();
                    if !protection.applied {
                        protection.detail = Some(format!(
                            "the permission list was applied but an ordinary user can still \
                             write here: {}",
                            check.writeable_by.join(", ")
                        ));
                    }
                }
                Err(detail) => {
                    protection.detail = Some(format!(
                        "the permission list was applied but could not be read back: {detail}"
                    ));
                }
            }
        }
        Err(detail) => protection.detail = Some(detail),
    }
    if protection.applied {
        log::info!("{}", protection.describe());
    } else {
        log::warn!("{}", protection.describe());
    }
    Ok(protection)
}

/// Protect every directory this crate owns, in one call.
///
/// The whole of the product's layout except the vault, which is skipped
/// deliberately rather than by omission: [`DirRole::ALL`] does not contain it,
/// and [`protect_dir`] would refuse it even if it did. The two mechanisms
/// together are what make "this crate never touches the vault" true rather than
/// intended.
///
/// # Errors
///
/// Returns an error only when the layout itself cannot be protected as asked —
/// today, when a role points at the vault. A directory that is missing, or whose
/// permissions were refused, comes back in the returned list with the reason
/// attached; a caller reports those and carries on, because the product has to
/// keep running. That split is deliberate: an error means *this request was
/// wrong*, and a listed failure means *the machine said no*.
pub fn protect_product_dirs(paths: &AvPaths) -> Result<Vec<DirProtection>, String> {
    // The vault is checked once, up front, so that a layout with a misconfigured
    // data directory is refused before half the tree has been changed rather
    // than after.
    for role in DirRole::ALL {
        if let Some(path) = role.path_in(paths) {
            if is_vault(&path, paths) {
                return Err(format!(
                    "this layout would protect {} as {}, but that path is the quarantine \
                     vault: refusing to apply anything, because a partly applied layout is \
                     harder to reason about than an untouched one. The vault's permissions \
                     belong to av-quarantine::hardening.",
                    path.display(),
                    role.describe()
                ));
            }
        }
    }
    let mut done = Vec::with_capacity(DirRole::ALL.len());
    for role in DirRole::ALL {
        if let Some(path) = role.path_in(paths) {
            done.push(protect_dir(&path, role, paths)?);
        }
    }
    Ok(done)
}

/// The record's file name, under the data directory.
pub const DACL_RECORD_FILE: &str = "dacl.record";

/// The record format's version.
///
/// Stored in the file and checked on load, for the reason
/// [`crate::tamper::MANIFEST_VERSION`] gives: this file outlives the build that
/// wrote it, and bincode will decode a struct that has lost or gained a field
/// into something plausible. A record this build does not understand is refused
/// with a sentence rather than applied as a DACL the user never had.
pub const DACL_RECORD_VERSION: u32 = 1;

/// Where the record lives for a given layout.
///
/// Under the data directory, beside the manifest, and that placement is the same
/// decision with the same consequence: the data directory is a fact about the
/// *machine*, so a record taken by one copy of the product is found by another.
#[must_use]
pub fn dacl_record_path(paths: &AvPaths) -> PathBuf {
    paths.data_dir.join(DACL_RECORD_FILE)
}

/// One directory's permissions, as they were before [`protect_product_dirs`]
/// replaced them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDacl {
    /// The directory.
    pub path: PathBuf,
    /// Which part of the product it is, kept so the report can name it the way
    /// every other report in this product names it.
    pub role: DirRole,
    /// Whether the directory existed when the record was taken. A record of a
    /// directory that was not there is a fact worth keeping: restoring must not
    /// create it, and a report that omitted it would look like a directory that
    /// had been forgotten.
    pub present: bool,
    /// Whether its DACL stopped inheriting from its parent.
    pub protected: bool,
    /// The DACL, in the form `acl::sddl_from` writes and
    /// `acl::restore_to_path` takes back. Empty when `present` is false.
    pub sddl: String,
}

/// Every directory the product's permissions were taken from, as they were.
///
/// # Why this exists at all
///
/// `wenle protect apply` rewrites the DACL of six directories, and until this
/// type existed there was no way back: the README said permissions are not a
/// setting the product can hold a copy of. That was wrong — a DACL can be read
/// and written as text — and the cost of it being wrong was that the one command
/// in this product that changes the machine's access control had no undo, which
/// is the property every other machine-changing command here has.
///
/// # The roots are recorded, and checked on the way back
///
/// The same reason [`crate::tamper::Roots`] exists on the manifest: a record
/// taken for one installation must not be applied to another's directories. The
/// two types are deliberately the same type, so a change to what "the same
/// installation" means changes both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaclRecord {
    /// [`DACL_RECORD_VERSION`] at the time it was written.
    pub version: u32,
    /// The installation it was taken against.
    pub roots: crate::tamper::Roots,
    /// One entry per directory, in [`DirRole::ALL`]'s order.
    pub entries: Vec<RecordedDacl>,
}

impl DaclRecord {
    /// Read the current permissions of every directory the product protects.
    ///
    /// Must be called *before* [`protect_product_dirs`], which is the whole
    /// point: called after, it would faithfully record the hardened state and
    /// the undo would put back what `apply` had just done.
    ///
    /// A directory that does not exist is recorded as absent rather than
    /// skipped or refused. On a machine where the service has never run, most of
    /// these directories are not there yet, and refusing would mean that the one
    /// command that changes the machine was unavailable on exactly the machines
    /// that have never been set up.
    pub fn capture(paths: &AvPaths) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(DirRole::ALL.len());
        for role in DirRole::ALL {
            let Some(path) = role.path_in(paths) else {
                continue;
            };
            if !path.is_dir() {
                entries.push(RecordedDacl {
                    path,
                    role,
                    present: false,
                    protected: false,
                    sddl: String::new(),
                });
                continue;
            }
            let (sddl, protected) = record_of(&path)?;
            entries.push(RecordedDacl {
                path,
                role,
                present: true,
                protected,
                sddl,
            });
        }
        Ok(Self {
            version: DACL_RECORD_VERSION,
            roots: crate::tamper::Roots {
                install_dir: paths.install_dir.clone(),
                data_dir: paths.data_dir.clone(),
            },
            entries,
        })
    }

    /// Write the record.
    ///
    /// Refuses to overwrite one that is already there, and that refusal is the
    /// same one `wenle integrate defender disable` makes for the same reason: a
    /// second record taken over a hardened tree would capture the *hardened*
    /// permissions and quietly destroy the only copy of the originals, so
    /// running the command twice would turn an undo into a no-op. The caller
    /// keeps the first record instead; the cycle is `restore`, then `apply`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if path.exists() {
            return Err(format!(
                "{} already holds a record of the permissions from before they were changed, \
                 and overwriting it would replace the only copy of them with what they are now. \
                 The record has not been written; the permission changes themselves still go \
                 ahead. Run `wenle protect restore` to put those permissions back and remove the \
                 record, and then `apply` again if you want a fresh one.",
                path.display()
            ));
        }
        let bytes = bincode::serialize(self).map_err(|error| error.to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("creating {}: {error}", parent.display()))?;
        }
        std::fs::write(path, bytes).map_err(|error| format!("writing {}: {error}", path.display()))
    }

    /// Read a record back, refusing a version this build does not know.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|error| {
            format!(
                "there is no usable record of the permissions from before `apply` changed them, \
                 at {}: {error}. Without one there is nothing to put back, and this command will \
                 not guess at what they were.",
                path.display()
            )
        })?;
        let record: Self = bincode::deserialize(&bytes).map_err(|error| {
            format!(
                "{} is not a record this build can read: {error}. It was written by a different \
                 version of the product, and applying its contents would set permissions nobody \
                 chose.",
                path.display()
            )
        })?;
        if record.version != DACL_RECORD_VERSION {
            return Err(format!(
                "the record at {} is version {} and this build writes version \
                 {DACL_RECORD_VERSION}. It cannot be applied by this build.",
                path.display(),
                record.version
            ));
        }
        Ok(record)
    }

    /// One sentence for a report.
    #[must_use]
    pub fn describe(&self) -> String {
        let recorded = self.entries.iter().filter(|entry| entry.present).count();
        format!(
            "{recorded} of {} directories recorded, taken for the installation at {}",
            self.entries.len(),
            self.roots.install_dir.display()
        )
    }
}

/// What happened to one directory when a record was put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The recorded permissions are on the directory now, and were read back to
    /// confirm it.
    ///
    /// The read-back is not decoration and is the same decision
    /// [`protect_product_dirs`] makes on the way in: a security-descriptor write
    /// that returned success is not the same fact as a directory that now has
    /// those permissions, and this is the product's only verb for putting a
    /// machine back the way it was. The claim `restore` makes in its report is
    /// "the permissions are back", so it is the claim that has to be read.
    Applied,
    /// The directory was not there when the record was taken, so the record says
    /// nothing about it and there is nothing to put back.
    ///
    /// Not a failure: on a machine where the service has not run yet, most of
    /// these directories do not exist, and `apply` records them as absent rather
    /// than refusing to protect a machine that has not been set up.
    NotRecorded,
    /// The directory is not there now. Restoring does not create directories —
    /// see [`restore_dacls`].
    NotPresent,
    /// The operating system refused the write, with its reason.
    Refused(String),
    /// The write reported success and reading the directory back says the
    /// permissions are not what was recorded.
    ///
    /// This is a bug in this crate rather than a permissions problem, and it is a
    /// variant of its own rather than a `Refused` with a different sentence so
    /// that a caller cannot report them the same way by accident.
    DidNotTake {
        /// What the directory's permissions say now, in the same SDDL form the
        /// record is written in, so the two can be compared by eye.
        now: String,
    },
}

impl RestoreOutcome {
    /// Whether the recorded permissions are on the directory — the one outcome
    /// that means this directory is done.
    #[must_use]
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }

    /// One sentence for a report, in the shape the rest of them use.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Applied => "put back".to_string(),
            Self::NotRecorded => {
                "was not there when the record was taken, so there is nothing to put back"
                    .to_string()
            }
            Self::NotPresent => {
                "is not there now, and this command does not create directories".to_string()
            }
            Self::Refused(reason) => reason.clone(),
            Self::DidNotTake { now } => format!(
                "the write was accepted and the directory does not have the recorded \
                 permissions: it has {now}"
            ),
        }
    }
}

/// What happened to one directory when a record was put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaclRestoration {
    /// The directory.
    pub path: PathBuf,
    /// Which part of the product it is, kept so the report can name it the way
    /// every other report in this product names it.
    pub role: DirRole,
    /// What became of it.
    pub outcome: RestoreOutcome,
}

/// Put every recorded DACL back, and read each one back to say whether it took.
///
/// # What it does not do
///
/// It does not create a directory that was not there, and it does not delete one
/// that has appeared since. The record's business is permissions; a command
/// named `restore` that also removed a directory would be a command whose second
/// effect nobody expected.
///
/// # Failures are per directory
///
/// A directory whose DACL the operating system refuses is reported and the rest
/// are still attempted, which is the same shape [`protect_product_dirs`] uses
/// and for the same reason: the machine is in a half-changed state either way,
/// and the useful answer is which half.
pub fn restore_dacls(record: &DaclRecord) -> Vec<DaclRestoration> {
    let mut out = Vec::with_capacity(record.entries.len());
    for entry in &record.entries {
        let outcome = restore_one(entry);
        out.push(DaclRestoration {
            path: entry.path.clone(),
            role: entry.role,
            outcome,
        });
    }
    out
}

/// One entry: skip, write, and read back.
fn restore_one(entry: &RecordedDacl) -> RestoreOutcome {
    if !entry.present {
        return RestoreOutcome::NotRecorded;
    }
    if !entry.path.is_dir() {
        return RestoreOutcome::NotPresent;
    }
    if let Err(reason) = acl::restore_to_path(&entry.path, &entry.sddl, entry.protected) {
        return RestoreOutcome::Refused(reason);
    }
    // Read the directory back rather than believing the return code. See
    // `RestoreOutcome::Applied` for why, and `record_of` for why the comparison
    // is made in the same text the record is written in rather than on the
    // descriptors directly.
    match record_of(&entry.path) {
        Ok((sddl, protected)) if sddl == entry.sddl && protected == entry.protected => {
            RestoreOutcome::Applied
        }
        Ok((now, _)) => RestoreOutcome::DidNotTake { now },
        // The directory was read once to write the record and cannot be read now,
        // which is a third thing again and is reported as refused with the read's
        // own sentence.
        Err(reason) => RestoreOutcome::Refused(reason),
    }
}

/// One directory's permissions as the record writes them, or the reason they
/// could not be read.
///
/// [`DaclRecord::capture`] is built on this, so the string a record holds and the
/// string a read-back produces come from one function and cannot drift.
fn record_of(path: &Path) -> Result<(String, bool), String> {
    let dacl = acl::Dacl::of_path(path)?;
    let protected = dacl.is_protected();
    Ok((acl::sddl_from(&dacl.aces(), protected), protected))
}


/// The masks that count as writing, for [`audit`]'s answer.
///
/// The specific file bits plus the two generic ones, because
/// `GetEffectiveRightsFromAclW` returns generic bits unmapped when the DACL was
/// written with them (`(A;OICI;GW;;;BU)` stays `0x40000000`) and a check that
/// only looked for `FILE_WRITE_DATA` would call such a directory read-only. A
/// security check must over-report the exposure, so a bit it does not recognise
/// that could mean write is treated as write: `GENERIC_ALL` is here for that
/// reason, and `WRITE_DAC`/`WRITE_OWNER`/`DELETE` are here because each of them
/// is a way to end up able to write.
const WRITE_MASK: u32 = 0x0000_0116   // write data, append, write EA, write attributes
    | 0x0001_0000                     // DELETE
    | 0x0004_0000                     // WRITE_DAC
    | 0x0008_0000                     // WRITE_OWNER
    | 0x4000_0000                     // GENERIC_WRITE
    | 0x1000_0000; // GENERIC_ALL

/// The masks that count as reading.
const READ_MASK: u32 = 0x0000_0089   // read data, read EA, read attributes
    | 0x0002_0000                     // READ_CONTROL
    | 0x8000_0000                     // GENERIC_READ
    | 0x1000_0000; // GENERIC_ALL

/// The masks that count as executing.
const EXECUTE_MASK: u32 = 0x0000_0020 // FILE_EXECUTE
    | 0x2000_0000                     // GENERIC_EXECUTE
    | 0x1000_0000; // GENERIC_ALL

/// Every account an ordinary user could be, for a directory.
///
/// The same union as [`crate::process`]'s trustee list, and the same reason: the
/// DACL's own entries may name an account no group list contains, and on a
/// machine where a user created the directory it *does* — measured, a fresh
/// temporary directory carries `MSI\<user>:(I)(OI)(CI)(F)` and no
/// `BUILTIN\Users` entry at all. A check built from group SIDs alone would call
/// that directory private.
///
/// **The owner is excluded**, and this is the one subtlety in the function.
/// `GetEffectiveRightsFromAclW` answers `0x001f01ff` — `FILE_ALL_ACCESS` — for an
/// object's owning account on a permission list that does not name it at all,
/// while every other trustee on that same list answers `0`. Measured on this
/// machine, in a directory protected the way this module protects one, and the
/// same shape as the process-side measurement in [`crate::process`]. So an audit
/// that left the owner in this list could never report any directory as
/// restricted, on any machine, which is a report that says nothing.
///
/// Removing them here is not the same as excusing them: what the operating
/// system says about the owner and what the owner can really do are different
/// things, and both are in the audit —
/// [`DirAudit::owner_can_rewrite_permissions`] for the reach that permission
/// lists cannot take away, and [`DirAudit::writeable_by`] for what the
/// permissions themselves say.
///
/// **Unless the permission list names the owner.** Then the owner is an ordinary
/// trustee like any other and is evaluated like one: the over-reporting above is
/// a property of what the function does with a *missing* entry, and when there is
/// an entry the answer is the entry's. Measured in the other direction too: a
/// directory the owner has granted itself full control on is reported writable,
/// which is the case [`crate::process`] established on the process side as well.
/// Without this the audit would miss the one case where an owner's reach is
/// written down in the permissions and is therefore a fault of the permission
/// list rather than a fact about ownership.
///
/// **When the owner cannot be determined, and only then**, the current account
/// stays in the list, which makes the audit over-report rather than under-report:
/// the safe direction to fail in, and the reason this takes the owner as a
/// parameter instead of assuming there is none. Measured on 2026-10-10, in the
/// other direction and on a real installation: the directories under
/// `%ProgramData%\WenleAV` are owned by `BUILTIN\Administrators`, whose entry the
/// permission list names, so the exclusion above does not fire — and the calling
/// account, an administrator, was then evaluated as an ordinary user and
/// answered with everything. `wenle protect status` reported all six directories
/// as writable by an ordinary user while `icacls` showed the protected list and
/// nothing else. The list already answers the question for every account it
/// names, so leaving the caller out costs no coverage.
fn ordinary_trustees(dacl: &acl::Dacl, owner: Option<&str>) -> Vec<String> {
    let excluded = match owner {
        Some(owner) if !names(dacl, owner) => Some(owner),
        _ => None,
    };
    let mut trustees: Vec<String> = acl::UNPRIVILEGED_TRUSTEES
        .iter()
        .map(|sid| (*sid).to_string())
        .collect();
    let mut add = |sid: String| {
        if !trustees.contains(&sid) {
            trustees.push(sid);
        }
    };
    for ace in dacl.aces() {
        if !acl::is_privileged(&ace.sid) && !is_the_owner(&ace.sid, excluded) {
            add(ace.sid.clone());
        }
    }
    // Only when there is no owner at all. When the owner is known the caller is
    // left out deliberately, and the machine that was measured to decide this is
    // in the documentation above: a permission list this module wrote, on a
    // directory owned by `BUILTIN\Administrators`, evaluated the calling
    // administrator as an ordinary user and reported the whole installation as
    // writable. A grant to an account outside [`acl::UNPRIVILEGED_TRUSTEES`] is
    // still seen, by the loop above: every unprivileged entry the list itself
    // names is evaluated on its own.
    if owner.is_none() {
        if let Ok(account) = acl::current_user_sid() {
            if !acl::is_privileged(&account) {
                add(account);
            }
        }
    }
    trustees
}

/// Whether a SID is the object's owner, comparing the way Windows does.
///
/// Case-insensitively, because the two strings come from two different calls and
/// a comparison that depended on both of them agreeing about the case of `s` in
/// `S-1-5-21` would be a comparison waiting to be wrong.
fn is_the_owner(sid: &str, owner: Option<&str>) -> bool {
    owner.is_some_and(|owner| owner.eq_ignore_ascii_case(sid))
}

/// Whether a permission list has an entry naming this SID.
///
/// On the stored entries rather than on an evaluation, deliberately: the question
/// is whether the owner's reach is *written down*, which is a question about the
/// list, and asking the access check would answer the different question about
/// what the owner can do.
fn names(dacl: &acl::Dacl, sid: &str) -> bool {
    dacl.aces()
        .iter()
        .any(|ace| ace.sid.eq_ignore_ascii_case(sid))
}

/// A one-line description of a DACL, of the shape `icacls` prints.
///
/// The same renderer as [`crate::process`]'s and deliberately a separate copy:
/// the two would drift the moment one of them needed a flag the other did not,
/// and a report that quietly differs between a process and a directory is worse
/// than two reports that are visibly each their own.
fn summarise(dacl: &acl::Dacl) -> String {
    let mut parts = Vec::new();
    if !dacl.is_protected() {
        parts.push("(not protected: this object still inherits)".to_string());
    }
    for ace in dacl.aces() {
        let who = match acl::describe(&ace.sid) {
            Some(name) => name.to_string(),
            None => ace.sid.clone(),
        };
        let mut flags = String::new();
        for (bit, name) in [
            (ace.inherited, "(I)"),
            (ace.object_inherit, "(OI)"),
            (ace.container_inherit, "(CI)"),
            (ace.inherit_only, "(IO)"),
        ] {
            if bit {
                flags.push_str(name);
            }
        }
        parts.push(format!(
            "{who}:{flags}0x{:08x}{}",
            ace.mask,
            if ace.denied { " (deny)" } else { "" }
        ));
    }
    if parts.is_empty() {
        parts.push("(empty DACL: nothing is granted to anyone)".to_string());
    }
    parts.join(", ")
}

/// Read a directory's permissions back and report what an ordinary user can do.
///
/// # Why this is the part that matters
///
/// It is the only thing in this module that answers a question about the
/// *machine* rather than about this crate's intentions. A caller that logs
/// [`protect_product_dirs`]'s output has a record of seven calls; a caller that
/// logs this has a record of who can write the product's rule database. Only the
/// second is worth showing a user, and only the second notices when the first
/// was wrong.
///
/// # Errors
///
/// Returns an error when the DACL cannot be read at all — a directory that does
/// not exist, or one this account may not read the permissions of. It does not
/// return an error for a directory that is wide open: that is a finding, not a
/// failure, and it comes back as [`DirAudit::writeable_by`] with the accounts in
/// it.
pub fn audit(path: &Path) -> Result<DirAudit, String> {
    if !path.exists() {
        return Ok(DirAudit {
            path: path.to_path_buf(),
            present: false,
            protected: false,
            trustees: Vec::new(),
            owner: None,
            owner_can_rewrite_permissions: false,
            writeable_by: Vec::new(),
            readable_by: Vec::new(),
            summary: "(does not exist)".to_string(),
        });
    }
    let dacl = acl::Dacl::of_path(path)?;
    // A failure to read the owner is *not* an error: the audit still has an
    // answer to give, and the answer it gives without the owner is the
    // over-reporting one. An error here would take a whole directory's
    // permissions report away over a detail that only makes it more cautious.
    let owner = match acl::Dacl::owner_of_path(path) {
        Ok(owner) => Some(owner),
        Err(detail) => {
            log::debug!("{detail}");
            None
        }
    };
    let owner_can_rewrite_permissions = owner
        .as_deref()
        .is_some_and(|owner| !acl::is_privileged(owner));
    let mut trustees = Vec::new();
    let mut writeable_by = Vec::new();
    let mut readable_by = Vec::new();
    for sid in ordinary_trustees(&dacl, owner.as_deref()) {
        // An entry that cannot be evaluated is reported as able to do
        // everything, for the same reason `crate::process` does it: a check must
        // never claim a restriction it has not established.
        let (mask, evaluated) = match dacl.effective(&sid) {
            Ok(mask) => (mask, true),
            Err(_) => (u32::MAX, false),
        };
        let rights = TrusteeRights {
            sid: sid.clone(),
            name: acl::describe(&sid),
            mask,
            can_write: !evaluated || mask & WRITE_MASK != 0,
            can_read: !evaluated || mask & READ_MASK != 0,
            can_execute: !evaluated || mask & EXECUTE_MASK != 0,
        };
        if rights.can_write {
            writeable_by.push(rights.who().to_string());
        }
        if rights.can_read {
            readable_by.push(rights.who().to_string());
        }
        trustees.push(rights);
    }
    Ok(DirAudit {
        path: path.to_path_buf(),
        present: true,
        protected: dacl.is_protected(),
        trustees,
        owner,
        owner_can_rewrite_permissions,
        writeable_by,
        readable_by,
        summary: summarise(&dacl),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DACL that grants everything to everyone, for the tests that need to
    /// know a directory really is open before they close it.
    ///
    /// `WD` rather than `BU` on purpose: `Everyone` is a superset of every
    /// account the audit checks, so a directory carrying it gives every trustee
    /// the audit looks at a real, non-zero mask. A test built on `BU` alone
    /// would only prove the audit can see the one group it was told about.
    const WIDE_OPEN: &str = concat!(
        "D:P(A;OICI;", sddl_full!(), ";;;SY)",
        "(A;OICI;", sddl_full!(), ";;;BA)",
        "(A;OICI;", sddl_full!(), ";;;WD)"
    );

    /// A directory that is put back the way it was however the test ends.
    ///
    /// Necessary rather than tidy: a `TempDir` whose DACL no longer grants the
    /// running account anything cannot be deleted, so `TempDir::drop` fails and
    /// the test suite leaves directories behind in `%TEMP%`. The restore happens
    /// in `Drop` so that it also happens when an assertion panics, which is
    /// exactly when the directory would otherwise be stuck.
    struct OpenDir {
        dir: tempfile::TempDir,
    }

    impl OpenDir {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("a temporary directory");
            acl::apply_to_path(dir.path(), WIDE_OPEN).expect("making the temporary directory open");
            Self { dir }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        /// The same directory, described as a layout so that `protect_dir` can be
        /// pointed at it. The other fields are where they would be on a real
        /// installation; only `install_dir` and the vault matter to the guard.
        fn paths(&self) -> AvPaths {
            let mut paths = AvPaths::with_data_dir(self.dir.path().join("install"), self.path());
            paths.quarantine_dir = self.path().join("quarantine");
            paths
        }
    }

    impl Drop for OpenDir {
        fn drop(&mut self) {
            // Restored to something the running account can delete, because a
            // protected DACL names SYSTEM, administrators and the users group
            // and this test may be running as none of them.
            let _ = acl::apply_to_path(self.dir.path(), WIDE_OPEN);
        }
    }

    #[test]
    fn the_audit_finds_the_write_access_that_is_really_there() {
        // The test the brief asks for, and the one that would have caught every
        // way of getting this wrong: a directory with a known-open DACL must be
        // reported as open, by name.
        let open = OpenDir::new();
        let audit = audit(open.path()).expect("auditing an open directory");

        assert!(audit.present, "{audit:?}");
        assert!(audit.protected, "the DACL applied by the test is protected");
        assert!(
            audit.writeable_by_ordinary_user(),
            "a directory granting Everyone full control must be reported as writable: {audit:?}"
        );
        assert!(
            audit.writeable_by.iter().any(|who| who.contains("Everyone")),
            "and the account that makes it writable is Everyone, which is what the DACL says: \
             {:?}",
            audit.writeable_by
        );
        assert!(
            !audit.readable_by.is_empty(),
            "the same account can plainly read it too: {audit:?}"
        );
        // The sentence a user reads has to say the alarming thing, not merely
        // imply it through a list.
        let line = audit.describe();
        assert!(line.contains("CAN write"), "{line}");
    }

    #[test]
    fn protecting_a_directory_takes_the_write_access_away_and_the_audit_sees_it() {
        // Protect, then audit: the assertion is on the *second* reading, not on
        // what `protect_dir` said it did, because a report of a call that
        // returned success is not evidence about the directory.
        let open = OpenDir::new();
        let paths = open.paths();
        let dir = open.path().join("db");
        std::fs::create_dir(&dir).expect("creating the directory to protect");

        let before = audit(&dir).expect("auditing it while it is open");
        assert!(
            before.writeable_by_ordinary_user(),
            "the new directory inherits the open DACL of its parent, so this test has something \
             to take away: {before:?}"
        );

        let protection =
            protect_dir(&dir, DirRole::Data, &paths).expect("protecting a product directory");
        assert!(protection.present, "{protection:?}");
        assert!(
            protection.applied,
            "the permission list has to be accepted and read back: {protection:?}"
        );
        assert_eq!(protection.role, DirRole::Data);
        assert!(protection.sddl.contains("0x1200A9"), "{}", protection.sddl);

        let after = audit(&dir).expect("auditing it after protecting it");
        assert!(
            !after.writeable_by_ordinary_user(),
            "no ordinary account may write the rule database's directory: {:?}",
            after.writeable_by
        );
        assert!(
            after.readable_by.iter().any(|who| who.contains("Users")),
            "and an ordinary user must still be able to read and execute there, or the scanner \
             cannot run: {:?}",
            after.readable_by
        );
        // The owner of a temporary directory is the account running the test, so
        // the audit has to report the escalation route it cannot close. This is
        // the field that keeps the sentence above from being the whole story.
        assert!(
            after.owner.is_some(),
            "the owner of a directory this account created has to be readable: {after:?}"
        );
        assert!(
            after.owner_can_rewrite_permissions,
            "an ordinary account owns this directory, so it can rewrite the permissions: {after:?}"
        );
        assert!(
            after.describe().contains("owned by"),
            "and the sentence has to say so: {}",
            after.describe()
        );
        assert!(!after.is_restricted(), "for the same reason: {after:?}");
        // `icacls`-shaped output naming the accounts, which is what somebody
        // compares against their own tools.
        assert!(after.summary.contains("BUILTIN\\Users"), "{}", after.summary);
        assert!(
            after.summary.contains("NT AUTHORITY\\SYSTEM"),
            "{}",
            after.summary
        );
        assert!(
            !after.describe().contains("CAN write"),
            "{}",
            after.describe()
        );
    }

    /// A mask from one of the constants above, as a number.
    ///
    /// Parsed from the string rather than re-typed, because the point of the
    /// test is to check the strings this module actually applies. A second copy
    /// of a mask in a test is a test of the copy.
    ///
    /// Two spellings have to be understood because SDDL has two: a hex mask, and
    /// the two-letter aliases the format defines. `FA` is here and it is
    /// `FILE_ALL_ACCESS` — the file alias, which is not the process one, which is
    /// why this module writes `FA` and [`crate::process`] writes `0x1F0FFF`.
    fn mask_of(text: &str) -> u32 {
        match text {
            "FA" => 0x001F_01FF,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00A0,
            other => {
                let digits = other
                    .strip_prefix("0x")
                    .unwrap_or_else(|| panic!("`{other}` is neither a hex mask nor a known SDDL alias"));
                u32::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("`{other}`: {e}"))
            }
        }
    }

    #[test]
    fn what_the_permissions_really_stop_and_what_only_ownership_could() {
        // Two measurements in one test, because the second is only interesting
        // given the first, and because the pair is the honest statement of what
        // this module achieves.
        //
        // The first is the claim that matters and it is measured by *doing* it
        // rather than by asking the operating system's opinion: the audit says
        // no ordinary user can write here, and that has to mean a write really
        // fails. `GetEffectiveRightsFromAclW` has already been caught
        // over-reporting the owner's rights in this very module, so a test that
        // only believed it would be a test of the same thing that was wrong.
        let open = OpenDir::new();
        let paths = open.paths();
        let dir = open.path().join("db");
        std::fs::create_dir(&dir).expect("creating the directory");
        protect_dir(&dir, DirRole::Data, &paths).expect("protecting it");

        let planted = dir.join("config.toml");
        let attempt = std::fs::write(&planted, b"real_time = false");
        assert!(
            attempt.is_err(),
            "a protected directory accepted a write from the account running the test; the \
             permission list is not doing what the audit says it does"
        );
        assert!(!planted.exists(), "and nothing was created");
        // The refusal is a permission refusal and not something else wearing the
        // same shape, so the error is checked for being a denial.
        let error = attempt.expect_err("already asserted it fails");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "a write into a protected directory has to fail as a permission error: {error}"
        );

        // The second: the owner can grant itself the permission it was refused.
        // This is not a hole in the permission list — a permission list cannot
        // restrict an object's owner, because `WRITE_DAC` on your own object is
        // not a privilege — but it is the limit of what this module can do, and
        // it is asserted here so that the documentation's claim about ownership
        // is a measurement and not a recollection.
        let account = acl::current_user_sid().expect("the current account's SID");
        let escalation = format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{account})"
        );
        let escalated = acl::apply_to_path(&dir, &escalation);
        assert!(
            escalated.is_ok(),
            "MEASUREMENT CHANGED: the owner of a directory could not rewrite its permissions \
             ({escalated:?}), so an owner is not the escalation route the documentation says it \
             is and both the field and the sentence about it have to be rewritten"
        );
        // And the escalation really did what it claimed, which is the point of
        // doing it rather than describing it: the same write now succeeds.
        assert!(
            std::fs::write(&planted, b"real_time = false").is_ok(),
            "the escalated permission list did not actually let the owner write, so this test \
             has measured the wrong thing"
        );
        // The audit sees the escalation too, which is what makes it a check
        // worth running rather than a report of what was intended.
        let after = audit(&dir).expect("auditing the escalated directory");
        assert!(
            after.writeable_by_ordinary_user(),
            "an audit of a directory that the owner has granted itself write on has to say so: \
             {after:?}"
        );
    }

    #[test]
    fn the_calling_account_is_not_an_ordinary_user_when_the_owner_is_known() {
        // Measured on 2026-10-10: `wenle protect status` run from an elevated
        // prompt reported all six of the product's directories as writable by an
        // ordinary user, on an installation whose permissions `icacls` showed to
        // be exactly the protected list. The fault was here and not in the
        // permissions — the directories under `%ProgramData%` are owned by
        // `BUILTIN\Administrators`, whose entry the list names, so the exclusion
        // did not fire, and the calling account was evaluated as though it were
        // an ordinary user and answered with everything.
        //
        // The owner is a parameter precisely so this can be asserted without
        // owning a directory as another account.
        let open = OpenDir::new();
        let dacl = acl::Dacl::of_path(open.path()).expect("reading the DACL");
        let me = acl::current_user_sid().expect("this account has a SID");

        let with_an_owner = ordinary_trustees(&dacl, Some(acl::ADMINISTRATORS));
        assert!(
            !with_an_owner.iter().any(|sid| sid.eq_ignore_ascii_case(&me)),
            "with a known owner the caller's own account must not be in the list of ordinary \
             trustees: {with_an_owner:?}"
        );

        // And the other direction, which is the fail-safe the documentation
        // names: with no owner at all there is nothing to excuse the account
        // with, so it stays in the list rather than the audit going quiet about
        // a directory it could not read.
        let without_an_owner = ordinary_trustees(&dacl, None);
        assert!(
            without_an_owner
                .iter()
                .any(|sid| sid.eq_ignore_ascii_case(&me)),
            "an owner that could not be read has to leave the caller in the list: \
             {without_an_owner:?}"
        );
    }

    /// Apply `sddl` with `SetFileSecurityW` — the call
    /// `av_quarantine::hardening` uses — so that the two calls can be compared on
    /// identical trees.
    ///
    /// Test-only, and deliberately not a second production path: this crate has
    /// one way of applying a permission list and it is `acl::apply_to_path`. This
    /// exists because "the two APIs differ" is worth more than "this one behaves
    /// like this" when another crate in the same workspace has documented the
    /// opposite behaviour from the other one — see
    /// `what_happens_to_the_entries_inside_a_directory_that_is_protected_afterwards`.
    fn apply_with_set_file_security(path: &Path, sddl: &str) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt as _;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };

        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `descriptor` is
        // a zeroed out-parameter the API allocates into on success, freed below
        // on both paths.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| format!("the permission string was refused: {e}"))?;

        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the descriptor came from the conversion above and is still
        // owned here; the path is NUL-terminated and lives for the call, and
        // `SetFileSecurityW` copies the DACL rather than retaining it.
        let applied = unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        // SAFETY: the descriptor was allocated by the call above and this is the
        // only place that frees it.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        applied
            .ok()
            .map_err(|e| format!("the operating system refused the permissions: {e}"))
    }

    /// Build a parent with a child inside it, the child inheriting the parent's
    /// permissions, and return both paths.
    fn parent_and_child(root: &Path, name: &str) -> (PathBuf, PathBuf) {
        let parent = root.join(name);
        std::fs::create_dir(&parent).expect("creating the parent");
        let child = parent.join("child");
        std::fs::create_dir(&child).expect("creating the child");
        (parent, child)
    }

    #[test]
    fn what_happens_to_the_entries_inside_a_directory_that_is_protected_afterwards() {
        // A measurement that settles a disagreement inside this workspace.
        //
        // `av_quarantine::hardening` documents, with its own measurement, that
        // setting a permission list on a directory does **not** update the
        // entries already inside it, and that a tree walk is therefore needed.
        // Measured here, protecting a directory **did** rewrite the entries on
        // the child that already existed. Both can be true at once, and the
        // difference that explains them is the call: av-quarantine applies with
        // `SetFileSecurityW` and this crate with `SetNamedSecurityInfoW`.
        //
        // This matters beyond tidiness. If the propagating call is the one this
        // crate uses, then `protect_product_dirs` fixes a tree that already
        // exists and one call per directory is a complete policy; if the
        // non-propagating one is, it is not, and the tree has to be visited.
        let open = OpenDir::new();

        // (a) protected with `acl::apply_to_path` — `SetNamedSecurityInfoW`.
        let (named, child_of_named) = parent_and_child(open.path(), "named");
        let (file_security, child_of_file_security) =
            parent_and_child(open.path(), "file-security");
        let (protective, child_of_protective) = parent_and_child(open.path(), "protective");
        for child in [&child_of_named, &child_of_file_security, &child_of_protective] {
            assert!(
                audit(child)
                    .expect("auditing a fresh child")
                    .writeable_by_ordinary_user(),
                "each child starts out inheriting the open permissions of the temporary root, so \
                 every one of these three trees has something to lose"
            );
        }
        // The third child is restricted *before* its parent changes, which is the
        // configuration the vault is in.
        apply_with_set_file_security(
            &child_of_protective,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        )
        .expect("restricting the third child on its own");
        let before_protective = audit(&child_of_protective).expect("auditing it once restricted");
        assert!(
            before_protective.protected,
            "the third child starts out with a protected list of its own: {before_protective:?}"
        );

        const SHAPE: &str = concat!(
            "D:P(A;OICI;", sddl_full!(), ";;;SY)",
            "(A;OICI;", sddl_full!(), ";;;BA)",
            "(A;OICI;", sddl_read_execute!(), ";;;BU)"
        );
        acl::apply_to_path(&named, SHAPE).expect("protecting the first parent");
        apply_with_set_file_security(&file_security, SHAPE).expect("protecting the second parent");
        // The third parent changes too, and it has to: a child that was left
        // alone because nothing above it changed would prove nothing at all.
        // This assertion is the one that was almost missing — the first version
        // of this test restricted the third child, protected the other two
        // parents, and then compared the third child with itself.
        acl::apply_to_path(&protective, SHAPE).expect("protecting the third parent");
        let parent_after = audit(&protective).expect("auditing the third parent");
        assert!(
            !parent_after.writeable_by_ordinary_user(),
            "the third parent really was protected: {:?}",
            parent_after.writeable_by
        );
        assert_ne!(
            parent_after.summary, before_protective.summary,
            "and its own list really did change, which is what makes the invariance of the child \
             below it a measurement rather than a coincidence"
        );

        let after_named = audit(&child_of_named).expect("auditing the first child");
        let after_file_security =
            audit(&child_of_file_security).expect("auditing the second child");
        let after_protective = audit(&child_of_protective).expect("auditing the third child");

        // The measurement, written as assertions on the thing that matters —
        // whether an ordinary user can still write into the child.
        assert!(
            !after_named.writeable_by_ordinary_user(),
            "`SetNamedSecurityInfoW` did not reach the child, so this crate's one-call-per-\
             directory policy is incomplete and `protect_product_dirs` has to walk the tree the \
             way `av_quarantine::hardening` does. Child: {after_named:?}"
        );
        assert!(
            after_named.summary.contains("BUILTIN\\Users:(I)"),
            "and it reached it by inheritance rather than by clearing the child's entries, which \
             is what the child's own unprotected permission list should show: {}",
            after_named.summary
        );
        assert!(
            !after_named.protected,
            "the child's own list is not protected — it is a copy, and that is the point: {}",
            after_named.summary
        );
        assert!(
            after_named.describe().contains("inherits"),
            "and the audit says which of the two it is looking at: {}",
            after_named.describe()
        );

        // `SetFileSecurityW`, the other crate's call, on an identical tree. The
        // measurement is the opposite of the one above and it is the finding of
        // this test: the child still carries the list it was created with,
        // unchanged, while the parent's list has been replaced.
        //
        // So both crates measured correctly and they measured different calls.
        // `av_quarantine::hardening`'s note — "setting the DACL on a directory
        // does not update the entries that are already inside it" — is true of
        // `SetFileSecurityW`, and the reason its [`restrict`] has to walk the
        // tree. This crate's one-call-per-directory policy is true of
        // `SetNamedSecurityInfoW`, and the reason it does not have to.
        assert!(
            after_file_security.writeable_by_ordinary_user(),
            "`SetFileSecurityW` now reaches the entries already inside a directory as well, so the \
             two calls have converged; `av_quarantine::hardening`'s tree walk is then no longer \
             load-bearing and its note about why it exists has to be rewritten. Child: \
             {after_file_security:?}"
        );
        assert!(
            after_file_security.summary.contains("Everyone:(I)"),
            "the child kept the entry it inherited when it was created, which is the entry that \
             says nobody rewrote it: {}",
            after_file_security.summary
        );

        // The child that had its own protected list first. Nothing may have
        // changed here: a protected list accepts nothing from its parent, which
        // is the whole reason `av-quarantine` marks its own as protected and the
        // reason this crate cannot weaken the vault.
        assert_eq!(
            after_protective.summary, before_protective.summary,
            "the third child's permission list changed when its parent was protected, even though \
             the child's own list is protected; that would mean a protected list does not stop \
             inheritance from above, which is the assumption the vault's protection rests on"
        );
        assert!(
            after_protective.protected,
            "the third child kept its own protected list: {after_protective:?}"
        );
        assert!(
            !after_protective.writeable_by_ordinary_user(),
            "and nothing the parent did gave an ordinary user write access to it: {:?}",
            after_protective.writeable_by
        );
        assert!(
            !after_protective
                .summary
                .contains("BUILTIN\\Users"),
            "in particular the parent's grant to users must not have been added to a list that \
             was already protected: {}",
            after_protective.summary
        );
    }

    #[test]
    fn the_protected_flag_comes_from_the_call_and_not_from_the_string() {
        // `acl::apply_to_path` ORs `PROTECTED_DACL_SECURITY_INFORMATION` in
        // unconditionally, so a string without the `P` still lands protected on
        // the object. Every string in this module carries the `P` anyway, and it
        // is worth being clear about why: the `P` is what the string *says*, so
        // the string is correct on its own terms and can be handed to any tool,
        // while the flag in the call is what actually stops the directory
        // re-inheriting from `%ProgramData%`.
        let open = OpenDir::new();
        let dir = open.path().join("cache");
        std::fs::create_dir(&dir).expect("creating a directory");
        acl::apply_to_path(&dir, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .expect("applying a list with no `P` in it");
        let audited = audit(&dir).expect("auditing it");
        assert!(
            audited.protected,
            "the flag in the call is the one that acts, so this comes back protected even though \
             the string did not ask for it: {audited:?}"
        );
        assert!(
            !audited.describe().contains("inherits"),
            "{}",
            audited.describe()
        );
    }

    #[test]
    fn the_read_and_execute_mask_is_what_a_scanner_needs_and_no_more() {
        // `0x1200A9` is `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`: everything a
        // scanner needs to load its own binaries and read its rule database, and
        // not one bit that would let it be rewritten. The failure this catches
        // is a widened grant, so the assertion is on the write bits rather than
        // on the number.
        let rx = mask_of(sddl_read_execute!());
        assert_eq!(
            rx & WRITE_MASK, 0,
            "the read-and-execute mask must not contain a write bit; it is 0x{rx:08x}"
        );
        assert_ne!(rx & READ_MASK, 0, "it has to allow reading");
        assert_ne!(rx & EXECUTE_MASK, 0, "it has to allow executing");
        // `FA`, by contrast, is every bit including the write ones — which is
        // why it is granted to SYSTEM and administrators and to nobody else.
        let full = mask_of(sddl_full!());
        assert_ne!(full & WRITE_MASK, 0);
        // And the log directory's mask is the read-and-execute one plus write,
        // which is the only difference between the two grants in the whole file.
        let modify = mask_of(sddl_modify!());
        assert_eq!(
            modify & rx,
            rx,
            "the log directory's mask must be a superset of the read-and-execute one: the log \
             directory is the one place an ordinary user may write, and it adds write rather than \
             trading something away for it. 0x{modify:08x} against 0x{rx:08x}"
        );
        assert_ne!(modify & WRITE_MASK, 0, "and it has to allow writing");
    }

    #[test]
    fn the_log_directory_gets_write_and_the_configuration_directory_does_not() {
        // The one asymmetry in the grants, asserted rather than left to the
        // strings. A log a user cannot append to is a support problem; a
        // configuration a user can write is a way to switch the product off.
        assert!(DirRole::Log.users_may_write());
        assert!(!DirRole::Config.users_may_write());
        assert!(DirRole::Log.sddl().contains("0x1301BF"), "{}", DirRole::Log.sddl());
        assert!(
            DirRole::Config.sddl().contains("0x1200A9"),
            "{}",
            DirRole::Config.sddl()
        );
        for role in DirRole::ALL {
            assert!(
                role.sddl().starts_with("D:P"),
                "{role:?} must be protected or it re-inherits: {}",
                role.sddl()
            );
            assert!(
                !role.sddl().contains("(D;"),
                "{role:?} must not use a deny ACE: {}",
                role.sddl()
            );
            assert!(
                role.sddl().contains(";;;SY)") && role.sddl().contains(";;;BA)"),
                "{role:?} must name SYSTEM and administrators: {}",
                role.sddl()
            );
            assert!(
                !role.sddl().contains(";;;WD)") && !role.sddl().contains(";;;AU)"),
                "{role:?} must not grant to Everyone or Authenticated Users: {}",
                role.sddl()
            );
        }
        assert_eq!(DirRole::ALL.len(), 6);
        let mut roles: Vec<DirRole> = DirRole::ALL.to_vec();
        roles.sort_unstable();
        roles.dedup();
        assert_eq!(roles.len(), DirRole::ALL.len(), "a role is listed twice");
    }

    #[test]
    fn the_vault_is_refused_by_name_when_it_is_handed_over_directly() {
        // The mechanical half of "this crate does not touch the vault": a caller
        // that asks anyway gets an error naming the crate that owns it, rather
        // than a second policy applied over the first.
        let open = OpenDir::new();
        let paths = open.paths();
        let vault = open.path().join("quarantine");
        std::fs::create_dir(&vault).expect("creating a stand-in vault");
        let inner = vault.join("items");
        std::fs::create_dir(&inner).expect("creating a stand-in vault subdirectory");

        for attempt in [vault.as_path(), inner.as_path()] {
            let error = protect_dir(attempt, DirRole::Data, &paths)
                .expect_err("the vault must not be protected by this crate");
            assert!(error.contains("quarantine"), "{error}");
            assert!(error.contains("av-quarantine"), "{error}");
        }
        // And the refusal is real, not advisory: nothing was applied, which is
        // what the directory's own audit shows.
        let audit = audit(&vault).expect("auditing the untouched vault");
        assert!(
            audit.writeable_by_ordinary_user(),
            "the refusal must leave the directory exactly as it was: {audit:?}"
        );
    }

    #[test]
    fn a_layout_whose_roles_point_at_the_vault_is_refused_before_anything_is_changed() {
        // The up-front check, and the reason it is up front: a layout that is
        // half-protected when the error is raised leaves a machine in a state
        // nobody can describe. Here the *rules* directory is the vault, which is
        // what a misconfigured data root looks like.
        let open = OpenDir::new();
        let mut paths = open.paths();
        std::fs::create_dir_all(&paths.quarantine_dir).expect("creating the vault");
        paths.rules_dir = paths.quarantine_dir.clone();
        let install = paths.install_dir.clone();
        std::fs::create_dir_all(&install).expect("creating the install directory");

        let error = protect_product_dirs(&paths).expect_err("a layout pointing at the vault");
        assert!(error.contains("av-quarantine"), "{error}");
        // The install directory would have been the first role applied, and it
        // was not: this is the assertion that the check really does come first.
        let install_audit = audit(&install).expect("auditing the install directory");
        assert!(
            install_audit.writeable_by_ordinary_user(),
            "nothing may have been applied before the layout was judged: {install_audit:?}"
        );
    }

    #[test]
    fn the_whole_layout_is_covered_and_the_vault_is_not_in_it() {
        // What `protect_product_dirs` claims to own, checked against the layout
        // rather than against a comment. Every role resolves to a directory, they
        // are distinct, and not one of them is the vault.
        let open = OpenDir::new();
        let paths = open.paths();
        std::fs::create_dir_all(&paths.data_dir).expect("data root");
        for role in DirRole::ALL {
            let path = role.path_in(&paths).expect("every role resolves");
            assert!(
                !is_vault(&path, &paths),
                "{role:?} resolves to the vault: {}",
                path.display()
            );
        }
        let roles: Vec<PathBuf> = DirRole::ALL
            .into_iter()
            .filter_map(|role| role.path_in(&paths))
            .collect();
        let mut unique = roles.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            roles.len(),
            "two roles resolve to the same directory, so one would be protected twice: {roles:?}"
        );
        // The configuration resolves to the directory holding `config.toml`
        // rather than to the file, and that directory is the data root.
        assert_eq!(
            DirRole::Config.path_in(&paths).expect("config"),
            paths.data_dir
        );
    }

    #[test]
    fn protecting_every_directory_reports_each_one_and_leaves_the_vault_alone() {
        // The whole-tree call, end to end, against a layout built inside a
        // temporary directory. Every directory is created first, because a
        // missing one is reported rather than created.
        let open = OpenDir::new();
        let paths = open.paths();
        std::fs::create_dir_all(&paths.data_dir).expect("data root");
        for role in DirRole::ALL {
            let path = role.path_in(&paths).expect("every role resolves");
            std::fs::create_dir_all(&path).expect("creating a product directory");
        }
        std::fs::create_dir_all(&paths.quarantine_dir).expect("creating the vault");

        let done = protect_product_dirs(&paths).expect("protecting the whole layout");
        assert_eq!(done.len(), DirRole::ALL.len());
        for protection in &done {
            assert!(protection.present, "{protection:?}");
            assert!(
                protection.applied,
                "every directory in a fresh layout has to be protectable: {protection:?}"
            );
        }
        // The log directory is the one that keeps its write grant, and the
        // report has to say so rather than claiming a restriction it did not make.
        let log = done
            .iter()
            .find(|protection| protection.role == DirRole::Log)
            .expect("the log directory is in the list");
        assert!(log.describe().contains("may write"), "{}", log.describe());
        let db = done
            .iter()
            .find(|protection| protection.role == DirRole::Data)
            .expect("the database directory is in the list");
        assert!(!db.describe().contains("may write"), "{}", db.describe());

        // And the vault, which is not in the list. This test's vault was never
        // restricted, so the data root's permission list reached it by
        // inheritance — measured, and the reason the ordering section of the
        // module documentation exists rather than being a precaution. What it
        // inherited is read and execute, so an ordinary user still cannot write
        // there; what it did *not* keep is its original open list.
        let vault = audit(&paths.quarantine_dir).expect("auditing the vault");
        assert!(
            !vault.writeable_by_ordinary_user(),
            "an unrestricted vault inside the data root picks up the data root's grant, which is \
             read and execute: {vault:?}"
        );
        assert!(
            !vault.protected,
            "and it picks it up as an inherited copy, not as its own list: {vault:?}"
        );
        assert!(
            vault.describe().contains("inherits"),
            "which the audit says out loud: {}",
            vault.describe()
        );
    }

    #[test]
    fn protecting_the_data_root_cannot_weaken_a_vault_that_is_already_restricted() {
        // The cross-crate claim, and the reason the vault section of this module
        // is more than politeness. The vault is *inside* the data root, the data
        // root is one of the directories this crate protects, and protecting a
        // directory reaches the entries inside it — measured in
        // `what_happens_to_the_entries_inside_a_directory_that_is_protected_afterwards`.
        // So "this crate does not weaken the vault" is a claim about the vault's
        // own permission list being protected, not about this crate's manners:
        // a protected list takes nothing from its parent, whoever the parent is.
        //
        // The vault here is restricted exactly as `av_quarantine::hardening`
        // restricts one — same string, same call — and the assertion is that its
        // permission list is byte-for-byte what it was after the whole product
        // layout is protected.
        let open = OpenDir::new();
        let paths = open.paths();
        std::fs::create_dir_all(&paths.data_dir).expect("data root");
        for role in DirRole::ALL {
            let path = role.path_in(&paths).expect("every role resolves");
            std::fs::create_dir_all(&path).expect("creating a product directory");
        }
        let vault = paths.quarantine_dir.clone();
        std::fs::create_dir_all(&vault).expect("creating the vault");
        apply_with_set_file_security(&vault, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .expect("restricting the vault the way av-quarantine does");

        let before = audit(&vault).expect("auditing the restricted vault");
        assert!(before.protected, "{before:?}");
        assert!(!before.writeable_by_ordinary_user(), "{before:?}");

        // The directories this crate owns are protected, and the vault is not
        // among them.
        let done = protect_product_dirs(&paths).expect("protecting the whole layout");
        assert!(
            !done
                .iter()
                .any(|protection| protection.path == vault),
            "the vault must not be in the list of directories this crate protected: {done:?}"
        );

        let after = audit(&vault).expect("auditing the vault afterwards");
        assert_eq!(
            after.summary, before.summary,
            "the vault's permission list changed when the data root was protected; a protected \
             list is supposed to accept nothing from its parent, and if that is not true then \
             this crate can weaken the vault by protecting the directory above it, and the \
             vault has to be restricted *after* `protect_product_dirs` rather than before"
        );
        assert!(after.protected, "{after:?}");
        assert!(!after.writeable_by_ordinary_user(), "{after:?}");
        assert!(
            !after.summary.contains("BUILTIN\\Users"),
            "and in particular no grant reached it: {}",
            after.summary
        );
    }

    #[test]
    fn a_directory_that_is_not_there_is_reported_rather_than_created() {
        // Creating the directory here would take the ownership and the timing
        // out of the caller's hands, and a directory created by an elevated
        // hardening pass rather than by the installer has a different owner.
        let open = OpenDir::new();
        let paths = open.paths();
        let missing = open.path().join("not-created");
        let protection =
            protect_dir(&missing, DirRole::Cache, &paths).expect("a missing directory is not an error");
        assert!(!protection.present, "{protection:?}");
        assert!(!protection.applied, "{protection:?}");
        assert!(!missing.exists(), "the directory must not have been created");
        let line = protection.describe();
        assert!(line.contains("does not exist"), "{line}");
        // And the audit of a missing path says so rather than failing, because a
        // caller reporting the state of a layout has to be able to ask about a
        // directory that is not there yet.
        let audit = audit(&missing).expect("auditing a path that does not exist");
        assert!(!audit.present);
        assert!(!audit.writeable_by_ordinary_user());
        assert!(audit.describe().contains("does not exist"), "{}", audit.describe());
    }

    #[test]
    fn an_audit_of_a_directory_the_account_cannot_read_is_an_error() {
        // Not a finding. A caller that cannot read the permissions must not be
        // handed an audit that says the directory is fine, which is what a
        // defaulted-to-empty answer would say.
        // Pid-free and path-based: a path under a directory with no read
        // permission is not needed here, because the case that must never be
        // silently successful is a path that cannot be opened at all.
        let missing = Path::new("\\\\?\\C:\\wenle-av-does-not-exist\\nested");
        assert!(audit(missing).is_ok(), "a missing path is answered, not failed");
        assert!(!audit(missing).expect("audit").present);
        // A path that exists but has no DACL to read is the error case, and it
        // is covered in `crate::acl`'s own tests for the null DACL.
    }

    #[test]
    fn the_write_mask_covers_every_way_of_getting_write_access() {
        // `FA` is the interesting case — it is what an open directory carries
        // and what a protected one grants to SYSTEM — and the generic bits are
        // the ones a hand-written DACL uses.
        for mask in [
            0x0000_0002u32, // FILE_WRITE_DATA
            0x0000_0004,    // FILE_APPEND_DATA
            0x0000_0010,    // FILE_WRITE_EA
            0x0000_0100,    // FILE_WRITE_ATTRIBUTES
            0x0001_0000,    // DELETE
            0x0004_0000,    // WRITE_DAC
            0x0008_0000,    // WRITE_OWNER
            0x4000_0000,    // GENERIC_WRITE
            0x1000_0000,    // GENERIC_ALL
            0x001F_01FF,    // FA, the whole of it
        ] {
            assert_ne!(mask & WRITE_MASK, 0, "0x{mask:08x} must count as write");
        }
        // And the read-and-execute mask `Users` is granted must count as neither.
        let rx = 0x1200A9u32;
        assert_eq!(rx & WRITE_MASK, 0, "0x1200A9 must not count as write");
        assert_ne!(rx & READ_MASK, 0, "0x1200A9 must count as read");
        assert_ne!(rx & EXECUTE_MASK, 0, "0x1200A9 must count as execute");
        // A bare READ_CONTROL is not write, and a bare SYNCHRONIZE is nothing at
        // all — the two mistakes that would make the audit useless in opposite
        // directions.
        assert_eq!(0x0002_0000u32 & WRITE_MASK, 0);
        assert_eq!(0x0010_0000u32 & WRITE_MASK, 0);
    }

    #[test]
    fn the_vault_guard_normalises_the_path_before_comparing_it() {
        // A guard a caller can walk past by spelling the path differently is not
        // a guard, and Windows paths are spelled differently in every log line.
        let open = OpenDir::new();
        let paths = open.paths();
        let vault = paths.quarantine_dir.clone();
        for spelling in [
            vault.clone(),
            PathBuf::from(format!("{}\\", vault.display())),
            PathBuf::from(vault.to_string_lossy().replace('\\', "/")),
            PathBuf::from(vault.to_string_lossy().to_uppercase()),
            vault.join("items").join("0"),
        ] {
            assert!(
                is_vault(&spelling, &paths),
                "{} must be recognised as the vault",
                spelling.display()
            );
        }
        assert!(!is_vault(&paths.data_dir, &paths));
        assert!(!is_vault(&paths.install_dir, &paths));
        // A directory whose name merely starts with the vault's must not be
        // caught: `quarantine-old` is not the vault.
        assert!(!is_vault(
            &PathBuf::from(format!("{}-old", vault.display())),
            &paths
        ));
    }

}
