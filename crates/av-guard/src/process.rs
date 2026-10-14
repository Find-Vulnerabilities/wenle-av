//! Protecting the running scanner from the account it is protecting.
//!
//! # What the threat actually is, measured
//!
//! The obvious story is "the service runs as `LocalSystem` and an ordinary user
//! can call `TerminateProcess` on it". On this machine that story is wrong in
//! its first half and right in a way that matters more, and both halves were
//! measured rather than assumed.
//!
//! **A process started by an ordinary account.** A child process spawned by
//! this (unelevated) test run carries
//!
//! ```text
//! D:(A;;0x1fffff;;;S-1-5-21-…-1001)   ← the owning account, by its own SID
//!   (A;;0x1fffff;;;BUILTIN\Administrators)
//!   (A;;0x1fffff;;;NT AUTHORITY\SYSTEM)
//! ```
//!
//! Not protected, three entries, and `0x1fffff` is `PROCESS_ALL_ACCESS`. The
//! owning account is named *by its own SID* and not through `BUILTIN\Users`, so
//! the right belongs to that one account, which is the problem,
//! because that account is the user. Every process running as them can open the
//! scanner with `PROCESS_VM_WRITE` and `PROCESS_CREATE_THREAD`: the CLI scan
//! they launched, the graphical front end, the service started with `--console`
//! in a developer's session, and any malware that got in as that user. That is
//! the case this module closes, and it is the ordinary case for everything in
//! this product that runs in a user's own session.
//!
//! Measured alongside it: `Everyone`, `NT AUTHORITY\Authenticated Users`,
//! `BUILTIN\Users` and `NT AUTHORITY\INTERACTIVE` all evaluate to
//! `0x00000000` on that same default DACL. So the default is *not* the
//! "`PROCESS_TERMINATE` for `BUILTIN\Users`" that it is often described as being:
//! it is narrower than that and worse than that, because the grant goes to the
//! owning account itself, which is the account an attacker already has.
//!
//! **A process started by a `LocalSystem` token.** `services.exe` (pid 1316 on
//! this machine) refuses `OpenProcess` with *every* right this account could
//! ask for: `READ_CONTROL`, `PROCESS_QUERY_LIMITED_INFORMATION`,
//! `PROCESS_QUERY_INFORMATION`, and `WRITE_DAC | READ_CONTROL`, each returning
//! Win32 error 5. That is direct evidence about the DACL rather than a guess at
//! it: if `Everyone`, `Authenticated Users`, `Users` or `INTERACTIVE` were
//! granted anything at all, one of those four calls would have passed, because
//! this account holds all four. So a `LocalSystem` service is **already** out of
//! an ordinary user's reach, and hardening its process object is defence in
//! depth rather than the load-bearing protection.
//!
//! Saying that plainly is the point of this section. The load-bearing work for
//! an installed `LocalSystem` service is [`crate::files`] and
//! [`crate::service`], where the measured defaults are genuinely open. This
//! module covers the three cases the default does not: a service run under a
//! user account, `--console`, and a deployment where the process was created by
//! something with a less restrictive token than `LocalSystem`. It is defence in
//! depth, and it is written down as defence in depth rather than described as
//! the wall.
//!
//! # Four rights that are worse than termination
//!
//! Stopping the scanner is the crude attack. Four of these do not stop it, they
//! *subvert* it, and the last two take the rest back:
//!
//! * **`PROCESS_VM_WRITE` with `PROCESS_VM_OPERATION`** writes into the
//!   scanner's address space. A rule database in memory, a list of detections, a
//!   decision about a file: all of them are bytes in that process, and an
//!   attacker who can write those bytes does not need the scanner to stop; they
//!   can make it call a file clean while it keeps reporting that it is working.
//! * **`PROCESS_CREATE_THREAD`** starts a thread inside the scanner running the
//!   attacker's code, with the scanner's own token. Where the scanner is
//!   `LocalSystem`, that is a privilege escalation with no exploit in it at all.
//! * **`PROCESS_SUSPEND_RESUME`** is the quiet one: suspending the scanner's
//!   threads stops it detecting anything while leaving it nominally alive, and
//!   every health check that asks "is the service running?" answers yes.
//! * **`WRITE_DAC` and `WRITE_OWNER`** undo everything above. `WRITE_DAC` lets
//!   the holder rewrite this very DACL and `WRITE_OWNER` lets them take the
//!   object and then rewrite it, so a protection that leaves either granted
//!   protects nothing at all, which is why they are in the list rather than
//!   assumed to be covered by the others.
//!
//! # What is applied, and why the numbers are hex rather than `FA`
//!
//! ```text
//! D:P(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)(A;;0x1000;;;IU)
//! ```
//!
//! Protected (`P`), `PROCESS_ALL_ACCESS` to `SYSTEM` and
//! `BUILTIN\Administrators`, and `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`)
//! to `NT AUTHORITY\INTERACTIVE`.
//!
//! Every other DACL in this crate writes `FA` for "full control" and this one
//! does not, because on a process object `FA` is the wrong number. Measured:
//! applying `(A;;FA;;;SY)` to a process and reading it back yields
//! `0x001F01FF` for SYSTEM, while `PROCESS_ALL_ACCESS` is `0x001F0FFF`. The
//! difference is `0x00000E00`, which is `PROCESS_SUSPEND_RESUME`,
//! `PROCESS_QUERY_INFORMATION` and `PROCESS_SET_INFORMATION`. `FA` is
//! `FILE_ALL_ACCESS`, and the object manager does not translate it between
//! object types: SDDL's two-letter names are file rights, and using one on a
//! process silently leaves three process rights ungranted. An administrator who
//! could not suspend or query the scanner in detail would be an administrator
//! locked out by a string nobody would think to check.
//!
//! # Why there is no `(D;;…;;;WD)` in that string
//!
//! The obvious construction is to write the deny out: deny `Everyone` the seven
//! dangerous rights, then grant SYSTEM and Administrators everything. It does
//! not work, and the reason is the evaluation order of a DACL.
//!
//! A DACL is walked in order. A deny ACE whose SID is in the caller's token
//! denies those bits *and ends the check* for them; a later allow ACE cannot
//! restore them. `NT AUTHORITY\SYSTEM` is a member of `Everyone`, and
//! `BUILTIN\Administrators` is a member of `Everyone` *and*, through
//! `NT AUTHORITY\Authenticated Users`, of `BUILTIN\Users`. So a deny ACE naming
//! `Everyone` or `Users` denies SYSTEM and the administrator too, wherever the
//! allowing ACEs are placed, and the first thing that breaks is the ability to
//! *manage* the product.
//!
//! That is not a reading of the documentation; a test in this module builds the
//! deny-style string, applies it to a real process handle and shows SYSTEM's
//! effective rights coming back with all seven bits missing while the grant to
//! SYSTEM sits in the same DACL, unreachable. The allow list above reaches the
//! same place from the other side: every principal not named is denied
//! everything it was not granted, and SYSTEM and Administrators are named.
//!
//! # The trade-offs, all of them deliberate
//!
//! * **An administrator can still manage the process**, because
//!   `BUILTIN\Administrators` holds `PROCESS_ALL_ACCESS`. A machine where the
//!   administrator cannot stop the antivirus is a machine where the antivirus
//!   is the malware, and no amount of protection is worth that.
//! * **The interactive user keeps `PROCESS_QUERY_LIMITED_INFORMATION`**,
//!   because the graphical front end has to be able to ask the service what it
//!   is doing. It is the *limited* right and not `PROCESS_QUERY_INFORMATION`:
//!   the limited right returns the image name, the exit code and the token's
//!   integrity level, and refuses the full token, the handle table and the
//!   command line. The front end gets what it needs to draw a window and an
//!   attacker gets nothing that helps them enumerate what the scanner holds.
//! * **The owner of the process object can always undo this.** Windows grants an
//!   object's owner `READ_CONTROL` and `WRITE_DAC` outside the DACL. For a
//!   service process created by the SCM the owner is `SYSTEM` and this costs
//!   nothing; for a process this crate hardens in a test or in a user's session,
//!   the owner is that user, which is what makes the tests below able to restore
//!   what they changed. It is the honest limit of the mechanism and it is
//!   repeated in [`Protection::limits`].
//! * **Nothing here survives a reboot.** The DACL lives on the process object,
//!   which dies with the process; the next one starts with its token's default
//!   DACL again. This has to be re-applied on every service start, which is why
//!   it belongs in a startup path and not in an installer. Named in
//!   [`Protection::limits`] as well, because a protection that quietly expires
//!   at the next boot is worse than one that was never claimed.
//!
//! The four limits together (administrators, the owner, a kernel-mode attacker
//! and the next reboot) are in [`Protection::limits`], and every report this
//! module produces is meant to be read next to them.
//!
//! # The owner, measured, and the one right a DACL cannot take away
//!
//! Windows grants an object's owner rights *outside* its DACL. This is not a
//! footnote here, because the account that starts a process is its owner, so on
//! any machine where a user launched the scanner the owner is that user and the
//! protection above is not the last word. Two probes, run against a child
//! process owned by this unelevated account after applying [`PROTECTED_DACL`]:
//!
//! ```text
//! OpenProcess(PROCESS_TERMINATE, …, child)      → Win32 error 5
//! OpenProcess(PROCESS_CREATE_THREAD, …, child)  → Win32 error 5
//! OpenProcess(PROCESS_VM_WRITE, …, child)       → Win32 error 5
//! OpenProcess(PROCESS_SUSPEND_RESUME, …, child) → Win32 error 5
//! OpenProcess(PROCESS_ALL_ACCESS, …, child)     → Win32 error 5
//! OpenProcess(WRITE_DAC, …, child)              → succeeds
//! OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
//!             …, child)                         → succeeds
//! ```
//!
//! The first five are the protection working, and they are worth stating
//! explicitly because they are stronger than the DACL: the account running the
//! probe *owns* that process and is still refused. The sixth is the limit (the
//! owner can rewrite the DACL and then take everything else back), and the
//! seventh is the `IU` grant doing its job.
//!
//! So an unprivileged owner always holds one of the seven, `WRITE_DAC`, and no
//! DACL can change that. That is reported separately, in
//! [`Protection::owner_rights`], rather than folded into
//! [`Protection::exposed`], because the two answer different questions: what the
//! DACL failed to close, and what no DACL can close. A report that merged them
//! could never say "protected" on any process a user had started, and a report
//! that can never say yes is one nobody reads.
//!
//! For the case this crate exists for, a service the SCM created as
//! `LocalSystem`, the owner is `SYSTEM`, which already holds
//! `PROCESS_ALL_ACCESS` and which [`Protection::manageable`] reports, so the
//! caveat costs nothing there.
//!
//! ## Why the owner is not evaluated with `GetEffectiveRightsFromAclW`
//!
//! Because it gets the answer wrong, measured. On the protected DACL above,
//! which names `SYSTEM`, `Administrators` and `INTERACTIVE` and does *not* name
//! the owner, that call returns `0x001f0fff`, `PROCESS_ALL_ACCESS`, for the
//! owning account. The probe immediately after it refused
//! `OpenProcess(PROCESS_ALL_ACCESS)` with error 5. The call over-reports the
//! owner's access by the whole mask, and it does so in the direction that would
//! make every report this module produces say "not protected" about a process
//! that is.
//!
//! So the owner is evaluated by its own rule, and the rule is taken from the two
//! probes rather than from the call. If the DACL names the owner, the ACEs that
//! name them are what the operating system honours (a DACL granting one right
//! to the owner was applied and `OpenProcess` for that one right succeeded while
//! the seven stayed refused), and the API's answer is used for them, over-report
//! and all, because over-reporting is the safe direction. If the DACL does not
//! name the owner, the owner's implicit grant is `READ_CONTROL` and `WRITE_DAC`,
//! of which only `WRITE_DAC` is dangerous.
//!
//! `acl::Dacl::effective` carries the same warning at the point of use, since
//! the trap is one call away for anyone reading a DACL.
//!
//! # The pseudo-handle question, measured, and what it does not settle
//!
//! `GetCurrentProcess()` returns `(HANDLE)-1`, a pseudo-handle the kernel
//! resolves to the calling process, and it is tempting to hand it straight to
//! `SetSecurityInfo` instead of opening a handle to your own pid. The brief this
//! crate was written against expected that to be refused. On this machine it
//! **succeeds** (`SetSecurityInfo` on the pseudo-handle for a DACL change
//! returns success), and the test `pseudo_handle_dacl_changes_are_measurable`
//! records the measurement rather than the expectation.
//!
//! What that measurement does *not* settle is *why*, and the ambiguity is worth
//! writing down rather than resolving in the flattering direction. Two things
//! independently let the call through, and the observation cannot separate them:
//! this process's own default DACL grants the running account `0x1fffff`, which
//! contains `WRITE_DAC`; and the running account is the object's *owner*, which
//! Windows grants `WRITE_DAC` implicitly whatever the DACL says. Either alone is
//! sufficient. So the measurement says the pseudo-handle is usable here, and it
//! does **not** say a pseudo-handle bypasses the access check, which would be a
//! finding of an entirely different size, since it would mean the DACL this
//! module applies to the current process protects nothing.
//!
//! [`protect`] therefore opens a real handle, and the reason that survives the
//! measurement is not the access check: [`protect`] takes a pid, so it has to
//! work for processes other than this one, and one path that works for every pid
//! is worth more than a second path that works for exactly one. If the
//! pseudo-handle were ever wanted, the way to establish it would be to run this
//! code as an account that is not the object's owner, which nothing on a
//! single-account machine can do.

use std::fmt;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS};

use crate::acl;

/// `PROCESS_TERMINATE` — `TerminateProcess`.
pub const PROCESS_TERMINATE: u32 = 0x0000_0001;
/// `PROCESS_CREATE_THREAD` — `CreateRemoteThread` into this process.
pub const PROCESS_CREATE_THREAD: u32 = 0x0000_0002;
/// `PROCESS_VM_OPERATION` — the half of memory writing that changes protection.
pub const PROCESS_VM_OPERATION: u32 = 0x0000_0008;
/// `PROCESS_VM_WRITE` — the half that writes the bytes.
pub const PROCESS_VM_WRITE: u32 = 0x0000_0020;
/// `PROCESS_SUSPEND_RESUME` — `NtSuspendProcess` and `NtResumeProcess`.
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0000_0800;
/// `PROCESS_QUERY_LIMITED_INFORMATION` — enough to ask a process what it is and
/// not enough to read its token, its handles or its command line.
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
/// `READ_CONTROL` — read the permissions back.
pub const READ_CONTROL: u32 = 0x0002_0000;
/// `WRITE_DAC` — rewrite this object's permissions.
pub const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER` — take this object, which is the step before rewriting them.
pub const WRITE_OWNER: u32 = 0x0008_0000;
/// `PROCESS_ALL_ACCESS` — every right the access mask defines for a process.
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_0FFF;

/// The seven rights that let an unprivileged process stop or subvert this one.
///
/// One mask rather than seven checks at seven call sites, because the list *is*
/// the policy — "these are the ways a process can be attacked" — and a policy
/// spread over seven `if`s is a policy nobody can review. [`Right`] is the same
/// list with names on it, for a report a person reads.
pub const DANGEROUS: u32 = PROCESS_TERMINATE
    | PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_WRITE
    | PROCESS_SUSPEND_RESUME
    | WRITE_DAC
    | WRITE_OWNER;

/// One of the rights in [`DANGEROUS`], with the sentence that explains it.
///
/// The list is closed and is enumerated exhaustively wherever it is used, so
/// adding an eighth right is a change the compiler insists on making everywhere
/// it matters rather than one that quietly appears in a report and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Right {
    /// `PROCESS_TERMINATE`.
    Terminate,
    /// `PROCESS_CREATE_THREAD`.
    CreateThread,
    /// `PROCESS_VM_OPERATION`.
    VmOperation,
    /// `PROCESS_VM_WRITE`.
    VmWrite,
    /// `PROCESS_SUSPEND_RESUME`.
    SuspendResume,
    /// `WRITE_DAC`.
    WriteDac,
    /// `WRITE_OWNER`.
    WriteOwner,
}

impl Right {
    /// Every right this crate denies, in mask order.
    pub const ALL: [Right; 7] = [
        Right::Terminate,
        Right::CreateThread,
        Right::VmOperation,
        Right::VmWrite,
        Right::SuspendResume,
        Right::WriteDac,
        Right::WriteOwner,
    ];

    /// The access-mask bit.
    pub const fn mask(self) -> u32 {
        match self {
            Right::Terminate => PROCESS_TERMINATE,
            Right::CreateThread => PROCESS_CREATE_THREAD,
            Right::VmOperation => PROCESS_VM_OPERATION,
            Right::VmWrite => PROCESS_VM_WRITE,
            Right::SuspendResume => PROCESS_SUSPEND_RESUME,
            Right::WriteDac => WRITE_DAC,
            Right::WriteOwner => WRITE_OWNER,
        }
    }

    /// The name Win32 gives it, for a report that has to name the right.
    pub const fn name(self) -> &'static str {
        match self {
            Right::Terminate => "PROCESS_TERMINATE",
            Right::CreateThread => "PROCESS_CREATE_THREAD",
            Right::VmOperation => "PROCESS_VM_OPERATION",
            Right::VmWrite => "PROCESS_VM_WRITE",
            Right::SuspendResume => "PROCESS_SUSPEND_RESUME",
            Right::WriteDac => "WRITE_DAC",
            Right::WriteOwner => "WRITE_OWNER",
        }
    }

    /// What an attacker does with it, in the words of the consequence.
    ///
    /// Written as the consequence and not as the mechanism, because that is what
    /// a person has to weigh: "an ordinary user could make the scanner call a
    /// malicious file clean" is a sentence somebody can act on, and
    /// "`PROCESS_VM_WRITE` is granted" is not.
    pub const fn consequence(self) -> &'static str {
        match self {
            Right::Terminate => "an ordinary user could stop the scanner outright",
            Right::CreateThread => {
                "an ordinary user could run their own code inside the scanner, with the \
                 scanner's own rights"
            }
            Right::VmOperation | Right::VmWrite => {
                "an ordinary user could rewrite what the scanner believes, and make it call a \
                 malicious file clean"
            }
            Right::SuspendResume => {
                "an ordinary user could freeze the scanner so that it detects nothing while \
                 still looking alive"
            }
            Right::WriteDac => {
                "an ordinary user could rewrite these permissions and then take the rest"
            }
            Right::WriteOwner => {
                "an ordinary user could take ownership of the process and then rewrite these \
                 permissions"
            }
        }
    }

    /// The right for an access-mask bit, if it is one of these seven.
    pub const fn from_mask(bit: u32) -> Option<Right> {
        match bit {
            PROCESS_TERMINATE => Some(Right::Terminate),
            PROCESS_CREATE_THREAD => Some(Right::CreateThread),
            PROCESS_VM_OPERATION => Some(Right::VmOperation),
            PROCESS_VM_WRITE => Some(Right::VmWrite),
            PROCESS_SUSPEND_RESUME => Some(Right::SuspendResume),
            WRITE_DAC => Some(Right::WriteDac),
            WRITE_OWNER => Some(Right::WriteOwner),
            _ => None,
        }
    }
}

impl fmt::Display for Right {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The DACL [`protect`] applies, as an SDDL string.
///
/// Public because a caller that logs it, a test that asserts on it and an
/// operator who wants to reproduce it by hand all need the same string, and
/// three copies of a security policy are three policies. See the module
/// documentation for why the two full-control entries are `0x1F0FFF` and not
/// `FA`.
///
/// The `P` is load-bearing in the same way it is for a directory, though for a
/// lesser reason: a process object usually has no parent contributing
/// inheritable entries, so protecting it changes nothing today. It is there so
/// that a DACL this crate applied is *complete* rather than *additive* — every
/// grant on the object is in this string and nothing arrives from anywhere else,
/// which is the property that makes reading the object back a verification
/// instead of a partial view.
pub const PROTECTED_DACL: &str = "D:P(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)(A;;0x1000;;;IU)";

/// The DACL [`restore`] applies: the shape a process object normally has.
///
/// `SYSTEM` and `Administrators` with `PROCESS_ALL_ACCESS`, plus the account
/// running this code — a stand-in for the token's default DACL, which grants
/// exactly those three accounts and which this crate cannot reproduce without
/// reading the token. Measured, the default entries are `0x1fffff` each;
/// `0x1F0FFF` is used instead because it is the number Win32 defines for a
/// process and the point of this function is to be right about the access mask.
///
/// The running account is named by its own SID, taken from the token, and not by
/// an SDDL alias: an alias would be a guess about which well-known SID resolves
/// to the owner, and the one thing `restore` must never do is fail to hand the
/// process back to the account that has to clean up.
///
/// Deliberately *not* a null DACL. `SetSecurityInfo` with a null DACL grants
/// every right to every account on the machine, which is looser than the default
/// it would be replacing, and "I removed the protection" must not come to mean
/// "I opened it to everyone".
///
/// Returns a `Result` because reading the token can fail, and a `restore` that
/// quietly applied a DACL without the running account in it would be the worst
/// possible outcome: a process nobody but SYSTEM can manage, produced by the
/// function whose job is to undo exactly that.
pub fn default_dacl() -> Result<String, String> {
    let account = acl::current_user_sid()
        .map_err(|detail| format!("the account running this could not be named: {detail}"))?;
    let mut sddl = String::from("D:P(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)");
    // SYSTEM and an administrator are already named, and an ACE repeated for the
    // same SID is noise in every tool that displays it.
    if account != acl::SYSTEM && account != acl::ADMINISTRATORS {
        sddl.push_str(&format!("(A;;0x1F0FFF;;;{account})"));
    }
    Ok(sddl)
}

/// What applying the protection did, or what reading it back found.
///
/// One type for both, because the interesting question is never "did the call
/// succeed" but "which of the seven is reachable by an ordinary account, and to
/// whom" — and a caller comparing what was applied against what the object now
/// says should not have to translate between two shapes to do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    /// The process the DACL belongs to.
    pub pid: u32,
    /// The dangerous rights the DACL no longer grants to any unprivileged
    /// account.
    pub denied: Vec<Right>,
    /// The dangerous rights it still does, which is the interesting and unhappy
    /// case.
    ///
    /// Non-empty here means the protection did not take, and the caller has to
    /// say so rather than print a tick.
    ///
    /// This is *what the DACL failed to close*, and deliberately not *what any
    /// account can still reach*: the object's owner is excluded and reported in
    /// [`Protection::owner_rights`] instead. See the module documentation for the
    /// two measurements that force the split.
    pub exposed: Vec<Right>,
    /// The account that owns the process object, as an `S-1-5-...` string.
    ///
    /// Always reported, because it decides how much the rest of the report is
    /// worth: the owner can rewrite this DACL, so a report that did not name the
    /// owner would be describing a lock without saying whose key fits it.
    pub owner: String,
    /// The dangerous rights the object's owner holds **outside** the DACL.
    ///
    /// The counterpart of [`Protection::exposed`] and disjoint from it, because
    /// the two answer different questions: `exposed` is what this crate failed to
    /// close and could close, and this is what no permission list can close. A
    /// caller that warns on `exposed` is warning about a broken deployment; a
    /// caller that warns on this is warning about how Windows treats ownership,
    /// which no deployment can fix.
    ///
    /// Measured: an unprivileged owner always holds `WRITE_DAC`, so this is
    /// either `[WriteDac]` or empty, and empty means the owner is `SYSTEM` or an
    /// administrator, whose larger access is [`Protection::manageable`]'s
    /// business and is granted by [`PROTECTED_DACL`] on purpose. It is never
    /// `[WriteDac]` for a service, which is the case that matters: the SCM
    /// creates the service process, so its owner is `SYSTEM`.
    pub owner_rights: Vec<Right>,
    /// Whether `NT AUTHORITY\INTERACTIVE` can still ask the process what it is.
    ///
    /// Reported separately because it is the deliberate hole in the wall: the
    /// graphical front end needs it, and a reader of the report is entitled to
    /// see that it is there rather than to infer it from a missing deny.
    pub query_limited: bool,
    /// Whether `SYSTEM` and `Administrators` still hold `PROCESS_ALL_ACCESS`.
    ///
    /// Also deliberate, and also reported rather than assumed: a protection that
    /// had accidentally locked the administrator out would be a worse fault than
    /// the one it was fixing, and it would look exactly like a success.
    pub manageable: bool,
    /// Every entry of the DACL, as the shape `icacls` prints.
    pub summary: String,
}

impl Protection {
    /// A single line for a person, phrased as what is now true of the machine.
    ///
    /// Three sentences for three states, and the middle one is why this is not a
    /// boolean: "the seven are closed, and the account that owns this process can
    /// still reopen them" is a true and useful thing to say, and it is neither of
    /// the two things a tick or a cross could carry.
    pub fn describe(&self) -> String {
        if !self.exposed.is_empty() {
            let names: Vec<&str> = self.exposed.iter().map(|right| right.name()).collect();
            return format!(
                "process {} is NOT protected: {} {} still reachable by an ordinary account",
                self.pid,
                names.join(", "),
                if names.len() == 1 { "is" } else { "are" }
            );
        }
        let mut line = format!(
            "process {} is protected: all seven dangerous rights are denied to every \
             unprivileged account, administrators keep full control, and an interactive user \
             can still ask it what it is doing",
            self.pid,
        );
        if !self.owner_rights.is_empty() {
            let names: Vec<&str> = self.owner_rights.iter().map(|right| right.name()).collect();
            line.push_str(&format!(
                ". The account that owns this process ({}) can still reach {} outside the \
                 permission list, because that is how Windows treats an object's owner — \
                 nothing a permission list can change, and not a fault of this protection",
                self.owner,
                names.join(", ")
            ));
        }
        line
    }

    /// The rights this protection does **not** provide against, said plainly.
    ///
    /// Every one of these is a real limit and each is a sentence rather than a
    /// word, because the failure this list prevents is a reader who assumes
    /// "protected" means more than it does. Four, and they are the four that are
    /// left after the mechanism has done everything it can.
    pub const fn limits() -> [&'static str; 4] {
        [
            "an administrator can stop or attach to this process: Administrators hold \
             PROCESS_ALL_ACCESS by design, because a machine whose administrator cannot manage \
             its antivirus is worse off than one whose antivirus can be stopped",
            "the owner of the process object can rewrite its permissions without the DACL \
             granting it: Windows gives an object's owner READ_CONTROL and WRITE_DAC outside \
             the DACL, measured by opening a protected process owned by an unelevated account \
             for WRITE_DAC and having it succeed while PROCESS_ALL_ACCESS was refused, and no \
             DACL can remove that",
            "a kernel-mode attacker is unaffected: the check happens in the object manager, and \
             code running above it does not have to pass through it",
            "the protection ends at the next reboot: it lives on the process object, which dies \
             with the process, and the replacement gets its token's default DACL again",
        ]
    }
}

/// A mask as the rights it names, for a report.
fn rights_in(mask: u32) -> Vec<Right> {
    Right::ALL
        .into_iter()
        .filter(|right| mask & right.mask() == right.mask())
        .collect()
}

/// Every trustee whose access to this object an ordinary account could have.
///
/// Three sources, unioned, and all three are needed:
///
/// * **The four well-known group SIDs** in [`acl::UNPRIVILEGED_TRUSTEES`],
///   which cover a DACL that grants to a group rather than to a person.
/// * **Every SID the DACL names** that is not `SYSTEM` or `Administrators`.
///   This is the one that matters on a real machine: measured, a process object's
///   default DACL names the *owning user by their own SID* and no group at all,
///   so a check that only looked at group SIDs would report a completely open
///   process as having nothing exposed. That is the shape of mistake this
///   function exists to not make.
/// * **The account running this check**, even when the DACL does not name it, so
///   that "can I, the person who ran this, write to my own product directory?"
///   has an answer rather than an absence.
///
/// A SID named in the DACL that is not administrators is treated as
/// unprivileged, which over-reports rather than under-reports: a grant to one
/// named ordinary user is a grant to an ordinary user, and the report says so
/// rather than reasoning about who else can log on.
///
/// # The owner is excluded, and that is not an oversight
///
/// `owner` is the account that owns the object, and it is left out of this list
/// for a measured reason: `GetEffectiveRightsFromAclW` returns
/// `PROCESS_ALL_ACCESS` for the owning account even on a DACL that does not name
/// it, while a real `OpenProcess(PROCESS_ALL_ACCESS)` on the same process is
/// refused with error 5. Including the owner would therefore make this function
/// report every protected process as wide open. The owner's real access is
/// computed by its own rule in [`owner_rights`] and reported in
/// [`Protection::owner_rights`]. The module documentation has both probes.
///
/// The upper-bound direction is deliberate everywhere else.
/// `GetEffectiveRightsFromAclW` evaluates one SID at a time and does not expand
/// group nesting, so the union over these trustees is what *could* be reached —
/// never less.
fn unprivileged_trustees(dacl: &acl::Dacl, owner: &str) -> Vec<String> {
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
        if !acl::is_privileged(&ace.sid) && ace.sid != owner {
            add(ace.sid.clone());
        }
    }
    // The account running the check, even when the DACL does not name it, so
    // that "can I, the person who ran this, write to my own product directory?"
    // has an answer rather than an absence. It is not the owner's grant being
    // smuggled back in: on the check that matters this is a *different* account
    // from the service's `SYSTEM` owner, and on a developer's box it is the same
    // account, whose genuine extra access is reported separately rather than
    // here.
    if let Ok(account) = acl::current_user_sid() {
        if !acl::is_privileged(&account) && account != owner {
            add(account);
        }
    }
    trustees
}

/// The dangerous rights the object's owner holds **outside** the DACL.
///
/// The complement of [`Protection::exposed`], not a subset of it: `exposed` is
/// what the DACL failed to close, and this is what no DACL can close. After a
/// successful [`protect`] the two are `[]` and `[WriteDac]` respectively on a
/// process this account started, and `[]` and `[]` on one the SCM started as
/// `LocalSystem`.
///
/// Measured, by probe against a process this crate had protected: `OpenProcess`
/// for `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_WRITE`,
/// `PROCESS_SUSPEND_RESUME` and `PROCESS_ALL_ACCESS` were all refused with Win32
/// error 5 on a process owned by the probing account, while `OpenProcess` for
/// `WRITE_DAC` succeeded. So an unprivileged owner holds exactly `WRITE_DAC`
/// outside the DACL — one of the seven — and that is what this returns. Both
/// probes are quoted in the module documentation.
///
/// `ReadControl` is the other half of the owner's implicit grant and is
/// deliberately not here: reading permissions back is not one of the seven and
/// is reported by nothing.
///
/// A privileged owner returns nothing. `SYSTEM` and an administrator holding
/// `PROCESS_ALL_ACCESS` is [`Protection::manageable`]'s business — it is a grant
/// the DACL *does* make in [`PROTECTED_DACL`] — and counting it here as well
/// would put a caveat on every correctly configured service.
fn owner_rights(owner: &str) -> Vec<Right> {
    if acl::is_privileged(owner) {
        Vec::new()
    } else {
        rights_in(WRITE_DAC)
    }
}

/// The union of what every unprivileged trustee is granted on this DACL.
///
/// The second half of the return is `false` when an evaluation failed, which the
/// caller must not read as "nothing granted". See [`summarise`] for the report
/// text and [`report`] for what happens to the failed case.
fn unprivileged_mask(dacl: &acl::Dacl, owner: &str) -> (u32, bool) {
    let mut mask = 0u32;
    let mut complete = true;
    for sid in unprivileged_trustees(dacl, owner) {
        match dacl.effective(&sid) {
            Ok(rights) => mask |= rights,
            Err(_) => {
                // A trustee that cannot be evaluated counts as *granted* the
                // dangerous rights. The other direction would report protection
                // that has not been established, which is the one answer a
                // security report must never give.
                mask |= DANGEROUS;
                complete = false;
            }
        }
    }
    // The owner, evaluated separately and only when the DACL names them.
    //
    // `unprivileged_trustees` leaves the owner out, for the measured reason its
    // own documentation gives: the API over-reports the owner's access to the
    // whole mask when the DACL does not name them. But when the DACL *does* name
    // them the answer is the ACEs' doing and is usable — measured, an ACE of
    // `0x0020` on the owner came back as `0x1020` and `OpenProcess` for that one
    // right succeeded — and leaving it out would mean a DACL that granted the
    // owner everything reported as though it granted nothing.
    if !acl::is_privileged(owner) && dacl.aces().iter().any(|ace| ace.sid == owner) {
        match dacl.effective(owner) {
            Ok(rights) => mask |= rights,
            Err(_) => {
                mask |= DANGEROUS;
                complete = false;
            }
        }
    }
    (mask, complete)
}

/// A one-line description of a DACL, of the shape `icacls` prints.
///
/// Not SDDL and not a table: it is the form in which somebody compares what this
/// crate did against what their own tools show, and it names the well-known
/// trustees rather than printing `S-1-5-...` at them.
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

/// Build a [`Protection`] from a process object's current DACL and owner.
///
/// The owner is passed in rather than read here because reading it needs a
/// handle, and the handle belongs to the caller that is about to release it. The
/// empty string means the owner could not be read — in which case no owner
/// exemption is applied and the unnamed-owner case is assumed, which is the
/// conservative reading: it reports the owner's `WRITE_DAC` rather than silently
/// dropping the caveat.
fn report(pid: u32, dacl: &acl::Dacl, owner: &str) -> Protection {
    let (unprivileged, _) = unprivileged_mask(dacl, owner);
    let denied: Vec<Right> = Right::ALL
        .into_iter()
        .filter(|right| unprivileged & right.mask() == 0)
        .collect();
    let exposed = rights_in(unprivileged);

    let query_limited = dacl
        .effective(acl::INTERACTIVE)
        .map(|mask| mask & PROCESS_QUERY_LIMITED_INFORMATION != 0)
        .unwrap_or(false);
    // Both, and `all` rather than `any`: a process only an administrator or only
    // SYSTEM can manage is a process half the machine's operators cannot touch,
    // and the report has one field for the pair because the field answers one
    // question — can this machine be administered?
    let manageable = [acl::SYSTEM, acl::ADMINISTRATORS].iter().all(|sid| {
        dacl.effective(sid)
            .map(|mask| mask & PROCESS_ALL_ACCESS == PROCESS_ALL_ACCESS)
            .unwrap_or(false)
    });

    Protection {
        pid,
        denied,
        exposed,
        owner: owner.to_string(),
        owner_rights: owner_rights(owner),
        query_limited,
        manageable,
        summary: summarise(dacl),
    }
}

/// A handle to a process, closed exactly once.
///
/// A guard rather than a `CloseHandle` at the end of each function: the
/// functions here have three and four `?` between the open and the close, and a
/// leaked process handle is one that keeps a terminated process's object alive
/// until the scanner exits.
struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenProcess` and is owned by this guard
        // and by nothing else; the result is ignored because a close that fails
        // has already had whatever effect it was going to have.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// `WRITE_DAC` and `READ_CONTROL`: what the DACL work needs on a process.
///
/// `WRITE_DAC` is what `SetSecurityInfo` checks for a DACL change. There is no
/// `PROCESS_SET_SECURITY_INFO` in Win32 — a process expresses that permission as
/// `WRITE_DAC` from the standard access mask, the same bit `icacls` asks for —
/// and the mapping is written down here so that nobody has to go looking for a
/// constant that does not exist. `READ_CONTROL` is asked for alongside because
/// [`verify`] reads the DACL back, and a handle opened for one and not the other
/// would make the apply and the check take two opens of the same object.
const SET_SECURITY: u32 = WRITE_DAC | READ_CONTROL;

/// The process id of this process.
pub fn current_pid() -> u32 {
    // SAFETY: takes no arguments and cannot fail.
    unsafe { GetCurrentProcessId() }
}

/// Open a process for the DACL work, with an error a user can act on.
fn open(pid: u32) -> Result<ProcessHandle, String> {
    // SAFETY: `OpenProcess` takes no buffer; the pid is a plain integer and
    // `false` means the returned handle is not inheritable, which is right for a
    // handle this module only ever passes to `SetSecurityInfo` and
    // `GetSecurityInfo`.
    let opened = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(SET_SECURITY), false, pid) };
    match opened {
        Ok(handle) => Ok(ProcessHandle(handle)),
        Err(error) => {
            let code = (error.code().0 as u32) & 0xFFFF;
            Err(format!(
                "process {pid} could not be opened for a permissions change (Win32 error \
                 {code}). Writing a process's permissions needs WRITE_DAC on it, which an \
                 account only holds for processes it owns — and for any process when it is \
                 elevated. For the product's own service, run this from an elevated prompt; \
                 right-click the terminal, then \"Run as administrator\"."
            ))
        }
    }
}

/// Protect a process by pid.
///
/// Applies [`PROTECTED_DACL`] and then reads it back, so what comes home is the
/// object's answer and not this function's intention — see [`verify`] for why
/// that distinction is the whole point.
pub fn protect(pid: u32) -> Result<Protection, String> {
    let handle = open(pid)?;
    acl::apply_to_process(handle.0, PROTECTED_DACL)
        .map_err(|detail| format!("process {pid} could not be protected: {detail}"))?;
    let dacl = acl::Dacl::of_process(handle.0)
        .map_err(|detail| format!("process {pid} could not be read back: {detail}"))?;
    let owner = acl::Dacl::owner_of_process(handle.0)
        .map_err(|detail| format!("process {pid} could not be protected: {detail}"))?;
    let outcome = report(pid, &dacl, &owner);
    log::info!("{}", outcome.describe());
    Ok(outcome)
}

/// Protect this process.
///
/// Thin over [`protect`] with this process's own pid, and deliberately so: see
/// the module documentation for the pseudo-handle measurement and for why there
/// is one code path here and not two.
pub fn protect_current_process() -> Result<Protection, String> {
    protect(current_pid())
}

/// Undo [`protect`], putting back the shape a process object normally has.
///
/// Here for two reasons, and the second is the important one. An operator needs
/// a way to hand a process back to the machine — a service being debugged on a
/// developer's box, a support engineer reproducing a report. And a test that
/// protects a process must be able to un-protect it on every path out, including
/// a panic, or the suite can leave behind something the harness cannot kill. See
/// the tests at the bottom of this module for how that is arranged.
pub fn restore(pid: u32) -> Result<(), String> {
    let sddl = default_dacl()?;
    let handle = open(pid)?;
    acl::apply_to_process(handle.0, &sddl)
        .map_err(|detail| format!("process {pid} could not be restored: {detail}"))
}

/// Read a process's DACL back and report whether each dangerous right is
/// actually denied.
///
/// # Why this is the part that matters
///
/// [`protect`] claims to have closed seven doors. Without this function that
/// claim is an assertion about a call that returned success, and a call
/// returning success is not the same fact as a DACL that says what it was meant
/// to say. An entry merged back in by inheritance, a grant written with the
/// wrong object's access mask — which is exactly the `FA`-on-a-process mistake
/// the module documentation describes — a security descriptor applied to the
/// wrong object class: all of them produce a green tick and a machine that is
/// not protected. So the check re-reads the object's DACL, evaluates it with the
/// operating system's own access check for every trustee an ordinary account
/// could hold, and reports what it found.
///
/// The failure direction is chosen deliberately: an entry that cannot be
/// evaluated counts as **granted**, so an unreadable DACL reports an exposed
/// right rather than a denied one. A check that guessed in the other direction
/// would report protection it had not established.
pub fn verify(pid: u32) -> Result<Protection, String> {
    let handle = open(pid)?;
    let dacl = acl::Dacl::of_process(handle.0)
        .map_err(|detail| format!("process {pid} could not be read: {detail}"))?;
    let owner = acl::Dacl::owner_of_process(handle.0)
        .map_err(|detail| format!("process {pid} could not be read: {detail}"))?;
    Ok(report(pid, &dacl, &owner))
}

/// True when no ordinary account can stop or subvert this process.
///
/// The one-line form of [`verify`], for a caller that has to decide whether to
/// warn, and it is the **strict** answer: it requires the DACL to have closed
/// the seven *and* the owner to be an account whose access is deliberate. Both
/// halves are needed, because a protected process owned by a user is one that
/// user can un-protect — the `WRITE_DAC` measured by probe in the module
/// documentation — and answering `true` for it would be reporting a lock while
/// ignoring who holds the key.
///
/// The consequence worth knowing: on a machine where a user started the process
/// this is `false` however well [`protect`] did, and for an installed service
/// the SCM created as `LocalSystem` it is `true`. That is not a defect in the
/// answer; it is the answer.
///
/// It is deliberately not `verify(pid).is_ok()` either: a process that cannot be
/// opened is a process whose protection cannot be vouched for, and this returns
/// `false` for it rather than the success an `Ok` would imply.
pub fn is_protected(pid: u32) -> bool {
    match verify(pid) {
        Ok(report) => {
            report.exposed.is_empty() && report.owner_rights.is_empty() && report.manageable
        }
        Err(_) => false,
    }
}

/// The union of what every unprivileged trustee is granted, as a raw mask.
///
/// Public because the same arithmetic decides both the process report and the
/// directory report in [`crate::files`], and a caller comparing the two should
/// not have to re-implement it.
pub fn unprivileged_rights(pid: u32) -> Result<u32, String> {
    let handle = open(pid)?;
    let dacl = acl::Dacl::of_process(handle.0)?;
    let owner = acl::Dacl::owner_of_process(handle.0).unwrap_or_default();
    Ok(unprivileged_mask(&dacl, &owner).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that change *this* process's own DACL.
    ///
    /// `cargo test` runs test functions as threads of one process, and two of
    /// the tests below apply a DACL to the process they are running in. Without
    /// this, one test's `before` reading could be taken while the other's
    /// protection is in place, and the failure would look like a bug in the
    /// protection rather than a race in the test. The mutex is held for the whole
    /// of each such test, and a test that panics while holding it poisons it —
    /// which is why the lock is taken through `into_inner` below: one failing
    /// test must not take the rest of the module with it by panicking every
    /// later lock.
    static CURRENT_PROCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the current-process lock, ignoring a poisoned mutex.
    fn lock_current_process() -> std::sync::MutexGuard<'static, ()> {
        CURRENT_PROCESS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A child process that exits on its own within about ten seconds.
    ///
    /// The reason the tests in this module are safe to run. A test that denies
    /// `PROCESS_TERMINATE` to the account running it must never be able to leave
    /// a process behind that nobody can kill — not when the test panics, not
    /// when the machine is slow, not when the code under test is broken. `ping`
    /// is used rather than `timeout` because `timeout` refuses to run without a
    /// console when its output is redirected, and the redirection is what keeps
    /// the test output readable.
    fn spawn_doomed_child() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/c", "ping -n 11 127.0.0.1 >NUL"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("starting a short-lived child process")
    }

    /// Restores and kills a child on every path out of a test, including a
    /// panic.
    ///
    /// The backstop under the whole module. `restore` first, so that the kill
    /// below is not fighting the DACL the test just applied; then `kill`, which
    /// is best-effort because the child's own ten-second timeout may have fired
    /// already. If both somehow failed the child still exits by itself, which is
    /// what makes this safe rather than merely careful.
    struct ChildGuard(std::process::Child);

    impl ChildGuard {
        fn new() -> Self {
            Self(spawn_doomed_child())
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = restore(self.0.id());
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn zz_measure_owner_named_in_the_dacl() {
        let child = ChildGuard::new();
        let pid = child.pid();
        let handle = open(pid).expect("opening the child");
        let owner = acl::Dacl::owner_of_process(handle.0).expect("owner");
        println!("OWNER {owner}");
        let sddl = format!(
            "D:P(A;;0x1000;;;SY)(A;;0x1000;;;BA)(A;;0x0020;;;{owner})"
        );
        acl::apply_to_process(handle.0, &sddl).expect("applying a DACL that names the owner");
        let dacl = acl::Dacl::of_process(handle.0).expect("reading it back");
        for sid in [
            owner.clone(),
            acl::SYSTEM.to_string(),
            acl::ADMINISTRATORS.to_string(),
            acl::EVERYONE.to_string(),
        ] {
            println!("EFF {sid} {:?}", dacl.effective(&sid).map(|m| format!("0x{m:08x}")));
        }
        for (name, bit) in [("TERMINATE", PROCESS_TERMINATE), ("VM_WRITE", PROCESS_VM_WRITE)] {
            let probe = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(bit), false, pid) };
            match probe {
                Ok(h) => {
                    println!("OPEN {name} OK");
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                }
                Err(e) => println!("OPEN {name} refused Win32 {}", (e.code().0 as u32) & 0xFFFF),
            }
        }
        restore(pid).expect("restoring the child");
    }

    #[test]
    fn the_dangerous_mask_is_exactly_the_seven_rights() {
        // The list is the policy. A bit added to `DANGEROUS` and not to `Right`
        // would be reported as denied while the report never named it, and a bit
        // added to `Right` and not to `DANGEROUS` would be named and not checked.
        let from_rights = Right::ALL
            .into_iter()
            .fold(0u32, |mask, right| mask | right.mask());
        assert_eq!(from_rights, DANGEROUS);
        assert_eq!(DANGEROUS.count_ones(), 7);
        for right in Right::ALL {
            assert_eq!(Right::from_mask(right.mask()), Some(right));
            assert_eq!(rights_in(right.mask()), vec![right]);
        }
        assert_eq!(Right::from_mask(0x8000_0000), None);
    }

    #[test]
    fn no_two_rights_share_a_number_or_a_word() {
        // A duplicated mask bit would make one right's report the other's, and a
        // duplicated name would make a report ambiguous about which door is open.
        let mut masks: Vec<u32> = Right::ALL.iter().map(|right| right.mask()).collect();
        masks.sort_unstable();
        masks.dedup();
        assert_eq!(masks.len(), Right::ALL.len());
        let mut names: Vec<&str> = Right::ALL.iter().map(|right| right.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Right::ALL.len());
        for right in Right::ALL {
            assert!(right.consequence().len() > 30, "{right}");
        }
    }

    #[test]
    fn the_protected_dacl_names_only_the_three_accounts_it_should() {
        // Read as text, because the string *is* the policy: SYSTEM and the
        // administrators with `PROCESS_ALL_ACCESS`, the interactive user with the
        // one limited right, and no deny ACE that could catch SYSTEM on its way
        // past.
        assert!(PROTECTED_DACL.starts_with("D:P"), "{PROTECTED_DACL}");
        assert!(
            PROTECTED_DACL.contains("(A;;0x1F0FFF;;;SY)"),
            "{PROTECTED_DACL}"
        );
        assert!(
            PROTECTED_DACL.contains("(A;;0x1F0FFF;;;BA)"),
            "{PROTECTED_DACL}"
        );
        assert!(
            PROTECTED_DACL.contains("(A;;0x1000;;;IU)"),
            "{PROTECTED_DACL}"
        );
        assert!(
            !PROTECTED_DACL.contains("(D;"),
            "a deny ACE here would deny SYSTEM as well as the attacker: {PROTECTED_DACL}"
        );
        assert!(!PROTECTED_DACL.contains(";;;WD)"), "{PROTECTED_DACL}");
        assert!(!PROTECTED_DACL.contains(";;;BU)"), "{PROTECTED_DACL}");
        assert!(
            !PROTECTED_DACL.contains("FA"),
            "`FA` is FILE_ALL_ACCESS and is not PROCESS_ALL_ACCESS on a process \
             object: {PROTECTED_DACL}"
        );
    }

    #[test]
    fn restore_names_the_running_account_so_cleanup_cannot_be_locked_out() {
        // The failure this prevents is the worst one available to `restore`: a
        // DACL with SYSTEM and Administrators in it and nobody else, applied to a
        // process owned by a user account, leaves a process that user cannot
        // touch again. Reading the token is what makes that impossible, and the
        // account has to appear in the string for it to be true.
        let sddl = default_dacl().expect("naming the running account");
        assert!(
            sddl.starts_with("D:P(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)"),
            "{sddl}"
        );
        let account = acl::current_user_sid().expect("the running account");
        if account == acl::SYSTEM || account == acl::ADMINISTRATORS {
            // An elevated run: the two entries above already cover it, and
            // repeating the SID would be noise.
            assert!(!sddl.contains(&account), "{sddl}");
        } else {
            assert!(
                sddl.contains(&format!("(A;;0x1F0FFF;;;{account})")),
                "{sddl}"
            );
        }
    }

    #[test]
    fn protecting_a_child_process_closes_the_seven_rights_and_is_undone() {
        // The end-to-end test, against a real process the test owns.
        //
        // What *is* exercised: opening a live process object for `WRITE_DAC`,
        // applying the protected DACL to it, reading it back with the operating
        // system's own access check, and restoring it. What is *not*: an actual
        // attempt by another account to terminate the child. This process runs as
        // one account and Windows will not let it acquire another, so the deny is
        // measured through the ACL rather than through a second `OpenProcess` —
        // which is the same evidence the report itself carries, and is stated
        // here rather than left to be assumed.
        let child = ChildGuard::new();
        let pid = child.pid();

        // Before: a freshly created process carries its token's default DACL,
        // which measures on this machine as full control for the owning account,
        // Administrators and SYSTEM.
        let before = verify(pid).expect("reading the child's initial permissions");
        assert!(
            !before.exposed.is_empty(),
            "a process with a default DACL must report the seven rights as reachable, or this \
             test is not measuring anything: {before:?}"
        );
        assert!(
            !before.query_limited,
            "the default DACL grants an interactive user no query right at all, which is one of \
             the things protecting it has to change: {before:?}"
        );
        assert_eq!(
            before.exposed,
            Right::ALL.to_vec(),
            "every one of the seven is reachable on a freshly created process, through the \
             grant the default DACL makes to the account that started it: {before:?}"
        );
        assert_eq!(
            before.owner_rights,
            vec![Right::WriteDac],
            "the owner's implicit WRITE_DAC is there from the start and stays there \
             afterwards: {before:?}"
        );

        let applied = protect(pid).expect("protecting a process this test owns");
        assert!(
            applied.exposed.is_empty(),
            "the seven must be closed after protecting: {applied:?}"
        );
        assert_eq!(applied.denied, Right::ALL);
        assert_eq!(
            applied.owner_rights,
            vec![Right::WriteDac],
            "and the one right the DACL cannot reach is named rather than lost: {applied:?}"
        );
        assert!(
            !is_protected(pid),
            "a process owned by an ordinary account is not protected in the strict sense, \
             because that account can rewrite the permissions: {applied:?}"
        );
        assert!(
            applied.manageable,
            "administrators must keep PROCESS_ALL_ACCESS, and this is also the assertion that \
             would catch `FA` being used for a process object: {applied:?}"
        );
        assert!(
            applied.query_limited,
            "the interactive user must keep PROCESS_QUERY_LIMITED_INFORMATION, or the front \
             end cannot ask the service anything"
        );

        // Read back through a second, independent call: what the object says, not
        // what `protect` returned.
        let checked = verify(pid).expect("re-reading the child's permissions");
        assert_eq!(checked.exposed, Vec::new());
        assert!(
            checked.summary.contains("BUILTIN\\Administrators"),
            "{checked:?}"
        );
        assert!(
            checked.summary.contains("NT AUTHORITY\\INTERACTIVE"),
            "{checked:?}"
        );

        restore(pid).expect("restoring the child");
        let after = verify(pid).expect("reading the child back after restoring");
        assert_eq!(
            after.exposed,
            Right::ALL.to_vec(),
            "restoring must put the process back to the state it started in, or the test \
             harness cannot clean up after it: {after:?}"
        );
    }

    #[test]
    fn the_deny_everyone_construction_denies_system_as_well() {
        // The measurement behind this module's documentation, and the reason
        // `PROTECTED_DACL` is an allow list.
        //
        // The string below is the construction that reads as obviously correct:
        // deny the seven to Everyone, then grant SYSTEM everything. If DACL
        // evaluation were "collect the denies, collect the allows, subtract",
        // SYSTEM would come out with `PROCESS_ALL_ACCESS`. It is not, and SYSTEM
        // comes out without the seven — because SYSTEM is in Everyone and a deny
        // ACE ends the check for the bits it names.
        let child = ChildGuard::new();
        let handle = open(child.pid()).expect("opening the child");
        acl::apply_to_process(
            handle.0,
            "D:P(D;;0x000C082B;;;WD)(A;;0x1F0FFF;;;SY)(A;;0x1F0FFF;;;BA)",
        )
        .expect("applying the deny-style DACL");

        let dacl = acl::Dacl::of_process(handle.0).expect("reading the DACL back");
        let system = dacl.effective(acl::SYSTEM).expect("evaluating SYSTEM");
        assert_eq!(
            system & DANGEROUS,
            0,
            "SYSTEM was denied the dangerous rights by a deny ACE naming Everyone. This is the \
             measurement; if it ever changes, the allow list is still the right shape because it \
             does not depend on evaluation order"
        );
        // The grant to SYSTEM is present and is simply not reached for those bits.
        assert!(
            dacl.aces()
                .iter()
                .any(|ace| ace.sid == acl::SYSTEM && !ace.denied),
            "the grant to SYSTEM is in the DACL and is being overridden, not missing"
        );
        // And the account the deny was aimed at is denied too, so the
        // construction is not merely failing to help — it works as its author
        // intended against the attacker and against the administrator alike.
        assert_eq!(
            dacl.effective(acl::EVERYONE)
                .expect("evaluating Everyone")
                & DANGEROUS,
            0
        );
    }

    #[test]
    fn fa_is_not_process_all_access_and_would_have_left_three_rights_granted() {
        // The other measured trap, and the one that would have shipped silently.
        //
        // `FA` is `FILE_ALL_ACCESS`, `0x001F01FF`. `PROCESS_ALL_ACCESS` is
        // `0x001F0FFF`. The difference is `PROCESS_SUSPEND_RESUME`,
        // `PROCESS_QUERY_INFORMATION` and `PROCESS_SET_INFORMATION`, and an SDDL
        // string does not translate between object types — so a DACL written with
        // the file spelling on a process object grants an administrator
        // everything except the ability to suspend and inspect it, and the
        // administrator's tools fail in a way nothing here would explain.
        assert_eq!(PROCESS_ALL_ACCESS, 0x001F_0FFF);
        assert_ne!(PROCESS_ALL_ACCESS, 0x001F_01FF);

        let child = ChildGuard::new();
        let handle = open(child.pid()).expect("opening the child");
        acl::apply_to_process(handle.0, "D:P(A;;FA;;;SY)").expect("applying the file spelling");
        let dacl = acl::Dacl::of_process(handle.0).expect("reading the DACL back");
        let system = dacl.effective(acl::SYSTEM).expect("evaluating SYSTEM");
        assert_eq!(
            system, 0x001F_01FF,
            "the measured value of `FA` on a process object"
        );
        assert_ne!(
            system & PROCESS_ALL_ACCESS,
            PROCESS_ALL_ACCESS,
            "`FA` must come up short of the full process mask, or this test is not measuring the \
             trap it exists for"
        );
        assert_eq!(
            PROCESS_ALL_ACCESS & !system,
            0x0000_0E00,
            "PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION"
        );
    }

    #[test]
    fn pseudo_handle_dacl_changes_are_measurable() {
        // `GetCurrentProcess()` returns a pseudo-handle the kernel resolves to
        // this process, and the brief this crate was written against expected
        // `SetSecurityInfo` to refuse it for a DACL change. On this machine it
        // does not — measured, and recorded here rather than asserted in the
        // direction the documentation predicted.
        //
        // What the measurement does not settle is *why*, and the test says so
        // rather than picking the interesting explanation. This process's own
        // DACL grants the running account `WRITE_DAC`, and the running account is
        // also the object's owner, which Windows grants `WRITE_DAC` implicitly;
        // either alone would let the call through, and nothing available on a
        // single-account machine separates them. So this pins the observable
        // behaviour and no more: the pseudo-handle is usable here.
        //
        // The two states are the same either way, because the change is undone
        // when it succeeded, so this test never leaves `PROTECTED_DACL` applied.
        use windows::Win32::System::Threading::GetCurrentProcess;

        let _guard = lock_current_process();
        // SAFETY: `GetCurrentProcess` takes no arguments and returns a
        // pseudo-handle that must not be closed. It is passed to one call that
        // either succeeds or fails, and is never stored.
        let pseudo = unsafe { GetCurrentProcess() };
        let outcome = acl::apply_to_process(pseudo, PROTECTED_DACL);
        log::info!(
            "SetSecurityInfo on the current-process pseudo-handle for a DACL change: {}",
            match &outcome {
                Ok(()) => "succeeded".to_string(),
                Err(detail) => format!("refused — {detail}"),
            }
        );
        if outcome.is_ok() {
            // Undone immediately, so this test does not depend on the order the
            // suite runs in.
            restore(current_pid()).expect("undoing the pseudo-handle change");
        }
        assert!(
            verify(current_pid()).is_ok(),
            "the current process must be readable after this test, whichever way it went"
        );
    }

    #[test]
    fn protecting_and_restoring_this_process_leaves_it_killable() {
        // The protection applied to the process running the tests.
        //
        // Safe to do, and the reasoning is worth writing down because it is not
        // obvious. The test harness holds a handle to this process that it opened
        // *before* any of this ran, carrying `PROCESS_TERMINATE`; access is
        // decided when a handle is opened and never re-checked, so the harness
        // can still terminate the test binary however the DACL reads afterwards.
        // A second and independent backstop: this process can always end itself
        // with `ExitProcess`, which needs no handle at all. And the DACL is put
        // back before the test returns, so the only window in which the process
        // is protected is the window in which this test is running.
        //
        // What *is* exercised: the apply, the verify and the restore on the
        // process this code is running in. What is *not*: termination by another
        // account, for the reason given in the child-process test above.
        let _guard = lock_current_process();
        let pid = current_pid();
        let before = verify(pid).expect("reading this process's own permissions");

        let applied = protect_current_process().expect("protecting this process");
        assert!(applied.exposed.is_empty(), "{applied:?}");
        assert!(applied.manageable, "{applied:?}");
        assert!(applied.query_limited, "{applied:?}");

        let checked = verify(pid).expect("re-reading this process's own permissions");
        for right in Right::ALL {
            assert!(
                !checked.exposed.contains(&right),
                "{right} is still reachable on this process after protecting it"
            );
        }
        assert_ne!(
            checked.summary, before.summary,
            "the reported permissions have to change, or the report is not reading the object"
        );
        // Naming the process in the sentence a user reads, so a report about the
        // wrong process is visible rather than plausible.
        assert!(checked.describe().contains(&pid.to_string()));

        restore(pid).expect("restoring this process");
        let after = verify(pid).expect("reading this process back");
        assert_eq!(
            after.exposed,
            Right::ALL.to_vec(),
            "restoring must put this process back to the state it started in: {after:?}"
        );
    }

    #[test]
    fn a_report_of_exposed_rights_names_them_rather_than_only_failing() {
        // The unhappy path has to be as legible as the happy one, because it is
        // the one a user sees when something is wrong.
        let report = Protection {
            pid: 4321,
            denied: vec![Right::Terminate],
            exposed: vec![Right::CreateThread, Right::VmWrite],
            owner: "S-1-5-21-0-0-0-1001".to_string(),
            owner_rights: vec![Right::WriteDac],
            query_limited: false,
            manageable: true,
            summary: String::new(),
        };
        let line = report.describe();
        assert!(line.contains("4321"), "{line}");
        assert!(line.contains("NOT protected"), "{line}");
        assert!(line.contains("PROCESS_CREATE_THREAD"), "{line}");
        assert!(line.contains("PROCESS_VM_WRITE"), "{line}");
        // And a caller can read "not protected" off the structure without
        // parsing that sentence, which is what the CLI does.
        assert!(!report.exposed.is_empty());
    }

    #[test]
    fn every_stated_limit_is_a_sentence_about_the_real_world() {
        // Four limits, each naming a real attacker or a real expiry. The test is
        // here so that a limit cannot be dropped in a later edit without the
        // documentation becoming wrong in the direction of claiming more.
        let limits = Protection::limits();
        assert_eq!(limits.len(), 4);
        let joined = limits.join(" ");
        for word in ["administrator", "owner", "kernel", "reboot"] {
            assert!(
                joined.contains(word),
                "the limits must still name {word}: {joined}"
            );
        }
    }

    #[test]
    fn a_process_that_cannot_be_opened_reports_no_protection() {
        // `is_protected` on a process that cannot be opened must be `false` and
        // not an error a caller might read as success. Pid 0 is never a real
        // process, so `OpenProcess` fails.
        assert!(!is_protected(0));
        assert!(verify(0).is_err());
        assert!(protect(0).is_err());
        // And the refusal says what to do about it rather than printing a code.
        let message = protect(0).expect_err("pid 0 is not a process");
        assert!(message.contains("elevated"), "{message}");
        assert!(message.contains("administrator"), "{message}");
    }

    #[test]
    fn restoring_a_process_that_cannot_be_opened_is_an_error_rather_than_silence() {
        // A restore that quietly did nothing would leave a caller believing it
        // had handed the machine back.
        assert!(restore(0).is_err());
    }

    #[test]
    fn the_unprivileged_trustees_cover_every_named_sid_except_the_owner() {
        // Two things at once, and both are measured.
        //
        // First, the reason this function exists at all: a default process
        // object's DACL names the owning *user* by their own SID and no group at
        // all, so a check built only from the four well-known group SIDs would
        // report a completely open process as having nothing exposed — and it
        // would do it while looking entirely correct. That is why every SID the
        // DACL names is pulled in, and the assertion on the union below is what
        // catches a regression to the group-only version.
        //
        // Second, the one exclusion. The owner is left to its own rule, because
        // `GetEffectiveRightsFromAclW` returns `PROCESS_ALL_ACCESS` for a
        // non-named owner on a DACL that refuses exactly that.
        let child = ChildGuard::new();
        let handle = open(child.pid()).expect("opening the child");
        let dacl = acl::Dacl::of_process(handle.0).expect("reading the child's DACL");
        let owner = acl::Dacl::owner_of_process(handle.0).expect("the owner");

        let trustees = unprivileged_trustees(&dacl, &owner);
        for sid in acl::UNPRIVILEGED_TRUSTEES {
            assert!(
                trustees.contains(&sid.to_string()),
                "{sid} missing from {trustees:?}"
            );
        }
        let named: Vec<String> = dacl
            .aces()
            .into_iter()
            .map(|ace| ace.sid)
            .filter(|sid| !acl::is_privileged(sid))
            .collect();
        // The default DACL names the owning account, so this asserts something
        // real rather than iterating an empty list.
        assert!(
            named.contains(&owner),
            "this test is about the owner being named by the default DACL: {named:?}"
        );
        for sid in named.iter().filter(|sid| **sid != owner) {
            assert!(
                trustees.contains(sid),
                "{sid} named in the DACL but not evaluated"
            );
        }
        assert!(
            !trustees.contains(&owner),
            "the owner must be left to its own rule, not evaluated as an ordinary \
             trustee: {trustees:?}"
        );
        assert!(
            !trustees.iter().any(|sid| acl::is_privileged(sid)),
            "a privileged account must not be counted as an ordinary one: {trustees:?}"
        );

        // The union still finds the default DACL's grant — through the owner's
        // own rule, since a default DACL grants the account that started the
        // process and no group at all.
        let (mask, complete) = unprivileged_mask(&dacl, &owner);
        assert!(complete, "every trustee on a default DACL is evaluable");
        assert_eq!(
            mask & DANGEROUS,
            DANGEROUS,
            "a default process DACL grants its owner everything, so every one of the seven \
             must be reported as reachable: 0x{mask:08x}"
        );
    }

    #[test]
    fn an_unprivileged_owner_is_reported_as_able_to_rewrite_the_permissions() {
        // The caveat, and the reason it is a field rather than a sentence. An
        // unprivileged owner holds `WRITE_DAC` outside the DACL — measured by
        // opening a protected process owned by this account for `WRITE_DAC` and
        // having it succeed while `PROCESS_ALL_ACCESS` was refused — so a
        // protected process a user started is still one that user can un-protect.
        // The service case is the other branch: owned by `SYSTEM`, holding
        // `PROCESS_ALL_ACCESS` through the DACL, and carrying no caveat at all.
        assert_eq!(owner_rights("S-1-5-21-0-0-0-1001"), vec![Right::WriteDac]);
        assert_eq!(owner_rights(acl::SYSTEM), Vec::new());
        assert_eq!(owner_rights(acl::ADMINISTRATORS), Vec::new());

        // And on a real protected process the caveat is exactly this, with the
        // other six genuinely refused by the operating system.
        let child = ChildGuard::new();
        let pid = child.pid();
        protect(pid).expect("protecting the child");
        let checked = verify(pid).expect("reading the child back");
        assert_eq!(checked.owner_rights, vec![Right::WriteDac], "{checked:?}");
        assert_eq!(checked.owner, acl::current_user_sid().expect("the account"));
        assert_eq!(
            checked.exposed,
            Vec::new(),
            "the DACL closed everything it can close, and `exposed` is about the DACL: \
             {checked:?}"
        );
        assert_eq!(checked.denied, Right::ALL);
        // The sentence a user reads has to carry it, or the field is the only
        // place the limit exists and nobody reads fields.
        let line = checked.describe();
        assert!(line.contains("owns this process"), "{line}");
        assert!(line.contains("WRITE_DAC"), "{line}");
        assert!(
            !line.contains("NOT protected"),
            "the six the DACL closed are closed, and saying otherwise would be the wrong \
             alarm: {line}"
        );
        // A protected process whose owner is unprivileged is therefore not
        // `is_protected`: an ordinary account can still reopen it. That is the
        // honest answer on a developer's machine, and the reason the field exists
        // rather than being folded away.
        assert!(!is_protected(pid));
    }
}

