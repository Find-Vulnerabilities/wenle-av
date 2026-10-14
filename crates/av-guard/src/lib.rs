//! Self-protection: what stops a program running as an ordinary user from
//! disabling this product.
//!
//! # The question this crate answers
//!
//! The product runs as a Windows service, usually as `LocalSystem`, on a machine
//! where the attacker is an ordinary user or a process running as one. So the
//! question is not whether this can be defeated. It can, and the limits are
//! listed at the end of this page. The question is:
//!
//! > **What can a non-elevated process do to this product, and what stops it?**
//!
//! Every module here is one clause of the answer, and the answer is written down
//! module by module below. The stakes are why the question is asked at all.
//! Malware that can kill the scanner, delete its database, rewrite its
//! configuration or stop it from starting has won, however good the detection is.
//!
//! # The answer, module by module
//!
//! ## [`process`]: taking the running process out
//!
//! `TerminateProcess` on the scanner needs one right, `PROCESS_TERMINATE`, and a
//! process object's default security descriptor grants a great deal more than
//! that to whoever created it. An ordinary user who can open the process can also
//! suspend it, change its memory, or inject a thread, and none of those needs the
//! process to be killed to be effective.
//!
//! [`process::protect_current_process`] rewrites this process's own DACL to name
//! `SYSTEM`, `Administrators` and the account the process is running as, and to
//! grant nothing to anyone else. It is the same function as [`process::protect`]
//! with `GetCurrentProcess`'s pid, and it is what the service calls at startup.
//! The seven rights that matter (terminate, create-thread, VM-write,
//! VM-operation, suspend-resume, set-information and write-DAC) are closed
//! together, because closing them one at a time leaves the others as an equally
//! good way in.
//!
//! **The measurement is the interesting part.** A DACL that does not name its own
//! object's owner makes `GetEffectiveRightsFromAclW` report *all access* for that
//! owner while reporting zero for every other trustee on the same DACL. An audit
//! that took that number at face value would say the process is wide open when it
//! is not. Worse, in the other direction, it would exclude the owner
//! unconditionally and miss a DACL that really does grant it everything. The
//! exclusion is therefore conditional on the DACL *not* naming the owner, and
//! both cases are tested.
//!
//! ## [`service`]: stopping it from starting, or from staying started
//!
//! Stopping the service, or making it stop itself, is the obvious attack. The
//! Service Control Manager's default security descriptor already denies an
//! ordinary interactive logon `SERVICE_START` and `SERVICE_STOP`, which is
//! measured here rather than assumed, so the direct attack does not work. What
//! does work is making the service crash on hostile input, and then the machine
//! stays unprotected until somebody notices.
//!
//! `service::configure_recovery` tells the SCM to restart the service after 5, 10
//! and 30 seconds, with the failure count forgotten after a day and non-crash
//! failures counted as failures. This module is not prevention and does not
//! pretend to be. It is the difference between a crash the product survives and a
//! crash that leaves the machine unguarded. The thirty-second third attempt is a
//! decision: a service that has failed three times is failing for a reason a
//! faster retry will not fix, and a service that restarts every five seconds
//! forever is a machine that never settles and a support case that says "it keeps
//! restarting". `service::integrity` reads the start type, the recovery policy,
//! the account and the running state *back off the machine*, because a hardening
//! pass that reported its own intentions would report them again on a machine
//! where they no longer hold.
//!
//! ## [`files`]: rewriting the database, the rules or the configuration
//!
//! Writing to the product's own files is the attack this module answers. On a
//! clean machine `%ProgramData%\WenleAV` inherits `Users:(CI)(WD,AD,WEA,WA)`:
//! write data, append data and write extended attributes, inherited by every
//! child. The rule database, the cache and the log are therefore writable by
//! every user on the machine until something takes that away. That measurement is
//! what makes the module necessary, and it is quoted rather than re-derived.
//!
//! `files::protect_product_dirs` rewrites the DACL of the install directory, and
//! of the database, rules, cache, log and configuration directories: full control
//! for `SYSTEM` and `Administrators`, read and execute for `Users`, and nothing
//! for anyone else. `files::audit` reads the DACL back and answers, per trustee,
//! what it can actually do. It must be able to say the sentence that matters,
//! that **a non-elevated user can write this file**. The audit is the half that
//! earns its keep, because a `protect` that reported success over a machine that
//! is still open is exactly the failure this crate exists to avoid. The tests
//! therefore protect a directory with a known-open DACL, confirm the audit sees
//! the write access that is really there, protect it, and confirm the audit sees
//! it gone.
//!
//! The brief asked for one grant that this crate withholds. The configuration
//! directory is *not* left writable by `Users`. The service reads its
//! configuration as `LocalSystem`, so a user write grant would buy nothing and
//! would hand an attacker the one file that decides what the product scans. The
//! argument, and the IPC-through-the-service alternative that replaces it, is in
//! the module documentation.
//!
//! ## [`tamper`]: noticing after the fact
//!
//! This module covers everything the three above cannot prevent, because
//! prevention has a boundary. An administrator may replace a binary, a restore
//! may put back an older tree, and a same-size edit leaves the size and the
//! timestamps looking right.
//!
//! `tamper::Manifest` records the SHA-256 and the size of the service binary, the
//! CLI, the GUI and the rule database. `verify` reports what is `Missing`,
//! `Added`, `Resized` or `Modified`, and for a changed program says whether it is
//! now unsigned or differently signed. It also carries the weak
//! `debugger_present`, whose three checks are all defeatable by anything already
//! running in this process. The module documentation says so in as many words,
//! because a check described as a tripwire is useful and one described as a
//! defence is a lie that gets relied on.
//!
//! A manifest is **a tripwire, not a signature**. An attacker who can write a
//! binary and the manifest passes it completely. What it catches is the cheap
//! version of every attack, which is most of them.
//!
//! # What is enforced, and by whom
//!
//! "The product protects itself" hides three very different strengths of claim:
//!
//! * **Enforced by the kernel, against anyone without the right.** The DACLs on
//!   the directories and on the running process, and the SCM's refusal to let an
//!   ordinary logon stop a service. The operating system checks these on every
//!   access, and they are the real protection this crate has.
//! * **Enforced by this crate, at the moment it is called.** Nothing reapplies a
//!   DACL by itself. A directory recreated by an installer inherits its parent's
//!   permissions, not ours, and `files::protect_product_dirs` has to be run
//!   again. `tamper::self_check` and `wenle protect status` are how that is
//!   noticed.
//! * **Not enforced at all, only reported.** The manifest check. It changes
//!   nothing and prevents nothing; it turns a silent change into a loud one.
//!
//! # What this crate cannot do
//!
//! Each of these is a real limit and none of them is fixable here. They are
//! listed because a self-protection module that did not name them would be read
//! as promising more than it delivers, and the promise would be believed.
//!
//! * **It cannot stop an administrator.** Administrators have full control of
//!   the install and data directories by design, since they are the ones who
//!   install, upgrade and uninstall the product, and `WRITE_DAC` on an object you
//!   own needs no privilege at all. An administrator can replace the binary, stop
//!   the service, rewrite every DACL this crate wrote, and take ownership of
//!   anything it protected. This is not a gap in the implementation; it is what
//!   administrator means.
//! * **It cannot stop a kernel-mode attacker.** A signed driver, a
//!   bring-your-own-vulnerable-driver load, or anything else running in ring 0
//!   can rewrite the process's memory, its token and its security descriptor
//!   without the kernel ever consulting a DACL. Protection against that is a
//!   driver of this product's own, and it is not this crate.
//! * **It cannot stop someone who boots another operating system.** Every DACL
//!   here is a field in a file on a filesystem that another OS can mount and
//!   write, and a bootable USB stick does not read them. The only answers to that
//!   are full-disk encryption and a measured boot, and both belong to the
//!   platform.
//! * **DACLs on a *process* are undone by a reboot, and DACLs on a *file* are
//!   not.** The distinction cuts both ways. A process's security descriptor lives
//!   in the process object, which the kernel destroys when the process exits, so
//!   [`process::protect`] protects *this run* and nothing after it: the service
//!   has to call it again on every start, and nothing in this crate can make it.
//!   A directory's or a service's descriptor is stored on the object itself, so
//!   it survives a reboot and an upgrade. That is why an uninstaller that does
//!   not undo it leaves a directory nobody but SYSTEM can clean up. Both halves
//!   are written down in the modules that own them.
//! * **It cannot stop an attacker who can write the manifest as well as the
//!   binary.** See the section above. The manifest is a file with the same
//!   permissions as everything else in the data directory, and there is no key in
//!   this process that an attacker on the same machine could not also read.
//! * **It cannot stop resource exhaustion.** Filling the disk, exhausting memory,
//!   or spinning the CPU degrades or stops the product, and no DACL prevents it.
//!   Quotas and job objects are the platform's answer.
//! * **It cannot stop an administrator from being talked into elevating.**
//!   Nothing in this crate can tell a legitimate installation from a user who was
//!   persuaded to click through a UAC prompt.
//! * **It does not make detection work.** Everything here protects the product
//!   from being turned off. A protected scanner that does not detect anything is
//!   a protected scanner that does not detect anything.
//!
//! # Where this crate sits in the workspace
//!
//! Above `av-core`, for the directory layout (`AvPaths`) that says which paths
//! the product owns; above `av-authenticode`, for the one question the tamper
//! check cannot answer itself, which is whether a replaced binary is still
//! signed; and below `av-service`, which installs and controls the service.
//!
//! **`av-guard` does not depend on `av-service`, and the direction is the
//! reverse.** A hardening crate that could not run unless the service crate's own
//! view of the world were available could not harden a service that failed to
//! start, which is the case where a hardening crate is most needed. The cost is
//! that a few small things are written twice: an `SC_HANDLE` guard, an error-code
//! mask, the name of the service, and a `denied(what)` sentence. The alternative
//! was a dependency cycle or a shared crate that owned neither half's
//! documentation. Those duplicates are noted here rather than moved, because
//! `av-service`'s copies are documented where they are used; if a third crate
//! ever needs them, that is when a shared home is worth building.
//!
//! The service's own name is not a constant in this crate. Every
//! function in [`service`] takes it as a parameter, because a second copy of a
//! name in a second crate is a thing that goes stale silently, and because a
//! check that can only run against one name cannot be pointed at an installation
//! that chose another.
//!
//! # This crate is Windows-only by construction
//!
//! There is no `cfg(windows)` gating in the hardening code and no non-Windows
//! fallback: the `windows` crate is a Windows target dependency, and a
//! "protection" that silently did nothing on another platform would be worse
//! than one that did not compile. The two places where a non-Windows build is
//! mechanically required, the SCM calls and the debugger checks, carry a
//! `cfg(not(windows))` arm whose only job is to return a sentence that says why
//! there is no answer.
//!
//! # Measured rather than assumed
//!
//! Every module documents what was checked against this machine rather than
//! reasoned about, and the tests run those checks again. The ones a reader of
//! this crate should know before trusting any of it:
//!
//! * `%ProgramData%\WenleAV` inherits `Users:(CI)(WD,AD,WEA,WA)`. ([`files`])
//! * The SCM's default service descriptor denies an ordinary logon
//!   `SERVICE_START` and `SERVICE_STOP` and grants the query rights.
//!   ([`service`])
//! * `QueryServiceConfig` alone cannot tell you a service is delayed-auto-start;
//!   a second query is required, and it does answer on this machine. ([`service`])
//! * `GetEffectiveRightsFromAclW` reports all-access for an object's *owner* on a
//!   DACL that does not name it (`0x001f0fff` for a process, `0x001f01ff` for a
//!   directory) while returning zero for every other trustee on the same DACL.
//!   ([`process`], [`files`])
//! * `FA` in SDDL is `FILE_ALL_ACCESS` (`0x1F01FF`) and **not**
//!   `PROCESS_ALL_ACCESS` (`0x1F0FFF`); the two-letter tokens are not translated
//!   between object types, so a `FA` written for a file would leave three process
//!   rights granted. ([`process`], [`files`])
//! * `SetNamedSecurityInfoW` rewrites the inherited entries on children that
//!   already exist, and `SetFileSecurityW` does not. That reconciles an apparent
//!   disagreement between this crate and `av-quarantine`, which walks its tree
//!   because it uses the second one. A child whose own DACL is
//!   *protected* is unchanged either way, which is what makes "protecting the
//!   data root cannot weaken an already-restricted vault" a fact rather than a
//!   hope. ([`files`])
//! * A locally built executable verifies as `Unsigned` and not as
//!   `Undetermined`. ([`tamper`])
//!
//! # Documentation and language
//!
//! Every user-visible string here is English, and every refusal is a sentence
//! naming what to do next rather than a bare Win32 code. For an access denial,
//! that sentence is chosen by *measuring* whether this process is already
//! elevated, because advice to elevate that is shown to an administrator is
//! advice that stops being read.

#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The security descriptor half shared by [`process`] and [`files`].
///
/// Private: it is machinery, not an answer. A caller that wants to know what a
/// process or a directory allows asks [`process`] or [`files`], which describe
/// the result in terms of rights and trustees rather than in terms of ACEs and
/// masks.
mod acl;

pub mod files;
pub mod process;
pub mod service;
pub mod tamper;
