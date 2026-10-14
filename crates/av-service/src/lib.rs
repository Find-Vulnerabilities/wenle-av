//! The Wenle AV background service.
//!
//! # What this crate is
//!
//! One process that owns the machine's antivirus state and answers for it. It
//! is the only writer of the quarantine vault, the only holder of the control
//! pipe, and the only thing that reads the rule database and reports what it
//! contains. Everything a user or a front end wants to know goes through it,
//! and everything it knows it can say.
//!
//! # The three pieces this is built out of
//!
//! * **The protocol is `av-ipc`.** Not a copy of it, not a parallel version of
//!   it: the message types, the framing, the correlation rules and the session
//!   state machine all live there and are tested there without a Windows API in
//!   sight. This crate does not re-derive any of it. Where this crate *maps*
//!   something into that vocabulary (the driver's event codes, the engine's scan
//!   reports), the mapping is exhaustive so that a new variant upstream stops
//!   this build rather than being quietly dropped.
//! * **The work is `av-scan`, `av-quarantine` and `av-realtime`.** All three
//!   are used exactly as they ship. Nothing in this crate reaches into their
//!   internals, because a service that patched around a library's behaviour
//!   would be a service whose behaviour is not the library's and cannot be
//!   reasoned about from the library's documentation.
//! * **The Windows-ness is five small modules.** [`pipe`] is the transport,
//!   [`scm`] is the service host, [`install`] is the other end of it (installing
//!   the service, removing it, and starting and stopping it), [`single`] is the
//!   one-instance guard, and [`driver`] is the presence check. Each is a thin
//!   layer over calls whose behaviour is the operating system's, and each keeps
//!   the decisions it can out of the calls it cannot test.
//!
//! # One of everything
//!
//! This process is built so that there is exactly one writer of each piece of
//! state, and that is a correctness property rather than a tidiness preference:
//!
//! * **One vault.** `av_quarantine::QuarantineVault` keeps its index in memory
//!   and rewrites the whole file on every change, so two live vaults over one
//!   directory each silently discard the other's entries. The service owns the
//!   vault, and `av_realtime`'s own copy is switched off. See [`host`]'s
//!   documentation for how and why that is disclosed rather than hidden.
//! * **One pipe.** Two listeners on one name is two answers to one question,
//!   whichever the client happens to reach.
//! * **One scan at a time.** A second concurrent scan is refused with a reason
//!   rather than queued: a user who asks for two full scans of `C:\` wants the
//!   second one refused, not to have both run at half speed and report
//!   half-finished results.
//!
//! # What it does to itself, and what it watches on its own account
//!
//! Four things, and the account of each is about what was applied rather than
//! what was intended:
//!
//! * **It hardens itself on every start.** [`selfprotect`] applies the parts of
//!   `av-guard` that a service may apply to itself (this process's own access
//!   list and the product's directories) and reads the third back: an SCM
//!   recovery policy so that a crash is a restart rather than a machine left
//!   unguarded. The read is not a shortcut: a service running as `LocalSystem`
//!   has `SERVICE_QUERY_CONFIG` on its own service and not
//!   `SERVICE_CHANGE_CONFIG`, measured 2026-10-10, so the policy is written by
//!   the elevated half, `wenle protect apply` and `wenle service install`, and
//!   the service's report says whether the machine has one and what puts it
//!   there if it does not. Until 2026-10-09 none of this was reached from the
//!   service at all, only from `wenle protect …`, a command a person types, so a
//!   machine was unhardened again after the next reboot. The one layout nothing
//!   is applied to is a cargo build tree, through the same check the command
//!   uses, because protecting a build tree with an installation's permissions
//!   makes every later build fail.
//! * **The control pipe has a real access list, read back off the object.**
//!   [`pipe`] creates every instance with [`pipe::CONTROL_PIPE_SDDL`] and then
//!   reads the DACL back, so what is reported is a fact about the pipe rather
//!   than about the string that was passed to create it. That list grants read
//!   and write to every interactive account, because the product's front ends
//!   have to reach it. That is why the separation between one signed-in user and
//!   another cannot be made by the list at all and is made per connection
//!   instead, in [`peer`].
//! * **It re-checks itself while it runs.** [`tamper`] does the cheap half on a
//!   timer (this process's access list and the product's directories, put back
//!   and then read back) and the expensive half, which hashes and
//!   signature-checks every file the integrity manifest names, once at start-up
//!   and then rarely, because it is tens of megabytes of reading. A finding is
//!   reported and nothing is repaired by it, and the manifest is never
//!   re-recorded: capturing a tampered file would make it the new baseline, so
//!   an automatic re-capture would turn a detection into a permanent blind spot.
//! * **The kernel holds the other half.** The driver strips the rights that let
//!   another process terminate or write into this one, and refuses writes to the
//!   files this product runs from, without asking this service anything. The
//!   configuration message that arms it is described with the rest of the
//!   driver's behaviour below. Neither half can stop an administrator, and
//!   [`selfprotect`] and `av-guard` say so in the same words rather than one
//!   claiming more than the other.
//!
//! # What this crate does not do, said plainly
//!
//! * **It does not install itself, and it cannot elevate.** [`install`] can put
//!   the service in the SCM, remove it, and start and stop it, but every one of
//!   those calls fails with `ERROR_ACCESS_DENIED` unless the process was already
//!   running elevated, and Windows requires the *user* to agree to that, which
//!   is not a thing a program can do for itself. So installation is a command a
//!   user runs from an elevated prompt, not something this product does to a
//!   machine behind their back. The SCM host in [`scm`] is written and, on this
//!   machine, is not run; the module says so.
//! * **It answers the kernel driver's decision port.** [`filter_port`] connects
//!   to the port the driver creates, decides each request the driver is holding
//!   a program open to ask, and turns what the driver reports into the same
//!   event stream a client reads. [`driver`] separately answers whether the
//!   driver is loaded at all, which is a *different* question: a driver that is
//!   loaded with nobody connected to its port blocks nothing, and an
//!   [`av_ipc::Event::Driver`] carrying a connection state change is how those
//!   two states are told apart. It also **asks the driver for things**: on every
//!   connection it sends one configuration message carrying what the user's
//!   `protection.*` and `driver.kernel_self_protection` settings ask for (the
//!   strip-these-rights callbacks and the write gate over this product's own
//!   files) and reports the driver's answer in [`host`]'s status. What is still
//!   unimplemented is the rest of the driver's behaviour: `driver.fail_closed`,
//!   `driver.scan_timeout_ms`, `driver.verbose_logging`, and the `protection.*`
//!   keys that would need subsystems neither side has (a registry callback, the
//!   boot sector) are settings nothing reads. [`config`] reports each of them as
//!   stored and not honoured, or as taking effect at the next start, rather than
//!   pretending otherwise.
//! * **It does not drive the sandbox.** [`config`] says so in the same list.
//! * **It scans memory when a client asks, and when a process starts.** A client
//!   that sends `Request::ScanProcess` gets a real answer: the process is opened,
//!   its regions are read through `av-memory`, and what the findings point at is
//!   dealt with by [`memory`] and [`host`]. Separately, when the driver reports a
//!   process creation, [`process_watch`] walks that process on a thread of its
//!   own and hands what it finds back to [`host`]. It is still bound by what the
//!   driver can tell it: with no driver connected there are no process events and
//!   so no watching, and it does not sweep memory as a step of a *file* scan.
//!   The `scanning.memory` setting is about file scans and is listed as not
//!   honoured for that reason. What the watching is *not* is pre-execution: the
//!   process has already started by the time it is walked, and a process found
//!   holding malicious code is terminated after the fact rather than prevented
//!   from running. The kernel's image-load callback is what would stop it sooner,
//!   and this build does not install one.
//!
//! The lists in [`config`] are the account of the second and third; they
//! are built from a table rather than derived, so that a setting cannot quietly
//! move from "not honoured" to "honoured" by a refactor.

#![warn(missing_docs)]
// Unwrapping is how a test asserts. The workspace lint stays on for the library,
// where a panic in a service is a dead machine, and is relaxed here rather than
// by scattering `allow` over every test body.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod allow;
pub mod config;
pub mod control;
pub mod driver;
pub mod engine;
pub mod error;
pub mod filter_port;
pub mod host;
pub mod install;
pub mod memory;
pub mod peer;
pub mod pipe;
pub mod process_watch;
pub mod scan;
pub mod scm;
pub mod selfprotect;
pub mod single;
pub mod tamper;
pub mod terminate;
pub mod win32;

pub use error::ServiceError;
pub use install::{ScmState, StartOutcome, StopOutcome};
