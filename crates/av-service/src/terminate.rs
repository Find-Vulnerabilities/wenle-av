//! Stopping a running process, and refusing to stop the wrong one.
//!
//! # The problem this module exists for
//!
//! `TerminateProcess` takes a handle, and the only handle the rest of this
//! product has is a process identifier. An identifier is not an identity: the
//! kernel reuses them, so between the moment a scan records "process 1234 holds
//! this code" and the moment something stops it, process 1234 can exit and a
//! different program can take the number. A product that terminated on the
//! identifier alone would then kill an unrelated program — and that is the one
//! mistake in this whole feature that cannot be taken back.
//!
//! So a process is named by [`ProcessToken`]: its identifier *and* the time it
//! was created, in 100-nanosecond ticks since 1601, which is what a `FILETIME`
//! counts. Two processes with the same identifier do not have the same creation
//! time, and unlike the executable path it cannot be spoofed by running a copy
//! of the same binary.
//!
//! # Why the creation time is read twice, and why that is not a race
//!
//! [`stop`] opens the process, reads the creation time **from the handle it
//! opened**, compares it with the token, and terminates **through that same
//! handle**. Once the open has succeeded the handle names a process object, and
//! a process object cannot be re-pointed at a different process: the comparison
//! is the only step that can be wrong, and it is answered from the object the
//! termination will act on. There is therefore no window between the check and
//! the act.
//!
//! The alternative that was considered and rejected is carrying an open handle
//! from the scan to the termination. That is *more* correct — it pins the object
//! so the identifier cannot even be reused — and it costs a handle per scanned
//! process held across a walk that can take seconds, on a machine where the
//! whole design of `av-memory` is built around not holding anything it does not
//! need to. The comparison above closes the same window for one extra call.
//!
//! # What this does not do
//!
//! It does not ask whether the process *should* be stopped. Every policy
//! question — whether the bytes came from a file, whether that file is
//! malicious in its own right, whether the user has allowed it — is answered
//! before [`stop`] is called, by `av_service::memory` and its callers. This
//! module is the mechanism and nothing else, which is why it has no access to a
//! configuration and no opinion about a verdict.

use std::fmt;

/// The exit code the terminated process is left with.
///
/// One, which is what `taskkill /F` uses and what a crash reporter treats as a
/// failure rather than as a clean exit. A distinctive code of this product's own
/// was considered and rejected: nothing reads it back, and a number that is not
/// documented anywhere is a number no user can interpret.
pub const EXIT_CODE: u32 = 1;

/// A process named well enough to be stopped without stopping a different one.
///
/// See this module's documentation for why the creation time is part of the
/// name. [`ProcessToken::created`] is `None` when Windows would not say, which
/// happens for a process this account may query limited information about but
/// not read the times of — and a token like that can never be used to stop
/// anything, because it cannot be told apart from a later process wearing the
/// same identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessToken {
    pid: u32,
    created: Option<u64>,
}

impl ProcessToken {
    /// Identify the process with this identifier, as it is now.
    ///
    /// Reads the creation time, which costs one open and one call. Taken
    /// **before** a process is scanned rather than after, so that the token
    /// names the process whose memory was read: a process that exits mid-scan
    /// and has its identifier reused must not yield a token for the newcomer.
    pub fn of(pid: u32) -> Self {
        Self {
            pid,
            created: creation_time_of(pid),
        }
    }

    /// The identifier, for a message or a log line.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// When the process was created, in 100-nanosecond ticks since 1601-01-01,
    /// when Windows would say.
    pub const fn created(&self) -> Option<u64> {
        self.created
    }

    /// A sentence naming the process, for a log line.
    pub fn describe(&self) -> String {
        match self.created {
            Some(created) => format!("process {} (created {created})", self.pid),
            None => format!("process {} (creation time unreadable)", self.pid),
        }
    }

    /// A token for an identifier with a creation time chosen by the caller.
    ///
    /// Exists so that the two guards in [`stop`] can be tested on a machine that
    /// is not going to have a process exit on cue: a test hands a live process's
    /// token a creation time that belongs to a different one, which is exactly
    /// what a reused identifier looks like, and checks that nothing is killed.
    #[cfg(test)]
    fn with_creation(mut self, created: Option<u64>) -> Self {
        self.created = created;
        self
    }
}

impl fmt::Display for ProcessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// What a creation time says about whether a process is the one a token names.
///
/// Split out from [`stop`] and pure so that the decision can be tested against
/// every combination directly, including the one a machine cannot be asked to
/// produce: a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    /// The token names this process.
    Same,
    /// The identifier now belongs to a different process.
    Replaced { expected: u64, found: u64 },
    /// One of the two times could not be read, so there is nothing to compare.
    Unknown,
}

fn identity(expected: Option<u64>, found: Option<u64>) -> Identity {
    match (expected, found) {
        (Some(expected), Some(found)) if expected == found => Identity::Same,
        (Some(expected), Some(found)) => Identity::Replaced { expected, found },
        _ => Identity::Unknown,
    }
}

/// What came of asking a process to stop.
///
/// [`Stopped::Terminated`] is the only variant that claims the product did
/// something, which is the property `av_ipc::Detection::terminated` is set from.
/// The rest are the several ways a request not to run a program any more can
/// fail, kept apart because they mean different things to a reader: a process
/// that had already exited is not a failure at all, an identifier that now
/// belongs to somebody else is a guard that worked, and a refusal is the
/// operating system saying no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing was attempted, and this is why.
    ///
    /// Never returned by [`stop`], which is always called because somebody
    /// decided to call it. It exists because the question a caller holding one
    /// of these is asking is "what happened about stopping this process", and
    /// "nothing, because the configuration says not to" is an answer to it —
    /// one that a report has to be able to print, and one that an `Option`
    /// around the other variants would push onto every reader as a second
    /// absence to handle.
    NotAttempted {
        /// Why, in a sentence a user can read.
        why: String,
    },
    /// The process is gone, and this call is why.
    Terminated,
    /// The process had already exited.
    AlreadyGone,
    /// The identifier now belongs to a different process, which was left alone.
    Replaced {
        /// The creation time the token was built with.
        expected: u64,
        /// The creation time the live process reported.
        found: u64,
    },
    /// The process could not be identified well enough to stop safely.
    Unidentified {
        /// Why, in a sentence a user can read.
        why: String,
    },
    /// The operating system refused.
    Refused {
        /// The Win32 error code.
        code: u32,
        /// What Windows said about it.
        message: String,
    },
    /// This build cannot stop a process at all.
    Unavailable {
        /// Why, in a sentence a user can read.
        why: String,
    },
}

impl Stopped {
    /// True when the process is gone because of this call.
    ///
    /// The predicate every caller that reports a termination must use, rather
    /// than matching on the variant itself: this is the claim
    /// `av_ipc::Detection::terminated` carries, and it is true of exactly one
    /// outcome.
    pub const fn happened(&self) -> bool {
        matches!(self, Stopped::Terminated)
    }

    /// What happened, in a sentence a log line or a report can carry.
    pub fn describe(&self) -> String {
        match self {
            Stopped::NotAttempted { why } => format!("the process was not stopped: {why}"),
            Stopped::Terminated => "the process was terminated".to_string(),
            Stopped::AlreadyGone => "the process had already exited".to_string(),
            Stopped::Replaced { expected, found } => format!(
                "the identifier now belongs to a different process, created {found} rather than \
                 {expected}, so it was left alone"
            ),
            Stopped::Unidentified { why } => {
                format!("the process could not be identified, so it was left alone: {why}")
            }
            Stopped::Refused { code, message } => {
                format!("the process could not be terminated: {message} (0x{code:08X})")
            }
            Stopped::Unavailable { why } => format!("no process can be terminated here: {why}"),
        }
    }
}

impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// `ERROR_INVALID_PARAMETER`, which is what opening a process that does not
/// exist reports.
///
/// The one Win32 code that means "there is no such process" rather than "you may
/// not have it", and the difference is the whole of [`Stopped::AlreadyGone`].
const ERROR_INVALID_PARAMETER: u32 = 87;
/// `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: u32 = 5;

/// Stop the process a token names, if it is still that process.
///
/// Refuses in every case where the identity cannot be established, including a
/// token with no creation time of its own. That is deliberate: the cost of
/// refusing is a malicious process that keeps running for as long as it takes
/// somebody to notice, and the cost of being wrong is an unrelated program
/// killed under a user who has no way to know why.
#[cfg(windows)]
pub fn stop(token: &ProcessToken) -> Stopped {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    let Some(expected) = token.created else {
        return Stopped::Unidentified {
            why: format!(
                "process {} was identified without its creation time, so it cannot be told apart \
                 from a later process that takes the same identifier",
                token.pid
            ),
        };
    };

    // SAFETY: the arguments are values and the returned handle is closed on
    // every path below.
    let handle = match unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            token.pid,
        )
    } {
        Ok(handle) => handle,
        Err(error) => {
            let code = crate::win32::code(&error);
            return if code == ERROR_INVALID_PARAMETER {
                // No process has this identifier. Nothing to do, and nothing
                // went wrong: the process this was about is gone.
                Stopped::AlreadyGone
            } else {
                Stopped::Refused {
                    code,
                    message: error.message(),
                }
            };
        }
    };

    let outcome = match identity(Some(expected), creation_time(handle)) {
        Identity::Replaced { expected, found } => Stopped::Replaced { expected, found },
        Identity::Unknown => Stopped::Unidentified {
            why: format!(
                "process {} could be opened but its creation time could not be read",
                token.pid
            ),
        },
        Identity::Same => {
            // SAFETY: the handle names a process object, which is what this
            // call takes, and it is still open here.
            match unsafe { TerminateProcess(handle, EXIT_CODE) } {
                Ok(()) => Stopped::Terminated,
                Err(error) => {
                    let code = crate::win32::code(&error);
                    // `TerminateProcess` on a process that has already exited
                    // reports `ERROR_ACCESS_DENIED`, so a plain denial is not
                    // enough to tell a genuine refusal from a process that left
                    // between the open and the call. Asking whether it is still
                    // running is, and the answer is what the caller is told.
                    if code == ERROR_ACCESS_DENIED && !is_running(handle) {
                        Stopped::AlreadyGone
                    } else {
                        Stopped::Refused {
                            code,
                            message: error.message(),
                        }
                    }
                }
            }
        }
    };

    // SAFETY: the handle came from `OpenProcess` and is used once, here, to
    // close it. Every path above has finished with it.
    unsafe {
        let _ = CloseHandle(handle);
    }
    outcome
}

/// Stop the process a token names, on a platform this build has no way to.
#[cfg(not(windows))]
pub fn stop(_token: &ProcessToken) -> Stopped {
    Stopped::Unavailable {
        why: "this build has no Windows process API to terminate with".to_string(),
    }
}

/// When a process was created, read through an already-open handle.
#[cfg(windows)]
fn creation_time(handle: windows::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;

    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the handle is open and the four pointers are to live locals that
    // outlive the call.
    unsafe {
        GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user).ok()?
    };
    // The two halves a `FILETIME` is stored in, in the order the structure
    // defines them rather than the order a little-endian read would suggest.
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Whether a process is still running, asked of an already-open handle.
///
/// `GetExitCodeProcess` leaves `STILL_ACTIVE` there while the process runs, and
/// that is the value a terminated process's exit code is compared against rather
/// than assumed. A process terminated with `STILL_ACTIVE` as its exit code would
/// read as running, which is the documented behaviour of every caller of this
/// function and not something this module can improve on.
#[cfg(windows)]
fn is_running(handle: windows::Win32::Foundation::HANDLE) -> bool {
    use windows::Win32::Foundation::STILL_ACTIVE;
    use windows::Win32::System::Threading::GetExitCodeProcess;

    let mut code: u32 = 0;
    // SAFETY: the handle is open and the pointer is to a live local.
    if unsafe { GetExitCodeProcess(handle, &mut code) }.is_err() {
        // The question could not be answered, and the answer that cannot cause
        // a wrong termination is "it is still running": that path reports a
        // refusal rather than an absence.
        return true;
    }
    code == STILL_ACTIVE.0 as u32
}

/// When the process with this identifier was created, if Windows will say.
#[cfg(windows)]
fn creation_time_of(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: the arguments are values; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let created = creation_time(handle);
    // SAFETY: the handle came from `OpenProcess` and is closed once, here.
    unsafe {
        let _ = CloseHandle(handle);
    }
    created
}

#[cfg(not(windows))]
fn creation_time_of(_pid: u32) -> Option<u64> {
    None
}

/// A child process for the tests that terminate one.
///
/// Shared between [`terminate`]'s own tests and [`crate::process_watch`]'s,
/// rather than copied into both, because the one copy that is subtly wrong is the
/// one that leaves a process behind on somebody's machine.
#[cfg(test)]
pub(crate) mod doomed {
    use std::process::{Child, Command, Stdio};

    /// A child that exits by itself within about ten seconds.
    ///
    /// The reason these tests are safe to run. A test that terminates a process
    /// must never be able to leave one behind that nothing can kill: not when it
    /// panics, not when the machine is slow, not when the code under test is
    /// broken. The idiom is `av_guard::process`'s, and `ping` is used rather
    /// than `timeout` because `timeout` refuses to run without a console when
    /// its output is redirected.
    fn spawn() -> Child {
        Command::new("cmd")
            .args(["/c", "ping -n 11 127.0.0.1 >NUL"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("starting a short-lived child process")
    }

    /// Kills the child on every path out of a test, including a panic.
    ///
    /// Best-effort, because the child's own ten-second timeout may have fired
    /// and because a test may have legitimately terminated it already. If both
    /// failed the child still exits by itself, which is what makes this a
    /// backstop rather than the only thing standing between a test and an
    /// orphan.
    pub(crate) struct ChildGuard(Child);

    impl ChildGuard {
        /// Start a child that will end on its own.
        pub(crate) fn new() -> Self {
            Self(spawn())
        }

        /// Its identifier.
        pub(crate) fn pid(&self) -> u32 {
            self.0.id()
        }

        /// Whether the child is still running, read as of now.
        ///
        /// Read immediately by the tests that assert *nothing* happened: a
        /// process that is running now does not stop by itself, so the answer
        /// needs no waiting for.
        pub(crate) fn is_running(&mut self) -> bool {
            matches!(self.0.try_wait(), Ok(None))
        }

        /// Wait, briefly, for the child to be reaped.
        ///
        /// The opposite direction does need waiting for. `TerminateProcess`
        /// starts a teardown and returns; the process object is not necessarily
        /// signalled by the time it does, so a test that read immediately after
        /// a successful termination would see a process that is on its way out
        /// and call it alive. Measured, not assumed: this assertion failed on
        /// the first run against an unreaped child.
        pub(crate) fn wait_for_exit(&mut self) -> bool {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match self.0.try_wait() {
                    Ok(Some(_)) => return true,
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                    Err(_) => return false,
                }
            }
            false
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminate::doomed::ChildGuard;

    #[test]
    fn a_token_for_a_dead_identifier_is_refused_rather_than_acted_on() {
        // The guard, at its cheapest: an identifier nothing can have. There is
        // no process to terminate, so the answer is that it is gone — not a
        // failure and not a termination.
        let token = ProcessToken::of(u32::MAX);
        assert!(token.created().is_none());
        let outcome = stop(&token);
        assert!(
            matches!(outcome, Stopped::AlreadyGone | Stopped::Unidentified { .. }),
            "{outcome:?}"
        );
        assert!(!outcome.happened());
    }

    #[test]
    fn a_token_whose_creation_time_matches_terminates_the_process() {
        let mut child = ChildGuard::new();
        let token = ProcessToken::of(child.pid());
        // The child was started by this test and is owned by this account, so
        // both the identifier and the creation time must have been readable.
        assert!(
            token.created().is_some(),
            "a process this test started must be readable: {}",
            token.describe()
        );
        assert!(child.is_running(), "the child is running before the call");

        let outcome = stop(&token);
        assert_eq!(outcome, Stopped::Terminated, "{}", outcome.describe());
        assert!(outcome.happened());
        assert!(child.wait_for_exit(), "the child is gone after the call");
    }

    #[test]
    fn a_token_whose_creation_time_differs_leaves_the_process_alone() {
        // The whole point of the module, as a differential. The identifier is
        // live and this account may terminate it — the only thing that changed
        // is the creation time, which is exactly what a reused identifier looks
        // like from the outside. Nothing may be killed.
        let mut child = ChildGuard::new();
        let token = ProcessToken::of(child.pid());
        let real = token.created().expect("a readable creation time");
        let wrong = token.clone().with_creation(Some(real.wrapping_add(1)));

        let outcome = stop(&wrong);
        assert_eq!(
            outcome,
            Stopped::Replaced {
                expected: real.wrapping_add(1),
                found: real,
            },
            "{}",
            outcome.describe()
        );
        assert!(!outcome.happened());
        assert!(
            child.is_running(),
            "a process whose identifier was reused must not be terminated"
        );
        assert!(
            outcome.describe().contains("left alone"),
            "the sentence has to say what was *not* done: {}",
            outcome.describe()
        );
    }

    #[test]
    fn a_token_with_no_creation_time_can_never_stop_anything() {
        // The refusal that costs a detection. A process whose creation time
        // could not be read cannot be told apart from a later one wearing its
        // identifier, so the honest answer is to do nothing and say so.
        let mut child = ChildGuard::new();
        let token = ProcessToken::of(child.pid()).with_creation(None);
        let outcome = stop(&token);
        assert!(
            matches!(outcome, Stopped::Unidentified { .. }),
            "{outcome:?}"
        );
        assert!(!outcome.happened());
        assert!(child.is_running(), "nothing was terminated");
        assert!(
            outcome.describe().contains("could not be identified"),
            "{}",
            outcome.describe()
        );
    }

    #[test]
    fn a_process_already_terminated_reads_as_gone_and_not_as_a_failure() {
        // Terminating twice is not an error. `TerminateProcess` on a process
        // that has exited reports `ERROR_ACCESS_DENIED`, and reporting that as
        // a refusal would tell a user the product failed at the moment it
        // succeeded.
        let mut child = ChildGuard::new();
        let token = ProcessToken::of(child.pid());
        if stop(&token) != Stopped::Terminated {
            // A machine where the first call did not work cannot tell us
            // anything about the second, so the test says so rather than
            // asserting something it did not establish.
            panic!("the first call did not terminate: {}", stop(&token).describe());
        }
        let second = stop(&token);
        assert!(
            matches!(second, Stopped::AlreadyGone | Stopped::Unidentified { .. }),
            "{second:?}"
        );
        assert!(
            !second.happened(),
            "the second call cannot claim a termination the first one made"
        );
        assert!(child.wait_for_exit());
    }

    #[test]
    fn the_identity_decision_is_exhaustive_over_what_can_be_known() {
        // The pure half, over every combination — including the two a machine
        // cannot be asked to produce on cue.
        assert_eq!(identity(Some(7), Some(7)), Identity::Same);
        assert_eq!(
            identity(Some(7), Some(8)),
            Identity::Replaced {
                expected: 7,
                found: 8
            }
        );
        // Unreadable on either side is not a match and not a mismatch: there is
        // nothing to compare, and both cases must land somewhere that does not
        // terminate.
        assert_eq!(identity(None, Some(7)), Identity::Unknown);
        assert_eq!(identity(Some(7), None), Identity::Unknown);
        assert_eq!(identity(None, None), Identity::Unknown);
    }

    #[test]
    fn only_a_termination_claims_a_termination() {
        // `Stopped::happened` is what `av_ipc::Detection::terminated` is set
        // from, so a variant that reported true would put a claim of a stopped
        // program into a notification about one that is still running.
        let outcomes = [
            Stopped::NotAttempted {
                why: "the configuration does not terminate processes".to_string(),
            },
            Stopped::Terminated,
            Stopped::AlreadyGone,
            Stopped::Replaced {
                expected: 1,
                found: 2,
            },
            Stopped::Unidentified {
                why: "no time".to_string(),
            },
            Stopped::Refused {
                code: ERROR_ACCESS_DENIED,
                message: "Access is denied.".to_string(),
            },
            Stopped::Unavailable {
                why: "no".to_string(),
            },
        ];
        for outcome in &outcomes {
            assert_eq!(
                outcome.happened(),
                *outcome == Stopped::Terminated,
                "{outcome:?}"
            );
            // And every one of them has something to say, because a report line
            // with an empty reason is the least useful thing a report can carry.
            assert!(!outcome.describe().is_empty(), "{outcome:?}");
        }
    }

    #[test]
    fn a_refusal_keeps_the_code_windows_gave_and_says_it_in_hex() {
        let refused = Stopped::Refused {
            code: ERROR_ACCESS_DENIED,
            message: "Access is denied.".to_string(),
        };
        let sentence = refused.describe();
        assert!(sentence.contains("0x00000005"), "{sentence}");
        assert!(sentence.contains("Access is denied."), "{sentence}");
    }
}
