//! The whole lifecycle, through the Service Control Manager, for the one
//! machine where that is possible.
//!
//! # Why every test here is `#[ignore]`d
//!
//! Installing a service needs administrator rights, and it changes the machine:
//! a name appears in the SCM's database, a process runs as `LocalSystem`, and
//! the service reads `%ProgramData%\WenleAV`. None of that is acceptable as a
//! side effect of `cargo test`, which is why `scm.rs` and `install.rs` both say
//! in their own documentation that the SCM host is written and not run.
//!
//! What is left is this file: the test that a person with an elevated prompt
//! and a machine they are willing to change can run on purpose, with
//!
//! ```text
//! cargo test -p av-service --test service_control_manager -- --ignored --test-threads=1
//! ```
//!
//! # It is one test, and it runs the whole lifecycle in order
//!
//! One test and not five, because the steps are not independent: there is one
//! service name and only one of them can hold it. Running five in parallel
//! would have four of them racing for a name the fifth is installing, and
//! `--test-threads=1` in the command above is a request rather than a guarantee
//! — one test cannot be run concurrently with itself.
//!
//! # What it leaves behind if it fails
//!
//! It cleans up in the order it set things up, and it does the cleanup on the
//! path where an assertion failed as well as the path where everything worked,
//! because the guard is a `Drop`. What it cannot do is clean up after a panic
//! that aborts the process or after the machine is switched off mid-test, so a
//! person who runs this and sees it fail should finish the job by hand:
//!
//! ```text
//! sc query WenleAvService
//! sc stop WenleAvService
//! sc delete WenleAvService
//! ```
//!
//! ```text
//! wenle service status
//! ```
//!
//! is the same three commands through this workspace's own front end, and is
//! the shorter thing to type.

#![cfg(windows)]
// See `control_pipe.rs` for why an integration test needs this line of its own:
// it is a separate crate root, and the library's `cfg(test)` allowance does not
// reach it.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::time::{Duration, Instant};

use av_ipc::{Client, Incoming, Reply, Request, StatusReport, PIPE_NAME};
use av_service::install::{self, ScmState, StartOutcome, StopOutcome};
use av_service::pipe::PipeConnection;

/// How long to wait for the service to start answering on the pipe.
///
/// `StartServiceW` waits for the service to report itself running, so by the
/// time it returns the listener exists. What is not instantaneous is the pipe
/// instance: `CreateNamedPipeW` happens on the service's main thread a moment
/// after it reports `RUNNING`, and a client that connects in that window gets
/// `ERROR_PIPE_BUSY`, which is a "try again". Thirty seconds is far longer than
/// that window and short enough that a service which genuinely failed to start
/// is reported rather than waited for.
const STARTUP_PATIENCE: Duration = Duration::from_secs(30);

/// How long to wait for the service to stop after the SCM is told to stop it.
const SHUTDOWN_PATIENCE: Duration = Duration::from_secs(30);

/// How long between polls while waiting.
const POLL: Duration = Duration::from_millis(100);

/// Removes the service when it goes out of scope, whatever happened.
///
/// A guard rather than a call at the end of the test, because the interesting
/// endings are the ones where an assertion failed halfway: a test that left
/// `WenleAvService` installed and running as `LocalSystem` on somebody's
/// machine would be a far worse bug than the one it was reporting.
struct Cleanup {
    /// Set once the service is installed, so `Drop` knows there is something to
    /// do.
    installed: bool,
}

impl Cleanup {
    fn new() -> Self {
        Self { installed: false }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best effort, and in the order that works: stop first, because
        // `DeleteService` marks a running service for deletion and leaves it in
        // the database until it has stopped. Every result here is deliberately
        // discarded — this is a `Drop` during a panic, and a failure to clean up
        // is reported by the file's documentation rather than by a second panic
        // that would abort the process.
        let _ = install::stop();
        let deadline = Instant::now() + SHUTDOWN_PATIENCE;
        while Instant::now() < deadline {
            match install::state() {
                Ok(ScmState::Stopped) => break,
                Ok(ScmState::NotInstalled) => return,
                _ => std::thread::sleep(POLL),
            }
        }
        let _ = install::remove();
    }
}

/// Ask the running service for its status, or say why it could not be asked.
fn status_over_the_pipe() -> Option<StatusReport> {
    let connection = PipeConnection::connect_to(PIPE_NAME).ok()?;
    let mut client = Client::new(connection);
    let id = client.send(Request::Status).ok()?;
    let deadline = Instant::now() + STARTUP_PATIENCE;
    loop {
        for incoming in client.recv().ok()? {
            if let Incoming::Reply { id: got, reply } = incoming {
                if got == id {
                    return match reply {
                        Reply::Status(report) => Some(report),
                        _ => None,
                    };
                }
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

/// Wait until the SCM reports `wanted`, or give up.
fn wait_for_state(wanted: ScmState, patience: Duration) -> Option<ScmState> {
    let deadline = Instant::now() + patience;
    loop {
        let state = install::state().ok()?;
        if state == wanted {
            return Some(state);
        }
        if Instant::now() >= deadline {
            return Some(state);
        }
        std::thread::sleep(POLL);
    }
}

#[test]
#[ignore = "requires administrator to install a service"]
fn the_whole_lifecycle_works_against_the_real_service_control_manager() {
    // The binary this same `cargo test` built, which is the point: the thing
    // installed is the thing under test and not whatever happens to be
    // installed on the machine.
    let image = std::path::PathBuf::from(env!("CARGO_BIN_EXE_wenle-av-service"));
    assert!(image.is_file(), "{} is not there", image.display());

    // Nothing here can run unelevated, and the failure is worth naming:
    // `ERROR_ACCESS_DENIED` comes back as a sentence that says what to do about
    // it, and a machine with the service already installed from a previous run
    // would otherwise fail at the first step with a confusing "exists".
    let mut cleanup = Cleanup::new();
    match install::state().expect("the SCM can be asked") {
        ScmState::NotInstalled => {}
        other => panic!(
            "WenleAvService is already {}. Run `sc delete WenleAvService`, wait for it to go, \
             and run this test again.",
            other.as_str()
        ),
    }

    // 1. Install.
    install::install(&image).expect("installing needs administrator rights");
    cleanup.installed = true;
    assert_eq!(
        install::state().expect("the SCM can be asked"),
        ScmState::Stopped,
        "an installed service that has never been started is stopped"
    );

    // 2. Start it, and wait for the pipe.
    assert_eq!(install::start().expect("starting"), StartOutcome::Started);
    let running =
        wait_for_state(ScmState::Running, STARTUP_PATIENCE).expect("the SCM can be asked");
    assert_eq!(running, ScmState::Running, "the service did not start");

    // 3. Talk to it over the real pipe, on the real name, as an ordinary user
    //    would.
    let deadline = Instant::now() + STARTUP_PATIENCE;
    let report = loop {
        if let Some(report) = status_over_the_pipe() {
            break report;
        }
        assert!(
            Instant::now() < deadline,
            "the service is running and answered nothing on {PIPE_NAME}"
        );
        std::thread::sleep(POLL);
    };
    // The two facts that make this an end-to-end test rather than a smoke test:
    // the report came from the service process, and the service process is the
    // one the SCM started.
    assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
    assert!(
        report.state == av_ipc::ServiceState::Running,
        "{:?}",
        report.state
    );

    // 4. Starting it again is not an error: the state the caller asked for is
    //    the state the machine is in.
    assert_eq!(
        install::start().expect("starting twice"),
        StartOutcome::AlreadyRunning
    );

    // 5. Stop it, and wait for the SCM to agree.
    assert_eq!(
        install::stop().expect("stopping"),
        StopOutcome::StopRequested
    );
    let stopped =
        wait_for_state(ScmState::Stopped, SHUTDOWN_PATIENCE).expect("the SCM can be asked");
    assert_eq!(stopped, ScmState::Stopped, "the service did not stop");

    // 6. Stopping it again is not an error either.
    assert_eq!(
        install::stop().expect("stopping twice"),
        StopOutcome::NotRunning
    );

    // 7. Remove it, and check the name is really gone rather than trusting that
    //    `DeleteService` returning `Ok` means the database no longer has it.
    install::remove().expect("removing");
    let gone =
        wait_for_state(ScmState::NotInstalled, SHUTDOWN_PATIENCE).expect("the SCM can be asked");
    assert_eq!(gone, ScmState::NotInstalled, "the name is still registered");
    cleanup.installed = false;

    // 8. And removing it a second time is refused with a sentence rather than
    //    with a bare code.
    let error = install::remove().expect_err("nothing left to remove");
    assert!(error.to_string().contains("not installed"), "{error}");
}
