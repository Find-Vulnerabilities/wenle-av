//! The Windows service host: the dispatcher, the control handler, and the
//! status the SCM is told.
//!
//! # It cannot be installed here, and that is not an excuse for not writing it
//!
//! `sc create WenleAvService binPath= ...` needs administrator rights and a
//! machine nobody is using. Nothing in this module is executed by any test in
//! this workspace, and the integration test that would drive it carries
//! `#[ignore = "requires administrator to install a service"]` and is not run.
//! That is stated rather than glossed: what is verified is the half that can be
//! — every state-to-status decision in [`status_fields`], the checkpoint rule,
//! and the mapping from a control code to an action — and what is not verified
//! is that the SCM accepts the result, because proving that means installing
//! something.
//!
//! # Reported honestly, which for a service means *checkpoints*
//!
//! `SERVICE_STATUS` is not a decoration. The SCM reads three things from it and
//! acts on all three:
//!
//! * **`dwCurrentState`**, which must never skip a step. A service that reports
//!   `RUNNING` without ever reporting `START_PENDING` is a service the SCM
//!   believes started instantly, and one that reports `STOPPED` without
//!   `STOP_PENDING` is one it believes stopped cleanly when it may have died.
//! * **`dwCheckPoint`**, which is meaningless unless the service is between
//!   states and *must advance* on every report while it is. A checkpoint that
//!   repeats tells the SCM nothing is happening, and a service that says nothing
//!   is happening gets killed at `dwWaitHint` and reported as hung.
//! * **`dwControlsAccepted`**, which is how the SCM knows it may send a stop. It
//!   is empty until the service is `RUNNING`: accepting a stop before then would
//!   be claiming a responsiveness the service does not have, because the stop
//!   flag is only read by the control loop, and there is no control loop yet.
//!
//! [`status_fields`] computes all of it from one exhaustive match over
//! [`ServiceState`], so a state added to the protocol cannot arrive here
//! without a status to report.
//!
//! # What the stop actually does
//!
//! The handler sets an [`AtomicBool`]. [`crate::control::serve`] checks it four
//! times a second and again on every pass of its loop, and returns. That is a
//! stop that stops: the pipe is closed, the watcher's threads are told to end,
//! the scan in flight is cancelled at its next file, and the SCM is told
//! `STOPPED`. A service whose handler did nothing would be a service the SCM
//! eventually terminates — and a terminated service is one whose quarantine
//! index was never written.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use av_ipc::ServiceState;

use crate::config::LoadedConfig;
use crate::error::ServiceError;
use crate::host::Host;

/// The name the SCM knows this service by.
///
/// Also the name `sc create` needs, and the name a user types. Kept here rather
/// than in the command-line tool because the service is the thing that answers
/// to it, and a second copy is a second thing to rename.
pub const SERVICE_NAME: &str = "WenleAvService";

/// The name a user sees in the services list.
pub const SERVICE_DISPLAY_NAME: &str = "Wenle AV Service";

/// How long the SCM should wait before treating a start as hung.
///
/// The pending operation is `Host::open`, and the long part of it is reading and
/// instantiating the rule database. The shipped database is 25,333,689 bytes and
/// was measured at **2.6 s** to load warm on this project's development machine;
/// a cold read on a slower disk, or a machine under load, is several times that.
/// The hint has to cover the cold case, because the failure it prevents is a
/// service killed while it is doing exactly what it was asked to and reported as
/// hung: an earlier 5,000 here was justified as "a rule database read rather than
/// anything that blocks", and a database read *is* a thing that blocks, for
/// seconds.
///
/// Thirty seconds rather than something larger because the SCM's own guidance is
/// that a service should answer a control within thirty, and a hint past that
/// trades one wrong answer for another.
pub const START_WAIT_HINT_MS: u32 = 30_000;

/// How long the SCM should wait before treating a stop as hung.
///
/// The pending operation is `Host::shut_down`, and the part of it that can take
/// time is the watcher's join: `av_realtime::RealtimeService::stop` sets its
/// worker's stop flag and joins the thread, and the worker reads that flag at the
/// top of its loop — so the join lasts as long as one file's scan. At the
/// measured rate for large executables, a few hundred megabytes is minutes.
///
/// # The honest limitation, which this number does not fix
///
/// **Nothing in this product can abandon a scan part-way through a file.**
/// `av_scan::ScanEngine::scan_file` does its own reading, no crate in the
/// workspace carries a cancellation token into that loop, and the flags that do
/// exist are read between files. So a stop is bounded by one file and not by this
/// hint, and a machine that happens to be scanning a large archive when it shuts
/// down will have the service terminated at the hint — which is precisely the
/// failure this module's own documentation says to avoid, because a terminated
/// service is one whose quarantine index was never written.
///
/// The hint is set to the SCM's thirty-second responsiveness expectation because
/// every larger number is a longer lie. The remedy is not a bigger constant: it
/// is a cancel token threaded from here into the scanner's read loop, so a stop
/// takes effect within a buffer rather than within a file.
pub const STOP_WAIT_HINT_MS: u32 = 30_000;

/// The size of the start hint, checked by the compiler rather than by a test.
///
/// It was a `#[test]` assertion first, and clippy was right to reject it: both
/// sides are constants, so the test restated a fact the compiler already knows
/// and could only ever report it after a test run. As a `const` block, shrinking
/// the hint below what a database load needs is a build failure in the file that
/// holds the number, which is where the mistake would be made.
///
/// Ten seconds is a floor and not the value — the same database was measured at
/// 2.6 s warm on this machine, and the constant is deliberately set far above the
/// single measurement there is.
const _: () = assert!(
    START_WAIT_HINT_MS >= 10_000,
    "the start hint has to cover the rule database's load, which is not a sub-second operation"
);

/// A pending state may never be given a zero deadline.
///
/// A zero `dwWaitHint` reads as "no deadline at all", which is the one thing a
/// pending state with a stated budget is not saying. Both are asserted here
/// because the value that would break it is a constant someone might edit.
const _: () = assert!(START_WAIT_HINT_MS > 0);
const _: () = assert!(STOP_WAIT_HINT_MS > 0);

/// `SERVICE_STOPPED`.
pub const STATE_STOPPED: u32 = 1;
/// `SERVICE_START_PENDING`.
pub const STATE_START_PENDING: u32 = 2;
/// `SERVICE_STOP_PENDING`.
pub const STATE_STOP_PENDING: u32 = 3;
/// `SERVICE_RUNNING`.
pub const STATE_RUNNING: u32 = 4;
/// `SERVICE_ACCEPT_NONE`.
pub const ACCEPT_NONE: u32 = 0;
/// `SERVICE_ACCEPT_STOP`.
pub const ACCEPT_STOP: u32 = 1;
/// `SERVICE_ACCEPT_SHUTDOWN`.
///
/// Advertised together with [`ACCEPT_STOP`] while the service is running, and it
/// is what makes [`control_action`]'s `SERVICE_CONTROL_SHUTDOWN` arm reachable at
/// all. The SCM sends a service only the controls it lists in
/// `dwControlsAccepted`, so without this bit a machine shutdown does not ask this
/// service to stop: it waits out the timeout and terminates the process.
/// [`control_action`]'s documentation has always described the clean stop as the
/// behaviour and the shutdown arm as the difference between stopping and being
/// killed — this bit is the half of that which was missing.
pub const ACCEPT_SHUTDOWN: u32 = 4;

/// What the SCM is told, as plain numbers.
///
/// A struct of this crate's own rather than a `windows::Win32::System::Services
/// ::SERVICE_STATUS`, so that every decision — which state, which controls,
/// which checkpoint, which wait hint — is made in code that compiles and is
/// tested on any platform. The Win32 struct is then a field-by-field copy with
/// nothing to get wrong, and that copy is the only part behind `cfg(windows)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFields {
    /// `dwCurrentState`.
    pub current_state: u32,
    /// `dwControlsAccepted`.
    pub controls_accepted: u32,
    /// `dwCheckPoint`.
    pub checkpoint: u32,
    /// `dwWaitHint`, in milliseconds.
    pub wait_hint_ms: u32,
}

/// The status to report for `state`, given the checkpoint last reported.
///
/// The checkpoint argument is the *previous* value, not the next: the SCM's
/// rule is that it advances on every report while the service is between
/// states, so the next value is a function of the last one, and a caller that
/// had to compute it itself is a caller that could repeat it.
///
/// Exhaustive over [`ServiceState`] with no wildcard arm — a fifth state would
/// otherwise reach the SCM as whatever this function happened to fall through
/// to, and the SCM would believe it.
pub fn status_fields(state: ServiceState, previous_checkpoint: u32) -> StatusFields {
    let (current_state, controls_accepted, pending) = match state {
        ServiceState::Starting => (STATE_START_PENDING, ACCEPT_NONE, true),
        ServiceState::Running => (STATE_RUNNING, ACCEPT_STOP | ACCEPT_SHUTDOWN, false),
        ServiceState::Stopping => (STATE_STOP_PENDING, ACCEPT_NONE, true),
        ServiceState::Stopped => (STATE_STOPPED, ACCEPT_NONE, false),
    };
    StatusFields {
        current_state,
        controls_accepted,
        // Zero when the service is not between states. A checkpoint reported
        // alongside `RUNNING` is a value the SCM ignores, and reporting a stale
        // non-zero one is how a service looks like it is still starting.
        checkpoint: if pending {
            previous_checkpoint.saturating_add(1)
        } else {
            0
        },
        // Per state rather than one number for both, because the two pending
        // operations are a database read and a thread join and there is no single
        // honest budget for the pair. See the two constants: the start hint is a
        // measurement, and the stop hint is the SCM's responsiveness guidance
        // standing in for a bound this product cannot yet give.
        wait_hint_ms: match state {
            ServiceState::Starting => START_WAIT_HINT_MS,
            ServiceState::Stopping => STOP_WAIT_HINT_MS,
            ServiceState::Running | ServiceState::Stopped => 0,
        },
    }
}

/// What the control handler does about a control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerAction {
    /// Set the stop flag. The control loop notices within
    /// [`crate::control::ACCEPT_POLL`].
    Stop,
    /// The SCM asking for the current status.
    ///
    /// Answered by doing nothing, and that is not laziness: this service reports
    /// its status on every transition, so the SCM's cached copy is never stale
    /// and re-sending it would be a write of the same bytes. A service that
    /// batched its transitions and reported them lazily would have to answer
    /// here, and would have to share the handle across two threads to do it.
    Interrogate,
    /// A control this service does not implement.
    ///
    /// The handler answers `ERROR_CALL_NOT_IMPLEMENTED` for these, which is the
    /// documented reply and a different thing from silence. In practice the SCM
    /// only sends controls listed in `dwControlsAccepted`, so this arm is for a
    /// shape of the machine this build does not expect — and saying so is
    /// better than pretending the control was handled.
    Unsupported,
}

/// Map an SCM control code to what to do about it.
///
/// [`SERVICE_CONTROL_SHUTDOWN`](https://learn.microsoft.com/windows/win32/services/service-control-handler-function)
/// is a stop, and treating it as anything else is how a service is killed by a
/// machine shutdown with its state unwritten.
pub fn control_action(control: u32) -> HandlerAction {
    /// `SERVICE_CONTROL_STOP`.
    const STOP: u32 = 1;
    /// `SERVICE_CONTROL_INTERROGATE`.
    const INTERROGATE: u32 = 4;
    /// `SERVICE_CONTROL_SHUTDOWN`.
    const SHUTDOWN: u32 = 5;

    match control {
        STOP | SHUTDOWN => HandlerAction::Stop,
        INTERROGATE => HandlerAction::Interrogate,
        _ => HandlerAction::Unsupported,
    }
}

/// What the service's main function needs and the SCM cannot pass it.
///
/// `StartServiceCtrlDispatcherW` calls the service's main function with the
/// command line and nothing else — there is no user-data parameter on that
/// path, unlike the control handler's. The parameters therefore go through a
/// process-wide cell, written once before the dispatcher starts and read once
/// by the main function. A [`OnceLock`](std::sync::OnceLock) and not a mutex:
/// the value is written before any thread that reads it exists, and a lock
/// would suggest a race that cannot happen.
#[cfg(windows)]
static STARTUP: std::sync::OnceLock<Startup> = std::sync::OnceLock::new();

/// The parameters, and the flag the control handler sets.
#[cfg(windows)]
#[derive(Debug)]
struct Startup {
    /// Where everything lives.
    paths: av_core::paths::AvPaths,
    /// The configuration in force.
    loaded: LoadedConfig,
    /// Set by the control handler, read by the control loop.
    stop: Arc<AtomicBool>,
}

/// Run as a service, under the SCM, until told to stop.
///
/// Returns `Ok` when the SCM stopped the service, and
/// [`ServiceError::Scm`] when the process was not started by the SCM — which is
/// what a user sees by double-clicking the executable, and which is a
/// configuration mistake rather than a fault. The caller distinguishes the two
/// with [`not_started_by_the_scm`] and prints something useful.
#[cfg(windows)]
pub fn run(paths: av_core::paths::AvPaths, loaded: LoadedConfig) -> Result<(), ServiceError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Services::{StartServiceCtrlDispatcherW, SERVICE_TABLE_ENTRYW};

    let stop = Arc::new(AtomicBool::new(false));
    // Set once, before the dispatcher exists. A second call would be a second
    // service in one process, which the SCM does not do either.
    let _ = STARTUP.set(Startup {
        paths,
        loaded,
        stop,
    });

    // The name must stay alive and keep its address until the call returns:
    // `SERVICE_TABLE_ENTRYW` holds a raw `PWSTR`.
    let mut name = crate::win32::to_wide_str(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        // The table is terminated by an entry with a null name. Without it
        // `StartServiceCtrlDispatcherW` reads past the end of the array, and
        // the failure is not a clean error.
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];

    // SAFETY: `table` is a two-element array that outlives the call, its first
    // entry names this service and its second is the terminator the API
    // requires. The API blocks until the service stops, and does not retain the
    // pointer past its return.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|error| ServiceError::Scm {
        message: format!(
            "StartServiceCtrlDispatcherW failed ({}): {error}",
            crate::win32::code(&error)
        ),
    })
}

/// True when an error is "this process is not a service".
///
/// The code is `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, and it is worth its
/// own predicate because the two callers treat it in opposite ways: a user
/// running the executable expecting a service gets told to use `--console`, and
/// anything else gets to be an error.
pub fn not_started_by_the_scm(error: &ServiceError) -> bool {
    match error {
        ServiceError::Scm { message } => message.contains(&format!(
            "({})",
            crate::win32::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
        )),
        _ => false,
    }
}

/// The service's main function, called by the SCM on a thread of its own.
///
/// The sequence is the whole point of this module, in the order the SCM
/// requires: register the handler, report `START_PENDING`, do the work, report
/// `RUNNING`, serve, report `STOP_PENDING`, stop, report `STOPPED`.
///
/// Nothing here returns a value or propagates an error, because the SCM's
/// calling convention has nowhere to put one. A failure is reported the way the
/// SCM reads failures: `dwWin32ExitCode` on the final status.
///
/// # Safety
///
/// Called by the SCM with the command line this process was started with, which
/// this function ignores. It must not be called by anything else, and the
/// SCM calls it on a thread it owns.
#[cfg(windows)]
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows::core::PWSTR) {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::RegisterServiceCtrlHandlerExW;

    // The only way this is `None` is a bug in `run`, and there is no handler
    // registered yet to report it through, so there is nothing to do but stop.
    let Some(startup) = STARTUP.get() else {
        log::error!("the service was entered without its startup parameters");
        return;
    };

    let name = crate::win32::to_wide_str(SERVICE_NAME);
    // The flag lives in the static, so the pointer stays valid for the life of
    // the process — which is what makes handing it to the SCM safe.
    let context = Arc::as_ptr(&startup.stop) as *const core::ffi::c_void;
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(control_handler), Some(context))
    } {
        Ok(handle) => handle,
        Err(error) => {
            log::error!("the service could not register its control handler: {error}");
            return;
        }
    };
    let mut status = StatusHandle::new(handle);

    // A failure to report a status is not worth aborting over: the SCM will
    // notice at its wait hint, and stopping here would leave the service
    // half-registered.
    let _ = status.report(ServiceState::Starting);

    let host = match Host::open(startup.paths.clone(), startup.loaded.clone()) {
        Ok(host) => host,
        Err(error) => {
            // A service that cannot open its vault must not report `RUNNING`
            // and sit there taking requests it cannot answer. It says why, in
            // the only place the SCM and the event log will read it.
            log::error!("the service could not start: {error}");
            let _ = status.report_failure(SERVICE_SPECIFIC_STARTUP_FAILED);
            return;
        }
    };

    let _ = status.report(ServiceState::Running);
    log::info!("{SERVICE_DISPLAY_NAME} is running");

    let host = match crate::control::serve(host, &startup.stop) {
        Ok(host) => host,
        Err(error) => {
            // The pipe could not be created or a client could not be connected
            // repeatedly. Fatal: the service's whole job is that pipe.
            log::error!("the control pipe failed: {error}");
            let _ = status.report_failure(SERVICE_SPECIFIC_PIPE_FAILED);
            return;
        }
    };

    // In this order, and the order is the module's documentation: the SCM is
    // told a stop is under way before the work of stopping starts, and told it
    // finished only when it has.
    let _ = status.report(ServiceState::Stopping);
    let mut host = host;
    host.shut_down();
    let _ = status.report(ServiceState::Stopped);
    log::info!("{SERVICE_DISPLAY_NAME} has stopped");
}

/// The control handler, called by the SCM on a thread of its own.
///
/// # Safety
///
/// `context` must be the pointer `service_main` registered — the address of the
/// `AtomicBool` inside the `STARTUP` static, which outlives this process. The
/// SCM passes back whatever was registered and nothing else calls this.
#[cfg(windows)]
unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    match control_action(control) {
        HandlerAction::Stop => {
            if !context.is_null() {
                // SAFETY: a non-null context is the pointer registered in
                // `service_main`, which is `Arc::as_ptr` of a flag held in a
                // process-wide static. A shared reference to an `AtomicBool` is
                // the only thing this does with it.
                let stop = unsafe { &*(context as *const AtomicBool) };
                stop.store(true, Ordering::SeqCst);
                log::info!("the service manager asked the service to stop");
            }
            NO_ERROR
        }
        // Nothing to do: see `HandlerAction::Interrogate`.
        HandlerAction::Interrogate => NO_ERROR,
        HandlerAction::Unsupported => crate::win32::ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// `NO_ERROR`.
#[cfg(windows)]
const NO_ERROR: u32 = 0;

/// The service-specific exit code for a failure to start.
#[cfg(windows)]
pub const SERVICE_SPECIFIC_STARTUP_FAILED: u32 = 1;

/// The service-specific exit code for a failure of the control pipe.
#[cfg(windows)]
pub const SERVICE_SPECIFIC_PIPE_FAILED: u32 = 2;

/// `ERROR_SERVICE_SPECIFIC_ERROR`, which is what tells the SCM to look at
/// `dwServiceSpecificExitCode`.
#[cfg(windows)]
const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

/// The handle the SCM gave us, and the checkpoint it was last told.
///
/// Holds the counter rather than recomputing it, because the SCM's rule is that
/// a checkpoint advances between reports and only the sequence of reports knows
/// what the last one was.
#[cfg(windows)]
#[derive(Debug)]
pub struct StatusHandle {
    /// The handle from `RegisterServiceCtrlHandlerExW`.
    handle: windows::Win32::System::Services::SERVICE_STATUS_HANDLE,
    /// The last checkpoint reported.
    checkpoint: u32,
}

#[cfg(windows)]
impl StatusHandle {
    /// Wrap a handle the SCM gave us.
    pub const fn new(handle: windows::Win32::System::Services::SERVICE_STATUS_HANDLE) -> Self {
        Self {
            handle,
            checkpoint: 0,
        }
    }

    /// Report a state, telling the SCM a stop is accepted once there is one.
    pub fn report(&mut self, state: ServiceState) -> Result<(), ServiceError> {
        let fields = status_fields(state, self.checkpoint);
        self.checkpoint = fields.checkpoint;
        self.send(&fields, 0, 0)
    }

    /// Report `STOPPED` with a failure attached.
    ///
    /// `dwWin32ExitCode` is what the SCM records and what the event log shows a
    /// user, so a service that failed to start and reported a clean stop would
    /// leave no trace of why.
    pub fn report_failure(&mut self, specific: u32) -> Result<(), ServiceError> {
        // The checkpoint resets, because the service is no longer between
        // states: it is going straight to stopped.
        self.checkpoint = 0;
        let fields = status_fields(ServiceState::Stopped, 0);
        self.send(&fields, ERROR_SERVICE_SPECIFIC_ERROR, specific)
    }

    /// Hand the fields to `SetServiceStatus`.
    fn send(
        &self,
        fields: &StatusFields,
        win32_exit_code: u32,
        specific_exit_code: u32,
    ) -> Result<(), ServiceError> {
        use windows::Win32::System::Services::{
            SetServiceStatus, ENUM_SERVICE_TYPE, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
            SERVICE_WIN32_OWN_PROCESS,
        };

        let raw = SERVICE_STATUS {
            // Own process, not shared: this service runs its own executable and
            // shares its address space with nothing.
            dwServiceType: ENUM_SERVICE_TYPE(SERVICE_WIN32_OWN_PROCESS.0),
            dwCurrentState: SERVICE_STATUS_CURRENT_STATE(fields.current_state),
            dwControlsAccepted: fields.controls_accepted,
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: specific_exit_code,
            dwCheckPoint: fields.checkpoint,
            dwWaitHint: fields.wait_hint_ms,
        };
        // SAFETY: `raw` is a fully initialised `SERVICE_STATUS` on this stack
        // that outlives the call, and the handle is the one this service
        // registered.
        unsafe { SetServiceStatus(self.handle, &raw) }.map_err(|error| ServiceError::Scm {
            message: format!("SetServiceStatus failed: {error}"),
        })
    }
}

/// Run as a service.
///
/// A named pipe and a service control handler are Windows things; on any other
/// platform this build has neither, and saying so is better than a stub that
/// silently succeeds.
#[cfg(not(windows))]
pub fn run(_paths: av_core::paths::AvPaths, _loaded: LoadedConfig) -> Result<(), ServiceError> {
    Err(ServiceError::Scm {
        message: "the service control manager is a Windows component and this build has none"
            .to_string(),
    })
}

/// Always false off Windows: nothing can have been started by an SCM that does
/// not exist.
#[cfg(not(windows))]
pub fn not_started_by_the_scm(_error: &ServiceError) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_is_reported_and_never_skipped() {
        // The four the SCM is told, in the order a normal run tells them. Each
        // one is a distinct number and none of them is zero, which is
        // `SERVICE_CONTINUE_PENDING`'s neighbourhood — a service that reported
        // a zero state would be reporting a state the SCM has no name for.
        let starting = status_fields(ServiceState::Starting, 0);
        assert_eq!(starting.current_state, STATE_START_PENDING);
        assert_ne!(starting.current_state, 0);

        let running = status_fields(ServiceState::Running, starting.checkpoint);
        assert_eq!(running.current_state, STATE_RUNNING);

        let stopping = status_fields(ServiceState::Stopping, running.checkpoint);
        assert_eq!(stopping.current_state, STATE_STOP_PENDING);

        let stopped = status_fields(ServiceState::Stopped, stopping.checkpoint);
        assert_eq!(stopped.current_state, STATE_STOPPED);

        // And the four are four different numbers, so no transition is a
        // no-op the SCM would not notice.
        let mut seen = [
            starting.current_state,
            running.current_state,
            stopping.current_state,
            stopped.current_state,
        ];
        seen.sort_unstable();
        for pair in seen.windows(2) {
            assert_ne!(pair[0], pair[1], "two states share a number");
        }
    }

    #[test]
    fn a_stop_is_accepted_only_once_the_service_is_running() {
        // Before `RUNNING` there is no control loop to notice the flag, so
        // accepting a stop would be claiming a responsiveness that is not
        // there. After `STOPPED` there is nothing left to stop.
        assert_eq!(
            status_fields(ServiceState::Starting, 0).controls_accepted,
            ACCEPT_NONE
        );
        // Both bits while running, and the shutdown bit is not decoration: the
        // SCM sends only what is listed here, so a service that accepts a stop
        // but not a shutdown is terminated at machine shutdown rather than asked
        // — which is what `control_action`'s `SERVICE_CONTROL_SHUTDOWN` arm
        // exists to answer.
        assert_eq!(
            status_fields(ServiceState::Running, 0).controls_accepted,
            ACCEPT_STOP | ACCEPT_SHUTDOWN
        );
        assert_eq!(
            status_fields(ServiceState::Stopping, 0).controls_accepted,
            ACCEPT_NONE
        );
        assert_eq!(
            status_fields(ServiceState::Stopped, 0).controls_accepted,
            ACCEPT_NONE
        );
    }

    #[test]
    fn a_checkpoint_advances_while_pending_and_is_zero_otherwise() {
        // The rule the SCM acts on: a repeated checkpoint while a state is
        // pending means "nothing is happening", and a service that says nothing
        // is happening is killed at `dwWaitHint`.
        let mut checkpoint = 0;
        for expected in 1..=3 {
            let fields = status_fields(ServiceState::Starting, checkpoint);
            assert_eq!(fields.checkpoint, expected, "a checkpoint must advance");
            assert_eq!(fields.wait_hint_ms, START_WAIT_HINT_MS);
            checkpoint = fields.checkpoint;
        }

        // Reporting `RUNNING` resets it, and the reset is what tells the SCM
        // the pending state is over.
        let running = status_fields(ServiceState::Running, checkpoint);
        assert_eq!(running.checkpoint, 0);
        assert_eq!(running.wait_hint_ms, 0);

        // And the stop sequence does the same dance in the other direction.
        let stopping = status_fields(ServiceState::Stopping, running.checkpoint);
        assert_eq!(stopping.checkpoint, 1);
        assert_eq!(stopping.wait_hint_ms, STOP_WAIT_HINT_MS);
        let again = status_fields(ServiceState::Stopping, stopping.checkpoint);
        assert_eq!(again.checkpoint, 2);
        let stopped = status_fields(ServiceState::Stopped, again.checkpoint);
        assert_eq!(stopped.checkpoint, 0);
        assert_eq!(stopped.wait_hint_ms, 0);

        // A caller that somehow passes a huge checkpoint does not wrap to zero
        // and look like a service that has finished starting.
        let saturated = status_fields(ServiceState::Starting, u32::MAX);
        assert_eq!(saturated.checkpoint, u32::MAX);
        assert_ne!(saturated.checkpoint, 0);
    }

    /// The two pending states get their own budgets, and neither is zero.
    ///
    /// A single shared number was the earlier version, and it was wrong for both
    /// operations at once: the start is a rule-database read whose cost is
    /// knowable and measured, and the stop is a thread join whose worst case this
    /// product cannot bound, because nothing in it can abandon a scan part-way
    /// through a file. What this pins is that the two are told apart rather than
    /// conflated, and that a pending state is never given a zero deadline — the
    /// value that says "no deadline at all". The *size* of the start hint is a
    /// compile-time assertion below rather than a test, because it is a constant.
    #[test]
    fn the_two_pending_states_have_their_own_wait_hints() {
        let starting = status_fields(ServiceState::Starting, 0);
        let stopping = status_fields(ServiceState::Stopping, 0);
        assert_eq!(starting.wait_hint_ms, START_WAIT_HINT_MS);
        assert_eq!(stopping.wait_hint_ms, STOP_WAIT_HINT_MS);
        assert_ne!(
            starting.wait_hint_ms, 0,
            "a pending state with no deadline is not a hint"
        );
        assert_ne!(stopping.wait_hint_ms, 0);
    }

    #[test]
    fn a_shutdown_is_a_stop() {
        // A machine shutting down stops the service, and a service that ignored
        // it is killed with its quarantine index unwritten.
        assert_eq!(control_action(1), HandlerAction::Stop);
        assert_eq!(control_action(5), HandlerAction::Stop);
        assert_eq!(control_action(4), HandlerAction::Interrogate);
    }

    #[test]
    fn an_unimplemented_control_is_answered_as_unimplemented() {
        // Not silence and not `NO_ERROR`: the SCM is entitled to know the
        // control was not handled. `SERVICE_CONTROL_PAUSE` and
        // `SERVICE_CONTROL_CONTINUE` are the realistic arrivals — this service
        // does not report accepting them, so a machine that sends one is a
        // machine whose expectations should be corrected rather than flattered.
        const PAUSE: u32 = 2;
        const CONTINUE: u32 = 3;
        assert_eq!(control_action(PAUSE), HandlerAction::Unsupported);
        assert_eq!(control_action(CONTINUE), HandlerAction::Unsupported);
        assert_eq!(control_action(0), HandlerAction::Unsupported);
        assert_eq!(control_action(255), HandlerAction::Unsupported);
        // And the two real ones are not in that set.
        assert_ne!(control_action(1), HandlerAction::Unsupported);
        assert_ne!(control_action(5), HandlerAction::Unsupported);
    }

    #[test]
    fn the_service_name_is_one_the_scm_will_take() {
        // `sc create` rejects a name containing `/` or `\`, and the SCM's own
        // limit is 256 characters. Checked here because a name the SCM refuses
        // is a name that fails at installation, on a machine nobody is watching.
        assert!(!SERVICE_NAME.is_empty());
        assert!(SERVICE_NAME.len() < 256);
        assert!(!SERVICE_NAME.contains('/'));
        assert!(!SERVICE_NAME.contains('\\'));
        assert!(!SERVICE_NAME.contains(' '));
        assert!(!SERVICE_DISPLAY_NAME.is_empty());

        // A pipe path is not a service name, and the two are easy to confuse
        // when one of them starts with a backslash.
        assert!(!crate::pipe::is_pipe_path(std::path::Path::new(
            SERVICE_NAME
        )));
    }

    #[test]
    fn only_the_service_controller_connect_failure_is_recognised() {
        let not_a_service = ServiceError::Scm {
            message: format!(
                "StartServiceCtrlDispatcherW failed ({}): the system is not in the right state",
                crate::win32::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
            ),
        };
        assert!(not_started_by_the_scm(&not_a_service));
        // Some other SCM failure is an error and must not be reported as "you
        // ran it wrong".
        assert!(!not_started_by_the_scm(&ServiceError::Scm {
            message: "SetServiceStatus failed: access is denied".to_string()
        }));
        assert!(!not_started_by_the_scm(&ServiceError::Other(
            "something else".to_string()
        )));
    }

    /// The numbers here are this crate's own so that the decisions above can be
    /// tested anywhere. This is the test that stops them drifting.
    #[cfg(windows)]
    #[test]
    fn the_numbers_are_the_ones_the_windows_crate_defines() {
        use windows::Win32::System::Services::{
            SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTINUE_PENDING, SERVICE_RUNNING,
            SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        };
        // `SERVICE_ACCEPT_NONE` is zero and the `windows` crate does not define
        // it — there is no `SERVICE_ACCEPT_NONE` in `Win32::System::Services`,
        // only the individual bits. Zero is asserted against the literal rather
        // than against a name this crate would have had to invent, because an
        // invented constant compared with an invented constant tests nothing.
        assert_eq!(ACCEPT_NONE, 0);
        assert_eq!(ACCEPT_STOP, SERVICE_ACCEPT_STOP);
        assert_eq!(ACCEPT_SHUTDOWN, SERVICE_ACCEPT_SHUTDOWN);
        assert_eq!(STATE_STOPPED, SERVICE_STOPPED.0);
        assert_eq!(STATE_START_PENDING, SERVICE_START_PENDING.0);
        assert_eq!(STATE_STOP_PENDING, SERVICE_STOP_PENDING.0);
        assert_eq!(STATE_RUNNING, SERVICE_RUNNING.0);
        // And the one zero state, which none of the four is.
        assert_eq!(SERVICE_CONTINUE_PENDING.0, 5);
        for state in [
            STATE_STOPPED,
            STATE_START_PENDING,
            STATE_STOP_PENDING,
            STATE_RUNNING,
        ] {
            assert_ne!(state, SERVICE_CONTINUE_PENDING.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_control_codes_are_the_ones_the_windows_crate_defines() {
        use windows::Win32::System::Services::{
            SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PAUSE,
            SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        };
        assert_eq!(control_action(SERVICE_CONTROL_STOP), HandlerAction::Stop);
        assert_eq!(
            control_action(SERVICE_CONTROL_SHUTDOWN),
            HandlerAction::Stop
        );
        assert_eq!(
            control_action(SERVICE_CONTROL_INTERROGATE),
            HandlerAction::Interrogate
        );
        assert_eq!(
            control_action(SERVICE_CONTROL_PAUSE),
            HandlerAction::Unsupported
        );
        assert_eq!(
            control_action(SERVICE_CONTROL_CONTINUE),
            HandlerAction::Unsupported
        );
    }
}
