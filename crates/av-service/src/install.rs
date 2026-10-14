//! Installing the service, removing it, and starting and stopping what is
//! installed.
//!
//! # Why this is in the service crate and not in the command-line tool
//!
//! The name is here — see [`crate::scm::SERVICE_NAME`] — and a second copy of
//! the name in `av-cli` would be a second thing to rename. But the deeper
//! reason is that these five calls are the *other half* of [`crate::scm`]: that
//! module is what the service does once the SCM has started it, and this is
//! what puts it in a position to be started. A command-line tool that reached
//! for `CreateServiceW` itself would be a tool that could install a service
//! this crate's host does not implement, and nothing would say so.
//!
//! # What is verified here and what is not
//!
//! The decisions are separated from the calls, as everywhere else in this
//! crate. [`image_path`] (the quoting rule), [`scm_state_of`] (the state
//! mapping) and [`denied`] (what a refusal says) are ordinary functions with
//! ordinary tests, and they are the parts that can be wrong in an interesting
//! way: a `binPath` that is not quoted because a path happened not to have a
//! space today is a service that cannot start after the product is installed
//! somewhere else, and it presents as "the service failed to start" with
//! nothing anywhere naming the quoting.
//!
//! What is *not* verified is the calls themselves. `CreateServiceW` needs
//! administrator rights, and a machine that is in use; the integration test
//! that would drive them carries
//! `#[ignore = "requires administrator to install a service"]` and is not run.
//!
//! # Elevation, said plainly
//!
//! Every call here that changes the machine fails with `ERROR_ACCESS_DENIED`
//! when the process is not elevated, and none of them can elevate: Windows
//! requires the *user* to agree, which is a thing a program cannot do for
//! itself. So a refusal is turned into a sentence that names the cause and the
//! fix rather than into `Access is denied. (os error 5)`, which is what a
//! user would otherwise be left with.

use std::path::Path;

use crate::error::ServiceError;
use crate::scm::{STATE_RUNNING, STATE_START_PENDING, STATE_STOPPED, STATE_STOP_PENDING};

// The name the service is installed under — and the one a person types at `sc`
// — re-exported from `crate::scm`, which is where it is defined and where the
// service's own half of the SCM conversation reads it.
//
// Re-exported rather than left for callers to reach through `scm` because this
// module is where every other fact about the *installed* service lives: the
// binary name, the image path, the state, the four calls that change it. A
// front end that had to name two modules of this crate to ask one question
// about one service would be reading this crate's filing rather than its
// interface, and the name would be the only thing it went to the other module
// for.
pub use crate::scm::{SERVICE_DISPLAY_NAME, SERVICE_NAME};

/// `ERROR_ACCESS_DENIED`.
const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_SERVICE_DOES_NOT_EXIST`, which is `sc query` on a machine where the
/// service was never installed — the state this crate's own documentation says
/// this machine is in.
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
/// `ERROR_SERVICE_EXISTS`, from `CreateServiceW` for a name already taken.
const ERROR_SERVICE_EXISTS: u32 = 1073;
/// `ERROR_SERVICE_ALREADY_RUNNING`.
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
/// `ERROR_SERVICE_NOT_ACTIVE`, from `ControlService` on a stopped service.
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

/// `SERVICE_CONTINUE_PENDING`, which [`crate::scm`] has no use for and this
/// does.
const STATE_CONTINUE_PENDING: u32 = 5;
/// `SERVICE_PAUSE_PENDING`.
const STATE_PAUSE_PENDING: u32 = 6;
/// `SERVICE_PAUSED`.
const STATE_PAUSED: u32 = 7;

/// The access this crate asks of the SCM when it means to change something.
///
/// `SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT`. Both, not just the first:
/// `CreateServiceW` needs the create right, and every subsequent call on the
/// handle — including the `CloseServiceHandle` the guard makes on the way out —
/// needs the connect right.
const MANAGER_WRITE_ACCESS: u32 = 0x0002 | 0x0001;

/// The access this crate asks when it only means to look.
const MANAGER_READ_ACCESS: u32 = 0x0001;

/// `DELETE`, in the service-specific access mask.
///
/// Spelled out rather than reached for through `SERVICE_ALL_ACCESS` because
/// `remove` is the one call that needs this right and nothing else, and asking
/// for less than all of it is the habit worth keeping in a function that
/// deletes things.
const DELETE_ACCESS: u32 = 0x0001_0000;

/// `SERVICE_ALL_ACCESS`.
///
/// Asked for at install time and at no other. It is what `sc create` asks for
/// too, and the alternative — a hand-built union of the seven rights below —
/// is a list that is right until somebody adds a call that needs an eighth.
const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;

/// Where the service is, as the SCM sees it.
///
/// A separate enum from [`av_ipc::ServiceState`] and deliberately so: that one
/// is what the *service* says about itself over the control pipe, and this one
/// is what the *SCM* says about it without asking it anything. They disagree in
/// the two cases a user most needs to be able to tell apart — a service that is
/// `RUNNING` to the SCM and answering nothing on the pipe, and a service that
/// is answering on the pipe while the SCM has lost it — and folding them into
/// one type would make those two states unrepresentable.
///
/// `Paused` and the two pause transitions are here because the SCM can report
/// them. This service never accepts a pause, so seeing one means somebody
/// paused it by a means this build does not have, which is a thing to report
/// rather than to round to `Running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmState {
    /// The SCM does not know this name.
    NotInstalled,
    /// Installed and not running.
    Stopped,
    /// Starting.
    StartPending,
    /// Stopping.
    StopPending,
    /// Running.
    Running,
    /// Coming back from a pause.
    ContinuePending,
    /// Going into a pause.
    PausePending,
    /// Paused.
    Paused,
    /// A state this build does not know, carried rather than rounded.
    Unrecognised(u32),
}

impl ScmState {
    /// The word used in the command line's output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ScmState::NotInstalled => "not-installed",
            ScmState::Stopped => "stopped",
            ScmState::StartPending => "start-pending",
            ScmState::StopPending => "stop-pending",
            ScmState::Running => "running",
            ScmState::ContinuePending => "continue-pending",
            ScmState::PausePending => "pause-pending",
            ScmState::Paused => "paused",
            ScmState::Unrecognised(_) => "unrecognised",
        }
    }

    /// True when the SCM reports the service as running.
    pub const fn is_running(self) -> bool {
        matches!(self, ScmState::Running)
    }

    /// True when the SCM reports the service as installed, whatever it is
    /// doing.
    pub const fn is_installed(self) -> bool {
        !matches!(self, ScmState::NotInstalled)
    }
}

/// The `SERVICE_STATUS.dwCurrentState` the SCM reports, as a [`ScmState`].
///
/// Exhaustive over the seven values Windows defines, with the eighth arm for a
/// number this build has not heard of. That arm is not a fallback for the seven
/// — it is the honest answer for a value from a newer Windows, and rounding it
/// to `Stopped` would be a command line reporting that the service is not
/// running because it did not recognise the word for "running".
pub const fn scm_state_of(current_state: u32) -> ScmState {
    match current_state {
        STATE_STOPPED => ScmState::Stopped,
        STATE_START_PENDING => ScmState::StartPending,
        STATE_STOP_PENDING => ScmState::StopPending,
        STATE_RUNNING => ScmState::Running,
        STATE_CONTINUE_PENDING => ScmState::ContinuePending,
        STATE_PAUSE_PENDING => ScmState::PausePending,
        STATE_PAUSED => ScmState::Paused,
        other => ScmState::Unrecognised(other),
    }
}

/// The `lpBinaryPathName` an install should write, for an executable at `image`.
///
/// # Why it is always quoted
///
/// `lpBinaryPathName` is a *command line*, not a path: the SCM splits it on
/// spaces and takes the first token as the program. An unquoted
/// `C:\Program Files\Wenle AV\wenle-av-service.exe` therefore starts
/// `C:\Program.exe`, which is either an error or — on a machine where somebody
/// has put a file there — the wrong program, running as `LocalSystem`, at boot.
/// MSDN's rule is "quote it if it has a space", and this quotes
/// unconditionally because the day the rule matters is the day the product is
/// installed somewhere with a space in it, which is not the day anybody is
/// looking at this function.
///
/// Quoting a path with no space is not merely harmless: the SCM's parser
/// accepts it, and `sc qc` shows the value back with the quotes intact, so the
/// two forms are the same to everything that reads it.
///
/// A path with a `"` in it would break this, and a Windows path cannot contain
/// one — `CreateDirectoryW` refuses the character — so there is nothing to
/// defend against and no branch here that would have to be tested.
pub fn image_path(image: &Path) -> String {
    format!("\"{}\"", image.display())
}

/// The name of the service's executable, as `[[bin]]` in `Cargo.toml` spells
/// it.
///
/// Here rather than in the command-line tool because it is half of what
/// [`install`] writes into the SCM, and the other half — [`SERVICE_NAME`] — is
/// already in this crate. A caller that pointed an install at the wrong
/// executable would get a service that starts and immediately stops, and the
/// SCM's event log would be the only place that said so.
pub const SERVICE_BINARY: &str = "wenle-av-service.exe";

/// Where a default install expects the service's executable to be.
///
/// Beside the front end, because that is where a Windows install puts it and
/// where a build tree puts it too: `target\debug\wenle.exe` and
/// `target\debug\wenle-av-service.exe` are siblings in exactly the same way as
/// the installed pair. An install that pointed at a debug build is a real
/// mistake a developer can make, and the fix is a sentence in the
/// documentation rather than a check here — this function cannot tell a debug
/// build from a release one, and guessing would only break the portable case.
pub fn installed_binary(install_dir: &Path) -> std::path::PathBuf {
    install_dir.join(SERVICE_BINARY)
}

/// What a refused call says.
///
/// One function rather than a sentence at each call site, because the sentence
/// is the same and because the *reason* is the same: all five calls here need
/// the same thing, and a user who has run one of them unelevated has run them
/// all unelevated. `what` names the operation, so the message says what was
/// refused rather than only that something was.
pub fn denied(what: &str) -> ServiceError {
    ServiceError::Scm {
        message: format!(
            "{what} was refused: access is denied. Installing, removing, starting and stopping \
             a service all need administrator rights. Run this from an elevated prompt — \
             right-click the terminal, then \"Run as administrator\"."
        ),
    }
}

/// The answer for every entry point on a build that has no SCM.
///
/// A named error and not an `unreachable!`: this workspace builds for one
/// platform today and these functions are ordinary library code that a second
/// platform would compile, so the honest thing is a refusal that says why
/// rather than a panic that would take the process with it.
#[cfg(not(windows))]
fn not_windows() -> ServiceError {
    ServiceError::Other("this build has no Service Control Manager".to_string())
}

/// The three calls that have to go through a handle, and the guard that owns
/// one.
///
/// Behind `cfg(windows)` together, because the `windows` crate is a Windows
/// target dependency and nothing in here can be typed on a machine without it.
/// What is *not* behind it is everything above and below: the state mapping,
/// the quoting rule and the messages are the parts a test on any platform has
/// something to say about.
#[cfg(windows)]
mod handles {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE,
    };

    use super::{denied, ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST, SERVICE_NAME};
    use crate::error::ServiceError;

    /// An `SC_HANDLE` closed exactly once, on every path out.
    ///
    /// A guard rather than a `CloseServiceHandle` at the end of each function:
    /// the functions here have four and five `?` between the open and the
    /// close, and a leak on the error path is the one that is never exercised
    /// until a machine has been running for a month.
    pub(super) struct Handle(pub(super) SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from `OpenSCManagerW`, `OpenServiceW` or
            // `CreateServiceW` and has not been closed: it is owned by this
            // guard and by nothing else. The result is ignored because a close
            // that fails has already had whatever effect it was going to have.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    /// A failed SCM call, as this crate's error type.
    ///
    /// One function rather than a `map_err` at each call site, because the one
    /// decision worth making here — whether a code means "refused" or "failed"
    /// — is the one a user reads, and because `denied` is the only place that
    /// sentence is written.
    pub(super) fn scm_error(what: &str, error: &windows::core::Error) -> ServiceError {
        if crate::win32::code(error) == ERROR_ACCESS_DENIED {
            return denied(what);
        }
        ServiceError::Scm {
            message: format!(
                "{what} failed ({}): {}",
                crate::win32::code(error),
                error.message()
            ),
        }
    }

    /// Open the SCM's database.
    pub(super) fn open_manager(access: u32) -> Result<Handle, ServiceError> {
        // SAFETY: a null machine name means this machine and a null database
        // name means the active database, which is what the SCM documents
        // `NULL` to mean for both. The call takes no buffer and retains
        // nothing.
        let handle = unsafe {
            OpenSCManagerW(
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR::null(),
                access,
            )
        };
        handle
            .map(Handle)
            .map_err(|error| scm_error("opening the service database", &error))
    }

    /// Open the service itself, with `access`.
    ///
    /// `Ok(None)` when the SCM says there is no service by this name, which is
    /// a state and not a failure — see [`ScmState::NotInstalled`].
    ///
    /// [`ScmState::NotInstalled`]: super::ScmState::NotInstalled
    pub(super) fn open_service(
        manager: &Handle,
        access: u32,
    ) -> Result<Option<Handle>, ServiceError> {
        let wide = crate::win32::to_wide_str(SERVICE_NAME);
        // SAFETY: `wide` is NUL-terminated and outlives the call; `manager`
        // owns a live SCM handle for the duration.
        let opened =
            unsafe { OpenServiceW(manager.0, windows::core::PCWSTR(wide.as_ptr()), access) };
        match opened {
            Ok(handle) => Ok(Some(Handle(handle))),
            Err(error) if crate::win32::code(&error) == ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
            Err(error) => Err(scm_error(
                &format!("opening the {SERVICE_NAME} service"),
                &error,
            )),
        }
    }
}

#[cfg(windows)]
use handles::{open_manager, open_service, scm_error, Handle};

/// Where the service is, as the SCM sees it.
///
/// The one call here that an unelevated process can make: `SERVICE_QUERY_STATUS`
/// is granted to `Everyone` on services that allow it, and `sc query` — which
/// every user is told to run when something is wrong — is exactly this. A
/// refusal is still reported as a refusal rather than guessed at, because
/// "not installed" and "not allowed to ask" are different answers and a user
/// chasing a broken installation needs the second one to be distinguishable
/// from the first.
#[cfg(windows)]
pub fn state() -> Result<ScmState, ServiceError> {
    use windows::Win32::System::Services::{
        QueryServiceStatusEx, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    };

    let manager = open_manager(MANAGER_READ_ACCESS)?;
    let Some(service) = open_service(&manager, SERVICE_QUERY_STATUS)? else {
        return Ok(ScmState::NotInstalled);
    };

    let mut status = SERVICE_STATUS_PROCESS::default();
    // SAFETY: `status` is a live, correctly aligned `SERVICE_STATUS_PROCESS` on
    // this stack, and the slice handed over is exactly its own bytes — the API
    // writes a struct of that type and this is one. The `peek` on the far side
    // is where the borrow of `status` ends, so nothing aliases it afterwards.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            std::ptr::addr_of_mut!(status).cast::<u8>(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    let mut needed = 0u32;
    // SAFETY: `service` owns a live service handle, `bytes` outlives the call
    // and its length is what the signature passes to the operating system, and
    // `needed` is a `u32` on this stack.
    let queried = unsafe {
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed)
    };
    queried.map_err(|error| scm_error("asking the SCM about the service", &error))?;
    Ok(scm_state_of(status.dwCurrentState.0))
}

#[cfg(not(windows))]
pub fn state() -> Result<ScmState, ServiceError> {
    Err(not_windows())
}

/// Install the service so that it runs `image`, starting at boot.
///
/// # The three choices that are made here
///
/// * **`SERVICE_AUTO_START`.** The point of installing this is that the machine
///   is protected without anybody remembering to start it. A demand-start
///   antivirus service is one that is not running on the machine that most
///   needs it.
/// * **`SERVICE_WIN32_OWN_PROCESS`.** Its own process, not one shared with
///   other services: a shared process is one whose crash takes the others with
///   it, and this service holds a kernel driver's worth of state.
/// * **`LocalSystem`.** The account is left at the SCM's default, which is
///   `LocalSystem`, and it is the account this actually needs: the service
///   reads every file on the machine and writes `%ProgramData%\WenleAV`. A
///   hardened installation would use a dedicated virtual account with a
///   narrowly written DACL, and this build does not — that is a real difference
///   from what a commercial product would do, and it is stated here rather than
///   left for somebody to find in `sc qc` output.
#[cfg(windows)]
pub fn install(image: &Path) -> Result<(), ServiceError> {
    use windows::Win32::System::Services::{
        CreateServiceW, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_WIN32_OWN_PROCESS,
    };

    let manager = open_manager(MANAGER_WRITE_ACCESS)?;
    let name = crate::win32::to_wide_str(SERVICE_NAME);
    let display = crate::win32::to_wide_str(SERVICE_DISPLAY_NAME);
    let binary = crate::win32::to_wide_str(&image_path(image));
    let null = windows::core::PCWSTR::null();

    // SAFETY: every `PCWSTR` here borrows a buffer that outlives the call —
    // `name`, `display` and `binary` are locals above — and the four arguments
    // that are null are the ones the SCM documents as optional: no load-order
    // group, no tag, no dependencies, and the default account with no password.
    // `manager` owns a live SCM handle opened for create.
    let created = unsafe {
        CreateServiceW(
            manager.0,
            windows::core::PCWSTR(name.as_ptr()),
            windows::core::PCWSTR(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            windows::core::PCWSTR(binary.as_ptr()),
            null,
            None,
            null,
            null,
            null,
        )
    };
    match created {
        Ok(handle) => {
            // Closed here rather than kept: nothing below needs it, and the
            // guard would otherwise hold it until the end of the function for
            // no reason.
            drop(Handle(handle));
            Ok(())
        }
        Err(error) if crate::win32::code(&error) == ERROR_SERVICE_EXISTS => {
            Err(ServiceError::Scm {
                message: format!(
                    "{SERVICE_NAME} is already installed. Remove it first with \
                 `wenle service remove`, or ask for its status with `wenle service status`."
                ),
            })
        }
        Err(error) => Err(scm_error(&format!("installing {SERVICE_NAME}"), &error)),
    }
}

#[cfg(not(windows))]
pub fn install(_image: &Path) -> Result<(), ServiceError> {
    Err(not_windows())
}

/// Remove the service.
///
/// `DeleteService` only marks the service for deletion: a running service is
/// stopped first and the name stays in the database until it has. So this
/// removes a *stopped* service and refuses nothing, and [`state`] afterwards is
/// the thing that says whether the name is gone — which is what
/// `wenle service remove` reports, rather than claiming a removal it has not
/// confirmed.
#[cfg(windows)]
pub fn remove() -> Result<(), ServiceError> {
    use windows::Win32::System::Services::DeleteService;

    let manager = open_manager(MANAGER_WRITE_ACCESS)?;
    // `DELETE` is 0x0001_0000 in the service-specific access mask, which is
    // also what `SERVICE_ALL_ACCESS` contains.
    let Some(service) = open_service(&manager, DELETE_ACCESS)? else {
        return Err(ServiceError::Scm {
            message: format!("{SERVICE_NAME} is not installed, so there is nothing to remove."),
        });
    };
    // SAFETY: `service` owns a live service handle opened for delete, and the
    // call takes no buffer.
    unsafe { DeleteService(service.0) }
        .map_err(|error| scm_error(&format!("removing {SERVICE_NAME}"), &error))
}

#[cfg(not(windows))]
pub fn remove() -> Result<(), ServiceError> {
    Err(not_windows())
}

/// What a start did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    /// The SCM was told to start it and returned no failure. `StartServiceW`
    /// waits for the service to report itself running or to fail, so this is
    /// not a request that was merely queued.
    Started,
    /// It was already running, so nothing was asked of the SCM.
    AlreadyRunning,
}

/// Start the service.
///
/// The SCM reports `ERROR_SERVICE_ALREADY_RUNNING` for a service that is up,
/// and that is turned into [`StartOutcome::AlreadyRunning`] rather than into an
/// error: a user who types `wenle service start` twice has got what they asked
/// for the second time as well, and a command that failed would be reporting
/// the wrong thing about the machine.
#[cfg(windows)]
pub fn start() -> Result<StartOutcome, ServiceError> {
    use windows::Win32::System::Services::{StartServiceW, SERVICE_START};

    let manager = open_manager(MANAGER_WRITE_ACCESS)?;
    let Some(service) = open_service(&manager, SERVICE_START)? else {
        return Err(ServiceError::Scm {
            message: format!(
                "{SERVICE_NAME} is not installed, so it cannot be started. Install it first \
                 with `wenle service install`."
            ),
        });
    };
    // SAFETY: `service` owns a live service handle opened for start, and a null
    // argument vector is the documented way to pass this service no arguments —
    // which is what it is installed with, and what `image_path` writes.
    match unsafe { StartServiceW(service.0, None) } {
        Ok(()) => Ok(StartOutcome::Started),
        Err(error) if crate::win32::code(&error) == ERROR_SERVICE_ALREADY_RUNNING => {
            Ok(StartOutcome::AlreadyRunning)
        }
        Err(error) => Err(scm_error(&format!("starting {SERVICE_NAME}"), &error)),
    }
}

#[cfg(not(windows))]
pub fn start() -> Result<StartOutcome, ServiceError> {
    Err(not_windows())
}

/// What a stop did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// The SCM accepted the stop and the service is stopping. Not "stopped":
    /// `ControlService` returns as soon as the control is delivered, and the
    /// service has a `Host` to shut down and a pipe to close after that.
    StopRequested,
    /// It was not running, so there was nothing to stop.
    NotRunning,
}

/// Stop the service.
///
/// `ERROR_SERVICE_NOT_ACTIVE` is turned into [`StopOutcome::NotRunning`] for
/// the reason [`start`] turns its own code into an outcome: the state the user
/// asked for is the state the machine is in.
#[cfg(windows)]
pub fn stop() -> Result<StopOutcome, ServiceError> {
    use windows::Win32::System::Services::{
        ControlService, SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STOP,
    };

    let manager = open_manager(MANAGER_WRITE_ACCESS)?;
    let Some(service) = open_service(&manager, SERVICE_STOP)? else {
        return Err(ServiceError::Scm {
            message: format!("{SERVICE_NAME} is not installed, so there is nothing to stop."),
        });
    };
    // The out-parameter is the service's status *at the moment of the control*,
    // which nothing here reads: `state` is the call that answers where the
    // service is, and it asks a fresh question rather than trusting this one.
    let mut status = SERVICE_STATUS::default();
    // SAFETY: `service` owns a live service handle opened for stop, and
    // `status` is a live, correctly aligned struct on this stack that outlives
    // the call.
    match unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } {
        Ok(()) => Ok(StopOutcome::StopRequested),
        Err(error) if crate::win32::code(&error) == ERROR_SERVICE_NOT_ACTIVE => {
            Ok(StopOutcome::NotRunning)
        }
        Err(error) => Err(scm_error(&format!("stopping {SERVICE_NAME}"), &error)),
    }
}

#[cfg(not(windows))]
pub fn stop() -> Result<StopOutcome, ServiceError> {
    Err(not_windows())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_path_is_quoted_whatever_it_contains() {
        // The failure this prevents, in full: an unquoted path with a space in
        // it is a command line whose first token is `C:\Program`, so the SCM
        // starts `C:\Program.exe` as `LocalSystem` at every boot. A path with
        // no space is quoted too, so that the rule does not depend on where the
        // product happens to be installed today.
        assert_eq!(
            image_path(Path::new(r"C:\Program Files\Wenle AV\wenle-av-service.exe")),
            r#""C:\Program Files\Wenle AV\wenle-av-service.exe""#
        );
        assert_eq!(
            image_path(Path::new(r"C:\wenle\wenle-av-service.exe")),
            r#""C:\wenle\wenle-av-service.exe""#
        );
        // And the quote is the first and last character, which is the property
        // the SCM's parser actually reads.
        let quoted = image_path(Path::new(r"C:\a b\c.exe"));
        assert!(quoted.starts_with('"'));
        assert!(quoted.ends_with('"'));
        assert_eq!(quoted.matches('"').count(), 2);
    }

    #[test]
    fn every_state_windows_defines_maps_to_its_own_answer() {
        // All seven, each to a different variant: a mapping that folded two of
        // them would report a paused service as a running one, or a service
        // that is coming back from a pause as a stopped one.
        let pairs = [
            (STATE_STOPPED, ScmState::Stopped),
            (STATE_START_PENDING, ScmState::StartPending),
            (STATE_STOP_PENDING, ScmState::StopPending),
            (STATE_RUNNING, ScmState::Running),
            (STATE_CONTINUE_PENDING, ScmState::ContinuePending),
            (STATE_PAUSE_PENDING, ScmState::PausePending),
            (STATE_PAUSED, ScmState::Paused),
        ];
        for (code, expected) in pairs {
            assert_eq!(scm_state_of(code), expected, "state {code}");
            assert_eq!(scm_state_of(code).as_str(), expected.as_str());
        }
        // Seven distinct words, so no two states read the same in the output.
        let mut words: Vec<&str> = pairs.iter().map(|(_, state)| state.as_str()).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), pairs.len());
    }

    #[test]
    fn a_state_this_build_does_not_know_is_carried_and_not_rounded() {
        // The arm that matters for a newer Windows: a value nobody here has
        // heard of must not be reported as "stopped", because a command line
        // that said "stopped" about a running service is worse than one that
        // says it does not know.
        assert_eq!(scm_state_of(0), ScmState::Unrecognised(0));
        assert_eq!(scm_state_of(8), ScmState::Unrecognised(8));
        assert_eq!(scm_state_of(u32::MAX), ScmState::Unrecognised(u32::MAX));
        assert!(!scm_state_of(8).is_running());
        // An unrecognised state is still an installed service: the SCM knows
        // the name, which is the question `is_installed` answers.
        assert!(scm_state_of(8).is_installed());
    }

    #[test]
    fn only_not_installed_is_not_installed() {
        // The distinction the command line turns on: `state` returning
        // `NotInstalled` is what makes `service status` say "not installed"
        // instead of inventing a state for a service that is not there.
        assert!(!ScmState::NotInstalled.is_installed());
        assert!(!ScmState::NotInstalled.is_running());
        for installed in [
            ScmState::Stopped,
            ScmState::StartPending,
            ScmState::StopPending,
            ScmState::Running,
            ScmState::ContinuePending,
            ScmState::PausePending,
            ScmState::Paused,
        ] {
            assert!(installed.is_installed(), "{installed:?}");
        }
        assert!(ScmState::Running.is_running());
        assert!(!ScmState::StartPending.is_running());
        assert!(!ScmState::StopPending.is_running());
    }

    #[test]
    fn a_refusal_says_what_needs_doing_about_it() {
        // The message this replaces is `Access is denied. (os error 5)`, which
        // tells a user what happened and nothing about what to do. Every
        // operation names itself, and every message names elevation.
        for what in [
            "installing WenleAvService",
            "removing WenleAvService",
            "starting WenleAvService",
            "stopping WenleAvService",
        ] {
            let message = denied(what).to_string();
            assert!(message.contains(what), "{message}");
            assert!(message.contains("administrator"), "{message}");
            assert!(message.contains("elevated"), "{message}");
        }
        // And it is the SCM variant, which is the one `is_fatal` treats as a
        // reason not to carry on.
        assert!(denied("installing").is_fatal());
    }

    #[test]
    fn the_service_binary_sits_beside_the_front_end() {
        // The sibling rule, which is what makes the default install work in a
        // build tree and in an installed one without a second code path.
        assert_eq!(
            installed_binary(Path::new(r"C:\wenle")),
            Path::new(r"C:\wenle\wenle-av-service.exe")
        );
        assert_eq!(
            installed_binary(Path::new(r"C:\Program Files\Wenle AV")),
            Path::new(r"C:\Program Files\Wenle AV\wenle-av-service.exe")
        );
        assert!(SERVICE_BINARY.ends_with(".exe"));
    }

    #[test]
    fn the_access_masks_are_the_right_bits() {
        // Small numbers with names, and a wrong one is a call that fails with
        // "access is denied" on an elevated prompt — the most confusing shape
        // this failure can take. `SC_MANAGER_CONNECT` is 1 and
        // `SC_MANAGER_CREATE_SERVICE` is 2.
        assert_eq!(MANAGER_READ_ACCESS, 1);
        assert_eq!(MANAGER_WRITE_ACCESS, 3);
        assert_eq!(
            MANAGER_WRITE_ACCESS & MANAGER_READ_ACCESS,
            MANAGER_READ_ACCESS
        );
        // `SERVICE_ALL_ACCESS` contains `SERVICE_QUERY_STATUS` (4),
        // `SERVICE_START` (16), `SERVICE_STOP` (32) and `DELETE` (0x1_0000),
        // which are the four the other calls ask for on their own.
        assert_eq!(SERVICE_ALL_ACCESS & 4, 4);
        assert_eq!(SERVICE_ALL_ACCESS & 16, 16);
        assert_eq!(SERVICE_ALL_ACCESS & 32, 32);
        assert_eq!(SERVICE_ALL_ACCESS & DELETE_ACCESS, DELETE_ACCESS);
    }

    #[test]
    fn the_error_codes_are_the_ones_windows_defines() {
        // Each is a decision — "already installed", "already running", "not
        // running", "not installed" — so a wrong number is a wrong answer to a
        // user rather than a crash, and this is the test that catches a typo.
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED as DENIED, ERROR_SERVICE_ALREADY_RUNNING as RUNNING,
            ERROR_SERVICE_DOES_NOT_EXIST as MISSING, ERROR_SERVICE_EXISTS as EXISTS,
            ERROR_SERVICE_NOT_ACTIVE as INACTIVE,
        };
        assert_eq!(ERROR_ACCESS_DENIED, DENIED.0);
        assert_eq!(ERROR_SERVICE_DOES_NOT_EXIST, MISSING.0);
        assert_eq!(ERROR_SERVICE_EXISTS, EXISTS.0);
        assert_eq!(ERROR_SERVICE_ALREADY_RUNNING, RUNNING.0);
        assert_eq!(ERROR_SERVICE_NOT_ACTIVE, INACTIVE.0);
    }
}
