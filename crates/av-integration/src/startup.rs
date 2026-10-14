//! Starting the window when the user signs in.
//!
//! # What is written, and what Windows does with it
//!
//! One string value under
//! `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. Windows
//! reads that key once per sign-in and starts each value's command line with the
//! user's own privileges. The value this module writes launches the graphical
//! front end with `--minimized`, which puts it in the notification area:
//!
//! ```text
//! "C:\Program Files\WenleAV\wenle-gui.exe" --minimized
//! ```
//!
//! # `remove` deletes one value and never the key
//!
//! This is the property of this module worth reading twice. `...\CurrentVersion\
//! Run` is *shared*: every program on the machine that starts at sign-in has a
//! value in it, and they are all in the same key, because that is what the key
//! is for. Deleting the key — which is what [`crate::shell`]'s and
//! [`crate::notifications`]'s removals do, correctly, to keys this product owns
//! outright — would remove the startup entries of every other program on the
//! machine at the same time.
//!
//! So [`remove`] deletes exactly one value, by name, through
//! `RegDeleteValueW`, and a name that is not there is `Ok`: it is the cleanup
//! step of a failed install as much as the undo of a successful one, and running
//! it on a machine where nothing was ever installed must not be the command that
//! breaks something.
//!
//! # Why this key, and not the two alternatives
//!
//! A program that runs at sign-in can be registered three ways in current
//! Windows: this key, a logon-triggered scheduled task, or a shortcut in the
//! user's Startup folder. The choice matters less for what Windows does than for
//! what a user can see and undo:
//!
//! * **The user can turn this off without this product's help.** Task Manager's
//!   *Startup apps* tab is a view of exactly these values, and switching one off
//!   there disables it. A user who does that has made a decision this product
//!   should not fight, and [`status`] reporting the value as absent is the
//!   correct answer — the entry really is not there any more.
//! * **It is one value with a name.** It is readable with `reg query`, removable
//!   with `reg delete`, and the name it is filed under is the product's own. A
//!   scheduled task is an XML document in a store most users never open, and a
//!   startup shortcut is a file in a folder whose contents are not obviously
//!   this product's.
//! * **It needs no elevation, and it must not have any.** This launches a
//!   tray icon and an egui window in the signed-in user's own session. A
//!   machine-wide entry would be an attempt to start one user's window from
//!   another user's sign-in.
//!
//! The honest cost of the choice: this key is the classic autorun location, and
//! some security software reports writes to it as suspicious behaviour. The
//! write is by a program registering its own executable, with the user's own
//! privileges, on a command the user typed — but that is what the write looks
//! like from outside, and saying so here is better than a user discovering it
//! from a warning they cannot explain.
//!
//! # A stale entry is silent
//!
//! Windows ignores a `Run` value whose program no longer exists; there is no
//! error at sign-in and no event in any log. So a product that was moved or
//! deleted leaves an entry that does nothing and says nothing, and the only way
//! to find it is to read the key. [`status`] returns the command line verbatim
//! and not a boolean for that reason — the path in it is what tells a user the
//! entry is pointing at a directory the product is no longer in.
//!
//! Nothing outside this module removes the entry. An uninstall has to run
//! `wenle integrate startup remove`, and the module documentation says so.

use std::path::{Path, PathBuf};

use av_core::{AvError, SERVICE_NAME};

use crate::registry::{Hive, Key, RegistryError};
use crate::shell::{self, ShellError};

/// The per-user startup key.
///
/// Below `HKEY_CURRENT_USER`, and shared with every other program on the
/// machine that starts at sign-in — see the module documentation for what that
/// means for [`remove`].
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The name this product's entry is filed under.
///
/// The product's name in Windows, which is the same string as the service's and
/// the install directory's. Deliberately not something like "Wenle AV Tray":
/// what a user sees in Task Manager's *Startup apps* list, in `reg query`, and
/// in this product's own output should be one name, and the name a user
/// recognises is the one on the box.
pub const VALUE_NAME: &str = SERVICE_NAME;

/// The argument that makes the window start in the notification area.
///
/// Named here, and parsed by `av-gui`, and the two have to agree — a command
/// line this module writes with a flag the window does not know would be a
/// startup entry that opens a window at every sign-in instead of waiting in the
/// tray, which is the opposite of what a user who ticked the setting asked for.
pub const MINIMIZED_FLAG: &str = "--minimized";

/// The command line a startup entry should hold, launching `program`.
///
/// Pure: it formats and does not look at the filesystem, so the string Windows
/// will run is tested as a string.
///
/// Quoted, for the reason the Explorer verbs are quoted: `C:\Program Files\
/// WenleAV` is an ordinary install location and is not a path without spaces.
/// The argument is outside the quotes because it is not part of the path.
pub fn command_line_for(program: &Path) -> String {
    format!("\"{}\" {MINIMIZED_FLAG}", program.display())
}

/// The command line this build would write, for the program this process is
/// running from.
///
/// The only program path that can be right is this executable's own directory's,
/// taken from `std::env::current_exe()`; nothing here accepts a path from the
/// caller. See [`crate::shell::launch_program`] for why the graphical front end
/// is preferred and the console is the fallback.
pub fn expected() -> Result<String, StartupError> {
    Ok(command_line_for(&program_path()?))
}

/// Register the entry, and read back what the registry now holds.
///
/// Idempotent: the value is written outright rather than merged, so running this
/// twice leaves the same registry as running it once, and running it after the
/// product has moved replaces the stale path rather than adding a second entry.
pub fn install() -> Result<StartupStatus, StartupError> {
    let program = program_path()?;
    let key = Key::create(Hive::CurrentUser, RUN_KEY)?;
    key.set_string(VALUE_NAME, &command_line_for(&program))?;

    log::info!(
        "registered {VALUE_NAME:?} in the per-user startup key, launching {}",
        program.display()
    );
    status()
}

/// Remove the entry, if it is there.
///
/// One value, deleted by name. Never the key — see the module documentation for
/// what else lives in it. A key or a value that is not there is `Ok`.
pub fn remove() -> Result<(), StartupError> {
    // `open` and not `create`: a `remove` on a machine where nothing was ever
    // installed must not be the command that creates the key it is removing
    // from.
    let Some(key) = Key::open(Hive::CurrentUser, RUN_KEY)? else {
        log::debug!("there is no per-user startup key, so there is nothing to remove");
        return Ok(());
    };
    key.delete_value(VALUE_NAME)?;
    log::info!("removed {VALUE_NAME:?} from the per-user startup key");
    Ok(())
}

/// The command line the machine holds, if any.
///
/// Read-only and verbatim: this is what Windows will run, and re-deriving it
/// from this process's own path would answer a different question — the one
/// [`expected`] answers. The two together are what let a caller say "this entry
/// points somewhere else", which is the fact a stale entry is made of.
pub fn status() -> Result<StartupStatus, StartupError> {
    let command = match Key::open_read_only(Hive::CurrentUser, RUN_KEY)? {
        Some(key) => key.string(VALUE_NAME)?,
        None => None,
    };
    Ok(StartupStatus { command })
}

/// The program a startup entry should launch.
///
/// # Why this is not [`shell::launch_program`]
///
/// `launch_program` falls back to `wenle.exe` when no graphical front end ships
/// beside this executable, which is right for a shell verb — a console that
/// scans a file and closes is better than a right-click that does nothing — and
/// wrong here. The command line this module writes carries
/// [`MINIMIZED_FLAG`], which is `av-gui`'s argument and not `av-cli`'s: a
/// startup entry that fell back to the console would run
/// `wenle.exe --minimized` at every sign-in, and that command line is refused —
///
/// ```text
/// error: unexpected argument '--minimized' found
/// Usage: wenle.exe [OPTIONS] <COMMAND>
/// ```
///
/// measured against the shipped `wenle.exe`, exit code 2. Windows starts a `Run`
/// value with no console attached and reports nothing, so the entry would do
/// nothing at every sign-in and say nothing about it — the silent stale entry
/// the module documentation already warns about, created on purpose by the
/// install command.
///
/// So a startup entry is refused rather than written when there is no front end
/// to write it for. There is no tray to start without one, which is the whole of
/// what the entry is for.
fn program_path() -> Result<PathBuf, StartupError> {
    Ok(program_in(&shell::executable_dir()?)?)
}

/// The same decision, from a directory rather than from this process.
///
/// Split out so that the refusal below is a test rather than a claim: the
/// fallback it removes is only reachable from a directory that has no front end
/// in it, and a test cannot arrange for the executable *running the tests* to
/// be somewhere else.
fn program_in(exe_dir: &Path) -> Result<PathBuf, StartupError> {
    if !shell::gui_is_available(exe_dir) {
        return Err(StartupError::NoFrontEnd {
            directory: exe_dir.to_path_buf(),
        });
    }
    Ok(exe_dir.join(shell::GUI_EXE))
}

/// What the machine holds about the startup entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StartupStatus {
    /// The value, verbatim, or `None` when it is absent.
    ///
    /// A `String` and not a `bool` because an entry pointing at a program that
    /// is no longer installed is present, is what makes the entry useless, and
    /// is invisible in every other way. See the module documentation.
    pub command: Option<String>,
}

impl StartupStatus {
    /// Whether there is an entry at all, whatever it points at.
    pub fn is_installed(&self) -> bool {
        self.command.is_some()
    }

    /// Whether the entry is missing, or is not the one this build would write.
    ///
    /// `false` when nothing can be read about the expected line, which is the
    /// two cases where there is no "what this build would write" to compare
    /// against: this process cannot find its own path, or there is no graphical
    /// front end beside it to write a startup entry for. Reported as not stale
    /// rather than guessed at — and in the second case nothing can be *written*
    /// either, so a user of a console-only copy is told about the missing front
    /// end by `install` rather than by this predicate.
    pub fn is_stale(&self) -> bool {
        match expected() {
            Ok(wanted) => self.differs_from(&wanted),
            Err(_) => false,
        }
    }

    /// Whether what the machine holds is something other than `wanted`.
    ///
    /// The comparison on its own, with the line to compare against passed in,
    /// which is the only form of it a test can make a claim about: the line this
    /// build would write comes from the directory the *test binary* is running
    /// from, and that is `target\release\deps` — a directory with no front end
    /// in it, which is why [`expected`] refuses there. An absent entry is not a
    /// stale one in either form.
    pub fn differs_from(&self, wanted: &str) -> bool {
        matches!(&self.command, Some(found) if found != wanted)
    }
}

/// A startup entry that could not be written or read.
///
/// The same two failures as [`crate::notifications`], and wrapped the same way
/// for the same reason: a registry call, or the one thing that is about this
/// process rather than about the registry — that it cannot find its own
/// executable, and therefore has no command line to register.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// This executable's own directory could not be determined, so there is no
    /// command line to write.
    #[error(transparent)]
    NoExecutable(#[from] ShellError),

    /// There is no graphical front end beside this executable, so there is
    /// nothing to start at sign-in that would have a notification area to wait
    /// in. See `program_path` for why the console is not a fallback here.
    #[error(
        "there is no {gui} in {directory}, so there is no window to start at sign-in — \
         the console front end does not accept {flag} and would do nothing",
        gui = shell::GUI_EXE,
        flag = MINIMIZED_FLAG
    )]
    NoFrontEnd {
        /// The directory the front end was looked for in — this executable's own.
        directory: PathBuf,
    },
}

impl From<StartupError> for AvError {
    /// The registry code survives; the rest becomes a sentence.
    fn from(error: StartupError) -> Self {
        match error {
            StartupError::Registry(registry) => AvError::from(registry),
            other => AvError::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_in_the_current_users_run_key() {
        // The path as a reviewer checks it against Windows' documentation, and
        // the property that makes it per-user: an install for every account
        // would be an attempt to open one user's window at another's sign-in.
        assert_eq!(
            RUN_KEY,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert!(!RUN_KEY.contains("LocalMachine"));
    }

    #[test]
    fn the_command_line_is_quoted_and_carries_the_flag() {
        // A path with a space in it, which is the case the quotes exist for,
        // and an argument outside them — a flag inside the quotes would be part
        // of the program name and Windows would look for a file called
        // `wenle-gui.exe" --minimized`.
        assert_eq!(
            command_line_for(Path::new(r"C:\Program Files\WenleAV\wenle-gui.exe")),
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --minimized"#
        );
    }

    #[test]
    fn the_flag_is_the_one_the_window_parses() {
        // Two crates, one string. `av-gui`'s argument parser accepts this exact
        // spelling, and a rename on either side would be a startup entry that
        // opens a window at every sign-in.
        assert_eq!(MINIMIZED_FLAG, "--minimized");
        assert!(!MINIMIZED_FLAG.contains('"'));
        assert!(!MINIMIZED_FLAG.contains(' '));
    }

    #[test]
    fn the_value_name_is_the_products_name_in_windows() {
        // What a user sees in Task Manager and in `reg query`. One name for one
        // product.
        assert_eq!(VALUE_NAME, "WenleAV");
        assert_eq!(VALUE_NAME, av_core::APP_USER_MODEL_ID);
    }

    #[test]
    fn an_absent_entry_is_not_a_stale_one() {
        // The distinction the report exists for: a machine where the product
        // has never been started at sign-in has no entry, and calling that
        // "stale" would describe a fault that is not there.
        let absent = StartupStatus::default();
        assert!(!absent.is_installed());
        assert!(!absent.is_stale());
        assert_eq!(absent.command, None);
    }

    #[test]
    fn an_entry_pointing_somewhere_else_is_the_stale_one() {
        // The line to compare against is passed in rather than taken from
        // `expected()`: that one comes from the directory this test binary runs
        // from, which has no front end in it, and a test that depended on where
        // it was built would be a test of the build directory.
        let wanted = command_line_for(Path::new(r"C:\Program Files\WenleAV\wenle-gui.exe"));
        let moved = StartupStatus {
            command: Some(r#""D:\old\wenle-gui.exe" --minimized"#.to_owned()),
        };
        assert!(moved.is_installed());
        assert!(moved.differs_from(&wanted), "it is not this build's line");

        let current = StartupStatus {
            command: Some(wanted.clone()),
        };
        assert!(
            !current.differs_from(&wanted),
            "the entry this build would write is not a stale one"
        );
        assert!(
            !StartupStatus::default().differs_from(&wanted),
            "and an absent entry is not either"
        );
    }

    #[test]
    fn the_entry_launches_the_window_and_not_the_console() {
        // The defect this replaces, and it was live in this machine's registry:
        // a startup entry was registered from a build directory, where the
        // console sits alone, so it read `"...\wenle.exe" --minimized`. That
        // command line is refused —
        //
        //     error: unexpected argument '--minimized' found
        //
        // exit code 2, measured against the shipped `wenle.exe` — and Windows
        // starts a `Run` value with no console and reports nothing, so the entry
        // would have done nothing at every sign-in and said nothing about it.
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::write(dir.path().join(shell::GUI_EXE), b"not a real program")
            .expect("a stand-in for the front end");
        assert_eq!(
            program_in(dir.path()).expect("the front end is right there"),
            dir.path().join(shell::GUI_EXE)
        );

        // And the console beside it is not the answer, even though it is an
        // executable and even though a shell verb would take it.
        std::fs::write(dir.path().join(shell::CLI_EXE), b"not a real program")
            .expect("a stand-in for the console");
        assert_eq!(
            program_in(dir.path()).expect("the front end is still right there"),
            dir.path().join(shell::GUI_EXE),
            "the console is not a fallback for a tray entry"
        );
    }

    #[test]
    fn there_is_no_startup_entry_for_a_copy_with_no_window() {
        // The other half, and the one that keeps the entry from being written at
        // all: with no front end there is no notification area to wait in, so
        // the honest answer is a refusal naming the directory rather than a
        // registry value that runs the wrong program.
        let dir = tempfile::tempdir().expect("a directory");
        std::fs::write(dir.path().join(shell::CLI_EXE), b"not a real program")
            .expect("a stand-in for the console");

        match program_in(dir.path()) {
            Err(StartupError::NoFrontEnd { directory }) => assert_eq!(directory, dir.path()),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
