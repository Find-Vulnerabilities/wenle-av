//! Explorer's right-click "Scan with Wenle Antivirus" verbs.
//!
//! # What a user sees, and what makes it appear
//!
//! Right-click a file, a folder, the empty space inside a folder, or a drive, and
//! Windows offers a command. Those are four different registry keys, because
//! Explorer looks in four different places depending on what was clicked:
//!
//! | What was right-clicked | Key below the hive |
//! |---|---|
//! | a file, of any type | `Software\Classes\*\shell\WenleScan` |
//! | a folder | `Software\Classes\Directory\shell\WenleScan` |
//! | empty space inside a folder | `Software\Classes\Directory\Background\shell\WenleScan` |
//! | a drive | `Software\Classes\Drive\shell\WenleScan` |
//!
//! Each key's *default* value is the menu text, and each has a `command` subkey
//! whose default value is the command line. That is the whole mechanism: no COM
//! object, no shell extension DLL loaded into `explorer.exe`, no code of ours
//! running in another process. Windows reads four strings and runs a program.
//!
//! # Why the GUI is launched and not the scanner
//!
//! A verb is started by Explorer, which has no console. A console program
//! started that way gets a console window of its own, and the window closes the
//! instant the process exits — so `wenle.exe scan "%1"` on a small clean file
//! produces a window that appears and vanishes before the user has read a word
//! of it. On a malicious file it produces a window that vanishes along with the
//! only account of what was found.
//!
//! So the verb launches `wenle-gui.exe --scan "<path>"`, which keeps a window on
//! screen with the result in it. The scanner is the fallback, taken only when
//! there is no graphical front end beside this executable — a build tree, or a
//! stripped install. The fallback is real and its consequence is visible: the
//! user gets a console window that closes when the scan ends. That is said here
//! and in [`launch_program`]'s documentation rather than hidden, because it is
//! the kind of thing a user reports as "the button does nothing".
//!
//! # `%1` and `%V`
//!
//! A verb's command line gets a substitution, and which one is not a preference:
//!
//! * On a file, a folder or a drive, the clicked item is the *selected item*, and
//!   the substitution for it is **`%1`**.
//! * On a click into the empty space of a folder, there is no selected item —
//!   only the folder being viewed. `%1` is empty there, so a verb written with it
//!   would launch the scanner with no argument at all and scan nothing while
//!   looking like it worked. The substitution for the folder being viewed is
//!   **`%V`**, and it is why `Directory\Background` is a separate entry in the
//!   table above and not a fifth spelling of `%1`.
//!
//! A drive is a selected item like any other and takes `%1`; `%V` happens to
//! hold the same string there, which is a coincidence and not a reason to use it.
//!
//! # Quoting, and why every half of this is quoted
//!
//! Both the program path and the substitution are wrapped in double quotes:
//!
//! ```text
//! "C:\Program Files\WenleAV\wenle-gui.exe" --scan "%1"
//! ```
//!
//! `C:\Program Files\...` is an ordinary install location and is not a path
//! without spaces; and a filename with a space in it is not an exotic case but
//! `My Documents` and `New folder (2)`. Unquoted, Explorer's own command-line
//! parsing hands the program the first token and Windows offers to find an
//! application for the rest. There is no variant of this that omits the quotes.
//!
//! # Single selection, said honestly
//!
//! `MultiSelectModel` is set to `Single`. The alternative, `Player`, would let
//! Explorer invoke the verb once for a whole selection, and the command line
//! would receive **one** of the selected paths — `%1` is the first item, and the
//! others are not passed at all. A user who selected nine files and clicked the
//! verb would watch one of them being scanned and be told nothing about the
//! other eight. Restricting Explorer to a single selection at a time means the
//! verb is never offered for nine files in the first place, which is a menu item
//! that does less than it might rather than one that lies about what it did.
//!
//! # The two scopes, and which one to pick
//!
//! [`Scope::Machine`] writes under `HKEY_LOCAL_MACHINE` and gives the verb to
//! every account on the machine; it needs administrator rights. [`Scope::User`]
//! writes under `HKEY_CURRENT_USER` and gives it to the account that ran the
//! command; it needs none. [`default_scope`] picks between them by asking whether
//! this process is elevated, which is the only honest way to choose — an
//! unelevated process cannot write the machine's half at all, and an elevated
//! one that silently wrote only its own user's half would leave an administrator
//! who installed the product for a whole machine with a menu item only they can
//! see.
//!
//! Nothing falls back. `install(Scope::Machine)` from an unelevated process is
//! [`ShellError::NeedsElevation`], not a quiet write to `HKEY_CURRENT_USER`.
//!
//! # What is not touched
//!
//! The keys above, and nothing else. No key is read that this crate did not
//! write — except through the removal path, which deletes exactly the four paths
//! it creates and leaves whatever a user put beside them. The menu text, the icon
//! reference and the command line are all values of those keys, so a `remove`
//! takes all of it and `status` can account for all of it.

use std::path::{Path, PathBuf};

use av_core::AvError;

use crate::registry::{Hive, Key, RegistryError};

/// The menu text Explorer shows.
///
/// One string, here, and not spelled out at four call sites. It is the only part
/// of the registration a user sees, and a product whose four right-click entries
/// disagree about its own name looks like four products.
pub const MENU_TEXT: &str = "Scan with Wenle Antivirus";

/// The name of the verb key, and therefore the `Verb` Explorer reports.
///
/// Chosen to be specific to this product: `Software\Classes\*\shell` is shared
/// by every program on the machine, and a key called `Scan` would collide with
/// the next one to try it. It is also the string [`remove`] deletes and
/// [`status`] looks for, so it is a constant and not a literal repeated four
/// times.
pub const VERB_KEY: &str = "WenleScan";

/// The value Explorer reads an icon from.
const ICON_VALUE: &str = "Icon";

/// The value that decides whether the verb is offered for a multiple selection.
const MULTI_SELECT_VALUE: &str = "MultiSelectModel";

/// The value naming the subkey that holds the command line.
const COMMAND_SUBKEY: &str = "command";

/// The graphical front end, preferred for the reason the module documentation
/// gives.
pub const GUI_EXE: &str = "wenle-gui.exe";

/// The command-line front end, used when there is no graphical one.
pub const CLI_EXE: &str = "wenle.exe";

/// One of the four places Explorer looks for a verb.
///
/// An enum rather than four constants because the four differ in exactly three
/// ways — the key path, the substitution, and how a person describes what was
/// clicked — and a table with three columns is one thing to keep right where four
/// constants are four. Every one of those three is a method here, so a fifth
/// location would be a compile error at every `match` rather than a missing entry
/// in a list somebody has to remember to update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    /// A file of any type: `Software\Classes\*`.
    File,
    /// A folder: `Software\Classes\Directory`.
    Directory,
    /// The empty space inside a folder: `Software\Classes\Directory\Background`.
    DirectoryBackground,
    /// A drive: `Software\Classes\Drive`.
    Drive,
}

impl Location {
    /// All four, in the order a report should list them: the two a user meets
    /// most often first.
    ///
    /// Exhaustive by construction — the array's length is the lint that keeps a
    /// new variant from being added without being registered, which is the one
    /// failure mode of this feature that a user would notice and a test would
    /// not.
    pub const ALL: [Location; 4] = [
        Location::File,
        Location::Directory,
        Location::DirectoryBackground,
        Location::Drive,
    ];

    /// The key path below the hive that holds this verb.
    ///
    /// The same string under `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER`, which
    /// is not an accident: `HKEY_CURRENT_USER\Software\Classes` and
    /// `HKEY_LOCAL_MACHINE\Software\Classes` are the two halves that
    /// `HKEY_CLASSES_ROOT` merges, so a verb registered in either is found by the
    /// same lookup.
    pub fn key_path(self) -> &'static str {
        match self {
            Self::File => r"Software\Classes\*\shell\WenleScan",
            Self::Directory => r"Software\Classes\Directory\shell\WenleScan",
            Self::DirectoryBackground => r"Software\Classes\Directory\Background\shell\WenleScan",
            Self::Drive => r"Software\Classes\Drive\shell\WenleScan",
        }
    }

    /// The key path of the `command` subkey, which is where the command line is.
    ///
    /// Built from [`Self::key_path`] rather than written out a second time, so
    /// that the two cannot drift: a `command` subkey under a path the verb is not
    /// registered at is a registration that looks present in one report and
    /// absent in the other.
    pub fn command_key_path(self) -> String {
        format!("{}\\{COMMAND_SUBKEY}", self.key_path())
    }

    /// The substitution Explorer makes in this location's command line.
    ///
    /// `%1` where something is selected and `%V` where the folder being viewed is
    /// the only thing there is — see the module documentation for why the
    /// distinction is not cosmetic.
    pub fn substitution(self) -> &'static str {
        match self {
            Self::File | Self::Directory | Self::Drive => "%1",
            Self::DirectoryBackground => "%V",
        }
    }

    /// What was right-clicked, as a person would say it.
    ///
    /// Used in help text and in the status report, so that "not registered" lines
    /// up with something the user can go and try.
    pub fn describe(self) -> &'static str {
        match self {
            Self::File => "a file",
            Self::Directory => "a folder",
            Self::DirectoryBackground => "the empty space inside a folder",
            Self::Drive => "a drive",
        }
    }
}

/// Which half of the registry a registration goes into.
///
/// Two, and not three: [`Hive::ClassesRoot`] is a merge of the other two and
/// cannot be written to unambiguously — a write through it lands in the machine's
/// half when elevated and the user's half when not, which is precisely the silent
/// choice this enum exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `HKEY_LOCAL_MACHINE`. Every account on this machine sees the verb.
    /// Requires administrator rights.
    Machine,
    /// `HKEY_CURRENT_USER`. Only the account that ran the command sees it. No
    /// elevation.
    User,
}

impl Scope {
    /// The hive this scope writes to.
    pub fn hive(self) -> Hive {
        match self {
            Self::Machine => Hive::LocalMachine,
            Self::User => Hive::CurrentUser,
        }
    }

    /// The scope's name as a person writes it, for a report or a flag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::User => "user",
        }
    }

    /// What this scope means for who sees the menu item, in one sentence.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Machine => "every account on this machine",
            Self::User => "this account only",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What can go wrong registering or removing the shell verbs.
///
/// Wraps [`RegistryError`] rather than repeating it, and adds the three things
/// that are about the *registration* rather than about a registry call: the
/// caller asked for a scope this process cannot write, there is no executable to
/// point the verb at, or there is no registry on this platform.
#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// The caller asked for a scope that needs rights this process does not
    /// have.
    ///
    /// Deliberately not a fallback. A command that quietly wrote the user's half
    /// when asked for the machine's would report success on a machine where the
    /// verb is invisible to every other account — which is the failure the user
    /// would find last and be least able to explain.
    ///
    /// Worded about *changing* rather than about registering, because
    /// `ensure_writable` is on the removal path too and this sentence is what
    /// `remove --machine` prints when it is not elevated. An error that told
    /// someone running `remove` that "registering" was refused would be
    /// describing a command they did not type — and the first thing it would
    /// make them wonder is whether the tool had done the opposite of what they
    /// asked. The remedy names the flag rather than describing it, for the same
    /// reason: it is the thing they would type next.
    #[error(
        "changing the {scope}-wide Explorer verbs needs administrator rights, and this process \
         is not elevated; run the command from an elevated prompt, or pass --user to change this \
         account only"
    )]
    NeedsElevation {
        /// The scope that was asked for.
        scope: Scope,
    },

    /// The running executable could not be located.
    #[error("this executable's own path could not be determined: {detail}")]
    NoExecutable {
        /// What the operating system said.
        detail: String,
    },
}

impl From<ShellError> for AvError {
    /// The registry code survives; the rest becomes a sentence.
    ///
    /// The `NeedsElevation` case is the one worth reading twice: it becomes
    /// [`AvError::Other`] with the whole sentence, and not
    /// [`AvError::AccessDenied`], because it is not a denial the operating
    /// system issued — nothing was attempted — and a caller that saw
    /// `AccessDenied` would go looking for a failing call that does not exist.
    fn from(error: ShellError) -> Self {
        match error {
            ShellError::Registry(registry) => AvError::from(registry),
            other => AvError::Other(other.to_string()),
        }
    }
}

/// Whether this process is running elevated.
///
/// # How, and why not the other way
///
/// `GetTokenInformation` with `TokenElevation`, on this process's own token.
/// The alternative is `AllocateAndInitializeSid` for the Administrators group
/// followed by `CheckTokenMembership`, and it answers a *different* question:
/// membership in the group is still true for an administrator running under User
/// Account Control, whose token has the group present but deny-only. That is the
/// ordinary state of an administrator's desktop session, and the answer this
/// function has to give them is "no, you cannot write `HKEY_LOCAL_MACHINE` from
/// this prompt" — which is exactly what `TokenElevation` reports and what group
/// membership gets backwards.
///
/// A failure to read the token is reported as `false`. Everything this decision
/// feeds is a choice between two scopes, and of the two ways to be wrong,
/// refusing to attempt an unelevated write and telling the user to elevate is the
/// one they can act on; the alternative reports a permission error from deep
/// inside a registry call instead.
pub fn is_elevated() -> bool {
    platform::is_elevated()
}

/// The scope to use when the caller did not name one.
///
/// Machine when this process is elevated, the current user otherwise. See
/// [`is_elevated`] for why that is the whole of the question.
pub fn default_scope() -> Scope {
    if is_elevated() {
        Scope::Machine
    } else {
        Scope::User
    }
}

/// Whether a graphical front end ships beside this executable.
///
/// Exposed because it is the one fact that decides whether the registered
/// command line opens a window that stays on screen, and a caller that wants to
/// warn a user about the console-window fallback needs to be able to ask.
pub fn gui_is_available(exe_dir: &Path) -> bool {
    exe_dir.join(GUI_EXE).is_file()
}

/// The program a verb should launch, given where the product is installed.
///
/// The graphical front end when there is one, the command-line scanner when
/// there is not. The fallback is a real, visible difference and not a quiet
/// degradation: `wenle.exe` is a console program, Explorer gives it a console
/// window, and that window closes the moment the scan finishes — so a user who
/// right-clicks a clean file sees a flash and nothing else. It is still better
/// than registering nothing, which is why the fallback exists rather than being
/// refused; it is documented here so that nobody has to reproduce it to find out.
pub fn launch_program(exe_dir: &Path) -> PathBuf {
    if gui_is_available(exe_dir) {
        exe_dir.join(GUI_EXE)
    } else {
        exe_dir.join(CLI_EXE)
    }
}

/// The command line registered for `location`, launching `program`.
///
/// Pure: it formats and does not look at the filesystem, which is what makes it
/// testable without an installation to point at and without a registry to write
/// to. Which program goes in it is [`launch_program`]'s decision, taken
/// separately and for that reason.
///
/// The shape is `"<program>" <verb> "<substitution>"` — both halves quoted, for
/// the reason the module documentation gives. The whole thing is one quoted
/// argument and not a concatenation of four format calls: a reader can see the
/// quoting at a glance, and a caller cannot accidentally assemble the parts in a
/// different order.
pub fn command_line_for(program: &Path, location: Location) -> String {
    match program_verb(program) {
        ProgramVerb::Gui => format!(
            "\"{}\" --scan \"{}\"",
            program.display(),
            location.substitution()
        ),
        ProgramVerb::Cli => format!(
            "\"{}\" scan \"{}\"",
            program.display(),
            location.substitution()
        ),
    }
}

/// Which subcommand of the launched program this location's verb uses.
///
/// The two front ends do not share a spelling for "scan this": the command-line
/// tool has a `scan` subcommand and the graphical one has a `--scan` flag. The
/// difference is the launched program's, so it is decided from the program's file
/// name — the only thing available — and the two spellings are here, together,
/// where a change to either front end's interface is one edit away from the
/// command line that would have gone stale.
enum ProgramVerb {
    /// `wenle-gui.exe --scan "<path>"`.
    Gui,
    /// `wenle.exe scan "<path>"`.
    Cli,
}

/// Which subcommand spelling a program's file name calls for.
///
/// Decided from the file name, which is the only thing about the program this
/// function has and the only thing that distinguishes the two front ends. Case
/// is ignored because Windows file names are case-insensitive and a file system
/// that preserved `WENLE-GUI.EXE` would otherwise register a command line that
/// runs `wenle.exe`'s spelling against `wenle-gui.exe`.
///
/// Anything that is neither name is treated as the command-line tool. The
/// alternative — refusing an unrecognised name — would make [`command_line_for`]
/// fallible for a case that cannot arise from [`launch_program`] and would put an
/// error path in front of the one caller that has a path from somewhere else.
fn program_verb(program: &Path) -> ProgramVerb {
    match program.file_name().and_then(|name| name.to_str()) {
        Some(name) if name.eq_ignore_ascii_case(GUI_EXE) => ProgramVerb::Gui,
        _ => ProgramVerb::Cli,
    }
}

/// Register the four verbs in `scope`.
///
/// Idempotent: the underlying call creates a key that is missing and opens one
/// that is not, and every value is written outright rather than merged, so
/// running this twice leaves the same registry as running it once. That is the
/// property that makes it usable as a repair — an install interrupted between the
/// second and third key is fixed by running it again, which is the only recovery
/// a user should need.
///
/// The command line points at *this* executable's directory, taken from
/// `std::env::current_exe()`. A verb that named a path the product is not
/// installed at would be a menu item that fails when clicked, which is worse than
/// no menu item, so nothing here accepts a path from the caller — the only path
/// that can be right is the one this process is running from.
pub fn install(scope: Scope) -> Result<(), ShellError> {
    ensure_writable(scope)?;
    let exe_dir = executable_dir()?;
    let program = launch_program(&exe_dir);

    for location in Location::ALL {
        let key = Key::create(scope.hive(), location.key_path())?;
        // The default value is the menu text. Explorer reads it as the label,
        // and it is the only string here a user ever sees.
        key.set_string("", MENU_TEXT)?;
        // `,0` is the index into the executable's resources. Zero is the first
        // icon, which is the application icon every Windows binary carries;
        // omitting the index makes Explorer guess, and guessing sometimes means
        // the generic executable icon.
        key.set_string(ICON_VALUE, &format!("{},0", program.display()))?;
        // See the module documentation: one path arrives per invocation whatever
        // this is set to, so the honest setting is the one that stops Explorer
        // offering the verb for a selection it cannot pass whole.
        key.set_string(MULTI_SELECT_VALUE, "Single")?;

        let command = Key::create(scope.hive(), &location.command_key_path())?;
        command.set_string("", &command_line_for(&program, location))?;

        log::debug!(
            "registered {} for {} under {}",
            location.key_path(),
            location.describe(),
            scope.hive()
        );
    }

    log::info!(
        "registered the Explorer scan verbs for {} under {}",
        scope.describe(),
        scope.hive()
    );
    Ok(())
}

/// Remove the four verbs from `scope`.
///
/// Removes the whole key tree, so the menu text, the icon reference, the
/// multi-select setting and the command subkey all go together — there is no
/// state this crate creates that is not under a key this deletes.
///
/// A key that was never there is not an error, which is what makes `remove`
/// usable as the cleanup step of a failed install as well as the uninstall step
/// of a successful one.
pub fn remove(scope: Scope) -> Result<(), ShellError> {
    ensure_writable(scope)?;
    for location in Location::ALL {
        Key::delete_tree(scope.hive(), location.key_path())?;
    }
    log::info!(
        "removed the Explorer scan verbs for {} from {}",
        scope.describe(),
        scope.hive()
    );
    Ok(())
}

/// What is registered in `scope`, read back from the registry.
///
/// A status that cannot say what is registered is not a status, so this reports
/// three things per location rather than a boolean: whether the key is there,
/// the exact command line found in it, and the menu text. The command line is
/// returned verbatim and not re-derived from this process's own path, because the
/// question a status answers is "what will Explorer run when this is clicked",
/// and the answer to that is a string that was written by whichever version of
/// the product performed the install — possibly a different one, possibly in a
/// different directory, possibly not this product at all.
pub fn status(scope: Scope) -> Result<ShellStatus, ShellError> {
    let mut entries = Vec::with_capacity(Location::ALL.len());
    for location in Location::ALL {
        entries.push(VerbStatus {
            location,
            registration: read_registration(scope, location)?,
        });
    }
    Ok(ShellStatus { scope, entries })
}

/// What is under one location.
fn read_registration(scope: Scope, location: Location) -> Result<Registration, ShellError> {
    let Some(key) = Key::open(scope.hive(), location.key_path())? else {
        return Ok(Registration::Absent);
    };
    let menu_text = key.string("")?;
    let icon = key.string(ICON_VALUE)?;

    let Some(command_key) = Key::open(scope.hive(), &location.command_key_path())? else {
        return Ok(Registration::Incomplete {
            detail: format!("there is no `{COMMAND_SUBKEY}` subkey under the verb"),
        });
    };
    let command = match command_key.string("")? {
        // Not `Absent`: the key is there and an empty command line would be
        // launched as an empty command. That is a registration that is present
        // and broken, which is a different thing from one that is not there, and
        // a report that merged them would tell a user to install something that
        // is already installed.
        Some(command) if command.trim().is_empty() => {
            return Ok(Registration::Incomplete {
                detail: format!("the `{COMMAND_SUBKEY}` subkey has an empty command line"),
            })
        }
        Some(command) => command,
        None => {
            return Ok(Registration::Incomplete {
                detail: format!(
                    "the `{COMMAND_SUBKEY}` subkey has no default value, so there is no command \
                     line in it"
                ),
            })
        }
    };

    Ok(Registration::Present {
        command,
        menu_text,
        icon,
    })
}

/// What is registered in one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellStatus {
    scope: Scope,
    entries: Vec<VerbStatus>,
}

impl ShellStatus {
    /// The scope that was read.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// One entry per location, in [`Location::ALL`]'s order.
    pub fn entries(&self) -> &[VerbStatus] {
        &self.entries
    }

    /// How many locations have a usable command line.
    pub fn registered(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.registration.is_registered())
            .count()
    }

    /// True when all four locations are registered, which is what an `install`
    /// that ran to completion produces.
    ///
    /// The four-and-not-more test is deliberate: a machine with three of the four
    /// is a machine where the verb is missing from one kind of right-click and
    /// present on the others, which a user experiences as "it works on files but
    /// not on folders" and which no count of "1 or more" would report.
    pub fn is_complete(&self) -> bool {
        self.registered() == Location::ALL.len()
    }

    /// True when nothing at all is registered here.
    pub fn is_absent(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.registration == Registration::Absent)
    }
}

/// One location's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbStatus {
    /// Which right-click this is about.
    pub location: Location,
    /// What is there.
    pub registration: Registration,
}

/// What was found under one location.
///
/// Three states and not two. "Registered" and "not registered" would have to file
/// a key that exists with no command line under one of them, and both answers
/// would be wrong in a way a user notices: calling it registered promises a menu
/// item that does nothing when clicked, and calling it absent sends the user to
/// install something that is half there already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// No key at this location.
    Absent,
    /// A key with a command line under it.
    Present {
        /// The command line, verbatim as it is in the registry.
        command: String,
        /// The menu text, when the key has a default value.
        menu_text: Option<String>,
        /// The `Icon` value, when there is one.
        icon: Option<String>,
    },
    /// A key at this location with no usable command line under it.
    Incomplete {
        /// What is missing, as a sentence a report can print.
        detail: String,
    },
}

impl Registration {
    /// Whether clicking this location would launch something.
    pub fn is_registered(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// The command line, when there is one.
    pub fn command(&self) -> Option<&str> {
        match self {
            Self::Present { command, .. } => Some(command),
            _ => None,
        }
    }
}

/// Refuse a scope this process cannot write, before anything is attempted.
///
/// A pre-check rather than a translation of the failure afterwards, because the
/// two produce different sentences and only one of them tells the user what to
/// do. A registry write that fails with `ERROR_ACCESS_DENIED` says so about a
/// key; this says "run the command from an elevated prompt, or pass `--user` to
/// change this account only", which is the whole of the remedy.
///
/// It does not *replace* the check the operating system performs. An elevated
/// process can still be denied by an ACL, and that comes back as a
/// [`RegistryError`] with code 5, which is a fact about the machine rather than
/// about elevation and is reported as one.
fn ensure_writable(scope: Scope) -> Result<(), ShellError> {
    match scope {
        Scope::User => Ok(()),
        Scope::Machine if is_elevated() => Ok(()),
        Scope::Machine => Err(ShellError::NeedsElevation { scope }),
    }
}

/// The directory this executable runs from.
///
/// Crate-visible because it is the same question every registration in this
/// crate has to answer: the only program path that can be right is this
/// process's own, so `notifications` and `startup` ask it here rather than each
/// deriving it a second way.
pub(crate) fn executable_dir() -> Result<PathBuf, ShellError> {
    let exe = std::env::current_exe().map_err(|e| ShellError::NoExecutable {
        detail: e.to_string(),
    })?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ShellError::NoExecutable {
            detail: format!("{} has no parent directory", exe.display()),
        })
}

/// The parts that need the operating system.
#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// See [`super::is_elevated`] for why this is the question asked and not
    /// group membership.
    pub(super) fn is_elevated() -> bool {
        // SAFETY: `GetCurrentProcess` takes no arguments and returns a
        // pseudo-handle that must not be closed — which is why it is not passed
        // to `CloseHandle` below.
        let process = unsafe { GetCurrentProcess() };
        let mut token = HANDLE::default();
        // SAFETY: `process` is the current-process pseudo-handle, and `token` is
        // an out-parameter the API fills on success.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        // SAFETY: `elevation` is the structure `TokenElevation` documents, and
        // its size is what the call is told. `returned` is an out-parameter.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        // SAFETY: the handle came from `OpenProcessToken` above and has not been
        // closed; the token is not used after this point on either path.
        unsafe {
            let _ = CloseHandle(token);
        }

        read.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// No elevation to have, and nothing to register in.
#[cfg(not(windows))]
mod platform {
    /// Always false: there is no token elevation on a platform with no tokens,
    /// and every caller treats this as "cannot write the machine's half".
    pub(super) fn is_elevated() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An install directory with spaces in it, which is what a release build is
    /// unpacked into by default.
    fn program_dir_with_spaces() -> PathBuf {
        PathBuf::from(r"C:\Program Files\WenleAV")
    }

    #[test]
    fn every_location_has_its_own_key_and_no_two_share_one() {
        // Two locations sharing a key would register one verb twice and leave
        // another right-click with nothing, and the feature would look like it
        // worked on whichever one was tested by hand.
        let mut paths: Vec<&str> = Location::ALL.iter().map(|l| l.key_path()).collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), Location::ALL.len());

        assert_eq!(Location::File.key_path(), r"Software\Classes\*\shell\WenleScan");
        assert_eq!(
            Location::Directory.key_path(),
            r"Software\Classes\Directory\shell\WenleScan"
        );
        assert_eq!(
            Location::DirectoryBackground.key_path(),
            r"Software\Classes\Directory\Background\shell\WenleScan"
        );
        assert_eq!(
            Location::Drive.key_path(),
            r"Software\Classes\Drive\shell\WenleScan"
        );
    }

    #[test]
    fn the_folder_verb_and_the_background_verb_are_separate_keys() {
        // The relationship that makes these two entries and not one, and it is
        // easy to get backwards: `Directory\Background` is a *sibling* of
        // `Directory\shell` under `Directory`, not a child of `Directory\shell`.
        // A verb written under `Directory\shell\<verb>` — the shape the other
        // three locations have — is therefore never consulted for a click into a
        // folder's empty space, and Explorer would show nothing there with no
        // error anywhere to explain it.
        let directory = Location::Directory.key_path();
        let background = Location::DirectoryBackground.key_path();
        assert_ne!(directory, background);
        assert!(!background.starts_with(directory), "not a child of the verb key");
        assert!(!directory.starts_with(background), "and not the other way round");
        assert!(background.starts_with(r"Software\Classes\Directory\Background"));
        assert!(directory.starts_with(r"Software\Classes\Directory\shell"));
    }

    #[test]
    fn the_command_subkey_hangs_off_each_verb_key() {
        for location in Location::ALL {
            assert_eq!(
                location.command_key_path(),
                format!("{}\\command", location.key_path()),
                "for {}",
                location.describe()
            );
        }
        assert_eq!(
            Location::Drive.command_key_path(),
            r"Software\Classes\Drive\shell\WenleScan\command"
        );
    }

    #[test]
    fn the_background_location_substitutes_the_folder_and_the_others_the_selection() {
        // The whole reason `Directory\Background` is its own entry: `%1` is empty
        // on a background click, so a verb written with it launches the scanner
        // with no argument and looks like it worked.
        assert_eq!(Location::DirectoryBackground.substitution(), "%V");
        for location in [Location::File, Location::Directory, Location::Drive] {
            assert_eq!(location.substitution(), "%1", "for {}", location.describe());
        }
    }

    #[test]
    fn every_location_describes_itself_differently() {
        let mut said: Vec<&str> = Location::ALL.iter().map(|l| l.describe()).collect();
        said.sort_unstable();
        said.dedup();
        assert_eq!(said.len(), Location::ALL.len());
    }

    #[test]
    fn a_file_verb_quotes_both_halves_of_its_command_line() {
        let command = command_line_for(&program_dir_with_spaces().join(GUI_EXE), Location::File);
        assert_eq!(
            command,
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --scan "%1""#
        );
    }

    #[test]
    fn each_location_gets_its_own_command_line() {
        let program = program_dir_with_spaces().join(GUI_EXE);
        assert_eq!(
            command_line_for(&program, Location::Directory),
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --scan "%1""#
        );
        assert_eq!(
            command_line_for(&program, Location::DirectoryBackground),
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --scan "%V""#
        );
        assert_eq!(
            command_line_for(&program, Location::Drive),
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --scan "%1""#
        );
    }

    #[test]
    fn a_trailing_backslash_on_the_install_directory_does_not_double() {
        // `launch_program` is `exe_dir.join(name)`, and a join onto a path that
        // already ends in a separator is where a doubled backslash would come
        // from. `\\` inside a quoted argument is still one separator to Explorer,
        // so the bug would not break the verb — it would just make the registered
        // path wrong in a way that only shows up when it is compared against a
        // real one, which is what `status` does.
        let with_slash = Path::new(r"C:\Program Files\WenleAV\");
        let without = Path::new(r"C:\Program Files\WenleAV");
        assert_eq!(
            command_line_for(&with_slash.join(GUI_EXE), Location::File),
            command_line_for(&without.join(GUI_EXE), Location::File),
        );
        assert_eq!(
            command_line_for(&with_slash.join(GUI_EXE), Location::File),
            r#""C:\Program Files\WenleAV\wenle-gui.exe" --scan "%1""#
        );
    }

    #[test]
    fn the_command_line_is_quoted_even_with_no_spaces_in_it() {
        // Not a redundant pair of quotes: `C:\wenle\wenle-gui.exe` needs no
        // quoting, and a build that emitted them only when the path contained a
        // space would be a build whose registered command line differs by
        // installation directory. One shape, always.
        assert_eq!(
            command_line_for(Path::new(r"C:\wenle\wenle-gui.exe"), Location::File),
            r#""C:\wenle\wenle-gui.exe" --scan "%1""#
        );
    }

    #[test]
    fn a_filename_with_a_space_stays_one_argument() {
        // The user's half of the same problem. `%1` is substituted by Explorer
        // with the path of whatever was clicked, and the quotes are what keep
        // `New folder (2)` from becoming two arguments.
        let command = command_line_for(Path::new(r"C:\wenle\wenle-gui.exe"), Location::Directory);
        assert!(command.ends_with(r#" --scan "%1""#), "{command}");
        assert_eq!(command.matches('"').count(), 4, "{command}");
    }

    #[test]
    fn the_fallback_program_is_the_scanner_and_the_preferred_one_is_the_window() {
        // A real temporary directory, because `gui_is_available` asks the
        // filesystem — and the filesystem is not the registry, so this may run
        // under `cargo test`.
        let dir = tempfile::tempdir().expect("a temporary directory");

        assert!(!gui_is_available(dir.path()));
        assert_eq!(launch_program(dir.path()), dir.path().join(CLI_EXE));
        assert_eq!(
            command_line_for(&launch_program(dir.path()), Location::File),
            format!(r#""{}\wenle.exe" scan "%1""#, dir.path().display())
        );

        std::fs::write(dir.path().join(GUI_EXE), b"stub").expect("writing the stub");
        assert!(gui_is_available(dir.path()));
        assert_eq!(launch_program(dir.path()), dir.path().join(GUI_EXE));
        assert_eq!(
            command_line_for(&launch_program(dir.path()), Location::File),
            format!(r#""{}\wenle-gui.exe" --scan "%1""#, dir.path().display())
        );
    }

    #[test]
    fn the_two_scopes_write_to_the_two_halves_of_classes_root() {
        assert_eq!(Scope::Machine.hive(), Hive::LocalMachine);
        assert_eq!(Scope::User.hive(), Hive::CurrentUser);
        // Neither may be the merged view: a write through it lands in whichever
        // half the token allows, which is the silent choice `Scope` exists to
        // prevent.
        for scope in [Scope::Machine, Scope::User] {
            assert_ne!(scope.hive(), Hive::ClassesRoot);
        }
    }

    #[test]
    fn the_default_scope_is_the_one_this_process_can_actually_write() {
        // The property, not the machine: an unelevated process must not be told
        // to write `HKEY_LOCAL_MACHINE`, and an elevated one must not silently
        // register for one account when the caller installed for the machine.
        let expected = if is_elevated() {
            Scope::Machine
        } else {
            Scope::User
        };
        assert_eq!(default_scope(), expected);
    }

    #[test]
    fn an_unelevated_request_for_the_machine_half_is_refused_by_name() {
        // Only assertable when this test process is not elevated, which is how
        // `cargo test` is normally run. When it is elevated the guard is not
        // reached at all, and asserting the refusal then would be asserting
        // something about the developer's prompt rather than about the code.
        if is_elevated() {
            assert!(ensure_writable(Scope::Machine).is_ok());
            assert!(ensure_writable(Scope::User).is_ok());
            return;
        }
        let error = ensure_writable(Scope::Machine).expect_err("must be refused");
        assert!(matches!(error, ShellError::NeedsElevation { .. }));
        let sentence = error.to_string();
        assert!(sentence.contains("administrator"), "{sentence}");
        // And the remedy, which is the only reason the sentence is worth
        // printing rather than a bare code.
        assert!(sentence.contains("elevated prompt"), "{sentence}");
        // And it names the flag rather than describing it, because the flag is
        // what the person reading it types next.
        assert!(sentence.contains("--user"), "{sentence}");
        // The sentence has to fit both commands that can produce it. `remove` is
        // guarded by the same function, and being told that *registering* was
        // refused when you asked for a removal leaves you unsure whether the tool
        // just did the opposite of what you typed.
        assert!(
            !sentence.contains("registering"),
            "the refusal must not name one verb: {sentence}"
        );
        // The user half is always allowed.
        assert!(ensure_writable(Scope::User).is_ok());
    }

    #[test]
    fn a_scope_and_a_location_both_read_as_english() {
        assert_eq!(Scope::Machine.as_str(), "machine");
        assert_eq!(Scope::Machine.to_string(), "machine");
        assert!(Scope::Machine.describe().contains("machine"));
        assert!(Scope::User.describe().contains("account"));
    }

    #[test]
    fn a_registration_that_is_not_present_has_no_command_line() {
        // The three states have to be distinguishable by a caller that only has
        // the value, because that is how the command line decides what to print.
        let absent = Registration::Absent;
        assert!(!absent.is_registered());
        assert_eq!(absent.command(), None);

        let incomplete = Registration::Incomplete {
            detail: "the `command` subkey has an empty command line".to_string(),
        };
        assert!(!incomplete.is_registered());
        assert_eq!(incomplete.command(), None);

        let present = Registration::Present {
            command: r#""C:\wenle\wenle-gui.exe" --scan "%1""#.to_string(),
            menu_text: Some(MENU_TEXT.to_string()),
            icon: Some(r"C:\wenle\wenle-gui.exe,0".to_string()),
        };
        assert!(present.is_registered());
        assert!(present.command().is_some_and(|c| c.contains("--scan")));
    }

    #[test]
    fn the_menu_text_names_the_product_and_the_verb() {
        // What the user sees, and the only string here they ever read. Asserted
        // so that a rename is a deliberate edit rather than something that
        // happens to one of the four locations.
        assert_eq!(MENU_TEXT, "Scan with Wenle Antivirus");
        assert!(MENU_TEXT.starts_with("Scan"));
        // The verb key is product-specific: `Software\Classes\*\shell` is shared
        // with every other program on the machine.
        assert!(VERB_KEY.starts_with("Wenle"));
        for location in Location::ALL {
            assert!(location.key_path().ends_with(VERB_KEY), "{location:?}");
        }
    }

    #[test]
    fn a_status_of_nothing_is_absent_and_a_full_one_is_complete() {
        let absent = ShellStatus {
            scope: Scope::User,
            entries: Location::ALL
                .iter()
                .map(|&location| VerbStatus {
                    location,
                    registration: Registration::Absent,
                })
                .collect(),
        };
        assert!(absent.is_absent());
        assert_eq!(absent.registered(), 0);
        assert!(!absent.is_complete());

        let present = |location| VerbStatus {
            location,
            registration: Registration::Present {
                command: "x".to_string(),
                menu_text: None,
                icon: None,
            },
        };
        let three = ShellStatus {
            scope: Scope::User,
            entries: [
                present(Location::File),
                present(Location::Directory),
                present(Location::DirectoryBackground),
                VerbStatus {
                    location: Location::Drive,
                    registration: Registration::Absent,
                },
            ]
            .into_iter()
            .collect(),
        };
        // Three of four is not complete, and that is the point: the user whose
        // drive right-click does nothing is the one this catches.
        assert_eq!(three.registered(), 3);
        assert!(!three.is_complete());
        assert!(!three.is_absent());
    }
}
