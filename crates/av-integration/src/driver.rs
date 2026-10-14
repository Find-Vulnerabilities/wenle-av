//! Installing the kernel driver, and reading back what the machine holds.
//!
//! # What this module is for
//!
//! `crates/av-driver` builds a real x86_64 kernel driver — a minifilter that
//! intercepts file operations and a filter communication port that asks this
//! product what to do about them. Until this module existed, nothing in the
//! workspace put it on a machine. The artifact compiled, `cargo build` produced
//! it, and no command anywhere copied it, registered it, or could say whether it
//! was running, which made everything the driver does a claim about a bench
//! rather than a feature of the product.
//!
//! This is the other half: two commands that change the machine, and one that
//! reports what they changed.
//!
//! # What installing it changes on the machine, and how to undo it
//!
//! Written out in full, because a kernel driver is the largest thing this
//! product does to a machine and because every other machine-changing module in
//! this crate makes the same promise: the change and its undo are documented
//! together, in the place the change is made.
//!
//! | What | Where | Undone by |
//! |---|---|---|
//! | the driver image | `%SystemRoot%\System32\drivers\WenleAvFilter.sys` | [`remove`], which deletes it |
//! | the service's key | `HKLM\SYSTEM\CurrentControlSet\Services\WenleAvFilter` | [`remove`], which deletes it whole |
//! | its values | `Type`, `Start`, `ErrorControl`, `Group`, `DependOnService`, `ImagePath` | with the key |
//! | the instance | `...\WenleAvFilter\Instances\WenleAvFilter Instance` | with the key |
//!
//! There is no hidden fifth thing. No file is left behind, no other service key
//! is touched, and no key this module did not create is read for anything but
//! reporting. [`remove`] deletes a key that was never created without complaint,
//! so it can always be run — including on a machine where [`install`] stopped
//! halfway, which is exactly when somebody runs it.
//!
//! **A filter that is already loaded stays loaded until the machine restarts.**
//! Deleting the service key stops it being loaded *next* time; it does not unload
//! it now, and nothing this module does can. `fltmc unload WenleAvFilter` does
//! that, and this module does not run it for you: unloading a filesystem filter
//! while other operations are in flight through it is a decision about those
//! operations, and it belongs to the person at the keyboard who can see what is
//! running. [`remove`] says so in its return value's documentation and the
//! command prints it.
//!
//! # One list, written and read
//!
//! `plan` is the whole registration as data: three keys, and the values each
//! must hold. [`install`] walks it writing, [`status`] walks the *same* list
//! reading, and the comparison in [`DriverStatus`] is therefore between what was
//! written and what is there, with no second list to keep in step. A registration
//! whose install path and check path were written separately is one where the
//! check reports a healthy machine as broken after somebody edits one of them,
//! and this is the cheapest possible way to not have that.
//!
//! # Why `Start` is 0 and `ErrorControl` is 1
//!
//! These two numbers decide what happens on a machine where the driver is wrong,
//! which is the only interesting case.
//!
//! `Start = 0` (`SERVICE_BOOT_START`) is not an optimisation. A filesystem
//! filter that loads late is a filter that was not watching while everything
//! before it started, and the point of this driver is to be present before
//! anything can be written. It is also why `ImagePath` is a `\SystemRoot\` path
//! and not a drive-letter path: at boot there is no `C:` yet for the loader to
//! resolve, and `\SystemRoot\` is a name it resolves itself.
//!
//! `ErrorControl = 1` (`SERVICE_ERROR_NORMAL`) is the opposite decision, and it
//! is deliberate. The value that would make a driver load failure stop the boot
//! is 3 (`SERVICE_ERROR_CRITICAL`), and a security product that refuses to let a
//! machine start because its own driver did not load is a security product that
//! has become the outage. With `1`, a driver that fails to load is logged by the
//! SCM and the machine continues without it. That is the honest failure: the
//! product is not protecting anything at that moment, and the machine still
//! works, which is what its owner needs at 3 a.m.
//!
//! # What is not checked here, and why
//!
//! **The signature.** A kernel driver must be signed by a key Windows trusts, or
//! the machine must have test-signing on. This module does not check that, and
//! the reason is not that it is unimportant: it is that the loader already
//! checks it, on every load, with the machine's own policy — the same policy that
//! knows about the test-signing flag, the Secure Boot state and the trust store.
//! A second opinion computed here from a file on disk would be a second
//! implementation of that policy, and the only thing it could add is a
//! disagreement. What this module checks is the part the loader will *not* tell
//! you about: a file that is not a native x86_64 image at all, which the SCM
//! accepts, creates a service for, starts, and which stops immediately with an
//! error naming neither the file nor the reason.
//!
//! **Whether the machine will accept the altitude.** [`av_driver_proto::install`]
//! documents that ours is not allocated by Microsoft. Two antivirus products
//! whose filters claim the same altitude in the same load order group produce a
//! filter manager that refuses to load the second one, and the only way to know
//! is to try. [`status`] reports what is registered so that the number is visible
//! rather than buried.

use std::path::{Path, PathBuf};

use av_core::AvError;
use av_driver_proto::install as id;

use crate::registry::{Hive, Key, RegistryError};

// -- the values that decide how the driver loads ------------------------------

/// `SERVICE_FILE_SYSTEM_DRIVER`.
///
/// Not `SERVICE_KERNEL_DRIVER` (1), which is a driver with no filesystem role,
/// and not the `SERVICE_FILE_SYSTEM_DRIVER` value *plus* the `0x100` interactive
/// bit that some drivers set. A minifilter registers with the filter manager,
/// and that is what this type says.
pub const TYPE_FILE_SYSTEM_DRIVER: u32 = 2;

/// `SERVICE_BOOT_START`. See the module documentation for why this is not a
/// preference.
pub const START_BOOT: u32 = 0;

/// `SERVICE_ERROR_NORMAL`. See the module documentation: this is the value that
/// makes a driver failure an event in the log rather than a machine that will not
/// boot.
pub const ERROR_NORMAL: u32 = 1;

/// `IMAGE_FILE_MACHINE_AMD64` — the only architecture `av-driver` is built for.
///
/// Written as the number rather than taken from `av-pe`, which reports the field
/// but does not name its values: nothing in the parser branches on the machine,
/// so a table of machine constants there would be a table nothing reads. The
/// check that uses this is here, where the branch is.
pub const MACHINE_AMD64: u32 = 0x8664;

/// `IMAGE_SUBSYSTEM_NATIVE`.
///
/// The field that says "the kernel loads this", as opposed to 2 (a Windows
/// application) or 3 (a console application). It is the single most useful thing
/// to look at when somebody has pointed this command at the wrong file.
pub const SUBSYSTEM_NATIVE: u32 = 1;

/// The instance's `Flags` value.
///
/// Zero, which is the value that asks the filter manager to attach this instance
/// to each volume as the volume is mounted. The bits of this field select
/// between that and a driver attaching volumes itself, and `av-driver` does no
/// attaching of its own — it registers an instance-setup callback, which is the
/// filter manager *asking* it about a volume, and never calls `FltAttachVolume`.
/// So zero is not a default chosen for looking conventional; a non-zero value
/// would describe behaviour the driver does not have.
const INSTANCE_FLAGS: u32 = 0;

// -- errors -------------------------------------------------------------------

/// A failure from installing, removing, or asking about the driver.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// Registering a boot-start kernel driver is a change to the machine.
    ///
    /// The same message shape as the other machine-changing modules in this
    /// crate, and worded about *changing* rather than about installing, because
    /// [`remove`] raises it too and a user running `remove` should not be told
    /// that an install was refused.
    #[error(
        "installing a kernel driver changes the whole machine, which needs administrator rights, \
         and this process is not elevated; run the command from an elevated prompt"
    )]
    NeedsElevation,

    /// `%SystemRoot%` is not set, so there is nowhere to install to.
    ///
    /// Not defaulted to `C:\Windows`. A process whose environment has no
    /// `SystemRoot` is a process whose notion of where Windows lives would be a
    /// guess, and guessing wrong here means writing a driver image into a
    /// directory the loader never reads — a successful install that does nothing.
    #[error(
        "the environment does not say where Windows is installed (%SystemRoot% is unset or \
         empty), so there is no directory to install the driver into; this is not a guess the \
         installer is willing to make"
    )]
    NoSystemRoot,

    /// This executable's own directory could not be determined.
    #[error("this executable's own path could not be determined: {detail}")]
    NoExecutable {
        /// What the operating system said.
        detail: String,
    },

    /// There is no driver image anywhere this process knows to look.
    ///
    /// A hard refusal. A registration naming a file that is not there is a
    /// service the SCM creates, starts and stops, and the error a user sees
    /// names neither the file nor this command.
    #[error(
        "there is no {name} or {built} in {searched}, so there is nothing to install and nothing \
         was written. An installed product keeps the first of those names beside this executable; \
         the second is what the driver's own workspace writes, and that workspace is \
         `crates/av-driver` — build it with `cargo build` there, or copy the file beside this one",
        name = id::FILE_NAME,
        built = id::BUILD_OUTPUT_NAME,
        searched = searched_list(.searched)
    )]
    SourceMissing {
        /// Every directory that was searched, in the order they were tried.
        searched: Vec<PathBuf>,
    },

    /// The image could not be read.
    #[error("could not read {path}: {detail}", path = .path.display())]
    SourceUnreadable {
        /// The file that could not be read.
        path: PathBuf,
        /// What the operating system said.
        detail: String,
    },

    /// The image is not something the kernel will load.
    ///
    /// The whole reason this module looks inside the file: see [`ImageFault`].
    #[error("{} is not a driver image: {fault}", .path.display())]
    NotADriver {
        /// The file that was refused.
        path: PathBuf,
        /// What was wrong with it.
        fault: ImageFault,
    },

    /// The image could not be copied into `System32\drivers`.
    #[error(
        "could not copy the driver to {path}: {detail}. Nothing was registered, so there is \
         nothing to undo",
        path = .path.display()
    )]
    CopyFailed {
        /// Where the copy was going.
        path: PathBuf,
        /// What the operating system said.
        detail: String,
    },
}

/// Every directory [`product_driver`] tried, as one line.
///
/// A `Vec` field rather than a single `PathBuf` because a driver image
/// legitimately lives in more than one place, and an error that names only the
/// first sends a user to look in the wrong one — and then to *copy* the file
/// there, which is how a stale driver gets registered.
///
/// A free function rather than a method on [`DriverError`] because thiserror
/// rewrites `.field` in a format string into `self.field` but does not rewrite a
/// call: a method here would compile as a call to a function named
/// `searched_list` that takes no arguments and is not in scope.
fn searched_list(searched: &[PathBuf]) -> String {
    searched
        .iter()
        .map(|directory| directory.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl From<DriverError> for AvError {
    /// The registry code survives; the rest becomes a sentence.
    ///
    /// [`DriverError::NeedsElevation`] is [`AvError::Other`] and not
    /// [`AvError::AccessDenied`], for the reason the other modules in this crate
    /// give: nothing was attempted, so there is no failing call for a caller to
    /// go looking for.
    fn from(error: DriverError) -> Self {
        match error {
            DriverError::Registry(registry) => AvError::from(registry),
            other => AvError::Other(other.to_string()),
        }
    }
}

/// What is wrong with a file that is not a driver.
///
/// Separate from [`DriverError`] because it is a fact about *bytes*, decided by a
/// pure function over a byte slice, and therefore testable without a machine that
/// has a driver on it. [`DriverError::NotADriver`] is that fact attached to the
/// path it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFault {
    /// `av-pe` refused the file: it is not a PE image, or it is a truncated one.
    Malformed {
        /// What the parser said. Passed through rather than paraphrased: it
        /// names the field and the offset, which is what a person needs to hear
        /// when they have pointed this command at a zip file.
        detail: String,
    },

    /// The file is built for a different architecture.
    ///
    /// The kernel loads images for the machine it is running on and no others,
    /// and the failure when it does not is the same silent one this check exists
    /// to move earlier.
    WrongMachine {
        /// The `IMAGE_FILE_MACHINE_*` value found.
        machine: u32,
    },

    /// The file is a user-mode image.
    ///
    /// A DLL is the file somebody actually points at by mistake — the build
    /// output for this product is named `av_driver.dll` — and this is the message
    /// that says so.
    NotNative {
        /// The `IMAGE_SUBSYSTEM_*` value found.
        subsystem: u32,
    },
}

impl std::fmt::Display for ImageFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { detail } => write!(f, "it is not a readable PE image ({detail})"),
            Self::WrongMachine { machine } => write!(
                f,
                "it is built for machine type 0x{machine:04X} and this product's driver is \
                 x86_64 (0x{MACHINE_AMD64:04X})"
            ),
            Self::NotNative { subsystem } => write!(
                f,
                "its subsystem is {subsystem} and a kernel driver's is {SUBSYSTEM_NATIVE} \
                 (native). Subsystem 2 is a Windows application and 3 is a console one; the \
                 kernel loads this file into ring 0, and what it does with a user-mode image is \
                 create the service, start it, and watch it stop immediately with an error that \
                 names neither the file nor the reason"
            ),
        }
    }
}

/// Whether these bytes are a driver the kernel will accept.
///
/// The three questions, in the order that produces the most useful message:
/// whether it is a PE at all, whether it is a *driver*, and whether it is this
/// machine's kind of driver. Subsystem before machine deliberately — a 32-bit
/// DLL fails both, and the subsystem is what tells the user they pointed at the
/// wrong file, where the machine type would send them looking for a build
/// problem they do not have.
///
/// # Errors
///
/// An [`ImageFault`] naming which of the three it was.
pub fn check_driver_image(bytes: &[u8]) -> Result<(), ImageFault> {
    let pe = av_pe::PeFile::parse(bytes).map_err(|error| ImageFault::Malformed {
        detail: error.to_string(),
    })?;

    if pe.subsystem() != SUBSYSTEM_NATIVE {
        return Err(ImageFault::NotNative {
            subsystem: pe.subsystem(),
        });
    }
    if pe.machine() != MACHINE_AMD64 {
        return Err(ImageFault::WrongMachine {
            machine: pe.machine(),
        });
    }
    Ok(())
}

// -- where the driver lives ---------------------------------------------------

/// `%SystemRoot%`, as the environment reports it.
///
/// # Errors
///
/// [`DriverError::NoSystemRoot`] when the variable is unset or empty. See that
/// variant for why this is not defaulted.
pub fn system_root() -> Result<PathBuf, DriverError> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| !root.as_os_str().is_empty())
        .ok_or(DriverError::NoSystemRoot)
}

/// Where the driver image goes, on a machine whose Windows is at `system_root`.
///
/// Pure arithmetic over the two constants, so a test can check the path without a
/// machine that has a driver on it — and so the answer does not depend on the
/// drive letter Windows happens to be installed on.
#[must_use]
pub fn installed_image(system_root: &Path) -> PathBuf {
    // `DEVICE_SUBDIR` is spelled with a backslash because it is a Windows fact
    // written into the registry, and `Path::join` on Windows accepts it. It is
    // joined rather than concatenated so that the separator between the root and
    // the subdirectory is the platform's own.
    system_root.join(id::DEVICE_SUBDIR).join(id::FILE_NAME)
}

/// The `ImagePath` the service key must hold.
///
/// `\SystemRoot\System32\drivers\WenleAvFilter.sys`, and the leading
/// `\SystemRoot\` is the load-bearing part. `Start = 0` means the loader reads
/// this before the drive letters exist, so a path beginning `C:\` is one the
/// loader cannot resolve at the moment it needs to — and the symptom on a machine
/// that has one is a boot-start driver that mysteriously does not start.
/// `\SystemRoot\` is a name the loader resolves itself, which is why every
/// boot-start driver uses it.
///
/// Built from the same two constants as [`installed_image`], so the path in the
/// registry and the path on disk cannot disagree.
#[must_use]
pub fn image_path() -> String {
    format!(r"\SystemRoot\{}\{}", id::DEVICE_SUBDIR, id::FILE_NAME)
}

/// The service's key path, under `HKEY_LOCAL_MACHINE`.
#[must_use]
pub fn service_key() -> String {
    format!(r"SYSTEM\CurrentControlSet\Services\{}", id::SERVICE_NAME)
}

/// The driver image in `directory`, if there is one.
///
/// # Why this is not a parameter on the command line
///
/// [`crate::amsi::product_dll`] gives the argument for its own case and it holds
/// here: the only path that can be right is one this process can find for
/// itself. A caller-supplied path lets a mistyped command register a driver that
/// is not this product's, and the resulting failure is silent — the loader
/// neither names the file nor says why it refused it.
///
/// # Why two names are searched
///
/// [`id::FILE_NAME`] is the installed name and [`id::BUILD_OUTPUT_NAME`] is what
/// cargo writes before packaging renames it. The first is what a product
/// installs; the second is what a workspace builds. Searching only for the first
/// would make this command refuse to run in the one place a developer tries it,
/// and searching only for the second would make it refuse in the one place it
/// matters.
#[must_use]
pub fn find_driver(directory: &Path) -> Option<PathBuf> {
    [id::FILE_NAME, id::BUILD_OUTPUT_NAME]
        .iter()
        .map(|name| directory.join(name))
        .find(|candidate| candidate.is_file())
}

/// Where the driver's own workspace puts its output, under a checkout root.
///
/// # Why the driver is not beside `wenle.exe`
///
/// It is a separate cargo workspace — `crates/av-driver/Cargo.toml`, with its
/// own `Cargo.lock` and its own `target` — because it needs the WDK and a
/// nightly toolchain, and neither may be a requirement of building the rest of
/// the product. A separate workspace means a separate target directory, so the
/// file is at `crates/av-driver/target/<triple>/<profile>/av_driver.dll` rather
/// than at `target/<profile>/` beside the executable.
///
/// # Why these four and not a search
///
/// Four fixed candidates, tried in order, rather than a walk of the whole tree:
/// a walk would find a stale build from a branch that was thrown away, and
/// installing *that* into the kernel is the one mistake this module exists to
/// prevent. Release before debug, because a copy of the product running from a
/// release tree should register the release driver.
///
/// The triple-qualified pair comes first because `-Z build-std` — which the
/// driver's own build uses — always writes there, and the unqualified pair
/// covers a build that did not.
const CHECKOUT_PLACES: [&str; 4] = [
    "crates/av-driver/target/x86_64-pc-windows-msvc/release",
    "crates/av-driver/target/x86_64-pc-windows-msvc/debug",
    "crates/av-driver/target/release",
    "crates/av-driver/target/debug",
];

/// The root of the checkout this executable is running from, if it is.
///
/// # Why the shape is checked rather than assumed
///
/// Walking two levels up from any executable would, in an installed product,
/// have this module looking for `C:\crates\...` beside `C:\Program Files`. The
/// check is exact: cargo puts a profile's output in a directory named `debug` or
/// `release` directly under one named `target`, and when that is not the shape,
/// this process was not run out of a checkout and there is nothing above it to
/// look in.
fn checkout_root(exe_dir: &Path) -> Option<&Path> {
    let profile = exe_dir.file_name()?;
    if profile != "debug" && profile != "release" {
        return None;
    }
    let target = exe_dir.parent()?;
    if target.file_name()? != "target" {
        return None;
    }
    target.parent()
}

/// [`find_driver`], everywhere this process can look for one.
///
/// Beside the executable first, because that is the deployment contract and the
/// only place an installed product keeps it. Then, when this executable is
/// running out of a cargo checkout, the driver's own workspace output.
///
/// # Errors
///
/// [`DriverError::NoExecutable`] when this process's own path cannot be
/// determined, and [`DriverError::SourceMissing`] when neither name is in any of
/// the directories searched — the variant carries the whole list, because an
/// error naming one directory sends a user to look in the wrong one.
pub fn product_driver() -> Result<PathBuf, DriverError> {
    let exe = std::env::current_exe().map_err(|error| DriverError::NoExecutable {
        detail: error.to_string(),
    })?;
    let directory = exe.parent().ok_or_else(|| DriverError::NoExecutable {
        detail: format!("{} has no parent directory", exe.display()),
    })?;

    let mut searched = vec![directory.to_path_buf()];
    if let Some(root) = checkout_root(directory) {
        searched.extend(CHECKOUT_PLACES.iter().map(|place| root.join(place)));
    }

    searched
        .iter()
        .find_map(|place| find_driver(place))
        .ok_or(DriverError::SourceMissing { searched })
}

// -- the registration, as data -------------------------------------------------

/// A registry value, in the type it has to be written as.
///
/// Owning its strings rather than borrowing them, because one of the six values
/// is [`image_path`]'s and is not a constant. The other five are, and paying a
/// `String` each for them is what lets one type — and therefore one comparison —
/// cover all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// `REG_SZ`.
    Str(String),
    /// `REG_MULTI_SZ`.
    Multi(Vec<String>),
    /// `REG_DWORD`.
    Dword(u32),
}

impl Value {
    /// The value as a person reads it, for a report.
    fn render(&self) -> String {
        match self {
            Self::Str(text) => text.clone(),
            Self::Multi(items) => items.join(", "),
            Self::Dword(number) => number.to_string(),
        }
    }

    /// Write this value under `name`.
    fn write(&self, key: &Key, name: &str) -> Result<(), RegistryError> {
        match self {
            Self::Str(text) => key.set_string(name, text),
            Self::Multi(items) => {
                let borrowed: Vec<&str> = items.iter().map(String::as_str).collect();
                key.set_multi_string(name, &borrowed)
            }
            Self::Dword(number) => key.set_dword(name, *number),
        }
    }

    /// Read the value under `name`, as the type this one was written as.
    ///
    /// The accessor is chosen by the *expected* type and not by what is in the
    /// registry, which is what makes a value somebody changed from `REG_DWORD` to
    /// `REG_SZ` come back as [`RegistryError::Type`] rather than silently
    /// comparing equal to its own rendering. `None` means the value is absent,
    /// which is a different finding from a value that differs.
    fn read(&self, key: &Key, name: &str) -> Result<Option<String>, RegistryError> {
        match self {
            Self::Str(_) => key.string(name),
            Self::Multi(_) => Ok(key.multi_string(name)?.map(|items| items.join(", "))),
            Self::Dword(_) => Ok(key.dword(name)?.map(|number| number.to_string())),
        }
    }
}

/// One key of the registration and the values it has to hold.
///
/// `key` is a full path under `HKEY_LOCAL_MACHINE` rather than a suffix, because
/// it is what a report has to print: the value that is wrong is only actionable
/// if the line naming it says which key to look in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    key: String,
    values: Vec<(&'static str, Value)>,
}

/// The whole registration, in the order it is written.
///
/// Three keys. The service key describes a boot-start file system driver that
/// belongs behind the filter manager; `Instances` names which instance the filter
/// manager should use; and the instance itself carries the altitude that decides
/// where this filter sits among the others in its load order group.
///
/// `Flags` is [`INSTANCE_FLAGS`] and `Altitude` is
/// [`av_driver_proto::install::ALTITUDE`]; see both for what they mean. The
/// per-value reasoning lives at the constants rather than here, because these are
/// the values the machine acts on and a reader looking one up should find the
/// explanation beside it rather than three hundred lines away in a table.
fn plan() -> Vec<Plan> {
    vec![
        Plan {
            key: service_key(),
            values: vec![
                // First, because it is the one a person reads: it says which file
                // on disk this service is, and half of the failures in this
                // module's documentation are about that file.
                ("ImagePath", Value::Str(image_path())),
                ("Type", Value::Dword(TYPE_FILE_SYSTEM_DRIVER)),
                ("Start", Value::Dword(START_BOOT)),
                ("ErrorControl", Value::Dword(ERROR_NORMAL)),
                ("Group", Value::Str(id::LOAD_ORDER_GROUP.to_string())),
                ("DependOnService", Value::Multi(vec![id::DEPENDENCY.to_string()])),
            ],
        },
        Plan {
            key: format!(r"{}\Instances", service_key()),
            values: vec![("DefaultInstance", Value::Str(id::INSTANCE_NAME.to_string()))],
        },
        Plan {
            key: format!(r"{}\Instances\{}", service_key(), id::INSTANCE_NAME),
            values: vec![
                ("Altitude", Value::Str(id::ALTITUDE.to_string())),
                ("Flags", Value::Dword(INSTANCE_FLAGS)),
            ],
        },
    ]
}

// -- what the machine was found to hold ---------------------------------------

/// One value of the registration, as the machine was found to hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The key it lives in, under `HKEY_LOCAL_MACHINE`.
    pub key: String,
    /// The value's name.
    pub name: &'static str,
    /// What `plan` says it should be, rendered.
    pub expected: String,
    /// What the registry holds, rendered; `None` when the value is not there.
    pub actual: Option<String>,
}

impl Found {
    /// Whether the machine holds what the installer would write.
    #[must_use]
    pub fn matches(&self) -> bool {
        self.actual.as_deref() == Some(self.expected.as_str())
    }

    /// Whether the value is not there at all, as opposed to being different.
    #[must_use]
    pub fn absent(&self) -> bool {
        self.actual.is_none()
    }
}

/// What a machine has registered, read back from the registry.
///
/// The return of [`install`] as well as of [`status`], deliberately: the command
/// that changes the machine is the command that reads the change back, so a
/// caller never has to take the installer's word for what it did. See this
/// crate's module documentation for the same rule stated about the shell verbs.
#[derive(Debug, Clone)]
pub struct DriverStatus {
    /// Where the driver image has to be for the registration to mean anything.
    pub image: PathBuf,
    /// Whether that file is there.
    pub file_present: bool,
    /// Every value of the registration, each compared against `plan`.
    pub values: Vec<Found>,
}

impl DriverStatus {
    /// Whether this machine is registered as `plan` describes, image and all.
    ///
    /// The two halves are both required and neither implies the other. A key
    /// naming a file that is not there is the failure this module's check exists
    /// for, and a file with no key is a driver nothing loads.
    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.file_present && self.values.iter().all(Found::matches)
    }

    /// The values the machine does not have.
    #[must_use]
    pub fn absent(&self) -> Vec<&Found> {
        self.values.iter().filter(|found| found.absent()).collect()
    }

    /// The values the machine has and that are not what `plan` says.
    #[must_use]
    pub fn differing(&self) -> Vec<&Found> {
        self.values
            .iter()
            .filter(|found| !found.absent() && !found.matches())
            .collect()
    }

    /// One sentence per thing that is wrong, in a form a status command prints.
    ///
    /// Sentences and not a boolean, because "the driver is not installed" is not
    /// actionable and "`Altitude` is 325000, expected 321000" is: the second one
    /// names the key, the value and both numbers, and a person can act on it
    /// without running anything else.
    ///
    /// Empty when nothing is wrong, which is the same condition as
    /// [`is_installed`](Self::is_installed) returning `true`.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !self.file_present {
            problems.push(format!(
                "the driver image is not at {} — a registration naming a file that is not there is \
                 one the loader accepts and then fails to find",
                self.image.display()
            ));
        }
        for found in self.absent() {
            problems.push(format!(
                "{}\\{} is not set (the installer writes {})",
                found.key, found.name, found.expected
            ));
        }
        for found in self.differing() {
            problems.push(format!(
                "{}\\{} is {} and the installer writes {}",
                found.key,
                found.name,
                found.actual.as_deref().unwrap_or("(unreadable)"),
                found.expected
            ));
        }
        problems
    }
}

// -- the three commands --------------------------------------------------------

/// Install the driver from `source` and register it for the whole machine.
///
/// Returns what the machine holds afterwards, read back out of the registry
/// rather than assumed from what was written.
///
/// Idempotent: running it twice leaves the same registry and the same file as
/// running it once, which also makes it how a half-finished install is repaired.
/// It does **not** load the filter — see [`remove`] for the same fact from the
/// other direction, and note that `fltmc load WenleAvFilter` activates a freshly
/// registered driver without a reboot.
///
/// # Errors
///
/// [`DriverError::NeedsElevation`] when this process is not elevated,
/// [`DriverError::SourceUnreadable`] or [`DriverError::NotADriver`] when the
/// source is not a driver image, [`DriverError::CopyFailed`] when the image
/// cannot be placed, and [`DriverError::Registry`] when the machine refuses the
/// registration. Nothing is written until the image has been checked, so a
/// refusal leaves the registry and the disk exactly as they were.
pub fn install(source: &Path) -> Result<DriverStatus, DriverError> {
    ensure_elevated()?;

    // Before anything is written. The order matters: this is the check that
    // catches a user pointing the command at the wrong file, and doing it after
    // the copy would mean a machine left with a bad image in `System32\drivers`
    // and no service to explain it.
    let bytes = std::fs::read(source).map_err(|error| DriverError::SourceUnreadable {
        path: source.to_path_buf(),
        detail: error.to_string(),
    })?;
    check_driver_image(&bytes).map_err(|fault| DriverError::NotADriver {
        path: source.to_path_buf(),
        fault,
    })?;

    let root = system_root()?;
    let image = installed_image(&root);
    // Named directly rather than taken from `image.parent()`, which would be an
    // `Option` whose `None` arm is unreachable and would therefore need an
    // `expect` to say so. The directory is the same join `installed_image`
    // performs, one step short of the file name.
    let drivers = root.join(id::DEVICE_SUBDIR);
    // `System32\drivers` exists on every Windows, so this creates nothing on a
    // real machine. It is here for the case where it does not — a stripped
    // image, or a test pointing at a temporary root — where the difference
    // between creating the directory and failing is the difference between a
    // driver that installs and a `PathNotFound` naming a directory nobody
    // mentioned.
    std::fs::create_dir_all(&drivers).map_err(|error| DriverError::CopyFailed {
        path: image.clone(),
        detail: error.to_string(),
    })?;
    std::fs::copy(source, &image).map_err(|error| DriverError::CopyFailed {
        path: image.clone(),
        detail: error.to_string(),
    })?;

    for step in plan() {
        let key = Key::create(Hive::LocalMachine, &step.key)?;
        for (name, value) in &step.values {
            value.write(&key, name)?;
        }
    }

    log::info!(
        "installed the kernel driver from {} to {} and registered {} as a boot-start file system \
         driver in the {} group at altitude {}",
        source.display(),
        image.display(),
        id::SERVICE_NAME,
        id::LOAD_ORDER_GROUP,
        id::ALTITUDE
    );

    status()
}

/// Unregister the driver and delete its image.
///
/// # What this does not do
///
/// It does not unload a filter that is already running. Deleting the service key
/// and the instance under it means the driver is not loaded *next* time; a filter
/// the filter manager has already attached stays attached until the machine
/// restarts, and a user who wants it gone before then runs
/// `fltmc unload WenleAvFilter`. This function does not do it on their behalf
/// because unloading a filesystem filter while operations are in flight through
/// it is a decision about those operations, and the caller who can see what is
/// running is the one who should make it.
///
/// # Errors
///
/// [`DriverError::NeedsElevation`] when this process is not elevated, and
/// [`DriverError::Registry`] when the machine refuses the delete.
pub fn remove() -> Result<(), DriverError> {
    ensure_elevated()?;

    // One call for the whole tree: the service key, its six values, `Instances`,
    // `DefaultInstance`, the instance and its two values. Enumerated rather than
    // deleted one by one for the reason `RegDeleteTree` exists — a list of
    // deletions written here would be a second copy of `plan`, and the first
    // value somebody adds to `plan` would be the one that survives an uninstall.
    Key::delete_tree(Hive::LocalMachine, &service_key())?;

    let image = installed_image(&system_root()?);
    if image.is_file() {
        std::fs::remove_file(&image).map_err(|error| DriverError::CopyFailed {
            path: image.clone(),
            detail: error.to_string(),
        })?;
    }

    log::info!(
        "removed the kernel driver's registration and its image at {}; a filter that is already \
         loaded stays loaded until the machine restarts, or until `fltmc unload WenleAvFilter`",
        image.display()
    );
    Ok(())
}

/// What this machine has registered, read back from the registry.
///
/// Reads only, so it needs no elevation — `HKLM\SYSTEM\CurrentControlSet\Services`
/// grants read access to every user, which is how `sc query` works from a prompt
/// nobody elevated. A machine where the key is absent is `Ok` and reports every
/// value as absent, because "the driver is not installed" is an answer and not a
/// failure.
///
/// # Errors
///
/// [`DriverError::Registry`] when a read fails for a reason other than the key
/// being absent, and [`DriverError::NoSystemRoot`] when the image's location
/// cannot be determined.
pub fn status() -> Result<DriverStatus, DriverError> {
    let image = installed_image(&system_root()?);
    let mut values = Vec::new();

    for step in plan() {
        // `open_read_only` and not `open`: status must not be able to write, and
        // the registry's own documentation for the two constructors says the
        // distinction is a decision at the call site rather than a capability of
        // the handle. A status command that asked for write access would fail
        // with access denied on a key whose only problem was that it belonged to
        // somebody else.
        let Some(key) = Key::open_read_only(Hive::LocalMachine, &step.key)? else {
            // The key is not there, so none of its values are. Reported value by
            // value rather than as one "the key is missing" line, because the
            // caller comparing a machine against `plan` wants the same shape of
            // answer in every case, and because a key that exists with five of
            // its six values is a real state this has to be able to describe.
            for (name, value) in step.values {
                values.push(Found {
                    key: step.key.clone(),
                    name,
                    expected: value.render(),
                    actual: None,
                });
            }
            continue;
        };
        for (name, value) in step.values {
            values.push(Found {
                key: step.key.clone(),
                name,
                expected: value.render(),
                actual: value.read(&key, name)?,
            });
        }
    }

    Ok(DriverStatus {
        file_present: image.is_file(),
        image,
        values,
    })
}

/// Refuse to change the machine from a process that may not.
///
/// [`crate::shell::is_elevated`] rather than a second copy of the token query:
/// this crate already asks that question, in the module that documents what the
/// answer means, and a second implementation would be a second thing to be wrong
/// about whether a user is an administrator.
fn ensure_elevated() -> Result<(), DriverError> {
    if crate::shell::is_elevated() {
        return Ok(());
    }
    Err(DriverError::NeedsElevation)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the plan, which is what install writes and status checks -------------

    #[test]
    fn the_registration_is_three_keys() {
        let plan = plan();
        assert_eq!(plan.len(), 3, "the service, Instances, and the one instance");
        assert_eq!(plan[0].key, service_key());
        assert_eq!(plan[1].key, format!(r"{}\Instances", service_key()));
        assert_eq!(
            plan[2].key,
            format!(r"{}\Instances\{}", service_key(), id::INSTANCE_NAME)
        );
    }

    #[test]
    fn the_service_key_holds_everything_the_filter_manager_reads() {
        // The list from `av-driver-proto`'s `install` module documentation, which
        // is where it was verified against the WDK: a driver that is missing any
        // one of these is a driver the filter manager refuses to load, and the
        // refusal is a line in a log rather than a message at a prompt.
        let names: Vec<&str> = plan()[0].values.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "ImagePath",
                "Type",
                "Start",
                "ErrorControl",
                "Group",
                "DependOnService"
            ]
        );
    }

    #[test]
    fn the_instance_key_holds_an_altitude_and_the_flags() {
        let names: Vec<&str> = plan()[2].values.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["Altitude", "Flags"]);
    }

    #[test]
    fn the_filter_manager_is_told_which_instance_to_use() {
        // `DefaultInstance` is a value under the `Instances` key, not a key of
        // its own, and the filter manager reads the instance's altitude from the
        // subkey it names. A registration that put the name one level up, or that
        // spelled it differently from the key, is a filter with no altitude.
        let step = &plan()[1];
        assert_eq!(step.values.len(), 1);
        let (name, value) = &step.values[0];
        assert_eq!(*name, "DefaultInstance");
        assert_eq!(value.render(), id::INSTANCE_NAME);
        assert!(
            plan()[2].key.ends_with(id::INSTANCE_NAME),
            "the name DefaultInstance holds has to be the key that is actually there"
        );
    }

    #[test]
    fn the_altitude_is_written_as_a_string_and_the_flags_as_a_number() {
        // The types are not interchangeable: the filter manager parses `Altitude`
        // as an infinite-precision decimal and reads `Flags` as a bit field, so a
        // `REG_DWORD` altitude is a value it cannot read and a `REG_SZ` flags is
        // one it will not.
        let step = &plan()[2];
        assert!(matches!(step.values[0].1, Value::Str(_)), "Altitude must be REG_SZ");
        assert!(matches!(step.values[1].1, Value::Dword(_)), "Flags must be REG_DWORD");
        assert_eq!(step.values[0].1.render(), id::ALTITUDE);
        assert_eq!(step.values[1].1.render(), INSTANCE_FLAGS.to_string());
    }

    #[test]
    fn the_service_type_numbers_are_the_ones_the_scm_acts_on() {
        // Written as numbers in the constants and checked here against what the
        // numbers mean, so that an edit to one of them fails a test rather than
        // producing a service the SCM creates in a state nobody intended.
        assert_eq!(TYPE_FILE_SYSTEM_DRIVER, 2, "SERVICE_FILE_SYSTEM_DRIVER");
        assert_eq!(START_BOOT, 0, "SERVICE_BOOT_START");
        assert_eq!(ERROR_NORMAL, 1, "SERVICE_ERROR_NORMAL");
        assert_ne!(
            ERROR_NORMAL, 3,
            "SERVICE_ERROR_CRITICAL would let a driver that failed to load stop the machine from \
             booting, which is the outage this product must not become"
        );
    }

    #[test]
    fn the_dependency_is_a_list_because_the_registry_type_is_a_list() {
        // `DependOnService` is `REG_MULTI_SZ` and the SCM does not accept a
        // `REG_SZ` there. The value holds one element and is still a list.
        let step = &plan()[0];
        let value = &step
            .values
            .iter()
            .find(|(name, _)| *name == "DependOnService")
            .expect("the plan registers the dependency")
            .1;
        assert!(matches!(value, Value::Multi(items) if items.len() == 1));
        assert_eq!(value.render(), id::DEPENDENCY);
    }

    // -- the paths -----------------------------------------------------------

    #[test]
    fn the_image_path_is_one_the_loader_can_resolve_at_boot() {
        // The `\SystemRoot\` prefix and not `%SystemRoot%`, not a drive letter,
        // and not an empty string. A boot-start driver is read before the drive
        // letters exist, and the loader resolves this name itself.
        let path = image_path();
        assert_eq!(path, r"\SystemRoot\System32\drivers\WenleAvFilter.sys");
        assert!(path.starts_with(r"\SystemRoot\"), "{path}");
        assert!(!path.contains(':'), "{path} names a drive, which does not exist at boot");
        assert!(path.ends_with(id::FILE_NAME), "{path}");
    }

    #[test]
    fn the_registry_path_and_the_disk_path_name_the_same_file() {
        // Two spellings of one location, and the difference between them is only
        // the root: the registry's is the loader's name for Windows and the
        // disk's is the filesystem's. A change to one that did not reach the
        // other is a service pointing at a file that was never written.
        let on_disk = installed_image(Path::new(r"C:\Windows"));
        assert_eq!(on_disk, Path::new(r"C:\Windows\System32\drivers\WenleAvFilter.sys"));
        assert!(
            image_path().ends_with(&format!(r"\{}\{}", id::DEVICE_SUBDIR, id::FILE_NAME)),
            "{} and {} have to end the same way",
            image_path(),
            on_disk.display()
        );
    }

    #[test]
    fn the_service_key_is_where_the_scm_looks_and_is_named_after_the_service() {
        assert_eq!(
            service_key(),
            r"SYSTEM\CurrentControlSet\Services\WenleAvFilter"
        );
        assert!(
            service_key().ends_with(id::SERVICE_NAME),
            "the key the SCM creates for a service is named after that service"
        );
        assert!(!service_key().starts_with(r"\"), "relative to HKEY_LOCAL_MACHINE");
    }

    // -- finding the image beside the executable -----------------------------

    #[test]
    fn a_build_tree_is_searched_for_the_name_cargo_writes() {
        // The case that makes `find_driver` more than a `join`: a developer runs
        // the command out of `target\debug` and the file there is called
        // `av_driver.dll`, because that is what a `cdylib` target produces. A
        // search that knew only the installed name would report the build as
        // missing its own driver.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let built = directory.path().join(id::BUILD_OUTPUT_NAME);
        std::fs::write(&built, b"not really a driver").expect("write");
        assert_eq!(find_driver(directory.path()), Some(built));
    }

    #[test]
    fn an_installed_product_is_searched_for_the_name_that_is_installed() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let installed = directory.path().join(id::FILE_NAME);
        std::fs::write(&installed, b"not really a driver").expect("write");
        assert_eq!(find_driver(directory.path()), Some(installed));
    }

    #[test]
    fn the_installed_name_wins_when_a_directory_holds_both() {
        // A directory holding both is one somebody has copied a build output
        // into an installed product's folder. The installed name is the one that
        // belongs there, and it is the one the registry will name.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let installed = directory.path().join(id::FILE_NAME);
        std::fs::write(&installed, b"packaged").expect("write");
        std::fs::write(directory.path().join(id::BUILD_OUTPUT_NAME), b"raw build output")
            .expect("write");
        assert_eq!(find_driver(directory.path()), Some(installed));
    }

    #[test]
    fn a_directory_with_neither_name_has_no_driver() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        assert_eq!(find_driver(directory.path()), None);
    }

    #[test]
    fn a_cargo_profile_directory_is_recognised_as_a_checkout() {
        // The pair that makes the walk up safe: cargo writes a profile's output
        // into `debug` or `release` directly under a directory named `target`,
        // and the workspace root is two levels up from there.
        for profile in ["debug", "release"] {
            let exe_dir = Path::new("repo").join("target").join(profile);
            assert_eq!(checkout_root(&exe_dir), Some(Path::new("repo")));
        }
    }

    #[test]
    fn a_directory_that_is_not_a_cargo_profile_is_not_a_checkout() {
        // Four shapes this must refuse, and the first is the important one: a
        // test binary runs out of `target\debug\deps`, so a walk that only
        // checked for a parent would climb out of the checkout in every test.
        let cases = [
            Path::new("repo").join("target").join("deps"),
            Path::new("repo").join("target"),
            Path::new("repo").join("debug"),
            PathBuf::from(r"C:\Program Files\Wenle"),
        ];
        for case in cases {
            assert_eq!(checkout_root(&case), None, "{}", case.display());
        }
    }

    #[test]
    fn the_refusal_names_every_directory_it_looked_in() {
        // A report of one directory when four were searched sends a user to look
        // in the wrong one — and the wrong one is where they will then copy the
        // file to, which is how a stale driver gets registered.
        let searched = vec![
            PathBuf::from(r"C:\repo\target\debug"),
            PathBuf::from(r"C:\repo\crates\av-driver\target\release"),
        ];
        let message = DriverError::SourceMissing { searched }.to_string();
        for directory in [r"C:\repo\target\debug", r"C:\repo\crates\av-driver\target"] {
            assert!(message.contains(directory), "{message}");
        }
        // The fix, not just the complaint: a user who has never built the driver
        // workspace needs to be told that it is one.
        assert!(message.contains("crates/av-driver"), "{message}");
        assert!(message.contains(id::FILE_NAME), "{message}");
        assert!(message.contains(id::BUILD_OUTPUT_NAME), "{message}");
    }

    // -- the image check -----------------------------------------------------

    /// A minimal PE image with the two fields set to what the caller says.
    ///
    /// Built through `av-pe`'s own fixture builders rather than assembled here,
    /// so that the bytes this module is tested against are the bytes the parser
    /// is tested against — and so a change to the PE format's layout is a change
    /// in one place.
    fn image(machine: u16, subsystem: u16) -> Vec<u8> {
        let mut pe = av_pe::testing::minimal_pe64();
        av_pe::testing::set_machine(&mut pe, machine);
        av_pe::testing::set_subsystem(&mut pe, subsystem);
        pe
    }

    #[test]
    fn a_native_amd64_image_is_accepted() {
        let built = image(MACHINE_AMD64 as u16, SUBSYSTEM_NATIVE as u16);
        // The fixture's own fields, read back through the parser, so that a
        // failure here says whether the builder or the check is wrong.
        let parsed = av_pe::PeFile::parse(&built).expect("the fixture parses");
        assert_eq!(parsed.machine(), MACHINE_AMD64);
        assert_eq!(parsed.subsystem(), SUBSYSTEM_NATIVE);
        check_driver_image(&built).expect("this is what a driver image looks like");
    }

    #[test]
    fn a_dll_is_refused_and_the_message_says_which_subsystem_it_is() {
        // The mistake this check exists for. `av_driver.dll` is what the build
        // produces, so it is the file a user is most likely to point the command
        // at, and it is a GUI-subsystem image.
        let dll = image(MACHINE_AMD64 as u16, 2);
        let fault = check_driver_image(&dll).expect_err("a GUI image is not a driver");
        assert_eq!(fault, ImageFault::NotNative { subsystem: 2 });
        let message = fault.to_string();
        assert!(message.contains("subsystem is 2"), "{message}");
        assert!(message.contains("a kernel driver's is 1"), "{message}");
    }

    #[test]
    fn the_subsystem_is_reported_before_the_machine_type() {
        // A 32-bit console application fails both checks, and the one to report
        // is the subsystem: it says "you pointed at the wrong file", where the
        // machine type would send the user looking for a build problem.
        let wrong = image(0x014C, 3);
        let fault = check_driver_image(&wrong).expect_err("neither field is right");
        assert_eq!(fault, ImageFault::NotNative { subsystem: 3 });
    }

    #[test]
    fn a_native_image_for_another_machine_is_refused() {
        // The remaining case: the right subsystem and the wrong architecture. A
        // 32-bit native image is a real thing — some drivers are — and this
        // product's driver is not one of them.
        let arm64 = image(0xAA64, SUBSYSTEM_NATIVE as u16);
        let fault = check_driver_image(&arm64).expect_err("this driver is x86_64 only");
        assert_eq!(fault, ImageFault::WrongMachine { machine: 0xAA64 });
        let message = fault.to_string();
        assert!(message.contains("0xAA64"), "{message}");
        assert!(message.contains("0x8664"), "{message}");
    }

    #[test]
    fn a_file_that_is_not_a_pe_is_refused_by_the_parser() {
        let fault = check_driver_image(b"this is a text file, not a driver")
            .expect_err("a text file is not a driver");
        assert!(matches!(fault, ImageFault::Malformed { .. }), "{fault:?}");
    }

    #[test]
    fn a_truncated_image_is_refused_rather_than_read_past_its_end() {
        // The parser's bounds checks are what make this a refusal rather than a
        // panic, and this module never sees the bytes except through it. A
        // truncated file is what a copy that failed halfway leaves behind.
        let mut built = image(MACHINE_AMD64 as u16, SUBSYSTEM_NATIVE as u16);
        built.truncate(0x100);
        let fault = check_driver_image(&built).expect_err("half a PE header is not one");
        assert!(matches!(fault, ImageFault::Malformed { .. }), "{fault:?}");
    }

    // -- the report ----------------------------------------------------------

    /// A status whose values all match, so that a test can break one.
    fn healthy() -> DriverStatus {
        DriverStatus {
            image: PathBuf::from(r"C:\Windows\System32\drivers\WenleAvFilter.sys"),
            file_present: true,
            values: plan()
                .into_iter()
                .flat_map(|step| {
                    step.values.into_iter().map(move |(name, value)| Found {
                        key: step.key.clone(),
                        name,
                        expected: value.render(),
                        actual: Some(value.render()),
                    })
                })
                .collect(),
        }
    }

    #[test]
    fn a_machine_holding_the_plan_is_installed() {
        let status = healthy();
        assert!(status.is_installed());
        assert!(status.problems().is_empty(), "{:?}", status.problems());
        assert!(status.absent().is_empty());
        assert!(status.differing().is_empty());
        // Every value of every key, which is the count that makes the report
        // worth reading rather than a spot check of two of them.
        assert_eq!(status.values.len(), 6 + 1 + 2);
    }

    #[test]
    fn a_missing_image_is_not_installed_even_when_every_value_matches() {
        // The failure the whole check exists for, and the one a value-by-value
        // comparison alone would miss: `HKLM` says the driver is there, the SCM
        // will try to start it, and there is no file.
        let mut status = healthy();
        status.file_present = false;
        assert!(!status.is_installed());
        let problems = status.problems();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("the driver image is not at"), "{}", problems[0]);
    }

    #[test]
    fn an_absent_value_and_a_different_value_are_reported_differently() {
        // "Not set" and "set to something else" call for different actions — one
        // is a registration that never completed and the other is one somebody
        // changed — and a report that said "wrong" for both would leave a user
        // to work out which.
        let mut status = healthy();
        let altitude = status
            .values
            .iter_mut()
            .find(|found| found.name == "Altitude")
            .expect("the plan has an Altitude");
        altitude.actual = Some("325000".to_string());
        status
            .values
            .iter_mut()
            .find(|found| found.name == "Group")
            .expect("the plan has a Group")
            .actual = None;

        assert!(!status.is_installed());
        assert_eq!(status.absent().len(), 1);
        assert_eq!(status.differing().len(), 1);
        assert_eq!(status.absent()[0].name, "Group");
        assert_eq!(status.differing()[0].name, "Altitude");

        let problems = status.problems();
        assert_eq!(problems.len(), 2);
        assert!(
            problems.iter().any(|line| line.contains("Group is not set")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|line| line.contains("Altitude is 325000")
                && line.contains("writes 321000")),
            "{problems:?}"
        );
    }

    #[test]
    fn every_problem_line_names_the_key_it_is_about() {
        // A line saying "Altitude is wrong" cannot be acted on without a
        // registry editor and a guess. The full key path is what makes the
        // report usable, and it is the reason `Plan` carries a full path rather
        // than a suffix.
        let mut status = healthy();
        for found in &mut status.values {
            found.actual = None;
        }
        for line in status.problems() {
            assert!(line.contains(r"SYSTEM\CurrentControlSet\Services\WenleAvFilter"), "{line}");
        }
    }

    #[test]
    fn an_absent_key_reports_its_values_rather_than_itself() {
        // What `status` does when the whole key is missing: it expands the plan
        // for that key into absent values, so a caller comparing a machine
        // against the plan sees the same shape of answer whether the key is
        // absent or merely empty. This checks the shape the function relies on —
        // that a key's values are always all present in the report.
        let status = DriverStatus {
            image: PathBuf::from(r"C:\Windows\System32\drivers\WenleAvFilter.sys"),
            file_present: false,
            values: plan()
                .into_iter()
                .flat_map(|step| {
                    step.values.into_iter().map(move |(name, value)| Found {
                        key: step.key.clone(),
                        name,
                        expected: value.render(),
                        actual: None,
                    })
                })
                .collect(),
        };
        assert_eq!(status.absent().len(), status.values.len());
        assert!(status.differing().is_empty());
        assert_eq!(status.problems().len(), status.values.len() + 1);
    }

    // -- the real registry, read only -----------------------------------------

    #[test]
    fn status_reads_this_machines_registry_without_writing_to_it() {
        // The one test here that calls the real API, and it is a read for a
        // reason: a test that registered a kernel driver would change the
        // machine it ran on, and one that failed halfway would leave a service
        // behind. What this proves is that every read the module performs works
        // against the real registry, which the pure tests above cannot.
        //
        // On a machine where the driver has been installed this reports it as
        // installed; on one where it has not, every value comes back absent.
        // Both are answers, and the test asserts only what holds in both cases.
        let status = status().expect("reading a service key needs no elevation");
        assert_eq!(status.values.len(), 6 + 1 + 2, "every value of the plan is reported");
        assert!(
            status.values.iter().all(|found| !found.name.is_empty()),
            "each reported value is named"
        );
        assert_eq!(
            status.is_installed(),
            status.file_present && status.values.iter().all(Found::matches),
            "the summary and the whole report have to agree"
        );
    }

    #[test]
    fn the_environment_says_where_windows_is() {
        // `system_root` is read by all three commands, and a machine where it
        // failed would make every one of them report that it cannot find
        // Windows. The variable is set by Windows itself for every process.
        let root = system_root().expect("%SystemRoot% is set on a running Windows");
        assert!(root.is_absolute(), "{}", root.display());
        assert!(
            installed_image(&root).ends_with(id::FILE_NAME),
            "{}",
            installed_image(&root).display()
        );
    }
}
