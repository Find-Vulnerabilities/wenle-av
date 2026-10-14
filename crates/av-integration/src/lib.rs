//! The part of the product that changes the machine by *registering* rather than
//! by *running*.
//!
//! # What this crate is
//!
//! Everything else in this workspace acts on a file or on a process. This crate
//! acts on Windows itself: it writes the four registry keys that make Explorer
//! offer "Scan with Wenle Antivirus" when a user right-clicks a file, a folder,
//! the empty space inside a folder, or a drive.
//!
//! It is deliberately the smallest crate here. It does not scan, it does not
//! quarantine, and it does not talk to the service. Registering a menu item is
//! not a thing the engine should have to be linked to do, and a shell extension
//! that could also detect something would be a shell extension with a detection
//! bug in it, running inside `explorer.exe`, with the user's privileges, before
//! any of the product's own processes have started.
//!
//! # The three properties a reviewer should check first
//!
//! **Nothing here runs at scan time.** There is no code in this crate on any
//! path a scan takes. It is called by `wenle integrate`, by an installer, or by
//! nothing at all, and once it has returned, the product's scanning behaviour is
//! whatever it was before.
//!
//! **Everything here is reversible with one `remove` per scope.** [`shell::remove`]
//! deletes four keys and everything under them (`Software\Classes\*\shell\WenleScan`
//! and its three siblings), and a key that was never there is `Ok`, so `remove`
//! can always be run, including on a machine where `install` never completed.
//! [`driver::remove`] does the same for the driver's service key and its image.
//! Between them this crate creates four menu keys, one service key with two
//! subkeys under it, and one file, which is the whole list; it starts no service,
//! it unloads no filter, and it does not touch any key it did not create.
//!
//! The two user-session registrations are reversible the same way, with one
//! difference worth naming: [`notifications`] creates one key under this user's
//! `Software\Classes` and [`startup`] creates one *value* under this user's
//! `...\CurrentVersion\Run`. The second is not a key, because that key is where
//! every other program that starts at sign-in keeps its own entry. See that
//! module's documentation, which is the only place the difference is
//! explained and the only place it needs to be.
//!
//! **The driver is the one thing here a scan depends on.** The shell verbs are
//! cosmetic and the AMSI provider is a second opinion; [`driver`] registers the
//! minifilter that `crates/av-driver` builds, and until it has run on a machine
//! that driver is an artifact nothing installs. It is fenced off from the other
//! modules in the way that matters: nothing calls it except `wenle integrate
//! driver`, no installer path reaches it implicitly, and no scan or service start
//! reaches it at all.
//!
//! **The one thing here that is not registration is [`defender`], and it is
//! fenced off from everything else.** Turning Windows Defender's real-time
//! monitoring off is a change to whether this machine is protected, not a menu
//! item, and it is the most dangerous thing in the product. It is therefore only
//! reachable by a person running `wenle integrate defender disable`: nothing in
//! this crate calls it except that command, no installer path reaches it, no
//! service start reaches it and no scan reaches it. Its undo is a record of the
//! previous registry value, written down *before* the value is changed, so that
//! `restore` puts back what was there rather than turning a security feature on
//! over somebody else's decision. Read that module's own documentation before
//! changing anything in it; it states what the user gives up, which keys are read
//! and which one is written, and what the registry cannot be asked.
//!
//! **The shell verbs are cosmetic, and that is worth stating plainly.** They add
//! a menu item and nothing else. They do not protect anything, they do not watch
//! anything, and they do not change what the scanner does with a file. A user who
//! never right-clicks a file loses no protection whatsoever by not installing
//! them, and a user who uninstalls them loses none either. Anything else this
//! crate might have said about itself would be an overclaim about a registry
//! key: the honest description is "this makes the product findable from
//! Explorer", and it is written here rather than left to be inferred from a
//! feature list.
//!
//! # The three layers
//!
//! [`registry`] is a typed wrapper over the handful of Win32 registry calls this
//! needs, with the four decisions it makes written down in its own
//! documentation. [`shell`] is the feature: the four locations, the command line
//! each gets, the scope a caller is registering in, and a status report that
//! names what is actually in the registry rather than what an install intended.
//! [`defender`] is the other feature, and it shares only the first layer: it
//! reads and writes `HKEY_LOCAL_MACHINE\SOFTWARE` keys of its own and has nothing
//! to do with `Software\Classes`. [`amsi`] and [`driver`] share it too, and share
//! nothing with each other: one registers a class ID under `SOFTWARE\Classes`
//! and the other a service under `SYSTEM\CurrentControlSet\Services`, and neither
//! knows the other exists. [`notifications`] and [`startup`] are the two that
//! register for the *signed-in user* rather than for the machine: a name and an
//! icon for the shell to attribute this product's notifications to, and the entry
//! that starts the window in the notification area at sign-in. Both write under
//! `HKEY_CURRENT_USER` and neither needs elevation, which is not a coincidence:
//! both are about the session a person is sitting in.
//!
//! Everything in [`shell`] that can be decided without the registry (the command
//! line's shape, the key paths, which substitution each location uses, which
//! scope a process should default to) is decided in a pure function and tested
//! here, and the same is true of
//! [`notifications`]' key paths and [`startup`]' command line. The tests in this
//! crate do not write to `HKCU\Software\Classes`, because a test that changes the
//! developer's own right-click menu is a test that changed their machine, and one
//! that fails halfway leaves the change behind. The tests in `tests/` that do
//! touch the registry write under `HKCU\Software\WenleAV\IntegrationTest`, a key
//! this product owns outright and deletes on the way out. Nothing in this crate's tests
//! writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` either, and for
//! the same reason twice over: that key is shared with every other program that
//! starts at sign-in, so a test failing halfway there would leave a machine that
//! starts something else twice.

#![warn(missing_docs)]
// Unwrapping is how a test asserts. The workspace lint stays on for the library,
// where an unwrap in a shell-integration path is a panic inside a command a user
// ran, and is relaxed here rather than by scattering `allow` over every test
// body. The same allowance every other crate in the workspace makes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

// The AMSI provider registration. Windows-only, and gated rather than stubbed:
// the constants it writes come from `av-amsi`, which is itself `#![cfg(windows)]`
// and empty everywhere else — so a stub here would have to write the CLSID down
// a second time, and two copies of an identifier that must match is exactly the
// drift `av-amsi`'s registration module exists to prevent. AMSI is a Windows API
// and there is nothing to register off Windows.
#[cfg(windows)]
pub mod amsi;
// Windows Defender is a Windows component and there is nothing to report about
// it anywhere else, so this is gated the way [`amsi`] is rather than stubbed the
// way [`registry`] is. The difference is what a stub would be a stub *for*:
// `registry` stubs an API, and this would be stubbing a product.
#[cfg(windows)]
pub mod defender;
// The kernel driver's registration: its image under `System32\drivers`, its
// service key, and the instance and altitude the filter manager reads. Windows
// only for the same reason `amsi` is — a kernel driver is a Windows thing and
// there is nothing to register anywhere else — and it is the one module here
// that changes the machine on a path a *scan* depends on: without it, the
// driver `crates/av-driver` builds is an artifact nothing installs. See its own
// documentation for what it writes and what undoes it.
#[cfg(windows)]
pub mod driver;
// The machine's local user profiles, read from the registry. Here rather than in
// the crate that watches the filesystem, because it is a fact about the machine
// and this is the crate that reads the machine — and because the alternative is
// that crate learning to read the registry for one question it cannot answer
// about itself. See its own documentation for the failure it prevents: a service
// running as `LocalSystem` whose "current user" is the system profile.
pub mod profiles;
pub mod registry;
pub mod shell;
// The two halves of the user-session front end's registration, and neither is
// gated: both are ordinary `HKEY_CURRENT_USER` writes through [`registry`], and
// the pure parts of both — the key paths, the command lines, which name the
// entry is filed under — are decided and tested without touching a registry.
//
// [`notifications`] gives the shell a name and an icon to attribute this
// product's notifications to. [`startup`] is the entry that starts the window in
// the notification area when the user signs in, and it is the one module here
// whose `remove` deletes a *value* rather than a key: `...\CurrentVersion\Run`
// is shared with every other program that starts at sign-in, and the module's
// own documentation is where that is spelled out.
pub mod notifications;
pub mod startup;

#[cfg(windows)]
pub use amsi::{AmsiError, AmsiStatus, Detail, Site, SiteKind, SiteState, SiteStatus};
#[cfg(windows)]
pub use defender::{DefenderError, DefenderStatus, Monitoring, Previous, Tamper};
#[cfg(windows)]
pub use driver::{
    DriverError, DriverStatus, Found, ImageFault, check_driver_image, find_driver, image_path,
    installed_image, product_driver, service_key, system_root,
};
pub use registry::{Hive, Key, RegistryError};
pub use shell::{Location, Scope, ShellError, ShellStatus, VerbStatus};
