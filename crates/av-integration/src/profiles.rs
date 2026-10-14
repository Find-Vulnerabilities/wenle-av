//! The machine's local user profiles: where they are and what is inside them.
//!
//! # Why this is not "the current user's folders"
//!
//! The Windows service runs as `LocalSystem`, and `LocalSystem` has a profile of
//! its own: `C:\Windows\System32\config\systemprofile`. Every "the current user's
//! Desktop/Downloads/Documents" call therefore answers with *the system's* three
//! directories when the service asks: directories that exist, that are empty,
//! and that the person using the machine will never put a file in.
//!
//! A watcher built on those answers reports full coverage while covering
//! nothing, which is the worst shape a protection failure can take: the user is
//! told they are protected, the status names real directories, and a sample
//! dropped in `C:\Users\them\Downloads` is never seen. The folders that matter
//! belong to the people using the machine, and which those are is a fact about
//! the machine (read here from the registry) rather than something to infer
//! from the identity of the process asking.
//!
//! # Read-only, and that is deliberate
//!
//! Nothing in this module writes. It is in this crate because it reads the
//! registry, which is what this crate already does, and not because it registers
//! anything.

use std::path::{Path, PathBuf};

use crate::registry::{Hive, Key};

/// Where Windows keeps the list of local profiles.
///
/// One subkey per profile, named by the account's SID, each holding a
/// `ProfileImagePath`. Read rather than enumerated from `C:\Users`, because the
/// two do not agree: a profile can live somewhere else entirely, and `C:\Users`
/// also holds `Public` and `Default`, which are not profiles anyone uses —
/// watching `Default` would be watching the template every logon is copied from.
pub const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The accounts that are services rather than people.
///
/// `LocalSystem`, `LocalService` and `NetworkService` each have a profile and an
/// entry in the profile list, and none of them is a person: their Desktop,
/// Downloads and Documents exist, stay empty, and are exactly what a
/// "current user" lookup answers with when the asker is the service. Skipping
/// them by SID is what makes this list mean *the people who use this machine*.
///
/// Fixed values and not a lookup: these three SIDs are the same on every Windows
/// machine, which is why they can be written down. `S-1-5-18` is `LocalSystem`,
/// `S-1-5-19` is `LocalService`, `S-1-5-20` is `NetworkService`.
pub const SERVICE_SIDS: [&str; 3] = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

/// Every local profile directory that exists, in the registry's order.
///
/// A profile whose directory is not there is left out. A profile deleted without
/// its registry entry being cleaned up is a fact about a machine that used to be,
/// and a watch armed on a path that is not there is one more root for the plan to
/// report as skipped.
///
/// An unreadable `ProfileList` gives an empty list rather than an error, and that
/// is the one place this module is deliberately quiet: the caller is building a
/// *default* watch plan and already has an answer for the current user from the
/// shell's known folders. An error here would turn "the default set could not be
/// widened" into "the watcher did not start", which is the worse of the two.
pub fn roots() -> Vec<PathBuf> {
    let Some(key) = open(PROFILE_LIST) else {
        log::debug!("the profile list at {PROFILE_LIST} could not be read");
        return Vec::new();
    };
    let Ok(subkeys) = key.subkeys() else {
        log::debug!("the subkeys of {PROFILE_LIST} could not be listed");
        return Vec::new();
    };

    let mut out = Vec::new();
    for sid in subkeys {
        if SERVICE_SIDS.iter().any(|service| sid.eq_ignore_ascii_case(service)) {
            continue;
        }
        // Opened per SID rather than by walking the `ProfileList` key's values:
        // `ProfileImagePath` is a value of the *subkey*, not of the key that
        // holds the subkeys.
        let path = format!(r"{PROFILE_LIST}\{sid}");
        let Some(profile) = open(&path) else { continue };
        // A `ProfileImagePath` that is missing, not a string, or not Unicode is
        // skipped rather than guessed at. There is no useful default for "where
        // this account's files are".
        let Ok(Some(image)) = profile.string("ProfileImagePath") else {
            log::debug!("{path} has no readable ProfileImagePath");
            continue;
        };
        let directory = expand(&image);
        if directory.is_dir() {
            out.push(directory);
        }
    }
    out
}

/// Open a key for reading, or `None` when it is not there or not readable.
fn open(path: &str) -> Option<Key> {
    match Key::open_read_only(Hive::LocalMachine, path) {
        Ok(key) => key,
        Err(error) => {
            log::debug!("{path} could not be opened for reading: {error}");
            None
        }
    }
}

/// The folders inside one profile a filesystem watcher should cover.
///
/// Deliberately the same list `av_realtime` watches for the current user, so a
/// machine with one profile behaves the same whether the service or the
/// command-line tool did the asking: they are the same product, and a different
/// answer from each would be a second definition of "the user's folders". Only
/// the ones that exist are returned.
pub fn folders(profile: &Path) -> Vec<PathBuf> {
    [
        profile.join("Downloads"),
        profile.join("Desktop"),
        profile.join("Documents"),
        // `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`. Covered
        // because a file placed here runs at every logon, which makes it the one
        // directory where a sample's first appearance is also the last chance to
        // catch it before it runs.
        profile
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup"),
        // `%LOCALAPPDATA%\Temp`. A dropped executable is very often written to a
        // temporary directory first, and under `LocalSystem` the process's own
        // temporary directory belongs to no user at all.
        profile.join("AppData").join("Local").join("Temp"),
    ]
    .into_iter()
    .filter(|candidate| candidate.is_dir())
    .collect()
}

/// Replace `%NAME%` in a stored path with what the variable holds.
///
/// `ProfileImagePath` is a `REG_EXPAND_SZ` on many machines — `%SystemDrive%\Users\name`
/// is a common spelling — and [`Key::string`] deliberately reads what is stored
/// rather than expanding it. Expanded with the Windows API rather than by
/// scanning for `%`, because `%` is a legal character in a path and what may
/// legally appear between two of them is the API's rule, not this crate's.
///
/// A value that cannot be expanded is returned as it was stored, which is the
/// useful failure: the path is then checked for existence by the caller and
/// skipped like any other that is not there.
#[cfg(windows)]
fn expand(value: &str) -> PathBuf {
    use windows::core::PCWSTR;
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;

    let source: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `source` is a NUL-terminated UTF-16 string that outlives the call.
    // A null destination is the documented way to ask for the length required,
    // and the count it returns includes the terminating NUL.
    let needed = unsafe { ExpandEnvironmentStringsW(PCWSTR(source.as_ptr()), None) };
    if needed == 0 {
        return PathBuf::from(value);
    }

    let mut buffer = vec![0u16; needed as usize];
    // SAFETY: `buffer` is `needed` elements, which is what the call above asked
    // for, and it outlives this call.
    let written = unsafe { ExpandEnvironmentStringsW(PCWSTR(source.as_ptr()), Some(&mut buffer)) };
    // The length can change between the two calls — the environment is shared —
    // so a result that no longer fits is refused rather than truncated.
    if written == 0 || written > needed {
        return PathBuf::from(value);
    }

    // `written` counts the terminating NUL, which is not part of the path.
    let length = (written as usize).saturating_sub(1);
    PathBuf::from(String::from_utf16_lossy(&buffer[..length]))
}

/// Non-Windows builds have no `ExpandEnvironmentStringsW` and no profile list.
///
/// The caller is a Windows-only product path; this exists so the module compiles
/// and its tests run, and it is unreachable from the watcher on a machine that is
/// not Windows.
#[cfg(not(windows))]
fn expand(value: &str) -> PathBuf {
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SIDs that are services are skipped, and that is the whole point.
    ///
    /// Asserted against the *live* registry rather than a fixture, because the
    /// claim is about this machine: the profile list is readable, the service
    /// accounts are in it, and they are not in the answer. A machine where the
    /// list cannot be read gives an empty list, which is the documented
    /// degradation — a quiet one, not a panic — and this test then asserts
    /// nothing, which is the honest outcome for a machine with no answer.
    ///
    /// # Both spellings are checked, because only one of them is caught by
    /// # accident
    ///
    /// `systemprofile` is unreadable to a non-administrator, so `is_dir` returns
    /// false and it drops out whether or not the SID is filtered — the check on
    /// it alone passed with the filter deliberately removed, which is how this
    /// test was found to be testing the wrong thing. `ServiceProfiles` *is*
    /// readable, so `LocalService` and `NetworkService` survive `is_dir` and are
    /// excluded by the SID list and nothing else. That is the half that fails
    /// when the filter goes, and an elevated service would see `systemprofile`
    /// too.
    #[test]
    fn the_service_accounts_are_not_profiles_anyone_uses() {
        let roots = roots();
        for root in &roots {
            let lowered = root.to_string_lossy().to_lowercase();
            for service in ["systemprofile", "serviceprofiles"] {
                assert!(
                    !lowered.contains(service),
                    "{} belongs to an account that is a service, not a person, and stays \
                     empty: {roots:?}",
                    root.display()
                );
            }
            assert!(
                root.is_dir(),
                "{} was returned and does not exist: {roots:?}",
                root.display()
            );
        }
    }

    /// A profile's folders are the ones that exist, and only those.
    #[test]
    fn a_profiles_folders_are_the_ones_that_are_there() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let profile = dir.path();
        std::fs::create_dir(profile.join("Downloads")).expect("Downloads");
        std::fs::create_dir(profile.join("Desktop")).expect("Desktop");

        let folders = folders(profile);

        // `Documents`, the startup folder and `AppData\Local\Temp` were not
        // created, so they must not be reported — a root armed on a directory
        // that is not there is one more entry in the plan's skipped list.
        assert_eq!(
            folders,
            vec![profile.join("Downloads"), profile.join("Desktop")],
            "the existing folders, in the documented order and nothing else"
        );
        for folder in &folders {
            assert!(folder.is_dir(), "{} is not a directory", folder.display());
        }
    }

    /// The startup folder is in the list, deep as its path is.
    ///
    /// Worth its own test because it is the one entry a reader would assume was
    /// forgotten: a file placed here runs at every logon, so it is where a
    /// sample's first appearance is also the last chance to catch it.
    #[test]
    fn a_profiles_startup_folder_is_covered() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let profile = dir.path();
        let startup = profile
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        std::fs::create_dir_all(&startup).expect("the startup folder");

        assert_eq!(folders(profile), vec![startup]);
    }
}
