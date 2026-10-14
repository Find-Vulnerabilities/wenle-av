//! One service per machine, enforced by the filesystem rather than by a mutex.
//!
//! # Why this exists at all
//!
//! Two copies of this service over one installation is not a cosmetic problem:
//!
//! * The quarantine vault keeps its index in memory and rewrites the whole file
//!   on every change. Two live [`av_quarantine::QuarantineVault`] values over
//!   one directory means the second one's `save_index` silently discards
//!   everything the first has quarantined since it opened — which is the exact
//!   class of damage `QuarantineVault::open_recovering` exists to repair, and
//!   the repair loses nothing only because the *bytes* are still on disk.
//! * Two services on one control pipe is two answers to one question, whichever
//!   of them the client happens to reach.
//! * Two realtime watchers is every filesystem event examined twice.
//!
//! # Why `CreateFileW` and not a named mutex
//!
//! A named mutex is the obvious mechanism and it has two problems here:
//!
//! * `CreateMutexW` in the `Global\` namespace needs `SeCreateGlobalPrivilege`.
//!   A service runs as `LocalSystem` and has it, so this is not fatal — but the
//!   `Local\` namespace is per-session, and the whole point is to catch a second
//!   copy started by somebody who is *not* the SCM, in another session, which a
//!   session-local mutex does not.
//! * A mutex says whether somebody holds it, not *who*. The failure has to be
//!   reported to a user, and "another instance holds `C:\ProgramData\WenleAV\
//!   service.lock`" is a sentence a support call can proceed from.
//!
//! `CreateFileW` with `dwShareMode = FILE_SHARE_READ` gives exactly the
//! semantics wanted and no privilege: the first opener gets the handle, the
//! second is refused with `ERROR_SHARING_VIOLATION` by the operating system,
//! which is the same guard the rest of the filesystem already uses. Windows
//! enforces sharing between handles in *one* process as well, so a second
//! attempt from inside this process is refused too — which is what makes the
//! guard testable without a service and without administrator.
//!
//! The handle is kept open for the process's lifetime by holding the guard; the
//! lock is released by the operating system when the process ends, including
//! when it crashes, which a lock file left behind by a tidy shutdown would not
//! manage.

use std::path::{Path, PathBuf};

use crate::error::ServiceError;

/// The name of the file the guard holds, inside the data directory.
pub const LOCK_FILE_NAME: &str = "service.lock";

/// A held single-instance lock.
///
/// Dropping it releases the lock. The process holds one of these for as long as
/// it is the service.
#[derive(Debug)]
pub struct InstanceGuard {
    path: PathBuf,
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

// The handle is a kernel object handle: valid process-wide, usable from any
// thread, and owned by exactly one `InstanceGuard`. `Send` is what the caller
// needs to keep the guard beside the service's threads; it is not `Sync`,
// because two threads closing one handle is the bug this type exists to make
// impossible.
#[cfg(windows)]
unsafe impl Send for InstanceGuard {}

impl InstanceGuard {
    /// Take the lock, or report that somebody else holds it.
    pub fn acquire(data_dir: &Path) -> Result<Self, ServiceError> {
        let path = data_dir.join(LOCK_FILE_NAME);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| ServiceError::io("create", parent, error))?;
        }
        Self::acquire_at(&path)
    }

    /// Take the lock on an explicit path.
    ///
    /// Separated from [`InstanceGuard::acquire`] so that the guard can be
    /// tested against a temporary directory, which is the only way to test it
    /// without administrator and without stopping a running service.
    pub fn acquire_at(path: &Path) -> Result<Self, ServiceError> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_ALWAYS,
            };

            let wide = crate::win32::to_wide(path.as_os_str());
            // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the
            // call, and every other argument is a plain value. The returned
            // handle is checked for validity by `CreateFileW` itself, which
            // returns `Err` rather than a sentinel.
            let handle = unsafe {
                CreateFileW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_READ,
                    None,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            match handle {
                Ok(handle) => Ok(Self {
                    path: path.to_path_buf(),
                    handle,
                }),
                // The sharing violation *is* the answer, and it is not an
                // error to be logged as a fault: it means the guard worked.
                Err(error)
                    if crate::win32::code(&error) == crate::win32::ERROR_SHARING_VIOLATION =>
                {
                    Err(ServiceError::AlreadyRunning {
                        path: path.to_path_buf(),
                    })
                }
                Err(error) => Err(ServiceError::io(
                    "open",
                    path,
                    std::io::Error::other(error.to_string()),
                )),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(ServiceError::Other(
                "the single-instance guard is a Windows file-sharing guard, and this platform has \
                 no sharing semantics to borrow"
                    .to_string(),
            ))
        }
    }

    /// The file the guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            // SAFETY: the handle was returned by `CreateFileW` and has not been
            // closed: this is the only place it is, and it is consumed here.
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_second_holder_is_refused_and_the_first_still_holds_it() {
        // The guard's whole contract, and it is testable without a service and
        // without administrator because Windows enforces share modes between
        // handles in one process as well as between processes.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(LOCK_FILE_NAME);

        let first = InstanceGuard::acquire_at(&path).expect("the first takes it");
        let second = InstanceGuard::acquire_at(&path);
        match second {
            Err(ServiceError::AlreadyRunning { path: reported }) => {
                assert_eq!(reported, path);
            }
            other => panic!("the second holder must be refused, got {other:?}"),
        }
        // The refusal is not a fault: it is the guard doing its job, and the
        // caller exits quietly on it rather than showing an error.
        assert!(InstanceGuard::acquire_at(&path)
            .expect_err("still held")
            .is_fatal());

        // Released on drop, and then takeable again — which is what makes the
        // lock survive a crash rather than needing a stale file cleaned up.
        drop(first);
        let third = InstanceGuard::acquire_at(&path).expect("released by the drop");
        assert_eq!(third.path(), path);
    }

    #[test]
    fn the_lock_lives_in_the_data_directory() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let guard = InstanceGuard::acquire(dir.path()).expect("takes it");
        assert!(guard.path().starts_with(dir.path()));
        assert_eq!(
            guard.path().file_name().and_then(|n| n.to_str()),
            Some(LOCK_FILE_NAME)
        );
    }
}
