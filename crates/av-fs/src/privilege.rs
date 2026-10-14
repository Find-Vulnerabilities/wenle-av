//! Holding, enabling and reporting the two token privileges a scanner wants.
//!
//! # The problem this solves
//!
//! A file's DACL is the only thing standing between a scanner and the bytes it
//! was asked to judge. On a machine where more than one account has ever logged
//! in, `C:\Users\alice\Documents\payroll.xlsx` is not readable by the process
//! that is scanning `C:\` unless that process is Alice, an administrator, or
//! `LocalSystem`. An antivirus that reports "could not read" and moves on is an
//! antivirus that has a hole exactly where the interesting files are: the
//! attacker's payload sits in a directory the scanner cannot open, and the scan
//! comes back clean.
//!
//! Windows has an answer for this that is older than Windows NT's first
//! service pack: **`SeBackupPrivilege`**. A process whose token holds it and has
//! it *enabled* may open any file for `GENERIC_READ` regardless of the DACL, as
//! long as it also passes `FILE_FLAG_BACKUP_SEMANTICS`. That is the same
//! mechanism `NTBACKUP` and every modern backup product use, it is documented,
//! and it is audited. This module is the half that obtains it.
//!
//! # Why this is not simply "call `AdjustTokenPrivileges` and be done"
//!
//! Three reasons, each of which is a state a caller has to be able to tell
//! apart, and each of which some other implementation of this idea collapses
//! into "yes" and then reports a file as unreadable with no explanation:
//!
//! 1. **The privilege may not be in the token at all.** `SeBackupPrivilege` is
//!    included in the tokens of administrators (elevated) and `LocalSystem`,
//!    and in no others. A standard user's `wenle scan C:\` cannot be made to
//!    work by any amount of code in this crate. That is [`Presence::Absent`],
//!    it is not a failure of this module, and the honest response is to say so
//!    and name elevation as the fix.
//! 2. **The privilege may be present and disabled.** This is the normal state
//!    of an elevated administrator's token: the privilege is there and off, and
//!    `AdjustTokenPrivileges` turns it on. That is [`Presence::Disabled`].
//! 3. **`AdjustTokenPrivileges` returns success even when it assigned
//!    nothing.** This is documented behaviour rather than a bug, and it is the
//!    single most common way this code goes wrong: the call succeeds, the
//!    privilege is still off, and every subsequent read is refused for a reason
//!    the caller believes cannot happen. The only reliable report is
//!    `GetLastError() == ERROR_NOT_ALL_ASSIGNED`, and this module checks it —
//!    which is also why [`enable`] re-reads the token afterwards instead of
//!    trusting the call's return value.
//!
//! # What enabling it costs
//!
//! `AdjustTokenPrivileges` changes the *process* token, so every thread and
//! every module in the process gets the privilege, not just the scanner. A
//! process that holds `SeBackupPrivilege` enabled can read any file on the
//! machine for as long as it holds it, and a DLL injected into that process
//! inherits the ability. That is a real cost and it is why [`mod@crate::read`]
//! enables it deliberately and says so, rather than reaching for it silently
//! inside a read call. It is not a cost that can be avoided while getting the
//! coverage: the privilege is per-process by design, and per-call is not a
//! thing the operating system offers.
//!
//! Nothing here ever *disables* a privilege it enabled. Re-enabling is
//! idempotent and cheap to check, and a scanner that flipped the privilege off
//! between files would pay two token calls per file on a disk with a million of
//! them.

use std::fmt;

/// A token privilege this crate knows how to ask for.
///
/// Two, and no more, because these are the two that matter to a scanner and a
/// list of privileges "just in case" would be a list nobody had thought about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Privilege {
    /// `SeBackupPrivilege` — open any file for reading regardless of its DACL.
    ///
    /// This is the one that makes "scan every file" true. It is held by
    /// administrators and `LocalSystem`, and by nothing else.
    Backup,
    /// `SeRestorePrivilege` — open any file for writing regardless of its
    /// DACL.
    ///
    /// A scanner never needs this. It is here because the quarantine vault, the
    /// log writer and the self-protection code all write into directories whose
    /// DACLs deny the account doing the writing once hardening has been applied
    /// — and a product that locks a directory and then cannot write its own log
    /// into it has broken itself. Naming it here keeps that need visible rather
    /// than letting a caller reach for `Backup` for a job it does not do.
    Restore,
}

impl Privilege {
    /// The name Windows knows it by.
    ///
    /// These strings are the API: `LookupPrivilegeValueW` is handed one and
    /// returns a LUID or fails, so a typo here is a runtime failure rather than
    /// a compile error, and the constant has to be exact.
    pub const fn name(self) -> &'static str {
        match self {
            Privilege::Backup => "SeBackupPrivilege",
            Privilege::Restore => "SeRestorePrivilege",
        }
    }

    /// Every privilege this crate knows about, for a status report that lists
    /// what it checked rather than only what it found.
    pub const ALL: [Privilege; 2] = [Privilege::Backup, Privilege::Restore];

    /// What a caller should do about not having it.
    ///
    /// A sentence, because the answer is different for the two and "access
    /// denied" is not an answer. [`Privilege::Backup`] is missing from exactly
    /// one situation — an unelevated process — so the fix is to elevate or to
    /// run as the service. [`Privilege::Restore`] is missing in the same
    /// situation plus one more, a service account configured without it, and
    /// the fix is the same either way.
    pub const fn remedy(self) -> &'static str {
        match self {
            Privilege::Backup => {
                "run elevated (or as the Wenle service) to read files whose permissions \
                 exclude this account"
            }
            Privilege::Restore => {
                "run elevated (or as the Wenle service) to write inside directories this \
                 product has locked down"
            }
        }
    }
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether the process token holds a privilege, and whether it is on.
///
/// Three states and not a boolean, because `false` cannot distinguish "you need
/// to elevate" from "you need to turn it on", and those are different answers
/// to give a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The token contains the privilege and it is enabled.
    Enabled,
    /// The token contains the privilege and it is disabled. Call [`enable`].
    Disabled,
    /// The token does not contain the privilege. Nothing this crate can do
    /// changes that; see [`Privilege::remedy`].
    Absent,
    /// The token could not be asked. The [`PresenceError`] says why.
    ///
    /// A distinct state from [`Presence::Absent`] on purpose: "I could not find
    /// out" and "the answer is no" lead to different messages, and collapsing
    /// them would mean telling a user to elevate when the real problem was that
    /// `OpenProcessToken` failed.
    Unknown,
}

impl Presence {
    /// Whether the privilege is on right now.
    pub const fn is_enabled(self) -> bool {
        matches!(self, Presence::Enabled)
    }

    /// Whether the token contains it at all.
    pub const fn is_held(self) -> bool {
        matches!(self, Presence::Enabled | Presence::Disabled)
    }

    /// One word for a status line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Presence::Enabled => "enabled",
            Presence::Disabled => "held but disabled",
            Presence::Absent => "not held",
            Presence::Unknown => "could not be determined",
        }
    }
}

impl fmt::Display for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the token could not be asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresenceError {
    /// `OpenProcessToken` failed.
    #[error("the process token could not be opened: {0}")]
    Open(String),
    /// `LookupPrivilegeValueW` did not recognise the name.
    ///
    /// Unreachable with the two constants in [`Privilege`], which are the names
    /// the operating system documents — kept as a variant rather than an
    /// `unreachable!()` so that a future third name fails as an error instead of
    /// as a panic in a scanner.
    #[error("the operating system does not know the privilege {0}")]
    UnknownName(String),
    /// `GetTokenInformation` failed.
    #[error("the privileges in the process token could not be read: {0}")]
    Query(String),
    /// `AdjustTokenPrivileges` failed for a reason other than the privilege
    /// being absent.
    #[error("the privilege {privilege} could not be enabled: {reason}")]
    Adjust {
        /// Which privilege.
        privilege: Privilege,
        /// What the operating system said.
        reason: String,
    },
}

/// A snapshot of both privileges, for a status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privileges {
    /// `SeBackupPrivilege`.
    pub backup: Presence,
    /// `SeRestorePrivilege`.
    pub restore: Presence,
}

impl Privileges {
    /// Ask the token about every privilege in [`Privilege::ALL`].
    ///
    /// Never fails: a privilege that could not be asked is
    /// [`Presence::Unknown`], because a status command that returns an error
    /// instead of a partial report is a status command a user cannot read when
    /// they most need it.
    pub fn query() -> Self {
        Self {
            backup: query(Privilege::Backup).unwrap_or(Presence::Unknown),
            restore: query(Privilege::Restore).unwrap_or(Presence::Unknown),
        }
    }

    /// Whether the process can read a file whose DACL excludes it.
    pub const fn can_read_anything(&self) -> bool {
        self.backup.is_enabled()
    }

    /// The one-line summary a user needs, in the order that matters.
    ///
    /// Reads as a sentence about this process rather than as a table, because
    /// the command that prints it is one an administrator runs to find out why
    /// a scan reported files it could not open.
    pub fn sentence(&self) -> String {
        if self.backup.is_enabled() {
            return "This process can read files whose permissions exclude it.".to_string();
        }
        match self.backup {
            Presence::Disabled => {
                "This process holds SeBackupPrivilege but has not enabled it; a scan will \
                 enable it on the first file that needs it."
                    .to_string()
            }
            Presence::Absent => format!(
                "This process cannot read files whose permissions exclude it: SeBackupPrivilege \
                 is not in its token. To fix that, {}.",
                Privilege::Backup.remedy()
            ),
            Presence::Unknown => {
                "Whether this process can read files whose permissions exclude it could not be \
                 determined: the process token could not be read."
                    .to_string()
            }
            Presence::Enabled => unreachable!("handled above"),
        }
    }
}

impl fmt::Display for Privileges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sentence())
    }
}

/// Ask whether the token holds `privilege`.
#[cfg(windows)]
pub fn query(privilege: Privilege) -> Result<Presence, PresenceError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: `GetCurrentProcess` takes no arguments and cannot fail. The token
    // handle it fills in is closed on every path below.
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| PresenceError::Open(e.to_string()))?;
    // Everything from here has to close `token`, and the early returns are why
    // this is not a `?` chain ending in a `let _ = CloseHandle(token)`.
    let result = query_with(token, privilege);
    // SAFETY: `token` came from `OpenProcessToken`, is still open, and is not
    // used after this point.
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

/// The body of [`query`], split out so the caller can close the token on every
/// path without a guard type for one function.
#[cfg(windows)]
fn query_with(
    token: windows::Win32::Foundation::HANDLE,
    privilege: Privilege,
) -> Result<Presence, PresenceError> {
    use windows::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, TOKEN_PRIVILEGES,
        SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    };
    use windows::Win32::Foundation::LUID;

    // The LUID is what the token's privilege list is keyed by. The *name* is
    // only used here, once.
    let mut wanted = LUID::default();
    let wide = wide_nul(privilege.name());
    // SAFETY: `wide` is NUL-terminated and lives for the call; `wanted` is a
    // valid `LUID` for the API to write into.
    unsafe { LookupPrivilegeValueW(windows::core::PCWSTR::null(), windows::core::PCWSTR(wide.as_ptr()), &mut wanted) }
        .map_err(|_| PresenceError::UnknownName(privilege.name().to_string()))?;

    // Two calls: the first for the size, the second for the answer. The buffer
    // is a `Vec<u8>` rather than a `TOKEN_PRIVILEGES` because a token carries a
    // *variable* number of them and a fixed-size struct would silently read
    // past its own array for any process holding more than one.
    let mut needed = 0u32;
    // SAFETY: a null buffer with a zero length is the documented way to ask how
    // much room the answer needs.
    let _ = unsafe {
        GetTokenInformation(token, TokenPrivileges, None, 0, &mut needed)
    };
    if needed == 0 {
        return Err(PresenceError::Query(
            "the token reported no privileges at all".to_string(),
        ));
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is `needed` bytes, which is what the previous call asked
    // for, and `needed` is written again with the true size.
    unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    }
    .map_err(|e| PresenceError::Query(e.to_string()))?;

    // SAFETY: `GetTokenInformation` with `TokenPrivileges` writes a
    // `TOKEN_PRIVILEGES` followed by `PrivilegeCount` `LUID_AND_ATTRIBUTES`
    // entries at the start of the buffer, and `needed` bytes are initialised.
    // The header is read first so the count comes from the API's own answer
    // rather than from an assumption about the buffer's length.
    let count = unsafe { (buffer.as_ptr() as *const TOKEN_PRIVILEGES).read() }.PrivilegeCount as usize;
    // The offset of the array, not the size of the struct. `TOKEN_PRIVILEGES`
    // declares `Privileges: [LUID_AND_ATTRIBUTES; 1]`, so `size_of` counts one
    // entry *and* the padding after the count — while `GetTokenInformation`
    // reports `offset_of!(Privileges) + n * sizeof(LUID_AND_ATTRIBUTES)`. Using
    // the struct size therefore rejects a token with more than a couple of
    // privileges as "does not fit", which is how this was caught: this machine's
    // own token has five, and the check said the 64 bytes the API asked for
    // could not hold them.
    let header = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let entry = std::mem::size_of::<windows::Win32::Security::LUID_AND_ATTRIBUTES>();
    if header + count * entry > buffer.len() {
        return Err(PresenceError::Query(format!(
            "the token claimed {count} privileges, which does not fit in the {needed} bytes it \
             asked for"
        )));
    }

    // SAFETY: the bounds check above proves every entry is inside `buffer`, and
    // `u32` has no invalid bit patterns, so the cast cannot produce an invalid
    // value.
    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().add(header) as *const windows::Win32::Security::LUID_AND_ATTRIBUTES,
            count,
        )
    };

    for held in entries {
        if held.Luid != wanted {
            continue;
        }
        let attributes = held.Attributes;
        return Ok(if attributes & SE_PRIVILEGE_ENABLED == SE_PRIVILEGE_ENABLED {
            Presence::Enabled
        } else if attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT == SE_PRIVILEGE_ENABLED_BY_DEFAULT {
            // Enabled by default and not currently enabled: the token's own
            // policy turned it off. Treating it as disabled is right, because
            // what the caller asked is whether it is *on*.
            Presence::Disabled
        } else {
            Presence::Disabled
        });
    }
    Ok(Presence::Absent)
}

/// Ask the token about `privilege` on a platform with no token to ask.
///
/// Every one of these answers is [`Presence::Absent`], which is true: this
/// product reads files through Windows APIs exclusively, and the crate compiles
/// elsewhere only so that a doc build and a `cargo check` on another host do
/// not have to be special-cased.
#[cfg(not(windows))]
pub fn query(_privilege: Privilege) -> Result<Presence, PresenceError> {
    Ok(Presence::Absent)
}

/// Turn `privilege` on for this process, and report what the token says
/// afterwards.
///
/// Returns the *observed* state rather than the outcome of the call, because
/// `AdjustTokenPrivileges` returns success when it has assigned nothing — see
/// the module documentation. `Ok(Presence::Absent)` therefore means "asked,
/// and the token does not have it", which is a normal answer for an unelevated
/// process and not an error.
///
/// Calling this when the privilege is already enabled is not an error and does
/// nothing.
#[cfg(windows)]
pub fn enable(privilege: Privilege) -> Result<Presence, PresenceError> {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::Foundation::LUID;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: as in `query`.
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| PresenceError::Open(e.to_string()))?;

    let result = (|| {
        let mut luid = LUID::default();
        let wide = wide_nul(privilege.name());
        // SAFETY: as in `query_with`.
        unsafe {
            LookupPrivilegeValueW(
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR(wide.as_ptr()),
                &mut luid,
            )
        }
        .map_err(|_| PresenceError::UnknownName(privilege.name().to_string()))?;

        let request = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // The last-error value has to be cleared first. `GetLastError` returns
        // the value set by the last call that set one, so without this a stale
        // `ERROR_NOT_ALL_ASSIGNED` from something else in this thread would be
        // read as this call's verdict — and the verdict would be wrong in the
        // direction that turns a working privilege into a reported absence.
        // SAFETY: `SetLastError` accepts any value.
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: the token was opened with `TOKEN_ADJUST_PRIVILEGES`, the
        // request is a well-formed single-entry `TOKEN_PRIVILEGES` that lives
        // for the duration of the call, and the optional previous-state and
        // returned-length parameters are null with a length of zero, which the
        // API documents as "do not report them".
        let adjusted = unsafe { AdjustTokenPrivileges(token, false, Some(&request), 0, None, None) };
        // SAFETY: reading the thread's last-error value has no preconditions.
        let last = unsafe { GetLastError() };

        match adjusted {
            // The documented "succeeded but assigned nothing" case. It is not
            // an error from the API's point of view and it is the case this
            // whole function exists to report correctly.
            Ok(()) if last == ERROR_NOT_ALL_ASSIGNED => Ok(Presence::Absent),
            Ok(()) => Ok(Presence::Enabled),
            Err(e) => Err(PresenceError::Adjust {
                privilege,
                reason: e.to_string(),
            }),
        }
    })();

    // SAFETY: `token` came from `OpenProcessToken`, is still open, and is not
    // used after this point.
    unsafe {
        let _ = CloseHandle(token);
    }

    // Read the token back rather than returning what the call claimed. One
    // extra `GetTokenInformation` per process, once, is nothing next to being
    // wrong about whether a million later reads will be permitted.
    match result {
        Ok(_) => query(privilege),
        Err(e) => Err(e),
    }
}

/// Turn `privilege` on, on a platform with no token.
#[cfg(not(windows))]
pub fn enable(_privilege: Privilege) -> Result<Presence, PresenceError> {
    Ok(Presence::Absent)
}

/// `s` as UTF-16 with a terminating NUL, which is how every `…W` API wants it.
///
/// `pub(crate)` because [`mod@crate::read`] needs the same conversion for paths and
/// two implementations of it would be one too many.
#[cfg(windows)]
pub(crate) fn wide_nul(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    let mut wide: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
    wide.push(0);
    wide
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_are_the_ones_the_api_uses() {
        // A typo here would be a runtime failure rather than a compile error,
        // so it is worth asserting the exact spelling once. These are the
        // strings Microsoft documents for `LookupPrivilegeValueW`.
        assert_eq!(Privilege::Backup.name(), "SeBackupPrivilege");
        assert_eq!(Privilege::Restore.name(), "SeRestorePrivilege");
        assert_eq!(Privilege::ALL.len(), 2);
    }

    #[test]
    fn a_privilege_prints_as_its_name() {
        assert_eq!(Privilege::Backup.to_string(), "SeBackupPrivilege");
        assert_eq!(Presence::Absent.to_string(), "not held");
        assert_eq!(Presence::Disabled.to_string(), "held but disabled");
        assert_eq!(Presence::Enabled.to_string(), "enabled");
    }

    #[test]
    fn every_presence_says_whether_it_is_held_and_enabled() {
        assert!(Presence::Enabled.is_enabled());
        assert!(Presence::Enabled.is_held());
        assert!(!Presence::Disabled.is_enabled());
        assert!(Presence::Disabled.is_held());
        assert!(!Presence::Absent.is_enabled());
        assert!(!Presence::Absent.is_held());
        // "Could not be determined" is neither held nor enabled. Saying it is
        // held would let a caller skip the remedy for a state it has not
        // established.
        assert!(!Presence::Unknown.is_held());
        assert!(!Presence::Unknown.is_enabled());
    }

    #[test]
    fn the_summary_never_claims_a_capability_that_was_not_established() {
        let absent = Privileges {
            backup: Presence::Absent,
            restore: Presence::Absent,
        };
        let sentence = absent.sentence();
        assert!(sentence.contains("cannot read"), "{sentence}");
        assert!(!absent.can_read_anything());

        let unknown = Privileges {
            backup: Presence::Unknown,
            restore: Presence::Unknown,
        };
        assert!(unknown.sentence().contains("could not be determined"));

        let on = Privileges {
            backup: Presence::Enabled,
            restore: Presence::Enabled,
        };
        assert!(on.can_read_anything());
        assert!(on.sentence().contains("can read"));
    }

    #[test]
    #[cfg(windows)]
    fn the_token_can_be_asked_about_a_privilege_it_definitely_has() {
        // Every process token carries this one, whatever the account; it is the
        // baseline that proves the query path works rather than merely
        // returning `Absent` for everything.
        //
        // `SeChangeNotifyPrivilege` is deliberately not in `Privilege`, which
        // is why the name is spelled here: the enum is the two a scanner wants,
        // and this test is about the mechanism rather than the list.
        let mut luid = windows::Win32::Foundation::LUID::default();
        let wide = wide_nul("SeChangeNotifyPrivilege");
        let found = unsafe {
            windows::Win32::Security::LookupPrivilegeValueW(
                windows::core::PCWSTR::null(),
                windows::core::PCWSTR(wide.as_ptr()),
                &mut luid,
            )
        };
        assert!(found.is_ok(), "LookupPrivilegeValueW rejected a real name");

        // And the query path returns *something* rather than an error, for a
        // privilege that is genuinely in this token.
        let presence = query(Privilege::Backup).expect("the token can be asked");
        assert!(
            matches!(
                presence,
                Presence::Enabled | Presence::Disabled | Presence::Absent
            ),
            "{presence:?}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn enabling_reports_what_the_token_says_and_never_lies_about_it() {
        // This test runs unelevated in CI and elevated on a developer's
        // machine, and it has to be correct in both. The assertion is therefore
        // not "the privilege is on" — an unelevated token does not have it and
        // no code can change that — but that the answer agrees with the token.
        let after = enable(Privilege::Backup).expect("enabling reports rather than fails");
        match after {
            Presence::Absent => {
                // Nothing this crate can do; the token does not have it. The
                // honest thing to assert is that a second look agrees, so that
                // `enable` is not reporting a state that does not exist.
                assert!(!after.is_enabled());
                assert_eq!(query(Privilege::Backup).expect("asked again"), after);
            }
            Presence::Enabled => {
                // If it says it turned it on, the token must agree.
                assert_eq!(query(Privilege::Backup).expect("asked again"), Presence::Enabled);
            }
            other => panic!("enabling produced {other:?}, which is neither of the two answers"),
        }
    }

    #[test]
    #[cfg(windows)]
    fn asking_about_a_privilege_costs_nothing_and_changes_nothing() {
        // `query` opens a token and reads it. It must not adjust anything: a
        // status command that silently enabled a privilege would be reporting
        // on a state it had just created.
        let first = query(Privilege::Restore).expect("the token can be asked");
        let second = query(Privilege::Restore).expect("the token can be asked");
        assert_eq!(first, second, "two reads of the same token disagreed");
    }

    #[test]
    fn the_remedy_is_a_sentence_a_user_can_act_on() {
        for privilege in Privilege::ALL {
            let remedy = privilege.remedy();
            assert!(remedy.len() > 20, "{privilege}: {remedy}");
            assert!(
                remedy.contains("elevated") || remedy.contains("Wenle service"),
                "{privilege}: {remedy}"
            );
        }
    }
}
