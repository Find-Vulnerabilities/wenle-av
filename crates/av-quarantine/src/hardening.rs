//! Who is allowed to read the vault, and why the cipher is not enough.
//!
//! # The boundary the cipher is not
//!
//! The payloads are sealed with AES-256-GCM and the key is wrapped by DPAPI, and
//! neither of those is a wall against a program running on this machine:
//! `master.key` sits in the same directory, and any process — as any user — can
//! call the same machine-scope unwrap this crate calls. So the ciphertext buys
//! exactly what [`crate::key`] says it buys: a vault that has left the machine
//! is unreadable, a stolen laptop's samples are not recoverable, and a
//! quarantined file is not a file anybody can run by double-clicking it.
//!
//! The *filesystem* is what has to stop a process that has not left the machine,
//! and until this module existed there was nothing doing that. What the vault
//! inherited from `%ProgramData%` is the default for a directory a standard user
//! created, measured on this machine rather than assumed:
//!
//! ```text
//! SYSTEM:(I)(OI)(CI)(F)   Administrators:(I)(OI)(CI)(F)   <user>:(I)(F)
//! CREATOR OWNER:(I)(OI)(CI)(IO)(F)   Users:(I)(OI)(CI)(RX)   Users:(I)(CI)(WD,AD,WEA,WA)
//! ```
//!
//! The consequence, on a machine where the product is working correctly, is that
//! any non-elevated program can
//!
//! * **delete `master.key`**, which does not merely unlock the vault — it
//!   destroys it. Every payload becomes undecryptable, and a user who was told
//!   their file was safe in quarantine has lost it for good.
//! * **delete payloads**, removing the evidence of what was found and the copy
//!   a false positive would have been restored from.
//! * **read the index**, which names what was detected, when, and the path the
//!   file came from — a list of which malware was burned and where it had got
//!   to, which is exactly what an attacker still resident on the machine wants
//!   to know.
//!
//! # What is set, and what it is worth
//!
//! One protected DACL, applied to the vault root and then to every entry below
//! it:
//!
//! ```text
//! D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<the account that made it>)
//! ```
//!
//! `P` is the load-bearing letter. It marks the DACL *protected*, so it stops
//! inheriting from `%ProgramData%` and the `Users: read` and `CREATOR OWNER`
//! entries above are gone rather than added to. Full control for SYSTEM and
//! Administrators, because the service runs as SYSTEM and both it and the GUI
//! have to open the same vault. Full control for the account that created the
//! directory, and this is the honest limit of the whole exercise: on a machine
//! where an unelevated process does the quarantining, that process **is** the
//! account holding the vault open, so the protection is against *other* users
//! and against the inherited defaults, not against malware running as the same
//! user. Closing that last gap needs the vault written by a service holding a
//! key the user's processes cannot reach, which is a real design and not this
//! one — [`crate::key`] says so as well.
//!
//! An administrator can take ownership of the directory and rewrite the DACL,
//! and no ACL on a filesystem can prevent that. What is being defended here is
//! the unprivileged process, which is the one that actually gets onto a user's
//! machine.
//!
//! # Why the entries below the root are visited one by one
//!
//! Setting the DACL on a directory does **not** update the entries that are
//! already inside it. A child's DACL is a copy taken when the child was created,
//! and Windows leaves that copy alone when the parent's DACL changes — measured
//! on this machine: after restricting the root, an `items` directory and a
//! `master.key` written by the previous version still carried
//! `Users:(I)(OI)(CI)(RX)`, so every user on the machine could still read the
//! key and delete it. An earlier draft of this module asserted the opposite in a
//! comment and was wrong.
//!
//! So [`restrict`] walks the tree. It does not walk it blindly: the entries the
//! vault always has are probed first, and a vault whose entries are already
//! right — which is every vault after its first open by this version — costs two
//! or three descriptor reads and no writes at all.
//!
//! # It never fails the vault
//!
//! [`restrict`] returns what happened rather than an error, and every path
//! through it ends in a vault that opens. A quarantine vault that refused to
//! work because a DACL could not be set would be trading the machine's
//! protection for its own tidiness, which is the wrong way round: a vault with
//! looser permissions still contains the malware.

use std::path::Path;

/// The account the service runs as.
const SYSTEM: &str = "S-1-5-18";
/// The built-in administrators group.
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// How many of the root's entries are probed before deciding whether the tree
/// needs visiting.
///
/// A vault root holds `items`, `master.key`, `index.enc` and, after a damaged
/// index has been moved aside, one `index.corrupt-*.enc` per incident. The
/// ceiling is here so that a directory somebody has filled with junk cannot
/// turn a cheap check into an expensive one.
const PROBES: usize = 64;

/// What was done about the vault's permissions.
///
/// Reported rather than assumed, because the answer differs by how the product
/// was started and a user is entitled to know which of them they got. The two
/// successful shapes are not the same promise and are not collapsed into one
/// variant for that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hardening {
    /// The vault grants full control to SYSTEM and Administrators and to
    /// nothing else. This is the shape an installed product has, where the
    /// service created the directory.
    ServiceOnly,
    /// The same, plus the account that created the directory — which is the
    /// account running the scan when the product is driven from a console.
    OwnerIncluded {
        /// The account, as a SID string.
        account: String,
    },
    /// No ACLs to set on this platform. The vault is protected by the cipher
    /// alone, which is stated rather than passed over.
    Unsupported,
    /// The permissions are not what they should be: either the operating system
    /// refused to set them, or the directory did not report back what was set.
    /// The vault works and its contents are still encrypted.
    Refused {
        /// What went wrong, for the log and for the user.
        detail: String,
    },
}

impl Hardening {
    /// One line for a person.
    ///
    /// Phrased as a statement about who can read the vault rather than about
    /// what the program did, because that is the fact a user is being told and
    /// the one they can act on.
    pub fn describe(&self) -> String {
        match self {
            Self::ServiceOnly => {
                "the vault is readable only by SYSTEM and administrators".to_string()
            }
            Self::OwnerIncluded { account } => format!(
                "the vault is readable by SYSTEM, administrators, and {account} (the account that \
                 created it) — not by other users"
            ),
            Self::Unsupported => {
                "this platform has no file permissions to set, so the vault is protected by \
                 encryption alone"
                    .to_string()
            }
            Self::Refused { detail } => format!(
                "the vault's permissions could not be restricted ({detail}); its contents are \
                 still encrypted, but another user on this machine may be able to read or delete \
                 them"
            ),
        }
    }

    /// Whether the vault ended up restricted to the accounts it should be.
    ///
    /// The refused and unsupported cases are the ones worth a warning, and a
    /// caller that has to decide whether to warn should not be matching on the
    /// variant itself: a new variant added later would then default to silence.
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::ServiceOnly | Self::OwnerIncluded { .. })
    }

    /// The two restricted shapes, told apart by whether the account that made
    /// the directory had to be named alongside SYSTEM and Administrators.
    fn restricted(account: Option<String>) -> Self {
        match account {
            Some(account) => Self::OwnerIncluded { account },
            None => Self::ServiceOnly,
        }
    }
}

/// Restrict the vault at `path` to SYSTEM, Administrators, and its creator.
///
/// Applied to the root and to every entry below it, because a child's DACL is
/// not revisited when its parent's changes — see the module documentation for
/// the measurement that showed it.
///
/// Best-effort by construction: see the module documentation for why this
/// reports instead of failing.
pub fn restrict(path: &Path) -> Hardening {
    platform::restrict(path)
}

#[cfg(windows)]
mod platform {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    use windows::core::{BOOL, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetAce, GetAclInformation, GetFileSecurityW, GetSecurityDescriptorDacl,
        GetTokenInformation, SetFileSecurityW, TokenUser, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{Hardening, ADMINISTRATORS, PROBES, SYSTEM};

    /// A file or directory flagged as a reparse point.
    ///
    /// Junctions are directories with this attribute rather than symlinks, and
    /// following one out of the vault while re-writing permissions would be a
    /// way to make the product damage something outside it.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    /// Set the DACL on the vault root and on everything already inside it, and
    /// say what shape it ended up.
    pub(super) fn restrict(path: &Path) -> Hardening {
        let account = match current_user_sid() {
            Ok(sid) => sid,
            // Without the account that is running, the vault cannot be
            // restricted *and* remain writable by the process that has to write
            // to it. Guessing is not available: an ACL that leaves out the
            // caller locks the product out of its own quarantine.
            Err(detail) => return Hardening::Refused { detail },
        };

        let allowed = allowed_accounts(account.as_deref());
        let owner = match &account {
            // SYSTEM and an administrator are already in the list, and an ACE
            // repeated for the same SID is noise in every tool that displays it.
            Some(sid) if sid != SYSTEM && sid != ADMINISTRATORS => Some(sid.clone()),
            _ => None,
        };
        let sddl = sddl_for(&allowed);

        if let Err(detail) = apply(path, &sddl) {
            return Hardening::Refused { detail };
        }
        // Read back rather than trusted. `SetFileSecurityW` returning success
        // means the call was accepted, and what a directory then reports is the
        // fact a user's own tools will show — so the claim this function makes
        // is the claim that was measured.
        match acl_sids(path) {
            Some(sids) if same_set(&sids, &allowed) => {}
            Some(sids) => {
                return Hardening::Refused {
                    detail: format!(
                        "the permissions were set but the vault reports {sids:?} instead of \
                         {allowed:?}"
                    ),
                }
            }
            None => {
                return Hardening::Refused {
                    detail: "the permissions were set but the vault's own permissions could not \
                             be read back"
                        .to_string(),
                }
            }
        }

        if stale(path, &allowed) {
            let fixed = reprotect(path, &sddl, &allowed);
            // Worth a line even when it is zero: "the vault was written by an
            // older version" is the answer to "why did opening take a second".
            log::info!(
                "the quarantine vault at {} held entries from before its permissions were \
                 restricted; {fixed} of them were re-protected",
                path.display()
            );
        }

        let outcome = Hardening::restricted(owner);
        log::info!(
            "the quarantine vault at {} is now restricted: {}",
            path.display(),
            outcome.describe()
        );
        outcome
    }

    /// The accounts the vault grants to: the two that always have to reach it,
    /// and the account that created it when that is a third one.
    ///
    /// Visible to the tests so that they can state the expected set without
    /// restating the rule, which would let the rule change and the test not.
    pub(super) fn allowed_accounts(account: Option<&str>) -> Vec<String> {
        let mut allowed = vec![SYSTEM.to_string(), ADMINISTRATORS.to_string()];
        if let Some(sid) = account {
            if sid != SYSTEM && sid != ADMINISTRATORS {
                allowed.push(sid.to_string());
            }
        }
        allowed
    }

    /// The SDDL string that grants exactly `allowed` full control, inherited,
    /// and inherits nothing itself.
    fn sddl_for(allowed: &[String]) -> String {
        let mut sddl = String::from("D:P");
        for sid in allowed {
            sddl.push_str(&format!("(A;OICI;FA;;;{sid})"));
        }
        sddl
    }

    /// Whether two lists name the same accounts, order aside.
    fn same_set(left: &[String], right: &[String]) -> bool {
        left.len() == right.len() && left.iter().all(|sid| right.contains(sid))
    }

    /// Whether any entry directly inside `root` still carries permissions the
    /// vault no longer grants.
    ///
    /// Cheap on purpose: the walk it guards visits every payload, and the whole
    /// point of it is that a vault which is already correct — every vault after
    /// its first open by this version — costs nothing but this check.
    fn stale(root: &Path, allowed: &[String]) -> bool {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            // Unreadable here is not worth failing over: the walk below would
            // find nothing either, and the root itself has just been verified.
            Err(_) => return false,
        };
        for entry in entries.flatten().take(PROBES) {
            match acl_sids(&entry.path()) {
                Some(sids) if same_set(&sids, allowed) => {}
                // A missing descriptor is treated as stale: an entry whose
                // permissions cannot be read is one whose permissions cannot be
                // vouched for.
                _ => return true,
            }
        }
        false
    }

    /// Give every entry under `root` the vault's permissions, and report how
    /// many needed them.
    ///
    /// Entries that are already correct are left untouched, so a vault with one
    /// old payload does not rewrite the DACL of a thousand new ones.
    ///
    /// A reparse point is skipped rather than followed: its target is outside
    /// the vault, and rewriting the target's permissions from here would be this
    /// function doing damage on the say-so of whoever put the link there.
    fn reprotect(root: &Path, sddl: &str, allowed: &[String]) -> usize {
        let mut fixed = 0usize;
        let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(e) => {
                    log::debug!(
                        "a vault directory could not be listed while re-protecting it: {}: {e}",
                        directory.display()
                    );
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    continue;
                }
                let is_stale = match acl_sids(&path) {
                    Some(sids) => !same_set(&sids, allowed),
                    None => true,
                };
                if is_stale {
                    match apply(&path, sddl) {
                        Ok(()) => fixed += 1,
                        Err(e) => log::warn!(
                            "an entry in the quarantine vault could not be re-protected: {}: {e}",
                            path.display()
                        ),
                    }
                }
                if metadata.is_dir() {
                    pending.push(path);
                }
            }
        }
        fixed
    }

    /// Apply one SDDL string as a protected DACL.
    pub(super) fn apply(path: &Path, sddl: &str) -> Result<(), String> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call. `descriptor` is a zeroed out-parameter that the API fills with
        // a `LocalAlloc` allocation on success, released below on both paths.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| format!("the permission string was refused: {e}"))?;

        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the descriptor came from the conversion above and is still
        // owned here; the path is NUL-terminated and lives for the call.
        // `SetFileSecurityW` reads the DACL out of it and does not keep it.
        let applied = unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                // Protected as well as set: this is the flag that stops the
                // directory inheriting `%ProgramData%`'s entries back.
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        // The failure reason has to be read before anything else runs, because
        // the API reports it through the thread's last error and the call below
        // can overwrite that.
        let failure = applied.ok().err();
        // SAFETY: the descriptor was allocated by the conversion call above and
        // has not been freed; freeing it is the documented release.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }

        match failure {
            Some(e) => Err(format!("the operating system refused the permissions: {e}")),
            None => Ok(()),
        }
    }

    /// Every account a file or directory's DACL names, in the order it holds
    /// them.
    ///
    /// `None` when there is no DACL to read — which is not the same as an empty
    /// one, and both mean the same thing to the caller: the permissions could
    /// not be vouched for. A null DACL in particular grants everyone everything,
    /// so it must not read as "no accounts to worry about".
    ///
    /// Only plain allow and deny entries are read. An object-control ACE has a
    /// different layout, and one appearing here means the DACL was not written
    /// by this module — reported as unreadable rather than parsed into a wrong
    /// answer.
    fn acl_sids(path: &Path) -> Option<Vec<String>> {
        /// The SID of an `ACCESS_ALLOWED_ACE` or `ACCESS_DENIED_ACE` begins
        /// after the 4-byte header and the 4-byte access mask.
        const SID_OFFSET: usize = 8;
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut needed = 0u32;
        // SAFETY: a null descriptor with a zero length is the documented way to
        // ask for the size; failing with an insufficient-buffer error and
        // filling in `needed` is the expected outcome.
        let _ = unsafe {
            GetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                None,
                0,
                &mut needed,
            )
        };
        if needed == 0 {
            return None;
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, which the call above
        // said is enough for this information class.
        // `GetFileSecurityW` reports through its return value rather than
        // through the thread's last error, unlike `SetFileSecurityW`'s `BOOL`
        // sibling in the same header — so this is the whole check.
        if !unsafe {
            GetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _)),
                needed,
                &mut needed,
            )
        }
        .as_bool()
        {
            return None;
        }

        let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _);
        let mut present = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = BOOL::default();
        // SAFETY: the descriptor is the one just written into `buffer`, which is
        // alive for the rest of the function.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .ok()?;
        if !present.as_bool() || dacl.is_null() {
            return None;
        }

        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` points at a valid ACL and `size` is the structure that
        // information class documents.
        unsafe {
            GetAclInformation(
                dacl,
                &mut size as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                windows::Win32::Security::AclSizeInformation,
            )
        }
        .ok()?;

        let mut sids = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: the index is below the count just read out of the ACL.
            unsafe { GetAce(dacl, index, &mut ace) }.ok()?;
            // SAFETY: `ace` points at an ACE header inside the ACL.
            let kind = unsafe { *(ace as *const u8) };
            if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_DENIED_ACE_TYPE {
                return None;
            }
            // SAFETY: the offset is inside an ACE of one of the two types
            // checked above, and points at that ACE's SID.
            let sid = unsafe { (ace as *const u8).add(SID_OFFSET) } as *mut std::ffi::c_void;
            let mut raw = PWSTR::null();
            // SAFETY: `sid` points at a SID inside the ACE.
            unsafe { ConvertSidToStringSidW(PSID(sid), &mut raw) }.ok()?;
            // SAFETY: the API allocated a NUL-terminated wide string.
            let text = unsafe { raw.to_string() }.ok()?;
            // SAFETY: the string came from `LocalAlloc` and has been copied.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(raw.0 as *mut std::ffi::c_void)));
            }
            sids.push(text);
        }
        Some(sids)
    }

    /// The SID of the account this process runs as, as a string.
    ///
    /// Visible to the tests for the same reason as [`allowed_accounts`].
    pub(super) fn current_user_sid() -> Result<Option<String>, String> {
        // SAFETY: `GetCurrentProcess` takes no arguments and returns a
        // pseudo-handle that must not be closed.
        let process = unsafe { GetCurrentProcess() };
        let mut token = HANDLE::default();
        // SAFETY: `process` is the current-process pseudo-handle, and `token`
        // is an out-parameter the API fills on success.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|e| format!("this process's token could not be opened: {e}"))?;

        // The size is asked for first because a token's user information is
        // variable-length and there is no documented bound to allocate against.
        let mut needed = 0u32;
        // SAFETY: a null buffer with a zero length is the documented way to ask
        // for the size; the call is expected to fail with
        // `ERROR_INSUFFICIENT_BUFFER` and fill in `needed`.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        if needed == 0 {
            // SAFETY: the handle was opened above and is not used afterwards.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
            return Err("this process's token reported no user".to_string());
        }

        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, which the call above
        // said is enough for this information class.
        let filled = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                needed,
                &mut needed,
            )
        };
        // SAFETY: as above; the token is no longer needed either way.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
        filled.map_err(|e| format!("this process's user could not be read: {e}"))?;

        // SAFETY: the call succeeded, so the buffer holds a `TOKEN_USER` whose
        // `User.Sid` points into that same buffer, which is alive here.
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        sid_to_string(user.User.Sid)
    }

    /// A SID as its `S-1-5-...` string form.
    fn sid_to_string(sid: PSID) -> Result<Option<String>, String> {
        let mut raw = PWSTR::null();
        // SAFETY: `sid` points at a valid SID inside a live buffer, and `raw`
        // is an out-parameter the API points at a `LocalAlloc` string on
        // success, copied out and freed immediately below.
        unsafe { ConvertSidToStringSidW(sid, &mut raw) }
            .map_err(|e| format!("this process's user could not be named: {e}"))?;
        // SAFETY: on success `raw` points at a NUL-terminated wide string
        // allocated by the API.
        let text = unsafe { raw.to_string() }.map_err(|e| e.to_string());
        // SAFETY: the string came from `LocalAlloc` inside the API and has been
        // copied out; this is its documented release.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(raw.0 as *mut std::ffi::c_void)));
        }
        text.map(Some)
    }
}

/// ACLs are a Windows idea; elsewhere the vault is protected by the cipher.
#[cfg(not(windows))]
mod platform {
    use std::path::Path;

    use super::Hardening;

    /// No ACLs to set on this platform.
    pub(super) fn restrict(_path: &Path) -> Hardening {
        Hardening::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    #[test]
    fn restricting_a_directory_reports_what_it_did() {
        let root = dir();
        let outcome = restrict(root.path());
        // On Windows this must be one of the two restricted shapes: the test
        // directory is created by the account running the tests, and setting a
        // DACL on a directory one owns is something an unprivileged process may
        // do. A refusal here would be a real failure, not an environment quirk.
        #[cfg(windows)]
        assert!(
            outcome.is_restricted(),
            "restricting a directory this process owns must succeed, got {outcome:?}"
        );
        #[cfg(not(windows))]
        assert_eq!(outcome, Hardening::Unsupported);
    }

    #[test]
    fn every_outcome_says_something_a_user_can_act_on() {
        // The refused and unsupported cases are the ones that matter: each has
        // to tell the user what protection they *do* have, because the sentence
        // a user reads when the ACL could not be set is the only warning they
        // will get.
        let refused = Hardening::Refused {
            detail: "access is denied".to_string(),
        };
        assert!(refused.describe().contains("access is denied"));
        assert!(refused.describe().contains("still encrypted"));
        assert!(!refused.is_restricted());

        assert!(Hardening::Unsupported.describe().contains("encryption"));
        assert!(!Hardening::Unsupported.is_restricted());

        assert!(Hardening::ServiceOnly.describe().contains("administrators"));
        assert!(Hardening::ServiceOnly.is_restricted());

        let owner = Hardening::OwnerIncluded {
            account: "S-1-5-21-1-2-3-1001".to_string(),
        };
        assert!(owner.describe().contains("S-1-5-21-1-2-3-1001"));
        assert!(owner.is_restricted());
    }

    #[cfg(windows)]
    mod windows_acl {
        use super::*;
        use std::os::windows::ffi::OsStrExt as _;

        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{
            GetAce, GetAclInformation, GetFileSecurityW, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        };

        /// What a directory's DACL actually says, as Windows reports it.
        ///
        /// Deliberately a second implementation of the read the production code
        /// does, rather than a call into it: a test that asks the code under
        /// test what it did is not a test. This one reads the descriptor
        /// straight from the API and names every SID it finds, so the two
        /// disagreeing is itself a finding.
        fn acl_sids(path: &Path) -> (Vec<String>, bool) {
            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut needed = 0u32;
            // SAFETY: a null descriptor with a zero length is the documented
            // way to ask for the size; failure with insufficient buffer is the
            // expected outcome.
            let _ = unsafe {
                GetFileSecurityW(
                    PCWSTR(wide.as_ptr()),
                    DACL_SECURITY_INFORMATION.0,
                    None,
                    0,
                    &mut needed,
                )
            };
            assert!(needed > 0, "the security descriptor has no size");
            let mut buffer = vec![0u8; needed as usize];
            // SAFETY: the buffer is at least `needed` bytes, which the call
            // above said is enough.
            unsafe {
                GetFileSecurityW(
                    PCWSTR(wide.as_ptr()),
                    DACL_SECURITY_INFORMATION.0,
                    Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _)),
                    needed,
                    &mut needed,
                )
            }
            .expect("reading back the security descriptor");

            let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _);
            let mut control = Default::default();
            let mut revision = 0u32;
            // SAFETY: the descriptor is the one just written into `buffer`.
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                .expect("reading the descriptor control");
            let protected = (control & SE_DACL_PROTECTED.0) != 0;

            let mut present = Default::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut defaulted = Default::default();
            // SAFETY: as above; the returned ACL points into `buffer`, which is
            // alive for the rest of the function.
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            }
            .expect("reading the descriptor's DACL");
            assert!(present.as_bool(), "the descriptor has no DACL");
            assert!(!dacl.is_null(), "the DACL is null");

            let mut size = ACL_SIZE_INFORMATION::default();
            // SAFETY: `dacl` points at a valid ACL and `size` is the
            // information structure that class documents.
            unsafe {
                GetAclInformation(
                    dacl,
                    &mut size as *mut _ as *mut std::ffi::c_void,
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    windows::Win32::Security::AclSizeInformation,
                )
            }
            .expect("reading the ACL size");

            let mut sids = Vec::new();
            for index in 0..size.AceCount {
                let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
                // SAFETY: the index is below the count just read out of the ACL.
                unsafe { GetAce(dacl, index, &mut ace) }.expect("reading an ACE");
                // The SID of an ACCESS_ALLOWED_ACE begins after the 4-byte ACE
                // header and the 4-byte access mask.
                let sid = unsafe { (ace as *const u8).add(8) } as *mut std::ffi::c_void;
                let mut raw = PWSTR::null();
                // SAFETY: `sid` points at a SID inside the ACE.
                unsafe { ConvertSidToStringSidW(PSID(sid), &mut raw) }.expect("naming a SID");
                // SAFETY: the API allocated a NUL-terminated wide string.
                sids.push(unsafe { raw.to_string() }.expect("a SID string"));
                // SAFETY: the string came from `LocalAlloc` and has been copied.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(raw.0 as *mut std::ffi::c_void)));
                }
            }
            (sids, protected)
        }

        /// The accounts the vault must end up granting to, as the test sees
        /// them: SYSTEM, Administrators, and whoever is running the tests.
        fn expected() -> Vec<String> {
            let account = platform::current_user_sid()
                .expect("this process's user")
                .expect("a token always has a user");
            platform::allowed_accounts(Some(&account))
        }

        /// A DACL that grants Everyone full control.
        ///
        /// Used to build the state the real bug produced: an entry inside the
        /// vault that still grants to an account the vault has decided to
        /// exclude.
        const LOOSE: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)";

        #[test]
        fn the_directory_ends_up_protected_and_names_only_the_accounts_it_should() {
            let root = dir();
            assert!(restrict(root.path()).is_restricted());
            let (sids, protected) = acl_sids(root.path());
            let allowed = expected();

            assert!(
                protected,
                "the DACL must be protected, or %ProgramData%'s Users:read and CREATOR OWNER \
                 entries come straight back: {sids:?}"
            );
            assert!(
                sids.iter().all(|sid| allowed.contains(sid)),
                "the vault grants to somebody it should not: {sids:?} against {allowed:?}"
            );
            assert!(
                sids.iter().any(|s| s == "S-1-5-18"),
                "SYSTEM must keep full control — the service runs as it: {sids:?}"
            );
            assert!(
                sids.iter().any(|s| s == "S-1-5-32-544"),
                "Administrators must keep full control: {sids:?}"
            );
            assert!(
                !sids.iter().any(|s| s == "S-1-5-11" || s == "S-1-1-0"),
                "Authenticated Users and Everyone must be gone: {sids:?}"
            );
        }

        #[test]
        fn an_entry_written_after_the_restriction_gets_the_same_permissions() {
            // The property that makes doing this at open worth anything: the key
            // and every payload are written later, and none of them may be
            // readable by the accounts the vault excludes.
            let root = dir();
            assert!(restrict(root.path()).is_restricted());
            let allowed = expected();

            let child = root.path().join("items");
            std::fs::create_dir(&child).expect("creating a child directory");
            let payload = child.join("payload.qtn");
            std::fs::write(&payload, b"sealed").expect("writing a child file");

            for path in [child, payload] {
                let (sids, _) = acl_sids(&path);
                assert!(
                    sids.iter().all(|sid| allowed.contains(sid)),
                    "{} grants to an account the vault excludes: {sids:?} against {allowed:?}",
                    path.display()
                );
                assert_eq!(
                    sids.len(),
                    allowed.len(),
                    "{} should grant to exactly the vault's accounts: {sids:?}",
                    path.display()
                );
            }
        }

        #[test]
        fn an_entry_written_before_the_restriction_is_re_protected() {
            // The regression this module was written twice for. Measured on a
            // real machine: restricting the root left `items` and `master.key`
            // still granting `Users:(I)(OI)(CI)(RX)`, because Windows does not
            // revisit a child's DACL when its parent's changes. The state below
            // is that state, built directly.
            let root = dir();
            let child = root.path().join("items");
            std::fs::create_dir(&child).expect("creating a child directory");
            let payload = child.join("old.qtn");
            std::fs::write(&payload, b"sealed").expect("writing a child file");

            // Everyone, full control, on the child and on the file inside it.
            platform::apply(&child, LOOSE).expect("loosening the child");
            platform::apply(&payload, LOOSE).expect("loosening the payload");
            let (before, _) = acl_sids(&child);
            assert!(
                before.iter().any(|s| s == "S-1-1-0"),
                "the test did not manage to build the state it is about: {before:?}"
            );

            assert!(restrict(root.path()).is_restricted());

            let allowed = expected();
            for path in [child, payload] {
                let (sids, _) = acl_sids(&path);
                assert_eq!(
                    sids.len(),
                    allowed.len(),
                    "{} was left with the permissions it had before the vault was restricted: \
                     {sids:?}",
                    path.display()
                );
                assert!(
                    sids.iter().all(|sid| allowed.contains(sid)),
                    "{} still grants to an account the vault excludes: {sids:?}",
                    path.display()
                );
            }
        }

        #[test]
        fn a_restricted_directory_can_still_be_written_to_and_removed_by_its_creator() {
            // The failure mode that would make this feature a bug: an ACL that
            // keeps other users out and the product out as well. The vault has
            // to stay writable by the process that just restricted it, and a
            // temporary directory has to remain disposable.
            let root = dir();
            assert!(restrict(root.path()).is_restricted());
            let file = root.path().join("index.enc");
            std::fs::write(&file, b"sealed").expect("writing inside a restricted vault");
            std::fs::remove_file(&file).expect("removing a file from a restricted vault");
            std::fs::create_dir(root.path().join("items")).expect("creating a directory");
            let path = root.path().to_path_buf();
            root.close().expect("removing the restricted directory");
            assert!(!path.exists());
        }
    }
}
