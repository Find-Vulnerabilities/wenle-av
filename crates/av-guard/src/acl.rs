//! Reading a DACL back, and asking it what it grants to whom.
//!
//! # Why this is a module of its own
//!
//! Two modules in this crate do the same four things to two different kinds of
//! object. [`crate::files`] hardens *named* objects (the install directory, the
//! database directory, the configuration and the log directory) and reads their
//! permissions back through `GetNamedSecurityInfoW`. [`crate::process`] hardens
//! a *kernel* object (a running process) and reads its permissions back
//! through `GetSecurityInfo` on a handle, because a process has no name to open
//! it by. Everything else is identical: convert an SDDL string into a
//! descriptor, apply it as a protected DACL, enumerate the ACEs, and evaluate
//! what a given trustee ends up with.
//!
//! Writing that four times over would mean four places where the ACE layout
//! could be misread, and a misread ACE is not a cosmetic bug: the whole point of
//! both modules is a *claim about what another user can do*, and an ACE reader
//! that skips the wrong eight bytes makes that claim false while looking
//! entirely correct. One reader, tested once, is the only shape that is worth
//! trusting.
//!
//! # Why SDDL and not a hand-built ACL
//!
//! Every DACL this crate applies is written as a string,
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` turns it into a
//! descriptor, and that descriptor is handed to `SetNamedSecurityInfoW` or
//! `SetSecurityInfo`. The alternative (`InitializeAcl`, then one
//! `AddAccessAllowedAce` per entry with a SID built by hand) is what the
//! quarantine vault does in `av-quarantine/src/hardening.rs`, and the vault has
//! a reason that does not apply here: it has to *rename* a trustee, substituting
//! the SID of the account that created the vault for a placeholder, and SDDL has
//! no syntax for that. Nothing in this crate needs to build a SID at run time.
//! What SDDL buys instead is that the security policy this crate enforces is a
//! string a person can read, quote in a bug report and compare against `icacls`
//! output, rather than an arithmetic sequence of eight-bit ACE headers.
//!
//! # ACE order, which is the one thing that can silently invert a policy
//!
//! A DACL is evaluated in order, and a deny ACE that matches a SID in the
//! caller's token denies those bits *and ends the check*: a later allow ACE
//! cannot give them back. That is why every DACL in this crate is an allow
//! list with no deny ACEs in it at all: see [`crate::process`] for the
//! measurement showing what a "deny to Everyone" DACL actually does to SYSTEM.
//!
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` preserves the order of
//! the ACEs in the string. It does not reorder them into the canonical
//! deny-first order, and it does not need to here, because there are no denies
//! to order.
//!
//! # What is deliberately not resolved
//!
//! A trustee's *account name* is not looked up. [`describe`] names the six SIDs
//! whose meaning is fixed by Windows and prints every other SID in its
//! `S-1-5-21-...` form. `LookupAccountSidW` would translate the rest, and it
//! consults a domain controller for a SID the local machine does not know, and a
//! self-protection check that blocks for thirty seconds on a network timeout is
//! a self-protection check that gets run once and then removed from the startup
//! path, and this product does not talk to the network to reach a verdict
//! anywhere else either. A SID is unambiguous without its name; it is only less
//! friendly to read.

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    GetAce, GetAclInformation, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};

/// `NT AUTHORITY\SYSTEM`.
pub(crate) const SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub(crate) const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `BUILTIN\Users`.
pub(crate) const USERS: &str = "S-1-5-32-545";
/// `Everyone`, which Windows calls `World` in SDDL and displays as `Everyone`.
pub(crate) const EVERYONE: &str = "S-1-1-0";
/// `NT AUTHORITY\Authenticated Users`.
pub(crate) const AUTHENTICATED_USERS: &str = "S-1-5-11";
/// `NT AUTHORITY\INTERACTIVE`, the logon type of a person sitting at the
/// machine.
pub(crate) const INTERACTIVE: &str = "S-1-5-4";

/// The trustees every check in this crate evaluates, with the SID an
/// unprivileged principal is guaranteed to hold.
///
/// This is the list that makes "can a non-elevated user do this?" answerable
/// without knowing which user is asking. Every interactive logon on Windows
/// carries [`EVERYONE`], [`AUTHENTICATED_USERS`] and [`USERS`], and an
/// interactive logon carries [`INTERACTIVE`] as well. So the *union* of what
/// those four SIDs are granted is an **upper bound** on what any unprivileged
/// principal can be granted by this DACL — it can over-report access and it
/// cannot under-report it, which is the direction a warning about a weak
/// permission has to err in.
///
/// It is an upper bound and not an equality, and the difference is worth being
/// precise about: a DACL that named one specific user's SID and nobody else's
/// would grant that user far more than this list reports, because none of these
/// four SIDs is that user. That case is covered separately — every report also
/// evaluates the SID of the account *running the check*, and enumerates every
/// SID the DACL actually names.
pub(crate) const UNPRIVILEGED_TRUSTEES: [&str; 4] =
    [EVERYONE, AUTHENTICATED_USERS, USERS, INTERACTIVE];

/// True when a SID is one this crate treats as privileged — an account that is
/// allowed to rewrite any of these DACLs and therefore is not the threat.
pub(crate) fn is_privileged(sid: &str) -> bool {
    sid == SYSTEM || sid == ADMINISTRATORS
}

/// The name Windows displays for the SIDs whose meaning is fixed, or `None` for
/// a SID that would have to be looked up.
///
/// See the module documentation for why the lookup is not done.
pub(crate) fn describe(sid: &str) -> Option<&'static str> {
    match sid {
        SYSTEM => Some("NT AUTHORITY\\SYSTEM"),
        ADMINISTRATORS => Some("BUILTIN\\Administrators"),
        USERS => Some("BUILTIN\\Users"),
        EVERYONE => Some("Everyone"),
        AUTHENTICATED_USERS => Some("NT AUTHORITY\\Authenticated Users"),
        INTERACTIVE => Some("NT AUTHORITY\\INTERACTIVE"),
        _ => None,
    }
}

/// A SID this value owns.
///
/// Holds its own `LocalAlloc` allocation for the SID's bytes, because
/// `GetEffectiveRightsFromAclW` needs a pointer that is valid for the duration
/// of the call and the conversion that produced it is the caller's to free.
///
/// The string it was parsed from is deliberately *not* kept. An earlier version
/// kept it and used it to check the round trip in a test, which was checking the
/// conversion against a copy of its own input; the test now converts the SID back
/// with [`sid_to_string`] and compares that, so the check is against the
/// operating system. Nothing else wanted the string, and a field carried for one
/// test is a field the next reader has to work out the purpose of.
#[derive(Debug)]
pub(crate) struct OwnedSid {
    pointer: PSID,
}

impl OwnedSid {
    /// Convert an `S-1-5-...` string into a SID.
    ///
    /// Failure is a malformed string, which is a bug in this crate rather than
    /// anything about the machine, so the message says which string.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pointer = PSID::default();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call, and `pointer` is a zeroed out-parameter the API fills with a
        // `LocalAlloc` allocation on success. That allocation is released in
        // `Drop` and nowhere else.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut pointer) }
            .map_err(|error| format!("`{text}` is not a valid SID: {error}"))?;
        Ok(Self { pointer })
    }

    /// The SID itself, for a call that wants one.
    pub(crate) fn psid(&self) -> PSID {
        self.pointer
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: `ConvertStringSidToSidW` allocates with `LocalAlloc` and
        // documents `LocalFree` as the release; this is the only place that
        // frees it, and the pointer is not used afterwards.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.pointer.0)));
        }
    }
}

/// One entry of a DACL, as much of it as this crate reads.
///
/// Derived from the ACE header rather than from the access mask alone, because
/// the *kind* of ACE decides whether the mask grants or denies and whether the
/// entry applies to the object or only to its children. An inherit-only entry
/// that a reader mistook for a grant is the difference between "a user can write
/// this directory" and "a user can write things created inside it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    /// The trustee, as an `S-1-5-...` string.
    pub(crate) sid: String,
    /// The access mask, with the four generic bits still in it.
    pub(crate) mask: u32,
    /// True for an `ACCESS_DENIED_ACE`.
    pub(crate) denied: bool,
    /// True when the entry came from the parent rather than this object.
    pub(crate) inherited: bool,
    /// True when the entry applies to child objects (`OI`).
    pub(crate) object_inherit: bool,
    /// True when the entry applies to child containers (`CI`).
    pub(crate) container_inherit: bool,
    /// True when the entry is `IO` — inherited by children only, and *not*
    /// applied to the object it sits on.
    pub(crate) inherit_only: bool,
}

/// A security descriptor kept alive for as long as this value, with the DACL
/// inside it read out once.
///
/// The descriptor is allocated by the operating system and released on drop.
/// Nothing here copies it, because the ACL pointer a caller gets points into
/// it — a copy would be a buffer to keep in step with a second buffer.
pub(crate) struct Dacl {
    descriptor: PSECURITY_DESCRIPTOR,
    acl: *const ACL,
}

impl Dacl {
    /// Read the DACL of a named object — a file or a directory.
    ///
    /// `GetNamedSecurityInfoW` materialises inheritance, so what comes back is
    /// the DACL as it *applies* to this object and not merely the entries stored
    /// on it. That distinction matters for everything this crate reports: a file
    /// inside a restricted directory has an empty stored DACL and an effective
    /// one that grants what its parent does, and a reader of the stored entries
    /// would say "nothing is granted", which is the exact opposite of the truth.
    pub(crate) fn of_path(path: &Path) -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt as _;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated narrow string that outlives the
        // call. The three `None`s are the owner, group and SACL, none of which
        // this crate reads, and `descriptor` is an out-parameter that the API
        // fills with a `LocalAlloc` allocation on success — released in `Drop`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut acl),
                None,
                &mut descriptor,
            )
        };
        Self::finish(status, descriptor, acl, path.display().to_string())
    }

    /// The account that owns a file or a directory, as an `S-1-5-...` string.
    ///
    /// The file-side counterpart of [`Dacl::owner_of_process`], and needed for
    /// the same measured reason: Windows grants an object's owner rights outside
    /// the DACL, and `GetEffectiveRightsFromAclW` reports those rights as though
    /// the DACL had granted them. Measured on this machine, on a directory whose
    /// permission list names only `SYSTEM`, `Administrators` and `Users` with
    /// read-and-execute: the owning account evaluates to `0x001f01ff` —
    /// `FILE_ALL_ACCESS` — and every other trustee evaluates to `0`. That is the
    /// same shape as the process measurement (`0x001f0fff` for an owner whose
    /// DACL does not name it), which is what makes it a property of the function
    /// rather than a fact about processes.
    ///
    /// So a caller that evaluates permission lists must know who the owner is
    /// before it can believe an answer about them. See `crate::files` for what
    /// the audit does with this and why the owner is reported separately instead
    /// of being folded into the answer.
    ///
    /// Read with `OWNER_SECURITY_INFORMATION` rather than as part of the DACL
    /// read, because the two are separate questions and a caller that does not
    /// care about the owner should not pay for the read.
    pub(crate) fn owner_of_path(path: &Path) -> Result<String, String> {
        use std::os::windows::ffi::OsStrExt as _;

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut owner = PSID::default();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call. The `None`s are the group, DACL and SACL; `owner` points into the
        // descriptor allocated on success, and the SID is copied to a string
        // before the descriptor is released below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status != WIN32_ERROR(0) {
            return Err(format!(
                "the owner of {} could not be read (Win32 error {})",
                path.display(),
                status.0
            ));
        }
        // SAFETY: on success the descriptor is ours to release and the SID points
        // into it; the string is copied out before the release, because the SID is
        // freed with the descriptor.
        let text = unsafe {
            let text = sid_to_string(owner);
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            text
        };
        text.ok_or_else(|| {
            format!(
                "the owner of {} is a SID that could not be turned into a string",
                path.display()
            )
        })
    }

    /// Read the DACL of a kernel object — here, a process.
    ///
    /// A process has no name, so `GetNamedSecurityInfoW` is unavailable and the
    /// handle-based `GetSecurityInfo` is the call. It takes the same
    /// `SE_KERNEL_OBJECT` class `SetSecurityInfo` takes on the way in, so the
    /// read and the write cannot disagree about what kind of object they are
    /// talking about.
    ///
    /// The handle must already carry `READ_CONTROL`; a denial is reported as a
    /// denial rather than as an empty DACL.
    pub(crate) fn of_process(handle: HANDLE) -> Result<Self, String> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `handle` is a live handle owned by the caller. The `None`s are
        // the owner, group and SACL, and `descriptor` is an out-parameter the
        // API allocates into on success and `Drop` releases.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut acl),
                None,
                Some(&mut descriptor),
            )
        };
        Self::finish(status, descriptor, acl, "the process object".to_string())
    }

    /// The account that owns a process object, as an `S-1-5-...` string.
    ///
    /// The owner matters to a security report for a reason the DACL cannot
    /// express: Windows grants an object's owner rights *outside* the DACL, so
    /// an account can reach a process that its DACL does not name it on. Measured
    /// on this machine, and the measurement is in [`crate::process`]: the owning
    /// account of a protected process object evaluates to `0x001f0fff` —
    /// `PROCESS_ALL_ACCESS` — on a DACL that names only `SYSTEM`,
    /// `Administrators` and `INTERACTIVE`. A report that read the DACL and
    /// stopped there would call that process protected from its own owner, which
    /// is the one thing it is not.
    ///
    /// Read with `OWNER_SECURITY_INFORMATION` on the same descriptor read as the
    /// DACL rather than with a second call, because a second call is a second
    /// chance for the object to have changed between the two reads.
    pub(crate) fn owner_of_process(handle: HANDLE) -> Result<String, String> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut owner = PSID::default();
        // SAFETY: `handle` is a live handle owned by the caller. The `None`s are
        // the group, DACL and SACL; `owner` points into the descriptor allocated
        // on success, and the SID is copied to a string before the descriptor is
        // released below.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        if status != WIN32_ERROR(0) {
            return Err(format!(
                "the owner of the process object could not be read (Win32 error {})",
                status.0
            ));
        }
        // SAFETY: on success the descriptor is ours to release and the SID
        // points into it; the string is copied out before the release, because
        // the SID is freed with the descriptor.
        let text = unsafe {
            let text = sid_to_string(owner);
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            text
        };
        text.ok_or_else(|| "the owner's SID could not be turned into a string".to_string())
    }

    /// The shared tail of both readers: turn a status and a descriptor into a
    /// `Dacl`, releasing the descriptor if the call failed.
    fn finish(
        status: WIN32_ERROR,
        descriptor: PSECURITY_DESCRIPTOR,
        acl: *mut ACL,
        what: String,
    ) -> Result<Self, String> {
        if status != WIN32_ERROR(0) {
            // A failed call still hands back a descriptor in some cases, and a
            // leak per failed check would be a leak on the path that runs when
            // something is already wrong.
            if !descriptor.is_invalid() {
                // SAFETY: the descriptor came from the API above and has not
                // been freed or used.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                }
            }
            return Err(format!(
                "the permissions of {what} could not be read (Win32 error {})",
                status.0
            ));
        }
        if acl.is_null() {
            // A null DACL is not "nothing is granted": it is the opposite. Every
            // caller has to know that, so it is a distinct error rather than an
            // empty ACE list.
            // SAFETY: the descriptor was allocated by the call above and has not
            // been freed.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
            return Err(format!(
                "{what} has no DACL at all, which grants every right to every account"
            ));
        }
        Ok(Self {
            descriptor,
            acl: acl as *const ACL,
        })
    }

    /// Whether the DACL stops inheriting from its parent.
    ///
    /// The `SE_DACL_PROTECTED` bit, which is the `P` in an SDDL string and the
    /// flag `PROTECTED_DACL_SECURITY_INFORMATION` sets on the way in. Without
    /// it, the entries this crate applies are *added to* whatever the parent
    /// contributes rather than replacing it, and on `%ProgramData%` the parent
    /// contributes `Users:(OI)(CI)(RX)` and a create-and-write ACE — so a
    /// "hardened" directory that was not protected is a directory any user can
    /// still write to. Measured on this machine; the output is quoted in
    /// [`crate::files`].
    pub(crate) fn is_protected(&self) -> bool {
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: the descriptor is live and owned by this value, and both out
        // parameters are live locals.
        let ok = unsafe {
            GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision)
        };
        ok.is_ok() && (control & SE_DACL_PROTECTED.0) != 0
    }

    /// Every entry in the DACL, in the order Windows evaluates them.
    ///
    /// A null ACL is impossible here — [`Dacl::finish`] refuses one — so an
    /// empty vector means an empty DACL, which denies everything to everybody.
    pub(crate) fn aces(&self) -> Vec<Ace> {
        /// In an `ACCESS_ALLOWED_ACE` or `ACCESS_DENIED_ACE`, the access mask
        /// starts after the 4-byte ACE header and the SID after that and the
        /// 4-byte mask.
        const MASK_OFFSET: usize = 4;
        const SID_OFFSET: usize = 8;
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        /// `OBJECT_INHERIT_ACE`.
        const OBJECT_INHERIT: u8 = 0x01;
        /// `CONTAINER_INHERIT_ACE`.
        const CONTAINER_INHERIT: u8 = 0x02;
        /// `INHERIT_ONLY_ACE`.
        const INHERIT_ONLY: u8 = 0x08;
        /// `INHERITED_ACE`.
        const INHERITED: u8 = 0x10;

        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `self.acl` points at a valid ACL for as long as this value
        // lives, and `size` is the structure that information class documents.
        let sized = unsafe {
            GetAclInformation(
                self.acl,
                &mut size as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                windows::Win32::Security::AclSizeInformation,
            )
        };
        if sized.is_err() {
            return Vec::new();
        }

        let mut aces = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: the index is below the count just read out of the ACL.
            if unsafe { GetAce(self.acl, index, &mut ace) }.is_err() {
                continue;
            }
            // SAFETY: `ace` points at an ACE header inside the ACL.
            let header = unsafe { *(ace as *const u8) };
            // An object ACE has a different layout — a GUID and a SID follow the
            // mask — and reading the plain SID offset out of one would produce a
            // SID-shaped number that is not a SID. Skipped rather than guessed
            // at, and a DACL this crate wrote never contains one.
            if header != ACCESS_ALLOWED_ACE_TYPE && header != ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            // SAFETY: the flags byte sits in the ACE header, after the type and
            // the size.
            let flags = unsafe { *(ace as *const u8).add(1) };
            // SAFETY: the mask sits at `MASK_OFFSET` inside an ACE of one of the
            // two types checked above.
            let mask = unsafe { *((ace as *const u8).add(MASK_OFFSET) as *const u32) };
            let sid = unsafe { (ace as *const u8).add(SID_OFFSET) } as *mut std::ffi::c_void;
            let Some(text) = sid_to_string(PSID(sid)) else {
                continue;
            };
            aces.push(Ace {
                sid: text,
                mask,
                denied: header == ACCESS_DENIED_ACE_TYPE,
                inherited: flags & INHERITED != 0,
                object_inherit: flags & OBJECT_INHERIT != 0,
                container_inherit: flags & CONTAINER_INHERIT != 0,
                inherit_only: flags & INHERIT_ONLY != 0,
            });
        }
        aces
    }

    /// What the DACL grants to one trustee, as an access mask.
    ///
    /// `GetEffectiveRightsFromAclW`, which is the operating system's own
    /// evaluation of this DACL for this trustee: it applies deny ACEs, it
    /// honours `IO` entries correctly, and it maps the generic bits (`GA`, `GR`,
    /// `GW`, `GX`) into the specific bits the access check will ask for. Doing
    /// that arithmetic here instead would be writing a second access-check
    /// implementation and calling it an audit, which is how an audit comes to
    /// agree with a bug in itself.
    ///
    /// Two things it deliberately does not model, and both are stated in every
    /// report that quotes it:
    ///
    /// * **The object's owner, and this one is a trap rather than a caveat.** The
    ///   call does *not* answer correctly for the account that owns the object:
    ///   measured, on a process whose DACL names only `SYSTEM`,
    ///   `Administrators` and `INTERACTIVE`, it returns `0x001f0fff` —
    ///   `PROCESS_ALL_ACCESS` — for the owning account, while a real
    ///   `OpenProcess(PROCESS_ALL_ACCESS)` by that account on that process is
    ///   refused with Win32 error 5. It over-reports the owner by the whole mask.
    ///   The owner's real extra access is `READ_CONTROL` and `WRITE_DAC` outside
    ///   the DACL, which is why a hardened directory's owner can always un-harden
    ///   it — and it is measured in [`crate::process`], where the probe results
    ///   are quoted. So: **do not pass an object's owner to this function and
    ///   believe the answer.** Either leave the owner out of the audit and report
    ///   its grant separately, which is what [`crate::process`] does, or read the
    ///   ACEs naming the owner and treat any generic bit in them as everything.
    /// * **Group nesting beyond the SID given.** The call evaluates one trustee.
    ///   A caller asking "what can a user do?" has to ask for each group that
    ///   user holds, which is why [`UNPRIVILEGED_TRUSTEES`] is a list and not a
    ///   single SID.
    pub(crate) fn effective(&self, sid: &str) -> Result<u32, String> {
        let owned = OwnedSid::parse(sid)?;
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            // SAFETY-free cast: the `windows` crate types `ptstrName` as a
            // `PWSTR` for every trustee form, including the form where the
            // pointer is a SID rather than a string. The API reads it as a SID
            // because `TrusteeForm` says so, and the SID outlives the call.
            ptstrName: windows::core::PWSTR(owned.psid().0 as *mut u16),
        };
        let mut rights = 0u32;
        // SAFETY: `self.acl` is a valid ACL for as long as this value lives,
        // `trustee` names a live SID, and `rights` is a live out-parameter.
        let status = unsafe { GetEffectiveRightsFromAclW(self.acl, &trustee, &mut rights) };
        if status != WIN32_ERROR(0) {
            return Err(format!(
                "the permissions could not be evaluated for {sid} (Win32 error {})",
                status.0
            ));
        }
        Ok(rights)
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by `GetNamedSecurityInfoW` or
        // `GetSecurityInfo` and has not been freed; this is its documented
        // release and the only place that frees it.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

/// A SID inside a live ACL, as its `S-1-5-...` string.
fn sid_to_string(sid: PSID) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut raw = PWSTR::null();
    // SAFETY: `sid` points at a SID inside an ACL that the caller keeps alive,
    // and `raw` is an out-parameter the API points at a `LocalAlloc` string on
    // success. That string is copied out and released immediately below.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) }.is_err() {
        return None;
    }
    // SAFETY: on success `raw` is a NUL-terminated wide string owned by us.
    let text = unsafe { raw.to_string() }.ok();
    // SAFETY: the string came from `LocalAlloc` and has been copied.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(raw.0 as *mut std::ffi::c_void)));
    }
    text
}

/// A descriptor built from an SDDL string, with its DACL handed out.
///
/// The descriptor exists only long enough to be applied, so it is not exposed:
/// `with_dacl` is the whole interface, and it is what keeps a caller from
/// holding a pointer into a freed descriptor.
struct SddlDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SddlDescriptor {
    fn parse(sddl: &str) -> Result<Self, String> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `descriptor`
        // is an out-parameter the API allocates into on success.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|error| format!("`{sddl}` is not a valid permission string: {error}"))?;
        Ok(Self { descriptor })
    }

    /// The DACL inside, for a call that is about to copy it onto an object.
    fn dacl(&self) -> Result<*const ACL, String> {
        let mut present = windows::core::BOOL::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = windows::core::BOOL::default();
        // SAFETY: the descriptor is live and owned by this value, and the three
        // out-parameters are live locals that point into it.
        unsafe { GetSecurityDescriptorDacl(self.descriptor, &mut present, &mut acl, &mut defaulted) }
            .map_err(|error| format!("the permission string has no DACL to apply: {error}"))?;
        if !present.as_bool() || acl.is_null() {
            return Err("the permission string has no DACL to apply".to_string());
        }
        Ok(acl as *const ACL)
    }
}

impl Drop for SddlDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`
        // and not freed elsewhere.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

/// Apply `sddl` to a file or directory as a **protected** DACL.
///
/// `SetNamedSecurityInfoW` rather than `SetFileSecurityW`, and the difference is
/// the object class: `SetFileSecurityW` cannot be pointed at a process, and
/// [`apply_to_process`] has to be, so the named-object path uses the same
/// `SE_*_OBJECT` vocabulary so that the two read as a pair.
///
/// `PROTECTED_DACL_SECURITY_INFORMATION` is OR'd in, and that flag is the whole
/// reason the hardening sticks: without it the new entries are merged with what
/// the parent contributes, and `%ProgramData%` contributes a writable grant to
/// `BUILTIN\Users` — measured, and quoted in [`crate::files`].
pub(crate) fn apply_to_path(path: &Path, sddl: &str) -> Result<(), String> {
    set_dacl(path, sddl, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION)
}

/// Put a DACL back on a file or directory, exactly as [`sddl_from`] wrote it.
///
/// # Why the protection flag is a parameter and not a constant
///
/// Hardening always protects, because a protected DACL is what makes the entries
/// the ones that apply. Putting a recorded DACL back must reproduce *what was
/// there*, and a directory may have been unprotected when the record was taken —
/// so a restore that protected it would leave the machine in a state it was
/// never in: the parent's grants would stop reaching it, and every child created
/// afterwards would be born with a DACL nobody chose. `was_protected` is
/// [`crate::files::RecordedDacl::protected`], read off the same descriptor the
/// string was written from.
///
/// The flag is passed explicitly in **both** directions rather than being left
/// out for the unprotected case, and that is deliberate. The documentation for
/// `SetNamedSecurityInfoW` reads as though omitting
/// `PROTECTED_DACL_SECURITY_INFORMATION` leaves the DACL unprotected, while the
/// behaviour observed in practice is that omitting it leaves the object's
/// existing `SE_DACL_PROTECTED` bit alone — two readings under which a restore
/// of an unprotected DACL over a hardened directory would silently stay
/// hardened. `UNPROTECTED_DACL_SECURITY_INFORMATION` says which of the two the
/// caller means, and the round trip is asserted in this module's tests.
pub(crate) fn restore_to_path(path: &Path, sddl: &str, was_protected: bool) -> Result<(), String> {
    let protection = if was_protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    set_dacl(path, sddl, DACL_SECURITY_INFORMATION | protection)
}

/// The shared body of the two above, differing only in the information flags.
fn set_dacl(
    path: &Path,
    sddl: &str,
    information: windows::Win32::Security::OBJECT_SECURITY_INFORMATION,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt as _;

    let built = SddlDescriptor::parse(sddl)?;
    let acl = built.dacl()?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `acl` points into
    // `built`, which is alive for the call and for nothing beyond it — the API
    // copies the DACL onto the object rather than retaining it. The owner, group
    // and SACL are `None`, which means "leave alone".
    let status = unsafe {
        windows::Win32::Security::Authorization::SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            information,
            None,
            None,
            Some(acl),
            None,
        )
    };
    if status != WIN32_ERROR(0) {
        return Err(format!(
            "the operating system refused the permissions for {} (Win32 error {})",
            path.display(),
            status.0
        ));
    }
    Ok(())
}

/// The DACL section of an SDDL string describing `aces`.
///
/// # Why this exists
///
/// Every other string this crate writes is a `const` — [`crate::files::DirRole::sddl`]
/// is a literal, because the permissions this product *chooses* are a policy and
/// a policy belongs in the source where it can be reviewed. This one is not a
/// policy: it is the DACL a directory happened to have before `wenle protect
/// apply` replaced it, and the only way to put that back is to be able to write
/// down a DACL that was read rather than chosen.
///
/// # What it emits, and the two decisions in it
///
/// The ACE type is `A` or `D` from [`Ace::denied`], the rights are the raw mask
/// in hex — not the generic letters, because a mask read off an object is
/// already specific and the letters are a mapping that would have to be exactly
/// reversed — and the trustee is the `S-1-5-...` form [`Ace::sid`] carries.
///
/// **Inherited entries are dropped when the DACL is not protected**, and kept
/// when it is. That is not tidying: an unprotected DACL's inherited entries are
/// not *on* the object at all — the operating system materialises them when the
/// DACL is read — so writing them back would turn them into explicit entries and
/// then let the parent's copies be added on top, doubling them. On a directory
/// that is written and restored repeatedly that grows without bound. A protected
/// DACL has no parent contributing anything, so its entries are all there is and
/// all of them are written.
pub(crate) fn sddl_from(aces: &[Ace], protected: bool) -> String {
    /// `OI`, `CI`, `IO` and `ID`, in the order `icacls` prints them.
    fn flags_of(ace: &Ace) -> String {
        let mut flags = String::new();
        if ace.object_inherit {
            flags.push_str("OI");
        }
        if ace.container_inherit {
            flags.push_str("CI");
        }
        if ace.inherit_only {
            flags.push_str("IO");
        }
        if ace.inherited {
            flags.push_str("ID");
        }
        flags
    }

    let mut text = String::from("D:");
    if protected {
        text.push('P');
    }
    for ace in aces {
        if !protected && ace.inherited {
            continue;
        }
        text.push_str(&format!(
            "({};{};0x{:08X};;;{})",
            if ace.denied { "D" } else { "A" },
            flags_of(ace),
            ace.mask,
            ace.sid
        ));
    }
    text
}

/// Apply `sddl` to a kernel object — a process — as a **protected** DACL.
///
/// The handle must carry `WRITE_DAC`. See [`crate::process`] for what that means
/// for the caller and for what `GetCurrentProcess()` can and cannot do here.
pub(crate) fn apply_to_process(handle: HANDLE, sddl: &str) -> Result<(), String> {
    let built = SddlDescriptor::parse(sddl)?;
    let acl = built.dacl()?;
    // SAFETY: `handle` is a live handle owned by the caller and opened with
    // `WRITE_DAC`. `acl` points into `built`, alive for the call; the API copies
    // the DACL rather than retaining it.
    let status = unsafe {
        windows::Win32::Security::Authorization::SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };
    if status != WIN32_ERROR(0) {
        return Err(format!(
            "the operating system refused the permissions for the process object (Win32 error {})",
            status.0
        ));
    }
    Ok(())
}

/// The SID of the account this process runs as.
///
/// Copied in approach from `av-quarantine`'s `hardening`, which needs it for the
/// same reason: a DACL that hardens a directory the product itself has to write
/// to has to name the account doing the writing, and guessing is not available.
pub(crate) fn current_user_sid() -> Result<String, String> {
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};

    // SAFETY: `GetCurrentProcess` takes no arguments and returns a pseudo-handle
    // that must not be closed.
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: `process` is the current-process pseudo-handle and `token` is an
    // out-parameter the API fills on success.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("this process's token could not be opened: {error}"))?;

    // The size is asked for first: a token's user information is
    // variable-length and there is no documented bound to allocate against.
    let mut needed = 0u32;
    // SAFETY: a null buffer with a zero length is the documented way to ask for
    // the size; the call is expected to fail with `ERROR_INSUFFICIENT_BUFFER`
    // and fill in `needed`.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        // SAFETY: the handle was opened above and is not used afterwards.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
        return Err("this process's token reported no user".to_string());
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: the buffer is at least `needed` bytes, which the call above said
    // is enough for this information class.
    let filled = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        )
    };
    // SAFETY: as above; the token is not needed either way.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(token) };
    filled.map_err(|error| format!("this process's user could not be read: {error}"))?;

    // SAFETY: the call succeeded, so the buffer holds a `TOKEN_USER` whose
    // `User.Sid` points into that same buffer, which is alive here.
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    sid_to_string(user.User.Sid).ok_or_else(|| "this process's user could not be named".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory this process owns, with a DACL this test wrote, so that the
    /// reader is measured against permissions whose contents are known rather
    /// than against whatever the machine happens to inherit.
    fn open_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        // Everyone, full control, protected — no inheritance to reason about.
        apply_to_path(dir.path(), LOOSE).expect("loosening the temporary directory");
        dir
    }

    /// A DACL that grants full control to SYSTEM, Administrators and Everyone.
    ///
    /// The same string the vault's tests call `LOOSE`, and loose on purpose: a
    /// reader is only shown to work by being pointed at something permissive.
    const LOOSE: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)";

    #[test]
    fn every_trustee_in_the_list_parses_and_evaluates() {
        // The list is the foundation of every unprivileged-access answer in this
        // crate. A typo in one SID would silently drop a principal from every
        // check, and the report would say "no unprivileged account has access"
        // about a principal nobody asked about.
        for sid in UNPRIVILEGED_TRUSTEES {
            let owned = OwnedSid::parse(sid).unwrap_or_else(|e| panic!("{sid}: {e}"));
            // The round trip checked against the operating system rather than
            // against a copy of the input: the SID is turned back into a string
            // by the same conversion every report in this crate uses, and it has
            // to come back as what went in.
            assert_eq!(
                sid_to_string(owned.psid()).as_deref(),
                Some(sid),
                "`{sid}` did not survive a round trip through `ConvertStringSidToSidW`"
            );
        }
        assert!(!UNPRIVILEGED_TRUSTEES
            .iter()
            .any(|sid| is_privileged(sid)));
    }

    #[test]
    fn a_sid_string_that_is_not_one_is_refused_rather_than_guessed_at() {
        assert!(OwnedSid::parse("not-a-sid").is_err());
        assert!(OwnedSid::parse("").is_err());
        assert!(OwnedSid::parse("S-1-5-").is_err());
        // The message names the string, because the only way to reach this is a
        // mistake in this crate's own table.
        assert!(OwnedSid::parse("nope")
            .expect_err("must fail")
            .contains("nope"));
    }

    #[test]
    fn a_permissive_dacl_reads_back_as_permissive() {
        let dir = open_dir();
        let dacl = Dacl::of_path(dir.path()).expect("reading the DACL back");
        assert!(
            dacl.is_protected(),
            "the `P` in the string must come back as SE_DACL_PROTECTED, or the \
             directory is still inheriting"
        );

        let sids: Vec<String> = dacl.aces().into_iter().map(|ace| ace.sid).collect();
        for expected in [SYSTEM, ADMINISTRATORS, EVERYONE] {
            assert!(sids.contains(&expected.to_string()), "{expected} in {sids:?}");
        }

        // Everyone was granted `FA`, and `FA` is `FILE_ALL_ACCESS` — every
        // specific bit. The evaluation has to say so.
        let rights = dacl.effective(EVERYONE).expect("evaluating Everyone");
        for bit in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            DELETE,
            WRITE_DAC,
            FILE_DELETE_CHILD,
        ] {
            assert_eq!(
                rights & bit,
                bit,
                "Everyone was granted full control and the evaluation shows \
                 0x{rights:08x}, missing 0x{bit:08x}"
            );
        }
    }

    #[test]
    fn a_dacl_that_grants_nothing_reads_back_as_granting_nothing() {
        // The other end of the same reader. A reader that answered "full
        // control" for everything would pass the test above and be useless.
        let dir = tempfile::tempdir().expect("a temporary directory");
        apply_to_path(dir.path(), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .expect("restricting the temporary directory");
        let dacl = Dacl::of_path(dir.path()).expect("reading the DACL back");
        assert_eq!(dacl.effective(EVERYONE).expect("evaluating Everyone"), 0);
        for sid in UNPRIVILEGED_TRUSTEES {
            assert_eq!(
                dacl.effective(sid).expect("evaluating"),
                0,
                "{sid} was granted nothing and the evaluation says otherwise"
            );
        }
        // And the privileged accounts still have everything, which is what
        // makes the DACL a grant list rather than a lock-out.
        assert_eq!(
            dacl.effective(SYSTEM).expect("evaluating SYSTEM") & FILE_WRITE_DATA,
            FILE_WRITE_DATA
        );
    }

    /// The access mask bits this test module names.
    ///
    /// Spelled out here rather than imported, so that the assertion above is
    /// about numbers a Windows programmer recognises rather than about whatever
    /// the `windows` crate calls them.
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;

    #[test]
    fn a_null_dacl_is_an_error_and_not_an_empty_one() {
        // `SetNamedSecurityInfoW` with a null DACL is the documented way to
        // grant everyone everything. A reader that reported "no entries" for it
        // would describe the most permissive state there is as the least.
        let dir = tempfile::tempdir().expect("a temporary directory");
        use std::os::windows::ffi::OsStrExt as _;
        let wide: Vec<u16> = dir
            .path()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; a null DACL
        // with no owner or group is the documented "everyone, everything".
        let status = unsafe {
            windows::Win32::Security::Authorization::SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
            )
        };
        assert_eq!(status, WIN32_ERROR(0), "the test could not set a null DACL");

        let read = Dacl::of_path(dir.path());
        assert!(
            read.is_err(),
            "a null DACL grants everything and must not read as an empty one"
        );
    }

    #[test]
    fn a_permission_string_that_is_not_one_is_refused() {
        assert!(apply_to_path(Path::new(r"C:\"), "D:P(nonsense)").is_err());
        // And the message quotes the string, so a caller can see what was
        // rejected without a debugger.
        let message = apply_to_path(Path::new(r"C:\"), "D:P(nonsense)")
            .expect_err("must fail");
        assert!(message.contains("D:P(nonsense)"), "{message}");
    }

    /// The read/write pair `wenle protect apply` and `wenle protect restore` are
    /// built on, checked as a fixed point rather than against a literal.
    ///
    /// A literal would be this module checking its own output against a copy of
    /// itself. What has to hold is that the text [`sddl_from`] writes, put back
    /// with [`restore_to_path`] and read again, produces *the same text* — so the
    /// assertion is `sddl_from(read(write(s))) == s`, with `s` itself the output
    /// of a read. If the writer dropped a flag the reader records, or the
    /// operating system normalised a mask on the way in, the second read is where
    /// it shows.
    ///
    /// The intermediate step is a *hardened* DACL rather than the same one
    /// written twice, because that is the sequence this exists for: a directory
    /// is hardened, and later the recorded permissions have to come back over the
    /// top of them.
    #[test]
    fn a_recorded_dacl_comes_back_as_what_was_recorded() {
        let dir = open_dir();
        let before = Dacl::of_path(dir.path()).expect("reading the DACL");
        let recorded = sddl_from(&before.aces(), before.is_protected());
        assert!(recorded.starts_with("D:P"), "{recorded}");
        drop(before);

        // What `apply` does to it.
        apply_to_path(dir.path(), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
            .expect("hardening the directory");
        let hardened = Dacl::of_path(dir.path()).expect("reading the hardened DACL");
        assert!(
            hardened.aces().iter().all(|ace| !ace.inherited),
            "the point of this test is that the recorded entries are put back over \
             a DACL that no longer has them"
        );
        drop(hardened);

        restore_to_path(dir.path(), &recorded, true).expect("putting the record back");
        let after = Dacl::of_path(dir.path()).expect("reading the DACL back");
        assert!(after.is_protected(), "the record was protected and a protected DACL is what a protected record means");
        assert_eq!(
            sddl_from(&after.aces(), after.is_protected()),
            recorded,
            "the permissions did not survive a write and a read"
        );
    }

    /// The case [`restore_to_path`]'s explicit `UNPROTECTED_…` flag exists for.
    ///
    /// Found necessary by reading the documentation rather than by a failure,
    /// which is the cheaper way round: `SetNamedSecurityInfoW`'s page reads as
    /// though omitting `PROTECTED_DACL_SECURITY_INFORMATION` produces an
    /// unprotected DACL, and the behaviour most often reported is that it leaves
    /// the existing bit alone. A restore that got that wrong would put a
    /// directory's entries back and leave it protected, so the parent's grants
    /// would never reach it again — a machine in a state it was never in, and
    /// silent, because every call would have returned success.
    ///
    /// Measured here against the real API, which is the only thing that settles
    /// it.
    #[test]
    fn an_unprotected_dacl_is_put_back_unprotected() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let original = Dacl::of_path(dir.path()).expect("reading the DACL");
        assert!(
            !original.is_protected(),
            "a fresh temporary directory is expected to inherit, or this test cannot \
             tell a restore that cleared the bit from one that never set it"
        );
        let recorded = sddl_from(&original.aces(), original.is_protected());
        assert!(recorded.starts_with("D:"), "{recorded}");
        assert!(!recorded.starts_with("D:P"), "{recorded}");
        drop(original);

        apply_to_path(dir.path(), LOOSE).expect("hardening the directory");
        let hardened = Dacl::of_path(dir.path()).expect("reading the hardened DACL");
        assert!(hardened.is_protected(), "the hardening did not take");
        drop(hardened);

        restore_to_path(dir.path(), &recorded, false).expect("putting the record back");
        let after = Dacl::of_path(dir.path()).expect("reading the DACL back");
        assert!(
            !after.is_protected(),
            "the record was unprotected and the directory is protected again: the \
             recorded entries are back but the parent's grants no longer reach it"
        );
    }

    /// The recorded entries of an unprotected DACL are the *explicit* ones, and
    /// the inherited ones are left to be inherited again.
    ///
    /// Writing an inherited entry back as an explicit one would duplicate it —
    /// the copy on the object plus the copy the parent keeps contributing — and
    /// on a directory that is written and restored repeatedly that grows without
    /// bound. This asserts the drop, and asserts it on a directory that really
    /// does have inherited entries to drop.
    #[test]
    fn inherited_entries_are_not_written_back_as_explicit_ones() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        apply_to_path(parent.path(), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")
            .expect("loosening the parent");
        let child = parent.path().join("child");
        std::fs::create_dir(&child).expect("creating a child directory");

        let dacl = Dacl::of_path(&child).expect("reading the child's DACL");
        assert!(
            dacl.aces().iter().any(|ace| ace.inherited),
            "the child inherits nothing from a parent that grants Everyone full \
             control, so this test is not measuring what it says it is"
        );
        let text = sddl_from(&dacl.aces(), dacl.is_protected());
        assert!(
            !text.contains("ID"),
            "an inherited entry was written back as an explicit one: {text}"
        );
    }
}
