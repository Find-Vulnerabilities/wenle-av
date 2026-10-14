//! The Windows named pipe behind [`av_ipc::Connection`].
//!
//! # What is here and what is next door
//!
//! `av-ipc` is the protocol: framing, the session state machine, the
//! correlation rules, and not one Win32 call. This is the other half of that
//! split — the seven functions that make the protocol run on a real machine —
//! and it is deliberately the smaller half. Everything that can be *wrong* in
//! an interesting way lives in `av-ipc` and is tested there without a system;
//! what lives here is `CreateNamedPipeW` and its friends, whose behaviour is
//! the operating system's and is not ours to test.
//!
//! The split is `av_driver_proto::path::VolumeNames`'s, one layer up: the
//! decision is testable, and the call that only works on Windows is one small
//! implementation behind an interface.
//!
//! # Who may reach the pipe, and how that is known rather than assumed
//!
//! The instance is created with an explicit permission list —
//! [`CONTROL_PIPE_SDDL`] — and the list is **read back off the created object**
//! and compared with what was asked for; see [`PipePermissions`].
//!
//! Until 2026-10-09 this file passed a null `SECURITY_ATTRIBUTES` and a comment
//! claimed the result was "the one that governs `%ProgramData%\WenleAV`". That
//! was false twice over: a pipe has no parent to inherit from, so no
//! directory's permission list has any bearing on it, and a null descriptor
//! asks for the **creating token's default DACL**, which is a property of the
//! account the service runs under rather than of this product. Nothing read the
//! result back, so nothing could have caught it — and what it produced, measured
//! on this machine by creating one and asking, was:
//!
//! ```text
//! D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-…-1001)(A;;FR;;;WD)(A;;FR;;;AN)
//! ```
//!
//! The creating account's SID with full control, and then **`Everyone` and
//! `ANONYMOUS LOGON` with read access to the pipe's contents** — which are
//! requests, replies, paths of files the product has decided about, and the
//! quarantine listing. That is the shape of the defect a self-protection
//! feature is supposed to have none of, and it was in the shipping code with a
//! comment asserting the opposite.
//!
//! # The two flags that are not decoration
//!
//! * **`PIPE_REJECT_REMOTE_CLIENTS`.** Without it a named pipe can be opened
//!   over SMB by anyone who can authenticate to this machine, which turns a
//!   local control channel into a network one that "quarantine this file" is
//!   reachable through. `av_ipc::transport`'s module documentation makes this
//!   promise; this is where it is kept.
//! * **`PIPE_TYPE_BYTE`.** Message mode looks attractive — the pipe would
//!   preserve write boundaries and the protocol would not need a length prefix
//!   — and it is wrong here for two reasons. Message mode *requires* the
//!   reader's buffer to be at least as large as the largest message or the read
//!   fails with `ERROR_MORE_DATA` and the message is lost, which is exactly the
//!   attacker-controlled-allocation problem `av_ipc::wire` solves properly with
//!   a used length into a fixed buffer. And message mode is not preserved by
//!   `ReadFile` on a pipe opened in byte read mode, so a client could receive
//!   something this end never sent as a message. Byte mode with our own framing
//!   is the one arrangement where both ends agree about where messages end.
//!
//! # Reads do not block, and that is a choice
//!
//! [`av_ipc::Connection::read_chunk`] documents that a non-blocking read is the
//! transport's business, and this is the transport that takes it up:
//! `PeekNamedPipe` answers "how many bytes are waiting" without consuming them,
//! so a read of an empty pipe returns `Read::Bytes(0)` — the value
//! `av_ipc::session` documents as "the transport handed over nothing" — instead
//! of parking the thread.
//!
//! Two things need that. The service's control loop has to drain the scan
//! thread's event channel between reads, and a thread parked in `ReadFile` on a
//! connected-but-idle client would deliver no events until the client happened
//! to send something. And a one-client-at-a-time accept loop has to be able to
//! notice that the client it is serving has gone without waiting for it to say
//! so. The cost is a poll interval, which is a few milliseconds of latency on a
//! channel a human is driving; the alternative is a second thread per
//! connection, chosen against for the reason this crate has a single-instance
//! guard in the first place.
//!
//! # Writes block, and that is not a choice
//!
//! `WriteFile` on a byte-mode pipe accepts up to the pipe's buffer and then
//! waits for the reader to drain it. A reply larger than the buffer therefore
//! blocks until the client reads, and a client that stops reading mid-frame
//! blocks the service's control thread for as long as it likes. There is no
//! clean way around it in this design: an overlapped write would need the
//! cancellation machinery of a real IOCP loop, and `PIPE_NOWAIT` is documented
//! as existing for LAN Manager compatibility rather than for use. So it is
//! stated rather than hidden — a client that stops reading is a client that
//! stops being served, and the connection is torn down as soon as the write
//! fails or the client disconnects.

use std::path::Path;

use av_ipc::{Connection, IpcError, Read};

use crate::error::ServiceError;

/// How much the pipe buffers in each direction before a write blocks.
///
/// 64 KiB, which holds a status report, a scan summary, and a quarantine
/// listing of a few hundred entries without the writer ever waiting. It does
/// not hold the 16 MiB `av_ipc::MAX_FRAME_BYTES` allows, and it does not need
/// to: the buffer is a threshold for *when the writer waits*, not a limit on
/// what can be sent, and a frame larger than it is written in pieces as the
/// client drains them.
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// How long a client waits for a free pipe instance before giving up.
///
/// `WaitNamedPipeW`'s timeout, in milliseconds, for the client side. An
/// instance is free almost always — the service creates the next one as soon as
/// a client connects — so this only has to outlast the gap between one client
/// disconnecting and the service noticing. Five seconds is generous for that
/// and short enough that a client run by hand does not appear to hang.
const CONNECT_TIMEOUT_MS: u32 = 5_000;

/// The permission list every instance of the control pipe is created with.
///
/// # Who is on it, and why
///
/// * **`SY` and `BA`** — `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` —
///   full control. The service may need to reach its own pipe, and an
///   administrator is outside every protection this product has by design: see
///   `av-guard`'s own documentation, which refuses to claim otherwise.
/// * **`IU`** — `NT AUTHORITY\INTERACTIVE` — read and write, which is what a
///   client needs. This is the deliberate hole. `wenle.exe` and the window are
///   the clients, they run as whoever is logged in, and a control channel the
///   product's own front ends cannot reach is a product with no front end.
///
/// # What this list does not do, said plainly
///
/// It does **not** separate one interactive user from another, and it is not
/// meant to: `INTERACTIVE` contains `BUILTIN\Users`, so every account that can
/// log on is covered by it whatever is written here. That separation is made
/// per client, in [`crate::control`], and it is the same split
/// `av-quarantine`'s vault documents — **the threat is the *other* user, not a
/// malicious program running as this one.** A permission list cannot make that
/// distinction; a per-connection check can.
///
/// What it does buy is the two things such a list can: `Everyone` and
/// `ANONYMOUS LOGON` are named nowhere and so reach nothing —
/// `the_list_names_no_account_that_should_not_be_on_it` holds that to the
/// source text — and `PIPE_REJECT_REMOTE_CLIENTS` keeps the channel off the
/// network.
pub const CONTROL_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// What the control pipe's permission list was asked to be, and what the object
/// says it is.
///
/// The pair rather than the applied string, because the failure worth guarding
/// against is a call that returned success and an object that did not change.
/// A permission list written to a kernel object is not a permission list that
/// took, and the only way to know is to ask the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipePermissions {
    /// The list that was applied, exactly as the source states it.
    pub requested: &'static str,
    /// The permission list read back off the object, in the form the system
    /// prints it, or the sentence saying why it could not be read.
    pub observed: Result<String, String>,
}

impl PipePermissions {
    /// A read that did not happen, with the reason.
    fn unread(reason: impl Into<String>) -> Self {
        Self {
            requested: CONTROL_PIPE_SDDL,
            observed: Err(reason.into()),
        }
    }

    /// Whether the object's permission list is the one that was asked for.
    ///
    /// Both sides are reduced to what they *grant* — a sorted list of
    /// `(account, rights)` — and those are compared. Comparing the two strings
    /// would be a test of the printer: measured on this machine, the constant
    /// below is stored as `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;IU)`, which
    /// is the same grant written three different ways. See `grants`.
    pub fn holds(&self) -> bool {
        let Ok(observed) = &self.observed else {
            return false;
        };
        // A constant that will not parse is a bug in this file and not anything
        // about the machine, and it is reported as "not established" rather than
        // as a match.
        match (grants(self.requested), grants(observed)) {
            (Ok(wanted), Ok(found)) => wanted == found,
            _ => false,
        }
    }

    /// One sentence for a person, phrased as what is true of the pipe.
    pub fn describe(&self) -> String {
        match &self.observed {
            Err(detail) => {
                format!("the control pipe's permissions could not be read back: {detail}")
            }
            Ok(observed) if self.holds() => format!(
                "the control pipe lets SYSTEM and administrators do anything to it and an \
                 interactive user read and write, and nobody else anything: {observed}"
            ),
            Ok(observed) => format!(
                "the control pipe's permissions are NOT the ones this build writes. It asked for \
                 {}, and the object reports {observed}",
                self.requested
            ),
        }
    }
}

/// One entry of a permission list, as this module compares it.
///
/// Only the trustee and the rights: the ACE's type and inheritance flags carry
/// nothing here, because a pipe has no children to inherit into and this crate
/// writes allow entries only. A deny entry would be a grant this does not
/// represent, which is why [`grants`] skips them rather than reading their mask
/// as though it were one.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Grant {
    sid: String,
    mask: u32,
}

/// What a permission list grants, with the generic bits resolved.
///
/// Both sides of [`PipePermissions::holds`] go through this, so what is compared
/// is what two lists *grant* and not how they are spelled. Three differences
/// between the wanted string and the stored one turn up in practice, and only
/// resolving the mask makes them one answer:
///
/// * **`GA` against `FA`.** The kernel resolves the four generic bits against
///   the object's type when it assigns a descriptor, so a list written
///   `(A;;GA;;;SY)` *is stored* as `FILE_ALL_ACCESS` and reads back as `FA`.
///   Measured here: the constant above comes back
///   `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;IU)`. A reader that compared the
///   strings would call a correct pipe a permission list that did not take,
///   which is the failure mode that makes an audit worthless — it must not cry
///   wolf, or the one real alarm is lost among the false ones.
/// * **`GRGW` against `GWGR`.** The printing routine walks the mask from its low
///   bits up, and `GW` sits below `GR`.
/// * **ACE order.** Windows evaluates a DACL in order and this crate writes one
///   order, but nothing promises an object hands the entries back in it, so the
///   list is sorted before it is compared.
///
/// `MapGenericMask` does the resolution rather than arithmetic here, and the
/// mapping is built from the SDK's own `FILE_GENERIC_*` constants rather than
/// from hex, so a reader can check it without decoding `0x12019f`.
#[cfg(windows)]
fn grants(sddl: &str) -> Result<Vec<Grant>, String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorDacl, PSID,
        ACL_SIZE_INFORMATION,
    };

    /// In an `ACCESS_ALLOWED_ACE`, the access mask starts after the 4-byte ACE
    /// header and the SID after that and the 4-byte mask. The same offsets
    /// `av_guard`'s reader uses.
    const MASK_OFFSET: usize = 4;
    const SID_OFFSET: usize = 8;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    let descriptor = descriptor_from_sddl(sddl)?;
    // Everything below has to release `descriptor`, including the two early
    // returns, so the work is done in a closure and the release is one place.
    let parsed = (|| -> Result<Vec<Grant>, String> {
        let mut present = windows::core::BOOL(0);
        let mut acl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        let mut defaulted = windows::core::BOOL(0);
        // SAFETY: `descriptor` is live for the whole closure and owned by this
        // function; the three out-parameters are live locals.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            .map_err(|error| format!("`{sddl}` has no permission list in it ({error})"))?;
        if !present.as_bool() || acl.is_null() {
            return Err(format!(
                "`{sddl}` has no permission list in it, which grants every right to every account"
            ));
        }
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `acl` points into `descriptor`, and `size` is the structure
        // this information class documents.
        unsafe {
            GetAclInformation(
                acl,
                &mut size as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| format!("`{sddl}` could not be walked ({error})"))?;

        let mut wanted = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: the index is below the count just read out of the ACL.
            if unsafe { GetAce(acl, index, &mut ace) }.is_err() {
                continue;
            }
            // SAFETY: `ace` points at an ACE header inside the ACL.
            if unsafe { *(ace as *const u8) } != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            // SAFETY: the mask sits at `MASK_OFFSET` inside an allow ACE.
            let mut mask = unsafe { *((ace as *const u8).add(MASK_OFFSET) as *const u32) };
            map_generic(&mut mask);
            // SAFETY: the SID sits at `SID_OFFSET` inside an allow ACE.
            let sid = unsafe { (ace as *const u8).add(SID_OFFSET) } as *mut std::ffi::c_void;
            let mut text = windows::core::PWSTR::null();
            // SAFETY: `sid` points at a SID inside the ACL, and `text` is an
            // out-parameter the API points at a `LocalAlloc` string on success.
            if unsafe { ConvertSidToStringSidW(PSID(sid), &mut text) }.is_err() {
                continue;
            }
            // SAFETY: on success `text` is a NUL-terminated wide string of ours.
            let sid = unsafe { text.to_string() }.unwrap_or_default();
            // SAFETY: the string came from `LocalAlloc` and has been copied.
            unsafe {
                let _ = windows::Win32::Foundation::LocalFree(Some(
                    windows::Win32::Foundation::HLOCAL(text.0 as *mut std::ffi::c_void),
                ));
            }
            wanted.push(Grant { sid, mask });
        }
        Ok(wanted)
    })();
    // SAFETY: the descriptor came from `descriptor_from_sddl` and is released
    // exactly once, here, after the ACL pointer into it is no longer used.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            descriptor.0,
        )));
    }
    let mut parsed = parsed?;
    parsed.sort();
    Ok(parsed)
}

/// Resolve the four generic bits in `mask` against the file type's mapping.
///
/// A named pipe *is* a file object, so the mapping the kernel applies when it
/// assigns the descriptor is the file one — which is why a list written with
/// `GRGW` is stored as `0x12019f`.
#[cfg(windows)]
fn map_generic(mask: &mut u32) {
    use windows::Win32::Security::{MapGenericMask, GENERIC_MAPPING};
    use windows::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    // SAFETY: `mask` is a live `u32` owned by the caller and `mapping` is a live
    // structure; the call reads one and writes the other, and neither outlives
    // the frame.
    unsafe { MapGenericMask(mask, &mapping) };
}

/// Turn `sddl` into a descriptor the system allocated.
///
/// The caller owns the result and releases it with `LocalFree`.
#[cfg(windows)]
fn descriptor_from_sddl(
    sddl: &str,
) -> Result<windows::Win32::Security::PSECURITY_DESCRIPTOR, String> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    let wide = crate::win32::to_wide_str(sddl);
    let mut descriptor = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is NUL-terminated and outlives the call, and `descriptor`
    // is a zeroed out-parameter the API points at a `LocalAlloc` allocation on
    // success. Every caller releases it with `LocalFree`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| format!("`{sddl}` is not a permission list the system accepts ({error})"))?;
    Ok(descriptor)
}

/// Print a descriptor's DACL the way the system spells it.
#[cfg(windows)]
fn sddl_from_descriptor(
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<String, String> {
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::DACL_SECURITY_INFORMATION;

    let mut text = windows::core::PWSTR::null();
    let mut length = 0u32;
    // SAFETY: `descriptor` is a live descriptor owned by the caller, and `text`
    // is an out-parameter the API points at a `LocalAlloc` wide string on
    // success. That string is copied out and released immediately below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            Some(&mut length),
        )
    }
    .map_err(|error| format!("the permissions could not be printed ({error})"))?;
    // SAFETY: on success `text` is a NUL-terminated wide string owned by us.
    let rendered =
        unsafe { text.to_string() }.map_err(|_| "the printed permissions were not text".to_string());
    // SAFETY: the string came from `LocalAlloc` and has been copied.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            text.0 as *mut std::ffi::c_void,
        )));
    }
    rendered
}

/// The DACL of a live pipe handle, as the system spells it.
///
/// # Two object classes, and why the second is tried at all
///
/// `SE_FILE_OBJECT` is the right class for a named pipe — a pipe *is* a file
/// object — and it is the one asked first. Measured on this machine, it answers
/// for a pipe created with [`CONTROL_PIPE_SDDL`] and it **fails with Win32 error
/// 87** for a pipe created with a null descriptor, whose DACL the system
/// defaulted. `SE_KERNEL_OBJECT` answers in that case, and the difference is not
/// academic: a defaulted DACL is the very thing this read exists to notice. A
/// check that stopped at "the file class would not say" would report an unread
/// permission list where the truth is a permission list anyone on the machine is
/// on.
///
/// The classes are asked in the other order nowhere, because the file class is
/// the one whose answer has been checked against `av_guard`'s own reader.
#[cfg(windows)]
fn read_back(handle: windows::Win32::Foundation::HANDLE) -> Result<String, String> {
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SE_KERNEL_OBJECT};

    match read_with_class(handle, SE_FILE_OBJECT) {
        Ok(observed) => Ok(observed),
        Err(from_file_class) => read_with_class(handle, SE_KERNEL_OBJECT).map_err(|from_kernel| {
            format!("{from_file_class}; asked again as a kernel object: {from_kernel}")
        }),
    }
}

/// One `GetSecurityInfo` DACL read, as a permission string.
#[cfg(windows)]
fn read_with_class(
    handle: windows::Win32::Foundation::HANDLE,
    class: windows::Win32::Security::Authorization::SE_OBJECT_TYPE,
) -> Result<String, String> {
    use windows::Win32::Security::Authorization::GetSecurityInfo;
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `handle` is a live pipe handle. The three `None`s are the owner,
    // group and SACL, none of which is read here, and `descriptor` is an
    // out-parameter the API allocates into on success and this function
    // releases.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            class,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if status != windows::Win32::Foundation::WIN32_ERROR(0) {
        return Err(format!("Win32 error {}", status.0));
    }
    if acl.is_null() {
        // A null DACL is not "nothing is granted": it is the opposite, and the
        // difference is the whole point of reading this back. Reported as the
        // danger it is rather than as an empty list.
        // SAFETY: the descriptor came from the call above and is not used after.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(descriptor.0),
            ));
        }
        return Err(
            "the object has no permission list at all, which grants every right to every account"
                .to_string(),
        );
    }
    let printed = sddl_from_descriptor(descriptor);
    // SAFETY: the descriptor came from the call above and is not used after this.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            descriptor.0,
        )));
    }
    printed
}

/// A permission list kept alive for the `CreateNamedPipeW` call that needs it.
///
/// The descriptor is the system's allocation and is released on drop; the
/// `SECURITY_ATTRIBUTES` points into it and is only meaningful while this value
/// lives, which is why the two are one value rather than two.
#[cfg(windows)]
struct PipeSecurityAttributes {
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
    attributes: windows::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl PipeSecurityAttributes {
    /// Build the attributes for a pipe created as `name`.
    ///
    /// `name` is only for the error message: a permission list that will not
    /// parse is a bug in this file, but the sentence has to say which pipe was
    /// not created because of it.
    fn new(name: &str) -> Result<Self, ServiceError> {
        let descriptor =
            descriptor_from_sddl(CONTROL_PIPE_SDDL).map_err(|message| ServiceError::Pipe {
                name: name.to_string(),
                message: format!("could not be created: {message}"),
            })?;
        Ok(Self {
            descriptor,
            attributes: windows::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: windows::core::BOOL(0),
            },
        })
    }

    /// The pointer `CreateNamedPipeW` wants.
    fn as_ptr(&self) -> *const windows::Win32::Security::SECURITY_ATTRIBUTES {
        &self.attributes
    }
}

#[cfg(windows)]
impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is released
        // exactly once, here.
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(self.descriptor.0),
            ));
        }
    }
}

/// The server end of the control pipe.
///
/// One instance at a time, created and connected in a loop. The name is held so
/// that the next instance can be created after a client goes: a pipe handle
/// serves exactly one client for its lifetime, and there is no way to re-listen
/// on a disconnected instance other than to disconnect it and connect it again.
#[derive(Debug)]
pub struct PipeListener {
    name: String,
    /// What the first instance's permission list turned out to be.
    ///
    /// Read once, at creation, rather than on every instance. A list that was
    /// wrong on the first instance is a bug in this file, and re-reading it per
    /// client would be a `GetSecurityInfo` per connection to re-establish a fact
    /// that cannot change between them — every instance is created by the same
    /// call with the same constant.
    permissions: PipePermissions,
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

// A pipe handle is a kernel object handle: valid process-wide and usable from
// any thread. It is owned by exactly one `PipeListener` — or, after a connect,
// by exactly one `PipeConnection` — and neither is `Sync`, because two threads
// reading one handle is the interleaving this transport must not allow.
#[cfg(windows)]
unsafe impl Send for PipeListener {}

impl PipeListener {
    /// Create the first instance of `name`.
    ///
    /// The name is checked with [`av_ipc::is_valid_pipe_name`] before the call,
    /// because `CreateNamedPipeW` silently *truncates* a name over 256
    /// characters rather than refusing it. A service that truncated its own
    /// name would be listening on a pipe no client looks at, and the failure
    /// would present as "the service is not running".
    pub fn create(name: &str) -> Result<Self, ServiceError> {
        if !av_ipc::is_valid_pipe_name(name) {
            return Err(ServiceError::Pipe {
                name: name.to_string(),
                message: format!(
                    "not a usable pipe name: it must start with {} and be at most {} bytes with no \
                     further separator",
                    av_ipc::PIPE_PREFIX,
                    av_ipc::MAX_PIPE_NAME_BYTES
                ),
            });
        }
        #[cfg(windows)]
        {
            let handle = create_instance(name)?;
            // Read the permission list back off the object that was just made,
            // rather than reporting the constant. See [`PipePermissions`].
            let observed = read_back(handle);
            let permissions = PipePermissions {
                requested: CONTROL_PIPE_SDDL,
                observed,
            };
            if !permissions.holds() {
                // A warning rather than a refusal: the service's job is to
                // answer for this machine's files, and a pipe whose permission
                // list is not what this build writes is still a pipe its own
                // front ends can use. Refusing to start over it would take the
                // product down for a defect in one of its own constants, and
                // the condition is reported in `wenle protect status` and in
                // the service log.
                log::warn!("{}", permissions.describe());
            }
            Ok(Self {
                name: name.to_string(),
                permissions,
                handle,
            })
        }
        #[cfg(not(windows))]
        {
            Err(ServiceError::Pipe {
                name: name.to_string(),
                message: "named pipes are a Windows transport and this build has none".to_string(),
            })
        }
    }

    /// The name this listener serves.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What this listener's instances were created with, and what the first one
    /// turned out to hold.
    pub fn permissions(&self) -> &PipePermissions {
        &self.permissions
    }

    /// Wait for a client and hand back the connection it arrived on.
    ///
    /// Blocks until somebody connects. `ConnectNamedPipe` on an instance that
    /// already has a client reports `ERROR_PIPE_CONNECTED`, which is success
    /// with a misleading name: a client that connected between
    /// `CreateNamedPipeW` and this call is connected, and treating that as a
    /// failure is how a service drops the one client that was fastest.
    #[cfg(windows)]
    pub fn connect(&mut self) -> Result<PipeConnection, ServiceError> {
        use windows::Win32::System::Pipes::ConnectNamedPipe;

        // SAFETY: `handle` is an unconnected pipe instance created by
        // `create_instance` and not yet owned by a connection. Synchronous, so
        // the null `OVERLAPPED` is the documented way to ask for a blocking
        // connect.
        let connected = unsafe { ConnectNamedPipe(self.handle, None) };
        match connected {
            Ok(()) => {}
            Err(error) if crate::win32::code(&error) == crate::win32::ERROR_PIPE_CONNECTED => {}
            Err(error) => {
                return Err(ServiceError::Pipe {
                    name: self.name.clone(),
                    message: format!("a client could not be connected: {error}"),
                })
            }
        }
        // The instance is the connection from here on: one handle serves one
        // client, and the listener has given it away. It gets a fresh instance
        // after the client goes.
        let handle = self.handle;
        self.handle = create_instance(&self.name)?;
        Ok(PipeConnection {
            name: self.name.clone(),
            handle,
            closed: false,
        })
    }

    #[cfg(not(windows))]
    pub fn connect(&mut self) -> Result<PipeConnection, ServiceError> {
        Err(ServiceError::Pipe {
            name: self.name.clone(),
            message: "named pipes are a Windows transport and this build has none".to_string(),
        })
    }

    /// Wait until a client is already connected, or `timeout` passes.
    ///
    /// The service uses this to spend its first moments doing something useful
    /// instead of blocking in `ConnectNamedPipe`: `PeekNamedPipe` says whether
    /// anybody is on the other end without consuming anything, and a service
    /// that is being started has a rule database to load.
    ///
    /// # The state this cannot report, and [`Self::refresh`] exists for
    ///
    /// `false` means "no client is attached", and it is the answer for two
    /// different situations. One is an instance no client has ever reached,
    /// which is what the accept loop wants and can wait on. The other is an
    /// instance a client reached and left *before* anything accepted it, and
    /// that instance is not waitable: no later client can connect to it, so a
    /// loop that only polled would poll for ever while the SCM was told the
    /// service was `RUNNING`. `PeekNamedPipe` does not distinguish them, so a
    /// caller that gets `false` and intends to wait again must call
    /// [`Self::refresh`] first.
    /// # Why this waits once instead of polling
    ///
    /// The loop used to ask every [`POLL_INTERVAL`] — five milliseconds — until
    /// the timeout ran out. That is twenty questions for the tenth of a second
    /// [`crate::control::ACCEPT_POLL`] allows, and therefore two hundred a
    /// second, for ever, on a service with no client, no driver and nothing to
    /// do. Measured on the shipped build: **2.1% of one core, continuously**,
    /// all of it in this loop's sleeps on the main thread. It is the largest
    /// single idle cost the product had.
    ///
    /// The granularity bought nothing, which is the part worth saying. The
    /// caller's timeout *is* the latency the product documents — `ACCEPT_POLL`
    /// says "a tenth of a second makes a stop take at most that long to be
    /// noticed and costs an idle service **ten** wake-ups a second", and the
    /// ten is this loop's own interval, not the inner one. Noticing a client in
    /// five milliseconds rather than a hundred only helps if something is
    /// waiting on a sub-tenth-of-a-second connection, and nothing is: the
    /// slowest thing that connects is a front end that redraws once a second.
    #[cfg(windows)]
    pub fn wait_for_client(&self, timeout: std::time::Duration) -> bool {
        use windows::Win32::System::Pipes::PeekNamedPipe;

        // One question, then one wait, then one more question. The second
        // question is the point of waiting at all: without it a caller that
        // waited the full timeout would report "nobody" for a client that
        // arrived one instruction after the deadline passed.
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut available = 0u32;
            // SAFETY: the handle is a pipe instance owned by this listener, and
            // the only out-parameter is a `u32` on this stack that outlives the
            // call. A null `OVERLAPPED` is correct for a synchronous handle.
            let peered =
                unsafe { PeekNamedPipe(self.handle, None, 0, None, Some(&mut available), None) };
            // `Ok` means a client is attached, whether or not it has sent
            // anything: `PeekNamedPipe` fails on an instance with no client and
            // succeeds on one with a client that is being quiet.
            if peered.is_ok() {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            // The whole remainder in one sleep. A `Duration::ZERO` timeout —
            // which is how [`Self::refresh`] asks its single question — never
            // reaches here, because the check above catches it first.
            std::thread::sleep(deadline.saturating_duration_since(now));
        }
    }

    #[cfg(not(windows))]
    pub fn wait_for_client(&self, _timeout: std::time::Duration) -> bool {
        false
    }

    /// Give the listener a fresh instance, so that the next client has
    /// somewhere to arrive.
    ///
    /// # The state this exists for
    ///
    /// The instance is created before the loop is ready to accept on it, and
    /// deliberately: a client that arrives while the service is starting, or
    /// while it is busy with another client, should queue on a waiting instance
    /// rather than get `ERROR_PIPE_BUSY` and be told the service may not be
    /// running. That is what makes the window — `host.drain()` plus a poll
    /// interval on an idle service, and the whole duration of a scan on a busy
    /// one — in which a client can connect and go away again without anything
    /// ever accepting it.
    ///
    /// The instance left behind is in neither of the states the loop knows
    /// about. See [`Self::wait_for_client`]: `PeekNamedPipe` reports it as "no
    /// client", exactly as it reports a brand-new instance, and no later client
    /// can connect to it. So a loop that polled and waited, polled and waited,
    /// would wait for ever — reporting `RUNNING` to the SCM the whole time and
    /// answering nobody, which any process on this machine could bring about
    /// with one `CreateFileW` and a `CloseHandle`.
    ///
    /// # Why this replaces the instance rather than repairing it
    ///
    /// `DisconnectNamedPipe` is the documented way to recycle an instance, and
    /// it was the first thing tried here — see `recycle` in this file's
    /// history. It is the right call for an instance whose client the *server*
    /// had accepted, and it does not work for this state: the instance is left
    /// one no client can reach, so `connect_to`'s `WaitNamedPipeW` spends its
    /// full five seconds and then reports "no instance became available". That
    /// was measured, not reasoned about — it is what
    /// `an_instance_a_client_abandoned_is_replaced_rather_than_waited_on_for_ever`
    /// fails with, twice, on a quiet machine, and it is why this is a
    /// replacement rather than a call to `DisconnectNamedPipe`. A fresh
    /// `CreateNamedPipeW` is in the listening state and nothing else needs to
    /// be true of it.
    ///
    /// # Why it is asked on every idle pass rather than when suspected
    ///
    /// There is nothing to suspect from: the two states are indistinguishable
    /// until the instance is replaced, so the replacement is the whole of the
    /// answer. The cost of asking is one create and one close per poll interval
    /// while the service is idle and nobody is talking to it — two calls
    /// against the twenty `PeekNamedPipe` calls the same pass already makes —
    /// which is the cheapest moment this service has.
    ///
    /// # Why the new instance is created before the old one is closed
    ///
    /// So that the name never stops existing. Closing first would leave a gap
    /// in which no instance of the name is there at all, and `WaitNamedPipeW`
    /// returns *immediately* when a pipe does not exist — so a client arriving
    /// in that gap would be told the service is not running instead of being
    /// made to wait a moment. Creating first means a client sees one instance
    /// or the other at every instant.
    ///
    /// # The one client this can drop
    ///
    /// A client that connects in the moment between the poll that saw nobody
    /// and this call is holding the instance this call closes, and goes with
    /// it. The last look before the close is what narrows that from a poll
    /// interval to the few instructions between two Win32 calls, and it is
    /// worth stating because it is the one case where this transport can drop a
    /// healthy connection. The alternative is a control plane that stops
    /// accepting altogether.
    #[cfg(windows)]
    pub fn refresh(&mut self) -> Result<(), ServiceError> {
        // One more look before the instance goes. `Duration::ZERO` makes this
        // a single `PeekNamedPipe` rather than another wait: somebody arrived
        // since the poll, they are on the instance about to be closed, and the
        // instance therefore stays and nothing here is needed.
        if self.wait_for_client(std::time::Duration::ZERO) {
            return Ok(());
        }
        let fresh = create_instance(&self.name)?;
        let stale = std::mem::replace(&mut self.handle, fresh);
        // SAFETY: `stale` came from `CreateNamedPipeW`, is owned by this
        // listener alone, and is closed exactly once, here. The name outlives
        // the close because `fresh` is already holding it.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(stale);
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn refresh(&mut self) -> Result<(), ServiceError> {
        Err(ServiceError::Pipe {
            name: self.name.clone(),
            message: "named pipes are a Windows transport and this build has none".to_string(),
        })
    }
}

#[cfg(windows)]
impl Drop for PipeListener {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateNamedPipeW` and is closed exactly
        // once, here. Closing the last instance removes the pipe's name.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

/// One connected client.
#[derive(Debug)]
pub struct PipeConnection {
    name: String,
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    /// Set once the peer has gone, so a second read reports the same thing
    /// rather than a fresh error from a closed handle.
    closed: bool,
}

#[cfg(windows)]
unsafe impl Send for PipeConnection {}

impl PipeConnection {
    /// Connect to a service listening on `name`.
    ///
    /// The client half of this transport, and it exists in the service crate
    /// rather than in a client crate because it is the same code either way —
    /// the pipe is symmetric — and because the end-to-end test that proves the
    /// transport works has to be able to play both parts. A client library
    /// would wrap this; it would not replace it.
    ///
    /// `WaitNamedPipeW` first, because a service that has just started has
    /// created its first instance but not called `ConnectNamedPipe` yet, and a
    /// bare `CreateFileW` in that window gets `ERROR_PIPE_BUSY` — which is a
    /// "try again" and not a "no service", though the two present identically
    /// to a user.
    pub fn connect_to(name: &str) -> Result<Self, ServiceError> {
        #[cfg(windows)]
        {
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
            };
            use windows::Win32::System::Pipes::WaitNamedPipeW;

            let wide = crate::win32::to_wide_str(name);
            // SAFETY: `wide` is NUL-terminated and outlives the call.
            let waited =
                unsafe { WaitNamedPipeW(windows::core::PCWSTR(wide.as_ptr()), CONNECT_TIMEOUT_MS) };
            if !waited.as_bool() {
                // Built from `GetLastError` straight away, before anything else
                // on this thread can overwrite it — the same idiom
                // `create_instance` uses for `CreateNamedPipeW`, which reports
                // the same way.
                let error = windows::core::Error::from_thread();
                let code = crate::win32::code(&error);
                // One return value, two failures, and they send a person to two
                // different places. `WaitNamedPipeW` returns at once when no
                // instance of the name exists at all — nothing is running under
                // it — and spends the entire timeout when instances exist and
                // none will take a client, which is a service that is there and
                // stuck. A single message covering both would have to say "the
                // service may not be running", which is the wrong advice for one
                // of them and unhelpfully vague for the other. The split is on
                // the one code that is documented for this call rather than on a
                // guess: everything else keeps the hedged wording, because
                // claiming a service is there when the system said something
                // this does not recognise would be worse than saying less.
                let message = if code == crate::win32::ERROR_FILE_NOT_FOUND {
                    "there is no pipe by this name on this machine — no service is running \
                     under it, and none is installed"
                        .to_string()
                } else {
                    format!(
                        "no instance of this pipe would take a client within \
                         {CONNECT_TIMEOUT_MS} ms (the system reported error {code}) — a service \
                         is probably running under this name and not answering"
                    )
                };
                return Err(ServiceError::Pipe {
                    name: name.to_string(),
                    message,
                });
            }
            // SAFETY: `wide` is NUL-terminated and outlives the call; the rest
            // are values, and a null security descriptor and template are what
            // an existing pipe wants.
            let handle = unsafe {
                CreateFileW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    windows::Win32::Foundation::GENERIC_READ.0
                        | windows::Win32::Foundation::GENERIC_WRITE.0,
                    // Zero, because a pipe instance is not shared the way a file
                    // is: the share mode governs re-opening the same file, and
                    // what actually limits a pipe is the instance count the
                    // server created. `windows` 0.62 made this a newtype, so the
                    // literal has to name the type it was always meant to be.
                    windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            match handle {
                Ok(handle) => Ok(Self {
                    name: name.to_string(),
                    handle,
                    closed: false,
                }),
                Err(error) => Err(ServiceError::Pipe {
                    name: name.to_string(),
                    message: format!("could not be opened: {error}"),
                }),
            }
        }
        #[cfg(not(windows))]
        {
            Err(ServiceError::Pipe {
                name: name.to_string(),
                message: "named pipes are a Windows transport and this build has none".to_string(),
            })
        }
    }

    /// The pipe this connection is on.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The handle underneath, for the one caller that has to ask the operating
    /// system who is on the other end of it.
    ///
    /// [`crate::peer`] is that caller: an access check needs the connection
    /// itself — `ImpersonateNamedPipeClient` takes the pipe handle and nothing
    /// else — and the alternative, having `PipeConnection` carry an identity it
    /// learned at connect time, would put a security decision inside the class
    /// that knows only how to move bytes.
    ///
    /// Not `pub`: this is the crate's own business, and a `HANDLE` out of a
    /// `PipeConnection` in a front end's hands is a way to reach a kernel object
    /// that has nothing to do with moving a frame.
    #[cfg(windows)]
    pub(crate) fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle
    }
}

impl Connection for PipeConnection {
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), IpcError> {
        #[cfg(windows)]
        {
            use windows::Win32::Storage::FileSystem::WriteFile;

            if self.closed {
                return Err(IpcError::PeerClosed);
            }
            let mut written_total = 0usize;
            while written_total < frame.len() {
                let mut written = 0u32;
                let chunk = &frame[written_total..];
                // SAFETY: the slice outlives the call and its length is what the
                // signature passes to the operating system; `written` is a `u32`
                // on this stack. A null `OVERLAPPED` is correct for a
                // synchronous handle.
                let result =
                    unsafe { WriteFile(self.handle(), Some(chunk), Some(&mut written), None) };
                match result {
                    Ok(()) if written == 0 => {
                        // A zero-length write on a blocking pipe means the far
                        // end went, and looping on it would spin.
                        self.closed = true;
                        return Err(IpcError::PeerClosed);
                    }
                    Ok(()) => written_total += written as usize,
                    Err(error) if crate::win32::is_peer_gone(crate::win32::code(&error)) => {
                        self.closed = true;
                        return Err(IpcError::PeerClosed);
                    }
                    Err(error) => {
                        return Err(IpcError::Transport(format!(
                            "writing to {}: {error}",
                            self.name
                        )))
                    }
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = frame;
            Err(IpcError::Transport(
                "this build has no named-pipe transport".to_string(),
            ))
        }
    }

    /// Read what is waiting, and nothing if nothing is.
    ///
    /// `PeekNamedPipe` first so that an empty pipe is `Read::Bytes(0)` rather
    /// than a blocked thread — see this module's documentation. `ReadFile` is
    /// then given exactly how much is available, so it returns immediately and
    /// never waits for a frame that has not finished arriving: a partial frame
    /// is `av_ipc::Decoder`'s business and it handles chunks of any size.
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<Read, IpcError> {
        #[cfg(windows)]
        {
            use windows::Win32::Storage::FileSystem::ReadFile;
            use windows::Win32::System::Pipes::PeekNamedPipe;

            if self.closed {
                return Err(IpcError::PeerClosed);
            }
            if buf.is_empty() {
                return Ok(Read::Bytes(0));
            }

            let mut available = 0u32;
            // SAFETY: the handle is a connected pipe owned by this connection;
            // `available` is a `u32` on this stack that outlives the call. The
            // null data-out arguments are this call being used only to ask a
            // question, which is what it is for.
            let peered =
                unsafe { PeekNamedPipe(self.handle(), None, 0, None, Some(&mut available), None) };
            if let Err(error) = peered {
                let code = crate::win32::code(&error);
                if crate::win32::is_peer_gone(code) {
                    self.closed = true;
                    return Ok(Read::Closed);
                }
                return Err(IpcError::Transport(format!(
                    "asking {} how much has arrived: {error}",
                    self.name
                )));
            }
            if available == 0 {
                // Connected and quiet. Not an error, and not a close.
                return Ok(Read::Bytes(0));
            }

            // At most what is there, and at most what the caller offered: a
            // `ReadFile` asked for more than `PeekNamedPipe` reported would
            // block, which is the one thing this function promises not to do.
            let wanted = (available as usize).min(buf.len());
            let mut read = 0u32;
            // SAFETY: the sub-slice outlives the call and its length is what the
            // signature passes to the operating system; `read` is a `u32` on
            // this stack. A null `OVERLAPPED` is correct for a synchronous
            // handle.
            let result = unsafe {
                ReadFile(
                    self.handle(),
                    Some(&mut buf[..wanted]),
                    Some(&mut read),
                    None,
                )
            };
            match result {
                // Zero bytes from a read that was asked for more means the far
                // end went; on a byte-mode pipe a zero-length read *is* the
                // close notification.
                Ok(()) if read == 0 => {
                    self.closed = true;
                    Ok(Read::Closed)
                }
                Ok(()) => Ok(Read::Bytes(read as usize)),
                Err(error) if crate::win32::is_peer_gone(crate::win32::code(&error)) => {
                    self.closed = true;
                    Ok(Read::Closed)
                }
                Err(error) => Err(IpcError::Transport(format!(
                    "reading from {}: {error}",
                    self.name
                ))),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = buf;
            Err(IpcError::Transport(
                "this build has no named-pipe transport".to_string(),
            ))
        }
    }
}

impl Drop for PipeConnection {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows::Win32::System::Pipes::DisconnectNamedPipe;

            // SAFETY: the handle is a connected pipe instance owned by this
            // connection, and it is disconnected and closed exactly once, here.
            // The `DisconnectNamedPipe` result is deliberately ignored: it
            // fails when the client has already gone, which is the common case
            // and not a fault.
            unsafe {
                let _ = DisconnectNamedPipe(self.handle);
                let _ = windows::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

/// How long a poll of a quiet pipe waits before asking again.
///
/// The cost of the non-blocking read this module documents: an idle client
/// costs one `PeekNamedPipe` and one sleep per interval, which is nothing, and
/// a client that sends a request waits up to this long for the service to
/// notice. Five milliseconds is below the threshold at which a person notices a
/// click and far above the cost of the syscall.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// A pipe name that is unique to this process and this moment.
///
/// For tests, which must not connect to the installed service or collide with
/// each other. The process id and a counter together are unique on one machine:
/// the process id separates concurrent test binaries, and the counter separates
/// tests inside one binary, which Rust runs on several threads at once. A name
/// that outlives the process that made it is not a hazard either, because
/// closing the last instance of a pipe removes the name — so a counter that
/// restarts at zero in the next run of the same binary cannot collide with a
/// listener that no longer exists.
///
/// `tag` is for a person reading a pipe listing while a test is stuck, and must
/// not contain a `\`: see [`av_ipc::is_valid_pipe_name`], which is what the
/// listener checks before it creates anything.
pub fn unique_name(tag: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{}{}-{tag}-{counter}",
        av_ipc::PIPE_PREFIX,
        std::process::id()
    )
}

/// Read `name`'s permission list off the machine.
///
/// # Why a checker opens the pipe instead of asking the service
///
/// Because the question is what the *machine* holds, and a service's answer
/// about itself is not that. The same reason `av_guard::files::audit` re-reads
/// a directory it just hardened: a call that returned success is not an object
/// that changed.
///
/// # The cost, stated rather than hidden
///
/// Opening a pipe **connects to it**. A checker that calls this consumes one
/// waiting instance, the service accepts a client that then says nothing and
/// goes, and the accept loop moves on — which is a state this transport already
/// has to handle, because a client that connects and leaves is exactly what
/// [`PipeListener::refresh`] exists for. `READ_CONTROL` alone is asked for, so
/// nothing on the pipe can be read or written through this handle.
///
/// A machine with no control pipe on it — the service is not running, or is not
/// installed — is reported as an unread permission list with that as the
/// reason, not as an error return.
pub fn audit(name: &str) -> PipePermissions {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows::Win32::System::Pipes::WaitNamedPipeW;

        if !av_ipc::is_valid_pipe_name(name) {
            return PipePermissions::unread(format!("`{name}` is not a pipe name"));
        }
        let wide = crate::win32::to_wide_str(name);
        // The same wait a client does, for the same reason: a service that has
        // just started has created its first instance but not yet called
        // `ConnectNamedPipe`, and a bare open in that window gets
        // `ERROR_PIPE_BUSY`, which is a "try again" and not a "no service".
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        let waited =
            unsafe { WaitNamedPipeW(windows::core::PCWSTR(wide.as_ptr()), CONNECT_TIMEOUT_MS) };
        if !waited.as_bool() {
            return PipePermissions::unread(format!(
                "no control pipe by that name would take a client within {CONNECT_TIMEOUT_MS} ms \
                 ({}) — the service is probably not running",
                windows::core::Error::from_thread()
            ));
        }
        /// `READ_CONTROL` — enough to read the permission list off the object
        /// and nothing else.
        const READ_CONTROL: u32 = 0x0002_0000;
        // SAFETY: `wide` is NUL-terminated and outlives the call; the rest are
        // values, and null security attributes and template are what an
        // existing pipe wants.
        let opened = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                READ_CONTROL,
                // `READ_CONTROL` is not a data access, so the read and write
                // share bits do not conflict with what the service is doing
                // with the same instance.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let handle: HANDLE = match opened {
            Ok(handle) => handle,
            Err(error) => {
                return PipePermissions::unread(format!(
                    "the control pipe could not be opened to read its permissions ({error})"
                ))
            }
        };
        let observed = read_back(handle);
        // SAFETY: the handle came from `CreateFileW` above and is closed exactly
        // once, here.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
        PipePermissions {
            requested: CONTROL_PIPE_SDDL,
            observed,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        PipePermissions::unread("named pipes are a Windows transport and this build has none")
    }
}

/// Create one unconnected instance of `name`.
///
/// Every instance is created with [`CONTROL_PIPE_SDDL`] and nothing else: a
/// permission list that varied between instances would be a list whose meaning
/// depended on which instance a client happened to reach.
#[cfg(windows)]
fn create_instance(name: &str) -> Result<windows::Win32::Foundation::HANDLE, ServiceError> {
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let wide = crate::win32::to_wide_str(name);
    // Built here and alive until the end of the function, which is all
    // `CreateNamedPipeW` needs: it copies the DACL onto the object it creates.
    let security = PipeSecurityAttributes::new(name)?;
    // SAFETY: `wide` is NUL-terminated and outlives the call, and `security`
    // owns the descriptor its pointer aims at for at least as long as the call.
    let handle = unsafe {
        CreateNamedPipeW(
            windows::core::PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(security.as_ptr()),
        )
    };
    if handle.is_invalid() {
        // `CreateNamedPipeW` reports through `GetLastError` rather than through
        // an `HRESULT`, which is what `Error::from_thread` builds one from.
        return Err(ServiceError::Pipe {
            name: name.to_string(),
            message: format!(
                "could not be created: {}",
                windows::core::Error::from_thread()
            ),
        });
    }
    Ok(handle)
}

/// True when `path` names a pipe, which is the only shape this transport's
/// names take.
///
/// A thin wrapper over [`av_ipc::is_valid_pipe_name`] that takes a `Path`, for
/// a caller that has one. Kept because a caller that has a `Path` and reaches
/// for `to_string_lossy` to check it has already lost the argument about
/// whether the name was the one it meant.
pub fn is_pipe_path(path: &Path) -> bool {
    path.to_str().is_some_and(av_ipc::is_valid_pipe_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_is_not_a_pipe_is_refused_before_the_call() {
        // `CreateNamedPipeW` truncates a name over 256 bytes instead of
        // refusing it, so a name that is too long has to be caught before the
        // call or the service listens on a pipe whose name it has already
        // forgotten. Each of these is a name a plausible mistake produces, and
        // the refusal must come from the check rather than from the system —
        // which is why these run without touching one.
        for name in [
            r"\\.\pipe\",       // the prefix, with nothing after it
            r"wenleav-control", // no prefix at all
            r"\\.\pipe\a\b",    // a second separator, which no client would build
            "",
        ] {
            assert!(
                !av_ipc::is_valid_pipe_name(name),
                "{name} is not a usable pipe name"
            );
        }
        // One over the byte limit: the case the truncation makes dangerous
        // rather than merely wrong. A client asking for the first 256 bytes of
        // this is asking for a different pipe.
        let long = format!(
            "{}{}",
            av_ipc::PIPE_PREFIX,
            "x".repeat(av_ipc::MAX_PIPE_NAME_BYTES)
        );
        assert!(!av_ipc::is_valid_pipe_name(&long));
    }

    #[test]
    fn the_name_the_product_ships_is_one_this_transport_can_create() {
        // `av_ipc::PIPE_NAME` is the name a client looks for. This is the
        // transport that has to be able to create it, and the two agreeing is a
        // fact worth pinning rather than a coincidence: a name the protocol
        // exported and the transport refused would be a product that never
        // starts.
        assert!(av_ipc::is_valid_pipe_name(av_ipc::PIPE_NAME));
        assert!(is_pipe_path(Path::new(av_ipc::PIPE_NAME)));
        assert!(av_ipc::PIPE_NAME.len() <= av_ipc::MAX_PIPE_NAME_BYTES);
    }

    #[test]
    fn two_names_from_one_process_are_two_valid_names() {
        // The property the end-to-end tests rest on: a name this function makes
        // is one the listener will actually accept, and two calls never produce
        // one name. A collision would be two listeners on one pipe, which
        // `CreateNamedPipeW` allows and which presents as neither test failing.
        let first = unique_name("status");
        let second = unique_name("status");
        assert_ne!(first, second);
        assert!(av_ipc::is_valid_pipe_name(&first), "{first}");
        assert!(av_ipc::is_valid_pipe_name(&second), "{second}");
        assert_ne!(first, av_ipc::PIPE_NAME);
        assert!(first.len() <= av_ipc::MAX_PIPE_NAME_BYTES);
    }

    #[test]
    fn the_poll_interval_is_a_poll_interval() {
        // A number rather than a constant nobody can check. The loop that uses
        // it sleeps between reads, so zero would be a busy spin on one core and
        // an hour would be a service that ignores a client.
        assert!(POLL_INTERVAL >= std::time::Duration::from_millis(1));
        assert!(POLL_INTERVAL <= std::time::Duration::from_millis(100));
    }

    #[test]
    fn the_permission_list_names_no_account_that_should_not_be_on_it() {
        // Sourced from the text rather than from a created object, so it holds
        // on a machine where no pipe can be made at all — and so it fails on the
        // day somebody adds an account to the constant rather than on the day a
        // test machine happens to disagree.
        //
        // `WD` is Everyone and `AN` is ANONYMOUS LOGON: the two that turn a
        // control channel that can quarantine files into one anybody on the
        // machine can drive. `BU` is `BUILTIN\Users`, which is the same set as
        // `IU` in practice and is not named separately for that reason; the
        // check is here because naming it would suggest this list separates one
        // user from another, which it does not.
        for unwanted in [";;;WD)", ";;;AN)", ";;;BU)", ";;;BG)"] {
            assert!(
                !CONTROL_PIPE_SDDL.contains(unwanted),
                "{unwanted} must not be on the control pipe: {CONTROL_PIPE_SDDL}"
            );
        }
        // The three that must be there, so that a constant emptied by accident
        // fails here rather than at the first client.
        for wanted in [";;;SY)", ";;;BA)", ";;;IU)"] {
            assert!(
                CONTROL_PIPE_SDDL.contains(wanted),
                "{wanted} must be on the control pipe: {CONTROL_PIPE_SDDL}"
            );
        }
        // `P` — protected — is what stops anything being inherited in. A pipe
        // has no parent to inherit from, so this is belt and braces; it is
        // checked because the same constant shape is what the directory
        // hardening uses, and a list that stopped being protected there was
        // measured to be one any user could still write to.
        assert!(
            CONTROL_PIPE_SDDL.starts_with("D:P"),
            "the permission list must be protected: {CONTROL_PIPE_SDDL}"
        );
    }

    #[test]
    fn a_permission_list_that_was_not_read_back_is_not_reported_as_held() {
        // The whole point of carrying the pair. A value with no read-back must
        // never compare equal to the wanted list, whatever the wanted list is,
        // because the failure this guards against is reporting protection that
        // was never observed.
        let unread = PipePermissions::unread("the object would not say");
        assert!(!unread.holds());
        assert!(unread.describe().contains("could not be read back"));

        // And a read-back of something else is not a match either. This is the
        // shape of the defect the read-back was added for: `CreateNamedPipeW`
        // returns success and the object holds the creating token's default
        // permission list. Measured on this machine, that is
        // `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-…-1001)(A;;FR;;;WD)(A;;FR;;;AN)`
        // — a list naming `Everyone` and `ANONYMOUS LOGON`, which the constant
        // above deliberately does not name.
        let other = PipePermissions {
            requested: CONTROL_PIPE_SDDL,
            observed: Ok(
                "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1001)(A;;FR;;;WD)(A;;FR;;;AN)"
                    .to_string(),
            ),
        };
        assert!(!other.holds());
        let described = other.describe();
        assert!(described.contains("NOT"), "{described}");
        assert!(described.contains("D:P(A;;GA;;;SY)(A;;GA;;;BA)"), "{described}");
    }

    #[cfg(windows)]
    #[test]
    fn the_permission_list_grants_what_the_sdk_says_it_grants() {
        use windows::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };

        // Compared against the SDK's own constants rather than against numbers
        // written here, so the test says what the list means and not what it
        // happened to evaluate to the day it was run.
        let granted = grants(CONTROL_PIPE_SDDL).expect("the constant must be a valid list");
        assert_eq!(
            granted,
            vec![
                Grant {
                    sid: "S-1-5-18".to_string(),
                    mask: FILE_ALL_ACCESS.0
                },
                Grant {
                    sid: "S-1-5-32-544".to_string(),
                    mask: FILE_ALL_ACCESS.0
                },
                Grant {
                    sid: "S-1-5-4".to_string(),
                    mask: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
                },
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
            "sorted by account, as `grants` returns them"
        );
        // The list is closed: three accounts, and the resolution above did not
        // quietly add a fourth.
        assert_eq!(granted.len(), 3, "{granted:?}");
    }

    #[cfg(windows)]
    #[test]
    fn the_same_grant_written_three_ways_compares_equal() {
        use windows::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };

        // The regression this comparison exists for. `CreateNamedPipeW` stores
        // the constant with its generic bits resolved — measured, that is
        // `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;IU)` — and a comparison of
        // the two strings calls a correct pipe a permission list that did not
        // take. Built here from the SDK's constants rather than copied from the
        // measurement, so it stays true if the measurement is ever re-taken.
        let stored = format!(
            "D:P(A;;{:#x};;;SY)(A;;{:#x};;;BA)(A;;{:#x};;;IU)",
            FILE_ALL_ACCESS.0,
            FILE_ALL_ACCESS.0,
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0
        );
        let permissions = PipePermissions {
            requested: CONTROL_PIPE_SDDL,
            observed: Ok(stored),
        };
        assert!(permissions.holds(), "{}", permissions.describe());

        // And the other direction, so that this cannot pass by comparing
        // nothing with nothing: a list that grants INTERACTIVE one bit less is
        // not the list that was asked for.
        let weaker = format!(
            "D:P(A;;{:#x};;;SY)(A;;{:#x};;;BA)(A;;{:#x};;;IU)",
            FILE_ALL_ACCESS.0,
            FILE_ALL_ACCESS.0,
            FILE_GENERIC_READ.0
        );
        assert!(!PipePermissions {
            requested: CONTROL_PIPE_SDDL,
            observed: Ok(weaker),
        }
        .holds());
    }

    #[cfg(windows)]
    #[test]
    fn a_pipe_this_listener_creates_holds_the_permissions_it_asked_for() {
        // The end-to-end fact: create a real pipe instance the way the service
        // does and read the permission list back off the object. This is the
        // test the old code had no equivalent of, because the old code passed a
        // null descriptor and there was nothing to compare against.
        let listener = PipeListener::create(&unique_name("permissions"))
            .expect("a pipe this process may create");
        let permissions = listener.permissions();
        assert!(
            permissions.holds(),
            "{}",
            permissions.describe()
        );
        let observed = permissions.observed.as_ref().expect("read back");
        assert!(observed.starts_with("D:P"), "{observed}");
    }

    #[cfg(windows)]
    #[test]
    fn the_audit_reader_reads_a_live_pipe_over_its_name() {
        // The path `wenle protect status` takes: no handle to the object, just
        // the name, opened with `READ_CONTROL` and read back. That is the
        // difference between a test of the comparison and a test of the check,
        // and it is the half that a stopped service cannot exercise — the test
        // below covers the stopped case.
        let name = unique_name("audit-live");
        // Bound rather than dropped: the pipe has to exist while it is read.
        let _listener = PipeListener::create(&name).expect("a pipe this process may create");
        let permissions = audit(&name);
        assert!(permissions.holds(), "{}", permissions.describe());
    }

    #[cfg(windows)]
    #[test]
    fn a_pipe_that_is_not_there_is_reported_rather_than_called_unprotected() {
        // A checker on a machine where the service is not running gets a
        // sentence saying so. It must not be an error return — the caller still
        // has a report to print — and it must not read as "the permissions were
        // read and are fine".
        let absent = unique_name("absent");
        let permissions = audit(&absent);
        assert!(!permissions.holds());
        let described = permissions.describe();
        assert!(described.contains("could not be read back"), "{described}");
        // The listener in the test above is still alive in another test, so this
        // name is genuinely one nothing is serving.
        assert!(
            permissions
                .observed
                .as_ref()
                .is_err_and(|reason| reason.contains("not running") || reason.contains("no control pipe")),
            "{:?}",
            permissions.observed
        );
    }

    #[test]
    fn a_name_that_is_not_a_pipe_is_refused_by_the_audit_reader() {
        // The audit reader checks the name before it opens anything, for the
        // same reason the listener does: `CreateFileW` on a truncated or
        // malformed name would report "no service" about a name no service was
        // ever asked to serve.
        let permissions = audit("not-a-pipe");
        assert!(!permissions.holds());
        assert!(permissions
            .observed
            .as_ref()
            .is_err_and(|reason| reason.contains("is not a pipe name")));
    }
}
