//! The Win32 registry, in the few verbs this product actually needs.
//!
//! # Why this is written here and not taken from a crate
//!
//! `winreg` is the obvious candidate and is deliberately not used. What this
//! crate needs is ten functions and three predefined roots, all of them stable
//! since Windows 2000; what `winreg` brings is a hundred public types, a
//! conversion layer built on `transmute`, and a dependency tree that would
//! appear in a security product's `Cargo.lock` for a feature that writes four
//! strings. The rest of this workspace already calls `windows` directly for its
//! ACLs, its pipes and its services (see
//! `crates/av-quarantine/src/hardening.rs`), and a second, differently-shaped
//! abstraction over the same API is a second thing to keep correct.
//!
//! What is taken from `windows` is the raw `Reg*W` calls and the `HKEY_*`
//! constants, unchanged. Nothing here re-implements what the operating system
//! does; what it adds is the four decisions the raw calls leave to every caller,
//! described below.
//!
//! # The decisions this layer makes
//!
//! **Absence is a different thing from failure, and the API does not spell the
//! two the same way.** `RegOpenKeyExW` reports a key that is not there as
//! `ERROR_FILE_NOT_FOUND`, which is a successful answer to "is this registered?"
//! rather than a fault. [`Key::open`] returns `Ok(None)` for that and for
//! `ERROR_PATH_NOT_FOUND`. Which of the two comes back depends on how much of
//! the path exists, and a caller that handled only one would report a fresh
//! machine's missing verb as a fault. [`Key::delete_tree`] and
//! [`Key::delete_value`] go further and return `Ok` for something that was never
//! there, because the state the caller asked for is the state the machine is now
//! in. [`Key::create`] is the opposite case and does *not* tolerate absence: it
//! exists to make a key exist.
//!
//! **A handle is closed exactly once.** [`Key`] is a handle with a `Drop`; there
//! is no `close`, no `Clone`, and no way to get the raw `HKEY` out. Leaking a
//! registry handle keeps a key open against `RegDeleteTreeW` and against the
//! user's own tools, and the leak is invisible until something unrelated fails.
//!
//! **A value that is not text is not text.** [`Key::string`] checks the type
//! before the bytes: a `REG_DWORD` is four bytes that would decode as two
//! UTF-16 units, and reporting it as `"Ā"` would be a menu item nobody typed.
//! And a `REG_SZ` whose bytes are not valid UTF-16 (unpaired surrogates, which
//! `Set-ItemProperty` will happily write and `String::from_utf16` refuses)
//! gives [`RegistryError::NotUnicode`], not a panic and not a lossy
//! replacement. Both are typed errors because both are *answers about a value
//! somebody else wrote*, and this product reports those to a user rather than
//! dying of them.
//!
//! **A key remembers where it is.** [`Key`] keeps its hive and path, and not
//! only for tidiness: every failure it reports names them, and without the
//! fields a `RegSetValueExW` failure would be a bare code with no indication of
//! which of the four shell verbs it happened to.
//!
//! # What it deliberately does not do
//!
//! * **No 32-bit/64-bit view flags.** `RegCreateKeyExW` writes to the view the
//!   process is in, and every shell verb here lives under `Software\Classes`,
//!   which Explorer reads from the 64-bit view on 64-bit Windows. There is no
//!   `KEY_WOW64_*KEY` anywhere in this module because there is nothing here that
//!   wants the other view: a 32-bit build of this product would register into
//!   the 32-bit view and Explorer would not see it. That is a real limitation
//!   rather than an oversight, and it is why this workspace targets
//!   `x86_64-pc-windows-msvc` only: see `rust-toolchain.toml`.
//! * **No transactions.** `RegCreateKeyTransactedW` needs a `KTM` transaction
//!   handle and a `CreateTransaction` call per install, and what it would buy is
//!   atomicity across four keys that are written in a loop and read back by
//!   Explorer individually. A half-written install is already a state that
//!   [`crate::shell::status`] reports per location, and it is repaired by
//!   running `install` again.
//! * **No watching.** Nothing here takes a change notification, so nothing here
//!   notices another program rewriting these keys behind it. [`crate::shell::status`]
//!   answers that question the honest way, by re-reading.
//!
//! # Key paths and `MAX_PATH`
//!
//! `\\?\` is a filesystem prefix and means nothing to the registry, so the
//! "long path" question does not arise here in the form it usually does. What
//! does arise is a *length* limit, and this module does not work around it.
//! Win32 documents a ceiling of about 255 characters on the `lpSubKey` a `Reg*W`
//! call accepts; the supported way past it is to split the path and descend one
//! component at a time, opening each level in turn.
//!
//! That is not implemented, and the reason is that the two numbers are not
//! close. Every path this crate writes is a compile-time constant under
//! `Software\Classes` and is under sixty characters; the longest string a caller
//! can put into this API is a test scratch key of its own invention, which is
//! shorter still. A path over the limit therefore comes back as the API's own
//! failure ([`RegistryError::Key`] carrying the code) rather than being
//! truncated or silently descending somewhere else. Splitting the path would be
//! thirty lines defending against a case no caller in this workspace can
//! construct, and the honest thing is to say so rather than to write the code
//! and pretend the limit is gone.

use std::fmt;

use av_core::AvError;

/// Which predefined root a key hangs under.
///
/// Three of the five `HKEY_*` constants. The two that are missing are missing on
/// purpose: `HKEY_USERS` needs a SID the caller would have to derive, and
/// `HKEY_PERFORMANCE_DATA` is not a store of settings at all. Neither has
/// anything to do with registering a shell verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hive {
    /// `HKEY_CLASSES_ROOT`. A *merged* view of the machine's and the current
    /// user's `Software\Classes`, which is why a key seen through it may then
    /// not be deletable through it: the merge is done by the API and the two
    /// halves are different stores. This crate never writes to it — it writes to
    /// [`Hive::LocalMachine`] or [`Hive::CurrentUser`], which are the two halves,
    /// so that a caller always knows which one it changed. It is here because
    /// reading through it is the question "will Explorer see this?", and that
    /// question has exactly one answer.
    ClassesRoot,
    /// `HKEY_LOCAL_MACHINE`. Machine-wide, shared by every user, writable only
    /// by an administrator.
    LocalMachine,
    /// `HKEY_CURRENT_USER`. This user's own settings, writable without
    /// elevation.
    CurrentUser,
}

impl Hive {
    /// The predefined handle.
    #[cfg(windows)]
    fn raw(self) -> windows::Win32::System::Registry::HKEY {
        use windows::Win32::System::Registry::{
            HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        };
        match self {
            Self::ClassesRoot => HKEY_CLASSES_ROOT,
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::CurrentUser => HKEY_CURRENT_USER,
        }
    }

    /// The hive's name as a person writes it, for a report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassesRoot => "HKEY_CLASSES_ROOT",
            Self::LocalMachine => "HKEY_LOCAL_MACHINE",
            Self::CurrentUser => "HKEY_CURRENT_USER",
        }
    }
}

impl fmt::Display for Hive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failure from a registry call, or from reading a value somebody else wrote.
///
/// # Why this is its own enum and not [`AvError`]
///
/// [`AvError`] is the workspace's error type and is deliberately flat: its
/// `Win32` variant carries a `&'static str` call name and a `u32` code, which is
/// the right shape for "a call failed" and the wrong shape for everything else
/// this module has to say. Three of the five failures below are not call
/// failures at all — a value with the wrong type, a value that is not UTF-16,
/// and a platform with no registry — and forcing them into `AvError::Other` with
/// a formatted sentence would throw away the structure that makes them worth
/// distinguishing. What the rest of the workspace actually acts on is the code,
/// and [`RegistryError::code`] preserves it across the conversion.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A call about a key failed.
    #[error("{call} on {hive}\\{path} failed with code {code} (0x{code:08X})")]
    Key {
        /// The call, as the API spells it.
        call: &'static str,
        /// The root it was called against.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The Win32 error code — not an `HRESULT`.
        code: u32,
    },

    /// A call about a value failed.
    #[error(
        "{call} on the value `{name}` of {hive}\\{path} failed with code {code} (0x{code:08X})"
    )]
    Value {
        /// The call, as the API spells it.
        call: &'static str,
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name. The empty string is a key's *default* value, and by
        /// the time this is displayed it has been turned into `(default)` — see
        /// `display_value_name`.
        name: String,
        /// The Win32 error code.
        code: u32,
    },

    /// A value holds something other than text.
    ///
    /// Its own variant because it is not a failure of any call: the registry
    /// answered perfectly and the answer is that somebody stored a number where
    /// a menu item was expected. The type is reported as its numeric value
    /// because there is no exhaustive list of them — `REG_*` has grown over time
    /// and a value written by a newer Windows is still a fact worth printing.
    #[error("the value `{name}` of {hive}\\{path} holds registry type {found}, which is not text")]
    NotText {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name.
        name: String,
        /// The `REG_*` type the value actually has.
        found: u32,
    },

    /// A value holds something other than a 32-bit number.
    ///
    /// The mirror of [`RegistryError::NotText`], and it exists for the same
    /// reason: a caller that asked a settings question — is this feature off? —
    /// must not be handed a string that happens to look like the answer. The
    /// type *and* the length are both reported, because the two refusals this
    /// covers are different mistakes: a `REG_SZ` where a number was expected,
    /// and a value that is typed as a `REG_DWORD` but is not four bytes long.
    /// `RegSetValueExW` will store either one, and a reader that checked only
    /// the type would take the first byte of a longer value and report it.
    #[error(
        "the value `{name}` of {hive}\\{path} holds registry type {found} ({bytes} bytes), which \
         is not a 32-bit number"
    )]
    NotNumeric {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name.
        name: String,
        /// The `REG_*` type the value actually has.
        found: u32,
        /// How many bytes the value holds.
        bytes: u32,
    },

    /// A string value whose bytes are not valid UTF-16.
    ///
    /// Unpaired surrogates. Windows will hold them in a `REG_SZ`, the API reads
    /// them back without complaint, and there is no `String` that corresponds to
    /// them. Reported rather than replaced: this value is about to become a menu
    /// item or a command line, and a lossy conversion would put a different
    /// string on the user's screen from the one in the registry, silently.
    #[error("the value `{name}` of {hive}\\{path} is not valid UTF-16")]
    NotUnicode {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name.
        name: String,
    },

    /// This platform has no registry.
    #[error("this platform has no registry, so nothing can be registered in it")]
    Unsupported,

    /// A `REG_MULTI_SZ` was asked to hold an element containing a NUL.
    ///
    /// A failure of the *request* rather than of any call, which is why it is
    /// its own variant and not a [`RegistryError::Value`]: nothing was attempted
    /// and no code came back. In this format a NUL is not an escaped character,
    /// it is the end of an element — so storing one would write a list with more
    /// entries than the caller passed, each shorter than the caller asked for,
    /// and reading it back would report names nobody wrote. The one caller here
    /// writes service names, and a silently split name is a dependency that does
    /// not exist.
    #[error("the value `{name}` of {hive}\\{path} cannot hold a string with a NUL in it")]
    EmbeddedNul {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name.
        name: String,
    },
}

impl RegistryError {
    /// The Win32 error code, when the failure is one the API reported.
    ///
    /// `None` for every failure that is not a call failure — the variants with
    /// no `code` field, which are the ones answering a question rather than
    /// reporting a broken call. A caller that wants to tell "access denied" from
    /// "the key is gone" asks this; a caller that only wants to report asks
    /// [`std::fmt::Display`].
    pub fn code(&self) -> Option<u32> {
        match self {
            Self::Key { code, .. } | Self::Value { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl From<RegistryError> for AvError {
    /// Keep the code; lose the structure.
    ///
    /// The two call-failure variants become [`AvError::Win32`] so that the code
    /// survives into the rest of the workspace, where [`AvError::is_transient`]
    /// reads it and where a caller can still tell `ERROR_ACCESS_DENIED` from the
    /// rest. The ones that are not call failures have no code to keep and go
    /// through [`AvError::Other`] with the sentence a person would read. The
    /// hive and the path are in that sentence rather than in a field, which is a
    /// real loss, and the alternative is an `AvError` variant that exists for
    /// one caller in a type every crate here shares.
    fn from(error: RegistryError) -> Self {
        match error {
            RegistryError::Key { call, code, .. } | RegistryError::Value { call, code, .. } => {
                AvError::Win32 { call, code }
            }
            other => AvError::Other(other.to_string()),
        }
    }
}

/// An open registry key.
///
/// Closes on drop and cannot be copied: one `RegCloseKey` per `RegOpenKeyExW` or
/// `RegCreateKeyExW`, which is the only way to be sure a key is not held open
/// against the next thing that wants it.
///
/// There is no way to get the raw `HKEY` out. A `Key` is a decision about who
/// closes it, and a caller that could take the handle could also close it a
/// second time — and the second close on a recycled handle value closes somebody
/// else's key.
#[derive(Debug)]
pub struct Key {
    /// Where this key is, so that a failure can name it. Carried rather than
    /// reconstructed from the handle, which cannot be done.
    hive: Hive,
    /// The path below the hive, as the caller wrote it.
    path: String,
    /// The handle. On a platform with no registry no `Key` is ever built, so the
    /// field is `cfg`-free and simply never exists there.
    #[cfg(windows)]
    raw: windows::Win32::System::Registry::HKEY,
}

#[cfg(windows)]
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `RegCreateKeyExW` or
        // `RegOpenKeyExW` and has not been closed: nothing else in this module
        // can reach it, and `Key` is not `Clone`. `RegCloseKey`'s failure modes
        // are all "that handle was not valid", which cannot happen here, and a
        // `Drop` that panicked would turn a leak into an abort — the result is
        // discarded for that reason and not out of carelessness.
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(self.raw);
        }
    }
}

impl Key {
    /// The root this key hangs under.
    ///
    /// Carried by every `Key` and returned here rather than reconstructed from
    /// the handle, which cannot be done. A caller that has a key and wants to
    /// name it in a message of its own — rather than passing the failure up to
    /// be named by [`RegistryError`] — needs both halves of where it is.
    pub fn hive(&self) -> Hive {
        self.hive
    }

    /// The path below the hive, as the caller wrote it.
    ///
    /// The caller's own spelling and not a normalised one: this is the string
    /// that goes into a message, and a path that had been rewritten on the way
    /// in would send somebody looking somewhere they had not asked about.
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[cfg(windows)]
impl Key {
    /// Create a key, creating the path above it as needed.
    ///
    /// `RegCreateKeyExW` opens the key when it exists and creates it when it
    /// does not, in one call, which is exactly the semantic a shell verb wants:
    /// an `install` run twice must be the same as an `install` run once, and an
    /// `install` run after a half-finished one must repair it rather than fail.
    ///
    /// # The access asked for
    ///
    /// `KEY_READ | KEY_WRITE`, and not `KEY_ALL_ACCESS`. The pair is the least
    /// privilege that covers every method on [`Key`] — `KEY_READ` is
    /// `KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY` plus the standard
    /// read right, and `KEY_WRITE` is `KEY_SET_VALUE | KEY_CREATE_SUB_KEY` plus
    /// the standard write right — while leaving out the two an installer of a
    /// menu item has no business holding: `WRITE_DAC` and `WRITE_OWNER`, the
    /// rights that let a process change *who may use* a key rather than what is
    /// in it. `KEY_ALL_ACCESS` would also fold in `KEY_WOW64_*_KEY`, and this
    /// crate wants one view on purpose — see the module documentation.
    pub fn create(hive: Hive, path: &str) -> Result<Self, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{
            RegCreateKeyExW, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, HKEY, KEY_READ, KEY_WRITE,
        };

        let wide = wide(path);
        let mut opened = HKEY::default();
        // The access pair is passed as the union of the two constants' bits
        // because the `windows` crate models `REG_SAM_FLAGS` as a newtype over
        // the bare constant rather than as a bitflags type. The union is what
        // Win32 documents and is not a flag invented here.
        let access = REG_SAM_FLAGS(KEY_READ.0 | KEY_WRITE.0);
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call, and `opened` is an out-parameter the API fills on success. The
        // class, the security attributes and the disposition are all optional and
        // all passed as absent — this module has no use for any of them, and
        // reading the disposition back would be a second way to learn what the
        // caller already knows.
        let status = unsafe {
            RegCreateKeyExW(
                hive.raw(),
                PCWSTR(wide.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                None,
                &mut opened,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Key {
                call: "RegCreateKeyExW",
                hive,
                path: path.to_string(),
                code: status.0,
            });
        }
        Ok(Self {
            hive,
            path: path.to_string(),
            raw: opened,
        })
    }

    /// Open an existing key, or `None` when there is no such key.
    ///
    /// Absence is [`None`] rather than an error, and *both* of the codes the API
    /// uses for it are mapped: `ERROR_FILE_NOT_FOUND` when the parent exists and
    /// `ERROR_PATH_NOT_FOUND` when it does not.
    ///
    /// # The access asked for, and why it is the same as [`Key::create`]'s
    ///
    /// `KEY_READ | KEY_WRITE`, identical to what `create` asks for. The first
    /// draft of this method asked for `KEY_READ` alone and documented that
    /// "nothing that opens a key this way writes through it" — which was a claim
    /// about the callers, written in a doc comment on the *method*, and the type
    /// system does not enforce it. Every write method is still callable on the
    /// handle this returns; what a caller who called one got was not a compile
    /// error but `ERROR_ACCESS_DENIED` at run time, from a call whose name and
    /// path looked perfectly correct. The integration test found it by reopening
    /// a key and then deleting a value from it.
    ///
    /// So the two constructors differ in exactly the thing their names say —
    /// whether an absent key is created — and not in a hidden capability. A
    /// caller who genuinely wants a read-only handle should have a distinct type
    /// to hold it, because that is a distinction the compiler can then keep; a
    /// boolean or a comment here cannot. And least privilege is still what is
    /// asked for: `WRITE_DAC` and `WRITE_OWNER`, the rights that decide *who may
    /// use* a key rather than what is in it, are left out of both constructors
    /// for the reasons [`Key::create`] gives.
    pub fn open(hive: Hive, path: &str) -> Result<Option<Self>, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS};
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, REG_SAM_FLAGS, HKEY, KEY_READ, KEY_WRITE,
        };

        let wide = wide(path);
        let mut opened = HKEY::default();
        let access = REG_SAM_FLAGS(KEY_READ.0 | KEY_WRITE.0);
        // SAFETY: `wide` outlives the call and `opened` is an out-parameter. The
        // options argument is documented as reserved and must be zero, which
        // `None` is.
        let status = unsafe {
            RegOpenKeyExW(hive.raw(), PCWSTR(wide.as_ptr()), None, access, &mut opened)
        };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Key {
                call: "RegOpenKeyExW",
                hive,
                path: path.to_string(),
                code: status.0,
            });
        }
        Ok(Some(Self {
            hive,
            path: path.to_string(),
            raw: opened,
        }))
    }

    /// Open a key to read it, asking for no right to write.
    ///
    /// # Why this exists, with the measurement that made it necessary
    ///
    /// [`Key::open`] asks for `KEY_READ | KEY_WRITE`, which is the right pair for
    /// a caller that is going to write: every method on [`Key`] then works on
    /// whatever it returns, and there is no way to hold a handle whose write
    /// methods fail. The cost is that it cannot open a key the caller may read
    /// and not write, and that is not a hypothetical:
    ///
    /// ```text
    /// HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
    ///   BUILTIN\Administrators   CreateLink, ReadKey        <- no KEY_SET_VALUE
    ///   Everyone                 CreateLink, ReadKey
    /// ```
    ///
    /// `RegOpenKeyExW` with `KEY_WRITE` against that key is `ERROR_ACCESS_DENIED`
    /// (5) for an ordinary user *and* for an administrator, and `reg query` reads
    /// it perfectly well because `reg.exe` asks only to read. A status command
    /// that could not read a security setting would be a status command that
    /// failed on exactly the machines its user was asking about.
    ///
    /// # Why a second constructor and not a flag, or a second type
    ///
    /// [`Key::create`]'s documentation argues for a distinct *type* over a flag,
    /// because a distinction the compiler can keep is one a caller cannot get
    /// wrong. That argument still holds and this is the smaller half of it: the
    /// two constructors are named for what they are for rather than carrying a
    /// boolean, so a call site reads as a decision — `open_read_only` is a caller
    /// saying it will not write — and the failure mode of getting it wrong is a
    /// `RegSetValueExW` that comes back code 5 rather than a silent write
    /// somewhere it should not have gone. A second type would mean a second copy
    /// of every read method on [`Key`], and the one caller that needs this today
    /// does not pay for that.
    pub fn open_read_only(hive: Hive, path: &str) -> Result<Option<Self>, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS};
        use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY, KEY_READ};

        let wide = wide(path);
        let mut opened = HKEY::default();
        // SAFETY: `wide` outlives the call and `opened` is an out-parameter. The
        // options argument is documented as reserved and must be zero, which
        // `None` is.
        let status = unsafe { RegOpenKeyExW(hive.raw(), PCWSTR(wide.as_ptr()), None, KEY_READ, &mut opened) };
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Key {
                call: "RegOpenKeyExW",
                hive,
                path: path.to_string(),
                code: status.0,
            });
        }
        Ok(Some(Self {
            hive,
            path: path.to_string(),
            raw: opened,
        }))
    }

    /// Remove a key, everything under it, and every value in it.
    ///
    /// A key that is not there is `Ok`, for the reason [`Key::open`] returns
    /// `None`: removing something already gone leaves the machine in the state
    /// the caller asked for. A `remove` that failed on a machine where the verb
    /// was never registered would be a `remove` that cannot clean up after
    /// itself — which is precisely when it is run.
    ///
    /// Not a method on [`Key`], because the recursive delete needs no open
    /// handle: `RegDeleteTreeW` takes a root and a path. That is also why it
    /// needs no access flags of its own — the API opens what it needs with
    /// `DELETE`, and the caller's token is what decides whether it may.
    pub fn delete_tree(hive: Hive, path: &str) -> Result<(), RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
        };
        use windows::Win32::System::Registry::RegDeleteTreeW;

        // Checked before the call rather than documented as forbidden, because
        // the consequence of getting it wrong is unbounded: an empty `lpSubKey`
        // means "the subkeys and values of *this handle*", and the handle here
        // is a hive. `HKEY_CLASSES_ROOT` in particular is a merged view over two
        // whole stores.
        if path.is_empty() {
            return Err(RegistryError::Key {
                call: "RegDeleteTreeW",
                hive,
                path: String::new(),
                code: ERROR_INVALID_PARAMETER.0,
            });
        }
        let wide = wide(path);
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call, and `hive.raw()` is a predefined root that needs no closing.
        let status = unsafe { RegDeleteTreeW(hive.raw(), PCWSTR(wide.as_ptr())) };
        if status == ERROR_SUCCESS
            || status == ERROR_FILE_NOT_FOUND
            || status == ERROR_PATH_NOT_FOUND
        {
            return Ok(());
        }
        Err(RegistryError::Key {
            call: "RegDeleteTreeW",
            hive,
            path: path.to_string(),
            code: status.0,
        })
    }

    /// Write a string value (`REG_SZ`).
    ///
    /// The name may be empty, which writes the key's *default* value — the one
    /// Explorer reads a verb's menu text and command line out of. That is why
    /// the empty name is part of this API rather than an accident of it.
    pub fn set_string(&self, name: &str, value: &str) -> Result<(), RegistryError> {
        self.set_text(name, value, REG_SZ)
    }

    /// Write an environment-expanded string value (`REG_EXPAND_SZ`).
    ///
    /// Nothing in this crate writes one; it is here because the two kinds are
    /// indistinguishable to a caller that only has text, and a wrapper that could
    /// write `REG_SZ` and not `REG_EXPAND_SZ` would be a wrapper the caller
    /// abandons the first time it needs the other one — at which point this layer
    /// is no longer the only thing touching these keys. The difference is real:
    /// `%SystemRoot%` in a `REG_SZ` is the literal eleven characters, and in a
    /// `REG_EXPAND_SZ` it is `C:\Windows`.
    pub fn set_expand_string(&self, name: &str, value: &str) -> Result<(), RegistryError> {
        self.set_text(name, value, REG_EXPAND_SZ)
    }

    /// Write a list of strings (`REG_MULTI_SZ`).
    ///
    /// The elements are stored end to end, each NUL-terminated, with one more
    /// terminator closing the list — which is why a NUL inside an element is
    /// refused rather than escaped; see [`RegistryError::EmbeddedNul`].
    ///
    /// An empty list is written as a single terminator and not as no bytes at
    /// all. A zero-length value is one a reader cannot tell from a truncated
    /// write, and "this depends on nothing" is something a caller has to be able
    /// to say after having said something else.
    pub fn set_multi_string(&self, name: &str, values: &[&str]) -> Result<(), RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{RegSetValueExW, REG_VALUE_TYPE};

        if values.iter().any(|value| value.contains('\0')) {
            return Err(RegistryError::EmbeddedNul {
                hive: self.hive,
                path: self.path.clone(),
                name: display_value_name(name),
            });
        }

        let wide_name = wide(name);
        let bytes = multi_string_bytes(values);

        // SAFETY: as `set_text` — `wide_name` is NUL-terminated and outlives the
        // call, `bytes` is only read, and the reserved argument must be zero,
        // which `None` is.
        let status = unsafe {
            RegSetValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                REG_VALUE_TYPE(REG_MULTI_SZ),
                Some(&bytes),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegSetValueExW", name, status.0));
        }
        Ok(())
    }

    /// Read a list of strings (`REG_MULTI_SZ`), or `None` when the value is not
    /// there.
    ///
    /// The mirror of [`Key::set_multi_string`], and it exists for the reason
    /// every read in this module exists: a write that returned success is not
    /// the same fact as a value that is now there and says what was asked.
    ///
    /// Only `REG_MULTI_SZ` is accepted. A `REG_SZ` read as a list would be a
    /// list of one element holding the whole string — a plausible-looking answer
    /// to a question nobody asked, which is worse than a refusal when the
    /// question is whether a driver is ordered behind the filter manager.
    ///
    /// A value whose last element is not terminated is read with that element
    /// included. The format requires the terminator, so such a value was written
    /// by something that does not follow it; dropping the element would report a
    /// dependency list missing one of its entries, and a dependency list that is
    /// short by one is exactly the kind of answer this module refuses to guess
    /// at elsewhere.
    pub fn multi_string(&self, name: &str) -> Result<Option<Vec<String>>, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS,
        };
        use windows::Win32::System::Registry::{RegQueryValueExW, REG_VALUE_TYPE};

        let wide_name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut needed = 0u32;
        // Two passes for the same reason `string` makes two: a registry value is
        // variable-length with no documented bound, so the only thing there is
        // to allocate against is the answer to the size question.
        //
        // SAFETY: a null data pointer with a zero length is the documented way to
        // ask for the size. `wide_name` outlives the call and `kind` is an
        // out-parameter the API fills.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut needed),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }

        // `kind` is the newtype, not the number: the reader's two constants come
        // from the `windows` crate and the writer's from this file, and the
        // conversion is what keeps the two comparable.
        if kind != REG_VALUE_TYPE(REG_MULTI_SZ) {
            return Err(RegistryError::NotText {
                hive: self.hive,
                path: self.path.clone(),
                name: display_value_name(name),
                found: kind.0,
            });
        }

        let mut bytes = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, which the call above
        // said is enough. `needed` doubles as the out-length.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut needed),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }
        bytes.truncate(needed as usize);

        // An odd byte count cannot come from a value this API wrote, and an even
        // one is decoded pairing the bytes little-endian. Refused rather than
        // rounded down, which would drop a byte and change an element.
        if bytes.len() % 2 != 0 {
            return Err(self.not_unicode(name));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();

        let values = parse_multi_string(&units).ok_or_else(|| self.not_unicode(name))?;
        Ok(Some(values))
    }

    /// Read a string value, or `None` when the value is not there.
    ///
    /// `REG_SZ` and `REG_EXPAND_SZ` are both read; any other type is
    /// [`RegistryError::NotText`], and bytes that are not valid UTF-16 are
    /// [`RegistryError::NotUnicode`].
    ///
    /// A value that is not there and a value that is there and empty are
    /// different answers — `Ok(None)` against `Ok(Some(String::new()))` — because
    /// a key whose command line is empty is a broken registration that a status
    /// report has to be able to name, and collapsing the two would hide exactly
    /// the state worth reporting.
    ///
    /// The bytes are *not* environment-expanded, even for a `REG_EXPAND_SZ`: this
    /// reads what is stored, and calling `ExpandEnvironmentStringsW` is a
    /// separate decision no caller here has made.
    pub fn string(&self, name: &str) -> Result<Option<String>, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS,
        };
        use windows::Win32::System::Registry::{
            RegQueryValueExW, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
        };

        let wide_name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut needed = 0u32;
        // The size is asked for first. A registry value is variable-length with
        // no documented bound, so there is nothing to allocate against except
        // the answer to this call — which is expected to fail with
        // `ERROR_INSUFFICIENT_BUFFER` and fill `needed` in. `ERROR_MORE_DATA` is
        // accepted as well: it is what a value larger than the (zero-length)
        // buffer is reported as on some paths, and treating it as a failure would
        // refuse to read the very values that needed the two-pass read.
        //
        // SAFETY: a null data pointer with a zero length is the documented way to
        // ask for the size. `wide_name` outlives the call, and `kind` is an
        // out-parameter the API fills.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut needed),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }

        // The type is checked before the bytes are read, so that a `REG_DWORD`
        // is refused as a number rather than decoded as two UTF-16 units of
        // text. `REG_EXPAND_SZ` is accepted because it *is* text: which of the
        // two kinds it is matters to whoever wrote it, not to whoever is reading
        // a menu item out of it.
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            return Err(RegistryError::NotText {
                hive: self.hive,
                path: self.path.clone(),
                name: display_value_name(name),
                found: kind.0,
            });
        }

        let mut bytes = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, which the call above
        // said is enough for this value. `needed` doubles as the out-length,
        // which the API overwrites with what it actually wrote.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut needed),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }
        bytes.truncate(needed as usize);

        // An odd byte count cannot come from a value this API wrote, and an even
        // one is decoded pairing the bytes little-endian, which is what Windows
        // stores a `REG_SZ` as. An odd count is refused rather than rounded down:
        // rounding would silently drop a byte and produce a string that is not
        // the one in the registry.
        if bytes.len() % 2 != 0 {
            return Err(self.not_unicode(name));
        }
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        // The terminating NUL is part of the stored length and is not part of the
        // string. Popped rather than filtered out of the middle: an interior NUL
        // is a different problem — a string two readers would see different
        // amounts of — and this API does not produce one.
        if units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).map(Some).map_err(|_| self.not_unicode(name))
    }

    /// Write a 32-bit number (`REG_DWORD`).
    ///
    /// Little-endian, which is what every `REG_DWORD` on every machine this
    /// product runs on is; `REG_DWORD_BIG_ENDIAN` exists in the API and nothing
    /// writes it, and the reader below refuses it rather than byte-swapping a
    /// value that some other program chose to store the other way round.
    pub fn set_dword(&self, name: &str, value: u32) -> Result<(), RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{RegSetValueExW, REG_DWORD};

        let wide_name = wide(name);
        // Exactly four bytes, and no terminator: the NUL that
        // [`Key::set_text`] appends is a property of a *string* value — it is
        // what makes the stored bytes a C string to `reg query` and to every
        // other reader — and a DWORD with five bytes in it is a value this
        // module's own reader would refuse.
        let bytes = value.to_le_bytes();

        // SAFETY: `wide_name` is NUL-terminated and `bytes` is a four-byte
        // slice the API only reads; both outlive the call. The reserved
        // argument is documented as reserved and must be zero, which `None` is.
        let status = unsafe {
            RegSetValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                REG_DWORD,
                Some(&bytes),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegSetValueExW", name, status.0));
        }
        Ok(())
    }

    /// Read a 32-bit number, or `None` when the value is not there.
    ///
    /// A `REG_DWORD` of exactly four bytes and nothing else. Anything else is
    /// [`RegistryError::NotNumeric`], including the `REG_DWORD` that is some
    /// other length: the type alone does not promise a size, and a reader that
    /// assumed four would take whatever the first four bytes happened to be.
    ///
    /// `REG_DWORD_BIG_ENDIAN` is refused rather than swapped. Nothing in
    /// Windows writes one, so a value stored that way was written by something
    /// that meant it, and guessing its byte order is guessing at somebody
    /// else's setting.
    pub fn dword(&self, name: &str) -> Result<Option<u32>, RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS,
        };
        use windows::Win32::System::Registry::{RegQueryValueExW, REG_DWORD, REG_VALUE_TYPE};

        let wide_name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut needed = 0u32;
        // The size is asked for first, exactly as [`Key::string`] does and for
        // the same reason: the type is only known from this call, and it has to
        // be known before the bytes are read. It is expected to fail with
        // `ERROR_INSUFFICIENT_BUFFER` and fill `needed` in; `ERROR_MORE_DATA`
        // is accepted as well.
        //
        // SAFETY: a null data pointer with a zero length is the documented way
        // to ask for the size. `wide_name` outlives the call, and `kind` and
        // `needed` are out-parameters the API fills.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut needed),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }
        if kind != REG_DWORD || needed != 4 {
            return Err(self.not_numeric(name, kind.0, needed));
        }

        let mut bytes = [0u8; 4];
        let mut length = bytes.len() as u32;
        // SAFETY: `bytes` is the four bytes the call above said this value
        // holds, and `length` is told that and is overwritten with what was
        // actually written. `wide_name` outlives the call.
        let status = unsafe {
            RegQueryValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut length),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegQueryValueExW", name, status.0));
        }
        // Checked again rather than trusted from the first call: the two reads
        // are two calls, and a value rewritten in between them by whoever owns
        // the key is exactly the case this guards.
        if kind != REG_DWORD || length != 4 {
            return Err(self.not_numeric(name, kind.0, length));
        }
        Ok(Some(u32::from_le_bytes(bytes)))
    }

    /// Delete a value. A value that is not there is `Ok`, for the reason
    /// [`Key::delete_tree`] gives.
    pub fn delete_value(&self, name: &str) -> Result<(), RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
        };
        use windows::Win32::System::Registry::RegDeleteValueW;

        let wide_name = wide(name);
        // SAFETY: `wide_name` is a NUL-terminated UTF-16 string that outlives the
        // call, and `self.raw` is a live handle for the same lifetime.
        let status = unsafe { RegDeleteValueW(self.raw, PCWSTR(wide_name.as_ptr())) };
        if status == ERROR_SUCCESS
            || status == ERROR_FILE_NOT_FOUND
            || status == ERROR_PATH_NOT_FOUND
        {
            return Ok(());
        }
        Err(self.value_error("RegDeleteValueW", name, status.0))
    }

    /// The names of this key's immediate subkeys, in the order the API returns
    /// them.
    ///
    /// That order is the registry's own — for a small key it is the order they
    /// were created in, and it is not documented to be anything at all. Callers
    /// that show this to a user sort it; callers that compare it to something
    /// compare it as a set. Saying so here is cheaper than every caller finding
    /// out.
    ///
    /// The buffer size comes from `RegQueryInfoKeyW` rather than from retrying a
    /// fixed guess, so a key with an unusually long subkey name is read on the
    /// first pass instead of after a failed one.
    pub fn subkeys(&self) -> Result<Vec<String>, RegistryError> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
        use windows::Win32::System::Registry::{RegEnumKeyExW, RegQueryInfoKeyW};

        let mut count = 0u32;
        let mut longest = 0u32;
        // SAFETY: every out-parameter but these two is optional and passed as
        // absent; `count` and `longest` have the documented types, and `self.raw`
        // is a live handle.
        let status = unsafe {
            RegQueryInfoKeyW(
                self.raw,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut longest),
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegQueryInfoKeyW", "", status.0));
        }

        // `longest` is measured in characters and excludes the terminator — the
        // API's own convention for `lpcbMaxSubKeyLen`, and the opposite of the
        // byte-count convention `lpcbData` uses three methods up. The extra
        // element is the terminator.
        let mut buffer = vec![0u16; longest as usize + 1];
        let mut names = Vec::with_capacity(count as usize);
        for index in 0..count {
            let mut length = buffer.len() as u32;
            // SAFETY: `buffer` holds `length` characters, which is what the call
            // is told; `length` is an in-out parameter the API overwrites with
            // the number of characters it wrote, terminator excluded. The
            // reserved argument and the class out-parameters are optional and
            // absent.
            let status = unsafe {
                RegEnumKeyExW(
                    self.raw,
                    index,
                    Some(PWSTR(buffer.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                // The count and the enumeration disagree, which is what another
                // process deleting a subkey in between looks like. Everything
                // read so far is still true, so this stops rather than failing.
                break;
            }
            if status != ERROR_SUCCESS {
                return Err(self.value_error("RegEnumKeyExW", "", status.0));
            }
            // SAFETY: the call succeeded, so it wrote `length` UTF-16 units into
            // `buffer`, which is at least that long. Lossy here and only here: a
            // subkey *name* is being listed, and refusing the whole listing
            // because one name is not valid UTF-16 would hide the names that are.
            names.push(String::from_utf16_lossy(&buffer[..length as usize]));
        }
        Ok(names)
    }

    /// The shared body of the two string writers.
    fn set_text(&self, name: &str, value: &str, kind: u32) -> Result<(), RegistryError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{RegSetValueExW, REG_VALUE_TYPE};

        let wide_name = wide(name);
        // The terminating NUL is written as part of the data, which is what
        // makes the value a C string to every reader — Explorer included, and
        // `reg query` too. Its length is counted in *bytes*: that is the
        // convention `RegSetValueExW` uses and the opposite of the one
        // `RegEnumKeyExW` uses for a name, and the two are a few lines apart in
        // the same header. Getting them the wrong way round truncates every value
        // to half its length, silently, and the value still reads back as valid
        // UTF-16.
        let mut data: Vec<u16> = value.encode_utf16().collect();
        data.push(0);
        let bytes: Vec<u8> = data.iter().flat_map(|unit| unit.to_le_bytes()).collect();

        // SAFETY: `wide_name` is NUL-terminated and `bytes` is a slice the API
        // only reads; both outlive the call. The reserved argument is documented
        // as reserved and must be zero, which `None` is.
        let status = unsafe {
            RegSetValueExW(
                self.raw,
                PCWSTR(wide_name.as_ptr()),
                None,
                REG_VALUE_TYPE(kind),
                Some(&bytes),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(self.value_error("RegSetValueExW", name, status.0));
        }
        Ok(())
    }

    /// A failure about a value, with this key's own identity filled in.
    fn value_error(&self, call: &'static str, name: &str, code: u32) -> RegistryError {
        RegistryError::Value {
            call,
            hive: self.hive,
            path: self.path.clone(),
            name: display_value_name(name),
            code,
        }
    }

    /// A value that is not valid UTF-16, with this key's own identity filled in.
    fn not_unicode(&self, name: &str) -> RegistryError {
        RegistryError::NotUnicode {
            hive: self.hive,
            path: self.path.clone(),
            name: display_value_name(name),
        }
    }

    /// A value that is not a 32-bit number, with this key's own identity filled
    /// in.
    fn not_numeric(&self, name: &str, found: u32, bytes: u32) -> RegistryError {
        RegistryError::NotNumeric {
            hive: self.hive,
            path: self.path.clone(),
            name: display_value_name(name),
            found,
            bytes,
        }
    }
}

/// `REG_SZ`.
#[cfg(windows)]
const REG_SZ: u32 = 1;

/// `REG_EXPAND_SZ`.
#[cfg(windows)]
const REG_EXPAND_SZ: u32 = 2;

/// `REG_MULTI_SZ`.
///
/// The type a service's `DependOnService` is written as, and the reason this
/// module grew a list-shaped pair of verbs: there is no way to say "this driver
/// must not start before the filter manager" with a single string, and writing
/// the name as a `REG_SZ` would be a value the SCM reads as absent.
#[cfg(windows)]
const REG_MULTI_SZ: u32 = 7;

/// The name a value is reported under.
///
/// A key's default value has an empty name, and a pair of empty quotes in a
/// message reads as a bug in the message rather than as the name of a value. The
/// spelling is the one `regedit` uses.
fn display_value_name(name: &str) -> String {
    if name.is_empty() {
        "(default)".to_string()
    } else {
        name.to_string()
    }
}

/// A NUL-terminated UTF-16 copy of `text`.
///
/// The same shape as `av-service`'s `win32::to_wide`, and deliberately not
/// shared with it: that one lives in a crate this one does not depend on, and the
/// alternative — a third crate holding three lines of `encode_utf16` — costs
/// more than the three lines do. An interior NUL would truncate silently, and one
/// cannot occur in a path or a value name this crate builds.
#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The bytes a `REG_MULTI_SZ` holding `values` is stored as.
///
/// Split out from [`Key::set_multi_string`] so that the layout is a thing with a
/// test rather than a thing inside a call — the same split this module makes
/// everywhere else, and here it earns its keep twice over. The format is a run
/// of NUL-terminated strings with *one more* terminator closing the list, and
/// both mistakes available are silent: dropping the extra terminator leaves a
/// value whose last element a reader cannot tell from the list's end, and
/// omitting the per-element terminators fuses every element into one. Neither is
/// visible in a write that succeeded.
///
/// An empty list is one terminator and not zero bytes; see
/// [`Key::set_multi_string`].
#[cfg(windows)]
fn multi_string_bytes(values: &[&str]) -> Vec<u8> {
    let mut data: Vec<u16> = Vec::new();
    for value in values {
        data.extend(value.encode_utf16());
        data.push(0);
    }
    // Outside the loop, because for an empty list it is the whole value.
    data.push(0);
    data.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// The values in a `REG_MULTI_SZ` whose units are `units`.
///
/// `None` when an element is not valid UTF-16 — unpaired surrogates, which the
/// registry will hold and no `String` corresponds to. The caller turns that into
/// the error that names the value; this function has no key to name it with.
///
/// Reading stops at the first empty element, which is the list's terminator.
/// Anything after it is not part of the value — a value with trailing NULs reads
/// as the list it is, rather than as extra empty elements somebody wrote.
///
/// A last element with no terminator is *kept*. The format requires one, so such
/// a value was written by something that does not follow it, and the choice is
/// between reporting an element the writer meant to be there and dropping it.
/// Dropping is worse in the one use this has: a dependency list that is short by
/// one entry is a wrong answer about what a driver waits for.
#[cfg(windows)]
fn parse_multi_string(units: &[u16]) -> Option<Vec<String>> {
    let mut values: Vec<String> = Vec::new();
    let mut element: Vec<u16> = Vec::new();
    for &unit in units {
        if unit == 0 {
            if element.is_empty() {
                return Some(values);
            }
            values.push(String::from_utf16(&element).ok()?);
            element.clear();
        } else {
            element.push(unit);
        }
    }
    if !element.is_empty() {
        values.push(String::from_utf16(&element).ok()?);
    }
    Some(values)
}

/// The registry is a Windows idea; elsewhere there is nothing to register in.
///
/// Every entry point answers with [`RegistryError::Unsupported`] rather than
/// being absent, so that a caller above this module compiles and reads the same
/// way on every platform and only the *outcome* differs.
#[cfg(not(windows))]
impl Key {
    /// No key can be created, because there is no registry.
    pub fn create(_hive: Hive, _path: &str) -> Result<Self, RegistryError> {
        Err(RegistryError::Unsupported)
    }

    /// No key can be opened, because there is no registry.
    pub fn open(_hive: Hive, _path: &str) -> Result<Option<Self>, RegistryError> {
        Err(RegistryError::Unsupported)
    }

    /// Nothing can be deleted, because there is no registry.
    pub fn delete_tree(_hive: Hive, _path: &str) -> Result<(), RegistryError> {
        Err(RegistryError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_path_is_refused_before_the_api_can_see_it() {
        // The one call in this module whose worst case is unbounded: an empty
        // path to `RegDeleteTreeW` means "the subkeys and values of the handle
        // itself", and the handle here is a hive. On Windows the guard fires
        // before the API is reached; a test that ran the real call to find out
        // would be a test that deleted somebody's registry.
        let error = Key::delete_tree(Hive::ClassesRoot, "");
        assert!(error.is_err());
        #[cfg(windows)]
        assert_eq!(error.unwrap_err().code(), Some(87));
    }

    #[test]
    fn a_default_value_is_reported_by_name_rather_than_as_nothing() {
        // The empty name is a real name — it is the value Explorer reads a
        // verb's menu text out of — and a message that printed it as nothing
        // would read as a bug in the message.
        assert_eq!(display_value_name(""), "(default)");
        assert_eq!(display_value_name("Icon"), "Icon");
    }

    #[test]
    fn a_hive_prints_its_own_name() {
        assert_eq!(Hive::LocalMachine.to_string(), "HKEY_LOCAL_MACHINE");
        assert_eq!(Hive::CurrentUser.as_str(), "HKEY_CURRENT_USER");
        assert_eq!(Hive::ClassesRoot.as_str(), "HKEY_CLASSES_ROOT");
    }

    #[test]
    fn a_call_failure_keeps_its_code_through_the_workspace_error() {
        // The property the command line relies on: the code survives, so a
        // caller can still tell access-denied from everything else after the
        // conversion, and `AvError::is_transient` still reads it.
        let error = RegistryError::Key {
            call: "RegCreateKeyExW",
            hive: Hive::LocalMachine,
            path: r"Software\Classes\*\shell\WenleScan".to_string(),
            code: 5,
        };
        match AvError::from(error) {
            AvError::Win32 { call, code } => {
                assert_eq!(call, "RegCreateKeyExW");
                assert_eq!(code, 5);
            }
            other => panic!("expected a Win32 error, got {other:?}"),
        }
    }

    #[test]
    fn a_failure_that_is_not_a_call_failure_says_so_in_a_sentence() {
        // Every variant with no code. Each has to name the value and where it
        // lives, because that is the whole of what the caller can act on.
        let not_text = RegistryError::NotText {
            hive: Hive::CurrentUser,
            path: r"Software\Classes\*\shell\WenleScan".to_string(),
            name: "Icon".to_string(),
            found: 3,
        };
        assert_eq!(not_text.code(), None);
        let sentence = not_text.to_string();
        assert!(sentence.contains("Icon"), "{sentence}");
        assert!(sentence.contains("HKEY_CURRENT_USER"), "{sentence}");
        assert!(sentence.contains('3'), "{sentence}");

        let not_unicode = RegistryError::NotUnicode {
            hive: Hive::CurrentUser,
            path: "Software".to_string(),
            name: "(default)".to_string(),
        };
        assert_eq!(not_unicode.code(), None);
        assert!(not_unicode.to_string().contains("UTF-16"));

        let unsupported = RegistryError::Unsupported;
        assert_eq!(unsupported.code(), None);
        assert!(unsupported.to_string().contains("no registry"));

        let embedded_nul = RegistryError::EmbeddedNul {
            hive: Hive::LocalMachine,
            path: r"SYSTEM\CurrentControlSet\Services\WenleAvFilter".to_string(),
            name: "DependOnService".to_string(),
        };
        assert_eq!(embedded_nul.code(), None);
        let sentence = embedded_nul.to_string();
        assert!(sentence.contains("DependOnService"), "{sentence}");
        assert!(sentence.contains("NUL"), "{sentence}");
    }

    #[test]
    fn a_multi_string_round_trips_through_its_own_layout() {
        // The pair, without a registry: what `set_multi_string` would store read
        // back by what `multi_string` decodes. This is the whole of the format's
        // risk — see `multi_string_bytes` for the two silent ways to get it
        // wrong — and it is checked here rather than by writing a key, because
        // the layout is arithmetic and the call is the operating system's.
        let units = |values: &[&str]| -> Vec<u16> {
            multi_string_bytes(values)
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        };

        for values in [
            vec!["FltMgr"],
            vec!["FltMgr", "WenleAvService"],
            vec!["a", "bb", "ccc"],
        ] {
            let decoded = parse_multi_string(&units(&values)).expect("valid UTF-16");
            assert_eq!(decoded, values, "a list must survive being written and read");
        }
    }

    #[test]
    fn an_empty_multi_string_is_a_list_with_no_elements_and_not_no_bytes() {
        // A zero-length value is one a reader cannot tell from a truncated
        // write, so the empty list has to be a real value. It decodes to no
        // elements rather than to one empty element: a list of one empty string
        // is a dependency on a service with no name, which is not a thing.
        let bytes = multi_string_bytes(&[]);
        assert_eq!(bytes, vec![0, 0], "one terminator, which is two bytes");
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let decoded = parse_multi_string(&units).expect("valid UTF-16");
        assert!(decoded.is_empty(), "{decoded:?}");
    }

    #[test]
    fn the_terminator_is_what_ends_the_list_and_not_the_length() {
        // Everything after the list's own terminator is not part of the value.
        // This is the property that makes a trailing run of NULs harmless
        // instead of an extra empty element per byte.
        let units = [b'A' as u16, 0, 0, 0, b'Z' as u16, 0];
        assert_eq!(
            parse_multi_string(&units).expect("valid UTF-16"),
            vec!["A".to_string()]
        );
    }

    #[test]
    fn an_unterminated_last_element_is_kept_rather_than_dropped() {
        // A value written by something that does not follow the format. Keeping
        // the element is the choice that fails loudly: a dependency list short
        // by one entry is a wrong answer about what a driver waits for, and it
        // is the kind of wrong answer that looks like a correct one.
        let units = [b'A' as u16, 0, b'B' as u16];
        assert_eq!(
            parse_multi_string(&units).expect("valid UTF-16"),
            vec!["A".to_string(), "B".to_string()]
        );
    }

    #[test]
    fn an_element_that_is_not_utf16_is_refused_rather_than_replaced() {
        // A lone high surrogate: the registry holds it, nothing decodes it, and
        // the caller turns the `None` into an error naming the value. Replacing
        // it would put a different string in a service's dependency list.
        assert!(parse_multi_string(&[0xD800u16, 0]).is_none());
        // A surrogate pair is one character and does decode — but only because
        // both units are in the same element. Split them with a terminator and
        // each half is unpaired, which is the failure a decoder that walked the
        // bytes rather than the elements would call valid.
        let smiling: Vec<u16> = "\u{1F600}".encode_utf16().collect();
        assert_eq!(smiling.len(), 2, "a supplementary character is two units");
        let mut one_element = smiling.clone();
        one_element.push(0);
        assert_eq!(
            parse_multi_string(&one_element).expect("a surrogate pair is valid UTF-16"),
            vec!["\u{1F600}".to_string()]
        );
        let split = [smiling[0], 0, smiling[1], 0];
        assert!(
            parse_multi_string(&split).is_none(),
            "each half on its own is unpaired"
        );
    }

    #[test]
    fn a_failure_about_a_value_names_the_value_it_was_about() {
        let error = RegistryError::Value {
            call: "RegSetValueExW",
            hive: Hive::LocalMachine,
            path: "Software".to_string(),
            name: display_value_name(""),
            code: 5,
        };
        assert!(error.to_string().contains("(default)"));
        assert!(error.to_string().contains("RegSetValueExW"));
    }
}
