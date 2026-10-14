//! The AMSI provider: content a host is about to run, examined before it runs.
//!
//! # The gap this closes, stated exactly
//!
//! Every other component in this product sees bytes that are *at rest*: a file
//! on a disk, a region of a process's memory, an archive entry. What none of
//! them sees is a script that a host has assembled in memory and is about to
//! execute. `powershell.exe -EncodedCommand <base64>` never writes the decoded
//! script anywhere a scanner can read it; by the time a file exists, the
//! interesting part is over.
//!
//! AMSI is where Windows solves that problem for everyone. A host that supports
//! it hands the text to whatever providers are registered, **after the host's own
//! de-obfuscation**, and waits for an answer before running it. That
//! de-obfuscation is the expensive part of analysing script, and here it is
//! done by the component that wrote the obfuscator's counterpart.
//!
//! # What this crate is, in one paragraph
//!
//! A COM in-proc server (`cdylib`) that Windows loads into the host process. It
//! implements `IAntimalwareProvider`, reads the content out of the `IAmsiStream`
//! it is given, and asks the service what it makes of the bytes, over the same
//! named pipe every other client uses. The service does the scanning,
//! because it already holds the compiled rule database and loading a second copy
//! in every `powershell.exe` on the machine is not a trade anybody would take.
//!
//! # The three promises, and they are the whole design
//!
//! 1. **It never hangs the host.** Everything that can block happens on a worker
//!    thread this crate owns, and the caller waits with a deadline. See
//!    [`Scanner::scan`].
//! 2. **It never crashes the host.** Every entry point a host can reach (this
//!    file's COM exports and [`Provider`]'s trait methods) is wrapped in
//!    `catch_unwind`, and the workspace's release profile is `panic = "unwind"`
//!    so that it has something to catch. A panic in a scanner must not become a
//!    dead `powershell.exe`.
//! 3. **It never reduces protection.** Every failure path answers
//!    `AMSI_RESULT_NOT_DETECTED`, which is *no opinion*. Not `CLEAN`, which is
//!    a claim a static scanner cannot make. See [`for_verdict`] for why that
//!    distinction is the one that matters and where it is enforced.
//!
//! # What it deliberately does not do
//!
//! * **It does not scan in-process.** See above: the rule database is 468 MB.
//! * **It does not register itself.** Writing `HKLM` needs an elevated writer
//!   and a decision about whether the DLL's directory is one a non-admin can
//!   write to. See the `registration` module, which is where that decision lives
//!   and is the reason it is not made here.
//! * **It does not replace the driver.** What AMSI covers is script, and only
//!   script, and only in hosts that ask. An executable launched from Explorer
//!   is not AMSI's business and is not affected by anything in this crate.
//!
//! # Platform
//!
//! Windows only, and the crate compiles to nothing anywhere else: an in-proc COM
//! server has no meaning off Windows, and a stub that pretended otherwise
//! would be a stub somebody eventually linked against.

#![cfg(windows)]
// Unwrapping is how a test asserts, and the workspace's `unwrap_used` /
// `expect_used` stay on for the library, where either would be a panic inside a
// process this crate does not own — `DllGetClassObject` is called by whatever
// host has loaded the DLL, and a panic there takes that host down. The same
// allowance every other crate in the workspace makes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod connection;
mod provider;
mod registration;
mod result;
mod scan;

use std::ffi::c_void;
use std::panic::AssertUnwindSafe;

use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED, S_FALSE, S_OK};
use windows::Win32::System::Com::IClassFactory;
use windows::core::{GUID, HRESULT, Interface};

pub use crate::provider::{
    can_unload, CLASS_E_CLASSNOTREG, DISPLAY_NAME, Factory, Provider, UNNAMED,
};
pub use crate::registration::{
    clsid_string, dll_path, is_trusted_dll_path, CLSID, CLASSES_KEY, CLASSES_KEY_WOW64, DLL_NAME,
    INPROC_SERVER_KEY, PROVIDERS_KEY, PROVIDERS_KEY_WOW64, THREADING_MODEL,
};
pub use crate::result::{blocks, for_verdict, no_opinion};
pub use crate::scan::{Scan, Scanner, BUDGET, IO_TIMEOUT};

/// The name the class object is registered under.
///
/// COM asks for a class object by CLSID, so this is only for the registry's
/// default value, where a person reads it.
pub use crate::provider::DISPLAY_NAME as CLASS_NAME;

/// The class object factory, as COM asks for one.
///
/// # Why this function is the shape it is
///
/// `DllGetClassObject` is the one entry point every in-proc COM server must
/// export by that exact name, and it is reached by `CoGetClassObject` rather
/// than by any Rust caller — so there is nothing to keep tidy about its
/// signature and a great deal to lose by getting it wrong.
///
/// It is wrapped in `catch_unwind` because a panic here would unwind into COM's
/// own frames, across a C ABI, in a process this crate does not own. Rust aborts
/// on that since 1.71, which means the host dies — the failure mode this whole
/// crate is arranged to avoid.
///
/// # What it returns
///
/// * `S_OK` and an interface pointer, on success.
/// * [`CLASS_E_CLASSNOTREG`] for any CLSID that is not [`CLSID`]. Not a generic
///   failure: COM callers distinguish "this server does not do that" from "this
///   server is broken", and a host that gets the second where it expected the
///   first reports a broken installation.
/// * `E_POINTER` for a null out-parameter.
/// * `E_UNEXPECTED` if a panic was caught. There is no better code: the
///   alternative would be to claim a failure this code cannot describe.
///
/// # Safety
///
/// The caller must pass three valid pointers, per the COM contract: `rclsid` and
/// `riid` to readable `GUID`s and `object` to a writable interface pointer. This
/// is an `extern "system"` export, so nothing here can be enforced by the type
/// system — the checks below are for null and nothing else can be checked.
///
/// **The function is `unsafe` for that reason, and the word is not decoration.**
/// A `# Safety` section on a safe function is a contract with nothing behind it:
/// every caller in this workspace had to be able to claim the three pointers were
/// valid without saying so anywhere. Marking it makes the claim a thing a caller
/// writes down, which is what the five call sites in this file's tests now do.
/// The signature COM sees does not change — `unsafe` is not part of the ABI — so
/// this is invisible to the host that calls it by name.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    object: *mut *mut c_void,
) -> HRESULT {
    let guarded = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if rclsid.is_null() || riid.is_null() || object.is_null() {
            return E_POINTER;
        }
        // SAFETY: `rclsid` was checked non-null above and COM guarantees it
        // points at a readable `GUID` for the duration of the call.
        let clsid = unsafe { *rclsid };
        if clsid != CLSID {
            return CLASS_E_CLASSNOTREG;
        }
        let factory: IClassFactory = Factory::new(Scanner::start()).into();
        // SAFETY: `factory` is a live interface, `riid` was checked non-null,
        // and `object` was checked non-null. `query` writes one interface
        // pointer on success and nothing on failure, which is what COM
        // requires.
        unsafe { factory.query(riid, object) }
    }));
    match guarded {
        Ok(hr) => hr,
        Err(_) => {
            log::error!("a panic was caught in DllGetClassObject; the host keeps running");
            E_UNEXPECTED
        }
    }
}

/// Whether COM may unload this DLL.
///
/// `S_OK` means yes, `S_FALSE` means no. See [`can_unload`] for why the answer
/// stops being yes once anything has happened — a live object is a pointer into
/// this module's code, and the worker thread has a program counter inside it.
///
/// Wrapped for the same reason as [`DllGetClassObject`], and this one matters
/// more: COM calls this from wherever the last `Release` happened, which is
/// inside the host's own code, and a panic escaping into that frame would take
/// down a process whose only mistake was running a script.
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    match std::panic::catch_unwind(can_unload) {
        Ok(true) => S_OK,
        Ok(false) => S_FALSE,
        Err(_) => {
            log::error!("a panic was caught in DllCanUnloadNow; the DLL will stay loaded");
            // Refusing to unload is always safe. Answering `S_OK` on a path that
            // panicked would be answering "yes, unload me" while knowing nothing.
            S_FALSE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::Interface;

    #[test]
    fn a_class_object_is_refused_for_a_clsid_this_server_does_not_serve() {
        // The registration is machine-wide, so this server is asked about
        // CLSIDs that are not its own the moment anything enumerates providers.
        // `CLASS_E_CLASSNOTREG` is what makes COM move on to the next one;
        // anything else and the host reports a broken installation.
        let mut object: *mut c_void = std::ptr::null_mut();
        let other = GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);
        // SAFETY: three live locals, which is every part of the contract. The
        // `Guid`s are values this function owns and `object` is a local the
        // function is allowed to write through.
        let hr = unsafe { DllGetClassObject(&other, &IClassFactory::IID, &mut object) };
        assert_eq!(hr, CLASS_E_CLASSNOTREG);
        assert!(object.is_null(), "nothing was written on the failure path");
    }

    #[test]
    fn a_null_out_parameter_is_refused_rather_than_followed() {
        let mut object: *mut c_void = std::ptr::null_mut();
        // SAFETY: this is the test that deliberately breaks the contract, and it
        // is the reason the contract is worth writing down: the null checks are
        // what turn a caller's mistake into `E_POINTER` instead of a fault in
        // somebody else's process. The null argument is the point of each case.
        assert_eq!(
            unsafe { DllGetClassObject(&CLSID, &IClassFactory::IID, std::ptr::null_mut()) },
            E_POINTER
        );
        assert_eq!(
            unsafe { DllGetClassObject(std::ptr::null(), &IClassFactory::IID, &mut object) },
            E_POINTER
        );
        assert_eq!(
            unsafe { DllGetClassObject(&CLSID, std::ptr::null(), &mut object) },
            E_POINTER
        );
    }

    #[test]
    fn a_real_class_object_comes_back_for_this_servers_own_clsid() {
        // The positive path. What `can_unload` answers afterwards is asserted in
        // `tests/unload_after_object.rs` rather than here: this binary's other
        // tests create objects and start the worker, so any absolute assertion
        // about that process-global is a race. See that file's header.
        let mut object: *mut c_void = std::ptr::null_mut();
        // SAFETY: as the first test — three live locals.
        let hr = unsafe { DllGetClassObject(&CLSID, &IClassFactory::IID, &mut object) };
        assert_eq!(hr, S_OK, "the factory could not be made");
        assert!(!object.is_null());

        // SAFETY: the call above returned `S_OK`, so `object` is a live
        // `IClassFactory` pointer that this test now owns. It is released
        // exactly once, by the drop at the end.
        let factory: IClassFactory = unsafe { Interface::from_raw(object) };
        drop(factory);
    }
}
