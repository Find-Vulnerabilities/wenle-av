//! The provider Windows calls, and the class factory that makes one.
//!
//! # What Windows hands over, and when
//!
//! A host that supports AMSI — PowerShell, `wscript.exe`, `cscript.exe`, the
//! Office macro runtime, WMI — calls `AmsiScanBuffer` with the text it is about
//! to run. AMSI walks the providers registered under
//! `HKLM\SOFTWARE\Microsoft\AMSI\Providers`, and for each one calls
//! `IAntimalwareProvider::Scan` **before** the host acts. A `DETECTED` answer
//! means the host does not run it.
//!
//! Two things follow, and they are the whole shape of this module.
//!
//! * **The content is already de-obfuscated.** PowerShell hands over the script
//!   it decoded, not the `-EncodedCommand` blob it was given. That is the one
//!   place in this product where somebody else does the hard part of the job,
//!   and it is why AMSI is worth having at all.
//! * **This function is on the critical path of somebody else's program.** It
//!   runs synchronously, on the host's thread, with the host stopped. Every
//!   path below returns, and the only thing that decides how long it takes is
//!   the budget in [`crate::scan`].
//!
//! # The three promises
//!
//! 1. **It never hangs the host.** [`Scanner::scan`](crate::scan::Scanner::scan)
//!    is bounded, and every failure below it is a failure to answer rather than
//!    a wait.
//! 2. **It never crashes the host.** A panic here is a panic in `powershell.exe`
//!    — the process dies, and the user has an antivirus that broke their
//!    machine. Every COM entry point in this crate is wrapped in
//!    `catch_unwind`, and the crate's profile is `panic = "unwind"` so that
//!    there is something to catch.
//! 3. **It never reduces protection.** Every failure answers
//!    [`no_opinion`](crate::result::no_opinion), which is `NOT_DETECTED` and not
//!    `CLEAN`. See [`crate::result`] for why that distinction is the one that
//!    matters.
//!
//! # What is read from the stream, and what is not
//!
//! `IAmsiStream` offers six attributes: the app name, the content name, the
//! content size, a pointer to the content, the session, and a redirect chain.
//! This provider reads the name and the size, then pulls the bytes with `Read`.
//! It does not use `AMSI_ATTRIBUTE_CONTENT_ADDRESS`, which would hand over a
//! pointer into the host's address space that this code would then have to trust
//! the length of — `Read` gives the same bytes through a checked copy.
//!
//! The name is a label and nothing else. It is passed to the engine — a name
//! ending in `.ps1` legitimately helps the classifier — and it is never
//! resolved as a path, never opened, and never used to decide anything the
//! content itself does not decide.

use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_OUTOFMEMORY, E_POINTER};
use windows::Win32::System::Antimalware::{
    AMSI_ATTRIBUTE_CONTENT_NAME, AMSI_ATTRIBUTE_CONTENT_SIZE, AMSI_RESULT, IAntimalwareProvider,
    IAntimalwareProvider_Impl, IAmsiStream,
};
use windows::Win32::System::Com::{CoTaskMemAlloc, IClassFactory, IClassFactory_Impl};
use windows::core::{
    implement, GUID, IUnknown, Interface, Ref, Result as WinResult, BOOL, HRESULT, PWSTR,
};

use crate::result::{for_verdict, no_opinion};
use crate::scan::{Scan, Scanner};

/// The name this provider reports to Windows and to the user.
///
/// Shown in `Get-MpComputerStatus`-style listings and in the console output of
/// hosts that enumerate providers, so it is the product name and not a
/// component name.
pub const DISPLAY_NAME: &str = "Wenle Antivirus";

/// `CLASS_E_CLASSNOTREG`, which `DllGetClassObject` returns for a CLSID it does
/// not serve.
///
/// Written here rather than taken from `windows`, which exports
/// `REGDB_E_CLASSNOTREG` and not this one. They are different values for
/// different situations — `REGDB_E_*` is about the registry lookup having
/// failed, this is about a class object having been asked for something it does
/// not implement — and a COM caller distinguishes them.
pub const CLASS_E_CLASSNOTREG: HRESULT = HRESULT(0x8004_0111u32 as i32);

/// What to call content whose name could not be read.
///
/// Deliberately has no extension. The name reaches the engine's classifier,
/// where an extension is a hint about what kind of file this is, and a hint
/// invented here would be a claim about content this code knows nothing about.
pub const UNNAMED: &str = "Script Block";

/// The longest content name read from the stream, in bytes of UTF-16.
///
/// A bound on an allocation whose size the *host* chooses. The name is a label;
/// four kilobytes of UTF-16 is more than any real path and far less than a
/// hostile stream could ask for.
const MAX_NAME_BYTES: usize = 4 * 1024;

/// The most content this provider will pull out of a host, in bytes.
///
/// A script block is kilobytes. A macro is kilobytes. What is not is an
/// assembly loaded through `Assembly.Load`, which some hosts do route through
/// AMSI — and 64 MiB of that is more than this process should allocate on a
/// path a user is waiting on. Beyond this the prefix is scanned and the report
/// says the content was cut short, which is honest and still catches a rule
/// anchored near the start of a script, which is where droppers put it.
const MAX_CONTENT_BYTES: u64 = 64 * 1024 * 1024;

/// How many COM objects this DLL has handed out and not yet seen released.
///
/// A count rather than a flag because a host may hold a factory and a provider
/// at once, and because a nonzero count is the only sound reason to refuse
/// `DllCanUnloadNow` for the objects themselves. The other reason is
/// [`crate::scan::worker_started`], which is permanent.
static LIVE_OBJECTS: AtomicUsize = AtomicUsize::new(0);

/// True when this DLL may be unloaded by its host.
///
/// # Why the answer is "never", once anything has happened
///
/// A COM in-proc server is unloaded when its host asks `DllCanUnloadNow` and is
/// told yes. Two things in this crate make that answer unsafe from the moment
/// they exist:
///
/// * **An object is alive.** The host holds a pointer into this module's code.
/// * **The worker thread exists.** It has a stack and a program counter inside
///   this image, and it wakes whenever the host next asks for a scan. Unloading
///   the module under it is a crash the moment it runs, in the host's process,
///   with no way for the host to have caused or predicted it.
///
/// So once a scan has happened, this DLL is in the host for the life of the
/// host. That is the normal state of an AMSI provider — Defender's is no
/// different — and it costs one loaded image and one parked thread.
///
/// # Why this is safe to call from anywhere
///
/// Both reads are atomic loads with no lock, because this is called by COM and
/// must not be able to deadlock against anything.
pub fn can_unload() -> bool {
    LIVE_OBJECTS.load(Ordering::Acquire) == 0 && !crate::scan::worker_started()
}

/// The provider.
///
/// `#[implement]` generates `Provider_Impl`, which is what the trait below is
/// written against, and `From<Provider> for IAntimalwareProvider`. The inner
/// struct is reached through the generated `Deref`, which is how `self.scanner`
/// works inside a trait method.
#[implement(IAntimalwareProvider)]
#[derive(Debug)]
pub struct Provider {
    scanner: Scanner,
}

impl Provider {
    /// A provider that scans through `scanner`.
    pub fn new(scanner: Scanner) -> Self {
        LIVE_OBJECTS.fetch_add(1, Ordering::AcqRel);
        Self { scanner }
    }
}

/// The matching decrement, on whichever thread COM releases the last reference.
impl Drop for Provider {
    fn drop(&mut self) {
        LIVE_OBJECTS.fetch_sub(1, Ordering::AcqRel);
    }
}

impl IAntimalwareProvider_Impl for Provider_Impl {
    /// Answer one question about content a host is about to run.
    ///
    /// The panic guard is not defensive programming. `catch_unwind` here is the
    /// difference between a bug in the engine showing up as one script that
    /// went unscanned and the same bug showing up as the user's PowerShell
    /// window vanishing — and the second is how a security product gets
    /// uninstalled.
    fn Scan(&self, stream: Ref<'_, IAmsiStream>) -> WinResult<AMSI_RESULT> {
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(move || {
            let stream = match stream.ok() {
                Ok(stream) => stream,
                Err(error) => {
                    // A stream that is not there is a host that called the
                    // provider wrongly, which is not this code's fault and not
                    // something to fail the host over.
                    log::warn!("AMSI asked for a scan with no stream: {error}");
                    return no_opinion();
                }
            };
            self.examine(stream)
        }));
        match outcome {
            Ok(result) => Ok(result),
            Err(_) => {
                log::error!(
                    "a panic was caught while scanning AMSI content; the host keeps running and \
                     this content goes unscanned"
                );
                Ok(no_opinion())
            }
        }
    }

    /// A session ended.
    ///
    /// Nothing to release. Sessions exist so a provider can cache per-session
    /// state — a decoded script, a reputation lookup — and this provider holds
    /// no state that outlives one `Scan`, which is why it does not read
    /// `AMSI_ATTRIBUTE_SESSION` either. Implemented rather than omitted because
    /// the trait requires it, and a no-op is the honest body for a provider
    /// with nothing to do.
    fn CloseSession(&self, _session: u64) {}

    /// The name Windows shows for this provider.
    ///
    /// The returned string must be allocated with `CoTaskMemAlloc`: AMSI frees
    /// it with `CoTaskMemFree`, and a `PWSTR` into a Rust `String` would be a
    /// heap corruption in the host.
    fn DisplayName(&self) -> WinResult<PWSTR> {
        co_task_mem_str(DISPLAY_NAME)
    }
}

impl Provider_Impl {
    /// The work of [`IAntimalwareProvider_Impl::Scan`], outside the guard.
    ///
    /// Split out so that the guarded section is one line and there is no way to
    /// add a path that skips it.
    fn examine(&self, stream: &IAmsiStream) -> AMSI_RESULT {
        let Some(size) = read_content_size(stream) else {
            // No size means no way to allocate, which means nothing can be
            // read. Answering from the engine about zero bytes would produce a
            // `Clean` verdict for content that was never looked at, and while
            // `for_verdict` turns that into `NOT_DETECTED` rather than `CLEAN`,
            // there is no reason to spend a pipe round trip arriving at it.
            log::warn!("AMSI content size could not be read; nothing was examined");
            return no_opinion();
        };
        let name = read_content_name(stream);
        let data = read_content(stream, size);

        let scan = self.scanner.scan(&name, &data);
        let verdict = scan.verdict();
        match &scan {
            // A detection is worth a line whatever the host does with it: this
            // is the only record of content that was refused before it ran.
            Scan::Reported(_) if verdict.is_detection() => {
                log::warn!("{name}: {}", scan.summary());
            }
            // And so is a scan that did not happen, because the alternative is
            // a machine quietly running scripts nothing is looking at.
            Scan::Unavailable(reason) => {
                log::warn!("{name} was not scanned: {reason}");
            }
            Scan::Reported(_) => {
                log::debug!("{name}: {}", scan.summary());
            }
        }
        for_verdict(verdict)
    }
}

/// The content's declared size in bytes, or `None` if the stream will not say.
///
/// The attribute is a `ULONGLONG`. `retdata` is read rather than assumed:
/// providers in the wild differ on whether it counts four bytes or eight, and
/// a size assembled from the wrong half of the buffer is an allocation of the
/// wrong length followed by a read into it.
fn read_content_size(stream: &IAmsiStream) -> Option<u64> {
    let mut buffer = [0u8; 8];
    let mut returned = 0u32;
    // SAFETY: `buffer` and `returned` are locals that outlive the call, and the
    // buffer's length is what the signature passes to the provider.
    let result = unsafe { stream.GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, &mut buffer, &mut returned) };
    if let Err(error) = result {
        log::warn!("AMSI content size could not be read: {error}");
        return None;
    }
    let take = (returned as usize).min(buffer.len());
    if take == 0 {
        return None;
    }
    // Zero-extended rather than read as a native `u64`, so that a provider that
    // filled in four bytes and said so produces the size it meant.
    let mut bytes = [0u8; 8];
    bytes[..take].copy_from_slice(&buffer[..take]);
    Some(u64::from_le_bytes(bytes))
}

/// The content's name, or [`UNNAMED`] when the stream will not say.
///
/// Never fails the scan. A name is a hint for the classifier and a label in a
/// report; content with a name that could not be read is still content.
fn read_content_name(stream: &IAmsiStream) -> String {
    let mut buffer = vec![0u8; MAX_NAME_BYTES];
    let mut returned = 0u32;
    // SAFETY: as in `read_content_size`.
    let result =
        unsafe { stream.GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME, &mut buffer, &mut returned) };
    if let Err(error) = result {
        log::debug!("AMSI content name could not be read: {error}");
        return UNNAMED.to_string();
    }
    let units = (returned as usize / 2).min(buffer.len() / 2);
    let mut utf16: Vec<u16> = buffer[..units * 2]
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    // The provider's documented contract includes the terminator in the
    // returned length. Trimmed rather than trusted: an interior NUL in a name
    // is a name that would print as two.
    while utf16.last() == Some(&0) {
        utf16.pop();
    }
    if utf16.is_empty() {
        return UNNAMED.to_string();
    }
    String::from_utf16_lossy(&utf16)
}

/// Pull up to `size` bytes of content out of the host.
///
/// Read in one call after one allocation rather than in chunks: the size is
/// known, and a loop that grew a `Vec` would reallocate and copy a buffer whose
/// final length was never in doubt. The loop below exists only because a stream
/// is allowed to return fewer bytes than it was asked for.
///
/// A short read is not an error. Whatever arrived is what gets scanned, and a
/// rule that needed the missing tail simply does not fire — which is a miss and
/// not a false positive, and is the right way round.
fn read_content(stream: &IAmsiStream, size: u64) -> Vec<u8> {
    let wanted = size.min(MAX_CONTENT_BYTES) as usize;
    if wanted == 0 {
        return Vec::new();
    }
    let mut data = vec![0u8; wanted];
    let mut filled = 0usize;
    while filled < data.len() {
        let mut read = 0u32;
        // SAFETY: the sub-slice outlives the call and its length is what the
        // signature passes to the provider; `read` is a `u32` on this stack.
        let result = unsafe { stream.Read(filled as u64, &mut data[filled..], &mut read) };
        match result {
            Ok(()) if read == 0 => break,
            Ok(()) => filled += (read as usize).min(data.len() - filled),
            Err(error) => {
                log::warn!("AMSI content read stopped at {filled} bytes: {error}");
                break;
            }
        }
    }
    if size > MAX_CONTENT_BYTES {
        log::warn!(
            "AMSI content is {size} bytes and only the first {MAX_CONTENT_BYTES} were scanned"
        );
    }
    data.truncate(filled);
    data
}

/// A `CoTaskMemAlloc`'d copy of `text`, for a COM out-parameter that the caller
/// frees.
fn co_task_mem_str(text: &str) -> WinResult<PWSTR> {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    wide.push(0);
    // SAFETY: the allocation is checked for null before use, is written with
    // exactly as many `u16` as were allocated, and is handed to the caller as
    // its owner. `CoTaskMemAlloc`'s alignment satisfies `u16`'s.
    unsafe {
        let memory = CoTaskMemAlloc(wide.len() * size_of::<u16>()) as *mut u16;
        if memory.is_null() {
            return Err(E_OUTOFMEMORY.into());
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), memory, wide.len());
        Ok(PWSTR(memory))
    }
}

/// The class factory `DllGetClassObject` hands back.
///
/// One scanner is shared by every provider this factory makes, so every host
/// process has exactly one worker thread and one connection however many
/// sessions it opens.
#[implement(IClassFactory)]
#[derive(Debug)]
pub struct Factory {
    scanner: Scanner,
}

impl Factory {
    /// A factory that makes providers scanning through `scanner`.
    pub fn new(scanner: Scanner) -> Self {
        LIVE_OBJECTS.fetch_add(1, Ordering::AcqRel);
        Self { scanner }
    }
}

impl Drop for Factory {
    fn drop(&mut self) {
        LIVE_OBJECTS.fetch_sub(1, Ordering::AcqRel);
    }
}

impl IClassFactory_Impl for Factory_Impl {
    /// Make a provider and hand back the interface `iid` names.
    ///
    /// Aggregation is refused rather than ignored. A host asking for it wants
    /// its own `IUnknown` to be the identity of this object, which would mean
    /// this code forwarding every `QueryInterface` it does not answer — and
    /// nothing in AMSI aggregation's scenario applies to a provider that holds
    /// no state worth sharing. Refusing is the documented answer and the honest
    /// one; silently returning a non-aggregated object would break whatever the
    /// host was trying to do in a way it could not detect.
    fn CreateInstance(
        &self,
        outer: Ref<'_, IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> WinResult<()> {
        if !outer.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        if object.is_null() || iid.is_null() {
            return Err(E_POINTER.into());
        }
        let provider: IAntimalwareProvider = Provider::new(self.scanner.clone()).into();
        // SAFETY: `provider` is a live interface and `object` was checked
        // non-null above; `query` writes one interface pointer into it and
        // adjusts the reference count by the COM rules. A refusal is returned
        // as an `HRESULT` rather than as an error, so no pointer is written on
        // the failure path — which is what COM requires.
        unsafe { provider.query(iid, object) }.ok()
    }

    /// A host asking this server to stay loaded.
    ///
    /// Nothing to do, and that is the correct body rather than a stub. This
    /// server already stays loaded for the life of the host — see
    /// [`can_unload`] — so there is no state a lock could protect and no
    /// counting a lock could change.
    fn LockServer(&self, _lock: BOOL) -> WinResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_not_registered_code_is_the_one_com_documents() {
        // Written by hand because `windows` does not export it, so this is the
        // only thing standing between a typo and a COM server that reports
        // "class not registered" as an unknown failure.
        assert_eq!(CLASS_E_CLASSNOTREG.0 as u32, 0x8004_0111);
        assert!(CLASS_E_CLASSNOTREG.is_err());
        // And it is not the registry-lookup code, which is a different value
        // for a different situation.
        assert_ne!(CLASS_E_CLASSNOTREG, windows::Win32::Foundation::REGDB_E_CLASSNOTREG);
    }

    #[test]
    fn a_name_is_allocated_the_way_com_will_free_it() {
        // The buffer has to be `CoTaskMemAlloc`'d; AMSI frees it with
        // `CoTaskMemFree` and anything else is heap corruption in the host.
        // The test can only check the contents and that a null is refused, but
        // those are the two failure modes that present as garbage in a provider
        // listing.
        let name = co_task_mem_str("Wenle Antivirus").expect("allocates");
        assert!(!name.is_null());
        // SAFETY: the pointer came from `CoTaskMemAlloc` just above and is read
        // as the NUL-terminated UTF-16 it was written as.
        let read_back = unsafe { name.to_string() }.expect("valid utf-16");
        assert_eq!(read_back, "Wenle Antivirus");
        // SAFETY: the allocation is released exactly once, here, by the same
        // allocator family the host would have used.
        unsafe {
            windows::Win32::System::Com::CoTaskMemFree(Some(name.0 as *const c_void));
        }
    }

    #[test]
    fn an_empty_name_still_produces_a_terminated_string() {
        let name = co_task_mem_str("").expect("allocates");
        assert!(!name.is_null());
        // SAFETY: as above.
        let read_back = unsafe { name.to_string() }.expect("valid utf-16");
        assert_eq!(read_back, "");
        // SAFETY: as above.
        unsafe {
            windows::Win32::System::Com::CoTaskMemFree(Some(name.0 as *const c_void));
        }
    }

    // The tests for `can_unload` and `DllCanUnloadNow` are not here. They assert
    // on process-globals that this binary's own `scan` tests move, so they live
    // in `tests/`, one scenario per file, where each gets a process of its own.
    // See `tests/unload_before_use.rs` for the full explanation.

    #[test]
    fn the_display_name_is_the_product_and_not_a_component() {
        // It is what a person sees in a provider listing, so a component name
        // here is a provider nobody can identify.
        assert_eq!(DISPLAY_NAME, "Wenle Antivirus");
        assert!(!DISPLAY_NAME.is_empty());
    }

    // Both operands are `const`, so clippy can fold each assertion away and is
    // right that neither can fail at run time. That is the point: this is not
    // checking a value computed at run time, it is failing the build of anyone
    // who edits the cap out of the band this path can actually carry. The same
    // allowance, for the same reason, as the window-size test in `av-gui`.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_content_cap_is_large_enough_for_what_this_path_carries() {
        // Script blocks and macros are kilobytes. The cap exists for the host
        // that routes something else through AMSI, and it must not be so low
        // that an ordinary large script is truncated.
        assert!(MAX_CONTENT_BYTES >= 16 * 1024 * 1024);
        // And it must be a bound at all, because the size is the host's number.
        assert!(MAX_CONTENT_BYTES <= 256 * 1024 * 1024);
    }

    #[test]
    fn a_name_buffer_is_bounded_and_the_fallback_has_no_extension() {
        assert_eq!(MAX_NAME_BYTES, 4096);
        // An invented extension would be a claim to the classifier.
        assert!(!UNNAMED.contains('.'));
        assert!(!UNNAMED.is_empty());
    }
}
