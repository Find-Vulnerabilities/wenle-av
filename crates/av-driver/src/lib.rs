//! The Wenle AV kernel-mode minifilter.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It is a thin shell. `av-driver-proto` holds the protocol, the wire layouts,
//! the path normalisation, the exclusion matching and the decision state
//! machine, and every one of its tests runs on stable Rust on a build machine.
//! This crate marshals kernel callbacks onto that logic and does nothing else:
//! no parsing, no policy, no arithmetic that a test could have checked
//! somewhere cheaper. That split exists because a driver's logic cannot be
//! tested without loading it, and logic that cannot be tested is logic that is
//! wrong.
//!
//! # Why the decision channel is a communication port and not an IOCTL
//!
//! Both are in `av-driver-proto`, and the split between them is not arbitrary.
//!
//! An IOCTL is *user-initiated*. The service sends one when it wants something:
//! change the mode, set the exclusions, read the counters, drain the event
//! queue. That is the right shape for configuration, and `av-driver-proto`'s
//! control codes are the ones a service issues.
//!
//! A decision request is *driver-initiated*. A file open has to stop and wait
//! for an answer that only the service can give. There is no IOCTL for that: an
//! IOCTL is a call the service makes into the driver, and this is the driver
//! calling out. The filter manager's communication port exists for exactly this
//! direction, and `FltSendMessage` -- with its bounded timeout -- is exactly
//! this direction with a deadline.
//!
//! So the port carries decisions and events upward, and the IOCTL codes carry
//! configuration and bulk reads downward. A protocol with only one of the two
//! could not express both directions, and a driver that inverted either would
//! be waiting for a message that can only be sent while it is waiting.
//!
//! # The deadlock this design exists to avoid
//!
//! A pre-operation callback runs on the thread performing the file operation.
//! Holding any lock across the wait would be a machine that stops: the reply
//! arrives on a different thread, and a driver lock held here that the reply
//! path also needed would never be released, because the reply cannot arrive.
//! Every piece of shared state in this file is therefore an atomic, or a slot
//! written once before any reader can exist -- never a `Mutex`. The one place
//! this driver blocks is `flt::FltSendMessage`, and there is no lock to hold
//! there. That is the property to preserve when editing this file, and it is
//! why the volume cache and the exclusion table are filled during start-up
//! rather than updated at run time.
//!
//! # What is verified, and what is not
//!
//! The image loads. In the test VM on 2026-09-26 it registered, started, and
//! appeared in `fltmc filters` at altitude 321000 -- so what has been watched
//! happening is this file's start-up path and its fail-open branch. **Nothing
//! has ever been refused by this filter**: refusing needs an answer from the
//! service, and no service has yet completed a connection.
//!
//! Nine defects have been found in this driver, seven of them on 2026-09-26, all
//! by running it in that VM. They are listed in the order they were found. Every
//! one of them had been there since it was written; what changed is that the
//! code around it started running. The ninth is the first one that is not *in*
//! this code at all -- the fault is in another filter -- and it is listed
//! because what this driver was doing at the time is what made it reachable.
//!
//! 1. **Zero volumes attached.** `fltmc attach WenleAvFilter C:` returned
//!    `0x801F000D` and named the cause: the operation table ended with an
//!    all-zero entry, which is a second registration of `IRP_MJ_CREATE` rather
//!    than the terminator [`flt::IRP_MJ_OPERATION_END`] requires. A minifilter
//!    with no instance receives no operations, so **none of the three callbacks
//!    below had ever executed** when this was found.
//! 2. **The port refused everyone.** An elevated service was refused with
//!    `E_ACCESSDENIED` because `FltCreateCommunicationPort` was given a null
//!    `security_descriptor`; the null case is not the filter manager's default
//!    descriptor, and it is not "SYSTEM plus administrators" either.
//! 3. **`FILE_EXECUTE` was `0x0001`.** That is `FILE_READ_DATA`. The gate in
//!    `create_pre_operation` exists to let ordinary opens through untouched; with
//!    the wrong bit it let through exactly the opens that did *not* read, so
//!    `decide` ran on nearly every file open on the machine.
//! 4. **`FLT_FILE_NAME_INFORMATION.Name` was read eight bytes late**, so
//!    `decide` turned `Volume.Length` into a buffer pointer and dereferenced it.
//! 5. **`PFLT_CONNECT_NOTIFY` took its first argument as a pointer.** The header
//!    passes `PFLT_PORT ClientPort` -- `typedef struct _FLT_PORT *PFLT_PORT`,
//!    `fltKernel.h` 257 -- **by value**, and `port_connect` read `*client_port`
//!    instead, storing the first eight bytes of the filter manager's own port
//!    object as the connected client. Every `FltSendMessage` after that was
//!    handed a number that is not a port.
//! 6. **`PFLT_MESSAGE_NOTIFY` was declared with five parameters where the header
//!    has six.** The `ULONG OutputBufferLength` -- a value -- landed in the slot
//!    this file called `*mut u32`, and `port_message` wrote `0` through it.
//! 7. **`FltSendMessage` was called from a post-operation callback at
//!    `DISPATCH_LEVEL`.** The header caps that call at `APC_LEVEL`
//!    (`fltKernel.h` 4642) and a write post-operation runs at `DISPATCH_LEVEL`
//!    for paging and unbuffered I/O. Found 2026-09-27, after `run` bugchecked
//!    the VM a second time with defect 5 already fixed -- which is what
//!    disproved the attribution of the previous crash to `port_connect`. The
//!    fix is `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO` on the two
//!    registrations that can be reached at that level, plus an explicit IRQL
//!    check in the three callbacks that reach a `APC_LEVEL`-capped API.
//! 8. **The unload callback passed its own argument as the filter.**
//!    `PFLT_FILTER_UNLOAD_CALLBACK` takes `FLT_FILTER_UNLOAD_FLAGS` -- a *value*
//!    -- and this file handed that value to `FltUnregisterFilter`, whose first
//!    parameter is the `PFLT_FILTER` to deregister, so the filter manager
//!    dereferenced a flags value as a filter object. Found 2026-09-26 and fixed by
//!    taking the filter from the static `driver_entry` writes; **confirmed
//!    2026-09-27** by reading the faulting instruction out of the dump and the
//!    registration bytes of the image that dump names. It is listed last because
//!    the confirmation, not the finding, is what turns it into a datum.
//! 9. **The write notification was sent *from* the write post-operation.**
//!    Defect 7 capped that call's IRQL and dropped the writes it could not
//!    report; the machine bugchecked anyway, in the second a service connected,
//!    on 09-27 and again on 10-01. The dump from 09-27, read on 10-01, faults at
//!    `ntoskrnl.exe +0x40b080` -- `IoGetRequestorProcess`, whose first
//!    instruction dereferences its `PIRP` argument -- and the caller is
//!    `WdFilter.sys`'s **own** `IRP_MJ_WRITE` post-operation, which runs *after*
//!    this filter's at the lower altitude (321000 against 328010) and looks up
//!    the requestor process of the operation's callback data. The data it is
//!    given is internally inconsistent: its `Flags` has the fast-I/O bit set
//!    (or `WdFilter` would not have taken that branch) *and* the IRP bit set
//!    (or the lookup would not have read the IRP slot), while the slot at
//!    `Data - 0xB8` holds zero. Of the twelve write callbacks the same dump
//!    retains, eleven are ordinary fast-I/O data and exactly one -- this
//!    filter's -- has the IRP bit set, and the only thing this filter does on
//!    that path, when a service is connected, is send.
//!
//!    **That is an attribution, not a mechanism.** What is measured is the
//!    fault, the caller, its altitude order, the inconsistency, and the A/B --
//!    driver loaded with no service is stable; driver unloaded with the service
//!    running is stable; driver loaded *and* connected goes down. How a send
//!    from inside a callback leaves the shared callback data inconsistent is
//!    not established, and the fix does not depend on knowing: the write
//!    post-operation now queues the notification and returns, so the callback
//!    no longer calls anything that can touch the operation, and the send
//!    happens on a filter-manager work item at `PASSIVE_LEVEL` -- legal for
//!    every write rather than for the ones that arrive below `APC_LEVEL`, which
//!    is a second, independent improvement over defect 7's fix.
//!
//! Defects 1 and 2 are why 3 through 7 were invisible for so long: with no
//! instance, no callback ran at all, and with no client, neither port callback
//! ever fired and `ask_service` and `send_event` both returned at their null
//! check. Fixing 2 is what made 5 reachable, and defect 7 is the same
//! "unreachable until a client exists" shape one layer further in -- which is
//! why it survived the fix that was aimed at 5.
//!
//! **Two of the eight are now confirmed against a dump, and a third is implicated
//! by one, by reading the image each dump names.** Defects 3, 6 and 7 do not
//! depend on anything the VM reported
//! -- the WDK headers say what each value, each parameter and each IRQL cap is,
//! and `build.rs` reads that header at build time and refuses to compile a
//! callback whose arity or pointer shape disagrees with it. That is still only the
//! *declarations* being certain. The difference the dumps made is this:
//!
//! - **Defect 5 is what 09-26 13:44 was.** fltMgr faulted inside `FltSendMessage`
//!   at `FLTMGR.SYS +0x17dab`, on `mov r13,[rcx+8]`, where `rcx = [r14]` and `r14`
//!   is provably still the second argument -- `PFLT_PORT *ServerPort`, a pointer to
//!   **this file's** port variable. What it found there was `0xffffffff80001874`:
//!   non-null, so it sailed through the `je` three bytes earlier, and not a port.
//!   That is defect 5's signature almost word for word, and the build the dump
//!   names (`TimeDateStamp 0x6ab7579a`) is the one from before the fix.
//! - **Defect 8 is what 09-26 12:07 was.** fltMgr faulted at `FLTMGR.SYS +0x58417`
//!   on `mov r13,[rbx+38h]`, which is `FltUnregisterFilter` dereferencing its first
//!   argument as the filter -- and that argument came from here. The KMDF image's
//!   own bytes say so: its `FLT_REGISTRATION` names `FilterUnloadCallback`
//!   `0x180001460`, and that function is `mov rsi,rcx` then `call
//!   [FltUnregisterFilter]` with `rcx` never reloaded, so it passes the callback's
//!   first argument through. **The KMDF binding was not the cause of 12:07**, which
//!   is the hypothesis that stood for a day on the strength of KMDF being the
//!   newest thing in the image.
//! - **Defect 4 is implicated by 09-26 13:18**, which is weaker than the other
//!   two and is labelled as such: the dump names an instruction of *this* driver
//!   rather than of fltMgr, so the image is read directly, and what it shows is a
//!   bounded wide-character scan on an unreadable base. Defect 4 is the reason a
//!   name pointer in this file could be unreadable. That is a fit, not a proof --
//!   see the bugcheck section below for what the dump does and does not say.
//!
//! Defect 5 is also the worked example of why the distinction between certain
//! *declarations* and a *diagnosis* is load-bearing. It was the standing suspect
//! for the 13:48 crash on a sound argument -- it was the one thing that first ran
//! when the service connected -- and when it was fixed the machine went down
//! again, in the same second, for the same reason. The argument's *form* was right
//! and its *premise* was wrong: `send_event` was also first reachable at connect,
//! and nothing had looked at it. The dump later confirmed the suspicion was
//! correct *for the earlier crash*, which is not the same as its having been
//! correct when it was made.
//!
//! ## The bugchecks, and what the dumps answered
//!
//! `tools/dumpwho.rs` in this workspace reads these and prints the module
//! containing the faulting instruction -- the one line of `!analyze -v` that
//! settles an attribution. **Four dumps have been read**: three from 09-26 that
//! survived in `C:\Windows\Minidump\`, and the 09-27 one kept at
//! `C:\WenleAV\kept.dmp`. The other 09-27 dump is gone from that VM.
//!
//! `TimeDateStamp` is what identifies the build each dump ran; `SizeOfImage` does
//! not, because every WDM build here is `0x12000` and only the KMDF one is
//! `0x14000`.
//!
//! | when | code | what the dump says | build |
//! |---|---|---|---|
//! | 09-26 12:07 | `0x7E` | `FLTMGR.SYS +0x58417`, in `FltUnregisterFilter` | KMDF, `0x6ab1b71d` |
//! | 09-26 13:18 | `0x3B` | `WenleAvFilter.sys +0x26f0`, inside `.text` | WDM, `0x6ab7511a` |
//! | 09-26 13:44 | `0x50` | `FLTMGR.SYS +0x17dab`, in `FltSendMessage` | WDM, `0x6ab7579a` |
//!
//! All three are **diagnosed**, not merely attributed, because the faulting
//! instruction was then read. For the two in fltMgr the host's `fltMgr.sys` agrees
//! with the dump on four independent fields -- `SizeOfImage` `0x9a000`,
//! `TimeDateStamp` `0x54ad72bc`, entry point `0x8c010`, and the name the dump
//! decodes -- so the instruction really is the one that ran. For 13:18 the build
//! the dump names is this project's own output, kept as
//! `WenleAvFilter.sys.pre-fix` in the deploy directory, and `+0x26f0` is
//! `movdqu xmm1,xmmword ptr [rcx+r8*2]` -- the first of four 16-byte loads in a
//! loop that `pcmpeqw`s every lane against zero. That is a search for a NUL
//! **`u16`**, `r8*2` being the two-byte element stride: this driver walking a
//! wide-character name, on a base pointer that was not readable. Its only caller
//! sits at `0x21a1` behind a `cmp rdx,105h` -- 261, `MAX_PATH` plus one -- so what
//! faulted is bounded name handling and nothing else in the image.
//!
//! **A diagnosis is not a verdict.** That the pointer came from defect 4's
//! misread `Name` is the reading the evidence supports -- that build is `pre-fix`,
//! so 3 and 4 were both live -- and it is still a reading. What the dump supplies
//! is the instruction, and no more.
//!
//! The 12:07 fault is the only one here the unload path owns: it followed `fltmc
//! unload` then `fltmc load`, on the KMDF build, with the filter attached to zero
//! volumes. The 13:44 one came half an hour later with the filter attached and no
//! unload in the sequence.
//!
//! **None of the three explains 09-27, and the 09-27 dump says what does.** Both
//! of that morning's crashes are `0x3B`/`0xc0000005` and both faulted at
//! `ntoskrnl.exe +0x40b080`. That number was wrong for four days: it had been
//! read as "the low 16 bits are `0xb080`", with kernel images 64 KB aligned
//! offered as the reason the offset could be taken from them. **The low 16 bits
//! of an offset are that offset modulo 64 KB, which is not the offset.**
//! `0x40b080` and `0xb080` are the same number to that test, and so are 64 other
//! candidates. Full subtraction of the image base is the only reading that means
//! anything, and `dumpwho` does that subtraction.
//!
//! `+0x40b080` is not a guess and not a symbol: it is the RVA of the **exported**
//! `IoGetRequestorProcess`, whose first instruction is `f7 41 10 00 20 00 00` --
//! `test dword ptr [rcx+10h], 2000h`, reading `Irp->Flags` at `+0x10` through
//! `rcx` = the `PIRP`. A fault on the first instruction of a leaf that only
//! dereferences its argument means the argument was bad, i.e. **something handed
//! `IoGetRequestorProcess` a `PIRP` that could not be read.** `Irp->Flags` alone
//! is not enough to place the blame; the faulting *data* address is what
//! separates a null or small pointer from freed pool or a user address, and a
//! triage dump carries it in the `EXCEPTION_RECORD64` the 09-27 header holds --
//! which `dumpwho` now reads (see `find_exception_records`).
//!
//! **This driver does not import `IoGetRequestorProcess` or any requested-process
//! API** -- six ntoskrnl imports at the time of that diagnosis, all listed under
//! "WDM, not KMDF" below; a seventh, `PsGetCurrentProcessId`, was added on
//! 2026-10-18, which reads the calling thread's own process and takes no
//! pointer, so it is not the family this paragraph is about -- so the
//! call came from fltMgr or from another filter. Within fltMgr the candidates are
//! narrowed by what the fault rules out: the `FltSendMessage` call site at
//! `+0x295` dereferences the same IRP at `+0x17EEB` and `+0x17EFE` before it
//! calls, so it cannot be the one that faulted. What remains is the exported
//! `FltGetRequestorProcess` / `FltGetRequestorProcessId` /
//! `FltGetRequestorProcessIdEx`, which compute `rcx = [CallbackData - 0xB8]` --
//! the IRP, since `sizeof(IRP)` is `0xB8` on x64 and fltMgr allocates its IRP
//! immediately before its `FLT_CALLBACK_DATA` -- and pass it on **with no null
//! check and no validation**. Those are the only paths that reach that
//! instruction with nothing dereferenced first, which is the signature the dump
//! shows. `WdFilter.sys` imports two of the three and shares this filter's
//! callback chain.
//!
//! **That is a narrowing, not an attribution.** Defects 5 and 8 are provably
//! absent from the 09-27 image, and the check is the binary rather than this
//! comment: its `filter_unload` takes the filter from the `FILTER` static and
//! never reads its own argument, and its `FltSendMessage` call site loads the
//! port from the `CLIENT_PORT` static that `port_connect` fills **by value**.
//! What has not been read yet is the one datum that would name the caller, and it
//! is in a file this project already has.
//!
//! Every other claim below about what the filter manager does with these
//! callbacks still comes from the WDK headers and the documentation rather than
//! from watching it happen. Where that gap matters it is called out where it
//! occurs rather than collected into a list at the end.
//!
//! # WDM, not KMDF
//!
//! This image is entered through `DriverEntry` and imports nothing from
//! `WDFLDR.SYS`. It did not use to: until 2026-09-26 the manifest said
//! `driver-type = "KMDF"`, which linked the framework's own entry point, and
//! the import table named `WDFLDR` -- measured with `dumpbin` and recorded in
//! this comment as though it were a neutral fact rather than a question. The
//! crate never called `WdfDriverCreate`, so the framework's bind had no unbind
//! and the load path belonged to a framework this driver does not otherwise use.
//! The manifest carries the full argument, and `build.rs` the shorter one.

#![no_std]
#![warn(missing_docs)]

// A kernel-mode crate with no panic handler does not link. `wdk-panic` supplies
// one; it is a `no_std` crate, so the handler is reachable only through an
// `extern crate` that is actually in the link.
#[cfg(not(test))]
extern crate wdk_panic;

mod flt;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

use av_driver_proto::decision::{Decision, DecisionPolicy};
use av_driver_proto::event::{EventAction, SubjectKind};
use av_driver_proto::exclusions::{
    ExclusionError, FixedExclusionTable, MAX_EXCLUSIONS, MAX_EXCLUSION_UNITS,
};
use av_driver_proto::path::device_to_dos_path;
use av_driver_proto::wire::{
    ConfigMessage, DecisionReplyMessage, DecisionRequestMessage, DriverStats, EventMessage,
    MessageKind, PortMessageHeader, EVENT_VALUE_TRUNCATED, MAX_PATH_UNITS, MAX_VALUE_UNITS,
};
use av_driver_proto::{
    gate_update, is_our_image, is_protected_file, strip_process, strip_thread, GateUpdate,
    GATE_DIR_UNITS, IMAGE_NAME_BYTES,
};

use flt::{
    FileDispositionInformation, FileDispositionInformationEx, FileRenameInformation,
    FltCallbackData, FltFileNameInformation, FltFilter, FltOperationRegistration, FltPort,
    FltRegistration, FltRelatedObjects, FltSetFileInformationParameters, IoSecurityContext,
    NtStatus, ObjectAttributes, UnicodeString, FILE_DISPOSITION_INFORMATION_CLASS,
    FILE_DISPOSITION_INFORMATION_EX_CLASS, FILE_EXECUTE, FILE_RENAME_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION_EX_CLASS, FILE_RENAME_NAME_OFFSET, FLT_FILE_NAME_NORMALIZED,
    FLT_FILE_NAME_QUERY_DEFAULT, FLT_PORT_ALL_ACCESS, FLT_POSTOP_FINISHED_PROCESSING,
    FLT_PREOP_COMPLETE, FLT_PREOP_SUCCESS_NO_CALLBACK, FLT_PREOP_SUCCESS_WITH_CALLBACK,
    IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, IRP_MJ_CREATE, IRP_MJ_OPERATION_END,
    IRP_MJ_SET_INFORMATION, IRP_MJ_WRITE, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE,
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

/// `FLT_REGISTRATION_VERSION`, from `fltKernel.h`.
///
/// This said `0x0200` until 2026-09-26, with a comment claiming that value had
/// been current since Windows 7. Both halves were wrong. The header labels
/// `0x0200` "Registration version for XP SP2 and W2K3 SP1"; `0x0202` is Vista
/// RTM and `0x0203` is Windows 8, which adds
/// `PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK`. The header's instruction is
/// not ambiguous -- "NOTE: You should always pass in this defined value (do not
/// explicitly specify older values)" -- and this crate's `FltRegistration` is
/// the current layout, with the nine trailing members spelled out in
/// `unused_tail`, so `size` and `version` now describe the same structure.
///
/// The old value did not fail loudly, which is the reason it survived: the
/// filter manager accepts a version it knows, and an older version is one it
/// knows.
const FLT_REGISTRATION_VERSION: u16 = 0x0203;

/// The port name, from the protocol crate so that the driver and the user-mode
/// client cannot disagree about it.
///
/// It used to be a literal here, and it disagreed with the literal in `av-core`
/// — see `av_driver_proto::port`, which is now the only place it is spelled.
const PORT_NAME: &[u8] = av_driver_proto::PORT_NAME_BYTES;

// The conversion from `DecisionPolicy`'s milliseconds to `FltSendMessage`'s
// 100-nanosecond units used to live here as a bare constant, and the arithmetic
// it was multiplied into produced a positive number -- which the filter manager
// reads as an absolute date in 1601 rather than as an interval. It is
// `DecisionPolicy::relative_timeout_100ns` now, where the sign is part of the
// conversion and there is a test that says so.

// The interrupt time, in 100-nanosecond units, which is the clock the protocol
// stamps messages with.
//
// `KeQueryInterruptTimePrecise`, and not the `KeQueryInterruptTime` the
// documentation for the same clock also names: the coarser spelling is a
// `#define` over `KUSER_SHARED_DATA.InterruptTime` (`wdm.h` 4684) rather than an
// export, so a declaration of it links nothing. That is measured rather than
// assumed — `KeQueryInterruptTime` with its terminating NUL occurs zero times in
// `Lib\10.0.26100.0\km\x64\ntoskrnl.lib` and `KeQueryInterruptTimePrecise`
// occurs five. The precise one is the one a driver can link.
//
// # It takes an out-parameter, and this declaration said it did not
//
// `wdm.h` 24471-24475:
//
//     _IRQL_requires_same_
//     ULONG64
//     KeQueryInterruptTimePrecise (
//         _Out_ PULONG64 QpcTimeStamp
//         );
//
// The return value is the interrupt time; `*QpcTimeStamp` receives the
// performance-counter value that goes with it, and only the first is wanted
// here. Dropping the parameter from the declaration did not drop the store from
// the function -- it made the kernel write eight bytes through whatever `rcx`
// happened to hold at the call. On the process-creation path that is the
// sequence counter the line above has just fetched, so the next process created
// after the driver loads bugchecks with `0x3B`, an access violation inside
// `ntoskrnl`, and `Rcx` holding a small number. That cost a boot loop to find:
// see the dump at `C:\Windows\Minidump\101026-17625-01.dmp`, whose stack window
// holds the return address of this very call (`WenleAvFilter.sys +0x1d53`) as a
// live frame 0xA8 bytes above the faulting `Rsp`. The five export references
// above were read as evidence that the *declaration* was right; they are
// evidence only that the *name* resolves.
//
// `build.rs` now compares this declaration against the header, so the next
// reader finds out at compile time instead. `wdk-sys` has no binding for this
// function at all, which is why it is written out here.
extern "system" {
    fn KeQueryInterruptTimePrecise(qpc_timestamp: *mut u64) -> u64;
}

/// The interrupt time, in 100-nanosecond units.
///
/// The out-parameter lives and dies in this frame and nothing reads it, which is
/// the whole reason this wrapper exists: a caller cannot get the parameter list
/// wrong through it, and getting the parameter list wrong here is a bugcheck
/// rather than a compile error.
///
/// Callers are the process-creation callback, the write-notification path and
/// the port-connect path. The header's only annotation on the function is
/// `_IRQL_requires_same_`, which constrains what it does to the IRQL rather than
/// what IRQL it may be entered at.
fn interrupt_time_100ns() -> u64 {
    let mut qpc_timestamp = 0u64;
    // SAFETY: the function writes one `u64` through its argument, and the
    // argument is the address of a live local of exactly that type. It has no
    // other precondition to satisfy.
    unsafe { KeQueryInterruptTimePrecise(&mut qpc_timestamp) }
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

/// The registered filter, or null before `FltRegisterFilter` has run.
///
/// An `AtomicPtr` rather than a `Mutex<Option<_>>` on purpose: every reader is
/// on a path that may be about to wait for the service, and a lock taken there
/// is the deadlock described in the crate documentation.
static FILTER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// The server end of the communication port, or null before it is created.
static SERVER_PORT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// The client connection, or null when no service is connected.
///
/// The filter manager writes through the pointer it is given when a connection
/// dies, so `FltSendMessage` is passed a local copy of this each time rather
/// than the address of the static. The disconnect callback is the only writer.
static CLIENT_PORT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// The next request identifier. Monotonic for the life of the driver, which is
/// what makes a reply identifiable: an id belongs to one request and is never
/// handed out again, so a reply carrying an id this driver has already answered
/// cannot be mistaken for the answer to a later one.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// The next event sequence number, on the same reasoning as the request id.
static NEXT_EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// What `PsSetCreateProcessNotifyRoutineEx` answered in `DriverEntry`.
///
/// Kept rather than discarded, and the whole reason is the sentence a discarded
/// return value makes false: a driver whose process notifications never
/// registered looks exactly like a driver on a machine where no program has
/// started. `port_connect` sends this to the service as an
/// [`EventAction::StateChanged`] event the moment one connects, so the answer
/// is available to a client rather than to a debugger.
///
/// The value is an `NTSTATUS`, and `STATUS_SUCCESS` is the one that means the
/// routine is registered. Nothing else is a success, including values a later
/// Windows defines.
static PROCESS_NOTIFY_STATUS: AtomicI32 = AtomicI32::new(STATUS_REGISTRATION_UNATTEMPTED);

/// What `ObRegisterCallbacks` answered in `DriverEntry`.
///
/// The second registration, kept for the same reason as the first, and reported
/// through the same channel: a
/// [`SubjectKind::Protection`](av_driver_proto::SubjectKind::Protection) event
/// the moment a service connects. The two are separate events rather than one
/// because they are separate questions — process-start notifications are how the
/// memory monitor learns a process exists, and object callbacks are how this
/// product keeps a handle to itself from being turned into a termination — and a
/// machine can have one and not the other.
///
/// `STATUS_SUCCESS` is the one value that means the callbacks are registered.
static OB_STATUS: AtomicI32 = AtomicI32::new(STATUS_REGISTRATION_UNATTEMPTED);

/// The handle `ObRegisterCallbacks` returned, or null when there is none.
///
/// Kept rather than discarded because `ObUnRegisterCallbacks` is the only way to
/// undo the registration, and it takes this value. The alternative — leaving the
/// callbacks registered across an unload — is a callback into a driver that has
/// been unloaded, which is a bugcheck rather than a leak.
static OB_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// What `CmRegisterCallbackEx` answered in `DriverEntry`.
///
/// The third registration, kept for the same reason as the other two and
/// reported through the same channel: a
/// [`SubjectKind::Registry`](av_driver_proto::SubjectKind::Registry) event the
/// moment a service connects. Registry notifications are how a key creation or a
/// value write is seen at all — the file callbacks cannot see them — and they
/// fail independently of both other mechanisms.
static REGISTRY_STATUS: AtomicI32 = AtomicI32::new(STATUS_REGISTRATION_UNATTEMPTED);

/// The cookie `CmRegisterCallbackEx` returned, valid only when
/// [`REGISTRY_REGISTERED`] is set.
///
/// A separate flag rather than "nonzero means registered": the cookie is a
/// `LARGE_INTEGER` the configuration manager chooses, and nothing in the API
/// says it cannot be zero. A zero check would then skip `CmUnRegisterCallback`
/// and leave a callback pointing into an unloaded image.
static REGISTRY_COOKIE: AtomicI64 = AtomicI64::new(0);

/// Whether [`REGISTRY_COOKIE`] holds a registration to undo.
///
/// Set after the cookie is stored and cleared when it is unregistered, so a
/// reader that sees the flag set sees the cookie too.
static REGISTRY_REGISTERED: AtomicBool = AtomicBool::new(false);

/// The value of [`PROCESS_NOTIFY_STATUS`] and [`OB_STATUS`] before the attempt.
///
/// Not `STATUS_SUCCESS`, which would make a driver that had never asked report
/// itself as registered — the one wrong answer this whole mechanism exists to
/// prevent. No `NTSTATUS` the kernel returns has this value: the severity bits
/// are `01` (informational), the customer bit is set, and `0x7FFF` is a
/// reserved facility.
///
/// Unreachable in practice, because both registrations are attempted in
/// `DriverEntry` and `port_connect` cannot run before `DriverEntry` returns.
/// Written as a distinct value rather than as zero anyway, because "cannot
/// happen" is a claim, and a reader of the status has no way to check it.
const STATUS_REGISTRATION_UNATTEMPTED: i32 = i32::MAX;

// ---------------------------------------------------------------------------
// The write gate's state
// ---------------------------------------------------------------------------

/// The length, in code units, of the directory in [`GATE_DIRECTORY`].
///
/// **Written at most once per driver load, and never cleared.** That is the
/// property the whole gate rests on, and it is two facts that have to be kept
/// apart:
///
/// * *This* value says the buffer has been filled. It is the one that
///   establishes the happens-before edge a reader needs, and zero means "never
///   filled" — which is why it cannot double as "not armed". A gate that was
///   armed and then disarmed would have to zero it, and the next arm would then
///   be a second write into a buffer a reader could be looking at.
/// * [`GATE_ARMED`] says whether the gate is on right now. That one goes both
///   ways, as often as the service asks, and it is the only one a disarm moves.
///
/// [`av_driver_proto::gate_update`] is written against exactly this split: its
/// `stored` argument is this value's slice, which stays non-empty after a
/// disarm, so a re-arm naming the same directory is [`GateUpdate::AlreadyArmed`]
/// and never a write.
static GATE_UNITS: AtomicU32 = AtomicU32::new(0);

/// Whether the write gate is on.
///
/// Separate from [`GATE_UNITS`] rather than folded into it; the argument is in
/// that field's documentation. Read first on the write path, because when it is
/// false the gate costs one relaxed load and nothing else.
static GATE_ARMED: AtomicBool = AtomicBool::new(false);

/// The installation directory the gate compares against.
struct GateDirectory(UnsafeCell<[u16; GATE_DIR_UNITS]>);

impl GateDirectory {
    /// An empty buffer.
    const fn new() -> Self {
        Self(UnsafeCell::new([0u16; GATE_DIR_UNITS]))
    }
}

// SAFETY: the buffer has exactly one writer, and it writes once, before
// `GATE_UNITS` is published with a release store; every reader reaches it
// through an acquire load of that length. So a reader and the writer can never
// overlap, which is the same argument `ExclusionTable` makes for its own cell —
// with a different event (that one is filled before `FltStartFiltering`, this
// one is filled at most once ever) leading to the same conclusion.
unsafe impl Sync for GateDirectory {}

static GATE_DIRECTORY: GateDirectory = GateDirectory::new();

/// Whether this driver is stripping handle rights. Set by
/// [`CONFIG_PROTECT_HANDLES`](av_driver_proto::CONFIG_PROTECT_HANDLES).
///
/// The registration is unconditional and this is not, and the difference is the
/// point: `ObRegisterCallbacks` can be refused by the kernel and cannot be
/// retried cheaply, while whether to *use* the callbacks is a policy the service
/// owns and can change at any time. A driver that folded the two together would
/// have to fail the load over a policy choice, or ignore the policy.
///
/// False until a service asks. A machine running the driver with no service is a
/// machine where the thing being protected is not running either.
static HANDLES_PROTECTED: AtomicBool = AtomicBool::new(false);

// The counters, one index each. `DriverStats`'s field order is this order,
// which is what makes `stats()` a straight read rather than a mapping that
// could drift away from the protocol.
//
// `C_BLOCKED_EXECUTIONS` has no `bump` since 2026-10-15, and that is the whole
// of what changed about it: the create gate was the only thing that could have
// moved it, the create gate was never answered with a refusal, and it no longer
// asks. Kept rather than deleted because the index is the protocol's and
// because removing it would shift every counter below by one -- which is the
// silent misread the assertion at the bottom of this file exists to prevent.
const C_BLOCKED_EXECUTIONS: usize = 0;
const C_BLOCKED_WRITES: usize = 1;
const C_IMAGES_BLOCKED: usize = 2;
const C_ALLOWED: usize = 3;
const C_TIMED_OUT: usize = 4;
const C_EXCLUDED: usize = 5;
const C_UNRESOLVED_VOLUME: usize = 6;
const C_OVERSIZE_PATH: usize = 7;

/// The counter array. One atomic each, so that a write from a callback on one
/// CPU cannot lose a concurrent write from another -- which a `static mut`
/// incremented field by field would.
static COUNTERS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

/// Add one to a counter. Relaxed ordering: these are counts, nothing is ordered
/// against them, and no decision reads them.
fn bump(index: usize) {
    COUNTERS[index].fetch_add(1, Ordering::Relaxed);
}

/// The driver's counters, which is what the status IOCTL returns.
///
/// Public because the service reads it, and a function rather than a static so
/// that the eight reads happen in one place. They are not a consistent snapshot
/// -- the counters are written from many threads -- but the set of eight is at
/// least written down once, where the protocol's field order can be checked
/// against it.
pub fn stats() -> DriverStats {
    let c = |index: usize| COUNTERS[index].load(Ordering::Relaxed);
    DriverStats {
        blocked_executions: c(C_BLOCKED_EXECUTIONS),
        blocked_writes: c(C_BLOCKED_WRITES),
        images_blocked: c(C_IMAGES_BLOCKED),
        allowed: c(C_ALLOWED),
        timed_out: c(C_TIMED_OUT),
        excluded: c(C_EXCLUDED),
        unresolved_volume: c(C_UNRESOLVED_VOLUME),
        oversize_path: c(C_OVERSIZE_PATH),
    }
}

/// The volume-name cache the path normaliser borrows.
///
/// The cache's own documentation carries the argument for its interior
/// mutability; the `Sync` below reduces to the same two facts -- a slot is
/// published by a release `fetch_or` that a reader acquires, and the slot index
/// comes from an atomic counter.
static VOLUMES: flt::VolumeCache = flt::VolumeCache::new();

// SAFETY: the cache's only interior mutation goes through the raw pointer that
// `prime` derives, and a slot becomes readable only after a release `fetch_or`
// on `ready` that a reader reaches through an acquire load. Nothing shared is
// mutated without that ordering, which is what `Sync` requires.
unsafe impl Sync for flt::VolumeCache {}

/// The exclusion table, in the `UnsafeCell` that lets it be a `static` and
/// still be filled during start-up.
struct ExclusionTable(UnsafeCell<FixedExclusionTable<MAX_EXCLUSIONS, MAX_EXCLUSION_UNITS>>);

impl ExclusionTable {
    /// An empty table.
    const fn new() -> Self {
        Self(UnsafeCell::new(FixedExclusionTable::new()))
    }

    /// Add one entry, encoding it from ASCII.
    ///
    /// # Safety
    ///
    /// Must run before `FltStartFiltering`; see [`Self::matches`].
    unsafe fn insert(&self, ascii: &[u8]) -> Result<(), ExclusionError> {
        let mut buffer = [0u16; MAX_EXCLUSION_UNITS];
        let n = encode_ascii(ascii, &mut buffer);
        // SAFETY: the caller's contract is that this runs before
        // `FltStartFiltering`, so no callback can hold a borrow of the table.
        let table = unsafe { &mut *self.0.get() };
        table.insert(&buffer[..n])
    }

    /// Whether `path` is excluded.
    fn matches(&self, path: &[u16]) -> bool {
        // SAFETY: the table is written only from `DriverEntry`, before
        // `FltStartFiltering`, and read only from callbacks, all of which the
        // filter manager dispatches after start-up. So no `&mut` to it can
        // exist while this shared borrow is live.
        unsafe { &*self.0.get() }.is_excluded(path)
    }
}

// SAFETY: as for the volume cache. The write happens in `DriverEntry` before
// `FltStartFiltering`; every read is from a callback dispatched after it.
unsafe impl Sync for ExclusionTable {}

static EXCLUSIONS: ExclusionTable = ExclusionTable::new();

/// Paths that are never sent for a decision, so that a service which has
/// stopped answering cannot stop the machine from starting, and so that the
/// product cannot end up asking itself about the files it just wrote.
///
/// The list itself lives in [`av_driver_proto::exclusions::BUILT_IN`] rather
/// than here, and that is the point of it being over there: it names directories
/// that belong to the product, the product's own paths are spelled in
/// `av_core::paths`, and a copy of those spellings kept next to the driver is a
/// copy that can drift. It drifted once — the entry said `Wenle` where the
/// product says `WenleAV` — and the entry then excluded nothing at all.
///
/// The exclusion table is read-only after start-up, because writing it from a
/// callback would need a lock on the decision path.
const BUILT_IN_EXCLUSIONS: [&str; 4] = av_driver_proto::exclusions::BUILT_IN;

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------

/// `DriverEntry`, named by the linker's `/ENTRY:DriverEntry` and called by the
/// loader. The export below is what gives that `/ENTRY:` a symbol to name.
///
/// The driver object handed here is left alone beyond being passed to
/// `FltRegisterFilter`. A minifilter's teardown belongs to `FLT_REGISTRATION`'s
/// `FilterUnloadCallback` -- `filter_unload` below -- and none of the three
/// Microsoft minifilter samples this driver was compared against (`avscan`,
/// `minispy`, `scanner`) installs a `DriverObject->DriverUnload` either.
/// Whether relying on the filter manager alone is enough to let this image be
/// unloaded is one of the open questions in this file's header: the one unload
/// attempted so far bugchecked the machine.
///
/// # Safety
///
/// Called once by the loader, with the driver object being loaded and the path
/// its service key was read from. Both are valid for the whole call.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: wdk_sys::PDRIVER_OBJECT,
    _registry_path: wdk_sys::PCUNICODE_STRING,
) -> wdk_sys::NTSTATUS {
    // SAFETY: `driver` is the value the framework passed, which is what
    // `FltRegisterFilter` needs to associate the filter with this driver, and
    // `REGISTRATION` is a `static` that outlives the call.
    let status = unsafe {
        flt::FltRegisterFilter(
            driver.cast::<c_void>(),
            core::ptr::addr_of!(REGISTRATION.0),
            FILTER.as_ptr(),
        )
    };
    if status != STATUS_SUCCESS {
        // A filter that failed to register has nothing registered, so there is
        // nothing to undo.
        return status;
    }
    // SAFETY: the call above succeeded, so it wrote a filter into this slot.
    let filter = FILTER.load(Ordering::Acquire);

    // The exclusions go in here, between registration and start. That window is
    // the whole argument for `ExclusionTable`'s `UnsafeCell`: after
    // `FltStartFiltering` there is no moment at which a callback could observe
    // a half-filled table.
    for entry in BUILT_IN_EXCLUSIONS {
        // SAFETY: this runs before `FltStartFiltering`, which is the contract.
        // An entry the table refuses -- too long, not normalised -- is dropped
        // rather than truncated, because a truncated exclusion matches paths
        // the list did not name.
        let _ = unsafe { EXCLUSIONS.insert(entry.as_bytes()) };
    }

    // All three registrations come before the port, and the order is not
    // stylistic.
    // `port_connect` reports what each of them answered, and a service is free
    // to connect the instant `FltCreateCommunicationPort` returns -- so a port
    // created first is a window in which a service is told
    // [`STATUS_REGISTRATION_UNATTEMPTED`] for a registration that is about to
    // succeed. Doing them first removes the window rather than narrowing it.
    //
    // No failure fails the load. The minifilter is the part that refuses
    // anything: process-start notifications are how the memory monitor learns a
    // process exists, object callbacks are how this product keeps a handle to
    // itself from being turned into a termination, and the registry callback is
    // how a key creation or a value write is seen at all — and a machine without
    // any of the three still scans and still blocks. Refusing to protect a
    // system because it could not protect itself is the worse of the two
    // failures, and it is the one that is invisible: the product would be absent
    // rather than degraded.
    //
    // What changed on 2026-10-09 is that no value is *thrown away* any more.
    // Every body exists now, and a body that never runs looks exactly like a
    // machine on which nothing happens — so each answer is stored here and sent
    // to the service when it connects.

    // SAFETY: `ObRegisterCallbacks` requires `PASSIVE_LEVEL` (it is documented
    // `_IRQL_requires_max_(PASSIVE_LEVEL)`), which `DriverEntry` runs at, and it
    // reaches nothing this driver owns. Returns the status and, on success, the
    // handle the unregister call will need.
    let ob_status = unsafe { register_object_callbacks() };
    OB_STATUS.store(ob_status, Ordering::Release);

    // SAFETY: `process_notify` has the `PCREATE_PROCESS_NOTIFY_ROUTINE_EX` type
    // `wdk-sys` declares for it. The trailing `0` is `FALSE`: register.
    // `BOOLEAN` is a `UCHAR`, not a Rust `bool`, which is why it is a number.
    let notify_status =
        unsafe { wdk_sys::ntddk::PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 0u8) };
    PROCESS_NOTIFY_STATUS.store(notify_status, Ordering::Release);

    // SAFETY: `CmRegisterCallbackEx` is `_IRQL_requires_max_(APC_LEVEL)`, which
    // `DriverEntry` satisfies, and `driver` is what the loader passed --
    // the kernel keeps the association for the life of the registration.
    // Neither failure fails the load, on the same reasoning as the two above.
    let registry_status = unsafe { register_registry_callback(driver.cast::<c_void>()) };
    REGISTRY_STATUS.store(registry_status, Ordering::Release);

    // The port is created before filtering starts, so that no operation can
    // ever be decided by a driver with nowhere to ask.
    // SAFETY: `filter` is registered, and this runs at `PASSIVE_LEVEL` inside
    // `DriverEntry`.
    let port = unsafe { create_port(filter) };
    if port.is_null() {
        // Failing the load is the honest outcome. A filter that started without
        // a port would allow every execution while reporting itself as
        // installed, which is worse than a driver that visibly did not load: an
        // operator who believes a filter is enforcing is an operator who has
        // stopped looking.
        // SAFETY: both registrations were attempted above and neither callback
        // can be running -- filtering has not started.
        unsafe { unregister_notifications() };
        // SAFETY: `filter` is registered and no callback has run.
        unsafe { flt::FltUnregisterFilter(filter) };
        FILTER.store(core::ptr::null_mut(), Ordering::Release);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // SAFETY: `filter` is the registered filter. This is the call after which
    // callbacks begin arriving -- including the instance-setup callbacks that
    // fill the volume cache.
    let status = unsafe { flt::FltStartFiltering(filter) };
    if status != STATUS_SUCCESS {
        // Registered, ported and notified but not started. `FltStartFiltering`
        // is where a minifilter begins receiving operations, so nothing of this
        // driver's has run and nothing is holding a decision.
        let port = SERVER_PORT.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !port.is_null() {
            // SAFETY: `port` came out of `SERVER_PORT` and is closed once.
            unsafe { flt::FltCloseCommunicationPort(port) };
        }
        // SAFETY: as for the failure above.
        unsafe { unregister_notifications() };
        // SAFETY: `filter` is the registered filter and no callback has run.
        unsafe { flt::FltUnregisterFilter(filter) };
        FILTER.store(core::ptr::null_mut(), Ordering::Release);
        return status;
    }

    STATUS_SUCCESS
}

/// Undo the three registrations `driver_entry` makes, in the reverse order.
///
/// Shared by the unload callback and both of `driver_entry`'s failure paths,
/// which is the reason it exists: the unload path inlined the process-notify
/// removal and the failure paths did not do it at all, so a load that failed
/// after registering left the routine registered. A process notification
/// arriving after `FltUnregisterFilter` has returned is a callback into a filter
/// that is gone.
///
/// The first two calls are unconditional and neither result is checked.
/// Removing a registration that was never made returns an error status rather
/// than faulting, which is the case when the registration itself failed; and a
/// registration that succeeded is one this has to remove regardless of what the
/// other one did. The third is skipped when no cookie was stored, because
/// `CmUnRegisterCallback` takes the cookie and there is no harmless value to
/// pass it for a registration that was never made.
///
/// # Safety
///
/// Must not run while a callback of any of the three registrations can be
/// executing. All three unregister calls block until the callbacks they are
/// removing have returned, so each half is safe wherever it is called; the
/// process half's guarantee is `PsSetCreateProcessNotifyRoutineEx`'s rather than
/// blocking's, and both callers here satisfy it — `DriverEntry` has not started
/// filtering, and `FltUnregisterFilter` does not return until it has drained
/// this filter's callbacks.
unsafe fn unregister_notifications() {
    let handle = OB_HANDLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        // SAFETY: `handle` came out of `OB_HANDLE`, which only
        // `register_object_callbacks` writes, and the swap above is what makes
        // this the single unregister of it.
        unsafe { wdk_sys::ntddk::ObUnRegisterCallbacks(handle) };
    }
    // SAFETY: this removes the routine `driver_entry` registered. The trailing
    // `1` is `TRUE`: remove.
    unsafe {
        let _ = wdk_sys::ntddk::PsSetCreateProcessNotifyRoutineEx(Some(process_notify), 1u8);
    }
    // The registry callback goes last and only when one was made: the flag and
    // the cookie are the pair that says so, and `CmUnRegisterCallback` waits
    // for callbacks already running on other threads, so nothing of ours can be
    // inside `registry_notify` when this returns.
    if REGISTRY_REGISTERED.swap(false, Ordering::AcqRel) {
        let cookie = REGISTRY_COOKIE.load(Ordering::Acquire);
        // SAFETY: `cookie` is the value `CmRegisterCallbackEx` returned and this
        // is its single unregister, which the flag swap above guarantees.
        unsafe {
            let _ = flt::CmUnRegisterCallback(cookie);
        }
    }
}

/// Register the registry callback, and keep the cookie that undoes it.
///
/// Split out of `driver_entry` for the reason [`register_object_callbacks`] is:
/// the altitude string has to be alive for the call, and a `static` a callee
/// could keep a pointer into is not something this file will hand out. The
/// configuration manager copies out of it.
///
/// The altitude is in the **minifilter** altitude numbering for the same reason
/// `OB_CALLBACK_REGISTRATION`'s is — the two registrations share the namespace,
/// and the published table is the only authority for it — so the value is one
/// above [`OB_ALTITUDE`]'s and inside the same `FSFilter Anti-Virus` band.
///
/// # Safety
///
/// Must run at `PASSIVE_LEVEL`, and `driver` must be the `PDRIVER_OBJECT` the
/// loader passed to `DriverEntry`, which the kernel keeps for the life of the
/// registration.
unsafe fn register_registry_callback(driver: *mut c_void) -> i32 {
    let mut altitude_units = [0u16; 16];
    let length = encode_ascii(REGISTRY_ALTITUDE, &mut altitude_units);
    let altitude = flt::UnicodeString {
        // Bytes, not units, as in `register_object_callbacks`.
        length: (length * 2) as u16,
        maximum_length: (length * 2) as u16,
        pad: 0,
        buffer: altitude_units.as_mut_ptr(),
    };

    let mut cookie: i64 = 0;
    // SAFETY: `altitude` and `altitude_units` are alive for the call and are
    // only read by it; `driver` is the value the loader passed; `cookie` is a
    // local out-parameter; `reserved` is documented as null.
    let status = unsafe {
        flt::CmRegisterCallbackEx(
            registry_notify,
            &altitude,
            driver,
            core::ptr::null_mut(),
            &mut cookie,
            core::ptr::null_mut(),
        )
    };
    if status == STATUS_SUCCESS {
        // The cookie first, then the flag: a reader that sees the flag set sees
        // the cookie the unregister call needs.
        REGISTRY_COOKIE.store(cookie, Ordering::Release);
        REGISTRY_REGISTERED.store(true, Ordering::Release);
    }
    status
}

/// The registry callback: name the change, hand it to a worker, refuse nothing.
///
/// Five `REG_NOTIFY_CLASS`es are reported — key created, key deleted, value set,
/// value deleted, key renamed — and every other class returns immediately. The
/// set is what persistence and ransomware-relevant registry activity are made
/// of; the rest of the registers (queries, enumerations, security changes) are
/// volume rather than signal, and this callback sees all of it on a running
/// machine.
///
/// # What it costs with no service connected
///
/// One atomic load: the class is not decoded and no path is resolved until a
/// service is there to receive the event. That check is why a machine with the
/// driver loaded and the service stopped pays nothing for this registration.
///
/// # Why it never refuses
///
/// A registry callback *can* fail an operation, and that is how a security
/// product turns a machine into one that cannot boot. This one returns success
/// on every path, the same boundary the rename and delete telemetry draws.
///
/// # Safety
///
/// Called by the configuration manager with the `EX_CALLBACK_FUNCTION`
/// signature: `argument1` is the `REG_NOTIFY_CLASS` as a pointer value and
/// `argument2` is that class's information block, both valid only for the
/// duration of this call. Everything read out of them is copied.
unsafe extern "system" fn registry_notify(
    _callback_context: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) -> flt::NtStatus {
    // Registry callbacks run at `PASSIVE_LEVEL`, and this is where that becomes
    // a checked fact rather than an assumption: `CmCallbackGetKeyObjectIDEx`
    // is capped at `APC_LEVEL`.
    if !flt::may_block_for_the_service() {
        return STATUS_SUCCESS;
    }
    // Nobody to tell. See the cost note above.
    if CLIENT_PORT.load(Ordering::Acquire).is_null() {
        return STATUS_SUCCESS;
    }

    // `Argument1` carries the class as a value, so `RegNtDeleteKey` -- which is
    // zero -- arrives as a null pointer. That is why the constants here are
    // `i32` and why this cast, rather than a null check, is the decode.
    let class = argument1 as usize as i32;
    let mut path = [0u16; MAX_PATH_UNITS];

    let (detail, units, value) = match class {
        flt::REG_NT_PRE_CREATE_KEY_EX => {
            let info = argument2.cast::<flt::RegCreateKeyInformation>();
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            // SAFETY: `argument2` is this class's `REG_CREATE_KEY_INFORMATION`
            // (or `_V1`, whose `CompleteName` is at the same offset), and it is
            // valid for the duration of the call.
            let name = unsafe { (*info).complete_name };
            // The block already carries the full path, so this class needs no
            // object lookup -- and does not have one: the key does not exist
            // yet, so there is no object to ask about.
            match unsafe { copy_counted_string(name, &mut path) } {
                Some(units) => (EventAction::REGISTRY_KEY_CREATED, units, None),
                None => return STATUS_SUCCESS,
            }
        }
        flt::REG_NT_DELETE_KEY => {
            let info = argument2.cast::<flt::RegDeleteKeyInformation>();
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            // SAFETY: as above, for this class's structure.
            let object = unsafe { (*info).object };
            match unsafe { key_object_path(object, &mut path) } {
                Some(units) => (EventAction::REGISTRY_KEY_DELETED, units, None),
                None => return STATUS_SUCCESS,
            }
        }
        flt::REG_NT_RENAME_KEY => {
            let info = argument2.cast::<flt::RegRenameKeyInformation>();
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            let object = unsafe { (*info).object };
            // The *object's* path, not `NewName`: a rename's new name is
            // relative to the parent key, and a relative name reported as
            // though it were a path is a path to something else. The key that
            // is being renamed is the fact this event can state exactly.
            match unsafe { key_object_path(object, &mut path) } {
                Some(units) => (EventAction::REGISTRY_KEY_RENAMED, units, None),
                None => return STATUS_SUCCESS,
            }
        }
        flt::REG_NT_SET_VALUE_KEY => {
            let info = argument2.cast::<flt::RegSetValueKeyInformation>();
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            // SAFETY: `argument2` is this class's structure.
            let (object, value_name, kind, data, bytes) = unsafe {
                (
                    (*info).object,
                    (*info).value_name,
                    (*info).value_type,
                    (*info).data,
                    (*info).data_size,
                )
            };
            let units = match unsafe { named_value_path(object, value_name, &mut path) } {
                Some(units) => units,
                None => return STATUS_SUCCESS,
            };
            // Only the string types are carried. A `REG_BINARY` or `REG_DWORD`
            // value has no text, and rendering its bytes as text would be a
            // rule matching against a representation this driver invented. The
            // event still says the value was written; it says nothing about
            // what was written.
            let value = if matches!(kind, flt::REG_SZ | flt::REG_EXPAND_SZ | flt::REG_MULTI_SZ)
                && !data.is_null()
                && bytes != 0
            {
                Some(RegistryValue {
                    kind,
                    data: data.cast::<u16>(),
                    bytes,
                })
            } else {
                None
            };
            (EventAction::REGISTRY_VALUE_SET, units, value)
        }
        flt::REG_NT_DELETE_VALUE_KEY => {
            let info = argument2.cast::<flt::RegDeleteValueKeyInformation>();
            if info.is_null() {
                return STATUS_SUCCESS;
            }
            // SAFETY: as above.
            let (object, value_name) = unsafe { ((*info).object, (*info).value_name) };
            match unsafe { named_value_path(object, value_name, &mut path) } {
                Some(units) => (EventAction::REGISTRY_VALUE_DELETED, units, None),
                None => return STATUS_SUCCESS,
            }
        }
        // Every other class: queries, enumerations, security, notifications.
        // Volume rather than signal, and each one is a key name resolved for
        // nothing if it were reported.
        _ => return STATUS_SUCCESS,
    };

    // SAFETY: no arguments, and `ntddk.h` 11385 declares it without a pointer
    // parameter -- unlike the filter-manager `FltGetRequestorProcess`, which is
    // what faulted on 2026-09-27 and is not used here. The header's return type
    // is `HANDLE` and the value is the identifier, so it is widened the way the
    // write path widens it.
    let process_id = unsafe { flt::PsGetCurrentProcessId() } as usize as u32;
    // `value` borrows the caller's buffer, which is valid only while this
    // callback runs. `defer_registry_event` copies it before returning, which
    // is what makes the report possible at all: by the time a worker thread
    // runs, the configuration manager has finished with the buffer.
    defer_registry_event(detail, process_id, &path[..units], value);
    STATUS_SUCCESS
}

/// Where a registry value's data is, and what type it is.
///
/// Live only for the duration of the callback that supplied it. The type is
/// kept because `REG_MULTI_SZ`'s data is a different shape from `REG_SZ`'s —
/// NUL-separated strings rather than one — and the conversion happens in
/// [`defer_registry_event`], which reads the data the way its type says.
#[derive(Clone, Copy)]
struct RegistryValue {
    /// One of `flt::REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`.
    kind: u32,
    /// The data, in UTF-16 for every type that reaches here.
    data: *const u16,
    /// The length in **bytes**, as the caller stated it.
    bytes: u32,
}

/// Copy a counted string the kernel handed over into `out`.
///
/// `None` when the pointer is null, the string names nothing, or it does not
/// fit — a truncated key path names a different key, which is a worse answer
/// than no event.
///
/// # Safety
///
/// `name`, when non-null, must point to a live counted string for the duration
/// of the call.
unsafe fn copy_counted_string(name: *const flt::UnicodeString, out: &mut [u16]) -> Option<usize> {
    if name.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let units = unsafe { (*name).as_units() };
    if units.is_empty() || units.len() > out.len() {
        return None;
    }
    out[..units.len()].copy_from_slice(units);
    Some(units.len())
}

/// Resolve a key object's full path through `CmCallbackGetKeyObjectIDEx`.
///
/// The only way to name a key from inside a callback: the object is opaque and
/// the information blocks carry no path except create-key's `CompleteName`.
///
/// # Safety
///
/// `object` must be the key object from an information block whose callback is
/// running, and this must run at `APC_LEVEL` or below.
unsafe fn key_object_path(object: *mut c_void, out: &mut [u16]) -> Option<usize> {
    if object.is_null() {
        return None;
    }
    // The cookie the registration returned. Read into a local: the call takes a
    // pointer, and the static's address is not something to hand a callee.
    let cookie = REGISTRY_COOKIE.load(Ordering::Acquire);
    let mut object_id: usize = 0;
    let mut name: *mut flt::UnicodeString = core::ptr::null_mut();
    // SAFETY: `object` is the caller's live key object, the out-parameters are
    // locals, and `flags` must be zero.
    let status =
        unsafe { flt::CmCallbackGetKeyObjectIDEx(&cookie, object, &mut object_id, &mut name, 0) };
    if status != STATUS_SUCCESS || name.is_null() {
        return None;
    }
    // SAFETY: the call above succeeded, so `name` points to a counted string it
    // allocated.
    let units = unsafe { copy_counted_string(name, out) };
    // SAFETY: allocated by the call above and released exactly once, here,
    // whatever `copy_counted_string` made of it.
    unsafe { flt::CmCallbackReleaseKeyObjectIDEx(name) };
    units
}

/// A key object's path with the value name appended: `key\Value`.
///
/// A value with an empty name is the key's default value, and `regedit` spells
/// that `(Default)`. Here it is reported as the key path with nothing appended,
/// because the registry has no name for the default value and inventing one
/// would be a string no rule could match against a real key.
///
/// # Safety
///
/// As for [`key_object_path`], and `value_name` must be the counted string from
/// the running callback's information block.
unsafe fn named_value_path(
    object: *mut c_void,
    value_name: *const flt::UnicodeString,
    out: &mut [u16],
) -> Option<usize> {
    // SAFETY: the caller's contract, forwarded.
    let used = unsafe { key_object_path(object, out) }?;
    if value_name.is_null() {
        return Some(used);
    }
    // SAFETY: the caller's contract.
    let value = unsafe { (*value_name).as_units() };
    if value.is_empty() {
        return Some(used);
    }
    if used + 1 + value.len() > out.len() {
        return None;
    }
    out[used] = u16::from(b'\\');
    out[used + 1..used + 1 + value.len()].copy_from_slice(value);
    Some(used + 1 + value.len())
}

/// Copy a registry value's data into `out` as text, and say whether it fit.
///
/// Truncation rather than refusal, which is the opposite of what
/// [`copy_counted_string`] does with a path: half a path names a different key,
/// while half a value still begins with the `%TEMP%` a rule is looking for.
/// The caller records that the prefix is a prefix; see
/// [`av_driver_proto::wire::EVENT_VALUE_TRUNCATED`].
///
/// The three string types are the only ones that reach here — the caller has
/// already refused the binary ones — and `REG_MULTI_SZ` is converted from
/// NUL-separated strings to `;`-separated ones so that the whole list survives
/// into a field that cannot hold a NUL.
///
/// # Safety
///
/// `value.data` must be valid for `value.bytes` bytes and this must run while
/// the callback that supplied it is still on the stack.
unsafe fn copy_registry_value(value: RegistryValue, out: &mut [u16]) -> (usize, bool) {
    // Bytes to units, rounded down: an odd length cannot be a whole UTF-16
    // unit, and reading the half one would be reading past the caller's
    // buffer's meaningful part.
    let available = (value.bytes as usize) / 2;
    let used = available.min(out.len());
    if used == 0 {
        return (0, false);
    }
    // SAFETY: the caller's contract, and `used <= available` by the line above.
    unsafe {
        core::ptr::copy_nonoverlapping(value.data, out.as_mut_ptr(), used);
    }
    // `REG_MULTI_SZ`'s separators become `;`, and its terminator disappears
    // with the other trailing zeros below.
    let mut units = used;
    if value.kind == flt::REG_MULTI_SZ {
        for unit in &mut out[..units] {
            if *unit == 0 {
                *unit = u16::from(b';');
            }
        }
    }
    // The registry's strings end with a NUL that is not part of the value; the
    // protocol's field is a counted string and does not carry one.
    while units > 0 && out[units - 1] == 0 {
        units -= 1;
    }
    // A `REG_MULTI_SZ`'s last separator is where its terminator was.
    if value.kind == flt::REG_MULTI_SZ {
        while units > 0 && out[units - 1] == u16::from(b';') {
            units -= 1;
        }
    }
    (units, available > out.len())
}

/// Register the object callbacks that protect this product's own processes.
///
/// Returns the `NTSTATUS` `ObRegisterCallbacks` gave and stores the handle on
/// success. Split out of `driver_entry` for the same reason `create_port` is: an
/// altitude string and an array of two registrations have to be alive for the
/// call and must not be `static`s the callee could keep pointers into. The
/// filter manager copies out of both.
///
/// # Safety
///
/// Must run at `PASSIVE_LEVEL`, which is what the call requires.
unsafe fn register_object_callbacks() -> i32 {
    // The altitude, in the minifilter altitude numbering. See [`OB_ALTITUDE`].
    //
    // `wdk_sys::UNICODE_STRING` and not this crate's `flt::UnicodeString`, even
    // though the two have the same layout and `flt.rs` pins that layout: this
    // structure is the *bindings'* type, declared by `OB_CALLBACK_REGISTRATION`,
    // and the two are different Rust types. They agree in size (16) and in
    // `Buffer`'s offset (8) because both are `#repr(C)` over the same C
    // structure, which is the fact that makes the local `altitude_units` array
    // below readable by the kernel at all.
    let mut altitude_units = [0u16; 16];
    let length = encode_ascii(OB_ALTITUDE, &mut altitude_units);
    let altitude = wdk_sys::UNICODE_STRING {
        // Bytes, not units. The `* 2` is `Length`'s definition rather than a
        // convenience.
        Length: (length * 2) as u16,
        MaximumLength: (length * 2) as u16,
        Buffer: altitude_units.as_mut_ptr(),
    };

    // One entry per object type, both for the same operation: an open that
    // creates a handle. `PostOperation` is null on both -- there is nothing to
    // undo, and a post-operation here would be a second callback on a path that
    // only ever removes bits.
    //
    // A **value**, not a reference: `ObjectType` is `*mut POBJECT_TYPE` and
    // `PsProcessType` is itself a `*mut POBJECT_TYPE` (`constants.rs`, generated
    // from `wdm.h`), so this is the object type rather than the address of a
    // variable holding one. Passing `addr_of!` here would hand the kernel a
    // pointer to the slot, which is a different object -- and one it would
    // dereference as a type.
    let mut operations = [
        wdk_sys::OB_OPERATION_REGISTRATION {
            ObjectType: unsafe { wdk_sys::PsProcessType },
            Operations: wdk_sys::OB_OPERATION_HANDLE_CREATE,
            PreOperation: Some(protect_process_handle),
            PostOperation: None,
        },
        wdk_sys::OB_OPERATION_REGISTRATION {
            ObjectType: unsafe { wdk_sys::PsThreadType },
            Operations: wdk_sys::OB_OPERATION_HANDLE_CREATE,
            PreOperation: Some(protect_thread_handle),
            PostOperation: None,
        },
    ];

    let mut registration = wdk_sys::OB_CALLBACK_REGISTRATION {
        // `OB_FLT_REGISTRATION_VERSION`, which is `0x0100`. The field is a
        // `USHORT` and the constant the bindings declare is a `u32`, which is
        // why this is a cast rather than the constant itself.
        Version: wdk_sys::OB_FLT_REGISTRATION_VERSION as u16,
        // Two, and it is the count of the array below rather than of the object
        // types this driver cares about: `ObRegisterCallbacks` reads exactly
        // this many entries from `OperationRegistration`.
        OperationRegistrationCount: operations.len() as u16,
        Altitude: altitude,
        // No context. Both callbacks read nothing from the registration, and a
        // context would be a pointer this driver would have to keep alive for
        // the life of the registration for no benefit.
        RegistrationContext: core::ptr::null_mut(),
        OperationRegistration: operations.as_mut_ptr(),
    };

    let mut handle: wdk_sys::PVOID = core::ptr::null_mut();
    // SAFETY: `registration` names a counted string over a live local buffer and
    // an array of two entries over a live local array, both of which outlive the
    // call. The out-parameter is a live local. The callbacks have the type
    // `POB_PRE_OPERATION_CALLBACK` declares.
    let status =
        unsafe { wdk_sys::ntddk::ObRegisterCallbacks(&mut registration, &mut handle) };

    if status == STATUS_SUCCESS && !handle.is_null() {
        OB_HANDLE.store(handle, Ordering::Release);
    }
    status
}

// ---------------------------------------------------------------------------
// The registration
// ---------------------------------------------------------------------------

/// `FLT_REGISTRATION` plus the operations array it points at, in one static so
/// that the pointer between them is to a `static` rather than to a temporary
/// the filter manager would outlive.
struct Registration(FltRegistration);

// SAFETY: the filter manager reads this structure and the array it points at.
// Both are `static`s that are never written after their initialiser, and the
// raw pointers inside are the addresses of those statics.
unsafe impl Sync for Registration {}

static REGISTRATION: Registration = Registration(FltRegistration {
    size: core::mem::size_of::<FltRegistration>() as u16,
    version: FLT_REGISTRATION_VERSION,
    flags: 0,
    context_registration: core::ptr::null(),
    operation_registration: core::ptr::addr_of!(OPERATIONS.0).cast::<FltOperationRegistration>(),
    filter_unload_callback: Some(filter_unload),
    instance_setup_callback: Some(instance_setup),
    unused_tail: [core::ptr::null(); 9],
});

/// The operation table, terminated by [`IRP_MJ_OPERATION_END`].
struct Operations([FltOperationRegistration; 5]);

// SAFETY: as for `Registration`: a `static`, never written, read only by the
// filter manager.
unsafe impl Sync for Operations {}

/// How many entries above the terminator.
///
/// Named rather than repeated as a literal, because the checks at the end of
/// this file walk the table and every one of them has been written with the
/// count inline at least once. A count that is wrong by one is not a compile
/// error -- it is a loop that stops before the last entry, and an entry nothing
/// asserts anything about.
const REGISTERED_OPERATIONS: usize = 4;

/// The entries themselves, as a `const` so that the checks at the end of
/// this file can read them -- a `static` cannot be read in a const context.
///
/// `OPERATIONS` below is built from this rather than from a second literal. The
/// invariants being checked are about these exact values, and a check against a
/// copy of them would go on passing while the table drifted.
const OPERATION_TABLE: [FltOperationRegistration; REGISTERED_OPERATIONS + 1] = [
    FltOperationRegistration {
        major_function: IRP_MJ_CREATE,
        flags: 0,
        pre_operation: Some(create_pre_operation),
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
    // `SKIP_PAGING_IO` on this one and the next, and it is load-bearing rather
    // than an optimisation: both callbacks reach an API that the header marks
    // `_IRQL_requires_max_(APC_LEVEL)`, and paging I/O arrives at
    // `DISPATCH_LEVEL`. See `flt::FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`.
    //
    // It is not sufficient on its own -- `create_pre_operation` is exempt only
    // because a CREATE is always `PASSIVE_LEVEL` -- so both callbacks check the
    // IRQL as well. The flag removes the common case; the check removes the rest.
    FltOperationRegistration {
        major_function: IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        flags: flt::FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        pre_operation: Some(section_pre_operation),
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
    // Both halves of the write path, and they are two different jobs.
    //
    // The **pre**-operation is the narrow write gate: it refuses a write to one
    // of this product's own files, in the kernel, without asking anyone. Added
    // 2026-10-09 (C3). On the common path it reads two atomics and returns
    // [`flt::FLT_PREOP_SUCCESS_WITH_CALLBACK`] -- **not** `..._NO_CALLBACK`,
    // which is what this comment said until 2026-10-11 and which would have
    // silently suppressed the post-operation below, stopping every
    // `FileWritten` event on the machine while the gate went on working
    // perfectly. So a machine with the gate disarmed -- which is every machine
    // until a service connects and asks for it -- pays for one relaxed load in
    // the pre-operation and the post-operation it was already paying for, and
    // nothing else.
    //
    // The **post**-operation is the tamper *detector* that was already here: it
    // observes a write that happened and defers an event. It cannot refuse,
    // which is exactly why the gate is a separate callback rather than a branch
    // inside it -- a post-operation runs after the write.
    //
    // A post-operation without a pre-operation used to be how this entry read.
    // The comment said that was how a write is observed without paying for a
    // callback on the way in, which was true and is no longer the design: the
    // gate cannot be built out of observation.
    FltOperationRegistration {
        major_function: IRP_MJ_WRITE,
        flags: flt::FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        pre_operation: Some(write_pre_operation),
        post_operation: Some(write_post_operation),
        reserved1: core::ptr::null_mut(),
    },
    // Rename and delete telemetry, added 2026-10-18. A pre-operation only: it
    // observes and never refuses, so there is nothing for a post-operation to
    // add, and [`FLT_PREOP_SUCCESS_NO_CALLBACK`] is the correct return for the
    // same reason it would be wrong on the write entry above.
    //
    // `SKIP_PAGING_IO` for the reason the two entries above carry it: the
    // callback resolves a file name, which is `_IRQL_requires_max_(APC_LEVEL)`,
    // and it checks the IRQL itself as well.
    FltOperationRegistration {
        major_function: IRP_MJ_SET_INFORMATION,
        flags: flt::FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        pre_operation: Some(set_information_pre_operation),
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
    // The terminator, and it has to be this major function. This entry read
    // `major_function: 0` until 2026-09-26, with a comment asserting that a null
    // callback pair is what marks the end of the array. `fltKernel.h` marks the
    // end with `IRP_MJ_OPERATION_END` and nothing else, so a zero here is not a
    // terminator -- it is `IRP_MJ_CREATE` (0x00), an operation entry [0] has
    // already registered.
    //
    // The cost was measured in the test VM: `fltmc attach WenleAvFilter C:`
    // failed with `ERROR_FLT_DUPLICATE_ENTRY` (0x801F000D, the HRESULT form of
    // `STATUS_FLT_DUPLICATE_ENTRY`), `fltmc instances` reported no instances,
    // and the driver was attached to nothing while every other symptom said it
    // had loaded normally. See `flt::IRP_MJ_OPERATION_END` for the full account,
    // and the test below for what keeps it fixed.
    FltOperationRegistration {
        major_function: IRP_MJ_OPERATION_END,
        flags: 0,
        pre_operation: None,
        post_operation: None,
        reserved1: core::ptr::null_mut(),
    },
];

static OPERATIONS: Operations = Operations(OPERATION_TABLE);

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Resolve a volume's DOS name and remember it.
///
/// This is where the volume cache is filled, and the reason is on
/// [`flt::VolumeCache`]: the filter manager calls this before it dispatches any
/// operation on the volume, so it is the last moment at which a slot can be
/// filled without a lock -- and the only callback that runs before an operation
/// exists, which is what `IoVolumeDeviceToDosName` requires of its caller.
///
/// `STATUS_SUCCESS` attaches to every volume, including one whose DOS name
/// could not be resolved. Refusing to attach would be the wrong trade: an
/// unresolvable volume is counted as `unresolved_volume` and its operations are
/// allowed, whereas a volume this filter is not attached to is not seen at all
/// -- and what is not seen cannot be counted.
///
/// # Safety
///
/// Called by the filter manager at `PASSIVE_LEVEL` with a valid `flt_objects`,
/// before any operation on that volume reaches this driver.
unsafe extern "system" fn instance_setup(
    flt_objects: *const FltRelatedObjects,
    _flags: u32,
    _volume_device_type: u32,
    _volume_filesystem_type: u32,
) -> NtStatus {
    if flt_objects.is_null() {
        return STATUS_SUCCESS;
    }

    // A stack buffer for the filter manager's name. The two-call convention is
    // answered by refusing rather than by allocating: a name too long for 64
    // units is not a `\Device\HarddiskVolumeN`, and this driver has no reason
    // to allocate for something it does not recognise. That is also why there
    // is no `ExAllocatePool` anywhere in this crate.
    let mut buffer = [0u16; flt::VOLUME_NAME_UNITS];
    let mut name = UnicodeString {
        length: 0,
        maximum_length: (flt::VOLUME_NAME_UNITS * 2) as u16,
        pad: 0,
        buffer: buffer.as_mut_ptr(),
    };
    let mut needed: u32 = 0;

    // SAFETY: `flt_objects` is non-null and is the callback's own argument;
    // `name` is a counted string over a live local buffer; `needed` is an
    // out-parameter to a local. The filter is read from this driver's own
    // static rather than from `flt_objects->Filter`, so exactly one field of
    // the structure is ever read -- and it is the one pinned by a layout
    // assertion.
    let status = unsafe { flt::FltGetVolumeName((*flt_objects).volume, &mut name, &mut needed) };
    if status != STATUS_SUCCESS {
        return STATUS_SUCCESS;
    }

    // SAFETY: a successful `FltGetVolumeName` leaves `name` valid for
    // `name.length` bytes of the buffer above.
    let units = unsafe { name.as_units() };
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return STATUS_SUCCESS;
    }

    // SAFETY: the filter manager guarantees this callback completes before it
    // dispatches any operation on this volume, which is the contract `prime`
    // documents, and `filter` is registered. It runs at `PASSIVE_LEVEL`, which
    // the name lookup inside requires.
    unsafe { VOLUMES.prime(filter, units) };

    STATUS_SUCCESS
}

/// Called when the driver is unloaded or the system shuts down.
///
/// The teardown is the reverse of `driver_entry`'s setup, and the port is
/// closed before the filter is unregistered because a client still connected to
/// a filter that is going away is a client that can call back into a
/// registration this driver has released.
extern "system" fn filter_unload(_flags: u32) -> NtStatus {
    let port = SERVER_PORT.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !port.is_null() {
        // SAFETY: `port` came out of `SERVER_PORT`, which only `create_port`
        // wrote, and this is the single place it is closed.
        unsafe { flt::FltCloseCommunicationPort(port) };
    }
    CLIENT_PORT.store(core::ptr::null_mut(), Ordering::Release);

    // SAFETY: `FltUnregisterFilter` has not run yet, so no callback of this
    // driver is executing and neither registration can be entered. See
    // `unregister_notifications`. Earlier in the unload than the filter's own
    // unregistration because that call is what guarantees the object callbacks
    // are finished -- and the object callbacks are the ones that could still be
    // running on another CPU while this unload runs, since nothing about them
    // goes through the filter manager.
    unsafe { unregister_notifications() };

    // The filter now comes out of `FILTER` rather than being the unload
    // callback's first argument, because it never was one: `PFLT_FILTER_UNLOAD_CALLBACK`
    // takes `FLT_FILTER_UNLOAD_FLAGS` and nothing else (`fltKernel.h` 2033).
    // Reading it from the static that `driver_entry` wrote is both the correct
    // source and the one that stays correct if this is ever reached twice, where
    // the second call would otherwise deregister a filter that is already gone.
    let filter = FILTER.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !filter.is_null() {
        // SAFETY: `filter` is the filter this driver registered and it is
        // unregistered exactly once, here -- the swap above is what makes the
        // second call find null. The call returns only once no callback is
        // running.
        unsafe { flt::FltUnregisterFilter(filter) };
    }

    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// The creation veto
// ---------------------------------------------------------------------------

/// The section gate's last few refusals, which [`process_notify`] repeats.
///
/// The type and its tests live in `av_driver_proto::refusal`, because a seqlock
/// whose reader runs in a process-creation callback is the kind of code that
/// must be exercised somewhere it can fail loudly. What stays here is the one
/// instance and the two calls into it.
static REFUSALS: av_driver_proto::refusal::RefusalMemo =
    av_driver_proto::refusal::RefusalMemo::new();

/// A process was created, or deleted.
///
/// # Why the callback was empty until 2026-10-09, and why it is not now
///
/// The body used to say that `ImageFileName` sits "at an offset this driver has
/// not derived from the header". That was true of a driver that reproduced the
/// layout by hand, and it was never true of this one: `wdk-sys` generates
/// `_PS_CREATE_NOTIFY_INFO` from the installed WDK header with `bindgen`, and
/// the generated file carries its own `size_of` and `offset_of` assertions
/// (`out/types.rs`, 72 bytes with `ImageFileName` at 48). Reading
/// `(*create_info).ImageFileName` is a **typed field read whose layout came from
/// the header**, which is exactly the property the old comment was asking for.
///
/// # The three ways the name the kernel gives is not a path
///
/// The header documents `PS_CREATE_NOTIFY_INFO` as a structure whose fields are
/// sometimes absent, and each case is checked rather than assumed:
///
/// - `FileOpenNameAvailable` false: the name may be a **partial** name — the
///   module's base name, sometimes without an extension. Resolving one as
///   though it were a path names a file that may not exist and would not be the
///   one that started.
/// - `ImageFileName` null, or its buffer null: the header allows it for a
///   subsystem process, and `CreateInfo` is null *itself* when the notification
///   is a process being **deleted** rather than created.
/// - a length that is zero, odd, or longer than the protocol's buffer: a
///   half-formed counted string, or one that cannot be carried without
///   truncation, and a truncated path is a different file.
///
/// In every one of them the event is **dropped**, matching the discipline the
/// exclusion table states for itself: an entry that is wrong by truncation
/// matches paths nobody named. A dropped process start is a missed scan; a
/// wrong path is a scan of the wrong program reported under the right one.
///
/// # The one decision this callback makes, and why it is not a wait
///
/// It does not ask the service anything, and it never waits for an answer. What
/// it does is **repeat a refusal the section gate has already made**, a moment
/// earlier, for the same path: `CreationStatus` is `_Inout_` in the header
/// (`ntddk.h` 11211), so writing `STATUS_ACCESS_DENIED` into it fails the
/// creation, and the parent's `CreateProcess` returns `ERROR_ACCESS_DENIED`
/// instead of running the program.
///
/// **Why this exists at all**, measured in the test VM on 2026-10-18:
/// `C:\Samples\wannacry.exe` was refused at the section gate at 12:32:53 —
/// `STATUS_INSUFFICIENT_RESOURCES`, the only status the filter manager honours
/// for a created section — and the process running it was walked at 12:32:54.
/// In the same second, through the same gate, the refusal of
/// `C:\Samples\taskdl.exe` was followed by no process at all. So the section
/// refusal is not universally ignored: it is sometimes effective, and the
/// product cannot tell which case it got. This callback is the one place that
/// can, because it runs after the decision and can still act on it.
///
/// The lever is narrow on purpose, and everything that makes it narrow is in
/// `av_driver_proto::refusal::RefusalMemo`: it fires only for a path this driver
/// refused less than a minute ago, on an exact case-insensitive match, and the
/// gate's next allow of that same path clears the record. Nothing here
/// interprets a file; there is no verdict in this callback and no way for it to
/// invent one.
///
/// # Safety
///
/// Called by the kernel with three pointers that are valid for the duration of
/// the call, on a thread that this callback must not hold up. The signature is
/// `wdk-sys`'s own `PCREATE_PROCESS_NOTIFY_ROUTINE_EX` types rather than
/// `*mut c_void` stand-ins, so that a mismatch with the callback type
/// `PsSetCreateProcessNotifyRoutineEx` declares is a build error instead of a
/// call through a wrongly-typed pointer.
unsafe extern "C" fn process_notify(
    _process: wdk_sys::PEPROCESS,
    process_id: wdk_sys::HANDLE,
    create_info: wdk_sys::PPS_CREATE_NOTIFY_INFO,
) {
    // `CreateInfo` is null when the process is being deleted, and the header
    // documents no other case, so this is also the "creation only" test.
    if create_info.is_null() || !flt::may_defer_for_the_service() {
        return;
    }

    // SAFETY: reading either member of the `Flags` union is reading the same
    // four bytes the kernel filled in. Both are safe views of it — `Flags` is a
    // `ULONG`, and the bitfield unit is the header's declaration of the bits
    // within that `ULONG`, which is why the accessor exists at all rather than
    // this shifting `Flags` by a bit position this file would have to know.
    let available = unsafe { (*create_info).__bindgen_anon_1.__bindgen_anon_1 };
    if available.FileOpenNameAvailable() == 0 {
        return;
    }

    // SAFETY: the callback's contract is that `create_info` is a live
    // `PS_CREATE_NOTIFY_INFO` for the duration of the call.
    let name = unsafe { (*create_info).ImageFileName };
    if name.is_null() {
        return;
    }
    // SAFETY: non-null, and the header types it as a counted string that is
    // valid for the duration of the callback.
    let (buffer, length) = unsafe { ((*name).Buffer, (*name).Length as usize) };
    if buffer.is_null() || length == 0 || length % 2 != 0 {
        return;
    }
    let units = length / 2;
    // The protocol's own maximum, not a second one: `set_path` on the worker
    // would reject anything longer, and rejecting it here saves the allocation.
    if units > MAX_PATH_UNITS {
        return;
    }

    // The DOS form is needed **here** and not on the worker, and that is the
    // 2026-10-18 change to this callback: the veto below is a write into
    // `CreationStatus`, which is only possible during this call, and the memo it
    // consults is keyed by the DOS path. The conversion is a lookup in
    // [`VOLUMES`] plus two copies — the volume table is primed when the service
    // connects and answers from memory — so it does no I/O on the creating
    // thread, which is the property the old arrangement was protecting.
    //
    // SAFETY: `buffer` and `length` are the counted string the kernel handed
    // over, and its length field is the guarantee that `buffer` is valid for
    // `units` code units for the duration of this call.
    let device = unsafe { core::slice::from_raw_parts(buffer, units) };
    let mut dos = [0u16; MAX_PATH_UNITS];
    let Ok(path) = device_to_dos_path(device, &VOLUMES, &mut dos) else {
        // The reasons are `device_to_dos_path`'s own — a volume with no DOS
        // letter, an embedded NUL, a parent component, a name too long — and
        // every one means this is not a path the service could match a rule
        // against. Dropped rather than truncated, as before and for the same
        // reason: a truncated path names a different file.
        return;
    };

    // The veto, and it comes before the queue-cap check below on purpose: a
    // refusal that could not be reported is still a refusal, and the event is
    // the measurement of what happened rather than the thing that makes it
    // happen.
    //
    // The exclusion table is consulted here as well as in [`named`], and the
    // two are not redundant: `named` decides what may be *asked about*, and this
    // decides what may be *refused*. The section gate never stores an excluded
    // path, but a user can add an exclusion in the second between the refusal
    // and the creation — and a user's exclusion is the freshest word this driver
    // has, newer than the engine's refusal. It is a few string comparisons
    // against a fixed table, which is what makes it affordable on the creation
    // path.
    let refused = !EXCLUSIONS.matches(path)
        && REFUSALS.refused_recently(path, interrupt_time_100ns());
    if refused {
        // SAFETY: `create_info` is the live `PS_CREATE_NOTIFY_INFO` the kernel
        // passed to this callback, and `CreationStatus` is declared `_Inout_`
        // (`ntddk.h` 11211) — the header's own statement that a notify routine
        // may write it to fail the creation.
        unsafe { (*create_info).CreationStatus = STATUS_ACCESS_DENIED };
    }

    // A dropped event is silent rather than counted, for the reason
    // [`defer_write_event`] gives: `DriverStats` has no field for one and its
    // layout is the protocol's.
    if PENDING_PROCESS_EVENTS.load(Ordering::Relaxed) >= MAX_PENDING_PROCESS_EVENTS {
        return;
    }

    // Null before `FltStartFiltering` and after `FltUnregisterFilter`. A
    // process notification can arrive in neither window — `DriverEntry`
    // registers this routine after filtering starts, and the unload path
    // deregisters it before unregistering the filter — so this is a guard.
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return;
    }

    // SAFETY: `ExAllocatePool2` with non-paged flags is
    // `_IRQL_requires_max_(DISPATCH_LEVEL)` (`wdm.h` 25427), which is as high as
    // this callback can be entered at. A null return is the pool refusing, and
    // it is handled.
    let block = unsafe {
        flt::ExAllocatePool2(
            flt::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<PendingProcessEvent>(),
            flt::PROCESS_EVENT_TAG,
        )
    }
    .cast::<PendingProcessEvent>();
    if block.is_null() {
        return;
    }

    // SAFETY: `block` came from the non-paged pool just above, is
    // `size_of::<PendingProcessEvent>()` bytes, and nothing else can reach it
    // until it is queued.
    let pending = unsafe { &mut *block };
    pending.event.sequence = NEXT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // Read here rather than on the worker: that is what makes the timestamp the
    // time the process started instead of the time it was reported.
    pending.event.now_100ns = interrupt_time_100ns();
    // `HANDLE` and `PEPROCESS` are both `*mut c_void` in `wdk-sys`, so the
    // identifier is a pointer whose value is the number. A process id fits in
    // 32 bits on this platform, which is also what the protocol's field is.
    pending.event.process_id = process_id as u32;
    // SAFETY: as above — `create_info` is live for this call, and
    // `ParentProcessId` is an `_In_ HANDLE` the kernel has already filled in
    // (`ntddk.h` 11206). Read here because the structure is not valid once this
    // callback returns. `HANDLE` is a pointer in `wdk-sys`; the same two-step
    // cast as `process_id` above, for the same reason.
    pending.parent_process_id = unsafe { (*create_info).ParentProcessId } as usize as u32;
    pending.event.detail = 0;
    pending.event.subject = SubjectKind::Process;
    // The event says which of the two things happened, and `ExecutionBlocked`
    // is the action the protocol already defines for "a process creation or a
    // file execution was refused before it happened". It has never been sent
    // before; the service's `drain_driver` is what turns it into a log line,
    // and that line is what tells the next run whether this veto fired.
    pending.event.action = if refused {
        EventAction::ExecutionBlocked
    } else {
        EventAction::ProcessStarted
    };
    pending.units = path.len() as u32;
    // The path is already the DOS form, and it is copied into the block because
    // a callback cannot leave `dos` — its own stack — behind for the worker.
    pending.path[..path.len()].copy_from_slice(path);

    unsafe {
        queue_pending(
            block.cast::<c_void>(),
            flt::PROCESS_EVENT_TAG,
            process_event_worker,
            &PENDING_PROCESS_EVENTS,
            filter,
        );
    }
}

/// The pre-operation for `IRP_MJ_CREATE`.
///
/// # What this stopped doing on 2026-10-15
///
/// It used to ask the service for a decision and wait for the answer — up to
/// [`DecisionPolicy::DEFAULT_TIMEOUT_MS`] on the calling thread, and up to
/// `av-service`'s `DECISION_DEADLINE` on the port thread. **It could not act on
/// that answer.** `av_service::filter_port`'s `refusing_gate` answers `false`
/// for every request this gate sends, so the `Block` arm was unreachable and
/// the verdict was discarded on every open the machine made.
///
/// What the wait cost was not the answer but the port: that thread is the only
/// reader of the decision port, and it is serial. While it was producing a
/// verdict for this gate, the acquire-for-section request behind it — the one
/// gate in this product that can refuse an execution — was waiting to be read.
/// And this gate is asked a great deal:
///
/// * `FILE_EXECUTE` is `0x0020` and `FILE_TRAVERSE` is `0x0020`, so **every
///   directory open** arrives here as an execution question. That is the mask
///   and not an inference; it is measured, and written down in that function's
///   own documentation.
/// * An icon or a manifest read that goes through the image loader needs a
///   `FILE_EXECUTE` open, so listing a folder of programs arrives here too.
///
/// That is the shape of the 2026-10-14 WannaCry run: the engine convicted the
/// sample's files repeatedly — the service log carries the convictions — and
/// the sample ran, encrypted, and asked for a ransom anyway.
///
/// # Why the ask was removed rather than made asynchronous
///
/// Asynchronous would have kept the scan, and the scan is the part that was
/// never wanted here: this gate's question is about a **read**, which
/// [`section_pre_operation`]'s own documentation says this product does not
/// promise to stop. The execution itself is asked about by that callback, from
/// a request volume of images rather than of opens, and it is the one that can
/// refuse. What is given up is real and narrow — a file the engine would
/// convict is no longer noticed when something merely reads it, so it is no
/// longer taken out of the vault's way before a user runs it — and it is the
/// trade that buys the section gate its answer.
///
/// # Safety
///
/// Called by the filter manager with a valid `data` and `flt_objects` for the
/// operation. The completion context is an out-parameter this implementation
/// never writes, which is what returning [`FLT_PREOP_SUCCESS_NO_CALLBACK`]
/// means.
unsafe extern "system" fn create_pre_operation(
    data: *mut FltCallbackData,
    _flt_objects: *const c_void,
    _completion_context: *mut *mut c_void,
) -> i32 {
    // SAFETY: the callback's contract is that `data` and the parameter block it
    // points at are valid.
    let wanted = unsafe { desired_access(data) };
    if wanted & FILE_EXECUTE == 0 {
        // Not an open that intends to execute anything. This is the
        // overwhelming majority of the file opens on a running system.
        bump(C_ALLOWED);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // An open asking `FILE_EXECUTE`, which the documentation above says is a
    // much weaker statement than it looks. Counted and allowed, with the same
    // counter as the arm above: `DriverStats` has eight fields and none of them
    // is free, and a tenth counter is a protocol change rather than a comment.
    // So how much of this gate's traffic is the `FILE_TRAVERSE` mask is not
    // separable here — which is worth knowing before anybody reads `allowed` as
    // a count of files this gate looked at.
    //
    // The access check itself stays because it is the only thing in this
    // function that would have to change for the gate to ask again, and because
    // reading it is one field of a structure the filter manager has already
    // filled in.
    bump(C_ALLOWED);
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// The pre-operation for `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`.
///
/// This is the gate that actually stops an execution. `CREATE` sees the intent
/// -- an open asking for `FILE_EXECUTE` -- but a section can also be created
/// from a handle that was opened without it, and this callback is the point at
/// which the mapping is about to happen. Registering both means neither alone
/// is the hole.
///
/// # The gate, and what its absence cost
///
/// The intent test the create callback makes on `DesiredAccess` has to be made
/// here too, and it was missing until 2026-10-01. This IRP is issued for **every**
/// section, not only for images: a program that memory-maps a data file -- and
/// that includes the machine's own antivirus reading a file it has just been
/// handed, and any loader parsing headers -- arrives at this callback exactly as
/// a process starting does. Without the test, every one of those went to the
/// service for a full scan, and, if the engine convicted the file, was refused.
///
/// What that looked like in the test VM, before the fix:
///
/// * `%APPDATA%\...\PSReadLine\ConsoleHost_history.txt` -- a text file, in a
///   directory the watcher does not watch -- was scanned, convicted by a rule it
///   matched, blocked here, and taken into quarantine.
/// * A sample copied into a folder was quarantined before anything ran it,
///   because something mapped it on the way in.
/// * Every mapped file on the machine cost the service a full scan, which is
///   what a saturated core looks like from outside.
/// * Scans that ran past [`DecisionPolicy::DEFAULT_TIMEOUT_MS`] left the service
///   replying to a driver that had stopped waiting, which is the
///   `ERROR_FLT_NO_WAITER_FOR_REPLY` (`0x801F0020`) warning per file.
///
/// So the gate is not a speed filter that trades coverage for throughput: what it
/// excludes is the reading of a file, which this product does not promise to
/// stop. [`flt::section_will_execute`] carries the argument for the two
/// conditions, and the assertions at the bottom of `flt.rs` carry the cases.
///
/// That the path above is reachable without the gate is readable in this file
/// rather than inferred from the VM: `decide` resolves the name of whatever the
/// callback was handed and sends it, and nothing between here and there asks what
/// the section is for. Which *file* a mapped read belongs to is what the service
/// log answers -- its `was refused: the engine scored it` line is emitted from
/// the driver's own reporting path and from nowhere else.
///
/// # Safety
///
/// As for [`create_pre_operation`].
unsafe extern "system" fn section_pre_operation(
    data: *mut FltCallbackData,
    _flt_objects: *const c_void,
    _completion_context: *mut *mut c_void,
) -> i32 {
    // SAFETY: `data` is the callback's own data pointer, and this callback is
    // the acquire-for-section pre-operation, so the parameter block carries the
    // arm the helper reads.
    if !unsafe { section_is_an_execution(data) } {
        // Not a section that anything is about to run: a mapped data file, or an
        // acquire of a section that already exists. Counted as allowed for the
        // same reason `create_pre_operation` counts its early return -- it is a
        // decision this driver made, and a counter that omits it would make the
        // two gates read as though they saw the same traffic.
        bump(C_ALLOWED);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // SAFETY: `data` is the callback's own data pointer.
    match unsafe { decide(data) } {
        Verdict::Block => {
            // `STATUS_INSUFFICIENT_RESOURCES` and not `STATUS_ACCESS_DENIED`:
            // it is the only failure the filter manager accepts for a created
            // section, and the wrong one is silently ignored -- see [`refuse`]
            // for the document and for the two measurements that read as a
            // refusal that did nothing.
            //
            // SAFETY: as in `create_pre_operation`.
            unsafe { refuse(data, STATUS_INSUFFICIENT_RESOURCES) };
            FLT_PREOP_COMPLETE
        }
        Verdict::Allow | Verdict::Unresolved => FLT_PREOP_SUCCESS_NO_CALLBACK,
    }
}

/// The post-operation for `IRP_MJ_WRITE`.
///
/// It queues the notification and returns. It does not send, and it must not:
/// a post-operation can be entered at `DISPATCH_LEVEL`, `FltSendMessage`'s cap
/// is `_IRQL_requires_max_(APC_LEVEL)` (`fltKernel.h` 4642), and a timeout of
/// zero says "do not wait" rather than "may be entered at `DISPATCH_LEVEL`" --
/// which this comment claimed was the same thing until 2026-09-27. See
/// [`defer_write_event`] for what the dump from that crash showed and why the
/// send moved to a worker thread.
///
/// `FLT_POSTOP_FINISHED_PROCESSING` is unchanged: returning
/// `FLT_POSTOP_MORE_PROCESSING_REQUIRED` would pend the operation until a
/// matching `FltCompletePendedPostOperation`, which is a write left unresolved.
///
/// # Safety
///
/// Called by the filter manager after the write has been issued. The callback's
/// data pointer is not read, here or later: the notification is four constants
/// and a counter, and every part of a write that would have to come out of the
/// callback -- above all its path, through `FltGetFileNameInformation` -- is
/// valid only until the callback returns, which is before the worker that sends
/// the notification runs. Reading it there would be reading it after it
/// expired, so nothing is taken from it here.
///
/// # The one field taken from the write, since 2026-10-18
///
/// The identifier of the process running this post-operation, from
/// [`flt::PsGetCurrentProcessId`]. That call reads the current thread, not the
/// callback data: it takes no argument that could be null or inconsistent, and
/// it cannot fault the way `FltGetRequestorProcess` did on 2026-09-27 (see the
/// module documentation). What it answers is "the process whose thread is
/// running now", which is the writing process when the write completed inline
/// -- the ordinary case, including cached and buffered writes -- and can be a
/// different process when the I/O manager completes the IRP on a worker
/// thread. The event is therefore attributable and not authoritative; a rule
/// that convicts on it must corroborate, which is the same standard the
/// threshold policy sets for every count-based signal.
unsafe extern "system" fn write_post_operation(
    _data: *mut FltCallbackData,
    _flt_objects: *const c_void,
    _completion_context: *mut c_void,
    _flags: u32,
) -> i32 {
    // SAFETY: `PsGetCurrentProcessId` has no precondition beyond "called from
    // kernel mode" in its declaration (`ntddk.h` 11385); it takes no argument
    // and dereferences nothing this driver supplies.
    let process_id = unsafe { flt::PsGetCurrentProcessId() } as usize as u32;
    defer_write_event(process_id);
    FLT_POSTOP_FINISHED_PROCESSING
}

/// The pre-operation for `IRP_MJ_WRITE`: the kernel write gate.
///
/// The one thing this driver refuses without asking anybody. It exists because
/// a tamper attempt on this product's own files is exactly the case in which
/// the service may already be dead -- an attacker who kills the service first
/// and then edits `wenle-av-service.exe` has defeated a gate that lives in the
/// service, and this one lives in the kernel and is armed by a message that
/// was sent while the service was alive.
///
/// # The one this must not become
///
/// The section gate's defect (2026-10-01) is the reason every line here is
/// narrow, and the shape of that mistake is worth restating because it is the
/// one available: a callback that fires for a class of operations much wider
/// than the thing it means to protect, deciding with a predicate that is true
/// for the wider class. There, every memory-mapped file on the machine was
/// scanned and convicted. Here the class is *writes* rather than every
/// operation, and the predicate is an exact whole-path comparison against a
/// directory the service named and six file names -- so the set of files this
/// can refuse is the set `PROTECTED_FILES` lists, inside the one directory the
/// gate was armed with, and nothing else.
///
/// It is deliberately **not** armed with the data directory: the service writes
/// `config.toml`, the log, and the quarantine vault there, and a gate over that
/// tree would be this product refusing to run.
///
/// # What it costs when it is off, which is most of the time
///
/// One relaxed load of an `AtomicBool` that this driver owns and never shares.
/// The gate is off on every machine until a service connects and sends a
/// configuration message asking for it, so this is the whole cost of an
/// `IRP_MJ_WRITE` pre-operation on a machine that has not asked for one.
///
/// # The post-operation, and why every allow path asks for it
///
/// This entry also has a **post-operation** -- the tamper detector -- and a
/// pre-operation that returns `FLT_PREOP_SUCCESS_NO_CALLBACK` *suppresses* it.
/// So every path below that is not a refusal returns
/// [`flt::FLT_PREOP_SUCCESS_WITH_CALLBACK`], and that is load-bearing rather
/// than stylistic: `..._NO_CALLBACK` here would stop every `FileWritten` event
/// on the machine, silently, while the write gate went on working perfectly.
/// Nothing would fail; the service would simply never hear about a write again.
///
/// The refused path returns `FLT_PREOP_COMPLETE`, which suppresses the
/// post-operation too -- correctly, because a write that never happened has
/// nothing to report.
///
/// # Safety
///
/// As for [`create_pre_operation`]: called by the filter manager with a valid
/// `data` for the operation, and the completion context is never written.
unsafe extern "system" fn write_pre_operation(
    data: *mut FltCallbackData,
    _flt_objects: *const c_void,
    _completion_context: *mut *mut c_void,
) -> i32 {
    // Relaxed on purpose, and the reason is the same one `gate_matches` gives
    // for its own loads: this load decides only whether to *look*. A stale
    // `false` here costs one write that should have been refused, and a
    // configuration message that has not yet been observed arming the gate is
    // a gate that is not yet armed -- which is a state this driver is correct
    // in. What must not be relaxed is the load that makes the *buffer* readable,
    // and that one is an acquire in `gate_matches`.
    if !GATE_ARMED.load(Ordering::Relaxed) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // The name lookup below is `_IRQL_requires_max_(APC_LEVEL)`
    // (`fltKernel.h` 2843) and a write can be entered at `DISPATCH_LEVEL`. The
    // registration carries `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`, which
    // removes the common case and not all of them: an unbuffered write is not
    // paging I/O and arrives at `DISPATCH_LEVEL` anyway.
    //
    // Failing **open** is the only answer available. There is no IRQL at which
    // this driver could resolve the name and still be inside the callback, and
    // refusing a write on the strength of a path it never read would be
    // refusing every write above `APC_LEVEL` -- which is a machine that cannot
    // save a file.
    if !flt::may_block_for_the_service() {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    let mut dos = [0u16; MAX_PATH_UNITS];
    // SAFETY: `data` is the callback's own data pointer, and this is an
    // `APC_LEVEL` or lower context -- checked just above.
    let matched = match unsafe { operation_file_dos_path(data, &mut dos) } {
        Some(units) => gate_matches(&dos[..units]),
        // A write whose name could not be had is a write this driver cannot
        // decide about, and there is no counter for it: `C_OVERSIZE_PATH` means
        // the path did not fit the protocol's buffer and `C_UNRESOLVED_VOLUME`
        // means the device had no DOS name. Neither is this, and incrementing
        // one of them would be recording a fact that is not so. The same arm
        // covers a volume with no DOS name, which cannot match a directory the
        // service named by drive letter, so there is nothing to compare and
        // nothing to count a second time either.
        None => false,
    };

    if !matched {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // The counter an operator reads to tell this gate from the two execution
    // gates. It was declared on 2026-09-26 and never moved, because until now
    // nothing in this driver could refuse a write.
    bump(C_BLOCKED_WRITES);
    // SAFETY: `data` is the callback data of the operation this pre-operation
    // is completing with `FLT_PREOP_COMPLETE` below.
    unsafe { refuse(data, STATUS_ACCESS_DENIED) };
    FLT_PREOP_COMPLETE
}

/// The pre-operation for `IRP_MJ_SET_INFORMATION`: rename and delete
/// telemetry, added 2026-10-18.
///
/// # What this is for
///
/// Ransomware's most legible signature is not the content of the files it
/// writes — which is encrypted, and which the write notification above sees only
/// as "something wrote a file". It is the *shape* of the file operations around
/// them: a burst of renames into a new extension, or a burst of deletes of
/// originals. Until this callback existed, this driver could not see either of
/// them at all: `IRP_MJ_WRITE` is a write to a file that exists, and a rename is
/// neither a write nor a create.
///
/// # What it is not
///
/// **It never refuses.** The return is [`FLT_PREOP_SUCCESS_NO_CALLBACK`] on
/// every path, including the ones that saw exactly what a targeted refusal would
/// want to stop. That is deliberate and it is the increment boundary: the three
/// refusals this driver makes are the ones with a measured false-positive story
/// behind them (see the module documentation), and a rename gate has none yet.
/// A rename is also the *ordinary* way an editor saves a file and the way an
/// installer moves every file it installs, so a gate here would be the
/// section-gate mistake in a second place: a class far wider than the intent.
/// The event is data for the engine to weigh, not a verdict.
///
/// # Where the path comes from, and why it is the target
///
/// `path` is the name the file is being **renamed to**, which is the ransomware
/// signal: `report.docx` becoming `report.docx.WNCRY` is told by the target and
/// not by the source. [`rename_target_units`] reads it out of the information
/// buffer and converts it, and falls back to the source name when the target
/// cannot be resolved (a rename relative to a directory handle), setting
/// `detail = 1` so that a consumer can tell a source name from a target one.
///
/// A delete has no target: `path` is the file being deleted, and the event means
/// "a delete was requested", not "the file is gone" — the delete happens when
/// the last handle closes, which can be long after this callback and can be
/// never.
///
/// # The IRQL
///
/// The name resolution is `_IRQL_requires_max_(APC_LEVEL)`, and the
/// registration carries `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`. The
/// callback checks the IRQL as well, because the flag removes the common case
/// and not all of them; a set-information above `APC_LEVEL` is reported as
/// nothing rather than as a fault.
///
/// # Safety
///
/// As for [`create_pre_operation`]: called by the filter manager with a valid
/// `data` for an `IRP_MJ_SET_INFORMATION` operation, and the completion context
/// is never written.
unsafe extern "system" fn set_information_pre_operation(
    data: *mut FltCallbackData,
    _flt_objects: *const c_void,
    _completion_context: *mut *mut c_void,
) -> i32 {
    if !flt::may_block_for_the_service() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // SAFETY: the callback's contract is that `data` and the parameter block it
    // points at are valid for the duration of this call, and this is the
    // set-information pre-operation, so the arm read is the arm this operation
    // carries.
    let Some(parameters) = (unsafe { set_information_parameters(data) }) else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    };

    let action = match parameters.file_information_class {
        FILE_RENAME_INFORMATION_CLASS | FILE_RENAME_INFORMATION_EX_CLASS => {
            EventAction::FileRenamed
        }
        FILE_DISPOSITION_INFORMATION_CLASS => {
            // `FILE_DISPOSITION_INFORMATION::DeleteFile`, one byte. A zero is a
            // *cancellation* of a delete another operation requested -- the way
            // a tool that opened a file for delete-on-close changes its mind --
            // and reporting it as a delete would be reporting the opposite.
            let buffer = parameters.info_buffer;
            if buffer.is_null() || (parameters.length as usize) < core::mem::size_of::<FileDispositionInformation>() {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            // SAFETY: non-null, and the parameter block declares at least the
            // one byte this reads.
            if unsafe { (*buffer.cast::<FileDispositionInformation>()).delete_file } == 0 {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            EventAction::FileDeleted
        }
        FILE_DISPOSITION_INFORMATION_EX_CLASS => {
            let buffer = parameters.info_buffer;
            if buffer.is_null() || (parameters.length as usize) < core::mem::size_of::<FileDispositionInformationEx>() {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            // SAFETY: as above, for the four-byte flags word. Most set-
            // information calls with this class clear a flag rather than ask
            // for a delete, so this is the field that decides whether the event
            // is about a delete at all.
            if unsafe { (*buffer.cast::<FileDispositionInformationEx>()).flags }
                & flt::FILE_DISPOSITION_DELETE
                == 0
            {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            EventAction::FileDeleted
        }
        // Every other information class -- an allocation size, an end-of-file,
        // a valid-data length, a compression or sparse flag -- is a change to a
        // file that this event vocabulary has no name for. Counted nowhere and
        // reported nowhere: an event whose action is a guess is worse than none.
        _ => return FLT_PREOP_SUCCESS_NO_CALLBACK,
    };

    // One scratch buffer rather than one per candidate name: a kernel thread's
    // stack is 12 KiB and this callback is already deeper than the write gate's
    // by the rename header it reads.
    let mut dos = [0u16; MAX_PATH_UNITS];
    let (units, detail) = match action {
        EventAction::FileRenamed => {
            // SAFETY: `parameters` is the set-information arm of a rename, and
            // `dos` is this function's own buffer.
            match unsafe { rename_target_units(&parameters, &mut dos) } {
                // The target converted. This is the name the event carries.
                Some(units) => (units, 0),
                // Relative to a directory handle, an unknown volume, or a name
                // that did not convert. The source is still a true statement
                // about which file moved, so it is reported with `detail = 1`
                // rather than dropped.
                None => match unsafe { operation_file_dos_path(data, &mut dos) } {
                    Some(units) => (units, 1),
                    None => return FLT_PREOP_SUCCESS_NO_CALLBACK,
                },
            }
        }
        _ => match unsafe { operation_file_dos_path(data, &mut dos) } {
            Some(units) => (units, 0),
            None => return FLT_PREOP_SUCCESS_NO_CALLBACK,
        },
    };

    // SAFETY: `PsGetCurrentProcessId` has no precondition beyond "called from
    // kernel mode" in its declaration (`ntddk.h` 11385), and the read happens
    // here, inside the callback, rather than on the worker for the reason the
    // write post-operation gives: it reads the current thread and dereferences
    // nothing this driver supplies. The attribution is the same
    // attributable-not-authoritative kind.
    let process_id = unsafe { flt::PsGetCurrentProcessId() } as usize as u32;
    defer_file_event(action, process_id, detail, &dos[..units]);
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// The `SetFileInformation` arm of a set-information operation, or `None`.
///
/// # Safety
///
/// `data` must be the callback data of an `IRP_MJ_SET_INFORMATION` operation,
/// from that operation's pre-operation.
unsafe fn set_information_parameters(
    data: *mut FltCallbackData,
) -> Option<FltSetFileInformationParameters> {
    if data.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let iopb = unsafe { (*data).iopb };
    if iopb.is_null() {
        return None;
    }
    // SAFETY: `iopb` is non-null, belongs to the operation, and the operation
    // is the one whose arm this reads. Copied out because the union is not
    // readable in the caller's frame without carrying the same proof there.
    Some(unsafe { (*iopb).parameters.set_file_information })
}

/// Resolve an operation's file to a DOS path in `out`, returning its length.
///
/// Extracted from [`write_pre_operation`] on 2026-10-18 when the rename and
/// delete callback became its second caller. The body is that callback's own;
/// what the extraction buys is that "resolve the file this operation is about"
/// is one piece of code, and a defect in it is one place rather than two that
/// have to be kept in step.
///
/// `None` covers both "the filter manager could not name it" and "the volume
/// has no DOS name", which every caller treats the same way: an event about a
/// path nobody can read is not an event.
///
/// # Safety
///
/// `data` must be the callback data of an operation whose file name the caller
/// may resolve, called at `APC_LEVEL` or below.
unsafe fn operation_file_dos_path(
    data: *mut FltCallbackData,
    out: &mut [u16; MAX_PATH_UNITS],
) -> Option<usize> {
    let mut information: *mut FltFileNameInformation = core::ptr::null_mut();
    // SAFETY: `data` is the caller's live callback data. The options are the
    // ones every caller wants for the same reason: the normalised form in the
    // device namespace is what the protocol's normaliser is written against,
    // and `FLT_FILE_NAME_QUERY_DEFAULT` lets the filter manager answer from its
    // cache. The name is valid only until the callback returns, which is why
    // the conversion happens here rather than being deferred.
    let status = unsafe {
        flt::FltGetFileNameInformation(
            data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &mut information,
        )
    };
    if status != STATUS_SUCCESS || information.is_null() {
        return None;
    }

    // SAFETY: `information` is non-null and was just returned by a successful
    // `FltGetFileNameInformation`.
    let device = unsafe { (*information).name.as_units() };
    let converted = device_to_dos_path(device, &VOLUMES, out).ok().map(|p| p.len());

    // SAFETY: `information` came from `FltGetFileNameInformation`, is non-null,
    // and has not been released on any path above.
    unsafe { flt::FltReleaseFileNameInformation(information) };
    converted
}

/// The rename target, converted to the DOS namespace, or `None`.
///
/// `FILE_RENAME_INFORMATION` and `FILE_RENAME_INFORMATION_EX` have the same
/// offsets for the three fields read here — a four-byte union, the root
/// directory handle, the byte length — so one reader serves both. The name
/// itself is at [`FILE_RENAME_NAME_OFFSET`], **not** at `size_of`, which rounds
/// the header to 24 and would drop the first two characters of every name.
///
/// # The bounds
///
/// `FileNameLength` is the I/O manager's own field and the parameter block's
/// `Length` is the size of the same buffer, so the two are read against each
/// other: a length longer than the buffer would be a read past its end, and the
/// smaller of the two is the only safe answer. A name of odd length is not a
/// UTF-16 string at all and is truncated to the even count rather than read
/// past.
///
/// # Safety
///
/// `parameters` must be the `SetFileInformation` arm of a rename operation,
/// read from that operation's pre-operation.
unsafe fn rename_target_units(
    parameters: &FltSetFileInformationParameters,
    out: &mut [u16; MAX_PATH_UNITS],
) -> Option<usize> {
    let buffer = parameters.info_buffer;
    if buffer.is_null() {
        return None;
    }
    let declared = parameters.length as usize;
    if declared < FILE_RENAME_NAME_OFFSET + 2 {
        return None;
    }

    // SAFETY: the buffer is non-null and the block declares at least the
    // header plus two bytes, which is what this reads.
    let header = unsafe { &*buffer.cast::<FileRenameInformation>() };
    if !header.root_directory.is_null() {
        // The new name is relative to a directory handle, and that handle names
        // a directory this callback has not been given. The source path is the
        // caller's fallback.
        return None;
    }

    let available = declared - FILE_RENAME_NAME_OFFSET;
    let bytes = (header.file_name_length as usize).min(available) & !1;
    if bytes == 0 {
        return None;
    }

    // SAFETY: the name starts at `FILE_RENAME_NAME_OFFSET` and `bytes` is no
    // more than what remains of a buffer the parameter block declares, rounded
    // down to whole UTF-16 units.
    let name = unsafe {
        core::slice::from_raw_parts(
            buffer.cast::<u8>().add(FILE_RENAME_NAME_OFFSET).cast::<u16>(),
            bytes / 2,
        )
    };
    device_to_dos_path(name, &VOLUMES, out).ok().map(|p| p.len())
}

/// Whether a resolved path is one of the files the write gate protects.
///
/// Split out of [`write_pre_operation`] for the reason the gate's state has the
/// shape it has: everything here is the read half of a write that happened once,
/// and `av-driver-proto`'s `gate_update` owns the write half and is tested.
///
/// # The two loads and why they are in this order
///
/// `GATE_ARMED` first, because it is the switch and a disarmed gate must not
/// read the buffer at all. Then `GATE_UNITS`, which is `Acquire` and is what
/// makes the buffer readable: the one write to it is published by a `Release`
/// store of this length *before* the switch is set, so a reader that sees the
/// gate armed through this acquire load is a reader that sees a filled buffer.
/// That pairing is the whole of the synchronisation -- there is no lock here and
/// there is no second writer to lose.
///
/// A length that is zero or past the buffer is not reachable through that
/// pairing, and it is checked anyway: a value that cannot happen is the one
/// worth refusing rather than trusting, because the consequence of trusting it
/// is a slice over memory this driver does not own.
fn gate_matches(path: &[u16]) -> bool {
    if !GATE_ARMED.load(Ordering::Acquire) {
        return false;
    }
    let units = GATE_UNITS.load(Ordering::Acquire) as usize;
    if units == 0 || units > GATE_DIR_UNITS {
        return false;
    }
    // SAFETY: `units` was published after the buffer was filled, and this
    // acquire load is paired with that release store. `GATE_DIRECTORY` is only
    // ever written through `apply_config`, only while its length is still zero,
    // and the length above is at most `GATE_DIR_UNITS`, which is the array's
    // own length.
    let directory = unsafe { &*GATE_DIRECTORY.0.get() };
    is_protected_file(&directory[..units], path)
}

// ---------------------------------------------------------------------------
// Kernel self-protection
// ---------------------------------------------------------------------------

/// The altitude this driver's object callbacks are registered at.
///
/// `OB_CALLBACK_REGISTRATION`'s `Altitude` is a string in the **minifilter**
/// altitude numbering: the structure's documentation defers to "Load Order
/// Groups and Altitudes for Minifilter Drivers", and `ObRegisterCallbacks`
/// answers `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION` (`0xC01F0002`) when another
/// driver already holds the value.
///
/// `321001` is one above this product's minifilter altitude (321000) so that
/// both of this product's registrations are unambiguously its own, and it is
/// inside 320000-329999, the `FSFilter Anti-Virus` band they both belong to.
/// That band is MSDN documentation and **not** a header fact: searching
/// `Include\10.0.26100.0` for `320000` or `329999` finds neither, so the only
/// authority for it is the table, and the only thing this driver needs from it
/// is to be inside it and to be unique on the machine.
const OB_ALTITUDE: &[u8] = b"321001";

/// The altitude this driver's registry callback is registered at.
///
/// `CmRegisterCallbackEx` orders registry callbacks by this string, and
/// `ObRegisterCallbacks` answers `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION` when
/// two registrations on the machine hold the same value — so it is one above
/// [`OB_ALTITUDE`]'s rather than equal to it, on the same reasoning that made
/// that one 321001 rather than 321000. Still inside the `FSFilter Anti-Virus`
/// band, and still a documented value rather than a header one.
const REGISTRY_ALTITUDE: &[u8] = b"321002";

/// `OB_PREOP_SUCCESS`, from `wdm.h`. `OB_PREOP_CALLBACK_STATUS` has exactly one
/// member, which is why a pre-operation callback has no verdict to return --
/// the only thing it may decide with is the access mask it rewrites.
const OB_PREOP_SUCCESS: i32 = wdk_sys::_OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;

/// `UserMode`, from `wdm.h`'s `MODE`.
///
/// A cast rather than the constant itself because the two types differ:
/// `KPROCESSOR_MODE` is generated as `CCHAR` (`i8`) and the enumerator as a
/// `c_int`. `SeSinglePrivilegeCheck`'s second parameter is the `CCHAR`, and
/// passing the `c_int` would be a type error rather than a silent bug -- but
/// only because this bindgen output happens to widen it, which is the kind of
/// thing that is worth naming where it is depended on.
const USER_MODE: wdk_sys::KPROCESSOR_MODE = wdk_sys::_MODE::UserMode as wdk_sys::KPROCESSOR_MODE;

/// Which object type a handle open is aimed at.
///
/// The two differ in one place that matters: a thread's `Object` is an
/// `ETHREAD`, and the process that owns it has to be asked for, where a
/// process's `Object` *is* the `EPROCESS`.
#[derive(Clone, Copy)]
enum Target {
    /// `PsProcessType`.
    Process,
    /// `PsThreadType`.
    Thread,
}

/// The object-manager pre-operation for handles to this product's processes.
///
/// `unsafe extern "C"` rather than `extern "system"` because that is the type
/// `POB_PRE_OPERATION_CALLBACK` declares (`types.rs`, generated from `wdm.h`).
/// On x86_64 the two calling conventions are the same and the difference is
/// therefore unobservable at runtime -- which is exactly why it is worth
/// matching the typedef: this is a *type-checked* assignment into
/// `OB_OPERATION_REGISTRATION::PreOperation`, and "the ABI happens to agree"
/// is a coincidence rather than a check.
///
/// # Safety
///
/// Called by the object manager with the registration context this driver
/// passed (null) and a valid `info`, for `PsProcessType` handle creates only.
unsafe extern "C" fn protect_process_handle(
    _registration_context: *mut c_void,
    info: wdk_sys::POB_PRE_OPERATION_INFORMATION,
) -> i32 {
    // SAFETY: the caller's contract is that `info` is valid for the duration of
    // the call.
    unsafe { protect_handle(info, Target::Process) }
}

/// The object-manager pre-operation for handles to this product's threads.
///
/// # Safety
///
/// As for [`protect_process_handle`], with `PsThreadType` in place of
/// `PsProcessType`.
unsafe extern "C" fn protect_thread_handle(
    _registration_context: *mut c_void,
    info: wdk_sys::POB_PRE_OPERATION_INFORMATION,
) -> i32 {
    // SAFETY: as above.
    unsafe { protect_handle(info, Target::Thread) }
}

/// Remove this product's protected rights from a handle open, if it is aimed at
/// this product.
///
/// # The only thing this may do
///
/// `DesiredAccess` may only be **reduced**. `OB_PRE_OPERATION_INFORMATION`'s
/// documentation is explicit that a pre-operation callback cannot add access a
/// caller did not ask for, and that is not a convention this driver is being
/// polite about -- the access check that follows is against the reduced mask, so
/// a mask with a bit added back is a bit the caller still has to be entitled to,
/// and the object manager would grant it on the strength of this driver's word.
/// Nothing here ever sets a bit; `strip_process` and `strip_thread` are `& !mask`
/// and are tested as such.
///
/// # Why an administrator is exempt
///
/// The same policy `av-guard`'s `PROTECTED_DACL` states and documents: this
/// protects the product from *other* users and from malware running as the
/// logged-in user, and it does not and cannot protect it from the machine's
/// administrator. Reporting otherwise would be the kind of claim that is worse
/// than no claim. `SeTcbPrivilege` is SYSTEM, `SeTokenIsAdmin` is an
/// administrator's token, and both are allowed through untouched.
///
/// # Safety
///
/// `info` must be the operation-information structure the object manager handed
/// to a pre-operation callback registered for handle creates, and this must run
/// at `PASSIVE_LEVEL` -- the token calls below require it, and the check is what
/// makes that a fact rather than an assumption.
unsafe fn protect_handle(
    info: wdk_sys::POB_PRE_OPERATION_INFORMATION,
    target: Target,
) -> i32 {
    if info.is_null() {
        return OB_PREOP_SUCCESS;
    }

    // The switch, first, because this callback runs for **every** handle open on
    // the machine and the overwhelming majority of machines have not asked for
    // this. One relaxed-shaped acquire load of an atomic this driver owns is the
    // whole cost of an ordinary `OpenProcess`.
    if !HANDLES_PROTECTED.load(Ordering::Acquire) {
        return OB_PREOP_SUCCESS;
    }

    // `PsReferencePrimaryToken`, `SeTokenIsAdmin` and `SeSinglePrivilegeCheck`
    // are each `_IRQL_requires_max_(PASSIVE_LEVEL)`, and the header documents
    // this callback as `_IRQL_requires_max_(PASSIVE_LEVEL)` too. A promise about
    // the caller is not a guarantee to the callee, so this asks.
    if !flt::at_passive_level() {
        return OB_PREOP_SUCCESS;
    }

    // SAFETY: `info` is non-null, which was just checked, and the caller's
    // contract is that it is valid for the duration of the call.
    let info = unsafe { &*info };

    if info.Operation != wdk_sys::OB_OPERATION_HANDLE_CREATE {
        // Only handle *creates* are registered for, so this is unreachable
        // today. It is here for the day `OB_OPERATION_HANDLE_DUPLICATE` is
        // added: a duplicate does not carry the create arm this reads below, and
        // reading it there would be reading whatever that operation put in the
        // union.
        return OB_PREOP_SUCCESS;
    }

    // SAFETY: reading the arm of the union the object manager fills in for a
    // handle-create pre-operation, which is the operation checked just above.
    // Both members of the union are `Copy`, so this is a read and not a move.
    let kernel_handle = unsafe { info.__bindgen_anon_1.__bindgen_anon_1.KernelHandle() };
    if kernel_handle != 0 {
        // A kernel handle is not a user-mode caller's. Only user-mode handles
        // are the thing this protects against, and stripping a kernel handle
        // would break this product's own service, which opens its own files.
        return OB_PREOP_SUCCESS;
    }

    // SAFETY: for `PsProcessType` the object is the `EPROCESS` being opened and
    // for `PsThreadType` the `ETHREAD`; `info.ObjectType` is what says which,
    // and it is the registration that decides, so the `target` carried in from
    // the callback is that fact rather than a guess.
    let process: wdk_sys::PEPROCESS = match target {
        Target::Process => info.Object.cast::<wdk_sys::_KPROCESS>(),
        // SAFETY: `info.Object` is an `ETHREAD` for this registration. The
        // object manager holds the reference that keeps it alive for the
        // duration of the callback, which is what `IoThreadToProcess` needs.
        Target::Thread => unsafe {
            wdk_sys::ntddk::IoThreadToProcess(info.Object.cast::<wdk_sys::_KTHREAD>())
        },
    };
    if process.is_null() {
        return OB_PREOP_SUCCESS;
    }

    // A process's handle to itself. This is not the thing being protected
    // against, and a process that cannot open itself with full access is a
    // process that will misbehave in ways nobody will attribute to a driver.
    // SAFETY: no preconditions, callable at any IRQL, returns a referenced
    // `EPROCESS` that lives as long as the caller.
    if process == unsafe { wdk_sys::ntddk::IoGetCurrentProcess() } {
        return OB_PREOP_SUCCESS;
    }

    // SAFETY: `process` is an `EPROCESS` the object manager holds a reference
    // to for the duration of this callback, and the returned pointer is into
    // that structure rather than an allocation. `flt.rs` says what was measured
    // about this call: it is a real `ntoskrnl` export that appears in no header.
    let name = unsafe { flt::PsGetProcessImageFileName(process.cast::<c_void>()) };
    if name.is_null() {
        return OB_PREOP_SUCCESS;
    }
    // SAFETY: the pointer is to `EPROCESS.ImageFileName`, a fixed array the
    // kernel keeps, and `IMAGE_NAME_BYTES` is at most its width. The slice is
    // read and dropped inside this function, so nothing outlives the reference
    // the object manager holds.
    let field = unsafe { core::slice::from_raw_parts(name, IMAGE_NAME_BYTES) };
    if !is_our_image(field) {
        return OB_PREOP_SUCCESS;
    }

    // SYSTEM: `SeTcbPrivilege` is the privilege that makes a token the system's,
    // and it is the check `PsIsSystemProcess` is documented to be equivalent to.
    //
    // SAFETY: `SE_EXPORTS` is the kernel's privilege table, initialised before
    // any driver loads, so it is non-null here; the field read is a `LUID` by
    // value out of a structure the kernel owns. `flt.rs` says why this goes
    // through the import slot rather than through `wdk_sys::SeExports` (which
    // does not link). `SeSinglePrivilegeCheck` is
    // `_IRQL_requires_max_(PASSIVE_LEVEL)`, which was checked above.
    let system = unsafe {
        wdk_sys::ntddk::SeSinglePrivilegeCheck((*flt::SE_EXPORTS).SeTcbPrivilege, USER_MODE)
    };
    if system != 0 {
        return OB_PREOP_SUCCESS;
    }

    // SAFETY: no preconditions; returns a referenced `EPROCESS` that outlives
    // the calls below.
    let current = unsafe { wdk_sys::ntddk::IoGetCurrentProcess() };
    // SAFETY: `current` is the calling process, which is alive for the duration
    // of the call. The returned reference is released on both paths below,
    // which is the whole reason it is taken into a local first.
    let token = unsafe { wdk_sys::ntddk::PsReferencePrimaryToken(current) };
    if token.is_null() {
        // No primary token to ask about. Allowing is the answer that cannot
        // break a machine: a handle open that this driver cannot classify is
        // not a handle open it may refuse.
        return OB_PREOP_SUCCESS;
    }
    // SAFETY: `token` is the reference just taken.
    let admin = unsafe { wdk_sys::ntddk::SeTokenIsAdmin(token) };
    // SAFETY: `token` is the reference just taken, and this is its single
    // release -- `PsReferencePrimaryToken` hands back a counted reference and
    // leaking one per handle open would be a leak on the busiest path on the
    // machine.
    unsafe { wdk_sys::ntddk::PsDereferencePrimaryToken(token) };
    if admin != 0 {
        return OB_PREOP_SUCCESS;
    }

    if info.Parameters.is_null() {
        // Not a case the header allows for a handle create, and checked rather
        // than assumed because the alternative to a check here is a null
        // dereference in a pre-operation callback, which is a bugcheck.
        return OB_PREOP_SUCCESS;
    }

    // The reduction itself, and it is the only write this callback makes.
    // SAFETY: `Parameters` points at the union the object manager filled in for
    // this operation, the arm below is the one `Operation` selected above, and
    // this callback is its only writer -- the object manager reads it after the
    // callback returns and not during.
    unsafe {
        let create = &mut (*info.Parameters).CreateHandleInformation;
        let asked_for = create.DesiredAccess;
        create.DesiredAccess = match target {
            Target::Process => strip_process(asked_for),
            Target::Thread => strip_thread(asked_for),
        };
    }

    OB_PREOP_SUCCESS
}

// ---------------------------------------------------------------------------
// The decision itself
// ---------------------------------------------------------------------------

/// What the driver decided.
enum Verdict {
    /// Let the operation continue.
    Allow,
    /// Complete it with a failure status — `STATUS_INSUFFICIENT_RESOURCES` for
    /// a section, `STATUS_ACCESS_DENIED` for a write. See [`refuse`].
    Block,
    /// The operation could not be turned into a well-formed question. Allowed,
    /// and counted separately so that a volume this driver cannot name is
    /// visible rather than invisible.
    Unresolved,
}

/// Resolve the path, consult the exclusions, ask the service, apply the answer.
///
/// The only caller is [`section_pre_operation`], and the subject it sends is
/// [`SubjectKind::Image`] for that reason. There used to be a second caller —
/// the create gate, sending [`SubjectKind::Process`] — and the argument that
/// removed it is in that callback's documentation. The subject is written here
/// rather than passed in because a gate that cannot refuse has no business
/// naming itself to the service as something that can, and because a parameter
/// with one value is a parameter that can be given the wrong one.
///
/// # Safety
///
/// `data` must be the callback data of the operation being decided, and this
/// must be called from that operation's pre-operation callback, before it
/// returns -- the name information fetched inside [`named`] is owned by the
/// filter manager and is valid only for the duration of the callback.
unsafe fn decide(data: *mut FltCallbackData) -> Verdict {
    // The IRQL gate, and it comes before the name lookup because the name
    // lookup is one of the two things it protects. `FltGetFileNameInformation`
    // is `_IRQL_requires_max_(APC_LEVEL)` (`fltKernel.h` 2843) and so is
    // `FltSendMessage` (`fltKernel.h` 4642), which `ask_service` reaches below.
    //
    // This is reachable: `section_pre_operation` runs for
    // `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`, which the memory manager
    // issues at `DISPATCH_LEVEL` for paging I/O. The registration now carries
    // `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`, which is what normally
    // stops those arriving -- but an unbuffered section acquisition is not
    // paging I/O and arrives anyway, and a check that is only correct because a
    // flag somewhere else is set is not a check.
    //
    // Failing open is the only answer available: there is no IRQL at which this
    // driver could ask the service and still be inside the callback. The
    // operation is allowed and counted as allowed, and the `DISPATCH_LEVEL`
    // case is a gap in what this driver sees rather than a decision it made.
    if !flt::may_block_for_the_service() {
        bump(C_ALLOWED);
        return Verdict::Unresolved;
    }

    let mut dos = [0u16; MAX_PATH_UNITS];
    // SAFETY: `data` is the caller's contract, and `dos` is this frame's own
    // 2 KiB of kernel stack.
    let Some(path) = (unsafe { named(data, &mut dos) }) else {
        // Every way of having no path to ask about has already counted itself.
        // There is no verdict to apply, and `Unresolved` is what the caller
        // turns into "let it continue".
        return Verdict::Unresolved;
    };

    if ask_service(path) {
        // An allow is the freshest word this driver has about the file, so it
        // clears any refusal still standing for it. Without this line a refused
        // path whose file was then re-uploaded, restored or re-allowed would
        // keep vetoing creations until the window expired — the one way the
        // creation veto could stop something the gate had just said yes to.
        REFUSALS.forget(path);
        bump(C_ALLOWED);
        Verdict::Allow
    } else {
        // Recorded before the caller returns the refusal, so that a creation the
        // refusal did not stop can still be stopped: see
        // `av_driver_proto::refusal::RefusalMemo` for the measurement that made
        // this necessary.
        REFUSALS.remember(path, interrupt_time_100ns());
        // The only remaining way to refuse, and therefore the only counter a
        // refusal moves. `blocked_executions` is the field beside it and is
        // always zero — see its own documentation in the protocol.
        bump(C_IMAGES_BLOCKED);
        Verdict::Block
    }
}

/// The DOS path of the file an operation is about, or `None` if there is not
/// one to ask about.
///
/// **The name information is released before this returns**, and that is a
/// change of its own. `decide` used to hold it across `ask`, which is a
/// `FltSendMessage` that can wait five seconds: the filter manager's
/// name-information record is pool, and holding one across a blocking wait on
/// every program launch is pool a busy machine cannot get back. Nothing below
/// the copy needs it — the path lives in `dos` — so it goes back as soon as the
/// copy is made, and there is no early return between the call and the release
/// for it to leak on.
///
/// Every way of answering `None` bumps its own counter *and* `allowed`, so that
/// the caller has nothing left to count but the outcome of the ask.
///
/// # Safety
///
/// `data` must be the callback data of an operation being decided, called from
/// that operation's pre-operation callback.
unsafe fn named<'a>(
    data: *mut FltCallbackData,
    dos: &'a mut [u16; MAX_PATH_UNITS],
) -> Option<&'a [u16]> {
    let mut information: *mut FltFileNameInformation = core::ptr::null_mut();
    // SAFETY: `data` is the caller's contract. The options ask for the
    // normalised form in the device namespace, which is the form the protocol's
    // normaliser is written against, and `FLT_FILE_NAME_QUERY_DEFAULT` lets the
    // filter manager answer from its cache -- the alternative,
    // `FLT_FILE_NAME_QUERY_OPENED`, asks the file system on every open.
    let status = unsafe {
        flt::FltGetFileNameInformation(
            data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &mut information,
        )
    };
    if status != STATUS_SUCCESS || information.is_null() {
        // The name could not be had at all. The protocol has no counter for
        // this -- `unresolved_volume` means specifically that the device path
        // had no DOS name behind it -- so the operation is allowed and counted
        // only as allowed. That gap is recorded here rather than papered over
        // by incrementing a counter whose documented meaning is different.
        bump(C_ALLOWED);
        return None;
    }

    // SAFETY: `information` is non-null and was just returned by a successful
    // `FltGetFileNameInformation`.
    let device = unsafe { (*information).name.as_units() };
    let resolved = device_to_dos_path(device, &VOLUMES, dos);

    // SAFETY: `information` came from `FltGetFileNameInformation`, is non-null,
    // and has not been released on any path -- `device` borrowed it, and the
    // path has been copied out of it by the line above.
    unsafe { flt::FltReleaseFileNameInformation(information) };

    match resolved {
        Ok(path) if !EXCLUSIONS.matches(path) => Some(path),
        // `excluded` is a subset of `allowed`, not an alternative to it: the
        // operation was allowed, and this is why. An operator who adds the two
        // counters together has misread them, which is why the protocol's
        // documentation for `allowed` says it is large by design.
        Ok(_) => {
            bump(C_EXCLUDED);
            bump(C_ALLOWED);
            None
        }
        // A volume with no DOS name is a path the service cannot match against
        // a rule that names a drive letter. Sending it anyway would produce a
        // request that cannot be answered correctly, and blocking on it would
        // be blocking on a question nobody asked.
        Err(_) => {
            bump(C_UNRESOLVED_VOLUME);
            bump(C_ALLOWED);
            None
        }
    }
}

/// Send the request and read the answer. `true` means allow.
///
/// **The subject is always [`SubjectKind::Image`]**, because [`decide`] is the
/// only caller and [`section_pre_operation`] is its only caller. The service
/// reads this field to decide which gate asked, and which gate asked is what
/// decides whether a refusal is possible at all — see that field's own
/// documentation in `av_service::filter_port`. Writing it from a constant here
/// rather than taking it as a parameter means there is no call site that could
/// name a gate it is not.
///
/// Every failure path returns `true`, which is `DecisionPolicy::DEFAULT`'s
/// `on_timeout` rather than this function's opinion: a missed detection is
/// recoverable, and a machine that cannot open its own files is not.
fn ask_service(path: &[u16]) -> bool {
    let port = CLIENT_PORT.load(Ordering::Acquire);
    if port.is_null() {
        // No service is connected. There is nobody to ask, and the answer to
        // "may this run" cannot be "no" when the thing that knows is absent.
        return true;
    }

    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let mut request = DecisionRequestMessage::new(id, SubjectKind::Image);
    // Who asked, for the service's log line and for nothing else.
    //
    // **The answer is not "the program about to run".** A section created
    // during process creation is created on the thread that called
    // `CreateProcess`, so this is the shell, the launcher or whatever else
    // spawned the program -- which is exactly why the service must not
    // terminate it. It is here because the field has been documented and zero
    // since 2026-10-01 and because the one question it settles is which
    // process's acquire a refusal belonged to: the 2026-10-13 fixture's own, or
    // a bystander's.
    //
    // SAFETY: the only caller is `decide`, whose IRQL gate is what makes this
    // `_IRQL_requires_max_(PASSIVE_LEVEL)` call legal. The function takes no
    // pointer, reads a field of the current thread's process, and cannot fault;
    // `flt.rs` says why it is not one of the `FltGetRequestorProcess*` family
    // this module puts out of bounds.
    request.process_id = unsafe { flt::PsGetCurrentProcessId() } as usize as u32;
    if request.set_path(path).is_err() {
        // A path longer than the protocol's maximum. The request cannot carry
        // it truncated -- a truncated path is a different file -- so it is not
        // sent at all. `C_ALLOWED` is bumped by the caller, once: this returns
        // `true` and `decide` counts the outcome, so counting it here as well
        // would make an oversize path read as two allowed operations.
        bump(C_OVERSIZE_PATH);
        return true;
    }

    let mut reply = DecisionReplyMessage::new(0, Decision::Allow);
    // A *capacity*, and a capacity for the payload. The filter manager consumes
    // the reply header itself — its `status` is this call's return value and its
    // `message_id` is the correlation — and copies only what follows it into
    // the buffer below, returning that smaller size. Passing the whole
    // structure's size here is what made every answer look truncated: the reply
    // length came back as 32 against an expectation of 48, and this function's
    // contract turns an unreadable reply into an allow. See
    // `DecisionReplyMessage::PAYLOAD_SIZE`.
    let mut reply_length = DecisionReplyMessage::PAYLOAD_SIZE as u32;

    // The timeout is the protocol's, converted from its unit to the filter
    // manager's. `DecisionPolicy::DEFAULT.on_timeout` is `Allow`, so there is
    // no separate branch for expiry: a non-success status, `STATUS_TIMEOUT`
    // among them, falls through to the `true` below.
    //
    // `relative_timeout_100ns` carries a sign, and the sign is what makes it a
    // wait at all -- see its own documentation for what an unsigned conversion
    // did to every decision on 2026-10-01.
    let mut timeout = DecisionPolicy::DEFAULT.relative_timeout_100ns();
    let mut client = port;

    // SAFETY: `FILTER` is the registered filter while a callback is running,
    // because the filter manager does not call into an unregistered filter.
    // `client` is a local copy, so the callee's write-back on a dead connection
    // cannot land in the static that a disconnect callback is clearing. Both
    // buffers are live locals of the sizes passed, and the timeout is non-null,
    // which is what makes a stalled service a delay rather than a hang.
    let (out, out_length) = outbound(core::ptr::addr_of_mut!(request));
    let status = unsafe {
        flt::FltSendMessage(
            FILTER.load(Ordering::Acquire),
            &mut client,
            out,
            out_length,
            // The payload's address, not the structure's. The header in front
            // of it never makes the return trip; see `reply_length` above.
            reply.payload_ptr().cast::<c_void>(),
            &mut reply_length,
            &mut timeout,
        )
    };

    if status != STATUS_SUCCESS {
        // Every failure lands here: no service, a dead connection, an expiry.
        // They share a counter because they share an outcome -- the driver
        // asked and did not get an answer -- and telling them apart would need
        // the service to be up, which is the thing that is missing.
        bump(C_TIMED_OUT);
        bump(C_ALLOWED);
        return true;
    }

    // A reply this driver cannot tie to its own request is not an answer. The
    // identifier is monotonic and the path tag is a second, independent check,
    // so a reply meant for a request that has already been answered would have
    // to match both against a request that no longer exists. That is the one
    // bug this protocol is built to make impossible rather than to detect, and
    // it is checked here because the driver is where a stale verdict applied to
    // the wrong file would do its damage.
    // The payload, because that is what the filter manager copies and what it
    // reports in `ReplyLength` on the way out. The whole-structure comparison
    // that used to stand here rejected every reply the service ever sent.
    if reply_length as usize != DecisionReplyMessage::PAYLOAD_SIZE {
        return true;
    }
    if reply.request_id != id || reply.path_tag != request.path_tag() {
        return true;
    }
    match Decision::from_wire(reply.decision) {
        // A value this protocol does not define is not a reason to refuse an
        // execution: it is a reason to distrust the message.
        None => true,
        Some(Decision::Allow) => true,
        Some(Decision::Block) => false,
    }
}

/// How many header-only events may be waiting for a worker thread at once.
///
/// A write post-operation runs for every write on the machine, and the routine
/// it queues has to win a worker thread and then the port before it retires.
/// Without a bound, a burst of writes would queue blocks faster than they
/// drain, and "an event per write" would be a memory leak with a protocol name.
/// 1024 blocks of 32 bytes is 32 KiB, which is a number chosen to be small
/// enough that the bound is never the reason a machine runs out of pool.
///
/// It was `MAX_PENDING_WRITES` until 2026-10-09, when the driver-state report
/// began using the same block through the same queue. The number did not
/// change; the name did, because it no longer counts one thing.
const MAX_PENDING_EVENTS: usize = 1024;

/// How many driver-state reports may be waiting, which is a different question.
///
/// Separate from [`MAX_PENDING_EVENTS`], and the reason is the failure the two
/// counters have: a busy machine — a build, an unpacking archive — can fill a
/// thousand write slots legitimately, and a state report that had to compete
/// for one of them would be dropped by exactly the machine that has the most
/// processes starting.
///
/// Eight rather than four since 2026-10-09, because a connection reports
/// **three** registrations rather than one — the process notification, the
/// object callbacks and the registry callback — so four was a single
/// connection's worth and had silently become a cap on how much of one report a
/// reconnect could keep. The number is still a bound on reconnects rather than
/// on machines: a report is queued once per registration per connection, and a
/// reconnect storm must not queue more work than the connects that caused it.
const MAX_PENDING_STATE_EVENTS: usize = 8;

/// How many process-start notifications may be waiting for a worker thread.
///
/// Not [`MAX_PENDING_EVENTS`], because the blocks are not the same size: a
/// process block carries the image name (2 KiB) where a write block carries
/// nothing, so the same count would be a bound on two different quantities. 64
/// blocks of about 2 KiB is 128 KiB, and a machine that has 64 processes
/// starting at once while the service is not draining is a machine with a
/// bigger problem than a dropped notification.
const MAX_PENDING_PROCESS_EVENTS: usize = 64;

/// How many rename and delete notifications may be waiting for a worker
/// thread.
///
/// The same size as [`MAX_PENDING_PROCESS_EVENTS`] and for the same reason: a
/// block of this kind carries a path, so it is about 2 KiB, and the count is a
/// bound on pool rather than on anything a consumer can observe. The number a
/// ransomware burst produces is exactly the case this has to survive without
/// becoming a leak, so it is small on purpose: the events over the cap are
/// dropped, and what a consumer does with a burst is read from the ones that
/// arrived rather than wait for the tail.
const MAX_PENDING_FILE_EVENTS: usize = 64;

/// How many registry notifications may be waiting for a worker thread.
///
/// The same size as [`MAX_PENDING_FILE_EVENTS`], and the cap matters more here:
/// a registry callback sees every write to `HKCU\Software`, and a process
/// looping on `RegSetValueEx` would otherwise queue a block per write. Sixty-four
/// blocks of about 2 KiB is 128 KiB, and what is over the cap is dropped — the
/// same trade the file callbacks make, and the reason a consumer reads a burst
/// from what arrived rather than waiting for the tail.
const MAX_PENDING_REGISTRY_EVENTS: usize = 64;

/// How long a driver-state report waits for the service to ask for it.
///
/// **Why this event waits longer than every other event.** A state report is
/// queued from the filter manager's connect callback
/// ([`defer_driver_state_event`]'s documentation says why it is deferred rather
/// than sent from there), so it is sent in the moment between the service's
/// `FilterConnectCommunicationPort` returning and its first `FilterGetMessage`:
/// a window in which the client port is live and **no receive is outstanding**.
/// A send with a zero timeout in that window is the one case where this driver's
/// own rule — "a timeout of zero returns immediately" — can cost a message that
/// has no second copy. The two are the process-notification status and the
/// object-callback status, which are the facts `wenle service status` exists to
/// report, and their absence is indistinguishable from a driver that registered
/// nothing at all. That is the shape of the 2026-10-10 field record:
/// `0 start(s): 0 examined` beside no registration line.
///
/// **What is not settled here, and what this does not depend on.** Whether a
/// no-reply send that finds no receive outstanding is *queued* for the client's
/// next `FilterGetMessage` or *dropped* is not something this workspace can
/// answer: `fltKernel.h` 4642 declares `FltSendMessage` with no documentation of
/// `Timeout` beyond its type, and no measurement of this driver exists that tells
/// the two apart. So this is not written as "the reports are being dropped" —
/// that would be a claim without evidence. It is written as the value that is
/// correct under **either** reading: if the message is queued, a bounded wait
/// changes nothing; if it is dropped, the wait is the difference between the
/// service reporting its registrations and never hearing about them.
///
/// Two seconds from the moment of the send, which is a relative (`LARGE_INTEGER`)
/// wait and therefore negative. Long enough for a service that is still starting
/// up and has work in front of its first receive; short enough that a client
/// which connected and then stopped asking costs a worker thread two seconds
/// rather than the life of the connection.
///
/// **What a positive value here would be**: `Timeout` is an absolute time in
/// 100-nanosecond units since 1601 when positive, so `+2s` is a date in 1601 and
/// the wait would expire before it began. That is a mistake this file has made
/// once and recorded — [`DecisionPolicy::relative_timeout_100ns`], where the sign
/// is part of the type's contract rather than a caller's habit.
const STATE_REPORT_TIMEOUT_100NS: i64 = -20_000_000;

/// How long an ordinary event's send waits for the service to be reading.
///
/// **Not zero, and this is the value a measurement changed.** The driver used to
/// send every event but a state report with a timeout of zero, on the reasoning
/// that the events are repeats in effect and a blocked worker thread stalls the
/// ones behind it. The first half of that reasoning was wrong for the registry
/// events, and 2026-10-18 measured it in the test VM: forty keys deleted in one
/// tight loop, forty delete events queued (the service's log showed consecutive
/// sequence numbers with exactly one consumed per key that never arrived), and
/// thirteen received. The twenty-seven others were not dropped before the queue
/// and not refused by the service — they were sent into the microseconds the
/// receive thread spends between one `FilterGetMessage` returning and the next
/// one being issued, and a send that does not wait fails into that gap. The same
/// forty keys deleted 150 ms apart arrive forty for forty, which is what made the
/// loss look like capacity rather than a race.
///
/// A hundred milliseconds, negative because the timeout is relative. It costs
/// nothing when a receive is outstanding, which is nearly always; when none is,
/// the cap on each pending queue (sixty-four) bounds the worst case at six
/// seconds of one worker thread, and a service that has stopped reading by
/// definition cannot answer a scan either.
const ORDINARY_EVENT_TIMEOUT_100NS: i64 = -1_000_000;

/// How many header-only events are queued, incremented by the two `defer_`
/// functions and decremented by [`event_worker`].
static PENDING_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// How many driver-state reports are queued.
static PENDING_STATE_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// How many process-start notifications are queued, incremented by
/// [`process_notify`] and decremented by [`process_event_worker`].
///
/// The filter manager drains queued work items before `FltUnregisterFilter`
/// returns, so this is zero again after an unload rather than a count that
/// outlives the filter.
static PENDING_PROCESS_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// How many rename and delete notifications are queued, incremented by
/// [`defer_file_event`] and decremented by [`file_event_worker`].
static PENDING_FILE_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// How many registry notifications are queued, incremented by
/// [`defer_registry_event`] and decremented by [`registry_event_worker`].
static PENDING_REGISTRY_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// Which counter an event of this action is counted in.
///
/// One function rather than a field in the block, because a stored counter
/// index is a second copy of a fact the block already carries and the copy is
/// what goes stale. Both ends of the queue call this: the `defer_` function
/// that checks the cap and the worker that releases the slot, so the count
/// cannot drift by being released against the wrong counter.
fn pending_counter(action: EventAction) -> &'static AtomicUsize {
    match action {
        EventAction::StateChanged => &PENDING_STATE_EVENTS,
        // The path-carrying blocks have their own caps: a rename burst and a
        // process-start burst are different quantities, and one counter for both
        // would let either starve the other.
        EventAction::FileRenamed | EventAction::FileDeleted => &PENDING_FILE_EVENTS,
        // Registry notifications carry a path too, and have their own cap for
        // the reason above: a key-writing loop and a rename burst are different
        // quantities and one counter for both would let either starve the other.
        EventAction::RegistryChanged => &PENDING_REGISTRY_EVENTS,
        _ => &PENDING_EVENTS,
    }
}

/// One event with no payload on its way to the service.
///
/// The fields are what [`EventMessage::new`] needs plus the two it does not
/// take, and no more: the message itself is 3168 bytes (2128 before the
/// registry value buffer, 2026-10-19), and building it on the worker thread
/// rather than on the path that saw the event is part of what deferring buys.
///
/// `repr(C)` since 2026-10-09, when [`PendingProcessEvent`] began holding one of
/// these as its first member. It never crosses into C — the filter manager
/// holds the pointer and hands it back without reading through it — but the
/// nesting is a layout obligation, and `repr(Rust)` is free to reorder.
#[repr(C)]
struct PendingEvent {
    sequence: u64,
    now_100ns: u64,
    /// The process the event is about, or zero when it is about none.
    process_id: u32,
    /// Action-specific: an `NTSTATUS` for a state report, zero otherwise.
    detail: u32,
    subject: SubjectKind,
    action: EventAction,
}

/// A process-start (or refused-start) notification on its way to the service.
///
/// The name is in the **DOS** namespace (`C:\Windows\notepad.exe`), converted in
/// the callback rather than on the worker. That is a deliberate inversion of the
/// old arrangement: the creation veto needs the DOS path while `CreationStatus`
/// is still writable, and that is only during the callback. The conversion is a
/// memory lookup over the primed volume table, so what the callback gives up is
/// a 2 KiB scratch buffer on its own stack and nothing else.
///
/// `#[repr(C)]` so that `event` is at offset zero: [`process_event_worker`]
/// receives a `*mut PendingProcessEvent` and reads the header out of it, and
/// the free path in [`queue_pending`] has already cast the same pointer to
/// something else.
#[repr(C)]
struct PendingProcessEvent {
    event: PendingEvent,
    /// The creating process, from `PS_CREATE_NOTIFY_INFO::ParentProcessId`.
    ///
    /// Read in [`process_notify`] rather than on the worker because the
    /// structure it comes from is only valid during that callback. Zero when
    /// the creator has already exited.
    parent_process_id: u32,
    /// Meaningful length of `path`. Not an allocation size.
    units: u32,
    /// The image as a DOS path, in UTF-16 code units, no terminating NUL.
    path: [u16; MAX_PATH_UNITS],
}

/// A rename or delete notification on its way to the service.
///
/// The path is the **target** for a rename and the deleted file for a delete,
/// already in the DOS namespace because the conversion needs
/// `FltGetFileNameInformation`'s result, which expires when the callback
/// returns.
///
/// `#[repr(C)]` for the same reason [`PendingProcessEvent`] has it: the worker
/// is handed a pointer to the header and reads through it.
///
/// A registry notification reuses this structure — see [`defer_registry_event`]
/// — because its block is the same shape: a header and one path. Two structures
/// that must stay byte-identical are two structures that will not.
#[repr(C)]
struct PendingFileEvent {
    event: PendingEvent,
    /// Meaningful length of `path`. Not an allocation size.
    units: u32,
    /// The file, in UTF-16 code units, no terminating NUL.
    path: [u16; MAX_PATH_UNITS],
}

/// A registry notification on its way to the service, with the value's data.
///
/// A separate structure from [`PendingFileEvent`] since 2026-10-19, when the
/// value buffer was added. It is separate because only one class of registry
/// event has a value and every file event would otherwise pay a kilobyte of
/// non-paged pool for a field it would leave zero.
///
/// `#[repr(C)]` for the same reason [`PendingProcessEvent`] is: the worker
/// receives a pointer to it and reads the header out of it at offset zero.
#[repr(C)]
struct PendingRegistryEvent {
    event: PendingEvent,
    /// Meaningful length of `path`. Not an allocation size.
    units: u32,
    /// Meaningful length of `value`. Zero when the event carried none.
    value_units: u32,
    /// The `REG_*` type, zero when there is no value.
    value_type: u32,
    /// [`EVENT_VALUE_TRUNCATED`] when the value did not fit.
    value_flags: u32,
    /// The key's path, with `\` and the value name appended for a value.
    path: [u16; MAX_PATH_UNITS],
    /// The value's data as text, no terminating NUL. `;` separates the strings
    /// of a `REG_MULTI_SZ`.
    value: [u16; MAX_VALUE_UNITS],
}

/// Hand a filled block to a worker thread, or free it and return.
///
/// Extracted from what was [`defer_write_event`]'s own tail when a second and
/// third kind of block began queueing through it. The sequence is the same one
/// the write path has used since the 10-01 fix, in the same order, because that
/// order is what the fix's own reasoning is about: check the IRQL and the cap
/// before allocating, take the filter handle before queueing, and give back
/// exactly what was not handed over on a failed queue.
///
/// # Safety
///
/// `block` must be a live non-paged allocation made with `tag`, at least as
/// large as the structure the routine that will run reads through it, and
/// reachable from nowhere else. `filter` must be non-null and registered.
unsafe fn queue_pending(
    block: *mut c_void,
    tag: u32,
    routine: flt::GenericWorkItemRoutine,
    pending: &'static AtomicUsize,
    filter: flt::FltFilter,
) {
    // SAFETY: `FltAllocateGenericWorkItem` is
    // `_IRQL_requires_max_(DISPATCH_LEVEL)` (`fltKernel.h` 4753) and allocates
    // from non-paged pool, so it is legal at every IRQL either caller runs at.
    // It is the filter manager's own work item rather than a `WORK_QUEUE_ITEM`:
    // `FltUnregisterFilter` waits for the filter manager's items and for nobody
    // else's.
    let work = unsafe { flt::FltAllocateGenericWorkItem() };
    if work.is_null() {
        // SAFETY: allocated by the caller, not queued, so this is its only
        // reference.
        unsafe { flt::ExFreePoolWithTag(block, tag) };
        return;
    }

    pending.fetch_add(1, Ordering::Relaxed);

    // SAFETY: `work` is the filter manager's own work item and `filter` is the
    // registered filter, which the caller's contract guarantees is not null.
    // `block` outlives this call: `routine` is what frees it, and the filter
    // manager does not run that routine until it is queued.
    let status =
        unsafe { flt::FltQueueGenericWorkItem(work, filter, routine, flt::CRITICAL_WORK_QUEUE, block) };

    if status != STATUS_SUCCESS {
        // The item was not queued, so no routine will run and this call owns
        // both allocations. That is the header's contract for a failed queue,
        // not an assumption: `FltQueueGenericWorkItem` returns the work item to
        // the caller and the caller still has to release it.
        pending.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: neither has been given to the filter manager.
        unsafe {
            flt::FltFreeGenericWorkItem(work);
            flt::ExFreePoolWithTag(block, tag);
        }
    }
}

/// Hand a write notification to a worker thread, which will send it.
///
/// # Why the notification is deferred, and what the dump showed
///
/// `FltSendMessage` is `_IRQL_requires_max_(APC_LEVEL)` (`fltKernel.h` 4642)
/// and a write post-operation can be entered at `DISPATCH_LEVEL`, so this
/// driver used to check the IRQL and drop the event when it was too high. That
/// check was correct and the machine bugchecked anyway, in the second a service
/// connected (2026-09-27, and again 2026-10-01), which is the second this
/// function stopped returning at its null-port check.
///
/// The dump from 09-27 was read on 10-01 and it does not fault in this driver
/// at all. It faults at `ntoskrnl.exe +0x40b080`, the first instruction of
/// `IoGetRequestorProcess` -- `test dword ptr [rcx+10h], 2000h`, reading
/// `Irp->Flags` -- reached with a `PIRP` that could not be read, and the caller
/// is `WdFilter.sys`'s `IRP_MJ_WRITE` post-operation (`0x140003430`, the
/// callback its own registration table names), which runs *after* this filter's
/// write post-operation at the lower altitude. `WdFilter` calls the filter
/// manager's `FltGetRequestorProcess`, which for callback data whose
/// `FLTFL_CALLBACK_DATA_IRP_OPERATION` bit is set reads the IRP from
/// `Data - 0xB8` and passes it on with no null check; the dump shows that bit
/// set on the callback data of *our* write and clear on the eleven other write
/// callbacks the same dump happens to hold. What makes our write's data
/// different from theirs is the only thing this filter does on that path.
///
/// # What this changes, and what it does not
///
/// The send moves off the callback and onto a system worker thread at
/// `PASSIVE_LEVEL`, where it is legal for every write rather than for the
/// writes that happened to arrive below `APC_LEVEL`. The event's fields are
/// copied into a pool block first, because a callback cannot leave anything on
/// its own stack behind.
///
/// The path is still deliberately left empty, and now for a second reason:
/// `FltGetFileNameInformation`'s result is valid only for the duration of the
/// callback, and this no longer runs inside one.
///
/// It takes the writing process's identifier and nothing else. That number is
/// read by the caller from the current thread rather than from the callback
/// data, because the callback data is not valid here -- `FltGetRequestorProcess`
/// on it is what faulted on 2026-09-27 -- and the identifier is the one fact
/// this path can take from a write safely. The path remains empty: resolving it
/// needs `FltGetFileNameInformation` inside the callback, and that result would
/// be expired before the worker runs.
///
/// Safe, not `unsafe`: the handle it passes to `FltQueueGenericWorkItem` comes
/// from the `FILTER` static, and the driver sets that before `FltStartFiltering`
/// and clears it in the unload callback, so no callback of this filter can run
/// with a null or stale one. That is an invariant this module keeps rather than
/// a precondition its caller has to know.
fn defer_write_event(process_id: u32) {
    // The IRQL this can be entered at is `DISPATCH_LEVEL`, and
    // `FltAllocateGenericWorkItem` and `FltQueueGenericWorkItem` are capped
    // there. Both facts are in `flt.rs`; this is where they meet.
    if !flt::may_defer_for_the_service() {
        return;
    }

    // A dropped event is silent rather than counted, for the reason the send
    // below gives. At the cap the event is dropped rather than queued: the
    // alternative is unbounded pool.
    if PENDING_EVENTS.load(Ordering::Relaxed) >= MAX_PENDING_EVENTS {
        return;
    }

    // The filter the work item will be tied to. Null before `FltStartFiltering`
    // and after `FltUnregisterFilter`; no callback runs in either window, so
    // this is a guard rather than a case, and it guards the one call below that
    // would take a null filter.
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return;
    }

    // SAFETY: `ExAllocatePool2` with non-paged flags is
    // `_IRQL_requires_max_(DISPATCH_LEVEL)` (`wdm.h` 25427), which is as high as
    // this runs. A null return is the pool refusing, and it is handled.
    let block = unsafe {
        flt::ExAllocatePool2(
            flt::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<PendingEvent>(),
            flt::EVENT_TAG,
        )
    }
    .cast::<PendingEvent>();
    if block.is_null() {
        return;
    }

    // SAFETY: `block` came from the non-paged pool just above, is
    // `size_of::<PendingEvent>()` bytes, and nothing else can reach it until it
    // is queued.
    let pending = unsafe { &mut *block };
    pending.sequence = NEXT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // Read now rather than in the worker: that is what makes the timestamp the
    // time of the write instead of the time of the send.
    pending.now_100ns = interrupt_time_100ns();
    // The process whose thread issued the write, read by the caller before it
    // got here. The write's own path is still deliberately not read: resolving
    // it needs the callback, and the callback has returned.
    pending.process_id = process_id;
    pending.detail = 0;
    pending.subject = SubjectKind::File;
    pending.action = EventAction::FileWritten;

    // SAFETY: as documented on `queue_pending`; `block` was allocated with
    // `EVENT_TAG` and `filter` was checked above.
    unsafe {
        queue_pending(
            block.cast::<c_void>(),
            flt::EVENT_TAG,
            event_worker,
            &PENDING_EVENTS,
            filter,
        );
    }
}

/// Hand a rename or delete notification to a worker thread, which will send it.
///
/// Deferred for the same reason every other event is: `FltSendMessage` is
/// `_IRQL_requires_max_(APC_LEVEL)` (`fltKernel.h` 4642), and a set-information
/// pre-operation can be entered above that.
///
/// Takes an already-converted DOS path rather than resolving one, because the
/// callback had to hold `FltGetFileNameInformation`'s result while it was still
/// valid, and this function runs after the callback may have returned.
///
/// A dropped event is silent rather than counted, for the reason
/// [`defer_write_event`] gives: `DriverStats` has no field for one.
fn defer_file_event(action: EventAction, process_id: u32, detail: u32, path: &[u16]) {
    if !flt::may_defer_for_the_service() {
        return;
    }
    if PENDING_FILE_EVENTS.load(Ordering::Relaxed) >= MAX_PENDING_FILE_EVENTS {
        return;
    }
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return;
    }

    // SAFETY: `ExAllocatePool2` with non-paged flags is
    // `_IRQL_requires_max_(DISPATCH_LEVEL)` (`wdm.h` 25427), which is as high as
    // this can run. A null return is the pool refusing, and it is handled.
    let block = unsafe {
        flt::ExAllocatePool2(
            flt::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<PendingFileEvent>(),
            flt::FILE_EVENT_TAG,
        )
    }
    .cast::<PendingFileEvent>();
    if block.is_null() {
        return;
    }

    // SAFETY: `block` came from the non-paged pool just above, is
    // `size_of::<PendingFileEvent>()` bytes, and nothing else can reach it
    // until it is queued.
    let pending = unsafe { &mut *block };
    pending.event.sequence = NEXT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // Read here rather than on the worker: the timestamp is the time of the
    // rename or delete, not of the send.
    pending.event.now_100ns = interrupt_time_100ns();
    pending.event.process_id = process_id;
    pending.event.detail = detail;
    pending.event.subject = SubjectKind::File;
    pending.event.action = action;
    pending.units = path.len() as u32;
    pending.path[..path.len()].copy_from_slice(path);

    // SAFETY: as documented on `queue_pending`; `block` was allocated with
    // `FILE_EVENT_TAG` and `filter` was checked above.
    unsafe {
        queue_pending(
            block.cast::<c_void>(),
            flt::FILE_EVENT_TAG,
            file_event_worker,
            &PENDING_FILE_EVENTS,
            filter,
        );
    }
}

/// Hand a registry notification to a worker thread, which will send it.
///
/// Deferred for the same reason the file events are — `FltSendMessage` is
/// `_IRQL_requires_max_(APC_LEVEL)` — and for one more: the path is built in the
/// callback out of a string `CmCallbackGetKeyObjectIDEx` allocated, which is
/// released before the callback returns. Nothing of it can be left for later.
///
/// The block is a [`PendingRegistryEvent`]. It was a [`PendingFileEvent`] until
/// 2026-10-19: the shapes agreed until a value's data had to travel too, and
/// widening the shared structure would have charged every file event a
/// kilobyte of non-paged pool for a buffer it would leave zero.
///
/// `detail` is one of the `EventAction::REGISTRY_*` codes — what kind of change
/// this is — because a registry event's path alone does not say whether a key
/// was created, a value written, or a key deleted.
///
/// `value` is the data of a value that is being set, and it is **copied here**
/// rather than on the worker: the caller's buffer belongs to the configuration
/// manager and is valid only while the callback runs.
fn defer_registry_event(
    detail: u32,
    process_id: u32,
    path: &[u16],
    value: Option<RegistryValue>,
) {
    if !flt::may_defer_for_the_service() {
        return;
    }
    if PENDING_REGISTRY_EVENTS.load(Ordering::Relaxed) >= MAX_PENDING_REGISTRY_EVENTS {
        return;
    }
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return;
    }

    // SAFETY: `ExAllocatePool2` with non-paged flags is
    // `_IRQL_requires_max_(DISPATCH_LEVEL)` (`wdm.h` 25427), which is as high as
    // this can run. A null return is the pool refusing, and it is handled.
    let block = unsafe {
        flt::ExAllocatePool2(
            flt::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<PendingRegistryEvent>(),
            flt::REGISTRY_EVENT_TAG,
        )
    }
    .cast::<PendingRegistryEvent>();
    if block.is_null() {
        return;
    }

    // SAFETY: `block` came from the non-paged pool just above, is
    // `size_of::<PendingRegistryEvent>()` bytes, and nothing else can reach it
    // until it is queued.
    let pending = unsafe { &mut *block };
    pending.event.sequence = NEXT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // Read here rather than on the worker: the timestamp is the time of the
    // registry operation, not of the send.
    pending.event.now_100ns = interrupt_time_100ns();
    pending.event.process_id = process_id;
    pending.event.detail = detail;
    pending.event.subject = SubjectKind::Registry;
    pending.event.action = EventAction::RegistryChanged;
    pending.units = path.len() as u32;
    pending.path[..path.len()].copy_from_slice(path);
    // The value's data is read here for the same reason and a harder one: the
    // buffer is the caller's, and after this callback returns it is not this
    // driver's to read.
    match value {
        Some(value) => {
            // SAFETY: `value.data` is that caller-owned buffer, `value.bytes`
            // its stated length, and this call is inside the callback that
            // supplied it. `copy_registry_value` reads no further than the
            // length it is given.
            let (units, truncated) =
                unsafe { copy_registry_value(value, &mut pending.value) };
            pending.value_units = units as u32;
            pending.value_type = value.kind;
            pending.value_flags = if truncated {
                EVENT_VALUE_TRUNCATED
            } else {
                0
            };
        }
        None => {
            pending.value_units = 0;
            pending.value_type = 0;
            pending.value_flags = 0;
        }
    }

    // SAFETY: as documented on `queue_pending`; `block` was allocated with
    // `REGISTRY_EVENT_TAG` and `filter` was checked above.
    unsafe {
        queue_pending(
            block.cast::<c_void>(),
            flt::REGISTRY_EVENT_TAG,
            registry_event_worker,
            &PENDING_REGISTRY_EVENTS,
            filter,
        );
    }
}

/// Tell the service what one of the driver's registrations answered.
///
/// Queued rather than sent, for the same reason a write notification is, and
/// the reason is stronger here: this runs inside the filter manager's connect
/// callback, and a send from there would be aimed at a client that has not yet
/// issued its first receive. A worker thread runs after the connect has
/// returned, when the client is asking — and it is given a bounded wait rather
/// than none, because "asking" is not guaranteed to have happened yet either:
/// see [`STATE_REPORT_TIMEOUT_100NS`].
///
/// `MAX_PENDING_STATE_EVENTS` and not `MAX_PENDING_EVENTS`: these are the
/// reports that say whether anything is registered at all, and a machine busy
/// enough to fill a thousand write slots is exactly the machine whose process
/// list a user would want to trust.
///
/// `subject` is which registration this is about, and it is a parameter rather
/// than a constant since 2026-10-09 because there are now three of them:
/// [`SubjectKind::Driver`] is `PsSetCreateProcessNotifyRoutineEx`,
/// [`SubjectKind::Protection`] is `ObRegisterCallbacks`, and
/// [`SubjectKind::Registry`] is `CmRegisterCallbackEx`. They are three different
/// facts about the machine and a service that could not tell them apart would
/// have to guess which one had failed — which is the whole reason the report
/// exists.
fn defer_driver_state_event(status: i32, subject: SubjectKind) {
    if !flt::may_defer_for_the_service() {
        return;
    }
    if PENDING_STATE_EVENTS.load(Ordering::Relaxed) >= MAX_PENDING_STATE_EVENTS {
        return;
    }
    let filter = FILTER.load(Ordering::Acquire);
    if filter.is_null() {
        return;
    }

    // SAFETY: as in `defer_write_event`. Non-paged, and the size is the
    // structure this casts to.
    let block = unsafe {
        flt::ExAllocatePool2(
            flt::POOL_FLAG_NON_PAGED,
            core::mem::size_of::<PendingEvent>(),
            flt::EVENT_TAG,
        )
    }
    .cast::<PendingEvent>();
    if block.is_null() {
        return;
    }

    // SAFETY: allocated just above, `size_of::<PendingEvent>()` bytes, and
    // nothing else can reach it until it is queued.
    let pending = unsafe { &mut *block };
    pending.sequence = NEXT_EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    pending.now_100ns = interrupt_time_100ns();
    // A registration status is about the driver, so there is no process
    // responsible. Zero is this protocol's "none", and the service's own
    // connection event uses its own pid for the opposite reason -- that event
    // is about the client.
    pending.process_id = 0;
    // The exact `NTSTATUS`. `EventMessage::detail` is documented as
    // action-specific and names an `NTSTATUS` first, and the alternative --
    // reporting a `DriverState` -- cannot carry the code, which is the thing a
    // reader needs to look up.
    pending.detail = status as u32;
    pending.subject = subject;
    pending.action = EventAction::StateChanged;

    // SAFETY: as above.
    unsafe {
        queue_pending(
            block.cast::<c_void>(),
            flt::EVENT_TAG,
            event_worker,
            &PENDING_STATE_EVENTS,
            filter,
        );
    }
}

/// The routine a queued header-only event runs on.
///
/// Called on a system worker thread at `PASSIVE_LEVEL`, which is the point of
/// the deferral: the send below is legal here for every event, including the
/// ones whose callback ran at `DISPATCH_LEVEL` and which the write path used to
/// drop on the floor.
///
/// One routine for both kinds of block, because both are a [`PendingEvent`] and
/// the fields it reads are the same four. The counter to release is derived
/// from the block's own action by [`pending_counter`] rather than passed in,
/// because the work item carries one context pointer and a counter index would
/// have to live in the block — a second copy of a fact it already holds.
///
/// # Safety
///
/// Called by the filter manager with the work item and the `context` that
/// [`defer_write_event`] or [`defer_driver_state_event`] queued, which is
/// always a block one of them allocated.
extern "system" fn event_worker(
    work_item: flt::FltGenericWorkItem,
    _filter: *mut c_void,
    context: *mut c_void,
) {
    // SAFETY: `context` is that block. It is read once, here, and nothing else
    // holds a reference to it.
    let action = unsafe {
        let pending = &*context.cast::<PendingEvent>();
        send_event(
            pending.sequence,
            pending.now_100ns,
            pending.subject,
            pending.action,
            pending.process_id,
            // A state report or a write notification names no creator. Zero is
            // this protocol's "none", the same value the field's documentation
            // gives every action other than a process start.
            0,
            pending.detail,
            &[],
            &[],
            0,
            false,
        );
        pending.action
    };

    // SAFETY: `work_item` is this routine's own, and the filter manager's
    // contract is that its routine is what frees it. Both are freed here
    // because this is the only point at which either is known to be finished
    // with, and the counter is decremented last so that it never describes a
    // block that has already been released.
    unsafe {
        flt::FltFreeGenericWorkItem(work_item);
        flt::ExFreePoolWithTag(context, flt::EVENT_TAG);
    }
    pending_counter(action).fetch_sub(1, Ordering::Relaxed);
}

/// The routine a queued process-start notification runs on.
///
/// It only sends; the path in the block is already the DOS form, because
/// [`process_notify`] had to have it while `CreationStatus` was still writable.
/// What is still deferred is the send itself, for the reason it always was:
/// `FltSendMessage` is `_IRQL_requires_max_(APC_LEVEL)` and this callback can be
/// entered at a higher one.
///
/// # Safety
///
/// Called by the filter manager with the work item and the `context` that
/// [`process_notify`] queued, which is always a `PendingProcessEvent` it
/// allocated.
extern "system" fn process_event_worker(
    work_item: flt::FltGenericWorkItem,
    _filter: *mut c_void,
    context: *mut c_void,
) {
    // SAFETY: `context` is that block. Every field read here is read once, and
    // nothing else holds a reference to it.
    unsafe {
        let pending = &*context.cast::<PendingProcessEvent>();
        let units = (pending.units as usize).min(MAX_PATH_UNITS);
        send_process_event(
            pending.event.sequence,
            pending.event.now_100ns,
            pending.event.action,
            pending.event.process_id,
            pending.parent_process_id,
            &pending.path[..units],
        );
    }

    // SAFETY: as in `event_worker` -- this routine's own work item, the block
    // the queueing callback allocated, freed once, counter last.
    unsafe {
        flt::FltFreeGenericWorkItem(work_item);
        flt::ExFreePoolWithTag(context, flt::PROCESS_EVENT_TAG);
    }
    PENDING_PROCESS_EVENTS.fetch_sub(1, Ordering::Relaxed);
}

/// The routine a queued rename or delete notification runs on.
///
/// It only sends: the path in the block is already the DOS form, and the
/// `detail` that says whether it is a source name or a target one was decided
/// in the callback, where the information buffer was still valid.
///
/// # Safety
///
/// Called by the filter manager with the work item and the `context` that
/// [`defer_file_event`] queued, which is always a `PendingFileEvent` it
/// allocated.
extern "system" fn file_event_worker(
    work_item: flt::FltGenericWorkItem,
    _filter: *mut c_void,
    context: *mut c_void,
) {
    // SAFETY: `context` is that block. Every field read here is read once, and
    // nothing else holds a reference to it.
    let action = unsafe {
        let pending = &*context.cast::<PendingFileEvent>();
        let units = (pending.units as usize).min(MAX_PATH_UNITS);
        send_event(
            pending.event.sequence,
            pending.event.now_100ns,
            SubjectKind::File,
            pending.event.action,
            pending.event.process_id,
            // A file event has no creator; zero is this protocol's "none".
            0,
            pending.event.detail,
            &pending.path[..units],
            &[],
            0,
            false,
        );
        pending.event.action
    };

    // SAFETY: as in `event_worker` -- this routine's own work item, the block
    // the queueing callback allocated, freed once, counter last.
    unsafe {
        flt::FltFreeGenericWorkItem(work_item);
        flt::ExFreePoolWithTag(context, flt::FILE_EVENT_TAG);
    }
    pending_counter(action).fetch_sub(1, Ordering::Relaxed);
}

/// The routine a queued registry notification runs on.
///
/// It only sends: the path in the block is already the registry namespace form,
/// resolved in the callback while the configuration manager's object was still
/// valid, and `detail` was read there from the `REG_NOTIFY_CLASS`. The value's
/// data, when there was one, was copied in the same callback for the same
/// reason.
///
/// # Safety
///
/// Called by the filter manager with the work item and the `context` that
/// [`defer_registry_event`] queued, which is always a [`PendingRegistryEvent`]
/// it allocated with [`flt::REGISTRY_EVENT_TAG`].
extern "system" fn registry_event_worker(
    work_item: flt::FltGenericWorkItem,
    _filter: *mut c_void,
    context: *mut c_void,
) {
    // SAFETY: `context` is that block. Every field read here is read once, and
    // nothing else holds a reference to it.
    let action = unsafe {
        let pending = &*context.cast::<PendingRegistryEvent>();
        let units = (pending.units as usize).min(MAX_PATH_UNITS);
        let value_units = (pending.value_units as usize).min(MAX_VALUE_UNITS);
        send_event(
            pending.event.sequence,
            pending.event.now_100ns,
            SubjectKind::Registry,
            pending.event.action,
            pending.event.process_id,
            // A registry event has no creator; zero is this protocol's "none".
            0,
            pending.event.detail,
            &pending.path[..units],
            &pending.value[..value_units],
            pending.value_type,
            pending.value_flags & EVENT_VALUE_TRUNCATED != 0,
        );
        pending.event.action
    };

    // SAFETY: as in `event_worker` -- this routine's own work item, the block
    // the queueing callback allocated, freed once, counter last.
    unsafe {
        flt::FltFreeGenericWorkItem(work_item);
        flt::ExFreePoolWithTag(context, flt::REGISTRY_EVENT_TAG);
    }
    pending_counter(action).fetch_sub(1, Ordering::Relaxed);
}

/// Send one process event, whose path is already the DOS form.
///
/// Free-standing rather than inlined into the worker so that the worker has one
/// thing to call and one place to free: the block goes back on every path out
/// of the worker, and a body with two `return`s inside it is a body where one of
/// them will eventually be written after the free.
///
/// `action` is [`EventAction::ExecutionBlocked`] when the creation veto fired
/// and [`EventAction::ProcessStarted`] otherwise. The two are distinct on the
/// wire so that the service's log says which of them happened, which is the
/// only measurement the veto has: `DriverStats` has no field for it, and the
/// protocol's layout is not this driver's to extend.
///
/// The exclusion table is deliberately **not** consulted here, and that is a
/// correction rather than an omission.
///
/// What this used to say is worth keeping, because it is how the line came to be
/// there: the table was consulted "for the same reason the create gate
/// consults" it, a process image being a file like any other. The table it names
/// is [`BUILT_IN_EXCLUSIONS`], by way of `av_driver_proto::exclusions`, and it
/// holds `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)` and the
/// product's own data directory. The reason it holds them is that a service
/// which has stopped answering must not be able to stop the machine from
/// starting — a reason about a **decision**, and this path makes none. A
/// `ProcessStarted` report is queued on a work item and sent; the driver waits
/// for no answer and there is no verdict it could refuse. Reusing the table here
/// bought no safety and cost the feature it was meant to serve.
///
/// What it cost, measured on 2026-10-10 against the deployed build:
/// `matches_prefix` compares the *whole* path against each entry, so every
/// process whose image is under one of those three directories — which is
/// System32 and nearly every installed program — was never reported at all. The
/// machine that produced this correction ran for half an hour, and the worker's
/// own tally read `0 start(s): 0 examined`: the exact shape of a watcher that is
/// not working, produced by one that was.
///
/// What the user does not want examined is a question the service already
/// answers, in `av_service::process_watch`, against the allow list that can be
/// edited (`skipped_allowed`) and against its own process tree
/// (`skipped_own`) — rather than against a constant compiled into the driver,
/// which is the copy that cannot be corrected by a user who disagrees with it.
fn send_process_event(
    sequence: u64,
    now_100ns: u64,
    action: EventAction,
    process_id: u32,
    parent_process_id: u32,
    path: &[u16],
) {
    // SAFETY: this is a worker thread at `PASSIVE_LEVEL`; `send_event`'s own
    // documentation is the precondition, and it states it there. `send_event`
    // builds a 3168-byte `EventMessage` in its own frame — 2128 until the
    // registry value buffer was added on 2026-10-19 — which the write path has
    // been doing on this same kind of thread since 10-01, and which still fits
    // a worker thread's 12 KiB stack.
    unsafe {
        send_event(
            sequence,
            now_100ns,
            SubjectKind::Process,
            action,
            process_id,
            parent_process_id,
            0,
            path,
            &[],
            0,
            false,
        );
    }
}

/// The part of a wire message that is this driver's to send, and its length.
///
/// **Every structure in `av_driver_proto::wire` begins with a 16-byte
/// [`PortMessageHeader`], and `FltSendMessage` is not given those bytes.** The
/// filter manager writes a `FILTER_MESSAGE_HEADER` of its own in front of the
/// buffer it is handed, so what `FilterGetMessage` produces on the other side is
/// the two contiguous: the filter manager's header, then this driver's message
/// beginning at its `kind`. The 16 bytes at the front of these structures are
/// this side's view of a slot it does not own.
///
/// Sending them anyway is what made the service connect and immediately drop
/// the connection, once a second, forever. The arithmetic that identifies it
/// uses only this workspace: the largest message this driver can send is
/// [`EventMessage`] at 2120 bytes (its size in October 2026, before the
/// registry value buffer; 3168 since), the service's receive buffer is
/// `EventMessage::SIZE` -- the same number -- and the filter manager answered
/// `STATUS_BUFFER_TOO_SMALL` (which `fltlib` reports as
/// `ERROR_INSUFFICIENT_BUFFER`) for it. **A message that is not larger than the
/// buffer cannot make the buffer too small**, so what reaches user mode is
/// larger than what was passed here, and the only thing that can have been added
/// to it is the header the filter manager owns. The service's own decode agrees:
/// the messages that did fit arrived with `kind 48`, which is not a kind --
/// `KIND_DECISION_REQUEST` is 1 -- but is `DecisionReplyMessage::SIZE`, the value
/// a request puts in the `reply_length` of the header the service was reading as
/// its `kind`, sixteen bytes early.
///
/// So the header is skipped here rather than sent. The field it carries is not
/// lost: `ReplyLength` is a parameter of `FltSendMessage`, and that is where the
/// decision path already passes `DecisionReplyMessage::SIZE` from.
///
/// # The sizes this has to add up to
///
/// Sent length is `size_of::<T>() - 16`, and the filter manager adds 16 back, so
/// the message the service decodes is exactly `size_of::<T>()` bytes -- the
/// number every layout assertion in `wire.rs` is written against. That is why
/// `RECEIVE_BYTES` can stay `EventMessage::SIZE`: the largest thing that arrives
/// is the largest thing this protocol defines, with nothing added twice.
fn outbound<T>(message: *mut T) -> (*mut c_void, u32) {
    // `wrapping_add` rather than `add`, so that this is a safe function: it
    // dereferences nothing and reads no field, and the only obligation it would
    // have had is the one the callers already meet -- a live `T` at `message`.
    let body = message.cast::<u8>().wrapping_add(PortMessageHeader::SIZE);
    let length = core::mem::size_of::<T>() - PortMessageHeader::SIZE;
    (body.cast::<c_void>(), length as u32)
}

// The subtraction above is only meaningful for a message that has a header to
// subtract, and an underflow would be silent in a release build -- it wraps to
// a length just under four gigabytes, which `FltSendMessage` would reject rather
// than send. These two are the only types this file sends; a third added later
// that is smaller than a header fails the build here instead of at the port.
const _: () = assert!(core::mem::size_of::<DecisionRequestMessage>() >= PortMessageHeader::SIZE);
const _: () = assert!(core::mem::size_of::<EventMessage>() >= PortMessageHeader::SIZE);

/// Send one event upward, waiting [`ORDINARY_EVENT_TIMEOUT_100NS`] for the
/// service to be reading — except a state report, which waits
/// [`STATE_REPORT_TIMEOUT_100NS`], and a write notification, which does not
/// wait at all.
///
/// Called from the two worker routines, which is what makes the call below
/// legal: `FltSendMessage` is `_IRQL_requires_max_(APC_LEVEL)`
/// (`fltKernel.h` 4642) and a worker thread runs at `PASSIVE_LEVEL`.
///
/// `path` is empty for an event that names no file, and a path that does not
/// fit the protocol's buffer means **no event is sent**: `set_path` refuses
/// rather than truncating, and a truncated path is a different file.
///
/// `value` is empty for every event but a registry value write. It is
/// **truncated** rather than refused when it does not fit, and
/// `value_truncated` says so — the opposite rule, for the reason
/// `EVENT_VALUE_TRUNCATED` gives: a value is evidence rather than identity.
///
/// # Safety
///
/// Must be called at `APC_LEVEL` or below, which for this driver means only
/// from a worker routine.
#[allow(clippy::too_many_arguments)]
unsafe fn send_event(
    sequence: u64,
    now_100ns: u64,
    subject: SubjectKind,
    action: EventAction,
    process_id: u32,
    parent_process_id: u32,
    detail: u32,
    path: &[u16],
    value: &[u16],
    value_type: u32,
    value_truncated: bool,
) {
    // True for both callers, and kept anyway. The claim "a worker thread runs
    // at `PASSIVE_LEVEL`" is the entire reason these events are deferred rather
    // than sent, so it is exactly the kind of claim this file checks rather
    // than asserts -- and a check that is only correct because a fact elsewhere
    // holds is not a check.
    if !flt::may_block_for_the_service() {
        return;
    }

    let port = CLIENT_PORT.load(Ordering::Acquire);
    if port.is_null() {
        // An event that happened before the service connected, or after it
        // left. There is no counter for a dropped event -- `DriverStats` has no
        // field for one and its layout is the protocol's -- so this is
        // deliberately silent rather than counted as something it is not.
        return;
    }

    let mut event = EventMessage::new(sequence, now_100ns, subject, action);
    event.process_id = process_id;
    event.parent_process_id = parent_process_id;
    event.detail = detail;
    if !path.is_empty() && event.set_path(path).is_err() {
        // Longer than `MAX_PATH_UNITS`. Refused rather than truncated: see the
        // doc comment. The sequence number is spent, which is what makes the
        // gap in the service's sequence check mean "an event was dropped"
        // whether it was dropped here or by a full queue.
        return;
    }
    if !value.is_empty() {
        event.set_value(value, value_type);
        // `set_value` sets this by itself only when it is given more than fits;
        // the worker hands it the already-truncated prefix, so the fact has to
        // come from the block that did the cutting.
        if value_truncated {
            event.value_flags |= EVENT_VALUE_TRUNCATED;
        }
    }

    // A state report waits two seconds; an ordinary event waits a hundred
    // milliseconds; a write notification does not wait at all. The reasons are
    // in the two constants and in the measurement recorded on
    // `ORDINARY_EVENT_TIMEOUT_100NS` -- in short, a zero-timeout send is lost
    // whenever it lands in the gap between two receives, which is most of a
    // tight burst.
    //
    // A write notification keeps the zero because it is the one stream that is
    // genuinely expendable: it is by far the highest volume on the machine (the
    // service's own log writes produce them, so a service at `trace` feeds
    // itself), and no rule in `rules.toml` reads it. Making it wait is what
    // would stall a worker thread behind a service that is not reading.
    let mut timeout: i64 = match action {
        EventAction::StateChanged => STATE_REPORT_TIMEOUT_100NS,
        EventAction::FileWritten => 0,
        _ => ORDINARY_EVENT_TIMEOUT_100NS,
    };
    let mut client = port;
    // SAFETY: `FILTER` is a live filter here -- `FltUnregisterFilter` does not
    // return until this work item has run, which is why the item is the filter
    // manager's -- and `client` is a local copy of the port, because the filter
    // manager writes through the pointer it is given when a connection dies.
    // The reply buffer and its length are null, which `FltSendMessage` allows
    // and which is what makes this a send with no reply. The timeout is
    // relative and negative or zero, so a service that has stopped reading
    // costs at most one timeout per queued event rather than the life of the
    // connection.
    let (out, out_length) = outbound(core::ptr::addr_of_mut!(event));
    unsafe {
        let _ = flt::FltSendMessage(
            FILTER.load(Ordering::Acquire),
            &mut client,
            out,
            out_length,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut timeout,
        );
    }
}

/// Mark the operation refused, with the status its caller will see.
///
/// `FLT_PREOP_COMPLETE` is only a refusal because of what this writes: the
/// status the caller of the file operation receives. Returning the code without
/// the status completes the operation successfully, which is the worst possible
/// outcome -- a driver that believes it blocked something.
///
/// # Why the status is a parameter
///
/// **The filter manager does not honour an arbitrary status on every
/// operation.** For `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` the reference
/// page for its [FLT_PARAMETERS][params] says a minifilter may fail the
/// operation only when `SyncType` is `SyncTypeCreateSection` and only with
/// `STATUS_INSUFFICIENT_RESOURCES`; a `SyncTypeOther` acquire may not be failed
/// at all. This driver wrote `STATUS_ACCESS_DENIED` there from 2026-10-02 until
/// 2026-10-18, and that status is not on the list: the section was created and
/// the program ran. The service's `was refused` line was true -- it answered --
/// and the operating system did not act on the answer, which is why a
/// convicted image still executed on 2026-10-17.
///
/// The write gate keeps `STATUS_ACCESS_DENIED`, which is the ordinary status
/// for a refused create or write and the one an application can report.
///
/// [params]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization
///
/// # Safety
///
/// `data` must be the callback data of the pre-operation that is returning
/// `FLT_PREOP_COMPLETE`, and that pre-operation must not already have completed
/// or pended the operation.
unsafe fn refuse(data: *mut FltCallbackData, status: i32) {
    // SAFETY: the caller's contract. `IoStatus` is at a fixed offset, pinned by
    // `flt.rs`'s layout assertions, and it is where the filter manager reads
    // the status from when a pre-operation completes the operation.
    unsafe {
        (*data).io_status.status = status;
        (*data).io_status.information = 0;
    }
}

/// Read `DesiredAccess` out of a create's parameters.
///
/// # Safety
///
/// `data` must be the callback data of an `IRP_MJ_CREATE` operation.
unsafe fn desired_access(data: *mut FltCallbackData) -> u32 {
    if data.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract. The parameter block is valid for the
    // duration of a callback on that operation.
    let iopb = unsafe { (*data).iopb };
    if iopb.is_null() {
        return 0;
    }
    // SAFETY: `iopb` is non-null and belongs to the operation.
    let context = unsafe { (*iopb).parameters.create.security_context };
    if context.is_null() {
        return 0;
    }
    // SAFETY: a non-null `SecurityContext` on a create points at an
    // `IO_SECURITY_CONTEXT` owned by the I/O manager for the operation.
    let context: &IoSecurityContext = unsafe { &*context.cast::<IoSecurityContext>() };
    context.desired_access
}

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

/// Create the communication port.
///
/// Split out of `driver_entry` because the name buffer has to be alive for the
/// call and must not be a `static` the callee could keep a pointer into. The
/// filter manager copies the name into the object it creates.
///
/// # Safety
///
/// `filter` must be a filter this driver has registered. Returns the port, or
/// null if it could not be created.
unsafe fn create_port(filter: FltFilter) -> FltPort {
    let mut name_units = [0u16; 32];
    let length = encode_ascii(PORT_NAME, &mut name_units);
    let mut name = UnicodeString {
        length: (length * 2) as u16,
        maximum_length: (length * 2) as u16,
        pad: 0,
        buffer: name_units.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: core::ptr::null_mut(),
        object_name: &mut name,
        // `OBJ_KERNEL_HANDLE` matters: without it the name is created with a
        // handle a user-mode caller could open, and the port would be a way for
        // any process on the machine to answer a decision request.
        attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    let mut port: FltPort = core::ptr::null_mut();

    // The port gets a security descriptor of its own, built here and freed
    // below. It read `core::ptr::null_mut()` until 2026-09-26, on the reasoning
    // that a null descriptor means the filter manager's default and that the
    // default is SYSTEM plus administrators. The measurement says a null
    // descriptor is not that: an elevated service was refused with
    // `E_ACCESSDENIED` (0x80070005) on every retry. `FLT_PORT_ALL_ACCESS` is
    // what `avscan` passes and what an elevated service needs.
    //
    // SAFETY: the out-parameter is a live local and `desired_access` is the
    // header's own mask. The call allocates, which is why there is no early
    // return between here and the free below.
    let mut descriptor: *mut c_void = core::ptr::null_mut();
    let status =
        unsafe { flt::FltBuildDefaultSecurityDescriptor(&mut descriptor, FLT_PORT_ALL_ACCESS) };
    if status != STATUS_SUCCESS {
        return core::ptr::null_mut();
    }
    attributes.security_descriptor = descriptor;

    // SAFETY: `filter` is registered by the caller's contract, `attributes`
    // names a counted string alive for the call, and the three callbacks have
    // the types the header declares. `max_connections` is one: this port talks
    // to the one service that owns the decision policy, and a second connection
    // would be a second opinion about whether a file may execute.
    let status = unsafe {
        flt::FltCreateCommunicationPort(
            filter,
            &mut port,
            &mut attributes,
            core::ptr::null_mut(),
            Some(port_connect),
            Some(port_disconnect),
            Some(port_message),
            1,
        )
    };

    // SAFETY: `descriptor` is what the call above returned, this is the only
    // place it is freed, and the filter manager has copied what it needs out of
    // it before `FltCreateCommunicationPort` returns.
    unsafe { flt::FltFreeSecurityDescriptor(descriptor) };

    if status != STATUS_SUCCESS {
        return core::ptr::null_mut();
    }
    SERVER_PORT.store(port, Ordering::Release);
    port
}

/// The service connected.
extern "system" fn port_connect(
    client_port: FltPort,
    _server_port_cookie: *mut c_void,
    _connection_context: *mut c_void,
    _size_of_context: u32,
    connection_port_cookie: *mut *mut c_void,
) -> NtStatus {
    if client_port.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // The connection cookie is this driver's to define and the header makes it
    // optional (`_Outptr_result_maybenull_`). Null is written into it rather
    // than left alone because `port_disconnect`'s one argument is whatever is
    // here, and an out-parameter the callee did not write is a value the
    // teardown path would be reading on trust.
    if !connection_port_cookie.is_null() {
        // SAFETY: the parameter is `_Outptr_` and non-null, which was just
        // checked, so it addresses a slot this callback is the writer of.
        unsafe { *connection_port_cookie = core::ptr::null_mut() };
    }
    // SAFETY: `client_port` is the connection the filter manager is handing
    // over and it is non-null, which was just checked. It is the port itself
    // and not a pointer to one -- `fltKernel.h` 4595 passes `PFLT_PORT`, and
    // line 257 is `typedef struct _FLT_PORT *PFLT_PORT` -- so this stores the
    // value rather than reading through it. This is the only writer of
    // `CLIENT_PORT` other than teardown and the disconnect callback, both of
    // which write null.
    CLIENT_PORT.store(client_port, Ordering::Release);

    // Tell the service what both registrations answered, once, on every
    // connection.
    //
    // Until 2026-10-09 nothing carried this and nothing could: the driver has
    // no control device for the service to ask through, and a registration
    // failure is otherwise invisible from user mode. The result was that a
    // machine whose process notifications never registered — which
    // `PsSetCreateProcessNotifyRoutineEx` can refuse, and which needs the image
    // to carry `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` — looked exactly like
    // a machine on which no program had started; and a machine whose object
    // callbacks were refused, which `ObRegisterCallbacks` does when another
    // driver holds the altitude, looked like a machine where nothing had tried
    // to touch this product.
    //
    // Queued rather than sent: this runs inside the filter manager's connect
    // callback, and `EventAction::StateChanged` replaces the value the driver
    // would otherwise have no way to state at all.
    defer_driver_state_event(
        PROCESS_NOTIFY_STATUS.load(Ordering::Acquire),
        SubjectKind::Driver,
    );
    defer_driver_state_event(OB_STATUS.load(Ordering::Acquire), SubjectKind::Protection);
    defer_driver_state_event(REGISTRY_STATUS.load(Ordering::Acquire), SubjectKind::Registry);

    STATUS_SUCCESS
}

/// The service disconnected.
extern "system" fn port_disconnect(_connection_context: *mut c_void) {
    // Clearing this is what makes every subsequent decision a fail-open one.
    // That is the intended behaviour rather than a fallback: with nobody to
    // ask, the driver has no basis to refuse anything, and the alternative --
    // refusing on the grounds that the service is gone -- is a machine that
    // stops running its own programs because an antivirus service crashed.
    CLIENT_PORT.store(core::ptr::null_mut(), Ordering::Release);
}

/// The service sent something unsolicited.
///
/// This is not the reply path: a reply to a request this driver is waiting on
/// arrives as the return of `FltSendMessage`, on the thread that is waiting.
/// What arrives here is a **configuration message** — the one kind that travels
/// user mode to driver — and the answer goes back two ways, deliberately:
///
/// * the four-byte `NTSTATUS` written through `output_buffer`, which is the
///   answer a caller should read, and
/// * this routine's own return value, which is always `STATUS_SUCCESS`.
///
/// The second is `STATUS_SUCCESS` even when the configuration was refused,
/// and the reason is that `FilterSendMessage` failing is indistinguishable on
/// the user side from the transport failing. A service that could not tell "the
/// driver rejected this directory" from "the driver is gone" would retry the
/// first forever and treat the second as a policy refusal. So the transport
/// always succeeds and the policy answer is in the buffer, which is also what
/// makes the refusal readable in a test rather than inferred.
///
/// The callback still does no waiting and allocates nothing: one unaligned copy
/// off the caller's buffer into a stack local, the gate decision — which is
/// `av-driver-proto`'s `gate_update`, tested in user mode — and two atomic
/// stores.
extern "system" fn port_message(
    _port_cookie: *mut c_void,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
    return_output_buffer_length: *mut u32,
) -> NtStatus {
    if !return_output_buffer_length.is_null() {
        // SAFETY: this parameter is `_Out_ PULONG` and non-null, which was just
        // checked, so it addresses a slot this routine is the writer of. It is
        // not the parameter named `_output_buffer_length`: that one is the
        // `ULONG` the header passes by value, and it has no address to write
        // through. See `MessageNotifyCallback` in `flt.rs`.
        unsafe { *return_output_buffer_length = 0 };
    }

    // SAFETY: the header documents `InputBuffer` as the sender's own buffer,
    // valid for `input_buffer_length` bytes for the duration of the call, and
    // `apply_config` reads at most `ConfigMessage::SIZE` of them and only after
    // checking that length. The buffer is probe-checked by the filter manager
    // and is **not** documented as aligned, which is why `apply_config` copies
    // it rather than casting in place.
    let status = unsafe { apply_config(input_buffer, input_buffer_length) };

    // The answer, when there is somewhere to put it. A caller that passed no
    // output buffer gets the transport's success and no policy answer, which is
    // its own choice and not a case worth failing the call over.
    if !output_buffer.is_null() && output_buffer_length as usize >= core::mem::size_of::<i32>() {
        // SAFETY: `output_buffer` is the caller's buffer, non-null, and at
        // least four bytes long, which was just checked. `write_unaligned`
        // because a user-mode buffer's alignment is not this driver's to
        // assume -- the same reason `apply_config` copies.
        unsafe { core::ptr::write_unaligned(output_buffer.cast::<i32>(), status) };
        if !return_output_buffer_length.is_null() {
            // SAFETY: as above: non-null and this routine is the only writer.
            unsafe { *return_output_buffer_length = core::mem::size_of::<i32>() as u32 };
        }
    }

    STATUS_SUCCESS
}

/// Apply a configuration message, answering the `NTSTATUS` it earned.
///
/// Separated from [`port_message`] so that the one part of this that is a
/// decision is readable on its own — it is the driver's half of what
/// `av-driver-proto::protect::gate_update` decides, and the half that cannot be
/// tested is exactly the two atomic stores and the buffer copy below.
///
/// # Why the message is copied rather than read in place
///
/// `PFLT_MESSAGE_NOTIFY`'s `InputBuffer` is documented as a locked user-mode
/// buffer, and "locked" is about pages rather than about **alignment** or about
/// the sender's thread being stopped. So:
///
/// * **Unaligned** reads are the normal case, not a corner. A `ConfigMessage`
///   contains `u32`s and a `[u16; 1024]`; reading any of them through a cast
///   would be an alignment assumption this driver has no right to make.
/// * **Torn** reads are possible in principle. The sender can write to its own
///   buffer while this runs, and a `dir_units` read before a `dir` read can
///   describe a different message than the units that follow. One copy makes
///   the message a single snapshot.
///
/// 2080 bytes of kernel stack, on a path that is entered once per connection
/// rather than once per operation.
///
/// # Safety
///
/// `input` must be null or valid for `length` bytes, which is the callback's
/// contract; every read below is bounded by `length` and by the structure's own
/// size, and the null case is checked rather than assumed.
unsafe fn apply_config(input: *mut c_void, length: u32) -> NtStatus {
    if input.is_null() || (length as usize) < ConfigMessage::SIZE {
        // A message shorter than the structure it claims to be. Refused rather
        // than read partially: every field below the prefix would be reading
        // whatever followed the sender's buffer.
        return STATUS_INVALID_PARAMETER;
    }

    // SAFETY: `input` is non-null and at least `ConfigMessage::SIZE` bytes,
    // which was just checked, and `read_unaligned` is defined for a source with
    // any alignment. The structure has no padding outside its fields and no
    // `Drop`, so this is a plain byte copy out of the sender's buffer.
    let message: ConfigMessage = unsafe { core::ptr::read_unaligned(input.cast::<ConfigMessage>()) };

    // Both halves of the prefix, and `is_readable` is what performs both checks
    // -- a `kind` this build knows and a version it can parse. Then the kind
    // itself, because "readable" means the layout below the prefix *can* be
    // read rather than that it is the one this function expects.
    if !message.prefix.is_readable()
        || MessageKind::from_wire(message.prefix.kind) != Some(MessageKind::Config)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // The directory already in the gate's buffer. Empty until the gate has been
    // written, which is what `gate_update` needs in order to tell "the first
    // arm" from "an update"; a disarmed gate keeps its directory, so this is
    // non-empty after a disarm.
    let stored_units = GATE_UNITS.load(Ordering::Acquire) as usize;
    let stored: &[u16] = if stored_units == 0 || stored_units > GATE_DIR_UNITS {
        &[]
    } else {
        // SAFETY: `stored_units` is at most the array's length, which was just
        // checked, and the buffer was filled before that length was published
        // by a release store -- this acquire load is paired with it.
        unsafe { &(&*GATE_DIRECTORY.0.get())[..stored_units] }
    };

    // The whole policy, from the crate whose tests run on the build machine.
    // Everything below is the application of its answer and nothing else.
    let update = gate_update(stored, message.dir(), message.gate_writes());

    match update {
        GateUpdate::Arm { units } => {
            // The one write to the buffer, and it can only happen while it is
            // still empty -- which is what makes it safe without a lock and is
            // argued at length on `gate_update`. `units` is `gate_update`'s
            // count of the same slice being copied, and the two `min`s are a
            // belt on braces this driver will never need: a copy that ran past
            // either bound would be a kernel memory write, and the cost of the
            // checks is two comparisons once per driver load.
            let source = message.dir();
            let count = units.min(source.len()).min(GATE_DIR_UNITS);
            // SAFETY: `GATE_DIRECTORY` is written here and nowhere else, the
            // length stored below is `count`, and `GATE_ARMED` is published
            // last -- so no reader can reach the buffer through the gate before
            // this write is complete.
            unsafe {
                (&mut *GATE_DIRECTORY.0.get())[..count].copy_from_slice(&source[..count]);
            }
            // Release, and the order of these two stores is the synchronisation
            // `gate_matches` documents: the length is what makes the buffer
            // readable, and it is visible before the switch that lets a reader
            // look at it.
            GATE_UNITS.store(count as u32, Ordering::Release);
            GATE_ARMED.store(true, Ordering::Release);
        }
        GateUpdate::AlreadyArmed => {
            // The same directory again, which the service sends on every
            // connect. Nothing is written; the gate is switched on in case it
            // was switched off.
            GATE_ARMED.store(true, Ordering::Release);
        }
        GateUpdate::Disarm => {
            // Off. The stored directory is left where it is -- see
            // `GateUpdate::Disarm` -- so a later message naming the same
            // directory arms again without a write.
            GATE_ARMED.store(false, Ordering::Release);
        }
        GateUpdate::Refused => {
            // Nothing is changed, including `HANDLES_PROTECTED` below. A
            // refused message is one this driver did not understand, and
            // applying the half of it that was legible would be acting on a
            // request nobody made.
            return STATUS_INVALID_PARAMETER;
        }
    }

    // The object-manager half. Independent of the gate and applied on every
    // message that was not refused, including one that turned the gate off: the
    // two are separate bits precisely because the two registrations fail
    // separately, and a service that wants one without the other says so in
    // `flags`.
    HANDLES_PROTECTED.store(message.protect_handles(), Ordering::Release);

    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whether the section an acquire-for-section callback is about is one that
/// something is about to execute.
///
/// The counterpart of [`desired_access`] for the other gate, and the same shape:
/// read one word out of the parameter block, hand it to a `const fn` in `flt.rs`
/// that names the rule, and return `false` on anything unexpected. `false` is
/// the safe answer -- it is the one that asks the service nothing -- and it is
/// also the correct answer for every input that is not a section being created
/// with an execute protection.
///
/// # Safety
///
/// `data` must be the callback data of an
/// `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` operation, called from that
/// operation's pre-operation. The parameter block is read as the arm that
/// operation carries; reading this arm out of a different operation's block
/// would be reading whatever that operation put there.
unsafe fn section_is_an_execution(data: *mut FltCallbackData) -> bool {
    if data.is_null() {
        return false;
    }
    // SAFETY: the caller's contract. The parameter block is valid for the
    // duration of a callback on that operation.
    let iopb = unsafe { (*data).iopb };
    if iopb.is_null() {
        return false;
    }
    // SAFETY: `iopb` is non-null, belongs to the operation, and the operation is
    // the one whose arm this reads.
    let section = unsafe { (*iopb).parameters.acquire_for_section };
    flt::section_will_execute(section.sync_type, section.page_protection)
}

/// Encode ASCII into UTF-16, returning how many units were written.
///
/// The protocol's strings are UTF-16 because that is what the kernel uses and
/// because a path that went through an eight-bit encoding is a path that cannot
/// name every file on a Windows system. The literals in this file are the port
/// name and the built-in exclusions, all of which are ASCII by construction --
/// which is why widening a byte is the whole conversion.
fn encode_ascii(bytes: &[u8], out: &mut [u16]) -> usize {
    let n = bytes.len().min(out.len());
    for (slot, &byte) in out.iter_mut().zip(bytes.iter()).take(n) {
        *slot = u16::from(byte);
    }
    n
}

/// The counters' index order is the protocol's field order. A field inserted
/// into `DriverStats` without an index to match would shift every counter by
/// one, silently, and an operator would read the result as a detection.
const _: () = {
    assert!(C_BLOCKED_EXECUTIONS == 0);
    assert!(C_OVERSIZE_PATH == 7);
    assert!(core::mem::size_of::<DriverStats>() == DriverStats::SIZE);
    assert!(COUNTERS.len() == 8);
};

/// The operation table's two invariants.
///
/// Both were violated on 2026-09-26 and neither was caught by anything: the
/// table ended with a zero major function, which is a second registration of
/// `IRP_MJ_CREATE`. The filter manager answered with
/// `STATUS_FLT_DUPLICATE_ENTRY` from inside instance creation -- not at load,
/// where the message names neither the array nor the entry that is wrong. The
/// driver registered, listed itself in `fltmc filters`, and was attached to no
/// volume at all.
const _: () = {
    // The array ends at the terminator, which is the only thing that marks the
    // end of it. `IRP_MJ_OPERATION_END` is 0x80; `IRP_MJ_CREATE` is 0x00.
    assert!(OPERATION_TABLE[REGISTERED_OPERATIONS].major_function == IRP_MJ_OPERATION_END);

    // And nothing is registered twice, which is what the filter manager
    // rejects. The terminator is excluded from the comparison because it is not
    // an operation -- including it would make this check pass for the wrong
    // reason on the day one of the entries above happens to be 0x80.
    let mut i = 0;
    while i < REGISTERED_OPERATIONS {
        let mut j = i + 1;
        while j < REGISTERED_OPERATIONS {
            assert!(OPERATION_TABLE[i].major_function != OPERATION_TABLE[j].major_function);
            j += 1;
        }
        i += 1;
    }

    // Every entry above the terminator registers at least one callback, or the
    // filter manager would never call it and the entry would be a claim the
    // driver does not keep.
    let mut k = 0;
    while k < REGISTERED_OPERATIONS {
        assert!(
            OPERATION_TABLE[k].pre_operation.is_some()
                || OPERATION_TABLE[k].post_operation.is_some()
        );
        k += 1;
    }

    // The write gate is the pre-operation and the tamper detector is the
    // post-operation, and this entry has to have both. Checked by major function
    // rather than by index because the whole failure this guards against is an
    // edit that changes which entry is which: a `None` in either slot is
    // indistinguishable from a correct table by reading it, and the consequences
    // are opposite in the two directions -- no pre-operation means the gate is
    // armed and never fires, no post-operation means writes stop being reported
    // while the `.rdata` counts still look healthy.
    let mut w = 0;
    while w < REGISTERED_OPERATIONS {
        if OPERATION_TABLE[w].major_function == IRP_MJ_WRITE {
            assert!(OPERATION_TABLE[w].pre_operation.is_some());
            assert!(OPERATION_TABLE[w].post_operation.is_some());
        }
        w += 1;
    }

    // The entries whose callbacks can run at `DISPATCH_LEVEL` must skip
    // paging I/O, because each of them reaches an API the header caps at
    // `APC_LEVEL`. This is the check that would have caught the defect that
    // bugchecked the test VM on 2026-09-27 -- an entry whose `flags` was left at
    // zero looks exactly like a correct one at every other level, and the cost
    // of the zero is a bugcheck on the first write after a service connects.
    //
    // CREATE is excluded on purpose and not by oversight: a create is always
    // `PASSIVE_LEVEL`, so its zero is correct. The set is named by major
    // function rather than by index so that reordering the table cannot make
    // this pass for the wrong entry.
    let mut m = 0;
    while m < REGISTERED_OPERATIONS {
        let entry = &OPERATION_TABLE[m];
        let reaches_a_blocking_api = entry.major_function == IRP_MJ_WRITE
            || entry.major_function == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
            || entry.major_function == IRP_MJ_SET_INFORMATION;
        if reaches_a_blocking_api {
            assert!(
                entry.flags & flt::FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO != 0,
                "a registration whose callback can run at DISPATCH_LEVEL must skip paging I/O"
            );
        }
        m += 1;
    }

    // The object-callback altitude, and the two facts about it that are this
    // driver's rather than the header's. `ObRegisterCallbacks` reads a counted
    // string, so a six-byte literal is the whole of what has to fit -- and a
    // truncation would be a *different* altitude registered, compared by the
    // kernel against every other driver's, with nothing to say so.
    assert!(OB_ALTITUDE.len() == 6);
    assert!(OB_ALTITUDE.len() <= 15);
    // The registry altitude is a counted string handed to
    // `CmRegisterCallbackEx` the same way, and it must differ from the object
    // callback's: the two share the numbering, and a collision is a registration
    // that fails with a status nobody would think to check for.
    assert!(REGISTRY_ALTITUDE.len() == 6);
    assert!(REGISTRY_ALTITUDE.len() <= 15);
    // The two differ in their last digit, which is the fact the collision
    // status above is about. Spelled as the byte rather than as a slice
    // comparison because slice `PartialEq` is not a `const fn`.
    assert!(OB_ALTITUDE[5] != REGISTRY_ALTITUDE[5]);

    // `wdm.h`'s `MODE::UserMode`: the caller's own token rather than the
    // token's. Kernel mode would ask about the process as the kernel sees it,
    // which is a different question and the wrong one here.
    assert!(USER_MODE == 1);
};
