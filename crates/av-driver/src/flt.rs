//! Hand-declared filter-manager bindings, plus the volume-name lookup the
//! path normaliser in `av-driver-proto` needs.
//!
//! # What comes from `wdk-sys`, and what is written out here
//!
//! Two different sets of names, and the split is the same one the rest of this
//! crate makes: take what the bindings already declare correctly, and hand-write
//! only what no header under `Include\10.0.26100.0` declares at all.
//!
//! **From `wdk-sys`**: the whole object-manager / process / security surface the
//! self-protection callback needs -- `ObRegisterCallbacks`,
//! `ObUnRegisterCallbacks`, `SeTokenIsAdmin`, `SeSinglePrivilegeCheck`,
//! `SeExports`, `PsProcessType`, `PsThreadType`, every `OB_*` structure and
//! typedef -- and `PsSetCreateProcessNotifyRoutineEx`. These are in the
//! `ntddk.rs` / `types.rs` / `constants.rs` the build generates, each with
//! bindgen's own `size_of` and `offset_of` assertions, so declaring them a
//! second time here would be a second copy to keep in step with the first.
//!
//! **Written out here**: the filter manager, in full. `wdk-sys` 0.5.1 generates
//! its bindings from a fixed list of API subsets -- `Base`, `Wdf`, `Gpio`,
//! `Hid` -- and the filter manager is in none of them. That is checkable rather
//! than a guess: the generated `ntddk.rs` under this crate's `target` directory
//! contains `PsSetCreateProcessNotifyRoutineEx` and not one occurrence of
//! `FltRegisterFilter`. The only `FLT_`-prefixed name in the whole generated
//! output is the constant `FLT_REGISTRATION_VERSION`.
//!
//! Plus exactly one name from neither: [`PsGetProcessImageFileName`], which is a
//! real `ntoskrnl.lib` export that appears in no header, and whose declaration
//! says what was measured about that.
//!
//! Every filter-manager layout comes from the installed WDK header
//! `10.0.26100.0\km\fltKernel.h` and every offset that matters is pinned by a
//! `const` assertion at the bottom of this file, so a layout mistake is a build
//! failure here rather than a bugcheck on a machine that cannot be debugged from
//! this one.
//!
//! # What is deliberately not modelled
//!
//! `FLT_CALLBACK_DATA` continues past `IoStatus` with a tag buffer and a union
//! of per-operation structures, and `FLT_IO_PARAMETER_BLOCK`'s `FLT_PARAMETERS`
//! is a union with three dozen arms. Only the leading fields are read, and a
//! pointer to the real structure can be read through a shorter declaration
//! because C lays out the prefix identically; the declarations below therefore
//! stop where this driver stops reading and say so, instead of reproducing a
//! few thousand lines of union that nothing here would look at.

use core::ffi::c_void;

use av_driver_proto::path::VolumeNames;

/// `NTSTATUS`, which is a signed 32-bit value on every Windows target.
pub type NtStatus = i32;

/// `STATUS_SUCCESS`. Worth spelling out because it is not zero on every
/// platform this code has been read on, and it is zero on the one that matters.
pub const STATUS_SUCCESS: NtStatus = 0;

/// `STATUS_ACCESS_DENIED`, from `ntstatus.h`. What a refused execution returns.
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022u32 as NtStatus;

/// `STATUS_INSUFFICIENT_RESOURCES`, from `ntstatus.h`. Returned when the
/// communication port cannot be created, which fails the driver's load.
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as NtStatus;

/// `STATUS_INVALID_PARAMETER`, from `ntstatus.h`.
///
/// What the port's message callback answers a configuration message it will not
/// apply: one that is not a [`crate::ConfigMessage`], one this build cannot
/// parse, or one whose write gate names a directory the gate cannot take.
///
/// `STATUS_INVALID_PARAMETER` rather than `STATUS_ACCESS_DENIED`: nothing about
/// the caller's rights was examined, and a service that read a refusal as an
/// access problem would look for a permission to grant.
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as NtStatus;

// An unknown volume is not an error for this driver: it is a request that goes
// up with the volume unresolved, which `av-driver-proto` reports as a flag on
// the request rather than as a detection the driver decided on its own.

/// An opaque `PFLT_FILTER`.
pub type FltFilter = *mut c_void;
/// An opaque `PFLT_PORT`.
pub type FltPort = *mut c_void;
/// An opaque `PFLT_VOLUME`.
pub type FltVolume = *mut c_void;
/// An opaque `PFLT_GENERIC_WORKITEM`.
///
/// Opaque in the strong sense: the filter manager allocates it and this driver
/// never reads a byte of it. Unlike a `WORK_QUEUE_ITEM`, which a driver has to
/// build itself from non-paged pool, this is a handle.
pub type FltGenericWorkItem = *mut c_void;

/// `IRP_MJ_CREATE`, from `wdm.h`. The gate this driver decides on.
pub const IRP_MJ_CREATE: u8 = 0x00;
/// `IRP_MJ_WRITE`, from `wdm.h`. Reported, never refused.
pub const IRP_MJ_WRITE: u8 = 0x04;
/// `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`, from `fltKernel.h`.
///
/// Not a major function in the I/O manager's table: `fltKernel.h` defines it as
/// `((UCHAR)-1)` and it exists only as a filter-manager registration key. It is
/// the point at which a section object is created for a file, which is what
/// actually maps an image for execution -- so a driver that wants to refuse an
/// execution *before it happens* registers here and not only on `CREATE`.
pub const IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: u8 = u8::MAX;

/// `IRP_MJ_OPERATION_END`, from `fltKernel.h`: the major function that marks the
/// end of an operation registration array, under the header's own comment,
/// "Marks the end of the operation list for registration".
///
/// This is the *only* thing that terminates that array. A driver that ends it
/// with an all-zero entry instead has not terminated anything: `IRP_MJ_CREATE`
/// is `0x00`, so the entry reads as a second registration of an operation the
/// array has already registered. The filter manager rejects that with
/// `STATUS_FLT_DUPLICATE_ENTRY` (`0xC01C_000D` in `ntstatus.h` line 15037),
/// whose message is "a duplicate handler definition has been provided for an
/// operation" -- and it does so when it
/// builds the handler table, which is at instance creation rather than at
/// `FltRegisterFilter`. The symptom is therefore not a failed load: the filter
/// registers, appears in `fltmc filters`, and is attached to nothing, because
/// every attempt to make an instance fails. Measured in the test VM on
/// 2026-09-26 -- `fltmc attach WenleAvFilter C:` returned exactly `0x801F000D`
/// and `fltmc instances -f WenleAvFilter` reported no instances.
///
/// That number is the *HRESULT* form of the same error, which is what `fltmc`
/// prints: `winerror.h` line 43100 is
/// `ERROR_FLT_DUPLICATE_ENTRY _HRESULT_TYPEDEF_(0x801F000DL)`. Both spellings
/// mean the one thing, and the two are worth telling apart only because
/// searching a dump or a log for `0xC01C000D` will not find the `0x801F000D`
/// that was actually recorded.
pub const IRP_MJ_OPERATION_END: u8 = 0x80;

/// `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`, from `fltKernel.h` line 1910:
/// `0x00000001`. The entry does not see paging I/O.
///
/// This is not a performance choice, it is the only way two of the three
/// registrations below can be correct. Paging I/O runs at `DISPATCH_LEVEL`, and
/// both APIs this driver calls from those callbacks -- `FltGetFileNameInformation`
/// (`fltKernel.h` 2843) and `FltSendMessage` (`fltKernel.h` 4642) -- are
/// `_IRQL_requires_max_(APC_LEVEL)`. A paging write is the memory manager
/// writing back a page it already owns, and a paging section acquisition is the
/// memory manager faulting one in; neither is a user asking to execute
/// something, and neither can be refused.
///
/// Skipping them narrows the window but does not close it -- an *unbuffered*
/// write completes at `DISPATCH_LEVEL` too, and that is not paging I/O -- which
/// is why every callback that reaches those two APIs also checks the IRQL
/// itself. See [`current_irql`].
pub const FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO: u32 = 0x0000_0001;

/// `PASSIVE_LEVEL`, from `wdm.h` line 189: `0`.
///
/// The level every thread runs at by default, and the level the object-manager
/// pre-operation is required to be at *before* it may touch a token. It is not
/// a constant this driver can assume it is running at: the header documents
/// `OB_PRE_OPERATION_CALLBACK` as `_IRQL_requires_max_(PASSIVE_LEVEL)`, which is
/// a promise about the caller rather than a guarantee to the callee, so
/// [`at_passive_level`] asks rather than assumes.
pub const PASSIVE_LEVEL: u8 = 0;

/// `APC_LEVEL`, from `wdm.h` line 191. The highest IRQL at which this driver may
/// call `FltGetFileNameInformation` or `FltSendMessage`.
///
/// `PASSIVE_LEVEL` (line 189) is 0 and `DISPATCH_LEVEL` (line 192) is 2, in that
/// order. `PASSIVE_LEVEL` is declared above because the self-protection callback
/// has a real question to ask about it -- whether a token may be touched --
/// while `DISPATCH_LEVEL` is compared against by [`may_defer_for_the_service`].
pub const APC_LEVEL: u8 = 1;

/// Whether the two calls that touch a token are legal here.
///
/// `PsReferencePrimaryToken` (`ntifs.h` 19576), `SeTokenIsAdmin` (`ntifs.h`
/// 18984) and `SeSinglePrivilegeCheck` (`ntddk.h` 11151) are each documented
/// `_IRQL_requires_max_(PASSIVE_LEVEL)`, and each of them is reached from a
/// callback the filter manager may enter at a raised IRQL. The comparison is the
/// whole of the check; what it protects is documented at the one call site that
/// asks, [`crate::protect_process_handle`].
pub fn at_passive_level() -> bool {
    current_irql() == PASSIVE_LEVEL
}

/// The IRQL this code is running at.
///
/// Declared here rather than taken from `wdk-sys` for the reason `lib.rs` gives
/// for `KeQueryInterruptTimePrecise`: it is one fewer binding version to depend
/// on for a call with no ABI to get wrong. Measured rather than assumed --
/// `KeGetCurrentIrql` occurs five times in
/// `Lib\10.0.26100.0\km\x64\ntoskrnl.lib`, so the declaration links.
///
/// The header wraps it in an inline (line 20367, "this function return the
/// current IRQL") on x64, but the same name is also a plain export, which is the
/// form declared here.
pub fn current_irql() -> u8 {
    // SAFETY: `KeGetCurrentIrql` has no preconditions, takes no arguments and
    // reads a register. It is callable at any IRQL, which is the point of it.
    unsafe { KeGetCurrentIrql() }
}

/// Whether the two filter-manager calls this driver makes from a callback are
/// legal here.
///
/// Both are `_IRQL_requires_max_(APC_LEVEL)`. Everything below is written in
/// terms of this rather than of the raw comparison, so that the reason is stated
/// once.
pub fn may_block_for_the_service() -> bool {
    current_irql() <= APC_LEVEL
}

/// `DISPATCH_LEVEL`, from `wdm.h` line 192.
///
/// The highest IRQL a post-operation callback can be entered at, and therefore
/// the highest this driver has to be able to *hand work off* from. It is
/// deliberately not a level at which anything may be sent: see
/// [`may_block_for_the_service`] above.
pub const DISPATCH_LEVEL: u8 = 2;

/// Whether work can be queued for a worker thread here.
///
/// The filter manager's work-item calls --
/// [`FltAllocateGenericWorkItem`], [`FltQueueGenericWorkItem`] -- are
/// `_IRQL_requires_max_(DISPATCH_LEVEL)` (`fltKernel.h` 4753 and 4780), which
/// is exactly as high as a callback can be entered, so this is true everywhere
/// in this driver. It is written as a comparison rather than assumed because
/// the claim it rests on -- which IRQL a callback runs at -- is a claim about
/// something this file does not control, and because the two facts have to stay
/// in step with each other: raising this constant above `DISPATCH_LEVEL` would
/// be claiming the filter manager may queue work items at `HIGH_LEVEL`.
pub fn may_defer_for_the_service() -> bool {
    current_irql() <= DISPATCH_LEVEL
}

/// `FLT_FILE_NAME_NORMALIZED`, from `fltKernel.h`.
pub const FLT_FILE_NAME_NORMALIZED: u32 = 0x0000_0001;
/// `FLT_FILE_NAME_QUERY_DEFAULT`, from `fltKernel.h`.
pub const FLT_FILE_NAME_QUERY_DEFAULT: u32 = 0x0000_0100;

/// `FLT_PORT_ALL_ACCESS`, from `fltKernel.h`: `FLT_PORT_CONNECT` (`0x0001`) |
/// `STANDARD_RIGHTS_ALL` (`0x001F_0000`). What the communication port's security
/// descriptor grants, and the value `avscan` passes.
///
/// This is not optional decoration. `FltCreateCommunicationPort` accepts a null
/// `security_descriptor`, and a port created that way refuses user mode
/// entirely -- **administrators included**. Measured in the test VM on
/// 2026-09-26: an elevated service was refused with `E_ACCESSDENIED`
/// (`0x80070005`) on all twenty-four retries the log carries. The comment in
/// `WenleAV-vm.bat` used to assert the opposite, that the null case yields the
/// default descriptor and therefore SYSTEM plus administrators; the measurement
/// says otherwise, and the bat's comment now says what was measured.
pub const FLT_PORT_ALL_ACCESS: u32 = 0x001F_0001;

/// `FILE_EXECUTE`, from `wdm.h` line 7270: `( 0x0020 )`. The access a
/// `CreateFile` asks for when it means to map the file for execution.
///
/// This read `0x0001` until 2026-09-26, under a comment claiming the value was
/// "numerically the same as `FILE_READ_DATA`, because on a file they are the
/// same right". Both halves were wrong, and the header says so on two adjacent
/// lines: `wdm.h` 7255 is `FILE_READ_DATA ( 0x0001 )` and 7270 is
/// `FILE_EXECUTE ( 0x0020 )`. They are different rights, which is the whole
/// reason a file can be readable and not executable. (`FILE_TRAVERSE` shares
/// `0x0020`, but that is the directory form of the same right.)
///
/// The cost was measured in the test VM. `create_pre_operation`'s gate is
/// `wanted & FILE_EXECUTE == 0`, the check whose entire purpose is to let the
/// overwhelming majority of opens through without a name lookup or a message.
/// With `0x0001` there it instead let through only the opens that did *not* ask
/// to read -- so every ordinary read on the machine passed the gate, and
/// `decide` ran on nearly every file open. The first one after the filter
/// attached bugchecked the machine with `0xc0000005`; the wild read itself is
/// documented on [`FltFileNameInformation`].
pub const FILE_EXECUTE: u32 = 0x0020;

/// `FLT_PREOP_SUCCESS_NO_CALLBACK`. The pre-operation is done and the filter
/// manager continues with the operation, without calling a post-operation.
///
/// `fltKernel.h` declares this family as an enum whose members are what matter
/// rather than its discriminant type, so the two this driver returns are
/// written as the integers the ABI passes. The full set is
/// `..._SUCCESS_WITH_CALLBACK` 0, `..._NO_CALLBACK` 1, `..._PENDING` 2,
/// `..._DISALLOW_FASTIO` 3, `..._COMPLETE` 4, `..._SYNCHRONIZE` 5; the three
/// this driver never returns are not declared, because a constant nothing
/// returns is a constant nothing checks.
pub const FLT_PREOP_SUCCESS_NO_CALLBACK: i32 = 1;

/// `FLT_PREOP_SUCCESS_WITH_CALLBACK`. The pre-operation is done **and** the
/// post-operation registered for the same major function is to be called.
///
/// The difference between this and `..._NO_CALLBACK` is not a hint: a
/// pre-operation that returns the latter *suppresses* the post-operation
/// entirely. Which means that adding a pre-operation to an entry that already
/// had a post-operation silently stops the post-operation running at all --
/// no error, no warning, and the filter manager has done exactly what it was
/// told. `IRP_MJ_WRITE` is the entry where that nearly happened here: the
/// tamper detector is its post-operation, and the write gate added to its
/// pre-operation on 2026-10-09 would have turned every `FileWritten` event off
/// if the allow paths returned `..._NO_CALLBACK`.
///
/// `..._SYNCHRONIZE` (5) is the third success value and is deliberately not
/// declared: it asks the filter manager to serialise the callback against
/// others on the same file object, and this driver needs nothing serialised
/// because it shares nothing mutable.
pub const FLT_PREOP_SUCCESS_WITH_CALLBACK: i32 = 0;

/// `FLT_PREOP_COMPLETE`. The pre-operation is finishing the operation itself,
/// which is only a refusal when the status written into `IoStatus` says so --
/// see `refuse` in `lib.rs`.
///
/// A pre-operation that completes the operation is the one case where no
/// post-operation runs, and that is the mechanism rather than a side effect:
/// there is no operation left for a post-operation to be called about.
pub const FLT_PREOP_COMPLETE: i32 = 4;

/// `FLT_POSTOP_FINISHED_PROCESSING`.
pub const FLT_POSTOP_FINISHED_PROCESSING: i32 = 0;

/// `UNICODE_STRING`, which is `USHORT Length; USHORT MaximumLength; PWSTR Buffer;`
/// with four bytes of padding before the pointer on x64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    /// Length in bytes, not in units, and not including any terminator.
    pub length: u16,
    /// Capacity in bytes.
    pub maximum_length: u16,
    /// Padding the C compiler inserts before `Buffer`, named so that a caller
    /// building one can initialise it to zero instead of leaving it undefined.
    pub pad: u32,
    /// Pointer to the first UTF-16 code unit.
    pub buffer: *mut u16,
}

impl UnicodeString {
    /// The units this string names, or an empty slice if it names none.
    ///
    /// # Safety
    ///
    /// The caller must know that `buffer` is valid for `length / 2` units. The
    /// only callers are the two places that just received one from the filter
    /// manager or built one from a static, and both name that invariant.
    pub unsafe fn as_units(&self) -> &[u16] {
        if self.buffer.is_null() || self.length < 2 {
            return &[];
        }
        // SAFETY: the caller's contract is that `buffer` covers
        // `length / 2` units, and `length` is a byte count, so this slice is
        // in bounds by that contract.
        unsafe { core::slice::from_raw_parts(self.buffer, usize::from(self.length) / 2) }
    }
}

/// `FLT_FILE_NAME_INFORMATION`, truncated after `Name`.
///
/// `fltKernel.h` line 2749 is the declaration and the field order is
/// `USHORT Size`, then `FLT_FILE_NAME_PARSED_FLAGS NamesParsed`, then
/// `FLT_FILE_NAME_OPTIONS Format`, then `UNICODE_STRING Name`. The widths come
/// from their own typedefs: `FLT_FILE_NAME_PARSED_FLAGS` is `typedef USHORT`
/// (line 2735) and `FLT_FILE_NAME_OPTIONS` is `typedef ULONG` (line 2646). Two
/// `USHORT`s and a `ULONG` are eight bytes, so `Name` is at offset **8**.
///
/// This structure put `Name` at offset **16** until 2026-09-26. The declaration
/// made `NamesParsed` a `u32` at offset 4 and `Format` a `u32` at offset 8 --
/// one field one size too wide, which pushed everything after it eight bytes
/// late. The bytes at offset 16 are not a `UNICODE_STRING`; they are the tail of
/// `Name`'s own layout, where `Name.Buffer` lives. So the read produced a length
/// from the low half of a pointer and, at offset 24, a buffer pointer built from
/// `Volume.Length`, `Volume.MaximumLength` and four bytes of padding -- an
/// integer, not an address. `UnicodeString::as_units` passed that to
/// `slice::from_raw_parts`, which is the access violation (`0xc0000005`) the
/// test VM bugchecked with, twice, on 2026-09-26.
///
/// The layout assertions at the bottom of this file did not catch it and could
/// not have: they pinned 4, 8 and 16, having been written from the same
/// misreading of the header as the declaration they were checking. An assertion
/// derived from the code it guards is a restatement, not a check -- which is why
/// the ones there now quote the header's line numbers instead.
///
/// The header continues with `Volume`, `Share`, `Extension`, `Stream`,
/// `FinalComponent` and `ParentDir`; nothing here reads them, and `Name` is the
/// whole path, which is the only reason this structure is fetched at all.
#[repr(C)]
pub struct FltFileNameInformation {
    /// `sizeof(FLT_FILE_NAME_INFORMATION)`, filled in by the filter manager.
    pub size: u16,
    /// `FLT_FILE_NAME_PARSED_FLAGS`, a `USHORT`: which components have been
    /// parsed out of `Name`. Not read here, but it has to occupy the two bytes
    /// it really occupies, or `name` moves.
    pub names_parsed: u16,
    /// `FLT_FILE_NAME_OPTIONS`, a `ULONG`: `FLT_FILE_NAME_NORMALIZED` or
    /// `FLT_FILE_NAME_OPENED`. Not read here.
    pub format: u32,
    /// The full name, as `\Device\HarddiskVolume3\Windows\System32\cmd.exe`.
    pub name: UnicodeString,
}

/// `FLT_REGISTRATION`.
///
/// All of the fields past `OperationRegistration` are pointers, so their order
/// cannot change this structure's size -- but `FilterUnloadCallback`'s position
/// is load-bearing and is asserted below, because a wrong slot there would call
/// something that is not a callback when the driver unloads.
#[repr(C)]
pub struct FltRegistration {
    /// `sizeof(FLT_REGISTRATION)`. The filter manager rejects a mismatch.
    pub size: u16,
    /// `FLT_REGISTRATION_VERSION`, which is 0x0200 for every target this
    /// driver builds for.
    pub version: u16,
    /// `FLT_REGISTRATION_FLAGS`. Zero: no contexts, no name provider.
    pub flags: u32,
    /// No context registration: this driver stores nothing per file.
    pub context_registration: *const c_void,
    /// The operation table, terminated by a zeroed entry.
    pub operation_registration: *const FltOperationRegistration,
    /// Called when the filter is unloaded or the system shuts down.
    pub filter_unload_callback: Option<FilterUnloadCallback>,
    /// Called once per volume, when the filter is attached to it. This is where
    /// the volume-name cache is filled, and the ordering that makes filling it
    /// there sound is documented on [`VolumeCache`].
    pub instance_setup_callback: Option<InstanceSetupCallback>,
    /// The remaining callbacks are not used and are null. Their positions are
    /// `InstanceQueryTeardown`, `InstanceTeardownStart`,
    /// `InstanceTeardownComplete`, `GenerateFileName`, `NormalizeNameComponent`,
    /// `NormalizeContextCleanup`, `TransactionNotification`,
    /// `NormalizeNameComponentEx`, `SectionNotification`.
    pub unused_tail: [*const c_void; 9],
}

/// `FLT_OPERATION_REGISTRATION`, one per major function, zero-terminated.
#[repr(C)]
pub struct FltOperationRegistration {
    /// The major function, or [`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`].
    pub major_function: u8,
    /// `FLT_OPERATION_REGISTRATION_FLAGS`. Zero, or
    /// [`FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO`].
    ///
    /// This was zero on all three entries until 2026-09-27, with a comment
    /// claiming paging I/O was deliberately kept "because a paging write of an
    /// executable is exactly the thing this driver wants to see". That is not
    /// what a paging write is: it is the memory manager writing back a page it
    /// already owns, it cannot be refused, and it arrives at `DISPATCH_LEVEL`
    /// where neither `FltGetFileNameInformation` nor `FltSendMessage` may be
    /// called. The two entries that can be reached at that level now skip it.
    pub flags: u32,
    /// Called before the operation.
    pub pre_operation: Option<PreOperationCallback>,
    /// Called after it.
    pub post_operation: Option<PostOperationCallback>,
    /// Reserved by the header.
    pub reserved1: *mut c_void,
}

/// `PFLT_PRE_OPERATION_CALLBACK`.
///
/// # Safety
///
/// Called by the filter manager with a valid `data` and `flt_objects`, at an
/// IRQL the header ties to the return value: `PASSIVE_LEVEL` unless the return
/// is `FLT_PREOP_COMPLETE`, in which case `DISPATCH_LEVEL` is also allowed.
pub type PreOperationCallback = unsafe extern "system" fn(
    data: *mut FltCallbackData,
    flt_objects: *const c_void,
    completion_context: *mut *mut c_void,
) -> i32;

/// `PFLT_POST_OPERATION_CALLBACK`.
///
/// # Safety
///
/// Called at `DISPATCH_LEVEL` or below, and at `DISPATCH_LEVEL` only when the
/// pre-operation returned `FLT_PREOP_SYNCHRONIZE`. Nothing here may page.
pub type PostOperationCallback = unsafe extern "system" fn(
    data: *mut FltCallbackData,
    flt_objects: *const c_void,
    completion_context: *mut c_void,
    flags: u32,
) -> i32;

/// `PFLT_GENERIC_WORKITEM_ROUTINE`, `fltKernel.h` line 4731:
///
/// ```c
/// typedef VOID
/// (FLTAPI *PFLT_GENERIC_WORKITEM_ROUTINE) (
///     _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
///     _In_ PVOID FltObject,
///     _In_opt_ PVOID Context
///     );
/// ```
///
/// # Safety
///
/// Called on a system worker thread at `PASSIVE_LEVEL`, so the things a
/// callback cannot do -- block, allocate from paged pool, call an
/// `_IRQL_requires_max_(APC_LEVEL)` API -- are legal here. The `FltObject` is
/// whatever was passed to [`FltQueueGenericWorkItem`]; the `Context` is the
/// data this driver queued.
pub type GenericWorkItemRoutine = unsafe extern "system" fn(
    work_item: FltGenericWorkItem,
    filter: *mut c_void,
    context: *mut c_void,
);

/// `POOL_FLAG_NON_PAGED`, from `wdm.h` line 25125: `0x40`, "Non paged pool NX".
///
/// Named rather than inlined because it is not zero: the old `POOL_TYPE`
/// spelling of non-paged pool *was* zero, and the flag form carries the NX bit
/// as well. A driver that assumed the two agree would ask for paged pool.
///
/// The choice is not stylistic either. The block this allocates is built from a
/// callback that can run at `DISPATCH_LEVEL`, where paged pool is not
/// addressable -- which is also what `wdm.h` line 25427 keys the call's IRQL
/// cap on: non-paged flags give `_IRQL_requires_max_(DISPATCH_LEVEL)`, and
/// `POOL_FLAG_PAGED` gives `APC_LEVEL`.
pub const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;

/// `CriticalWorkQueue`, from `wdm.h` line 26996: the first member of
/// `WORK_QUEUE_TYPE`, so zero.
///
/// A write notification wants to be delivered while it is still news, and this
/// is the queue that does that. `DelayedWorkQueue` can be starved for as long
/// as the machine is busy. Queueing without bound on a critical queue is how a
/// driver monopolises the worker pool, which is what `MAX_PENDING_EVENTS` in
/// `lib.rs` exists to prevent.
pub const CRITICAL_WORK_QUEUE: i32 = 0;

/// Four characters read as a little-endian `u32`: `WlEv`. Pool tags are how a
/// pool allocation is attributed to its owner in a kernel dump.
///
/// It reads `WlWr` (`WRITE_EVENT_TAG`) until 2026-10-09, when the driver began
/// queueing a second kind of header-only event through the same block — the
/// report of what `PsSetCreateProcessNotifyRoutineEx` answered. A tag that says
/// "write" on a block that is not one is the kind of thing a dump reader
/// believes, so the name and the bytes both changed.
pub const EVENT_TAG: u32 = u32::from_le_bytes(*b"WlEv");

/// Four characters read as a little-endian `u32`: `WlPs`.
///
/// A process-start notification's block is the only one in this driver that is
/// more than a header — it carries the image name the kernel handed to the
/// process-creation callback — so it is a separate allocation, with a separate
/// tag, from [`EVENT_TAG`].
pub const PROCESS_EVENT_TAG: u32 = u32::from_le_bytes(*b"WlPs");

/// `PFLT_FILTER_UNLOAD_CALLBACK`, `fltKernel.h` line 2033:
///
/// ```c
/// typedef NTSTATUS
/// (FLTAPI *PFLT_FILTER_UNLOAD_CALLBACK) (
///     FLT_FILTER_UNLOAD_FLAGS Flags
///     );
/// ```
///
/// One parameter, and it is the flags: a `ULONG`, passed by value. This declared
/// `filter: FltFilter` until 2026-09-26, which takes a 64-bit pointer where a
/// 32-bit scalar is handed over. Of the three declarations corrected in this
/// file that day it is the one that crashed nothing -- the callback is only
/// reached on an unload, the argument is never read, and the upper half of the
/// register is ignored either way. It is fixed because the declaration was
/// untrue, not because it was a fault.
pub type FilterUnloadCallback = unsafe extern "system" fn(flags: u32) -> NtStatus;

/// `PCFLT_RELATED_OBJECTS`, truncated after `Volume`.
///
/// `Size` is `USHORT`, `TransactionContext` is a `USHORT` that only the
/// transaction manager uses, and four bytes of padding follow before the first
/// pointer. `Volume` at offset 16 is the whole reason this is declared: the
/// instance-setup callback receives one of these and nothing else that names
/// the volume being attached.
///
/// The header continues with `Instance`, `FileObject` and `Transaction`, for 48
/// bytes in total. They are not declared, and the size assertion at the bottom
/// of this file pins the truncated size rather than the real one -- which is
/// the honest form of the assertion, because it is the number that would change
/// if `Volume` moved. A pointer to the real structure still reads `Volume`
/// correctly, because a C prefix lays out identically whether or not the rest
/// of the structure was declared.
#[repr(C)]
pub struct FltRelatedObjects {
    /// `sizeof(FLT_RELATED_OBJECTS)`, filled in by the filter manager.
    pub size: u16,
    /// The TxF mini-version. Not read here.
    pub transaction_context: u16,
    pad: u32,
    /// The filter this instance belongs to. Not read: the driver has its own
    /// copy in `FILTER` and does not need this one.
    pub filter: FltFilter,
    /// The volume being attached to.
    pub volume: FltVolume,
}

/// `PFLT_INSTANCE_SETUP_CALLBACK`.
///
/// # Safety
///
/// Called at `PASSIVE_LEVEL`, which is what makes the volume-name lookup in the
/// implementation legal: `IoVolumeDeviceToDosName` allocates and is only
/// callable from a thread that can be paged.
pub type InstanceSetupCallback = unsafe extern "system" fn(
    flt_objects: *const FltRelatedObjects,
    flags: u32,
    volume_device_type: u32,
    volume_filesystem_type: u32,
) -> NtStatus;

/// `PFLT_CONNECT_NOTIFY`, `fltKernel.h` line 4593:
///
/// ```c
/// typedef NTSTATUS
/// (FLTAPI *PFLT_CONNECT_NOTIFY) (
///       _In_ PFLT_PORT ClientPort,
///       _In_opt_ PVOID ServerPortCookie,
///       _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
///       _In_ ULONG SizeOfContext,
///       _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
///       );
/// ```
///
/// Five parameters, and the first is the news: `ClientPort` is a `PFLT_PORT` --
/// `fltKernel.h` line 257, `typedef struct _FLT_PORT *PFLT_PORT` -- passed **by
/// value**. It is the port to keep, not a pointer to one.
///
/// This declared four parameters with the first as `client_port: *mut FltPort`,
/// until 2026-09-26, and `port_connect` in `lib.rs` dereferenced it. That read
/// the first eight bytes of the filter manager's own `_FLT_PORT` object and
/// stored *those* as the connected client port, so `FltSendMessage` was handed a
/// number that is not a port. Nothing could see it before that day: the port
/// refused every client until the security descriptor was fixed, so this
/// callback had never once run.
///
/// The missing fifth parameter is `_Outptr_result_maybenull_`, so a driver that
/// does not want a connection cookie may leave it alone; this one writes null
/// into it, which is what `port_disconnect`'s argument then is.
pub type ConnectNotifyCallback = unsafe extern "system" fn(
    client_port: FltPort,
    server_port_cookie: *mut c_void,
    connection_context: *mut c_void,
    size_of_context: u32,
    connection_port_cookie: *mut *mut c_void,
) -> NtStatus;

/// `PFLT_DISCONNECT_NOTIFY`, `fltKernel.h` line 4607:
///
/// ```c
/// typedef VOID
/// (FLTAPI *PFLT_DISCONNECT_NOTIFY) (
///       _In_opt_ PVOID ConnectionCookie
///       );
/// ```
///
/// Returns `VOID`. The argument is whatever `ConnectNotifyCallback` left in its
/// `ConnectionPortCookie`, which this driver sets to null.
pub type DisconnectNotifyCallback = unsafe extern "system" fn(connection_context: *mut c_void);

/// `PFLT_MESSAGE_NOTIFY`, `fltKernel.h` line 4579:
///
/// ```c
/// typedef NTSTATUS
/// (FLTAPI *PFLT_MESSAGE_NOTIFY) (
///     _In_opt_ PVOID PortCookie,
///     _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
///     _In_ ULONG InputBufferLength,
///     _Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
///     _In_ ULONG OutputBufferLength,
///     _Out_ PULONG ReturnOutputBufferLength
///     );
/// ```
///
/// **Six** parameters. This declared five until 2026-09-26, and the mistake was
/// in the middle rather than at the end: the fourth is the output buffer and the
/// fifth is `OutputBufferLength`, a `ULONG` **by value**, while the sixth --
/// `ReturnOutputBufferLength`, the `PULONG` a handler writes its byte count
/// through -- was dropped altogether. The declaration here called the value slot
/// `*mut u32` and `port_message` wrote `0` through it, so a message from user
/// mode would have been answered by writing to whatever address the buffer
/// length happened to be.
///
/// Nothing reaches this callback yet -- the service uses `FilterConnect`,
/// `FilterGetMessage` and `FilterReplyMessage`, and none of those arrives here;
/// `FilterSendMessage` is what would. It is corrected as a fault that is one
/// line of user-mode code away from firing, not as the cause of a crash.
pub type MessageNotifyCallback = unsafe extern "system" fn(
    port_cookie: *mut c_void,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
    return_output_buffer_length: *mut u32,
) -> NtStatus;

/// `IO_STATUS_BLOCK`, truncated to the fields this driver reads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoStatusBlock {
    /// `NTSTATUS` or the number of bytes transferred, depending on who set it.
    pub status: NtStatus,
    pad: u32,
    /// Byte count for a successful operation.
    pub information: usize,
}

/// `FLT_CALLBACK_DATA`, truncated after `IoStatus`.
///
/// The header continues with `TagData` and a union of requestor data; nothing
/// here reads past `IoStatus`, and a C prefix lays out identically whether or
/// not the rest of the structure was declared.
#[repr(C)]
pub struct FltCallbackData {
    /// `FLT_CALLBACK_DATA_FLAGS`.
    pub flags: u32,
    pad: u32,
    /// The thread that issued the operation.
    pub thread: *mut c_void,
    /// The parameters of the operation.
    pub iopb: *mut FltIoParameterBlock,
    /// Where the pre-operation writes `STATUS_ACCESS_DENIED` to refuse.
    pub io_status: IoStatusBlock,
}

/// `FLT_IO_PARAMETER_BLOCK`, truncated after `Parameters`.
#[repr(C)]
pub struct FltIoParameterBlock {
    /// `IRP` flags; not read here.
    pub irp_flags: u32,
    /// The major function, which for a filter-manager callback may be
    /// [`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`].
    pub major_function: u8,
    /// The minor function; not read here.
    pub minor_function: u8,
    /// Operation flags; not read here.
    pub operation_flags: u8,
    reserved: u8,
    /// The file the operation is on.
    pub target_file_object: *mut c_void,
    /// The instance the operation arrived through; not read here.
    pub target_instance: *mut c_void,
    /// The per-operation parameters. The `Create` and
    /// `AcquireForSectionSynchronization` arms are modelled.
    pub parameters: FltParameters,
}

/// `FLT_PARAMETERS`, of which the two arms this driver reads are modelled.
///
/// A union's size is its largest member's; each arm is declared only as far as
/// the driver reads it, and an opaque span that is at least as large as the
/// largest arm the header declares keeps `size_of` honest for the assertions
/// below. Every arm starts at offset zero, so adding one cannot move another.
#[repr(C)]
pub union FltParameters {
    /// `Create`, the arm a `IRP_MJ_CREATE` pre-operation reads.
    pub create: FltCreateParameters,
    /// `AcquireForSectionSynchronization`, the arm
    /// `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` reads.
    pub acquire_for_section: FltSectionParameters,
    _span: [usize; 32],
}

/// The `Create` arm's leading field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FltCreateParameters {
    /// `PIO_SECURITY_CONTEXT`, whose `DesiredAccess` says whether this open
    /// intends to execute the file.
    pub security_context: *mut IoSecurityContext,
}

/// The `AcquireForSectionSynchronization` arm's two leading fields, which are
/// the whole of what this driver reads of it.
///
/// `fltKernel.h` 941-947:
///
/// ```c
/// struct {
///     FS_FILTER_SECTION_SYNC_TYPE SyncType;
///     ULONG PageProtection;
///     PFS_FILTER_SECTION_SYNC_OUTPUT OutputInformation;
///     ULONG Flags;
///     ULONG AllocationAttributes; // Specified if SyncType is SyncTypeCreateSection
/// } AcquireForSectionSynchronization;
/// ```
///
/// `PageProtection` is at **offset 4**, immediately after the enum, and not
/// behind a pointer: `FS_FILTER_SECTION_SYNC_TYPE` is a C enum, which MSVC lays
/// out as four bytes, so the field the driver gates on is the second word of the
/// union. This was read from the header rather than recalled, and the offsets are
/// asserted at the bottom of this file -- the one structure in this file whose
/// layout a plausible-but-wrong memory would have put somewhere else entirely
/// (`PVOID StartVa; ULONG Length;` is how the same IRP's parameters are described
/// in places that are not this header, and it would have moved the protection
/// past the end of the arm).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FltSectionParameters {
    /// `FS_FILTER_SECTION_SYNC_TYPE`: [`SYNC_TYPE_OTHER`] or
    /// [`SYNC_TYPE_CREATE_SECTION`] (`ntifs.h` 19808).
    pub sync_type: u32,
    /// `ULONG PageProtection`, one of the `PAGE_*` values from `wdm.h` 8777.
    /// Meaningful when `sync_type` is [`SYNC_TYPE_CREATE_SECTION`].
    pub page_protection: u32,
}

/// `SyncTypeOther`, the first value of `FS_FILTER_SECTION_SYNC_TYPE`
/// (`ntifs.h` 19809): an existing section is being acquired, not created.
pub const SYNC_TYPE_OTHER: u32 = 0;

/// `SyncTypeCreateSection` (`ntifs.h` 19810): the section itself is being
/// created, and `PageProtection` says what it is for.
pub const SYNC_TYPE_CREATE_SECTION: u32 = 1;

/// The four `PAGE_EXECUTE*` protections (`wdm.h` 8782-8785), which are the
/// values `0x10` through `0x80`.
pub const PAGE_EXECUTE_MASK: u32 = 0xF0;

/// Whether an acquire-for-section is the creation of a section that will be
/// executable -- that is, whether an execution is about to happen.
///
/// This is the section path's counterpart to the `FILE_EXECUTE` test the create
/// pre-operation makes on `DesiredAccess`, and it exists because the section
/// callback had no counterpart at all: it asked the service about **every**
/// non-paging acquire, which includes every memory-mapped *data* file on the
/// machine. Measured on 2026-10-01, that is what made the service scan a
/// `ConsoleHost_history.txt` and quarantine it, quarantine a sample the moment
/// it was copied into a folder, and hold a core busy; a scan that ran past the
/// driver's five-second timeout is what produced the
/// `ERROR_FLT_NO_WAITER_FOR_REPLY` warnings alongside them.
///
/// Both conditions are needed and neither is merely a filter for speed:
///
/// * `SyncTypeCreateSection` is the moment the section comes into existence, and
///   the only moment at which `PageProtection` describes the request rather than
///   the already-existing object. Acquiring an existing section is not a new
///   execution, and its `PageProtection` is not specified.
/// * An execute protection is what separates an image about to run from a data
///   file about to be read. `PAGE_READONLY`, `PAGE_READWRITE` and
///   `PAGE_WRITECOPY` are the three a memory-mapped data file asks for, and none
///   of them sets a bit in the mask.
///
/// A `const fn` rather than two comparisons at the call site so that the
/// assertions at the bottom of this file can check the table rather than
/// restate it.
pub const fn section_will_execute(sync_type: u32, page_protection: u32) -> bool {
    sync_type == SYNC_TYPE_CREATE_SECTION && page_protection & PAGE_EXECUTE_MASK != 0
}

/// `IO_SECURITY_CONTEXT`, from `wdm.h`.
///
/// The first member is `SecurityQos`, not `SecurityDescriptor` -- worth having
/// read rather than recalled, because both are pointers and a wrong first
/// member would put `DesiredAccess` at the right offset by luck while making
/// every other field of the structure a lie.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoSecurityContext {
    /// `PSECURITY_QUALITY_OF_SERVICE`. Not read here.
    pub security_qos: *mut c_void,
    /// `PACCESS_STATE`. Not read here.
    pub access_state: *mut c_void,
    /// `ACCESS_MASK`. The `FILE_EXECUTE` bit is why this structure is read.
    pub desired_access: u32,
    /// `ULONG`. Not read here.
    pub full_create_options: u32,
}

/// `OBJECT_ATTRIBUTES`, from `wdm.h`, for naming the communication port.
#[repr(C)]
pub struct ObjectAttributes {
    /// `sizeof(OBJECT_ATTRIBUTES)`.
    pub length: u32,
    /// `POBJECT_ATTRIBUTES` parent, or null for a name in the root.
    pub root_directory: *mut c_void,
    /// The port name, which must be a counted `UNICODE_STRING`.
    pub object_name: *mut UnicodeString,
    /// `OBJ_CASE_INSENSITIVE` and friends.
    pub attributes: u32,
    /// Optional; null here.
    pub security_descriptor: *mut c_void,
    /// Optional; null here.
    pub security_quality_of_service: *mut c_void,
}

/// `OBJ_CASE_INSENSITIVE`, from `wdm.h`.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
/// `OBJ_KERNEL_HANDLE`, from `wdm.h`. Required: a port name created with a
/// user-mode handle would be openable by anything that guessed it.
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

#[link(name = "fltMgr")]
extern "system" {
    /// Registers the minifilter. `driver` is the `PDRIVER_OBJECT` the loader
    /// hands to `DriverEntry`.
    pub fn FltRegisterFilter(
        driver: *mut c_void,
        registration: *const FltRegistration,
        ret_filter: *mut FltFilter,
    ) -> NtStatus;

    /// Starts the callbacks. Until this returns, no operation is seen.
    pub fn FltStartFiltering(filter: FltFilter) -> NtStatus;

    /// Deregisters. Returns only once no callback is running.
    pub fn FltUnregisterFilter(filter: FltFilter);

    /// Creates the server end of a communication port.
    pub fn FltCreateCommunicationPort(
        filter: FltFilter,
        server_port: *mut FltPort,
        object_attributes: *mut ObjectAttributes,
        server_port_cookie: *mut c_void,
        connect_notify: Option<ConnectNotifyCallback>,
        disconnect_notify: Option<DisconnectNotifyCallback>,
        message_notify: Option<MessageNotifyCallback>,
        max_connections: i32,
    ) -> NtStatus;

    /// Closes the server end.
    pub fn FltCloseCommunicationPort(server_port: FltPort);

    /// Allocates the filter manager's default security descriptor, granting
    /// `desired_access` to SYSTEM and to administrators.
    ///
    /// The port has to be given one; see [`FLT_PORT_ALL_ACCESS`]. The
    /// allocation is the filter manager's, and it is released with
    /// [`FltFreeSecurityDescriptor`] rather than by anything here -- which is
    /// the one place in this crate a byte is allocated, and it is freed on
    /// every path out of `create_port`.
    pub fn FltBuildDefaultSecurityDescriptor(
        security_descriptor: *mut *mut c_void,
        desired_access: u32,
    ) -> NtStatus;

    /// Releases what [`FltBuildDefaultSecurityDescriptor`] returned.
    pub fn FltFreeSecurityDescriptor(security_descriptor: *mut c_void);

    /// Sends a message to the service and optionally waits for a reply.
    ///
    /// `timeout` is a relative `LARGE_INTEGER` in 100-nanosecond units, and a
    /// null `timeout` waits for ever, which is the one thing this driver must
    /// never do.
    pub fn FltSendMessage(
        filter: FltFilter,
        client_port: *mut FltPort,
        sender_buffer: *mut c_void,
        sender_buffer_length: u32,
        reply_buffer: *mut c_void,
        reply_length: *mut u32,
        timeout: *mut i64,
    ) -> NtStatus;

    /// Allocates a work item that the filter manager owns.
    ///
    /// `_IRQL_requires_max_(DISPATCH_LEVEL)` (`fltKernel.h` 4753), which is the
    /// reason this pair and not a `WORK_QUEUE_ITEM`: a write post-operation runs
    /// at `DISPATCH_LEVEL`, and what has to happen there is a *deferral* of the
    /// send rather than the send itself.
    ///
    /// Ownership is the second reason, and the one that matters on unload.
    /// `FltUnregisterFilter` does not return until every work item queued
    /// against the filter has run, so a worker thread cannot still be calling
    /// `FltSendMessage` with a filter handle that has been deregistered. A raw
    /// `ExQueueWorkItem` gives no such promise.
    pub fn FltAllocateGenericWorkItem() -> FltGenericWorkItem;

    /// Releases a work item. Called from the routine it ran, which is the only
    /// place that knows it has.
    pub fn FltFreeGenericWorkItem(flt_work_item: FltGenericWorkItem);

    /// Queues it, tied to `filter`.
    ///
    /// `_IRQL_requires_max_(DISPATCH_LEVEL)` (`fltKernel.h` 4780). `context` is
    /// handed to `routine` untouched, which is how one event's fields reach the
    /// worker thread without a queue of this driver's own.
    ///
    /// Returns an `NTSTATUS`, and the work item is *not* freed on failure --
    /// the caller still owns it and still has to release it.
    pub fn FltQueueGenericWorkItem(
        flt_work_item: FltGenericWorkItem,
        filter: FltFilter,
        routine: GenericWorkItemRoutine,
        queue_type: i32,
        context: *mut c_void,
    ) -> NtStatus;

    /// Fetches the name of the file an operation is on.
    pub fn FltGetFileNameInformation(
        data: *mut FltCallbackData,
        name_options: u32,
        ret_information: *mut *mut FltFileNameInformation,
    ) -> NtStatus;

    /// Releases what `FltGetFileNameInformation` returned. Must be called from
    /// the same IRQL, and before the callback returns.
    pub fn FltReleaseFileNameInformation(information: *mut FltFileNameInformation);

    /// Looks up a volume by its `\Device\HarddiskVolumeN` name.
    pub fn FltGetVolumeFromName(
        filter: FltFilter,
        volume_name: *const UnicodeString,
        ret_volume: *mut FltVolume,
    ) -> NtStatus;

    /// The disk device object backing a volume, which is what the DOS-name
    /// lookup wants.
    pub fn FltGetDiskDeviceObject(volume: FltVolume, ret_device: *mut *mut c_void) -> NtStatus;

    /// The filter-manager name of a volume, which is `\Device\HarddiskVolumeN`.
    ///
    /// Two-call convention: with a buffer too small for the name it returns
    /// `STATUS_BUFFER_TOO_SMALL` and writes the size needed into
    /// `buffer_size_needed`. This driver takes that answer as a refusal to cache
    /// rather than as a signal to allocate: the caller's buffer is a stack
    /// array, which is the only kind of allocation this driver does.
    pub fn FltGetVolumeName(
        volume: FltVolume,
        volume_name: *mut UnicodeString,
        buffer_size_needed: *mut u32,
    ) -> NtStatus;
}

extern "system" {
    /// `KeGetCurrentIrql`, from `wdm.h`. `KIRQL` is a `UCHAR`.
    ///
    /// Declared rather than read from `wdk-sys`, on the same reasoning as
    /// `KeQueryInterruptTimePrecise` in `lib.rs`: one fewer binding version to
    /// depend on, for a call that takes no arguments and so has nothing to get
    /// wrong.
    ///
    /// What this comment used to say is worth keeping, because it is how the
    /// other one of these came to be wrong. It cited five references to the name
    /// in `Lib\10.0.26100.0\km\x64\ntoskrnl.lib` as evidence that the
    /// declaration was right -- "the same count the other one has". A name
    /// resolving in the library is evidence about the *name*, and none at all
    /// about the parameter list. The other declaration left a parameter off and
    /// bugchecked the machine on every boot (see the comment on it in `lib.rs`).
    /// Both are compared against their headers at build time now, by `build.rs`.
    fn KeGetCurrentIrql() -> u8;

    /// `IoVolumeDeviceToDosName`, from `ntddk.h`: the one call that turns a
    /// volume device object into `C:`. Allocates the returned buffer from the
    /// pool the caller's IRQL allows, so it is only called at `PASSIVE_LEVEL`.
    pub fn IoVolumeDeviceToDosName(
        volume_device_object: *mut c_void,
        dos_name: *mut UnicodeString,
    ) -> NtStatus;

    /// Releases the reference `FltGetDiskDeviceObject` added.
    pub fn ObDereferenceObject(object: *mut c_void);

    /// `ExAllocatePool2`, from `wdm.h` line 25431. `POOL_FLAGS` is a `ULONG64`
    /// and `SIZE_T` is a `usize`, so the three arguments are the three types
    /// here with nothing to widen.
    ///
    /// The return is zeroed unless `POOL_FLAG_UNINITIALIZED` is set -- which is
    /// what the deprecation notice on `ExAllocatePoolWithTag` in the same
    /// header gives as the reason to use this instead of it.
    pub fn ExAllocatePool2(flags: u64, number_of_bytes: usize, tag: u32) -> *mut c_void;

    /// `ExFreePoolWithTag`, from `wdm.h`. The tag has to be the one the block
    /// was allocated with; freeing with a different one corrupts the pool
    /// accounting rather than failing.
    pub fn ExFreePoolWithTag(base: *mut c_void, tag: u32);

    /// `PsGetProcessImageFileName`, declared here because **no header declares
    /// it**.
    ///
    /// That is a fact about the WDK, measured rather than assumed: it occurs
    /// zero times under `Include\10.0.26100.0`, and it is nonetheless a real
    /// export -- `Lib\10.0.26100.0\km\x64\ntoskrnl.lib` carries it three times,
    /// which was checked with two controls on the same search: `KeGetCurrentIrql`
    /// also three, `ZzzNotASymbolAtAll` zero. So the name links and the header
    /// simply does not describe it, which is why this declaration exists instead
    /// of a `wdk-sys` path.
    ///
    /// It returns the `UCHAR[15]` `EPROCESS.ImageFileName` field directly -- a
    /// pointer *into* the process object, not an allocation, and not a reference
    /// the caller releases. That is the whole reason it is used here rather than
    /// the header-declared alternative, `SeLocateProcessImageName`
    /// (`ntifs.h` 19444): that one returns a full path, and it allocates it and
    /// writes the result back into the process object. Both are unacceptable on
    /// a path that runs once per handle open, which is what this is.
    ///
    /// The cost is fifteen bytes and no directory, which is the right trade for
    /// the question being asked -- "is this handle aimed at *our* process" is
    /// answered by the file name alone, and [`crate::PROTECTED_IMAGES`] is what
    /// it is compared against.
    ///
    /// # Safety
    ///
    /// `process` must be a valid `PEPROCESS` with a reference held for the
    /// duration of the call. The returned pointer is to at most 15 bytes that
    /// the caller must not write and must not free.
    pub fn PsGetProcessImageFileName(process: *mut c_void) -> *const u8;

    /// `PsGetCurrentProcessId`, from `ntddk.h` line 11385 -- declared here rather
    /// than taken from `wdk-sys` because the binding generator emits the header's
    /// `#if (NTDDI_VERSION >= NTDDI_WIN2K)` block only for the target it was run
    /// for, and the name is in `ntoskrnl.lib` regardless.
    ///
    /// **This is not the requested-process API the module documentation puts out
    /// of bounds.** That prohibition is about `FltGetRequestorProcess` and its two
    /// siblings, which dereference `[CallbackData - 0xB8]` without a null check;
    /// this one is a field read of the calling thread's own process and has no
    /// pointer argument at all. What it answers is *who issued this operation*,
    /// which for a section created during process creation is the process that
    /// called `CreateProcess` -- not the program about to be started. Its only
    /// use here is the pid on the service's log line.
    ///
    /// `ntddk.h` annotates it `_IRQL_requires_max_(PASSIVE_LEVEL)` by default, so
    /// the only caller must already be at passive level; `decide`'s IRQL gate is
    /// what provides that.
    ///
    /// The return type is `HANDLE` in the header and the value is the process
    /// identifier, so it is widened to `usize` by the caller rather than
    /// dereferenced as a pointer.
    pub fn PsGetCurrentProcessId() -> *mut c_void;

    /// `SeExports`, reached through its import slot rather than by name.
    ///
    /// **Two declarations for one object, and the alternative does not link.**
    /// `wdk-sys` declares this the way `ntifs.h` does -- `pub static mut
    /// SeExports: PSE_EXPORTS` inside an `extern "C"` block -- and that
    /// declaration produces an undefined symbol named `SeExports`, which this
    /// link configuration cannot resolve. Measured rather than guessed:
    /// `link.exe` answered
    ///
    /// ```text
    /// error LNK2019: unresolved external symbol SeExports referenced in
    ///                function `av_driver::protect_handle`
    /// ```
    ///
    /// and the reason is in the library, not in the name. `ntoskrnl.lib`
    /// contains `__imp_SeExports` and **does not** contain a bare `SeExports`
    /// symbol: searching the file for the string finds it three times, once
    /// inside the import-name table (`SeExports\0ntoskrnl.exe`) and twice
    /// adjacent to `__imp_SeExports` in the symbol tables. A compiler that saw
    /// `__declspec(dllimport)` would emit the `__imp_` name itself, and WDK code
    /// gets that from the build rather than from the header -- which is why the
    /// same source links in a WDK build and not here.
    ///
    /// So this names the slot the linker does have. `__imp_SeExports` holds the
    /// value `SeExports` would have had, which is a `PSE_EXPORTS`: a pointer to
    /// the kernel's privilege table. Reading this *is* reading `SeExports`, and
    /// the type below is the same `PSE_EXPORTS` `wdk-sys` uses for it.
    ///
    /// One field of that table is read -- `SeTcbPrivilege`, the privilege
    /// `PsIsSystemProcess` is documented to test for -- and the table is the
    /// kernel's own, initialised before any driver loads.
    ///
    /// # Safety
    ///
    /// The kernel initialises it before this driver's `DriverEntry` runs, so it
    /// is non-null wherever this driver can be. The table it points at must not
    /// be written, which nothing in this crate does.
    #[link_name = "__imp_SeExports"]
    pub static mut SE_EXPORTS: wdk_sys::PSE_EXPORTS;
}

/// The longest volume name this driver will hold, in UTF-16 units. A drive
/// letter form is two units (`C:`); a mounted-folder form is longer, and a
/// volume mounted at a path is exactly the case worth not truncating. Both
/// `FltGetVolumeName`'s answer (`\Device\HarddiskVolumeN`) and the DOS name have
/// to fit.
pub const VOLUME_NAME_UNITS: usize = 64;

/// How many volumes are remembered.
///
/// Eight rather than one because a machine with a second volume is ordinary,
/// and rather than a fraction of the 26 drive letters because each entry is 272
/// bytes of a `static` and this is not a cache with an eviction policy -- it is
/// a table filled once per volume at attach time and never written again. A
/// ninth volume is not cached, which costs a `unresolved_volume` count and
/// nothing else: the operation is allowed, and the service still sees it.
pub const VOLUME_SLOTS: usize = 8;

/// One remembered volume name, keyed by the exact device prefix.
///
/// `repr(C)` is not decoration here. Without it Rust is free to order the
/// fields, and the layout assertions at the bottom of this file -- which exist
/// so that a mistake in this file is a build failure -- would be asserting a
/// layout nothing guarantees. This is the one structure in the file that is not
/// passed to the filter manager, so it is the one where the attribute could be
/// forgotten without the filter manager noticing.
#[repr(C)]
#[derive(Clone, Copy)]
struct VolumeEntry {
    /// `\Device\HarddiskVolume3`, with no trailing separator.
    device: [u16; VOLUME_NAME_UNITS],
    device_len: usize,
    /// `C:`, with no trailing separator and no backslash.
    dos: [u16; VOLUME_NAME_UNITS],
    dos_len: usize,
}

impl VolumeEntry {
    /// A slot that names nothing. `device_len == 0` never matches, because the
    /// normaliser rejects an empty device path before it asks.
    const EMPTY: Self = Self {
        device: [0; VOLUME_NAME_UNITS],
        device_len: 0,
        dos: [0; VOLUME_NAME_UNITS],
        dos_len: 0,
    };
}

/// The volume-name cache handed to `av_driver_proto`'s normaliser.
///
/// # When it is written, and why that is the whole soundness argument
///
/// Filling a slot costs three filter-manager calls and a paged allocation --
/// `FltGetVolumeFromName`, `FltGetDiskDeviceObject`, `IoVolumeDeviceToDosName`
/// -- and the last of those is callable only at `PASSIVE_LEVEL`. Filling it
/// lazily from a `CREATE` callback would therefore be a blocking, allocating,
/// pageable operation on the path that decides whether a program may run, on
/// the thread that is holding up every file open behind it. So the fill happens
/// once per volume instead, in the instance-setup callback, which the filter
/// manager invokes at `PASSIVE_LEVEL` when it attaches the filter to a volume
/// and -- this is the part the argument rests on -- *before* it dispatches any
/// operation to that instance. The write therefore happens-before every read of
/// the same slot, and the slot is never written twice.
///
/// # Why it is an array of atomics rather than a `Vec` behind a lock
///
/// A lock here would have to be taken by a reader, and a reader is a
/// pre-operation callback that may be about to block on `FltSendMessage`. A
/// lock that a decision path takes is a lock the reply path must not need, and
/// the cheapest way to be sure of that is not to have one. Slots are handed out
/// by `next` so no two writers share one, and a slot is published by setting
/// its bit in `ready` with release ordering, which is what makes the entry
/// visible to a reader that acquires the bit.
pub struct VolumeCache {
    /// Written once per slot, by the one writer that `next` gave the slot to.
    entries: core::cell::UnsafeCell<[VolumeEntry; VOLUME_SLOTS]>,
    /// Bit `i` is set once slot `i` holds a complete entry.
    ready: core::sync::atomic::AtomicU8,
    /// Handed out one per `prime`, so two concurrent primes cannot collide.
    next: core::sync::atomic::AtomicUsize,
}

impl VolumeCache {
    /// An empty cache.
    pub const fn new() -> Self {
        Self {
            entries: core::cell::UnsafeCell::new([VolumeEntry::EMPTY; VOLUME_SLOTS]),
            ready: core::sync::atomic::AtomicU8::new(0),
            next: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Resolve and remember `device`, which must be `\Device\HarddiskVolumeN`.
    ///
    /// # Safety
    ///
    /// `filter` must be a filter this driver has registered, and the caller
    /// must guarantee that no operation on this volume can be dispatched to
    /// this driver before this returns -- which is exactly what the
    /// instance-setup callback guarantees, and is why it is the only caller.
    /// It must also be called at `PASSIVE_LEVEL`, because
    /// `IoVolumeDeviceToDosName` allocates.
    pub unsafe fn prime(&self, filter: FltFilter, device: &[u16]) {
        if device.is_empty() || device.len() > VOLUME_NAME_UNITS {
            return;
        }

        // Claimed before the lookups, so that two concurrent attaches take two
        // different slots rather than racing for one.
        let slot = self
            .next
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if slot >= VOLUME_SLOTS {
            return;
        }

        let volume_name = UnicodeString {
            length: (device.len() * 2) as u16,
            maximum_length: (device.len() * 2) as u16,
            pad: 0,
            // SAFETY: the cast drops the constness of a slice this call only
            // reads from, immediately below, before `device` is used again.
            buffer: device.as_ptr() as *mut u16,
        };

        let mut volume: FltVolume = core::ptr::null_mut();
        // SAFETY: `filter` is registered, `volume_name` is a counted string
        // built from a live slice, and the out-pointer is to a local.
        let status = unsafe { FltGetVolumeFromName(filter, &volume_name, &mut volume) };
        if status != STATUS_SUCCESS || volume.is_null() {
            return;
        }

        let mut disk: *mut c_void = core::ptr::null_mut();
        // SAFETY: `volume` came back from the call above and is still valid
        // until the reference taken here is released, which is done below.
        let status = unsafe { FltGetDiskDeviceObject(volume, &mut disk) };
        if status != STATUS_SUCCESS || disk.is_null() {
            return;
        }

        let mut dos = UnicodeString {
            length: 0,
            maximum_length: 0,
            pad: 0,
            buffer: core::ptr::null_mut(),
        };
        // SAFETY: `disk` is the reference just taken; `dos` is an out-parameter
        // the callee fills in, and its buffer is released below.
        let status = unsafe { IoVolumeDeviceToDosName(disk, &mut dos) };

        // The disk device object reference is dropped whether or not the name
        // lookup worked. Leaking it would pin the volume for the driver's life.
        // SAFETY: `disk` is the reference `FltGetDiskDeviceObject` added, and
        // this is the single release of it on every path out of this function.
        unsafe { ObDereferenceObject(disk) };

        if status != STATUS_SUCCESS {
            return;
        }

        // SAFETY: the callee's contract is that a successful
        // `IoVolumeDeviceToDosName` leaves `dos.buffer` valid for `dos.length`
        // bytes; the slice is copied out and the buffer released immediately.
        let dos_units = unsafe { dos.as_units() };
        let mut entry = VolumeEntry {
            device: [0; VOLUME_NAME_UNITS],
            device_len: device.len(),
            dos: [0; VOLUME_NAME_UNITS],
            dos_len: 0,
        };
        entry.device[..device.len()].copy_from_slice(device);

        // `IoVolumeDeviceToDosName` normally answers `C:` or `C:\`; the
        // protocol's `VolumeNames` contract wants no trailing separator, and
        // the normaliser appends the separator itself.
        let mut n = dos_units.len();
        while n > 0 && (dos_units[n - 1] == u16::from(b'\\') || dos_units[n - 1] == 0) {
            n -= 1;
        }
        if n == 0 || n > VOLUME_NAME_UNITS {
            return;
        }
        entry.dos[..n].copy_from_slice(&dos_units[..n]);
        entry.dos_len = n;

        // SAFETY: `slot` is this call's own -- `next` hands out each index at
        // most once, so no other thread writes this element -- and the entry is
        // published below with a release store, so no reader can observe a
        // partial one. `addr_of_mut!` keeps the write in terms of the raw
        // pointer rather than a `&mut` to the array, which would claim
        // exclusive access to slots other threads are filling.
        unsafe { core::ptr::addr_of_mut!((*self.entries.get())[slot]).write(entry) };
        self.ready
            .fetch_or(1u8 << slot, core::sync::atomic::Ordering::Release);
    }
}

impl VolumeNames for VolumeCache {
    fn dos_name_for_device(&self, device: &[u16]) -> Option<&[u16]> {
        use core::sync::atomic::Ordering;

        // The acquire load is what makes the slot contents visible: it reads a
        // value in the release sequence of the `fetch_or` that published it.
        let ready = self.ready.load(Ordering::Acquire);
        if ready == 0 {
            return None;
        }

        for slot in 0..VOLUME_SLOTS {
            if ready & (1u8 << slot) == 0 {
                continue;
            }
            // SAFETY: bit `slot` was set by a `fetch_or` with release ordering
            // that synchronises with the acquire load above, so the write that
            // filled the element happens-before this read; and the element is
            // never written again, because the writer that filled it owns it
            // alone. The borrow returned is of the cache, not of any buffer
            // passed in, which is what `VolumeNames` requires.
            let entry: &VolumeEntry = unsafe { &(*self.entries.get())[slot] };
            if entry.device_len == device.len() && &entry.device[..entry.device_len] == device {
                return Some(&entry.dos[..entry.dos_len]);
            }
        }
        None
    }
}

// Layout assertions. These are the reason this file can be trusted at all: a
// wrong offset is a build failure, not a bugcheck. Each expected value is
// arithmetic on the WDK header's field order, with x64 alignment applied.
const _: () = {
    // USHORT, USHORT, ULONG, then one pointer.
    assert!(core::mem::size_of::<UnicodeString>() == 16);
    assert!(core::mem::offset_of!(UnicodeString, buffer) == 8);

    // `fltKernel.h` 2749: USHORT Size, USHORT NamesParsed (line 2735 is
    // `typedef USHORT FLT_FILE_NAME_PARSED_FLAGS`), ULONG Format (line 2646 is
    // `typedef ULONG FLT_FILE_NAME_OPTIONS`), then UNICODE_STRING Name.
    //
    // These said 4, 8 and 16 until 2026-09-26, which is one field-width out at
    // the front and put `name` eight bytes past the real one. The numbers had
    // been derived from the declaration rather than from the header, so the
    // block agreed with the bug and the bug shipped. Any future edit here should
    // be made with `fltKernel.h` open, not by adjusting a number until it
    // compiles.
    assert!(core::mem::offset_of!(FltFileNameInformation, names_parsed) == 2);
    assert!(core::mem::offset_of!(FltFileNameInformation, format) == 4);
    assert!(core::mem::offset_of!(FltFileNameInformation, name) == 8);
    assert!(core::mem::size_of::<FltFileNameInformation>() == 24);

    // `wdm.h` 7270: `FILE_EXECUTE ( 0x0020 )`. The assertion worth having is not
    // the value itself but that it is not the value next to it in the header:
    // `FILE_READ_DATA` is `0x0001` (line 7255), and `FILE_EXECUTE` with that bit
    // clear is the difference between a driver that watches executions and one
    // that watches every read on the machine.
    assert!(FILE_EXECUTE == 0x0020);
    assert!(FILE_EXECUTE & 0x0001 == 0);

    // The `FLT_PREOP_*` values, from `fltKernel.h`'s
    // `FLT_PREOP_CALLBACK_STATUS` enumeration. Asserted because two of them
    // differ by one and mean opposite things about whether a post-operation
    // runs: `..._SUCCESS_WITH_CALLBACK` is 0 and `..._NO_CALLBACK` is 1, and
    // swapping them is a change nothing else in this driver would notice -- the
    // gate would still refuse, and every write would stop being reported.
    assert!(FLT_PREOP_SUCCESS_WITH_CALLBACK == 0);
    assert!(FLT_PREOP_SUCCESS_NO_CALLBACK == 1);
    assert!(FLT_PREOP_COMPLETE == 4);

    // Two USHORTs and a ULONG make eight bytes, then thirteen pointers.
    assert!(core::mem::offset_of!(FltRegistration, flags) == 4);
    assert!(core::mem::offset_of!(FltRegistration, operation_registration) == 16);
    // The slot a wrong-order declaration would move. The filter manager calls
    // this when the driver unloads, so a wrong value here is not survivable.
    assert!(core::mem::offset_of!(FltRegistration, filter_unload_callback) == 24);
    // The second slot a wrong-order declaration would move, and the one that
    // fills the volume cache. A pointer living here would be called as a
    // callback -- at attach time, once per volume, at PASSIVE_LEVEL.
    assert!(core::mem::offset_of!(FltRegistration, instance_setup_callback) == 32);
    assert!(core::mem::size_of::<FltRegistration>() == 8 + 13 * 8);
    assert!(
        core::mem::offset_of!(FltRegistration, unused_tail) == 40,
        "the tail must start after InstanceSetupCallback"
    );

    // Two USHORTs, four bytes of padding, then two pointers of the six.
    assert!(core::mem::offset_of!(FltRelatedObjects, filter) == 8);
    assert!(core::mem::offset_of!(FltRelatedObjects, volume) == 16);
    // The *truncated* size. The C structure is 48 bytes -- it continues with
    // `Instance`, `FileObject` and `Transaction` -- and this declaration stops
    // after `Volume` because nothing here reads further. Asserting 48 would fail
    // to compile, which is the point: the number below is what `Volume`'s
    // offset implies about this declaration, and it is the only number that
    // would change if a field were inserted above `Volume`.
    assert!(core::mem::size_of::<FltRelatedObjects>() == 24);

    // Two `[u16; 64]` arrays and two `usize` lengths, with no padding.
    assert!(core::mem::offset_of!(VolumeEntry, device) == 0);
    assert!(core::mem::offset_of!(VolumeEntry, device_len) == 128);
    assert!(core::mem::offset_of!(VolumeEntry, dos) == 136);
    assert!(core::mem::offset_of!(VolumeEntry, dos_len) == 264);
    assert!(core::mem::size_of::<VolumeEntry>() == 272);
    // One byte of `ready` addresses one slot per bit, so the table cannot be
    // wider than the mask that publishes it.
    assert!(VOLUME_SLOTS <= 8);

    // UCHAR, ULONG (so three bytes of padding), then three pointers.
    assert!(core::mem::offset_of!(FltOperationRegistration, major_function) == 0);
    assert!(core::mem::offset_of!(FltOperationRegistration, flags) == 4);
    assert!(core::mem::offset_of!(FltOperationRegistration, pre_operation) == 8);
    assert!(core::mem::offset_of!(FltOperationRegistration, post_operation) == 16);
    assert!(core::mem::offset_of!(FltOperationRegistration, reserved1) == 24);
    assert!(core::mem::size_of::<FltOperationRegistration>() == 32);

    // The three fields `FltCallbackData` is read through.
    assert!(core::mem::offset_of!(FltCallbackData, thread) == 8);
    assert!(core::mem::offset_of!(FltCallbackData, iopb) == 16);
    // `IoStatus`, which is where a refused execution is written.
    assert!(core::mem::offset_of!(FltCallbackData, io_status) == 24);
    assert!(core::mem::offset_of!(FltCallbackData, io_status.status) == 24);

    // ULONG, four UCHARs, two pointers, then the parameter union.
    assert!(core::mem::offset_of!(FltIoParameterBlock, major_function) == 4);
    assert!(core::mem::offset_of!(FltIoParameterBlock, target_file_object) == 8);
    assert!(core::mem::offset_of!(FltIoParameterBlock, target_instance) == 16);
    assert!(core::mem::offset_of!(FltIoParameterBlock, parameters) == 24);

    // `Create.SecurityContext` is the first pointer of the union's first arm.
    assert!(core::mem::offset_of!(FltCreateParameters, security_context) == 0);
    assert!(core::mem::size_of::<FltParameters>() >= 8);

    // `AcquireForSectionSynchronization`: the enum, then the protection it
    // requested. The second field is the whole reason the section callback can
    // tell an image from a data file, and offset 8 is where a remembered
    // `PVOID StartVa; ULONG Length;` would have put it.
    assert!(core::mem::offset_of!(FltSectionParameters, sync_type) == 0);
    assert!(core::mem::offset_of!(FltSectionParameters, page_protection) == 4);
    assert!(core::mem::size_of::<FltSectionParameters>() == 8);

    // `ntifs.h` 19808-19810. `SyncTypeOther` first, so the value a zeroed
    // structure carries is "not a creation" -- which is the answer that asks
    // nothing of the service, and therefore the safe one to be wrong about.
    assert!(SYNC_TYPE_OTHER == 0);
    assert!(SYNC_TYPE_CREATE_SECTION == 1);

    // `wdm.h` 8777-8785: the mask must cover the four `PAGE_EXECUTE*` values and
    // nothing else. The three that a memory-mapped data file asks for are the
    // assertion worth having -- `PAGE_READONLY` 0x02, `PAGE_READWRITE` 0x04 and
    // `PAGE_WRITECOPY` 0x08 -- because a mask that caught any of them would put
    // the driver back where it was on 2026-10-01, scanning every mapped file on
    // the machine.
    assert!(PAGE_EXECUTE_MASK == 0x10 | 0x20 | 0x40 | 0x80);
    assert!(PAGE_EXECUTE_MASK & 0x01 == 0); // PAGE_NOACCESS
    assert!(PAGE_EXECUTE_MASK & 0x02 == 0); // PAGE_READONLY
    assert!(PAGE_EXECUTE_MASK & 0x04 == 0); // PAGE_READWRITE
    assert!(PAGE_EXECUTE_MASK & 0x08 == 0); // PAGE_WRITECOPY

    // The table the callback gates on, checked here rather than only at the call
    // site. Every row is a case the product has been asked about: a running
    // image, a `LoadLibraryEx`-as-data image, and the three protections a mapped
    // data file uses.
    assert!(section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x20)); // PAGE_EXECUTE_READ
    assert!(section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x80)); // PAGE_EXECUTE_WRITECOPY
    assert!(section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x10)); // PAGE_EXECUTE
    assert!(section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x40)); // PAGE_EXECUTE_READWRITE
    assert!(!section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x02)); // PAGE_READONLY
    assert!(!section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x04)); // PAGE_READWRITE
    assert!(!section_will_execute(SYNC_TYPE_CREATE_SECTION, 0x08)); // PAGE_WRITECOPY
    assert!(!section_will_execute(SYNC_TYPE_CREATE_SECTION, 0)); // unspecified
    // An existing section being acquired is never a new execution, whatever
    // protection it was created with.
    assert!(!section_will_execute(SYNC_TYPE_OTHER, 0x20));
    assert!(!section_will_execute(SYNC_TYPE_OTHER, 0));

    // `SecurityQos`, `AccessState`, `DesiredAccess`.
    assert!(core::mem::offset_of!(IoSecurityContext, desired_access) == 16);
    assert!(core::mem::size_of::<IoSecurityContext>() == 24);

    // ULONG, pointer, pointer, ULONG, pointer, pointer.
    assert!(core::mem::offset_of!(ObjectAttributes, object_name) == 16);
    assert!(core::mem::size_of::<ObjectAttributes>() == 48);
};
