//! The Wenle AV kernel driver's protocol, decisions and path logic, as a crate
//! that compiles and runs its tests on stable Rust in user mode.
//!
//! # Why this crate exists
//!
//! The driver that uses this code is a KMDF minifilter. It can only be verified
//! by loading it, which needs test-signing mode, a reboot, and a machine
//! somebody is willing to bugcheck, and this product's development machine is
//! the machine someone is using. A design that puts the protocol, the decision
//! state machine and the path arithmetic *inside* KMDF callbacks can therefore
//! only be **believed**. Every one of those pieces is ordinary logic that does
//! not need a kernel to run, so it lives here, where `cargo test` executes it
//! on this machine in a second.
//!
//! The driver crate, `crates/av-driver`, is what is left: registering callbacks,
//! marshalling IOCTLs, and calling into this. It is deliberately thin, and
//! deliberately the only part that is unverified.
//!
//! | Module | What it holds | Verified by |
//! |---|---|---|
//! | [`ioctl`] | The control codes and their `CTL_CODE` derivation | tests |
//! | [`wire`] | Every structure that crosses the boundary, with pinned sizes and offsets | tests |
//! | [`event`] | The vocabulary the driver reports, and the mode/state rules | tests |
//! | [`decision`] | The pending-request table, the timeout, and the reply rules | tests |
//! | [`path`] | `\Device\...` to `C:\...`, with the volume lookup behind a trait | tests, with a fake volume table |
//! | [`exclusions`] | Case-insensitive, component-boundary exclusion matching | tests |
//! | [`port`] | The name of the filter communication port, in the one place both sides read it | tests |
//! | [`install`] | What the driver is called on a machine: service, file, altitude, group | tests |
//! | [`protect`] | Which access rights the kernel strips from handles to this product, which of its files a write may not open, and what a configuration message does to that gate | tests |
//! | [`refusal`] | The section gate's last few refusals, which the process-creation callback repeats through `CreationStatus` | tests |
//!
//! # No dependencies, and `no_std`
//!
//! This crate has **no dependencies at all** and is `no_std` outside its tests.
//! Both are load-bearing:
//!
//! * The kernel build has to satisfy every dependency this crate declares, and
//!   almost nothing in this workspace qualifies: `av_core` pulls `serde`,
//!   `av_signatures` pulls `sha2`, and neither compiles into a driver.
//! * A crate that cannot allocate cannot be made to allocate by a hostile
//!   length field. Every variable-length quantity in the protocol is a used
//!   length into a buffer the structure already owns, which is why
//!   [`wire::DecisionRequestMessage::path`] can be handed a `path_units` of
//!   `u32::MAX` and return a 1024-element slice.
//!
//! The second property is the reason for the first. It is not a coincidence
//! that a crate with no allocator is also a crate that is easy to compile into
//! a driver.
//!
//! # The two channels, and why there are two
//!
//! | Channel | Direction | Carries |
//! |---|---|---|
//! | Filter communication port (`FltCreateCommunicationPort`) | both | decision requests and their replies; status; live events |
//! | IOCTLs on a control device | user mode initiates | configuration, counters, and draining the event queue |
//!
//! The split is not arbitrary. A **decision request is initiated by the
//! driver** (a callback on the thread doing a file operation needs an answer
//! before it can return), and an IOCTL cannot do that: an IOCTL is initiated by
//! user mode, and a driver that wanted to "call out" with one would have to park
//! an IRP and complete it later, inventing a request queue and a reply
//! mechanism that the filter manager's port already provides. So the decision
//! path uses the port.
//!
//! Everything else is initiated by user mode. A service asking "are you
//! loaded", "what are your counters", "stop blocking", or "give me the events
//! you queued while I was restarting" is asking, not being asked, and an IOCTL
//! is what that is. The port *does* also carry live events and heartbeats,
//! because those are driver-initiated and a service should learn about a block
//! without polling for it, and the event queue behind
//! [`ioctl::IOCTL_READ_EVENTS`] exists for the window when no service is
//! connected, so an event generated while the service was down is not lost.
//! The two paths are mutually exclusive by connection state, so no event is
//! delivered twice.
//!
//! # What is not verified
//!
//! Stated plainly, because the value of this crate is that everything outside
//! this list *is*:
//!
//! * **The driver has never been loaded.** Nothing in this crate has run in a
//!   kernel. Everything here is tested in user mode, and the parts that can
//!   only be checked by loading a driver are listed in `crates/av-driver`'s
//!   documentation as unverified.
//! * **The timing constants are policy, not measurement.**
//!   [`decision::DecisionPolicy::DEFAULT_TIMEOUT_MS`] and its ceiling were
//!   chosen from reasoning about what a user tolerates and what a scan costs,
//!   not measured against a running filter. Said again at the constant.
//! * **The WDK facts are read, not run.** The `CTL_CODE` macro, the
//!   `FILTER_MESSAGE_HEADER` layout, the existence of `FltSendMessage`'s
//!   timeout parameter and the absence of any `FltGetVolumeDosName` were all
//!   read out of the headers under
//!   `C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0` on the
//!   machine this was written on, and each is cited where it is used. What was
//!   not done is *call* any of them.
//! * **Volume name resolution is behind a trait.** The tests use a
//!   five-entry constant table. The driver's implementation calls
//!   `IoVolumeDeviceToDosName` and caches the result, and that call has never
//!   been made.

#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
// A test that unwraps is a test that failed loudly at the line that broke,
// which is the whole point of it. The lints stay on for the library, where an
// `unwrap` would be a panic in a filesystem filter and therefore a bugcheck.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod decision;
pub mod event;
pub mod exclusions;
pub mod install;
pub mod ioctl;
pub mod path;
pub mod port;
pub mod protect;
pub mod refusal;
pub mod wire;

pub use decision::{
    Decision, DecisionPolicy, PendingTable, RegisterError, RequestId, ResolveOutcome,
};
pub use event::{
    DriverState, EnforcementMode, EventAction, SeverityCode, SubjectKind, VerdictCode,
};
pub use exclusions::{ExclusionError, FixedExclusionTable};
pub use install::{
    ALTITUDE as DRIVER_ALTITUDE, DEPENDENCY as DRIVER_DEPENDENCY, DEVICE_SUBDIR as DRIVER_SUBDIR,
    FILE_NAME as DRIVER_FILE_NAME, INSTANCE_NAME as DRIVER_INSTANCE_NAME,
    LOAD_ORDER_GROUP as DRIVER_LOAD_ORDER_GROUP, SERVICE_NAME as DRIVER_SERVICE_NAME,
};
pub use ioctl::PROTOCOL_VERSION;
pub use path::{PathError, VolumeNames};
pub use port::{NAME as PORT_NAME, NAME_BYTES as PORT_NAME_BYTES};
pub use protect::{
    gate_update, is_absolute_dos_directory, is_our_image, is_protected_file, strip_process,
    strip_thread, GateUpdate, GATE_DIR_UNITS, IMAGE_NAME_BYTES, PROTECTED_FILES, PROTECTED_IMAGES,
    STRIPPED_FROM_PROCESS, STRIPPED_FROM_THREAD,
};
pub use wire::{
    ConfigMessage, DecisionReplyMessage, DecisionRequestMessage, DriverStats, DriverStatus,
    EventBatch, EventMessage, ExclusionBuffer, MessageKind, MessagePrefix, PortMessageHeader,
    PortReplyHeader, SetModeRequest, StatusMessage, CONFIG_GATE_WRITES, CONFIG_PROTECT_HANDLES,
};
