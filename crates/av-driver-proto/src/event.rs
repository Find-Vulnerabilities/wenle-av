//! The vocabulary of things the driver reports and the codes they travel as.
//!
//! Every enum here has an `as_wire`/`from_wire` pair, and every `from_wire`
//! returns an `Option`. That shape is not decoration: the value arrives from a
//! peer that may be a different build, so an unknown code is a *normal* event
//! and must be representable. Turning an unknown `u32` into an enum by
//! transmuting it is undefined behaviour, and refusing to turn it into an enum
//! by panicking is worse — a panic in a filesystem filter at `APC_LEVEL`
//! bugchecks the machine. So the unknown case is `None` and every caller
//! decides what to do with it.
//!
//! # Why the driver has a vocabulary at all
//!
//! The driver cannot scan, cannot hash a file, and cannot decide anything. What
//! it can do is *name* what it saw well enough for user mode to act. These
//! enums are that naming, and they are deliberately coarse: the driver
//! distinguishes "a process was created" from "a file was written" because
//! those need different handling, and it does not distinguish "a PE image" from
//! "a DLL" because user mode can see the path and work that out for itself
//! with far more context than the driver has.

/// What an event or request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    /// A file being opened, written or executed.
    File,
    /// A process being created.
    Process,
    /// An image being loaded into an existing process.
    Image,
    /// The driver itself.
    Driver,
    /// The product's protection of itself, in the kernel.
    ///
    /// Distinct from [`SubjectKind::Driver`], which is the driver *running*, and
    /// the distinction is the same one [`EventAction::ProcessStarted`] draws
    /// against [`EventAction::ImageLoaded`]: these are two different questions
    /// with two different answers. A driver can be started, attached and
    /// answering every decision while one of its own registrations was refused
    /// -- `ObRegisterCallbacks` can be, and the caller has to be told which
    /// registration and with what status, or it cannot tell a protected product
    /// from one that merely looks loaded.
    ///
    /// The service's own self-protection reports itself through the service's
    /// status rather than through this: the driver's port carries this driver's
    /// registrations, and nothing about a user-mode DACL travels on it.
    Protection,
}

impl SubjectKind {
    /// A file.
    pub const WIRE_FILE: u32 = 1;
    /// A process.
    pub const WIRE_PROCESS: u32 = 2;
    /// An image.
    pub const WIRE_IMAGE: u32 = 3;
    /// The driver.
    pub const WIRE_DRIVER: u32 = 4;
    /// The kernel-side self-protection registrations.
    pub const WIRE_PROTECTION: u32 = 5;

    /// The value that goes on the wire. Zero is never a valid subject, so a
    /// zeroed field is a bug rather than `File`.
    pub const fn as_wire(self) -> u32 {
        match self {
            SubjectKind::File => Self::WIRE_FILE,
            SubjectKind::Process => Self::WIRE_PROCESS,
            SubjectKind::Image => Self::WIRE_IMAGE,
            SubjectKind::Driver => Self::WIRE_DRIVER,
            SubjectKind::Protection => Self::WIRE_PROTECTION,
        }
    }

    /// Decode a wire value.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            Self::WIRE_FILE => Some(SubjectKind::File),
            Self::WIRE_PROCESS => Some(SubjectKind::Process),
            Self::WIRE_IMAGE => Some(SubjectKind::Image),
            Self::WIRE_DRIVER => Some(SubjectKind::Driver),
            Self::WIRE_PROTECTION => Some(SubjectKind::Protection),
            _ => None,
        }
    }

    /// The word used in the user interface and in `--json` output.
    pub const fn as_str(self) -> &'static str {
        match self {
            SubjectKind::File => "file",
            SubjectKind::Process => "process",
            SubjectKind::Image => "image",
            SubjectKind::Driver => "driver",
            SubjectKind::Protection => "protection",
        }
    }
}

/// What happened.
///
/// The set is exactly the operations this product acts on, and the module
/// documentation says why it is not larger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventAction {
    /// A process creation or a file execution was refused before it happened.
    ///
    /// This is the only event the driver ever *blocks* on, and it is the reason
    /// the product has a driver at all: user-mode real-time scanning can see a
    /// file after it is written and can hook a process after it starts, and
    /// only a filter in the create path can stop `cmd.exe` from running.
    ExecutionBlocked,
    /// Something was written to a file that the rules care about.
    FileWritten,
    /// An image was mapped into a process.
    ImageLoaded,
    /// A process was created.
    ///
    /// Distinct from [`EventAction::ImageLoaded`] rather than folded into it, and
    /// the two are not interchangeable: `ImageLoaded` describes a mapping — an
    /// image, possibly a DLL, becoming part of a process that already exists —
    /// and this one describes the process itself coming into being, which is the
    /// moment the product's memory monitor is keyed on. Recording one as the
    /// other would be a report that says a DLL was loaded when what happened was
    /// that a program started, and every consumer downstream of this enum builds
    /// its sentence from the action.
    ///
    /// `process_id` is the new process, and `path` is its image as a DOS path.
    /// The driver sends it only when the kernel says the image name is the exact
    /// name the file was opened by — see `av-driver`'s process notification —
    /// because the alternative the header documents is a *partial* name, and a
    /// partial name resolved as though it were a path is a path to the wrong
    /// file.
    ProcessStarted,
    /// A write was refused. Distinct from [`EventAction::FileWritten`] because
    /// the two describe opposite outcomes, and a report that merged them would
    /// tell a user a file was modified when in fact it was protected.
    WriteBlocked,
    /// The driver is alive. Carries no subject.
    Heartbeat,
    /// The enforcement mode changed, or the service connected or disconnected.
    /// `detail` carries the new [`DriverState`].
    StateChanged,
    /// The event queue overflowed and events were discarded.
    ///
    /// Emitted so that the gap is *visible*: without it, a service that missed
    /// a thousand events sees a quiet machine. The count of what was lost goes
    /// in `detail`.
    EventsDropped,
}

impl EventAction {
    /// A process or file execution was refused.
    pub const WIRE_EXECUTION_BLOCKED: u32 = 1;
    /// A file was written.
    pub const WIRE_FILE_WRITTEN: u32 = 2;
    /// An image was loaded.
    pub const WIRE_IMAGE_LOADED: u32 = 3;
    /// A process was created.
    pub const WIRE_PROCESS_STARTED: u32 = 8;
    /// A write was refused.
    pub const WIRE_WRITE_BLOCKED: u32 = 4;
    /// The driver is alive.
    pub const WIRE_HEARTBEAT: u32 = 5;
    /// The driver's state changed.
    pub const WIRE_STATE_CHANGED: u32 = 6;
    /// Events were discarded.
    pub const WIRE_EVENTS_DROPPED: u32 = 7;

    /// The value that goes on the wire. Zero is never valid, so a zeroed field
    /// is a bug rather than a heartbeat.
    pub const fn as_wire(self) -> u32 {
        match self {
            EventAction::ExecutionBlocked => Self::WIRE_EXECUTION_BLOCKED,
            EventAction::FileWritten => Self::WIRE_FILE_WRITTEN,
            EventAction::ImageLoaded => Self::WIRE_IMAGE_LOADED,
            EventAction::ProcessStarted => Self::WIRE_PROCESS_STARTED,
            EventAction::WriteBlocked => Self::WIRE_WRITE_BLOCKED,
            EventAction::Heartbeat => Self::WIRE_HEARTBEAT,
            EventAction::StateChanged => Self::WIRE_STATE_CHANGED,
            EventAction::EventsDropped => Self::WIRE_EVENTS_DROPPED,
        }
    }

    /// Decode a wire value.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            Self::WIRE_EXECUTION_BLOCKED => Some(EventAction::ExecutionBlocked),
            Self::WIRE_FILE_WRITTEN => Some(EventAction::FileWritten),
            Self::WIRE_IMAGE_LOADED => Some(EventAction::ImageLoaded),
            Self::WIRE_PROCESS_STARTED => Some(EventAction::ProcessStarted),
            Self::WIRE_WRITE_BLOCKED => Some(EventAction::WriteBlocked),
            Self::WIRE_HEARTBEAT => Some(EventAction::Heartbeat),
            Self::WIRE_STATE_CHANGED => Some(EventAction::StateChanged),
            Self::WIRE_EVENTS_DROPPED => Some(EventAction::EventsDropped),
            _ => None,
        }
    }

    /// Whether this action describes a refusal, and therefore whether it is
    /// worth a user's attention.
    ///
    /// A heartbeat is not, and neither is a file write — a machine writes
    /// thousands of files an hour and a notification for each is a product
    /// nobody keeps installed. This is the predicate the notification layer
    /// should be filtering on rather than re-deriving from the action list.
    pub const fn is_blocking_event(self) -> bool {
        matches!(
            self,
            EventAction::ExecutionBlocked | EventAction::WriteBlocked
        )
    }

    /// Whether the driver may refuse the operation this action describes.
    ///
    /// Two of the eight, and the test below pins the other six as not-refusable.
    /// Most of them cannot be refused at all: they describe something that has
    /// already happened by the time the driver sees it.
    /// [`EventAction::ImageLoaded`] is a post-callback by construction —
    /// `PsSetLoadImageNotifyRoutine` runs after the mapping exists — and
    /// unfixing it would mean unmapping a section out of a running process,
    /// which is not something a security product should be doing to a machine
    /// it is supposed to be protecting.
    ///
    /// [`EventAction::ProcessStarted`] is the one that *could* be and is still
    /// not **this** action: the kernel lets a create-notification write
    /// `CreationStatus` and abort the creation outright. The driver reports a
    /// creation it let through as `ProcessStarted`, and a creation it failed as
    /// [`EventAction::ExecutionBlocked`] — a different action, because the two
    /// outcomes are different, and because no consumer should have to infer
    /// "it ran" or "it did not" from a field that means neither.
    ///
    /// The refusal is never this driver's own verdict. Since 2026-10-18 it
    /// repeats a `Block` the section gate has already been given for the same
    /// path within the last minute (`av-driver`'s `RefusalMemo` says why that
    /// repeat was needed), so the answer was made by the engine under its own
    /// thresholds, and the create path neither waits nor decides anything new.
    pub const fn is_blockable(self) -> bool {
        matches!(
            self,
            EventAction::ExecutionBlocked | EventAction::WriteBlocked
        )
    }

    /// Whether `detail` carries a meaning for this action.
    ///
    /// The three that do: `StateChanged` puts the new [`DriverState`] there,
    /// `EventsDropped` puts the number lost, and `FileWritten` puts the number
    /// of bytes written, saturated at `u32::MAX`. A reader that trusted this
    /// for the wrong action would print a byte count as an error code, which is
    /// why the predicate exists rather than the field being documented as
    /// sometimes-meaningful.
    pub const fn has_detail(self) -> bool {
        matches!(
            self,
            EventAction::StateChanged | EventAction::EventsDropped | EventAction::FileWritten
        )
    }
}

/// `av_core::Severity` as a wire code.
///
/// The numbers match the declaration order of `av_core::Severity` — `Info`,
/// `Low`, `Medium`, `High`, `Critical` — which is the order its derived `Ord`
/// compares in, so a service sorting by the wire code sorts by severity. That
/// is a claim about another crate and it is checked by a test in
/// `crates/av-cli`, which is the crate that links both.
///
/// The driver does not *evaluate* severities. It copies one back out of a
/// verdict it was given, which is why the codes have to agree with the rest of
/// the product rather than being local to this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum SeverityCode {
    /// Recorded, never actionable.
    #[default]
    Info,
    /// Worth mentioning.
    Low,
    /// Two of these are enough on their own.
    Medium,
    /// Enough on its own.
    High,
    /// Enough, with room to spare.
    Critical,
}

impl SeverityCode {
    /// The value that goes on the wire. `Info` is zero, which is the one place
    /// in this file where zero *is* valid — because a defaulted severity must
    /// be the harmless one, and `Info` contributes no score anywhere in this
    /// product.
    pub const fn as_wire(self) -> u32 {
        match self {
            SeverityCode::Info => 0,
            SeverityCode::Low => 1,
            SeverityCode::Medium => 2,
            SeverityCode::High => 3,
            SeverityCode::Critical => 4,
        }
    }

    /// Decode a wire value. Anything above `Critical` is `None` rather than
    /// being clamped to `Critical`: a severity this build does not know about
    /// is a message from a newer service, and silently downgrading it to the
    /// highest known value would be inventing data.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(SeverityCode::Info),
            1 => Some(SeverityCode::Low),
            2 => Some(SeverityCode::Medium),
            3 => Some(SeverityCode::High),
            4 => Some(SeverityCode::Critical),
            _ => None,
        }
    }

    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            SeverityCode::Info => "info",
            SeverityCode::Low => "low",
            SeverityCode::Medium => "medium",
            SeverityCode::High => "high",
            SeverityCode::Critical => "critical",
        }
    }
}

/// No verdict. Used in [`crate::wire::EventMessage::verdict`] for actions that
/// no verdict applies to, such as a heartbeat or a file write.
///
/// `u32::MAX` rather than zero, because zero is [`VerdictCode::Clean`] and an
/// event that was never judged must not read as "judged, and clean" — that is
/// the same distinction `av_core::Verdict::Unknown` draws from
/// `av_core::Verdict::Clean`, one layer down.
pub const VERDICT_NONE: u32 = u32::MAX;

/// `av_core::Verdict` as a wire code.
///
/// The numbers match the declaration order of `av_core::Verdict` — `Clean`,
/// `Suspicious`, `Malicious`, `Unknown`. Note what that order means: sorting by
/// wire code does **not** sort by seriousness, because `Unknown` is last and is
/// not more serious than `Malicious`. It is last because it is the odd one out.
/// A caller that wants an ordering must state one; there is no natural one, and
/// inventing a total order over these four states is how a bug becomes a
/// blocked boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VerdictCode {
    /// Nothing found.
    #[default]
    Clean,
    /// Worth mentioning, not worth acting on.
    Suspicious,
    /// Act.
    Malicious,
    /// Not judged.
    Unknown,
}

impl VerdictCode {
    /// The value that goes on the wire. `Clean` is zero, so a zeroed verdict
    /// field reads as clean — see [`VerdictCode::from_wire_lossy`] for why that
    /// is the right default and not the dangerous one.
    pub const fn as_wire(self) -> u32 {
        match self {
            VerdictCode::Clean => 0,
            VerdictCode::Suspicious => 1,
            VerdictCode::Malicious => 2,
            VerdictCode::Unknown => 3,
        }
    }

    /// Decode a wire value. [`VERDICT_NONE`] decodes to `None`, as does
    /// anything above `Unknown`.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(VerdictCode::Clean),
            1 => Some(VerdictCode::Suspicious),
            2 => Some(VerdictCode::Malicious),
            3 => Some(VerdictCode::Unknown),
            _ => None,
        }
    }

    /// Decode a wire value, treating anything unrecognised as
    /// [`VerdictCode::Unknown`].
    ///
    /// This is the direction a *reader* should use, and the reason is the
    /// asymmetry between the two possible mistakes. Reading an unknown verdict
    /// as `Clean` says "we looked and it was fine" when we did not look —
    /// which is the error `av_core` documents `Unknown` as existing to prevent.
    /// Reading it as `Unknown` says "we do not know", which is true.
    pub const fn from_wire_lossy(value: u32) -> Self {
        match Self::from_wire(value) {
            Some(v) => v,
            None => VerdictCode::Unknown,
        }
    }
}

/// The name of a verdict wire code, for logging a value this build may not
/// understand.
///
/// Used instead of `VerdictCode::from_wire(..).map(as_str)` by the `Debug`
/// impls, where an unrecognised number has to be printed rather than dropped.
pub const fn verdict_name(value: u32) -> &'static str {
    match VerdictCode::from_wire(value) {
        Some(VerdictCode::Clean) => "clean",
        Some(VerdictCode::Suspicious) => "suspicious",
        Some(VerdictCode::Malicious) => "malicious",
        Some(VerdictCode::Unknown) => "unknown",
        None if value == VERDICT_NONE => "none",
        None => "unrecognised",
    }
}

/// How the driver was loaded and how it is getting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DriverState {
    /// `DriverEntry` is still running. Callbacks are not registered yet.
    #[default]
    Starting,
    /// Registered and enforcing, or observing, per [`EnforcementMode`].
    Running,
    /// Registered, but something is wrong: the port is not connected, or the
    /// decision table is full, or requests are expiring. The driver keeps
    /// running — see [`EnforcementMode::effective`] for what "keeps running"
    /// means for enforcement.
    Degraded,
    /// Unloading. No new requests are issued.
    Stopping,
    /// Unloaded. Only ever seen by a service that read a stale structure.
    Stopped,
}

impl DriverState {
    /// The value that goes on the wire. `Starting`, not zero-is-invalid: a
    /// defaulted state is a driver that has not finished initialising, which is
    /// the truthful description of a driver whose state field was never set.
    pub const fn as_wire(self) -> u32 {
        match self {
            DriverState::Starting => 0,
            DriverState::Running => 1,
            DriverState::Degraded => 2,
            DriverState::Stopping => 3,
            DriverState::Stopped => 4,
        }
    }

    /// Decode a wire value.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(DriverState::Starting),
            1 => Some(DriverState::Running),
            2 => Some(DriverState::Degraded),
            3 => Some(DriverState::Stopping),
            4 => Some(DriverState::Stopped),
            _ => None,
        }
    }

    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            DriverState::Starting => "starting",
            DriverState::Running => "running",
            DriverState::Degraded => "degraded",
            DriverState::Stopping => "stopping",
            DriverState::Stopped => "stopped",
        }
    }

    /// Whether the driver issues decision requests in this state. A driver that
    /// is stopping must not: the service may already have gone, and every
    /// request it made would wait out its full timeout for nothing.
    pub const fn issues_requests(self) -> bool {
        matches!(self, DriverState::Running | DriverState::Degraded)
    }
}

/// How much the driver is willing to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EnforcementMode {
    /// Everything is reported, nothing is refused. The default, and see
    /// [`EnforcementMode::effective`] for why.
    #[default]
    Observe,
    /// A verdict of block is enforced.
    Blocking,
    /// The driver is attached but not evaluating anything. Distinct from
    /// unloading: its callbacks are still in the stack, and it returns
    /// `FLT_PREOP_SUCCESS_NO_CALLBACK` immediately.
    Disabled,
}

impl EnforcementMode {
    /// The value that goes on the wire.
    pub const fn as_wire(self) -> u32 {
        match self {
            EnforcementMode::Observe => 0,
            EnforcementMode::Blocking => 1,
            EnforcementMode::Disabled => 2,
        }
    }

    /// Decode a wire value. Anything unrecognised is `None`, and the caller
    /// must treat that as [`EnforcementMode::Observe`] rather than as
    /// `Blocking` — see [`EnforcementMode::from_wire_lossy`].
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(EnforcementMode::Observe),
            1 => Some(EnforcementMode::Blocking),
            2 => Some(EnforcementMode::Disabled),
            _ => None,
        }
    }

    /// Decode a wire value, treating anything unrecognised as
    /// [`EnforcementMode::Observe`].
    ///
    /// The safe direction, and it is worth being explicit that this is a
    /// *choice*: a service that asked for a mode this driver does not implement
    /// gets the mode that refuses nothing. Defaulting the other way would mean
    /// a version-skewed install blocks file operations according to a policy
    /// neither side can describe.
    pub const fn from_wire_lossy(value: u32) -> Self {
        match Self::from_wire(value) {
            Some(mode) => mode,
            None => EnforcementMode::Observe,
        }
    }

    /// What the driver will actually do, given this mode, the driver's state
    /// and whether a service is connected.
    ///
    /// **This function is the reason the product cannot brick a machine.**
    ///
    /// The rule it encodes: a verdict can only be enforced when there is
    /// somebody to ask for one. [`EnforcementMode::Blocking`] with no connected
    /// service does not mean "block everything"; it means every request would
    /// wait out its timeout and then take
    /// [`crate::decision::DecisionPolicy::on_timeout`], which is
    /// [`crate::decision::Decision::Allow`]. The mode that actually gets
    /// enforced in that situation is therefore [`EnforcementMode::Observe`],
    /// and saying so here rather than letting it be discovered by timing out
    /// makes the behaviour visible in the driver's status instead of inferable
    /// from a machine that got very slow.
    ///
    /// The consequence for a caller: an operator who wants blocking must have
    /// the service running *and connected*, and a service crash silently
    /// downgrades enforcement to observation rather than to a hung file system.
    /// That is the right failure — a missed detection is recoverable, a machine
    /// that cannot open files is not.
    pub const fn effective(self, state: DriverState, service_connected: bool) -> Self {
        match self {
            EnforcementMode::Disabled => EnforcementMode::Disabled,
            _ if !state.issues_requests() => EnforcementMode::Disabled,
            EnforcementMode::Blocking if !service_connected => EnforcementMode::Observe,
            mode => mode,
        }
    }

    /// Whether this mode refuses anything.
    pub const fn blocks(self) -> bool {
        matches!(self, EnforcementMode::Blocking)
    }

    /// The word used in the user interface.
    pub const fn as_str(self) -> &'static str {
        match self {
            EnforcementMode::Observe => "observe",
            EnforcementMode::Blocking => "blocking",
            EnforcementMode::Disabled => "disabled",
        }
    }
}

/// The `flags` field of [`crate::wire::SetModeRequest`].
pub mod mode_flags {
    /// The mode may not be changed again until the driver is reloaded.
    ///
    /// Used by a managed deployment that wants the mode fixed at install time.
    /// Enforced by the driver refusing a later [`super::EnforcementMode`]
    /// write, which is a weaker guarantee than it sounds — a local
    /// administrator can unload the driver — and is documented here as exactly
    /// that rather than as tamper-proofing.
    pub const LOCKED: u32 = 1 << 0;
    /// Persist the mode across a reload of the driver.
    pub const PERSIST: u32 = 1 << 1;
    /// Reset the counters in [`crate::wire::DriverStats`].
    pub const RESET_STATS: u32 = 1 << 2;
    /// Every bit this build knows about.
    pub const KNOWN: u32 = LOCKED | PERSIST | RESET_STATS;
}

/// The `flags` field of [`crate::wire::DecisionRequestMessage`].
pub mod request_flags {
    /// The path in the message is the raw device path because
    /// [`crate::path`] could not resolve a drive letter for its volume.
    ///
    /// The service must not treat it as a DOS path, and — importantly — must
    /// not match it against an exclusion list written in DOS terms. Those files
    /// are therefore always scanned, which is the direction to fail in.
    pub const PATH_UNRESOLVED: u32 = 1 << 0;
    /// The operation has not happened yet and can still be refused.
    ///
    /// Set for a pre-operation callback. **Clear** means the operation is
    /// already done and the reply is advisory only — the driver will record the
    /// verdict but cannot un-run the program. A service that answers `Block` to
    /// a request without this bit has misunderstood the protocol, and the
    /// driver ignores the block rather than pretending it acted.
    pub const PRE_OPERATION: u32 = 1 << 1;
    /// The file is on a remote volume. `path` is best-effort.
    pub const REMOTE: u32 = 1 << 2;
    /// Every bit this build knows about.
    pub const KNOWN: u32 = PATH_UNRESOLVED | PRE_OPERATION | REMOTE;
}

/// The `flags` field of [`crate::wire::DecisionReplyMessage`].
pub mod reply_flags {
    /// The service answered from a cache or a fast path rather than a full
    /// scan. Recorded so that a report can distinguish "we scanned it and it
    /// was clean" from "we recognised it and it was clean", which are different
    /// levels of confidence.
    pub const FROM_CACHE: u32 = 1 << 0;
    /// The service's own scanning is degraded — a signature database that
    /// failed to load, say. The verdict is still used, because a partial scan
    /// is more information than none, but the driver moves to
    /// [`super::DriverState::Degraded`] and the status reports it.
    pub const SERVICE_DEGRADED: u32 = 1 << 1;
    /// Every bit this build knows about.
    pub const KNOWN: u32 = FROM_CACHE | SERVICE_DEGRADED;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every enum round-trips through its wire code, and no two variants share
    /// one. A shared code would make one variant unreachable, which in a
    /// `match` on the decoded value is a silently wrong behaviour rather than a
    /// compile error.
    #[test]
    fn every_vocabulary_enum_round_trips() {
        let subjects = [
            SubjectKind::File,
            SubjectKind::Process,
            SubjectKind::Image,
            SubjectKind::Driver,
            SubjectKind::Protection,
        ];
        let actions = [
            EventAction::ExecutionBlocked,
            EventAction::FileWritten,
            EventAction::ImageLoaded,
            EventAction::ProcessStarted,
            EventAction::WriteBlocked,
            EventAction::Heartbeat,
            EventAction::StateChanged,
            EventAction::EventsDropped,
        ];
        let severities = [
            SeverityCode::Info,
            SeverityCode::Low,
            SeverityCode::Medium,
            SeverityCode::High,
            SeverityCode::Critical,
        ];
        let verdicts = [
            VerdictCode::Clean,
            VerdictCode::Suspicious,
            VerdictCode::Malicious,
            VerdictCode::Unknown,
        ];
        let states = [
            DriverState::Starting,
            DriverState::Running,
            DriverState::Degraded,
            DriverState::Stopping,
            DriverState::Stopped,
        ];
        let modes = [
            EnforcementMode::Observe,
            EnforcementMode::Blocking,
            EnforcementMode::Disabled,
        ];

        for s in subjects {
            assert_eq!(SubjectKind::from_wire(s.as_wire()), Some(s));
        }
        for (a, b) in actions.iter().zip(actions.iter().skip(1)) {
            assert_ne!(a.as_wire(), b.as_wire(), "adjacent actions collide");
            assert_eq!(EventAction::from_wire(a.as_wire()), Some(*a));
        }
        assert_eq!(
            EventAction::from_wire(actions[actions.len() - 1].as_wire()),
            Some(actions[actions.len() - 1])
        );
        for s in severities {
            assert_eq!(SeverityCode::from_wire(s.as_wire()), Some(s));
        }
        for v in verdicts {
            assert_eq!(VerdictCode::from_wire(v.as_wire()), Some(v));
        }
        for s in states {
            assert_eq!(DriverState::from_wire(s.as_wire()), Some(s));
        }
        for m in modes {
            assert_eq!(EnforcementMode::from_wire(m.as_wire()), Some(m));
        }
    }

    /// The wire codes are distinct *within* each enum, checked exhaustively
    /// rather than on adjacent pairs only.
    #[test]
    fn no_two_variants_of_an_enum_share_a_wire_code() {
        let actions = [
            EventAction::ExecutionBlocked,
            EventAction::FileWritten,
            EventAction::ImageLoaded,
            EventAction::ProcessStarted,
            EventAction::WriteBlocked,
            EventAction::Heartbeat,
            EventAction::StateChanged,
            EventAction::EventsDropped,
        ];
        for (i, a) in actions.iter().enumerate() {
            for b in &actions[i + 1..] {
                assert_ne!(a.as_wire(), b.as_wire(), "{a:?} and {b:?} collide");
            }
            // And every code decodes back to this variant and no other.
            assert_eq!(EventAction::from_wire(a.as_wire()), Some(*a));
        }
    }

    /// The codes that are *not* zero, because a zeroed field must never read as
    /// a real subject or action. The exceptions are documented and deliberate:
    /// `Info`, `Clean`, `Starting` and `Observe` are all the harmless default.
    #[test]
    fn zero_is_reserved_where_a_zeroed_field_would_be_misleading() {
        assert_eq!(
            SubjectKind::from_wire(0),
            None,
            "a zeroed subject is not a file"
        );
        assert_eq!(
            EventAction::from_wire(0),
            None,
            "a zeroed action is not a heartbeat"
        );

        // The deliberate exceptions.
        assert_eq!(SeverityCode::from_wire(0), Some(SeverityCode::Info));
        assert_eq!(VerdictCode::from_wire(0), Some(VerdictCode::Clean));
        assert_eq!(DriverState::from_wire(0), Some(DriverState::Starting));
        assert_eq!(
            EnforcementMode::from_wire(0),
            Some(EnforcementMode::Observe)
        );
        assert_eq!(VerdictCode::default(), VerdictCode::Clean);
        assert_eq!(EnforcementMode::default(), EnforcementMode::Observe);
        assert_eq!(DriverState::default(), DriverState::Starting);
    }

    /// `VerdictCode::from_wire_lossy` must send an unknown value to `Unknown`,
    /// not to `Clean`. This is the single most consequential decode in the
    /// file: it is the difference between "we did not judge it" and "we judged
    /// it and it was fine".
    #[test]
    fn an_unknown_verdict_decodes_to_unknown_not_clean() {
        assert_eq!(VerdictCode::from_wire(VERDICT_NONE), None);
        assert_eq!(
            VerdictCode::from_wire_lossy(VERDICT_NONE),
            VerdictCode::Unknown
        );
        assert_eq!(VerdictCode::from_wire_lossy(99), VerdictCode::Unknown);
        assert_eq!(VerdictCode::from_wire_lossy(u32::MAX), VerdictCode::Unknown);
        // And the values it does know are passed through untouched.
        assert_eq!(VerdictCode::from_wire_lossy(0), VerdictCode::Clean);
        assert_eq!(VerdictCode::from_wire_lossy(2), VerdictCode::Malicious);
    }

    /// `VERDICT_NONE` must be distinguishable from every real verdict, and
    /// `verdict_name` must be able to name it — a log line that printed
    /// "unknown" for "no verdict was ever recorded" would conflate two
    /// different things.
    #[test]
    fn no_verdict_is_distinct_from_every_verdict() {
        assert_ne!(VERDICT_NONE, VerdictCode::Clean.as_wire());
        assert_ne!(VERDICT_NONE, VerdictCode::Suspicious.as_wire());
        assert_ne!(VERDICT_NONE, VerdictCode::Malicious.as_wire());
        assert_ne!(VERDICT_NONE, VerdictCode::Unknown.as_wire());
        assert_eq!(verdict_name(VERDICT_NONE), "none");
        assert_eq!(verdict_name(VerdictCode::Clean.as_wire()), "clean");
        assert_eq!(verdict_name(7), "unrecognised");
    }

    /// Severity ordering must match the wire codes, because a service sorts a
    /// notification list by severity and this is the only place the two
    /// orderings are tied together.
    #[test]
    fn severity_order_matches_the_wire_codes() {
        assert!(SeverityCode::Info < SeverityCode::Low);
        assert!(SeverityCode::Low < SeverityCode::Medium);
        assert!(SeverityCode::Medium < SeverityCode::High);
        assert!(SeverityCode::High < SeverityCode::Critical);
        assert!(SeverityCode::Info.as_wire() < SeverityCode::Critical.as_wire());
    }

    /// The blockable set is exactly the set that describes a refusal that has
    /// not happened yet. If this list grows, someone has found a way to refuse
    /// something the driver currently only reports, and the doc comment on
    /// `is_blockable` says why each of the others cannot be.
    #[test]
    fn only_the_pre_operation_actions_are_blockable() {
        assert!(EventAction::ExecutionBlocked.is_blockable());
        assert!(EventAction::WriteBlocked.is_blockable());
        assert!(!EventAction::FileWritten.is_blockable());
        assert!(!EventAction::ImageLoaded.is_blockable());
        // The one that could be refused through `CreationStatus` and is not.
        assert!(!EventAction::ProcessStarted.is_blockable());
        assert!(!EventAction::Heartbeat.is_blockable());
        assert!(!EventAction::StateChanged.is_blockable());
        assert!(!EventAction::EventsDropped.is_blockable());

        // The two sets agree: whatever is blockable is worth notifying about.
        for action in [
            EventAction::ExecutionBlocked,
            EventAction::FileWritten,
            EventAction::ImageLoaded,
            EventAction::ProcessStarted,
            EventAction::WriteBlocked,
            EventAction::Heartbeat,
            EventAction::StateChanged,
            EventAction::EventsDropped,
        ] {
            if action.is_blockable() {
                assert!(action.is_blocking_event(), "{action:?}");
            }
        }
    }

    /// A service is only asked for a verdict when there is somebody to ask.
    /// This is the whole "cannot brick the machine" rule, stated as a table.
    #[test]
    fn blocking_without_a_service_is_observation() {
        let running = DriverState::Running;
        assert_eq!(
            EnforcementMode::Blocking.effective(running, true),
            EnforcementMode::Blocking
        );
        assert_eq!(
            EnforcementMode::Blocking.effective(running, false),
            EnforcementMode::Observe,
            "blocking with nobody to ask must degrade to observation"
        );
        assert_eq!(
            EnforcementMode::Observe.effective(running, true),
            EnforcementMode::Observe
        );
        // Disabled stays disabled, connected or not.
        assert_eq!(
            EnforcementMode::Disabled.effective(running, true),
            EnforcementMode::Disabled
        );
        assert_eq!(
            EnforcementMode::Disabled.effective(running, false),
            EnforcementMode::Disabled
        );
    }

    /// A driver that is not issuing requests enforces nothing, whatever mode
    /// was configured. `Stopping` is the case that matters: it is the window in
    /// which the service may already have been told to quit.
    #[test]
    fn a_driver_that_is_not_issuing_requests_enforces_nothing() {
        for state in [
            DriverState::Starting,
            DriverState::Stopping,
            DriverState::Stopped,
        ] {
            assert!(!state.issues_requests(), "{state:?}");
            assert_eq!(
                EnforcementMode::Blocking.effective(state, true),
                EnforcementMode::Disabled,
                "{state:?} must not enforce"
            );
        }
        assert!(DriverState::Running.issues_requests());
        assert!(
            DriverState::Degraded.issues_requests(),
            "degraded still asks"
        );
    }

    /// An unrecognised mode must resolve to the one that refuses nothing.
    #[test]
    fn an_unknown_enforcement_mode_decodes_to_observe() {
        assert_eq!(EnforcementMode::from_wire(9), None);
        assert_eq!(
            EnforcementMode::from_wire_lossy(9),
            EnforcementMode::Observe,
            "an unknown mode must never be read as blocking"
        );
        assert_eq!(
            EnforcementMode::from_wire_lossy(u32::MAX),
            EnforcementMode::Observe
        );
        // Known values are untouched.
        assert_eq!(
            EnforcementMode::from_wire_lossy(1),
            EnforcementMode::Blocking
        );
    }

    /// Every flag set has a `KNOWN` mask that covers exactly its members, so a
    /// driver checking `flags & !KNOWN` for bits it does not implement cannot
    /// accidentally reject a bit this build does define.
    #[test]
    fn flag_known_masks_cover_exactly_their_members() {
        assert_eq!(
            mode_flags::KNOWN,
            mode_flags::LOCKED | mode_flags::PERSIST | mode_flags::RESET_STATS
        );
        assert_eq!(
            request_flags::KNOWN,
            request_flags::PATH_UNRESOLVED | request_flags::PRE_OPERATION | request_flags::REMOTE
        );
        assert_eq!(
            reply_flags::KNOWN,
            reply_flags::FROM_CACHE | reply_flags::SERVICE_DEGRADED
        );

        // Each member is a single bit, and the members of one set never share a
        // bit. A flag that covered two bits, or that overlapped a neighbour,
        // would make `flags & !KNOWN` reject a bit this build does implement,
        // which is the difference between reading a message and dropping it.
        // The member count per set differs (three, three, two), so the sets are
        // listed with their own lengths rather than padded with zeroes -- a
        // padded zero would sail into the subtraction below and underflow.
        let sets: [(&str, &[u32], u32); 3] = [
            (
                "mode_flags",
                &[
                    mode_flags::LOCKED,
                    mode_flags::PERSIST,
                    mode_flags::RESET_STATS,
                ],
                mode_flags::KNOWN,
            ),
            (
                "request_flags",
                &[
                    request_flags::PATH_UNRESOLVED,
                    request_flags::PRE_OPERATION,
                    request_flags::REMOTE,
                ],
                request_flags::KNOWN,
            ),
            (
                "reply_flags",
                &[reply_flags::FROM_CACHE, reply_flags::SERVICE_DEGRADED],
                reply_flags::KNOWN,
            ),
        ];

        for (name, members, known) in sets {
            let mut combined = 0u32;
            for &bit in members {
                assert_ne!(bit, 0, "{name}: a member is zero");
                assert_eq!(bit & (bit - 1), 0, "{name}: {bit:#X} is not a single bit");
                assert_eq!(bit & combined, 0, "{name}: {bit:#X} overlaps a neighbour");
                assert_eq!(bit & !known, 0, "{name}: {bit:#X} is missing from KNOWN");
                combined |= bit;
            }
            assert_eq!(
                combined, known,
                "{name}: KNOWN carries bits no member claims"
            );
        }
    }

    /// `has_detail` must be honest about which actions use `detail`, because a
    /// reader that trusted it for the wrong action would print a path's byte
    /// count as an error code.
    #[test]
    fn detail_is_claimed_only_where_it_is_used() {
        assert!(EventAction::StateChanged.has_detail());
        assert!(EventAction::EventsDropped.has_detail());
        assert!(EventAction::FileWritten.has_detail());
        // A heartbeat carries no detail; its `detail` field is zero and means
        // nothing.
        assert!(!EventAction::Heartbeat.has_detail());
        assert!(!EventAction::ExecutionBlocked.has_detail());
        // A process start carries its process id in `process_id`, not in
        // `detail`, which is zero and means nothing for this action.
        assert!(!EventAction::ProcessStarted.has_detail());
    }

    /// The `as_str` renderings must be distinct per enum, since they are what
    /// ends up in a log line.
    #[test]
    fn display_names_are_distinct() {
        let subjects = [
            SubjectKind::File,
            SubjectKind::Process,
            SubjectKind::Image,
            SubjectKind::Driver,
            SubjectKind::Protection,
        ];
        for (i, a) in subjects.iter().enumerate() {
            for b in &subjects[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
        let states = [
            DriverState::Starting,
            DriverState::Running,
            DriverState::Degraded,
            DriverState::Stopping,
            DriverState::Stopped,
        ];
        for (i, a) in states.iter().enumerate() {
            for b in &states[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
        let modes = [
            EnforcementMode::Observe,
            EnforcementMode::Blocking,
            EnforcementMode::Disabled,
        ];
        for (i, a) in modes.iter().enumerate() {
            for b in &modes[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
}
