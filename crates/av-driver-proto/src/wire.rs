//! The structures that cross the kernel/user boundary, with their layout
//! pinned.
//!
//! # Why every layout is written by hand
//!
//! A `#[repr(C)]` struct with a mix of `u32` and `u64` fields has a layout the
//! compiler chooses: it inserts padding where the ABI wants it, and where it
//! does that is a function of the target, the compiler version and sometimes
//! the order the fields were declared in. Kernel and user mode must agree on
//! the layout *byte for byte* — a four-byte disagreement about where a path
//! starts is not a warning, it is a driver reading a length field as path data.
//!
//! So every structure here obeys four rules:
//!
//! 1. **Fixed-width fields only.** No `usize`, no `bool`, no pointers, no
//!    `repr(Rust)` types. Nothing whose size depends on the target.
//! 2. **Padding is written out** as named `_pad` fields rather than left to the
//!    ABI. Where padding is implicit it is called out in a comment with the
//!    offset it occupies.
//! 3. **Every size and every field offset is asserted** in this module's tests,
//!    by literal number, so a field inserted in the middle fails the build
//!    rather than changing the protocol silently.
//! 4. **Alignment never exceeds 8**, so the same layout holds on a 32-bit
//!    target where `u64` alignment is 8 but pointer alignment is 4. This
//!    matters for the driver only in that it removes a class of "works on the
//!    dev machine" bug; the product ships x64 (`rust-toolchain.toml` targets
//!    `x86_64-pc-windows-msvc`) and there is no 32-bit build to test.
//!
//! # The rule about lengths
//!
//! **No length that arrives from outside is ever used as an allocation size.**
//!
//! There are two length-valued fields in the protocol — [`DecisionRequestMessage::path_units`]
//! and [`EventMessage::path_units`] — and both are *used lengths into a buffer
//! that is already allocated at its full size by the structure itself*. The
//! buffer is `[u16; MAX_PATH_UNITS]`; `path_units` says how much of it is
//! meaningful, and [`DecisionRequestMessage::path`] answers with a slice
//! clamped to that buffer's length. A `path_units` of `u32::MAX` produces a
//! one-thousand-and-twenty-four-element slice, not a four-gigabyte allocation,
//! because no code path here can allocate.
//!
//! That property is not an accident of this module; it is why the crate is
//! `no_std` and has no dependencies. A crate that cannot allocate cannot be
//! made to allocate by a hostile length field.
//!
//! # Why the filter manager's own headers appear here
//!
//! [`PortMessageHeader`] and [`PortReplyHeader`] mirror `FILTER_MESSAGE_HEADER`
//! and `FILTER_REPLY_HEADER` from the WDK's `shared/fltUserStructures.h`. That
//! header declares:
//!
//! ```text
//! typedef struct _FILTER_MESSAGE_HEADER {
//!     ULONG     ReplyLength;   // OUT: total reply length *including* the
//!                              //      FILTER_REPLY_HEADER, or 0 if none
//!     ULONGLONG MessageId;     // OUT: echo this in the reply
//! } FILTER_MESSAGE_HEADER;
//!
//! typedef struct _FILTER_REPLY_HEADER {
//!     NTSTATUS  Status;        // IN: returned to the waiting driver
//!     ULONGLONG MessageId;     // IN: the id from the message being answered
//! } FILTER_REPLY_HEADER;
//! ```
//!
//! They are re-declared rather than imported so that the *user-mode* half of
//! this protocol, which links against `fltlib` and nothing else, can be
//! compiled and tested without a WDK. The layout is asserted against the same
//! numbers the WDK header produces.
//!
//! Note what `MessageId` is: the filter manager's own correlation id, generated
//! by `FltSendMessage`, which user mode must copy into the reply. It is *not*
//! the product's [`crate::decision::RequestId`]. Both exist and both are
//! needed — see [`crate::decision`] for why the port's correlation cannot
//! replace the product's, and the test
//! `a_reply_for_an_expired_request_is_not_applied_to_its_replacement` for the
//! bug that difference prevents.

use core::fmt;

use crate::exclusions::{MAX_EXCLUSIONS, MAX_EXCLUSION_UNITS};

// --- capacity constants ----------------------------------------------------

/// Longest path this protocol carries, in UTF-16 code units, not counting a
/// terminating NUL — because [`crate::path`] works on `UNICODE_STRING`-shaped
/// slices which do not have one.
///
/// This is 1024 units, not the 260 of `MAX_PATH` and not the 32767 a `\\?\`
/// path may reach. The trade is stated rather than hidden:
///
/// * `MAX_PATH` (260) is not enough. The driver resolves a path through the
///   filter manager's name provider, which returns the *normalised* name, and
///   normalised names routinely exceed 260 characters on a machine with deep
///   user directories or a redirected profile. A buffer that overflowed on
///   those would refuse to ask about exactly the files in the awkward corners
///   where malware likes to live.
/// * 32767 units would make every decision request 64 KB. Each one is a
///   nonpaged allocation held while a thread waits on a verdict, and a busy
///   machine can have hundreds outstanding. 1024 units keeps the message at
///   just over 2 KB, which is a size the filter manager's port handles
///   comfortably.
/// * What happens past 1024 units is *not* truncation. A truncated path is a
///   path that could be matched against the wrong exclusion or the wrong
///   allow-list entry, so the driver refuses to send the request at all, counts
///   it, and takes the timeout default. See
///   [`crate::decision::PendingTable::register`] for the same reasoning applied
///   to a full table.
pub const MAX_PATH_UNITS: usize = 1024;

/// Bytes in a full-size path field. Used for size assertions and for the
/// driver's buffer arithmetic.
pub const MAX_PATH_BYTES: usize = MAX_PATH_UNITS * 2;

/// Events returned by one [`IOCTL_READ_EVENTS`](crate::ioctl::IOCTL_READ_EVENTS)
/// call.
///
/// Eight [`EventMessage`]s is a little under 17 KB of buffered I/O per call. The
/// number is a rate question, not a size one: a service that has been down for
/// an hour and a machine that generated a thousand events while it was away
/// needs about a hundred and twenty calls to drain, which at any plausible
/// polling interval is under a second of catch-up. Larger batches would mean a
/// larger nonpaged allocation held for the duration of every drain.
pub const MAX_EVENT_BATCH: usize = 8;

/// The reserved message kind. A zeroed buffer has this kind, which is what
/// makes an all-zero message invalid rather than a request to allow everything.
/// See [`MessageKind`].
pub const KIND_RESERVED: u32 = 0;
/// [`MessageKind::DecisionRequest`] on the wire.
pub const KIND_DECISION_REQUEST: u32 = 1;
/// [`MessageKind::Event`] on the wire.
pub const KIND_EVENT: u32 = 2;
/// [`MessageKind::Status`] on the wire.
pub const KIND_STATUS: u32 = 3;
/// [`MessageKind::Config`] on the wire.
pub const KIND_CONFIG: u32 = 4;

/// What an inbound message is.
///
/// The wire field is a `u32` and not this enum, deliberately: a message from a
/// service built against a newer protocol has a `kind` this driver has never
/// heard of, and it must be *representable* so the driver can reject it with a
/// status. Deserialising an unknown value into an enum is either undefined
/// behaviour or a panic, and a panic in a filesystem filter at `APC_LEVEL`
/// bugchecks the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// The driver is asking for a verdict and will wait for the reply.
    DecisionRequest,
    /// Something happened that the service should record.
    Event,
    /// The driver's liveness and counters.
    Status,
    /// The service telling the driver how to protect itself.
    ///
    /// The only kind that travels **user mode to driver** as an unsolicited
    /// message. The other three are driver-initiated and this one is not, which
    /// is why it is the one the port's message callback has to parse rather
    /// than the one it sends. See [`ConfigMessage`].
    Config,
}

impl MessageKind {
    /// The value that goes on the wire.
    pub const fn as_wire(self) -> u32 {
        match self {
            MessageKind::DecisionRequest => KIND_DECISION_REQUEST,
            MessageKind::Event => KIND_EVENT,
            MessageKind::Status => KIND_STATUS,
            MessageKind::Config => KIND_CONFIG,
        }
    }

    /// Decode a wire value. `None` for anything unrecognised, including the
    /// reserved zero.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            KIND_DECISION_REQUEST => Some(MessageKind::DecisionRequest),
            KIND_EVENT => Some(MessageKind::Event),
            KIND_STATUS => Some(MessageKind::Status),
            KIND_CONFIG => Some(MessageKind::Config),
            // KIND_RESERVED and every value a future version might define.
            _ => None,
        }
    }

    /// True for a value this build understands.
    pub const fn is_known(value: u32) -> bool {
        value == KIND_DECISION_REQUEST
            || value == KIND_EVENT
            || value == KIND_STATUS
            || value == KIND_CONFIG
    }
}

/// The filter manager's per-message header.
///
/// `ReplyLength` is the *total* expected reply size including the reply header,
/// or zero when no reply is wanted. The filter manager's own header says so in
/// as many words; copying the field without copying that sentence is how a
/// driver ends up passing the payload size and having its reply rejected as
/// short.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PortMessageHeader {
    /// Total expected reply length in bytes, including [`PortReplyHeader`].
    /// Zero means "fire and forget".
    pub reply_length: u32,
    /// Implicit padding: offset 4, length 4. Present because `MessageId` is a
    /// `ULONGLONG` (8-byte aligned) and `ReplyLength` is a `ULONG` (4-byte).
    /// Written out so the layout test has something to point at.
    pub _pad0: u32,
    /// The filter manager's correlation id. User mode echoes this into
    /// [`PortReplyHeader::message_id`].
    pub message_id: u64,
}

impl PortMessageHeader {
    /// Size the WDK header produces on x64, and on x86 as well because
    /// `unsigned __int64` is 8-byte aligned under the MSVC ABI in both.
    pub const SIZE: usize = 16;
}

impl fmt::Debug for PortMessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortMessageHeader")
            .field("reply_length", &self.reply_length)
            .field("message_id", &self.message_id)
            .finish()
    }
}

/// The filter manager's reply header, which begins every reply.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PortReplyHeader {
    /// `NTSTATUS`, which the WDK typedefs as `LONG`. A negative value here is
    /// what `FltSendMessage` returns to the waiting driver instead of a reply.
    pub status: i32,
    /// Implicit padding: offset 4, length 4, for the same reason as
    /// [`PortMessageHeader::_pad0`].
    pub _pad0: u32,
    /// Must equal the [`PortMessageHeader::message_id`] of the message being
    /// answered.
    pub message_id: u64,
}

impl PortReplyHeader {
    /// Same arithmetic as [`PortMessageHeader::SIZE`].
    pub const SIZE: usize = 16;

    /// `STATUS_SUCCESS`.
    pub const STATUS_SUCCESS: i32 = 0;
}

impl Default for PortReplyHeader {
    fn default() -> Self {
        Self {
            status: Self::STATUS_SUCCESS,
            _pad0: 0,
            message_id: 0,
        }
    }
}

impl fmt::Debug for PortReplyHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortReplyHeader")
            .field("status", &format_args!("{:#010X}", self.status))
            .field("message_id", &self.message_id)
            .finish()
    }
}

/// The fields every driver-to-user message starts with.
///
/// `kind` and `version` are here rather than being implied, and both are here
/// for the same reason: a service that receives a message it does not
/// understand must be able to say so. Without `kind` it would have to guess
/// from the message's length, and two structures in this file are the same
/// length by coincidence; without `version` it would have to guess from the
/// connection, and a driver and a service are installed and updated by
/// different mechanisms at different times.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MessagePrefix {
    /// The filter manager's header, filled in by [`crate::wire`]'s user-mode
    /// counterpart and by `FltSendMessage` in the kernel.
    pub header: PortMessageHeader,
    /// A [`MessageKind`] wire value.
    pub kind: u32,
    /// [`crate::ioctl::PROTOCOL_VERSION`] of the sender.
    pub version: u32,
}

impl MessagePrefix {
    /// 16 for the header plus two `u32`. No implicit padding: 24 is already a
    /// multiple of 8, so the compiler adds none and this is the real size.
    pub const SIZE: usize = 24;

    /// Build a prefix. `reply_length` must be the total reply size including
    /// the reply header, or zero for a message that wants no answer.
    pub const fn new(kind: MessageKind, reply_length: u32) -> Self {
        Self {
            header: PortMessageHeader {
                reply_length,
                _pad0: 0,
                message_id: 0,
            },
            kind: kind.as_wire(),
            version: crate::ioctl::PROTOCOL_VERSION,
        }
    }

    /// Whether this prefix carries a `kind` this build understands *and* a
    /// protocol version it can parse.
    ///
    /// Both checks, and in this order, because they answer different questions:
    /// `kind` decides whether the layout below the prefix can be read at all,
    /// and `version` decides whether the sender and receiver agree about that
    /// layout. A message can pass the first and fail the second.
    pub fn is_readable(&self) -> bool {
        MessageKind::is_known(self.kind) && is_compatible(self.version)
    }
}

impl Default for MessagePrefix {
    fn default() -> Self {
        Self {
            header: PortMessageHeader::default(),
            kind: KIND_RESERVED,
            version: 0,
        }
    }
}

impl fmt::Debug for MessagePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessagePrefix")
            .field("header", &self.header)
            .field("kind", &MessageKind::from_wire(self.kind))
            .field("version", &format_args!("{:#010X}", self.version))
            .finish()
    }
}

/// Whether a peer's advertised protocol version can be parsed by this build.
///
/// **Exact equality, and nothing softer.** [`crate::ioctl::PROTOCOL_VERSION`] is
/// split into a major and a minor half so that a compatibility rule *could* be
/// written, and this function is where it would be written. It is not written,
/// because no structure in this file has a stable prefix yet that a compatible
/// change could be confined to: adding a field to
/// [`DecisionRequestMessage`] moves the path, which is the one field every
/// consumer reads. Claiming minor-version compatibility before there is a
/// structure that supports it would be a promise this crate cannot keep, and
/// the failure it would cause — a driver and a service disagreeing about where
/// a path begins — is the worst failure in the protocol.
pub const fn is_compatible(peer_version: u32) -> bool {
    peer_version == crate::ioctl::PROTOCOL_VERSION
}

// --- driver -> user --------------------------------------------------------

/// A file the driver is refusing to let run until user mode says otherwise.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DecisionRequestMessage {
    /// Kind, version, and the filter manager's correlation id.
    pub prefix: MessagePrefix,
    /// The product's correlation id, from
    /// [`crate::decision::RequestId`]. Distinct from
    /// `prefix.header.message_id`; see [`crate::decision`].
    pub request_id: u64,
    /// A [`crate::event::SubjectKind`] wire value.
    pub subject: u32,
    /// Reserved. **No bit is defined on either side.**
    ///
    /// A sender writes zero and a receiver does not act on a bit it finds set.
    /// The field is here so that a flag can be added later without changing
    /// the message size — and a receiver that guessed at the meaning of a bit
    /// it was not told about would be reading a sender's reserved space as an
    /// instruction.
    pub flags: u32,
    /// How long the driver will wait before taking
    /// [`crate::decision::DecisionPolicy::on_timeout`]. Carried in the message
    /// because the service should log a request it cannot answer in time, and
    /// it cannot know the deadline otherwise.
    pub timeout_ms: u32,
    /// Meaningful length of [`DecisionRequestMessage::path`], in UTF-16 code
    /// units. **Not** an allocation size — see the module documentation.
    pub path_units: u32,
    /// The process that asked, when the driver can name one.
    ///
    /// **Not necessarily the program that is about to run.** A section created
    /// during process creation is created on the thread that called
    /// `CreateProcess`, so this names the launcher — the shell, `cmd`, a
    /// service host — and not the new process. A DLL loaded into a running
    /// process is asked about by that process itself. Zero when nothing filled
    /// it, which is every message this driver sent before 2026-10-18.
    pub process_id: u32,
    /// The thread that tried to run it.
    pub thread_id: u32,
    /// The path, as UTF-16 code units with no terminating NUL. Only the first
    /// [`DecisionRequestMessage::path_units`] are meaningful.
    pub path: [u16; MAX_PATH_UNITS],
}

impl DecisionRequestMessage {
    /// 24 + 8 + 4 + 4 + 4 + 4 + 4 + 4 = 56 bytes of header, then
    /// [`MAX_PATH_BYTES`]. 56 + 2048 = 2104, which is a multiple of 8, so there
    /// is no trailing padding.
    pub const SIZE: usize = 56 + MAX_PATH_BYTES;

    /// Offset of [`DecisionRequestMessage::path`], used by the tests and by the
    /// driver when it fills the field through a pointer.
    pub const PATH_OFFSET: usize = 56;

    /// A request with no path set.
    pub fn new(request_id: u64, subject: crate::event::SubjectKind) -> Self {
        Self {
            prefix: MessagePrefix::new(
                MessageKind::DecisionRequest,
                DecisionReplyMessage::SIZE as u32,
            ),
            request_id,
            subject: subject.as_wire(),
            flags: 0,
            timeout_ms: 0,
            path_units: 0,
            process_id: 0,
            thread_id: 0,
            path: [0; MAX_PATH_UNITS],
        }
    }

    /// The meaningful part of the path.
    ///
    /// Clamped by the array's own length, so no value of
    /// [`DecisionRequestMessage::path_units`] can produce an out-of-bounds
    /// slice — including `u32::MAX`.
    pub fn path(&self) -> &[u16] {
        let units = (self.path_units as usize).min(MAX_PATH_UNITS);
        &self.path[..units]
    }

    /// Set the path, or fail if it does not fit.
    ///
    /// Failing rather than truncating is the whole point: a truncated path
    /// could match the wrong exclusion, and the caller's correct response is to
    /// not send the request and take the timeout default. See
    /// [`MAX_PATH_UNITS`].
    pub fn set_path(&mut self, path: &[u16]) -> Result<(), PathTooLong> {
        if path.len() > MAX_PATH_UNITS {
            return Err(PathTooLong {
                needed: path.len(),
                capacity: MAX_PATH_UNITS,
            });
        }
        self.path[..path.len()].copy_from_slice(path);
        self.path_units = path.len() as u32;
        Ok(())
    }

    /// [`crate::path::path_tag`] of the *meaningful* part of the path, which is
    /// what a reply must echo back.
    ///
    /// Computed from the clamped slice, so a hostile `path_units` changes which
    /// tag comes out but cannot make this read past the array.
    pub fn path_tag(&self) -> u64 {
        crate::path::path_tag(self.path())
    }
}

impl Default for DecisionRequestMessage {
    fn default() -> Self {
        Self::new(0, crate::event::SubjectKind::File)
    }
}

impl fmt::Debug for DecisionRequestMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The path is deliberately not dumped: 1024 `u16`s of mostly zero in a
        // kernel debugger's log is noise that hides the fields that matter.
        f.debug_struct("DecisionRequestMessage")
            .field("prefix", &self.prefix)
            .field("request_id", &self.request_id)
            .field(
                "subject",
                &crate::event::SubjectKind::from_wire(self.subject),
            )
            .field("flags", &format_args!("{:#06X}", self.flags))
            .field("timeout_ms", &self.timeout_ms)
            .field("path_units", &self.path_units)
            .field("process_id", &self.process_id)
            .field("thread_id", &self.thread_id)
            .field("path", &crate::path::display_u16(self.path()))
            .finish()
    }
}

/// A path did not fit in a fixed-size wire field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTooLong {
    /// Units the caller tried to store.
    pub needed: usize,
    /// Units the field holds.
    pub capacity: usize,
}

impl fmt::Display for PathTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "path needs {} UTF-16 units but the field holds {}",
            self.needed, self.capacity
        )
    }
}

/// User mode's answer to one [`DecisionRequestMessage`].
///
/// **Carries no [`MessagePrefix`], and that is deliberate.** The filter manager
/// pairs a reply with the message it answers using
/// [`PortReplyHeader::message_id`], so a reply has no need to declare its kind —
/// it is whatever the message it answers was. It also needs no `version`,
/// because the sender and receiver of a reply are the same two parties that
/// already agreed on the request's version. Adding either would be two more
/// fields that could disagree with the thing they describe.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DecisionReplyMessage {
    /// `status` is how the *filter manager* is told the reply is valid; a
    /// negative value there makes `FltSendMessage` fail instead of returning
    /// the decision. `message_id` is the correlation.
    pub reply: PortReplyHeader,
    /// Echoed from the request. This is the field the pending table checks —
    /// see [`crate::decision::PendingTable::resolve`].
    pub request_id: u64,
    /// A [`crate::decision::Decision`] wire value.
    pub decision: u32,
    /// Reserved. **No bit is defined on either side.**
    ///
    /// A sender writes zero and a receiver does not act on a bit it finds set.
    /// The field is here so that a flag can be added later without changing
    /// the message size. The same rule as the request's `flags`, and for the
    /// same reason: a reserved field that one side starts interpreting is a
    /// protocol change made in one place.
    pub flags: u32,
    /// Echoed from the request: the kind of thing the decision is about.
    ///
    /// **This is not redundant with `request_id` and it is not politeness.**
    /// It is what makes [`crate::decision::ResolveOutcome::Mismatch`]
    /// reachable from a real wire message. `request_id` alone identifies *a*
    /// request; if a service's own bookkeeping ever crossed two answers over,
    /// the id would still be live and a wrong verdict would be applied to a
    /// file nobody asked about. The driver compares all three echoes before it
    /// applies anything, and a reply that describes a different file is
    /// discarded and leaves the request pending, to be decided by its timeout.
    pub subject: u32,
    /// Padding, so `path_tag` is 8-aligned without the compiler inserting a
    /// gap this crate cannot name.
    pub _pad0: u32,
    /// Echoed from the request: [`crate::path::path_tag`] of the path the
    /// request carried. See `subject` for why it is here.
    pub path_tag: u64,
}

impl DecisionReplyMessage {
    /// 16 + 8 + 4 + 4 + 4 + 4 + 8 = 48, a multiple of 8.
    pub const SIZE: usize = 48;

    /// The bytes of this structure that cross the port back to the driver.
    ///
    /// **The filter manager consumes [`PortReplyHeader`] itself.** Its
    /// `status` becomes `FltSendMessage`'s return value and its `message_id` is
    /// what pairs the reply with the waiting message; what lands in the
    /// driver's reply buffer is everything after them, and the `ReplyLength`
    /// the driver passes *in* is a capacity for those bytes and not for the
    /// whole structure. The header's 16 bytes are added back when that capacity
    /// is advertised to user mode, which is what
    /// [`PortMessageHeader::reply_length`]'s "including the FILTER_REPLY_HEADER"
    /// means.
    ///
    /// Measured rather than assumed — `FLTMGR.SYS` 10.0.26100,
    /// `FltSendMessage` at `0x180017CD0` (image base `0x180000000`): the
    /// caller's `ReplyLength` is read at `0x180017D6A`/`0x180018317`, kept in a
    /// local, and written into the outgoing [`PortMessageHeader::reply_length`]
    /// as `lea eax,[rdi+10h]` / `mov [rcx],eax` (`0x180018106`); the sender
    /// buffer length is given the same `+ 0x10` at `0x180017E15`, and that
    /// value is what the receive side compares against the user's buffer at
    /// `0x180017EFE`.
    ///
    /// A driver that hands over the whole structure and then requires the whole
    /// structure's size back receives 32 bytes for a 48-byte expectation and
    /// discards every answer — which reads from service side exactly like a
    /// service that never convicts anything.
    pub const PAYLOAD_OFFSET: usize = PortReplyHeader::SIZE;

    /// `SIZE - PAYLOAD_OFFSET`: 32 bytes, the reply capacity to give
    /// `FltSendMessage`.
    pub const PAYLOAD_SIZE: usize = Self::SIZE - Self::PAYLOAD_OFFSET;

    /// The first payload byte — the address `FltSendMessage`'s reply buffer
    /// must point at, and the address of [`Self::request_id`].
    pub fn payload_ptr(&mut self) -> *mut u8 {
        (self as *mut Self)
            .cast::<u8>()
            .wrapping_add(Self::PAYLOAD_OFFSET)
    }

    /// A reply carrying `decision` for `request_id`.
    ///
    /// The echoes start at zero and it is the caller's job to fill them from
    /// the request it is answering. A reply sent with them still zero will be
    /// discarded as a mismatch by any request whose subject is not in wire
    /// value `0` — which no subject is, because zero is reserved. That is the
    /// intended direction: a half-filled reply is a dropped reply, and a
    /// dropped reply becomes an allow at the timeout.
    pub const fn new(request_id: u64, decision: crate::decision::Decision) -> Self {
        Self {
            reply: PortReplyHeader {
                status: PortReplyHeader::STATUS_SUCCESS,
                _pad0: 0,
                message_id: 0,
            },
            request_id,
            decision: decision.as_wire(),
            flags: 0,
            subject: 0,
            _pad0: 0,
            path_tag: 0,
        }
    }

    /// Build a reply that echoes the identifying fields of the request it
    /// answers. This is the constructor a service should use; [`Self::new`]
    /// exists for the tests that deliberately want a mismatched reply.
    ///
    /// Not `const`, unlike [`Self::new`]: computing the path tag walks the
    /// path, and `for` loops are not available in a `const fn` on this crate's
    /// minimum toolchain. Nothing here needs to run at compile time.
    pub fn answering(
        request: &DecisionRequestMessage,
        decision: crate::decision::Decision,
    ) -> Self {
        Self {
            reply: PortReplyHeader {
                status: PortReplyHeader::STATUS_SUCCESS,
                _pad0: 0,
                message_id: 0,
            },
            request_id: request.request_id,
            decision: decision.as_wire(),
            flags: 0,
            subject: request.subject,
            _pad0: 0,
            path_tag: request.path_tag(),
        }
    }
}

impl Default for DecisionReplyMessage {
    fn default() -> Self {
        // The default decision is `Allow` for the same reason
        // `DecisionPolicy::on_timeout` is: a reply structure that was never
        // filled in must not be a block. See [`crate::decision::DecisionPolicy`].
        Self::new(0, crate::decision::Decision::Allow)
    }
}

impl fmt::Debug for DecisionReplyMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionReplyMessage")
            .field("reply", &self.reply)
            .field("request_id", &self.request_id)
            .field(
                "decision",
                &crate::decision::Decision::from_wire(self.decision),
            )
            .field("flags", &format_args!("{:#06X}", self.flags))
            .field(
                "subject",
                &crate::event::SubjectKind::from_wire(self.subject),
            )
            .field("path_tag", &format_args!("{:#018X}", self.path_tag))
            .finish()
    }
}

/// Something the driver saw, on its way to the service.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EventMessage {
    /// Kind, version, correlation. `reply_length` is zero for an event: an
    /// event is a notification and the driver does not wait for it. A driver
    /// that waited for an acknowledgement of every write on the machine would
    /// be a driver that made every write as slow as the slowest service.
    pub prefix: MessagePrefix,
    /// Monotonic within one driver load. Gaps tell the service it missed
    /// events, which is how a bounded queue reports overflow without a separate
    /// channel.
    pub sequence: u64,
    /// When it happened, in 100-nanosecond units since 1601-01-01, which is
    /// what `KeQuerySystemTimePrecise` returns and what a kernel driver has
    /// without converting. Converting to a civil time in the kernel would mean
    /// carrying a timezone database there.
    pub timestamp_100ns: u64,
    /// A [`crate::event::SubjectKind`] wire value.
    pub subject: u32,
    /// A [`crate::event::EventAction`] wire value.
    pub action: u32,
    /// An `av_core::Severity` wire value. The driver does not evaluate
    /// severities — it copies the one the service sent back in a verdict, or
    /// the constant for the action when there was no verdict.
    pub severity: u32,
    /// An `av_core::Verdict` wire value, or
    /// [`crate::event::VERDICT_NONE`] when the action had no verdict.
    pub verdict: u32,
    /// The process responsible, when there is one.
    pub process_id: u32,
    /// The thread responsible, when there is one.
    pub thread_id: u32,
    /// Meaningful length of [`EventMessage::path`]. Not an allocation size.
    pub path_units: u32,
    /// Action-specific detail: an `NTSTATUS`, a dropped-event count, a driver
    /// state. Meaningless without [`EventMessage::action`].
    pub detail: u32,
    /// The path as UTF-16 code units, no terminating NUL.
    pub path: [u16; MAX_PATH_UNITS],
}

impl EventMessage {
    /// 24 + 8 + 8 + 4 * 8 = 72, then [`MAX_PATH_BYTES`]. 72 + 2048 = 2120,
    /// which is a multiple of 8.
    pub const SIZE: usize = 72 + MAX_PATH_BYTES;

    /// Offset of [`EventMessage::path`].
    pub const PATH_OFFSET: usize = 72;

    /// Create an event with `sequence` and `now_100ns`, which the caller stamps
    /// so that a test can produce identical messages.
    pub fn new(
        sequence: u64,
        now_100ns: u64,
        subject: crate::event::SubjectKind,
        action: crate::event::EventAction,
    ) -> Self {
        Self {
            // No reply wanted: see the field documentation.
            prefix: MessagePrefix::new(MessageKind::Event, 0),
            sequence,
            timestamp_100ns: now_100ns,
            subject: subject.as_wire(),
            action: action.as_wire(),
            severity: 0,
            verdict: crate::event::VERDICT_NONE,
            process_id: 0,
            thread_id: 0,
            path_units: 0,
            detail: 0,
            path: [0; MAX_PATH_UNITS],
        }
    }

    /// The meaningful part of the path, clamped by the array's own length.
    pub fn path(&self) -> &[u16] {
        let units = (self.path_units as usize).min(MAX_PATH_UNITS);
        &self.path[..units]
    }

    /// Set the path, or fail if it does not fit.
    pub fn set_path(&mut self, path: &[u16]) -> Result<(), PathTooLong> {
        if path.len() > MAX_PATH_UNITS {
            return Err(PathTooLong {
                needed: path.len(),
                capacity: MAX_PATH_UNITS,
            });
        }
        self.path[..path.len()].copy_from_slice(path);
        self.path_units = path.len() as u32;
        Ok(())
    }
}

impl Default for EventMessage {
    fn default() -> Self {
        Self::new(
            0,
            0,
            crate::event::SubjectKind::File,
            crate::event::EventAction::Heartbeat,
        )
    }
}

impl fmt::Debug for EventMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventMessage")
            .field("prefix", &self.prefix)
            .field("sequence", &self.sequence)
            .field(
                "subject",
                &crate::event::SubjectKind::from_wire(self.subject),
            )
            .field("action", &crate::event::EventAction::from_wire(self.action))
            .field(
                "severity",
                &crate::event::SeverityCode::from_wire(self.severity),
            )
            .field("verdict", &crate::event::verdict_name(self.verdict))
            .field("process_id", &self.process_id)
            .field("path_units", &self.path_units)
            .field("detail", &self.detail)
            .field("path", &crate::path::display_u16(self.path()))
            .finish()
    }
}

/// The driver's liveness and counters, sent on a timer and on demand.
///
/// Sent over the port as a [`MessageKind::Status`] message *and* returned by
/// [`IOCTL_QUERY_STATUS`](crate::ioctl::IOCTL_QUERY_STATUS). The two are the
/// same structure on purpose: the port message tells a connected service that
/// the driver is alive without it having to ask, and the IOCTL lets a service
/// that has just started find out how long the driver has been running without
/// it, which is how it knows whether the machine rebooted while it was away.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusMessage {
    /// Kind, version, correlation. No reply wanted.
    pub prefix: MessagePrefix,
    /// The counters. The same structure the IOCTL returns.
    pub status: DriverStatus,
}

impl StatusMessage {
    /// 24 + 56 = 80, a multiple of 8.
    pub const SIZE: usize = 80;

    /// A status message carrying `status`.
    pub const fn new(status: DriverStatus) -> Self {
        Self {
            prefix: MessagePrefix::new(MessageKind::Status, 0),
            status,
        }
    }
}

impl fmt::Debug for StatusMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusMessage")
            .field("prefix", &self.prefix)
            .field("status", &self.status)
            .finish()
    }
}

/// What the driver is doing, in one structure.
///
/// Returned by [`IOCTL_QUERY_STATUS`](crate::ioctl::IOCTL_QUERY_STATUS) and
/// carried by [`StatusMessage`].
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct DriverStatus {
    /// [`crate::ioctl::PROTOCOL_VERSION`] of the *driver*, which may differ
    /// from the version of the message that carried this structure if the
    /// service is older. A service that reads this and finds it unfamiliar has
    /// learned something the message prefix alone would not have told it.
    pub protocol_version: u32,
    /// A [`crate::event::DriverState`] wire value.
    pub state: u32,
    /// A [`crate::event::EnforcementMode`] wire value.
    pub mode: u32,
    /// Events waiting to be drained by
    /// [`IOCTL_READ_EVENTS`](crate::ioctl::IOCTL_READ_EVENTS).
    pub queued_events: u32,
    /// Milliseconds since the driver was loaded.
    pub uptime_ms: u64,
    /// Decisions asked of user mode since load.
    pub decisions_asked: u64,
    /// Decisions that reached user mode and were answered in time.
    pub decisions_answered: u64,
    /// Decisions the driver gave up on: the wait expired, the port was not
    /// connected, the table was full, or the request was never sent because
    /// the path was too long. All four take
    /// [`crate::decision::DecisionPolicy::on_timeout`].
    ///
    /// One counter for four causes rather than four counters, because the
    /// *response* is identical and a service alarming on this needs to know
    /// only that something is stopping the driver from getting answers.
    /// [`DriverStats`] breaks down the two that a service can act on.
    pub decisions_unanswered: u64,
    /// Events discarded because the queue was full.
    pub events_dropped: u64,
}

impl DriverStatus {
    /// Four `u32` fields and five `u64` fields: 4 * 4 + 8 * 5 = 56, already a
    /// multiple of 8.
    ///
    /// This was 48 in the first draft, which is what a count of *eight* `u64`
    /// fields would give — an arithmetic slip, and the size test caught it.
    /// The count is spelled out here so the next field added has to argue with
    /// a number rather than with a memory.
    pub const SIZE: usize = 56;
}

impl fmt::Debug for DriverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverStatus")
            .field(
                "protocol_version",
                &format_args!("{:#010X}", self.protocol_version),
            )
            .field("state", &crate::event::DriverState::from_wire(self.state))
            .field("mode", &crate::event::EnforcementMode::from_wire(self.mode))
            .field("queued_events", &self.queued_events)
            .field("uptime_ms", &self.uptime_ms)
            .field("decisions_asked", &self.decisions_asked)
            .field("decisions_answered", &self.decisions_answered)
            .field("decisions_unanswered", &self.decisions_unanswered)
            .field("events_dropped", &self.events_dropped)
            .finish()
    }
}

/// Counters that say how effective the filter is being.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct DriverStats {
    /// Executions refused at the create gate.
    ///
    /// **Always zero since 2026-10-15, and that is not a fault.** No create
    /// was ever refused: the service's `refusing_gate` answers `false` for
    /// every subject that gate sends, so the driver's `Block` arm was
    /// unreachable and the answer it waited up to five seconds for was
    /// discarded. The field stays because it is part of a `repr(C)` structure
    /// whose layout is the protocol's, and because a build that resumed
    /// refusing creates would have somewhere to say so. Refusals that happen
    /// are in [`DriverStats::images_blocked`].
    pub blocked_executions: u64,
    /// Writes refused. Meaningful only in
    /// [`crate::event::EnforcementMode::Blocking`]; a service that sees this
    /// non-zero while the mode is `Observe` has a bug.
    pub blocked_writes: u64,
    /// Image loads refused.
    pub images_blocked: u64,
    /// Operations the driver looked at and allowed. Large by design — every
    /// file open on the machine that was not a program is one of these, and a
    /// service that alarms on this number has misread it.
    pub allowed: u64,
    /// Requests that expired before a verdict arrived.
    pub timed_out: u64,
    /// Operations that never became a request because the path matched the
    /// exclusion table. Counted so that an operator can see an over-broad
    /// exclusion doing what an over-broad exclusion does.
    pub excluded: u64,
    /// Operations that never became a request because the device path had no
    /// DOS drive behind it — a network redirector, most often. See
    /// [`crate::path::PathError::UnknownVolume`] for why these are scanned
    /// rather than skipped.
    pub unresolved_volume: u64,
    /// Operations that never became a request because the path was longer than
    /// [`MAX_PATH_UNITS`].
    pub oversize_path: u64,
}

impl DriverStats {
    /// 8 * 8 = 64, a multiple of 8.
    pub const SIZE: usize = 64;
}

impl fmt::Debug for DriverStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriverStats")
            .field("blocked_executions", &self.blocked_executions)
            .field("blocked_writes", &self.blocked_writes)
            .field("images_blocked", &self.images_blocked)
            .field("allowed", &self.allowed)
            .field("timed_out", &self.timed_out)
            .field("excluded", &self.excluded)
            .field("unresolved_volume", &self.unresolved_volume)
            .field("oversize_path", &self.oversize_path)
            .finish()
    }
}

/// The input to [`IOCTL_SET_MODE`](crate::ioctl::IOCTL_SET_MODE).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SetModeRequest {
    /// A [`crate::event::EnforcementMode`] wire value.
    pub mode: u32,
    /// Reserved. **No bit is defined on either side.**
    ///
    /// A caller writes zero and the driver does not act on a bit it finds set.
    /// The field is here so that a flag can be added later without changing
    /// the IOCTL's input size.
    pub flags: u32,
    /// The decision timeout in milliseconds. Zero means "leave it as it is",
    /// so that a caller that only wants to change the mode does not have to
    /// know the current timeout and write it back — a read-modify-write it
    /// would have to do without a lock, and which would race with another
    /// caller doing the same.
    pub timeout_ms: u32,
    /// Implicit padding: offset 12, length 4. Present because the structure
    /// contains a `u64` in no version, but written out so that adding one later
    /// does not silently change the size.
    pub _pad0: u32,
}

impl SetModeRequest {
    /// 4 * 4 = 16.
    pub const SIZE: usize = 16;
}

/// Arm handle protection: strip the process and thread rights this product
/// protects from every handle opened to one of its own processes.
pub const CONFIG_PROTECT_HANDLES: u32 = 0x0000_0001;
/// Arm the write gate: refuse writes to this product's own files in the
/// driver, without asking user mode.
pub const CONFIG_GATE_WRITES: u32 = 0x0000_0002;

/// The service telling the driver how to protect itself.
///
/// # Why this travels the port and not an IOCTL
///
/// The crate documentation's table says configuration is an IOCTL, and for
/// everything else it is. This message is the exception and the reason is
/// ordering: the driver arms itself the moment a service connects, and a
/// configuration that arrived over a control device would need the service to
/// open the device, discover the driver, and issue an IOCTL before the first
/// write — a window in which the driver is filtering with no policy. The port's
/// connect callback is the one moment the driver knows a service exists, so the
/// message the service sends back over that port is the one that cannot be
/// late.
///
/// The six IOCTLs in [`crate::ioctl`] still have no handler and no control
/// device exists; this message does not change that, and it is deliberately not
/// a seventh code in that table.
///
/// # Why there is no `version` field
///
/// [`ExclusionBuffer`] carries one because an IOCTL's input buffer arrives with
/// nothing around it. This structure is carried by a [`MessagePrefix`], whose
/// `version` is checked by [`MessagePrefix::is_readable`] before any of the
/// fields below are read. A second version field would be a second thing to
/// keep in step with the first.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfigMessage {
    /// Kind, version, correlation. `reply_length` is zero, and that is about
    /// the **filter manager**, not about the message: `reply_length` is the
    /// field `FltSendMessage` reads to decide whether to wait for an answer, and
    /// a user-mode sender that set it would be asking `FilterSendMessage` to
    /// wait for a reply that this callback cannot produce as a wait — the
    /// callback must not block.
    ///
    /// The answer is nonetheless immediate and does come back from the
    /// callback: a four-byte `NTSTATUS` through the port's output buffer, which
    /// `FilterSendMessage` fills in and reports the length of. That is how the
    /// service learns whether the driver applied its configuration — see
    /// `port_message` in `crates/av-driver`. This documentation said the driver
    /// reported through [`crate::event::EventAction::StateChanged`] and never
    /// through a reply until 2026-10-09, which was true of a driver that had
    /// nothing to answer with.
    pub prefix: MessagePrefix,
    /// Which protections to arm. A [`u32`] of `CONFIG_*` bits.
    ///
    /// Bits rather than two booleans in two fields, and a field rather than a
    /// single "protect everything" flag, because the two halves fail
    /// independently: an `ObRegisterCallbacks` registration can be refused by
    /// the kernel while the write gate is fine, and a service that could not
    /// say which it wanted would have to choose both or neither.
    pub flags: u32,
    /// Meaningful length of [`ConfigMessage::dir`], in UTF-16 code units.
    ///
    /// **Not** an allocation size — the same rule as every other length in this
    /// module. Zero means "no installation directory", which disarms the write
    /// gate whatever `flags` says: a gate with no directory to compare against
    /// has nothing to protect and must not guess.
    pub dir_units: u32,
    /// The installation directory, as UTF-16 code units with no terminating
    /// NUL, in DOS form (`C:\WenleAV`).
    ///
    /// Sent rather than derived, because the driver has no way to ask where it
    /// was installed and the answer is not derivable from where the `.sys`
    /// lives — a build tree and an installed product put the driver in the same
    /// place and the product's files in two different ones.
    pub dir: [u16; MAX_PATH_UNITS],
}

impl ConfigMessage {
    /// 24 + 4 + 4 = 32, then [`MAX_PATH_BYTES`]. 32 + 2048 = 2080, a multiple
    /// of 8, so there is no trailing padding.
    pub const SIZE: usize = 32 + MAX_PATH_BYTES;

    /// Offset of [`ConfigMessage::dir`]. Named because the driver reads the
    /// field through the port's `InputBuffer` pointer, and a number written at
    /// both ends is a number that can disagree.
    pub const DIR_OFFSET: usize = 32;

    /// A configuration that arms nothing.
    pub const fn new(flags: u32) -> Self {
        Self {
            prefix: MessagePrefix::new(MessageKind::Config, 0),
            flags,
            dir_units: 0,
            dir: [0; MAX_PATH_UNITS],
        }
    }

    /// Whether [`CONFIG_PROTECT_HANDLES`] is asked for.
    pub const fn protect_handles(&self) -> bool {
        self.flags & CONFIG_PROTECT_HANDLES != 0
    }

    /// Whether [`CONFIG_GATE_WRITES`] is asked for.
    ///
    /// False when no directory was sent, whatever the bit says — see
    /// [`ConfigMessage::dir_units`].
    pub const fn gate_writes(&self) -> bool {
        self.flags & CONFIG_GATE_WRITES != 0 && self.dir_units != 0
    }

    /// The meaningful part of the directory, clamped by the array's own length
    /// so that no value of `dir_units` can produce an out-of-bounds slice.
    pub fn dir(&self) -> &[u16] {
        let units = (self.dir_units as usize).min(MAX_PATH_UNITS);
        &self.dir[..units]
    }

    /// Set the directory, or fail if it does not fit.
    ///
    /// Refusing rather than truncating, for the reason [`MAX_PATH_UNITS`]
    /// gives: a truncated directory is a *different* directory, and a write
    /// gate armed with one would protect a tree that is not the product's.
    pub fn set_dir(&mut self, path: &[u16]) -> Result<(), PathTooLong> {
        if path.len() > MAX_PATH_UNITS {
            return Err(PathTooLong {
                needed: path.len(),
                capacity: MAX_PATH_UNITS,
            });
        }
        self.dir[..path.len()].copy_from_slice(path);
        self.dir_units = path.len() as u32;
        Ok(())
    }

    /// Arm the write gate over `path`, or fail if the path does not fit.
    ///
    /// # Why this is one call and not `set_dir` plus an OR
    ///
    /// [`ConfigMessage::gate_writes`] is the bit **and** a non-zero
    /// [`ConfigMessage::dir_units`], so the two halves have to be set together
    /// or the gate does nothing. Two calls at the one call site is two places to
    /// get it wrong, and the way it goes wrong is silent: a directory with no
    /// bit is a gate that refuses nothing, and a bit with no directory is the
    /// same, while the caller that set only the bit would report the gate as
    /// armed. One function that does both, failing as a unit, is the same
    /// discipline `set_dir`'s refusal-not-truncate rule comes from.
    ///
    /// On `Err` nothing is changed: `set_dir` returns before the bit is set, so
    /// a caller that gets an error holds a message that asks for no gate rather
    /// than one that asks for a gate over a truncated path.
    pub fn arm_gate(&mut self, path: &[u16]) -> Result<(), PathTooLong> {
        self.set_dir(path)?;
        self.flags |= CONFIG_GATE_WRITES;
        Ok(())
    }
}

impl Default for ConfigMessage {
    fn default() -> Self {
        // Nothing armed. A configuration structure that was never filled in
        // must not arm anything, which is the same direction as
        // `DecisionReplyMessage`'s default allow.
        Self::new(0)
    }
}

impl fmt::Debug for ConfigMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigMessage")
            .field("prefix", &self.prefix)
            .field("flags", &format_args!("{:#06X}", self.flags))
            .field("dir_units", &self.dir_units)
            .field("dir", &crate::path::display_u16(self.dir()))
            .finish()
    }
}

impl fmt::Debug for SetModeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetModeRequest")
            .field("mode", &crate::event::EnforcementMode::from_wire(self.mode))
            .field("flags", &format_args!("{:#06X}", self.flags))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

/// The input to
/// [`IOCTL_SET_EXCLUSIONS`](crate::ioctl::IOCTL_SET_EXCLUSIONS).
///
/// Replaces the table wholesale rather than adding and removing entries. An
/// incremental protocol needs ids for entries so that a later call can name the
/// one it wants removed, and those ids are more state to get wrong than the
/// whole table is to resend. The table is at most
/// [`MAX_EXCLUSIONS`] × [`MAX_EXCLUSION_UNITS`] units.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExclusionBuffer {
    /// [`crate::ioctl::PROTOCOL_VERSION`]. Checked so that a service built
    /// against a differently-shaped table is rejected rather than
    /// misinterpreted.
    pub version: u32,
    /// How many rows of `entries` are meaningful. Clamped by the driver to
    /// [`MAX_EXCLUSIONS`]; **never** used as an allocation size.
    pub count: u32,
    /// Meaningful length of each corresponding row, in UTF-16 units.
    ///
    /// A per-row length rather than a NUL terminator, because a path
    /// legitimately may not contain a NUL and a table whose entries were
    /// NUL-terminated could not represent one that did.
    pub units: [u16; MAX_EXCLUSIONS],
    /// Fixed-size rows. Only [`ExclusionBuffer::units`] of each is meaningful.
    pub entries: [[u16; MAX_EXCLUSION_UNITS]; MAX_EXCLUSIONS],
}

impl ExclusionBuffer {
    /// 8 for the two `u32`s, `MAX_EXCLUSIONS * 2` for `units`, and
    /// `MAX_EXCLUSIONS * MAX_EXCLUSION_UNITS * 2` for the rows.
    pub const SIZE: usize = 8 + MAX_EXCLUSIONS * 2 + MAX_EXCLUSIONS * MAX_EXCLUSION_UNITS * 2;

    /// The row at `index`, clamped to the meaningful length.
    ///
    /// `None` past [`ExclusionBuffer::count`] or past [`MAX_EXCLUSIONS`], so
    /// an out-of-range index cannot read a row the sender did not fill in.
    pub fn entry(&self, index: usize) -> Option<&[u16]> {
        let count = (self.count as usize).min(MAX_EXCLUSIONS);
        if index >= count {
            return None;
        }
        let units = (self.units[index] as usize).min(MAX_EXCLUSION_UNITS);
        Some(&self.entries[index][..units])
    }

    /// Every meaningful row, in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u16]> {
        let count = (self.count as usize).min(MAX_EXCLUSIONS);
        (0..count).map(move |i| {
            let units = (self.units[i] as usize).min(MAX_EXCLUSION_UNITS);
            &self.entries[i][..units]
        })
    }
}

impl Default for ExclusionBuffer {
    fn default() -> Self {
        Self {
            version: 0,
            count: 0,
            units: [0; MAX_EXCLUSIONS],
            entries: [[0; MAX_EXCLUSION_UNITS]; MAX_EXCLUSIONS],
        }
    }
}

impl fmt::Debug for ExclusionBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Written out rather than assembled from `debug_struct`/`debug_list`: a
        // `DebugList` borrows the formatter and cannot be nested as a field.
        write!(
            f,
            "ExclusionBuffer {{ version: {:#010X}, count: {}, entries: [",
            self.version, self.count
        )?;
        for (index, entry) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", crate::path::display_u16(entry))?;
        }
        f.write_str("] }")
    }
}

/// The output of
/// [`IOCTL_READ_EVENTS`](crate::ioctl::IOCTL_READ_EVENTS).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventBatch {
    /// How many of [`EventBatch::events`] are meaningful, at most
    /// [`MAX_EVENT_BATCH`].
    pub count: u32,
    /// Implicit padding: offset 4, length 4, because [`EventMessage`] is
    /// 8-aligned.
    pub _pad0: u32,
    /// The events, oldest first. A gap in
    /// [`EventMessage::sequence`] between two calls means the driver dropped
    /// events; see [`DriverStatus::events_dropped`].
    pub events: [EventMessage; MAX_EVENT_BATCH],
}

impl EventBatch {
    /// 8 + `MAX_EVENT_BATCH * EventMessage::SIZE`.
    pub const SIZE: usize = 8 + MAX_EVENT_BATCH * EventMessage::SIZE;

    /// The meaningful events.
    pub fn events(&self) -> &[EventMessage] {
        let count = (self.count as usize).min(MAX_EVENT_BATCH);
        &self.events[..count]
    }
}

impl Default for EventBatch {
    fn default() -> Self {
        Self {
            count: 0,
            _pad0: 0,
            events: [EventMessage::default(); MAX_EVENT_BATCH],
        }
    }
}

impl fmt::Debug for EventBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBatch")
            .field("count", &self.count)
            .field("events", &self.events())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    /// Every size, as a literal. A field inserted anywhere in any of these
    /// structures changes at least one number here, and the failure names the
    /// structure rather than showing up as a protocol mismatch on a machine
    /// with a driver loaded.
    #[test]
    fn structure_sizes_are_pinned() {
        assert_eq!(size_of::<PortMessageHeader>(), 16);
        assert_eq!(size_of::<PortReplyHeader>(), 16);
        assert_eq!(size_of::<MessagePrefix>(), 24);
        assert_eq!(size_of::<DecisionRequestMessage>(), 2104);
        assert_eq!(size_of::<DecisionReplyMessage>(), 48);
        assert_eq!(size_of::<EventMessage>(), 2120);
        assert_eq!(size_of::<StatusMessage>(), 80);
        assert_eq!(size_of::<DriverStatus>(), 56);
        assert_eq!(size_of::<DriverStats>(), 64);
        assert_eq!(size_of::<SetModeRequest>(), 16);
        assert_eq!(size_of::<ConfigMessage>(), 2080);
        assert_eq!(size_of::<EventBatch>(), 16_968);

        // The associated constants must agree with `size_of`, or a driver using
        // them for its `FltSendMessage` lengths is sending a wrong number.
        assert_eq!(size_of::<PortMessageHeader>(), PortMessageHeader::SIZE);
        assert_eq!(size_of::<PortReplyHeader>(), PortReplyHeader::SIZE);
        assert_eq!(size_of::<MessagePrefix>(), MessagePrefix::SIZE);
        assert_eq!(
            size_of::<DecisionRequestMessage>(),
            DecisionRequestMessage::SIZE
        );
        assert_eq!(
            size_of::<DecisionReplyMessage>(),
            DecisionReplyMessage::SIZE
        );
        assert_eq!(size_of::<EventMessage>(), EventMessage::SIZE);
        assert_eq!(size_of::<StatusMessage>(), StatusMessage::SIZE);
        assert_eq!(size_of::<DriverStatus>(), DriverStatus::SIZE);
        assert_eq!(size_of::<DriverStats>(), DriverStats::SIZE);
        assert_eq!(size_of::<SetModeRequest>(), SetModeRequest::SIZE);
        assert_eq!(size_of::<ConfigMessage>(), ConfigMessage::SIZE);
        assert_eq!(size_of::<EventBatch>(), EventBatch::SIZE);
    }

    /// `ExclusionBuffer`'s size is written as an expression, so this test
    /// states the arithmetic independently and checks the compiler agrees.
    ///
    /// 8 + 64 * 2 + 64 * 260 * 2 = 8 + 128 + 33_280 = 33_416.
    #[test]
    fn exclusion_buffer_size_is_pinned() {
        assert_eq!(MAX_EXCLUSIONS, 64);
        assert_eq!(MAX_EXCLUSION_UNITS, 260);
        assert_eq!(size_of::<ExclusionBuffer>(), 33_416);
        assert_eq!(size_of::<ExclusionBuffer>(), ExclusionBuffer::SIZE);
    }

    /// Alignment must never exceed 8, so that a 32-bit build would produce the
    /// same layout. See the module documentation.
    #[test]
    fn no_structure_is_over_aligned() {
        assert_eq!(align_of::<PortMessageHeader>(), 8);
        assert_eq!(align_of::<PortReplyHeader>(), 8);
        assert_eq!(align_of::<MessagePrefix>(), 8);
        assert_eq!(align_of::<DecisionRequestMessage>(), 8);
        assert_eq!(align_of::<DecisionReplyMessage>(), 8);
        assert_eq!(align_of::<EventMessage>(), 8);
        assert_eq!(align_of::<StatusMessage>(), 8);
        assert_eq!(align_of::<DriverStatus>(), 8);
        assert_eq!(align_of::<DriverStats>(), 8);
        assert_eq!(align_of::<SetModeRequest>(), 4);
        assert_eq!(align_of::<ConfigMessage>(), 8);
        assert_eq!(align_of::<ExclusionBuffer>(), 4);
        assert_eq!(align_of::<EventBatch>(), 8);
    }

    /// Every field offset, so the implicit padding the module documents as
    /// implicit is still *checked*.
    #[test]
    fn field_offsets_are_pinned() {
        assert_eq!(offset_of!(PortMessageHeader, reply_length), 0);
        assert_eq!(offset_of!(PortMessageHeader, _pad0), 4);
        assert_eq!(offset_of!(PortMessageHeader, message_id), 8);

        assert_eq!(offset_of!(PortReplyHeader, status), 0);
        assert_eq!(offset_of!(PortReplyHeader, _pad0), 4);
        assert_eq!(offset_of!(PortReplyHeader, message_id), 8);

        assert_eq!(offset_of!(MessagePrefix, header), 0);
        assert_eq!(offset_of!(MessagePrefix, kind), 16);
        assert_eq!(offset_of!(MessagePrefix, version), 20);

        assert_eq!(offset_of!(DecisionRequestMessage, prefix), 0);
        assert_eq!(offset_of!(DecisionRequestMessage, request_id), 24);
        assert_eq!(offset_of!(DecisionRequestMessage, subject), 32);
        assert_eq!(offset_of!(DecisionRequestMessage, flags), 36);
        assert_eq!(offset_of!(DecisionRequestMessage, timeout_ms), 40);
        assert_eq!(offset_of!(DecisionRequestMessage, path_units), 44);
        assert_eq!(offset_of!(DecisionRequestMessage, process_id), 48);
        assert_eq!(offset_of!(DecisionRequestMessage, thread_id), 52);
        assert_eq!(offset_of!(DecisionRequestMessage, path), 56);
        assert_eq!(
            offset_of!(DecisionRequestMessage, path),
            DecisionRequestMessage::PATH_OFFSET
        );

        assert_eq!(offset_of!(DecisionReplyMessage, reply), 0);
        assert_eq!(offset_of!(DecisionReplyMessage, request_id), 16);
        assert_eq!(offset_of!(DecisionReplyMessage, decision), 24);
        assert_eq!(offset_of!(DecisionReplyMessage, flags), 28);

        assert_eq!(offset_of!(EventMessage, prefix), 0);
        assert_eq!(offset_of!(EventMessage, sequence), 24);
        assert_eq!(offset_of!(EventMessage, timestamp_100ns), 32);
        assert_eq!(offset_of!(EventMessage, subject), 40);
        assert_eq!(offset_of!(EventMessage, action), 44);
        assert_eq!(offset_of!(EventMessage, severity), 48);
        assert_eq!(offset_of!(EventMessage, verdict), 52);
        assert_eq!(offset_of!(EventMessage, process_id), 56);
        assert_eq!(offset_of!(EventMessage, thread_id), 60);
        assert_eq!(offset_of!(EventMessage, path_units), 64);
        assert_eq!(offset_of!(EventMessage, detail), 68);
        assert_eq!(offset_of!(EventMessage, path), 72);
        assert_eq!(offset_of!(EventMessage, path), EventMessage::PATH_OFFSET);

        assert_eq!(offset_of!(DecisionReplyMessage, reply), 0);
        assert_eq!(offset_of!(DecisionReplyMessage, request_id), 16);
        assert_eq!(offset_of!(DecisionReplyMessage, decision), 24);
        assert_eq!(offset_of!(DecisionReplyMessage, flags), 28);
        assert_eq!(offset_of!(DecisionReplyMessage, subject), 32);
        assert_eq!(offset_of!(DecisionReplyMessage, _pad0), 36);
        // 8-aligned rather than at 40 by luck: the `_pad0` above is what puts
        // it here, and a reply whose tag was read at the wrong offset would
        // either match everything or nothing.
        assert_eq!(offset_of!(DecisionReplyMessage, path_tag), 40);

        assert_eq!(offset_of!(StatusMessage, prefix), 0);
        assert_eq!(offset_of!(StatusMessage, status), 24);
        assert_eq!(offset_of!(DriverStatus, protocol_version), 0);
        assert_eq!(offset_of!(DriverStatus, state), 4);
        assert_eq!(offset_of!(DriverStatus, mode), 8);
        assert_eq!(offset_of!(DriverStatus, queued_events), 12);
        assert_eq!(offset_of!(DriverStatus, uptime_ms), 16);
        assert_eq!(offset_of!(DriverStatus, decisions_asked), 24);
        assert_eq!(offset_of!(DriverStatus, decisions_answered), 32);
        assert_eq!(offset_of!(DriverStatus, decisions_unanswered), 40);
        assert_eq!(offset_of!(DriverStatus, events_dropped), 48);

        assert_eq!(offset_of!(DriverStats, blocked_executions), 0);
        assert_eq!(offset_of!(DriverStats, blocked_writes), 8);
        assert_eq!(offset_of!(DriverStats, images_blocked), 16);
        assert_eq!(offset_of!(DriverStats, allowed), 24);
        assert_eq!(offset_of!(DriverStats, timed_out), 32);
        assert_eq!(offset_of!(DriverStats, excluded), 40);
        assert_eq!(offset_of!(DriverStats, unresolved_volume), 48);
        assert_eq!(offset_of!(DriverStats, oversize_path), 56);

        assert_eq!(offset_of!(SetModeRequest, mode), 0);
        assert_eq!(offset_of!(SetModeRequest, flags), 4);
        assert_eq!(offset_of!(SetModeRequest, timeout_ms), 8);
        assert_eq!(offset_of!(SetModeRequest, _pad0), 12);

        assert_eq!(offset_of!(ConfigMessage, prefix), 0);
        assert_eq!(offset_of!(ConfigMessage, flags), 24);
        assert_eq!(offset_of!(ConfigMessage, dir_units), 28);
        assert_eq!(offset_of!(ConfigMessage, dir), 32);
        assert_eq!(offset_of!(ConfigMessage, dir), ConfigMessage::DIR_OFFSET);

        assert_eq!(offset_of!(ExclusionBuffer, version), 0);
        assert_eq!(offset_of!(ExclusionBuffer, count), 4);
        assert_eq!(offset_of!(ExclusionBuffer, units), 8);
        // 8 + 2 * MAX_EXCLUSIONS = 8 + 128 = 136. Written as the arithmetic so
        // that changing MAX_EXCLUSIONS fails here with the new number visible
        // rather than as a bare mismatch.
        assert_eq!(offset_of!(ExclusionBuffer, entries), 8 + 2 * MAX_EXCLUSIONS);
        assert_eq!(offset_of!(ExclusionBuffer, entries), 136);

        assert_eq!(offset_of!(EventBatch, count), 0);
        assert_eq!(offset_of!(EventBatch, _pad0), 4);
        assert_eq!(offset_of!(EventBatch, events), 8);
    }

    /// A `_pad` field must really be padding, and the way to show that is that
    /// the structure's bytes at that range are never read by anything. The
    /// offsets test above already proves where each *field* lives; what this
    /// adds is that the padding is reachable through the named field rather
    /// than being tail padding the compiler invented, which is the difference
    /// between a struct whose layout is written down and one that merely
    /// happens to work today.
    ///
    /// The check is arithmetic rather than a byte dump: the named `_pad` must
    /// start where the previous field ends, and the next field must start where
    /// the `_pad` ends. If the compiler inserted padding of its own, one of
    /// those two equations would fail.
    #[test]
    fn named_padding_fields_are_contiguous_with_their_neighbours() {
        assert_eq!(
            offset_of!(PortMessageHeader, _pad0),
            offset_of!(PortMessageHeader, reply_length) + size_of::<u32>()
        );
        assert_eq!(
            offset_of!(PortMessageHeader, message_id),
            offset_of!(PortMessageHeader, _pad0) + size_of::<u32>()
        );
        assert_eq!(
            offset_of!(PortReplyHeader, message_id),
            offset_of!(PortReplyHeader, _pad0) + size_of::<u32>()
        );
        assert_eq!(
            offset_of!(SetModeRequest, _pad0) + size_of::<u32>(),
            size_of::<SetModeRequest>()
        );
        assert_eq!(
            offset_of!(EventBatch, events),
            offset_of!(EventBatch, _pad0) + size_of::<u32>()
        );
    }

    /// Nothing between two named fields may be unaccounted for: for every
    /// structure here, each field offset must equal the previous field's offset
    /// plus its size, or the gap must be a named `_pad`. `MessagePrefix` has no
    /// `_pad` at all, so it is the structure where a compiler-inserted gap
    /// would be most likely and least visible.
    #[test]
    fn message_prefix_has_no_hidden_gap() {
        assert_eq!(
            offset_of!(MessagePrefix, kind),
            offset_of!(MessagePrefix, header) + PortMessageHeader::SIZE,
            "a gap appeared between the port header and the kind"
        );
        assert_eq!(
            offset_of!(MessagePrefix, version),
            offset_of!(MessagePrefix, kind) + size_of::<u32>()
        );
        assert_eq!(
            offset_of!(MessagePrefix, version) + size_of::<u32>(),
            MessagePrefix::SIZE,
            "MessagePrefix gained tail padding"
        );
    }

    /// `MessageKind::from_wire` must reject the reserved value and every value
    /// above the highest known one — including values a future version might
    /// define, which is the case that matters.
    #[test]
    fn unknown_message_kinds_are_rejected_not_guessed() {
        assert_eq!(MessageKind::from_wire(KIND_RESERVED), None);
        // One past the highest kind this build defines. This said `4` until
        // `KIND_CONFIG` took that value on 2026-10-09, and it is written as an
        // expression now so that the next kind added moves it rather than
        // leaving a test that passes for the wrong reason.
        assert_eq!(MessageKind::from_wire(KIND_CONFIG + 1), None);
        assert_eq!(MessageKind::from_wire(u32::MAX), None);
        assert!(!MessageKind::is_known(KIND_RESERVED));
        assert!(!MessageKind::is_known(KIND_CONFIG + 1));
        assert!(!MessageKind::is_known(0xFFFF_FFFF));

        assert_eq!(
            MessageKind::from_wire(KIND_DECISION_REQUEST),
            Some(MessageKind::DecisionRequest)
        );
        assert_eq!(MessageKind::from_wire(KIND_EVENT), Some(MessageKind::Event));
        assert_eq!(
            MessageKind::from_wire(KIND_STATUS),
            Some(MessageKind::Status)
        );
        assert_eq!(
            MessageKind::from_wire(KIND_CONFIG),
            Some(MessageKind::Config)
        );
    }

    /// Every kind round-trips.
    #[test]
    fn message_kinds_round_trip() {
        for kind in [
            MessageKind::DecisionRequest,
            MessageKind::Event,
            MessageKind::Status,
            MessageKind::Config,
        ] {
            assert_eq!(MessageKind::from_wire(kind.as_wire()), Some(kind));
        }
    }

    /// The configuration message's two behaviours that are decisions rather
    /// than layout: a gate with no directory is not armed, and a directory that
    /// does not fit is refused rather than truncated.
    #[test]
    fn a_write_gate_with_no_directory_is_not_armed() {
        let mut config = ConfigMessage::new(CONFIG_GATE_WRITES | CONFIG_PROTECT_HANDLES);
        assert!(config.protect_handles());
        assert!(
            !config.gate_writes(),
            "a gate with no directory has nothing to compare a path against"
        );
        assert_eq!(config.dir().len(), 0);

        config
            .set_dir(&r"C:\WenleAV".encode_utf16().collect::<Vec<_>>())
            .expect("fits");
        assert!(config.gate_writes());

        // And the flags really are independent, which is why they are bits.
        let handles_only = ConfigMessage::new(CONFIG_PROTECT_HANDLES);
        assert!(handles_only.protect_handles());
        assert!(!handles_only.gate_writes());

        // A structure that was never filled in arms nothing.
        let default = ConfigMessage::default();
        assert!(!default.protect_handles());
        assert!(!default.gate_writes());
        assert_eq!(default.prefix.kind, KIND_CONFIG);
        assert_eq!(default.prefix.header.reply_length, 0);
        assert!(default.prefix.is_readable());

        let over = vec![0x41u16; MAX_PATH_UNITS + 1];
        assert!(config.set_dir(&over).is_err());
        // The refused call must not have written anything.
        assert_eq!(config.dir_units as usize, r"C:\WenleAV".len());
    }

    /// Arming the gate sets the directory and the bit together, and a refusal
    /// leaves the message asking for no gate at all.
    ///
    /// This is the pair [`ConfigMessage::arm_gate`] exists to make indivisible.
    /// The failure it prevents is silent in both directions: a directory with no
    /// bit and a bit with no directory both refuse nothing, and a caller that
    /// set one without the other would believe it had armed a defence.
    #[test]
    fn arming_the_write_gate_sets_both_halves_or_neither() {
        let mut config = ConfigMessage::new(CONFIG_PROTECT_HANDLES);
        assert!(!config.gate_writes(), "nothing armed yet");

        let directory: Vec<u16> = r"C:\Program Files\WenleAV".encode_utf16().collect();
        config.arm_gate(&directory).expect("fits");
        assert!(config.protect_handles(), "the other flag survives");
        assert!(
            config.gate_writes(),
            "arming the gate must set the bit as well as the directory"
        );
        assert_eq!(config.dir(), directory.as_slice());

        // A directory too long for the buffer: the call fails, and the message
        // is left exactly as it was — still asking for no gate, and still
        // holding the directory from before.
        let over = vec![0x41u16; MAX_PATH_UNITS + 1];
        assert!(config.arm_gate(&over).is_err());
        assert_eq!(
            config.dir(),
            directory.as_slice(),
            "a refused arm wrote part of the path it refused"
        );
        assert!(config.gate_writes(), "and did not disarm the gate either");
    }

    /// A hostile `dir_units` cannot produce a slice longer than the buffer.
    #[test]
    fn a_hostile_directory_length_cannot_escape_the_buffer() {
        let mut config = ConfigMessage::new(CONFIG_GATE_WRITES);
        config.set_dir(&[0x41; 4]).expect("fits");
        assert_eq!(config.dir().len(), 4);
        config.dir_units = u32::MAX;
        assert_eq!(config.dir().len(), MAX_PATH_UNITS);
    }

    /// A zeroed buffer must not read as a valid request. This is the reason
    /// `KIND_RESERVED` exists, and it matters because kernel pool is not
    /// guaranteed to be zeroed and a service bug can produce a short write.
    #[test]
    fn a_zeroed_message_is_not_readable() {
        let prefix = MessagePrefix::default();
        assert_eq!(prefix.kind, KIND_RESERVED);
        assert_eq!(prefix.version, 0);
        assert!(!prefix.is_readable());
        assert!(!MessageKind::is_known(prefix.kind));
    }

    /// A message whose kind is understood but whose version is not must be
    /// rejected. The two checks are independent, and this test exists so that
    /// deleting either one fails something.
    #[test]
    fn a_known_kind_with_an_unknown_version_is_not_readable() {
        let mut prefix = MessagePrefix::new(MessageKind::DecisionRequest, 0);
        assert!(prefix.is_readable());
        prefix.version = 0x0002_0000;
        assert!(
            !prefix.is_readable(),
            "a future major version must be refused"
        );
        prefix.version = crate::ioctl::PROTOCOL_VERSION + 1;
        assert!(
            !prefix.is_readable(),
            "even a one-bit difference must be refused"
        );
    }

    /// Compatibility is exact equality today, and the test says so in a way
    /// that will fail loudly when someone relaxes it without writing the
    /// structure-level reasoning the doc comment demands.
    #[test]
    fn compatibility_is_exact() {
        assert!(is_compatible(crate::ioctl::PROTOCOL_VERSION));
        assert!(!is_compatible(0));
        assert!(!is_compatible(crate::ioctl::PROTOCOL_VERSION + 1));
        // Same major, different minor — the case a compatibility rule would
        // most plausibly allow, and the case that is refused.
        assert!(!is_compatible(crate::ioctl::PROTOCOL_VERSION | 1));
    }

    /// The path accessor is clamped by the array, so a hostile `path_units`
    /// cannot produce a slice longer than the buffer. This is the concrete form
    /// of the module's rule about lengths, and the reason the crate has no
    /// allocator.
    #[test]
    fn a_hostile_path_length_cannot_escape_the_buffer() {
        let mut request = DecisionRequestMessage::new(1, crate::event::SubjectKind::File);
        request.set_path(&[0x41; 4]).expect("fits");
        assert_eq!(request.path().len(), 4);

        // Simulate a peer that lied about the length.
        request.path_units = u32::MAX;
        assert_eq!(request.path().len(), MAX_PATH_UNITS);

        let mut event = EventMessage::new(
            1,
            0,
            crate::event::SubjectKind::File,
            crate::event::EventAction::FileWritten,
        );
        event.path_units = u32::MAX;
        assert_eq!(event.path().len(), MAX_PATH_UNITS);
    }

    /// A path that does not fit is refused, not truncated. Truncation is the
    /// bug this prevents: half a path is a path that can match the wrong
    /// exclusion.
    #[test]
    fn an_oversize_path_is_refused_rather_than_truncated() {
        let mut request = DecisionRequestMessage::new(1, crate::event::SubjectKind::File);
        let exact = vec![0x41u16; MAX_PATH_UNITS];
        assert!(request.set_path(&exact).is_ok());
        assert_eq!(request.path().len(), MAX_PATH_UNITS);
        // 1024 filled with 0x41, and `set_path` wrote all of them.
        assert!(request.path().iter().all(|&c| c == 0x41));

        let over = vec![0x42u16; MAX_PATH_UNITS + 1];
        let err = request.set_path(&over).expect_err("must not fit");
        assert_eq!(
            err,
            PathTooLong {
                needed: MAX_PATH_UNITS + 1,
                capacity: MAX_PATH_UNITS
            }
        );
        // The failed call must not have written anything: a truncated path left
        // in the buffer plus a full-length `path_units` is exactly the mismatch
        // this whole design avoids.
        assert_eq!(request.path_units, MAX_PATH_UNITS as u32);
        assert!(request.path().iter().all(|&c| c == 0x41));
    }

    /// The reply header's `message_id` and the request's `request_id` are
    /// separate fields and the constructors must not conflate them.
    #[test]
    fn the_port_message_id_and_the_product_request_id_are_separate_fields() {
        let request = DecisionRequestMessage::new(0xDEAD_BEEF, crate::event::SubjectKind::Process);
        // The port id is the filter manager's to fill in, and it starts zero.
        assert_eq!(request.prefix.header.message_id, 0);
        assert_eq!(request.request_id, 0xDEAD_BEEF);

        let reply = DecisionReplyMessage::new(0xDEAD_BEEF, crate::decision::Decision::Block);
        assert_eq!(reply.reply.message_id, 0);
        assert_eq!(reply.request_id, 0xDEAD_BEEF);
    }

    /// The echo fields on a reply are what make
    /// [`crate::decision::ResolveOutcome::Mismatch`] reachable from a real
    /// message: the pending table checks the subject and the path tag, so both
    /// have to survive the trip. This pins that `answering` fills them from the
    /// request, and that a reply built from a *different* request is
    /// distinguishable — which is the crossed-answers case the fields exist to
    /// catch.
    #[test]
    fn an_answering_reply_carries_what_the_pending_table_checks() {
        use crate::decision::Decision;

        // `Vec` is available here because this module only compiles in a test
        // build, where the crate is not `no_std`. Nothing in the library
        // proper allocates.
        let utf16 = |s: &str| -> Vec<u16> { s.encode_utf16().collect() };

        let mut cmd = DecisionRequestMessage::new(1, crate::event::SubjectKind::File);
        cmd.set_path(&utf16(r"C:\Windows\System32\cmd.exe"))
            .expect("fits");

        let mut other = DecisionRequestMessage::new(2, crate::event::SubjectKind::Process);
        other
            .set_path(&utf16(r"C:\Temp\invoice.doc"))
            .expect("fits");

        let honest = DecisionReplyMessage::answering(&cmd, Decision::Block);
        assert_eq!(honest.request_id, cmd.request_id);
        assert_eq!(honest.subject, cmd.subject);
        assert_eq!(honest.path_tag, cmd.path_tag());
        assert_eq!(honest.decision, Decision::Block.as_wire());

        // Built the same way, for a different file and a different subject.
        let crossed = DecisionReplyMessage::answering(&other, Decision::Block);
        assert_ne!(
            crossed.path_tag,
            cmd.path_tag(),
            "the tag is what tells two files apart"
        );
        assert_ne!(crossed.subject, cmd.subject);
        // Tag and path length agree, which is the property the table relies on:
        // a tag computed over a different number of units is what a truncated
        // path would look like.
        assert_eq!(cmd.path_tag(), crate::path::path_tag(cmd.path()));
    }

    /// A request asks for a reply the size of `DecisionReplyMessage`; an event
    /// asks for none. `ReplyLength` is the *total* including the reply header,
    /// which is why the value is the whole structure's size and not its
    /// payload.
    #[test]
    fn reply_lengths_match_what_the_sender_will_accept() {
        let request = DecisionRequestMessage::new(1, crate::event::SubjectKind::File);
        assert_eq!(
            request.prefix.header.reply_length as usize,
            DecisionReplyMessage::SIZE
        );
        // The payload after the reply header is `request_id` (8), `decision`
        // (4), `flags` (4), `subject` (4), `_pad0` (4) and `path_tag` (8).
        assert_eq!(request.prefix.header.reply_length as usize, 16 + 32);

        let event = EventMessage::new(
            1,
            0,
            crate::event::SubjectKind::File,
            crate::event::EventAction::Heartbeat,
        );
        assert_eq!(event.prefix.header.reply_length, 0);
        let status = StatusMessage::new(DriverStatus::default());
        assert_eq!(status.prefix.header.reply_length, 0);
    }

    /// The reply that reaches the driver is the payload, not the structure:
    /// the filter manager owns the header and strips it before the copy, so
    /// `FltSendMessage`'s reply buffer must begin at [`DecisionReplyMessage::payload_ptr`]
    /// and its capacity is [`DecisionReplyMessage::PAYLOAD_SIZE`].
    #[test]
    fn the_reply_payload_begins_after_the_filter_managers_header() {
        let mut reply = DecisionReplyMessage::new(7, crate::decision::Decision::Block);
        let base = core::ptr::addr_of!(reply) as usize;
        let payload = reply.payload_ptr() as usize;

        // The two ways of saying where the payload starts have to agree: the
        // constant is the header's size, and the field the driver reads first
        // is `request_id`.
        assert_eq!(payload - base, PortReplyHeader::SIZE);
        assert_eq!(
            offset_of!(DecisionReplyMessage, request_id),
            DecisionReplyMessage::PAYLOAD_OFFSET
        );

        // 8 + 4 + 4 + 4 + 4 + 8, and the two halves account for the whole.
        assert_eq!(DecisionReplyMessage::PAYLOAD_SIZE, 32);
        assert_eq!(
            DecisionReplyMessage::PAYLOAD_OFFSET + DecisionReplyMessage::PAYLOAD_SIZE,
            DecisionReplyMessage::SIZE
        );
    }

    /// `ExclusionBuffer::entry` must refuse an index the sender did not fill
    /// in, so a hostile `count` cannot make the driver read a row of zeros as
    /// an exclusion entry.
    #[test]
    fn exclusion_buffer_indexing_is_bounded_by_the_senders_count() {
        let mut buffer = ExclusionBuffer::default();
        assert_eq!(buffer.count, 0);
        assert!(buffer.entry(0).is_none(), "count 0 means no rows");
        assert_eq!(buffer.iter().count(), 0);

        buffer.count = 2;
        buffer.units[0] = 3;
        buffer.entries[0][..3].copy_from_slice(&[0x43, 0x3A, 0x5C]); // "C:\"
        buffer.units[1] = 1;
        buffer.entries[1][0] = 0x44; // "D"

        assert_eq!(buffer.entry(0), Some(&[0x43u16, 0x3A, 0x5C][..]));
        assert_eq!(buffer.entry(1), Some(&[0x44u16][..]));
        assert!(buffer.entry(2).is_none(), "past count");
        assert_eq!(buffer.iter().count(), 2);

        // A count past the array is clamped, not trusted.
        buffer.count = u32::MAX;
        assert_eq!(buffer.iter().count(), MAX_EXCLUSIONS);
        // And a row length past the row is clamped too.
        buffer.units[0] = u16::MAX;
        assert_eq!(buffer.entry(0).map(<[u16]>::len), Some(MAX_EXCLUSION_UNITS));
    }

    /// `EventBatch::events` is clamped the same way.
    #[test]
    fn event_batch_count_is_clamped() {
        let mut batch = EventBatch::default();
        assert_eq!(batch.events().len(), 0);
        batch.count = 3;
        assert_eq!(batch.events().len(), 3);
        batch.count = u32::MAX;
        assert_eq!(batch.events().len(), MAX_EVENT_BATCH);
    }

    /// Defaults must be the safe ones. A defaulted reply allows; a defaulted
    /// message prefix is unreadable rather than a request.
    #[test]
    fn defaults_are_the_fail_safe_ones() {
        assert_eq!(
            DecisionReplyMessage::default().decision,
            crate::decision::Decision::Allow.as_wire()
        );
        assert!(!MessagePrefix::default().is_readable());
        assert_eq!(PortMessageHeader::default().reply_length, 0);
        assert_eq!(
            PortReplyHeader::default().status,
            PortReplyHeader::STATUS_SUCCESS
        );
        assert_eq!(DriverStatus::default().decisions_asked, 0);
        assert_eq!(DriverStats::default().allowed, 0);
        assert_eq!(SetModeRequest::default().timeout_ms, 0);
        assert_eq!(ExclusionBuffer::default().count, 0);
    }

    /// The `Debug` impls must not dump the whole path array. A kernel
    /// debugger's log is not the place for two kilobytes of mostly-zeroes, and
    /// a `Debug` that did would push the fields that matter off the screen. The
    /// bound is generous; what is being tested is that it is not
    /// `MAX_PATH_UNITS`.
    ///
    /// The path is rendered as text rather than as a `u16` array, which is the
    /// same reason [`crate::path::display_u16`] exists on the non-test side.
    #[test]
    fn debug_output_is_bounded_by_the_used_path_length() {
        let mut event = EventMessage::new(
            7,
            0,
            crate::event::SubjectKind::File,
            crate::event::EventAction::FileWritten,
        );
        event.set_path(&[0x41; 3]).expect("fits");
        let rendered = format!("{event:?}");
        assert!(rendered.contains("AAA"), "{rendered}");
        assert!(
            rendered.len() < 400,
            "Debug dumped the whole buffer: {} bytes",
            rendered.len()
        );

        // A full-length path must not blow it up either. The bound is derived
        // from the display cap and not from the buffer: a `\` renders escaped,
        // so the worst case is two output bytes per displayed unit, and
        // `MAX_PATH_UNITS` is four times `MAX_DISPLAY_UNITS`. The point of the
        // assertion is that the cap holds, so it is written against the cap.
        let mut request = DecisionRequestMessage::new(1, crate::event::SubjectKind::Process);
        request
            .set_path(&[0x5C; MAX_PATH_UNITS])
            .expect("exactly fits");
        let rendered = format!("{request:?}");
        let bound = 2 * crate::path::MAX_DISPLAY_UNITS + 128;
        assert!(
            rendered.len() < bound,
            "{} bytes, over the {bound} the display cap allows",
            rendered.len()
        );
        assert!(
            rendered.len() < MAX_PATH_BYTES,
            "Debug rendered more than the buffer it was given"
        );
    }
}
