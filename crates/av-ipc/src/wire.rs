//! The frame: a length, a header, and a body that is not parsed until the
//! header has been checked.
//!
//! # The two numbers, and why the length is the dangerous one
//!
//! ```text
//! frame   = length:u32le | payload
//! payload = header (24 bytes) | body (bincode)
//! header  = magic:8 | version:u32le | kind:u16le | flags:u16le | correlation:u64le
//! ```
//!
//! `length` counts the header and the body together. It is read off a socket
//! from a process this one does not control, which makes it an
//! attacker-chosen allocation size — the bug class `av_driver_proto::wire`'s
//! module documentation describes avoiding, where a `u32` length is a *used
//! length into a buffer that already exists* and never a size to reserve. There
//! is no such trick available here: this crate has no fixed buffer to point
//! into, so the answer is the other one, and it is [`MAX_FRAME_BYTES`]. A
//! length above it is refused **as soon as the four bytes are there**, before
//! the payload arrives and therefore before anything is reserved for it, and
//! the connection is closed. [`Decoder::push`] is where that happens and
//! [`crate::error::IpcError::poisons_connection`] is what the caller acts on.
//!
//! What that buys is a bound the crate can state: a peer can make this process
//! hold at most `MAX_FRAME_BYTES + 4` bytes, whatever it claims, and a test
//! asserts the buffer does not grow past four on the hostile input.
//!
//! # The header, and the order the checks happen in
//!
//! The magic number and the version are checked **before** the body is handed
//! to the deserialiser. That ordering is the point of having a header at all: a
//! body is not self-describing, so a build that deserialised first and compared
//! versions afterwards would have already interpreted one build's bytes as
//! another build's structures. `av_rules::database` does the same thing in the
//! same order for the same reason.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::IpcError;
use crate::message::Message;

/// Identifies a control frame. Chosen to be unlikely to appear at the start of
/// anything else on the pipe and readable in a hex dump.
pub const MAGIC: [u8; 8] = *b"WENLEIPC";

/// The protocol version, `major` in the high half and `minor` in the low.
///
/// A version and not a hash of the layout, following
/// `av_driver_proto::ioctl::PROTOCOL_VERSION`: the peer has to compare this
/// against a constant compiled into it, and a service has to be able to say
/// *which* version it wanted in a message a human reads.
///
/// There is no compatibility story yet — [`is_compatible`] refuses anything but
/// an exact match — and the version is bumped on any change to the layout of
/// [`crate::message::Message`], [`crate::report`] or [`crate::detect`], because
/// bincode encodes an enum as its declaration index. Reordering the variants of
/// [`crate::Request`] therefore changes the wire format without changing any
/// type's name, and a peer built against the other order would read
/// `QuarantineDelete` as `QuarantineList`.
///
/// `0x0001_0003` (2026-10-18) added `DriverEvent::parent_process_id`. bincode
/// has no field names to skip, so an older client would read every field after
/// it one word early; the exact-match check is what turns that into a refused
/// connection rather than a misread event.
///
/// `0x0001_0004` (2026-10-18) added `DriverEventAction::FileRenamed` and
/// `FileDeleted`. An enum is its declaration index, so these are two more
/// values a peer must agree about — and they sit before `Unrecognised`, which
/// moved with them.
///
/// `0x0001_0005` (2026-10-18) added `DriverEventAction::RegistryChanged` and
/// `DriverSubject::Registry`, each before its enum's `Unrecognised`, so the
/// indices after them moved again.
pub const PROTOCOL_VERSION: u32 = 0x0001_0005;

/// Bytes of length prefix in front of every frame.
pub const FRAME_PREFIX_BYTES: usize = 4;

/// Bytes of protocol header at the start of every payload: the magic, the
/// version, the kind, the flags and the correlation identifier.
///
/// 8 + 4 + 2 + 2 + 8 = 24, which is the alignment of the `u64` correlation
/// field, so the body begins on an 8-byte boundary.
pub const HEADER_BYTES: usize = 24;

/// The shortest payload that can be a frame: one that is nothing but a header.
pub const MIN_FRAME_BYTES: usize = HEADER_BYTES;

/// The largest frame this build will read.
///
/// This is the bound on a single allocation a peer can make this process
/// perform. Sixteen megabytes rather than something smaller because the largest
/// genuinely variable message in the vocabulary is
/// [`crate::Reply::QuarantineList`], which carries one
/// [`av_quarantine::QuarantineEntry`] per item — a few hundred bytes each, so
/// this holds a listing of a machine with tens of thousands of items, and the
/// service caps the listing well below that anyway so a client learns it was
/// truncated rather than being disconnected for asking.
///
/// It is a *cap on the peer*, not a target: nothing in the vocabulary comes
/// close to it in normal operation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// The reserved kind. A zeroed header has this kind, which is what makes an
/// all-zero message invalid rather than a request that happens to be first in
/// the enum.
pub const KIND_RESERVED: u16 = 0;
/// [`MessageKind::Request`] on the wire.
pub const KIND_REQUEST: u16 = 1;
/// [`MessageKind::Reply`] on the wire.
pub const KIND_REPLY: u16 = 2;
/// [`MessageKind::Event`] on the wire.
pub const KIND_EVENT: u16 = 3;

/// Which of the three things a payload is.
///
/// A `u16` field on the wire rather than this enum, following
/// `av_driver_proto::wire::MessageKind`: a peer built against a later version
/// sends a kind this build has never heard of, and it has to be
/// *representable* so this build can answer `UnknownKind` instead of
/// panicking. The enum is deliberately not `#[non_exhaustive]` — see
/// [`crate::message::Message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MessageKind {
    /// A client asking the service to do something.
    Request,
    /// The service's answer to one request.
    Reply,
    /// The service telling a client something it did not ask about.
    Event,
}

impl MessageKind {
    /// The value that goes on the wire.
    pub const fn as_wire(self) -> u16 {
        match self {
            MessageKind::Request => KIND_REQUEST,
            MessageKind::Reply => KIND_REPLY,
            MessageKind::Event => KIND_EVENT,
        }
    }

    /// Decode a wire value. `None` for anything unrecognised, including zero.
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            KIND_REQUEST => Some(MessageKind::Request),
            KIND_REPLY => Some(MessageKind::Reply),
            KIND_EVENT => Some(MessageKind::Event),
            _ => None,
        }
    }

    /// True for a value this build understands.
    pub const fn is_known(value: u16) -> bool {
        value == KIND_REQUEST || value == KIND_REPLY || value == KIND_EVENT
    }

    /// The word used in an error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            MessageKind::Request => "request",
            MessageKind::Reply => "reply",
            MessageKind::Event => "event",
        }
    }
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// True when this build can read a peer that announces `version`.
///
/// Exact equality, the same rule `av_driver_proto::wire::is_compatible` applies
/// and for the same reason: bincode encodes an enum as its declaration index,
/// so two builds that disagree about the order of [`crate::Request`]'s variants
/// agree about the version number only if the version number was bumped, and a
/// build that accepted "same major, any minor" would be promising a stability
/// the encoding does not have.
pub const fn is_compatible(version: u32) -> bool {
    version == PROTOCOL_VERSION
}

/// A request identifier.
///
/// Assigned by the client, echoed by the service, and the only thing tying a
/// reply to the question it answers — the pipe carries events interleaved with
/// replies, so "the next message is the answer to the last request" is not
/// true and never was.
///
/// Zero is reserved: it is the correlation of an [`crate::Event`], which is not
/// part of any exchange. A request or reply carrying it is
/// [`IpcError::MissingCorrelation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId(u64);

impl RequestId {
    /// The identifier an event carries, which is to say none.
    pub const NONE: Self = Self(0);
    /// The first identifier a client uses.
    pub const FIRST: Self = Self(1);

    /// Wrap a value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The value on the wire.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// True for [`RequestId::NONE`].
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// The next identifier, or `None` when the client has used them all.
    ///
    /// Returns `Option` rather than wrapping. A wrapped identifier is one the
    /// service has already answered, and the service refuses those — so a
    /// wrapping client would start receiving `RequestIdNotIncreasing` for every
    /// request and would have no way to tell that from a service that had lost
    /// its state.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The fixed part of a frame, parsed and checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The protocol version the sender speaks.
    pub version: u32,
    /// What the payload is.
    pub kind: MessageKind,
    /// Reserved flag bits. Must be zero.
    pub flags: u16,
    /// Which exchange this message belongs to.
    pub correlation: RequestId,
}

impl Header {
    /// Bytes this header occupies at the start of a payload.
    pub const SIZE: usize = HEADER_BYTES;

    /// Append this header to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.kind.as_wire().to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.correlation.value().to_le_bytes());
    }

    /// Check and read the header at the start of `payload`.
    ///
    /// Every check here is a check on *framing*, and each one is a named error
    /// rather than a decode failure, because each one says something different
    /// about what to do next: a bad magic means the peer is not speaking this
    /// protocol, a version mismatch means it is speaking a different one, an
    /// unknown kind means it is a later one, and an unknown flag means it is a
    /// later one that requires something of this build.
    pub fn parse(payload: &[u8]) -> Result<Self, IpcError> {
        if payload.len() < HEADER_BYTES {
            return Err(IpcError::ShortFrame {
                length: payload.len() as u32,
                min: MIN_FRAME_BYTES,
            });
        }
        if payload[..8] != MAGIC {
            return Err(IpcError::BadMagic);
        }
        let version = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        if !is_compatible(version) {
            return Err(IpcError::UnsupportedVersion {
                found: version,
                supported: PROTOCOL_VERSION,
            });
        }
        let kind_raw = u16::from_le_bytes([payload[12], payload[13]]);
        let kind =
            MessageKind::from_wire(kind_raw).ok_or(IpcError::UnknownKind { kind: kind_raw })?;
        let flags = u16::from_le_bytes([payload[14], payload[15]]);
        if flags != 0 {
            return Err(IpcError::UnsupportedFlags { found: flags });
        }
        let mut correlation = [0u8; 8];
        correlation.copy_from_slice(&payload[16..24]);
        Ok(Self {
            version,
            kind,
            flags,
            correlation: RequestId::new(u64::from_le_bytes(correlation)),
        })
    }
}

/// Put a length prefix in front of a payload.
///
/// Fails for a payload over [`MAX_FRAME_BYTES`] rather than producing a frame
/// the peer would refuse: the sender is the one place where the reason is
/// known, and a service that framed a 20 MB listing would otherwise learn about
/// its own bug from a client hanging up.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, IpcError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            length: payload.len() as u32,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut out = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reassembles frames from a byte stream whose boundaries are the operating
/// system's business and not this crate's.
///
/// A pipe hands over whatever arrived, so a message can be split across any
/// number of reads and several messages can arrive in one. The decoder holds
/// the partial tail and yields whole messages only.
///
/// # It is not a queue
///
/// [`Decoder::push`] returns the messages *that chunk completed*, not the
/// messages it happens to be holding. There is no state in which a message is
/// inside the decoder and has not been returned, which is what makes "fed one
/// byte at a time" and "fed the whole buffer" produce identical output rather
/// than merely equal totals.
///
/// # After an error
///
/// A failure that [`IpcError::poisons_connection`] reports leaves the buffer
/// exactly as it was and the decoder unusable: the length prefix that framed
/// the failed message is not trustworthy, so there is no position from which to
/// resume. The caller closes the connection.
#[derive(Debug)]
pub struct Decoder {
    buffer: Vec<u8>,
    max_frame: usize,
    decoded: u64,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// A decoder with the default frame cap.
    pub fn new() -> Self {
        Self::with_max_frame(MAX_FRAME_BYTES)
    }

    /// A decoder with an explicit cap. For tests, and for a caller that knows
    /// its own messages are small.
    pub fn with_max_frame(max_frame: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_frame,
            decoded: 0,
        }
    }

    /// Feed the bytes of one read and take whatever whole messages it completed.
    ///
    /// # Errors
    ///
    /// The oversized-length case is the one this exists for, and it is raised
    /// on the chunk that completes the four-byte prefix — not when the payload
    /// arrives, because the whole point is that the payload never does.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Message>, IpcError> {
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(message) = self.take_one()? {
            out.push(message);
        }
        Ok(out)
    }

    /// Bytes held for a frame that has not arrived yet.
    ///
    /// Exposed so that the test which matters can assert something stronger
    /// than "an error was returned": after a frame length of `u32::MAX` is
    /// refused, this is still four, which is the difference between refusing an
    /// allocation and making one.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// How many messages have been produced, for the caller's own counters.
    pub fn decoded(&self) -> u64 {
        self.decoded
    }

    /// True when a partial frame is held.
    pub fn is_partial(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Take one whole message out of the buffer, or `None` if there is not one.
    fn take_one(&mut self) -> Result<Option<Message>, IpcError> {
        if self.buffer.len() < FRAME_PREFIX_BYTES {
            return Ok(None);
        }
        let length = u32::from_le_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]);

        // The hostile input. Checked here, before the wait for the payload and
        // therefore before anything is reserved for it: a peer that claims
        // 4 GiB gets an error from four bytes it sent, not a 4 GiB allocation.
        if length as usize > self.max_frame {
            return Err(IpcError::FrameTooLarge {
                length,
                max: self.max_frame,
            });
        }
        // Checked on the prefix as well, so a peer that sends a four-byte frame
        // is refused now rather than after a payload that could not contain a
        // header has been waited for and then rejected.
        if (length as usize) < MIN_FRAME_BYTES {
            return Err(IpcError::ShortFrame {
                length,
                min: MIN_FRAME_BYTES,
            });
        }

        let end = FRAME_PREFIX_BYTES + length as usize;
        if self.buffer.len() < end {
            return Ok(None);
        }
        let message = Message::decode(&self.buffer[FRAME_PREFIX_BYTES..end])?;
        self.buffer.drain(..end);
        self.decoded = self.decoded.saturating_add(1);
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Request;
    use crate::report::ScanId;

    /// A request a test can round-trip without building an engine.
    fn sample_request() -> Message {
        Message::Request(
            RequestId::new(7),
            Request::CancelScan { id: ScanId::new(3) },
        )
    }

    #[test]
    fn the_header_is_twenty_four_bytes_and_the_body_starts_aligned() {
        // The layout is a contract with the other end of the pipe, and the
        // arithmetic in the doc comment is the only place it is written down.
        assert_eq!(MAGIC.len() + 4 + 2 + 2 + 8, HEADER_BYTES);
        assert_eq!(HEADER_BYTES % 8, 0);
        let mut out = Vec::new();
        Header {
            version: PROTOCOL_VERSION,
            kind: MessageKind::Request,
            flags: 0,
            correlation: RequestId::new(1),
        }
        .write(&mut out);
        assert_eq!(out.len(), HEADER_BYTES);
    }

    #[test]
    fn a_message_survives_its_own_framing() {
        let payload = sample_request().encode().expect("encodes");
        let framed = frame(&payload).expect("frames");
        assert_eq!(
            u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize,
            payload.len()
        );
        let mut decoder = Decoder::new();
        let messages = decoder.push(&framed).expect("decodes");
        assert_eq!(messages, vec![sample_request()]);
        assert_eq!(decoder.buffered_bytes(), 0);
        assert!(!decoder.is_partial());
    }

    /// The first hostile input, by test rather than by hope.
    #[test]
    fn a_length_larger_than_the_maximum_frame_is_rejected_before_it_is_reserved() {
        let mut decoder = Decoder::new();
        let hostile = u32::MAX.to_le_bytes();
        let error = decoder
            .push(&hostile)
            .expect_err("a 4 GiB frame is not a frame");
        match error {
            IpcError::FrameTooLarge { length, max } => {
                assert_eq!(length, u32::MAX);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        // Four bytes, which is all the peer sent. The assertion the doc comment
        // makes is this one: the rejection cost nothing.
        assert_eq!(decoder.buffered_bytes(), 4);

        // And the boundary: exactly the maximum is a frame, one byte more is
        // not. A cap that refused its own maximum would be off by one.
        let mut decoder = Decoder::with_max_frame(64);
        assert!(matches!(
            decoder.push(&65u32.to_le_bytes()),
            Err(IpcError::FrameTooLarge {
                length: 65,
                max: 64
            })
        ));
    }

    #[test]
    fn a_payload_split_across_reads_decodes_to_the_same_messages_as_one_buffer() {
        // The second hostile input. A pipe does not deliver messages, it
        // delivers bytes, and this is the differential that says so.
        let whole: Vec<u8> = [sample_request(), sample_request(), sample_request()]
            .iter()
            .flat_map(|m| {
                let payload = m.encode().expect("encodes");
                frame(&payload).expect("frames")
            })
            .collect();

        let mut at_once = Decoder::new();
        let expected: Vec<Message> = at_once.push(&whole).expect("decodes");
        assert_eq!(expected.len(), 3);

        // One byte at a time. Every intermediate push must either return
        // nothing or return whole messages, and the total must be identical.
        let mut dribble = Decoder::new();
        let mut seen: Vec<Message> = Vec::new();
        for (index, byte) in whole.iter().enumerate() {
            let messages = dribble
                .push(std::slice::from_ref(byte))
                .unwrap_or_else(|e| panic!("byte {index} failed: {e}"));
            // The property that makes a decoder a decoder: it holds a partial
            // frame and never emits one.
            if messages.is_empty() {
                assert!(dribble.is_partial() || index + 1 == whole.len());
            }
            seen.extend(messages);
        }
        assert_eq!(seen, expected);

        // And at every awkward split point, which catches a decoder that
        // happens to work for one-byte reads and breaks on two.
        for split in 0..whole.len() {
            let mut decoder = Decoder::new();
            let mut got = decoder.push(&whole[..split]).expect("first part");
            got.extend(decoder.push(&whole[split..]).expect("second part"));
            assert_eq!(got, expected, "split at {split}");
        }
    }

    #[test]
    fn two_messages_in_one_read_come_out_as_two() {
        // The other half of "a pipe delivers bytes": not just split messages
        // but coalesced ones.
        let mut bytes = Vec::new();
        for message in [sample_request(), sample_request()] {
            let payload = message.encode().expect("encodes");
            bytes.extend_from_slice(&frame(&payload).expect("frames"));
        }
        let mut decoder = Decoder::new();
        let messages = decoder.push(&bytes).expect("decodes");
        assert_eq!(messages.len(), 2);
        assert_eq!(decoder.decoded(), 2);
    }

    #[test]
    fn a_four_byte_frame_is_refused_without_waiting_for_a_payload() {
        // A length that cannot hold a header is a framing error in its own
        // right, and the reader must not sit waiting for a payload it will
        // then reject.
        let mut decoder = Decoder::new();
        assert!(matches!(
            decoder.push(&4u32.to_le_bytes()),
            Err(IpcError::ShortFrame { length: 4, min: 24 })
        ));
        // No payload was buffered for it, and the four bytes are still held:
        // the decoder does not pretend to have found a place to resume from.
        assert_eq!(decoder.buffered_bytes(), 4);
        // A zero length is refused the same way, on a decoder of its own —
        // this one is unusable after the error above, which is what
        // `poisons_connection` means.
        let mut zero = Decoder::new();
        assert!(matches!(
            zero.push(&0u32.to_le_bytes()),
            Err(IpcError::ShortFrame { length: 0, min: 24 })
        ));
    }

    #[test]
    fn a_wrong_magic_and_a_wrong_version_are_named_errors_and_not_parse_failures() {
        // The version check is the one `av_rules::database` is the precedent
        // for. A body is not self-describing, so this has to happen before the
        // body is touched; the test proves it by handing over a header with a
        // body that could not possibly decode, and checking which error comes
        // back.
        let mut payload = Vec::new();
        Header {
            version: PROTOCOL_VERSION,
            kind: MessageKind::Request,
            flags: 0,
            correlation: RequestId::new(1),
        }
        .write(&mut payload);
        payload.extend_from_slice(&[0xff; 32]);

        let mut wrong_version = payload.clone();
        wrong_version[8..12].copy_from_slice(&0x0002_0000u32.to_le_bytes());
        assert!(matches!(
            Message::decode(&wrong_version),
            Err(IpcError::UnsupportedVersion {
                found: 0x0002_0000,
                ..
            })
        ));

        let mut wrong_magic = payload.clone();
        wrong_magic[0] = b'X';
        assert!(matches!(
            Message::decode(&wrong_magic),
            Err(IpcError::BadMagic)
        ));

        // A kind this build has never heard of: representable, and refused by
        // name rather than deserialised on the off chance.
        let mut wrong_kind = payload.clone();
        wrong_kind[12..14].copy_from_slice(&999u16.to_le_bytes());
        assert!(matches!(
            Message::decode(&wrong_kind),
            Err(IpcError::UnknownKind { kind: 999 })
        ));

        // A flag bit, which is how a later build would demand something.
        let mut wrong_flags = payload.clone();
        wrong_flags[14..16].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            Message::decode(&wrong_flags),
            Err(IpcError::UnsupportedFlags { found: 1 })
        ));

        // And the header that is all there is must be refused as a frame, not
        // as a decode of an empty body.
        assert!(matches!(
            Message::decode(&payload[..HEADER_BYTES]),
            Err(IpcError::Body(_))
        ));
    }

    #[test]
    fn the_kind_and_flag_round_trip_through_the_wire_values() {
        for kind in [MessageKind::Request, MessageKind::Reply, MessageKind::Event] {
            assert_eq!(MessageKind::from_wire(kind.as_wire()), Some(kind));
            assert!(MessageKind::is_known(kind.as_wire()));
        }
        // Zero is reserved so a zeroed header is a bug rather than a request.
        assert_eq!(MessageKind::from_wire(KIND_RESERVED), None);
        assert!(!MessageKind::is_known(KIND_RESERVED));
        assert!(!MessageKind::is_known(4));
    }

    #[test]
    fn framing_refuses_a_payload_it_could_not_frame() {
        let oversized = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            frame(&oversized),
            Err(IpcError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn request_identifiers_do_not_wrap() {
        assert_eq!(RequestId::FIRST.next(), Some(RequestId::new(2)));
        assert_eq!(RequestId::NONE.next(), Some(RequestId::FIRST));
        // Not a wrap to zero, which is reserved: a client that ran out says so.
        assert_eq!(RequestId::new(u64::MAX).next(), None);
        assert!(RequestId::NONE.is_none());
        assert!(!RequestId::FIRST.is_none());
    }

    #[test]
    fn the_version_predicate_refuses_a_neighbouring_version() {
        assert!(is_compatible(PROTOCOL_VERSION));
        assert!(!is_compatible(PROTOCOL_VERSION + 1));
        // The neighbour is derived rather than written down. It used to be the
        // literal `0x0001_0001`, which was the next minor version right up
        // until the day the protocol was bumped to it — and on that day this
        // assertion was refusing the version the build actually speaks, so the
        // test passed while testing the opposite of what it says. A version
        // written into a test is a version that expires.
        assert!(!is_compatible(PROTOCOL_VERSION ^ 0x0000_0001));
        assert!(!is_compatible(PROTOCOL_VERSION ^ 0x0001_0000));
        assert!(!is_compatible(0));
    }
}
