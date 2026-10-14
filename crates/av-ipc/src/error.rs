//! Everything that can go wrong reading, writing or correlating a message.

use crate::message::{ReplyKind, RequestKind};
use crate::wire::{MessageKind, RequestId};

/// A protocol failure.
///
/// The variants split into two kinds, and the split is the one thing a caller
/// has to understand about this type. Some of these are *the stream is fine,
/// this message is not*: a client that sends a reply for an identifier it never
/// used has made a mistake, and the connection can carry on. The rest mean the
/// byte stream is no longer trustworthy — the length prefix that framed this
/// message was wrong, so the next four bytes are not a length — and the only
/// correct response is to close the connection. [`IpcError::poisons_connection`]
/// is that distinction, in one place, rather than a rule every caller has to
/// remember.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// A frame's length prefix was larger than
    /// [`crate::wire::MAX_FRAME_BYTES`].
    ///
    /// This is the attacker-controlled allocation size, and it is refused
    /// before a single byte is reserved for it. The same class of bug, and the
    /// same answer, as `av_driver_proto::wire`'s used-length fields — see this
    /// crate's documentation.
    #[error(
        "frame length {length} exceeds the {max}-byte maximum; the length prefix is not \
         trustworthy and the connection must be closed"
    )]
    FrameTooLarge {
        /// The length the peer claimed.
        length: u32,
        /// [`crate::wire::MAX_FRAME_BYTES`].
        max: usize,
    },

    /// A frame was shorter than the protocol header, so it cannot be one.
    ///
    /// Checked on the length prefix alone, so a peer that sends four bytes of
    /// `0x00000004` is refused without waiting for a payload that could never
    /// carry a header.
    #[error("frame length {length} is shorter than the {min}-byte protocol header")]
    ShortFrame {
        /// The length the peer claimed.
        length: u32,
        /// [`crate::wire::MIN_FRAME_BYTES`].
        min: usize,
    },

    /// The payload does not begin with the protocol's magic number.
    #[error("payload does not begin with the WENLEIPC magic number")]
    BadMagic,

    /// The peer speaks a different version.
    ///
    /// A named error rather than a parse failure, because the two demand
    /// different answers: a parse failure says the message was corrupt, and
    /// this says the message was fine and means something else. The same shape
    /// as `av_rules::database::DatabaseError::UnsupportedVersion`.
    #[error(
        "protocol version {found:#010x} is not the version this build speaks \
         ({supported:#010x}); the peer is a different build"
    )]
    UnsupportedVersion {
        /// The version in the header.
        found: u32,
        /// [`crate::wire::PROTOCOL_VERSION`].
        supported: u32,
    },

    /// The header's reserved flag bits are not zero.
    ///
    /// Checked rather than ignored, because a flag bit is how this protocol
    /// would negotiate anything in future; ignoring an unknown one is how a
    /// future build's "I require you to do X" is silently not done.
    #[error("header flags {found:#06x} are not zero, and this build defines no flags")]
    UnsupportedFlags {
        /// The flags found in the header.
        found: u16,
    },

    /// The header's kind is not one this build defines.
    #[error("message kind {kind} is not a kind this build defines")]
    UnknownKind {
        /// The kind found in the header.
        kind: u16,
    },

    /// The body did not decode.
    #[error("message body did not decode: {0}")]
    Body(String),

    /// The body decoded, and there were bytes left over.
    ///
    /// Not harmless: the leftover bytes are a place to hide a second message
    /// that a reader which trusted the frame length would not look at. The
    /// frame's length and the body's are two independent numbers and they have
    /// to agree.
    #[error("message body had {trailing} bytes after the value it decoded to")]
    TrailingBytes {
        /// How many bytes were left.
        trailing: usize,
    },

    /// A request or reply carried correlation identifier zero.
    ///
    /// Zero is reserved for events, which are not part of any exchange, so a
    /// zeroed header is a bug rather than a request nobody answers.
    #[error("a request or reply carried correlation id 0, which is reserved for events")]
    MissingCorrelation,

    /// A reply arrived for a request this client does not have outstanding.
    #[error("a reply arrived for request {id}, which is not outstanding")]
    UnexpectedReply {
        /// The identifier the reply named.
        id: RequestId,
    },

    /// A reply answered the wrong question.
    #[error("request {id} asked for a {expected} reply and got a {actual}")]
    WrongReply {
        /// The request being answered.
        id: RequestId,
        /// What the request asked for.
        expected: ReplyKind,
        /// What arrived.
        actual: ReplyKind,
    },

    /// A reply answered a request the service has already answered.
    #[error("a reply answered request {id}, which has already been answered or never arrived")]
    UnknownRequest {
        /// The identifier the reply named.
        id: RequestId,
    },

    /// A request identifier did not increase.
    ///
    /// A client numbers its requests upward, and the service refuses anything
    /// that does not, because the alternative is remembering every identifier
    /// it has ever seen — unbounded state an attacker chooses the size of.
    /// A repeat would also run the request twice, which for
    /// [`crate::Request::QuarantineDelete`] is not a no-op.
    #[error(
        "request {id} arrived after request {last}; identifiers must increase, and a repeat \
         would run the request twice"
    )]
    RequestIdNotIncreasing {
        /// The identifier that arrived.
        id: RequestId,
        /// The highest identifier seen before it.
        last: RequestId,
    },

    /// A message arrived in the direction it is not allowed to travel.
    #[error("a {kind} is not something a client sends; this endpoint is the service")]
    WrongDirection {
        /// What arrived.
        kind: MessageKind,
    },

    /// A request kind arrived at the service's client endpoint.
    #[error("a {kind} is not something the service sends; this endpoint is a client")]
    NotAServiceMessage {
        /// What arrived.
        kind: RequestKind,
    },

    /// The client has used every request identifier.
    #[error("this client has used every request identifier there is")]
    RequestIdsExhausted,

    /// The service is holding as many unanswered requests as it will.
    ///
    /// This is the bound on state whose size the peer chooses, and it is
    /// refused rather than grown. See
    /// [`crate::session::MAX_OUTSTANDING_REQUESTS`].
    #[error(
        "the service is already holding {max} unanswered requests; a client has to read its \
         replies before sending more"
    )]
    TooManyOutstanding {
        /// [`crate::session::MAX_OUTSTANDING_REQUESTS`].
        max: usize,
    },

    /// The peer closed the connection.
    #[error("the peer closed the connection")]
    PeerClosed,

    /// The transport itself failed.
    #[error("transport failure: {0}")]
    Transport(String),

    /// The message could not be encoded.
    #[error("message could not be encoded: {0}")]
    Encode(String),
}

impl IpcError {
    /// True when this failure means the byte stream is no longer trustworthy.
    ///
    /// Every one of these is a statement about the framing rather than about
    /// the message inside it: the length prefix was impossible, or the header
    /// that followed it was not a header. Once one of those is true, the reader
    /// has no way to find where the next message starts, so carrying on means
    /// interpreting a body as a length. The caller closes the connection.
    pub const fn poisons_connection(&self) -> bool {
        matches!(
            self,
            IpcError::FrameTooLarge { .. }
                | IpcError::ShortFrame { .. }
                | IpcError::BadMagic
                | IpcError::UnsupportedVersion { .. }
                | IpcError::UnsupportedFlags { .. }
                | IpcError::UnknownKind { .. }
                | IpcError::TrailingBytes { .. }
                | IpcError::Encode(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_the_reader_could_not_frame_poisons_the_connection() {
        // The two hostile inputs from the crate documentation, plus the header
        // checks that share their property: after any of these, the next four
        // bytes are not a length.
        assert!(IpcError::FrameTooLarge {
            length: u32::MAX,
            max: crate::wire::MAX_FRAME_BYTES
        }
        .poisons_connection());
        assert!(IpcError::ShortFrame {
            length: 3,
            min: crate::wire::MIN_FRAME_BYTES
        }
        .poisons_connection());
        assert!(IpcError::BadMagic.poisons_connection());
        assert!(IpcError::UnsupportedVersion {
            found: 0x0002_0000,
            supported: crate::wire::PROTOCOL_VERSION
        }
        .poisons_connection());
        assert!(IpcError::TrailingBytes { trailing: 1 }.poisons_connection());
        // A message that decoded into something this build does not accept does
        // not poison anything: the framing was sound and the next message is
        // where the reader expects it.
        assert!(!IpcError::MissingCorrelation.poisons_connection());
        assert!(!IpcError::WrongDirection {
            kind: MessageKind::Reply
        }
        .poisons_connection());
        assert!(!IpcError::PeerClosed.poisons_connection());
    }
}
