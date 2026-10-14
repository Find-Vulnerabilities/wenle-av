//! The seam between this protocol and whatever carries it.
//!
//! # Why a named pipe and not a localhost socket
//!
//! Both would work. The pipe is chosen for three reasons, and the first is the
//! one that decides it:
//!
//! * **The pipe's security is the filesystem's.** A caller either can open
//!   `\\.\pipe\wenleav-control` or cannot, and what decides it is the default
//!   DACL of the pipe — the same mechanism, and in practice the same list of
//!   principals, that already governs `%ProgramData%\WenleAV`. A localhost TCP
//!   socket has no such notion: on a machine with more than one user, every
//!   local process that can guess the port can connect, and the only thing
//!   standing between it and "quarantine this file / restore that one" is a
//!   token this protocol would have to invent and keep secret. Inventing a
//!   credential and failing to keep it is a well-trodden path to a local
//!   privilege escalation in a security product.
//! * **There is no port.** A TCP endpoint has to be numbered, and a number can
//!   be taken — by another product, by a leftover from a previous version, or
//!   by malware that got there first and is now impersonating the service. A
//!   pipe name cannot be occupied by anything that is not already running as a
//!   principal allowed to create it.
//! * **There is no firewall to negotiate.** A listening socket is a listening
//!   socket to every firewall and every scanner on the machine, including the
//!   ones this installation might be expected to coexist with; a named pipe is
//!   not a network surface at all.
//!
//! [`PIPE_NAME`] is created with `PIPE_REJECT_REMOTE_CLIENTS`, so the endpoint
//! is not reachable over SMB either: without it, a pipe can be opened from
//! another machine by anyone who can authenticate to this one, which is the
//! localhost argument again in a worse form. That flag is the transport's, so
//! it lives with the transport — in `av-service`, where the pipe is built — and
//! it is named here because it is part of what this protocol promises.
//!
//! # The trait
//!
//! [`Connection`] is a byte stream and nothing else: a message-shaped write and
//! a chunk-shaped read. It exists so that the session state machine in
//! [`crate::session`] — which is where the correlation rules, the identifier
//! ordering and the direction checks live — can be tested against an in-memory
//! loopback rather than against a real pipe. That is the same split
//! `av_driver_proto::path::VolumeNames` uses for volume names: the decision is
//! testable, and the call that only works on Windows is one small implementation
//! behind an interface.
//!
//! Nothing in this file names a Windows type. The implementation that does is
//! `av-service::pipe`.

use crate::error::IpcError;

/// The pipe every Wenle AV control client connects to.
///
/// # What this name does and does not isolate
///
/// `\\.\pipe\` is the **machine-wide** namespace: every session on this machine
/// reaches this endpoint, and so would a remote one if the pipe accepted remote
/// clients. Until 2026-10-09 this constant's documentation claimed the opposite
/// — that the leading `\\.\` was the `Local\` namespace and that the endpoint was
/// therefore per-session, with a service in session 0 that a user session could
/// not reach. All three claims were false, and the last one was false in the
/// direction that matters: the service is *reachable* from every session, which
/// is exactly why a front end works at all, and it was the reason nobody had
/// written the client-authorisation rule that now lives in
/// `av_service::peer`.
///
/// Three separate things keep the channel narrow, and none of them is the name:
///
/// * `PIPE_REJECT_REMOTE_CLIENTS`, set on every instance, keeps the endpoint off
///   the network — so "machine-wide" means this machine's sessions and not
///   anybody who can authenticate to it.
/// * The instance's permission list, `av_service::pipe::CONTROL_PIPE_SDDL`,
///   decides which accounts may open it at all. That list grants read and write
///   to `NT AUTHORITY\INTERACTIVE`, which contains `BUILTIN\Users`: every account
///   that can sign on to this machine is on it. That is deliberate — a control
///   channel the product's own front ends cannot reach is a product with no
///   front end — and it means the pipe's permissions separate nobody from
///   anybody.
/// * `av_service::peer`, which decides per connection what the account on the
///   other end may do. That is the layer that separates one signed-in user from
///   another, and it is the only one that can.
///
/// So the honest summary is the one the service's documentation gives: the
/// transport is machine-wide, the permission list admits every interactive
/// account, and the authorisation is per request.
pub const PIPE_NAME: &str = r"\\.\pipe\wenleav-control";

/// The prefix every Win32 named pipe path starts with.
///
/// Here so that a test can build its own name without spelling the prefix a
/// second time, and so that a service can refuse to create anything that is not
/// a pipe path.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// The longest name [`PIPE_PREFIX`] can be followed by.
///
/// Windows truncates a pipe name at 256 characters in total, and a truncated
/// name is a *different pipe*: a service that created one would be listening
/// somewhere no client looks. Named so the arithmetic is checkable rather than
/// folklore.
pub const MAX_PIPE_NAME_BYTES: usize = 256;

/// What one read produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// Bytes arrived. The count is at least one.
    Bytes(usize),
    /// The peer closed its end.
    Closed,
}

/// A reliable, ordered byte stream a session can run over.
///
/// Both methods are blocking in every implementation this workspace ships, and
/// the trait says so rather than pretending otherwise: a non-blocking read
/// would push a readiness question into the state machine, and readiness is the
/// transport's business.
pub trait Connection: Send {
    /// Write one whole frame.
    ///
    /// All of it or none of it from the caller's point of view: an
    /// implementation that wrote half a frame and returned `Ok` would leave
    /// [`crate::session::Client`] believing a message had been sent.
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), IpcError>;

    /// Read whatever has arrived, up to `buf.len()` bytes.
    ///
    /// A short read is not an error and neither is a read that splits a frame:
    /// [`crate::wire::Decoder`] exists for exactly that.
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<Read, IpcError>;
}

/// True when `name` is a well-formed pipe path this product could create.
///
/// Checked in a test rather than assumed, because a name one character over the
/// limit is not rejected by `CreateNamedPipeW` — it is silently truncated, and
/// the service ends up listening on a pipe nobody connects to.
pub fn is_valid_pipe_name(name: &str) -> bool {
    name.len() <= MAX_PIPE_NAME_BYTES
        && name
            .strip_prefix(PIPE_PREFIX)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('\\'))
}

/// An in-memory pair of connections, for testing a session without a system.
///
/// Two of these back to back are a loopback: whatever one writes, the other
/// reads, in order. Deliberately dumb — it does not simulate partial writes,
/// latency or failure, because the point is to test the protocol's own rules
/// and not an operating system's.
#[cfg(test)]
pub(crate) mod loopback {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::{Connection, Read};
    use crate::error::IpcError;

    #[derive(Debug, Default)]
    struct Pipe {
        bytes: Mutex<VecDeque<u8>>,
        /// Set when the far end has gone, so a read reports `Closed` rather
        /// than blocking forever.
        closed: Mutex<bool>,
    }

    /// One end of an in-memory connection.
    #[derive(Debug)]
    pub(crate) struct Loopback {
        inbound: Arc<Pipe>,
        outbound: Arc<Pipe>,
        /// How many bytes this end will hand over per read, so that a test can
        /// force a frame to be split without writing a second fake.
        chunk: usize,
    }

    impl Loopback {
        /// A connected pair.
        pub(crate) fn pair() -> (Self, Self) {
            Self::pair_with_chunk(usize::MAX)
        }

        /// A connected pair where every read returns at most `chunk` bytes.
        ///
        /// `chunk = 1` is the byte-at-a-time transport the crate documentation
        /// promises to survive, exercised through the session rather than only
        /// through the decoder.
        pub(crate) fn pair_with_chunk(chunk: usize) -> (Self, Self) {
            let a_to_b = Arc::new(Pipe::default());
            let b_to_a = Arc::new(Pipe::default());
            let a = Self {
                inbound: Arc::clone(&b_to_a),
                outbound: Arc::clone(&a_to_b),
                chunk: chunk.max(1),
            };
            let b = Self {
                inbound: a_to_b,
                outbound: b_to_a,
                chunk: chunk.max(1),
            };
            (a, b)
        }

        /// Mark this end closed, so the far end's next read reports it.
        pub(crate) fn close(&self) {
            if let Ok(mut closed) = self.outbound.closed.lock() {
                *closed = true;
            }
        }
    }

    impl Connection for Loopback {
        fn write_frame(&mut self, frame: &[u8]) -> Result<(), IpcError> {
            let closed = self
                .outbound
                .closed
                .lock()
                .map_err(|_| IpcError::Transport("loopback lock was poisoned".to_string()))?;
            if *closed {
                return Err(IpcError::PeerClosed);
            }
            let mut bytes = self
                .outbound
                .bytes
                .lock()
                .map_err(|_| IpcError::Transport("loopback lock was poisoned".to_string()))?;
            bytes.extend(frame.iter().copied());
            Ok(())
        }

        fn read_chunk(&mut self, buf: &mut [u8]) -> Result<Read, IpcError> {
            let mut bytes = self
                .inbound
                .bytes
                .lock()
                .map_err(|_| IpcError::Transport("loopback lock was poisoned".to_string()))?;
            if bytes.is_empty() {
                let closed =
                    self.inbound.closed.lock().map_err(|_| {
                        IpcError::Transport("loopback lock was poisoned".to_string())
                    })?;
                return Ok(if *closed {
                    Read::Closed
                } else {
                    // A blocking implementation would wait here; the loopback
                    // has nothing to wait for, and a test that asked it to wait
                    // would be a test that hung.
                    Read::Bytes(0)
                });
            }
            let take = buf.len().min(self.chunk).min(bytes.len());
            for slot in buf.iter_mut().take(take) {
                *slot = bytes.pop_front().unwrap_or(0);
            }
            Ok(Read::Bytes(take))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_name_is_one_windows_will_accept() {
        // 256 is the documented cap, and it is a *name* cap and not a path cap,
        // so the prefix counts towards it.
        assert!(is_valid_pipe_name(PIPE_NAME));
        assert!(PIPE_NAME.starts_with(PIPE_PREFIX));
        assert!(PIPE_NAME.len() <= MAX_PIPE_NAME_BYTES);
        // A name one character over is silently truncated by Windows, and a
        // truncated name is a different pipe.
        let absurd = format!("{PIPE_PREFIX}{}", "a".repeat(MAX_PIPE_NAME_BYTES));
        assert!(!is_valid_pipe_name(&absurd));
        // A path that is not in the pipe namespace at all, and a bare prefix
        // with nothing after it.
        assert!(!is_valid_pipe_name(r"C:\ProgramData\WenleAV\control"));
        assert!(!is_valid_pipe_name(PIPE_PREFIX));
        assert!(!is_valid_pipe_name(r"\\.\pipe\a\b"));
    }

    #[test]
    fn the_loopback_carries_bytes_in_order_and_reports_a_close() {
        // The fake itself, tested before anything is tested with it: a
        // loopback that lost a byte would make an unrelated session test look
        // like a protocol bug.
        let (mut a, mut b) = loopback::Loopback::pair();
        a.write_frame(b"hello").expect("writes");
        let mut buf = [0u8; 8];
        assert_eq!(b.read_chunk(&mut buf).expect("reads"), Read::Bytes(5));
        assert_eq!(&buf[..5], b"hello");
        a.close();
        assert_eq!(b.read_chunk(&mut buf).expect("reads"), Read::Closed);
        // And a write to a closed far end is refused rather than lost.
        b.close();
        assert!(matches!(a.write_frame(b"x"), Err(IpcError::PeerClosed)));
    }

    #[test]
    fn a_one_byte_loopback_hands_over_one_byte_at_a_time() {
        let (mut a, mut b) = loopback::Loopback::pair_with_chunk(1);
        a.write_frame(b"abc").expect("writes");
        let mut buf = [0u8; 8];
        for expected in [b"a", b"b", b"c"] {
            assert_eq!(b.read_chunk(&mut buf).expect("reads"), Read::Bytes(1));
            assert_eq!(&buf[..1], expected);
        }
    }
}
