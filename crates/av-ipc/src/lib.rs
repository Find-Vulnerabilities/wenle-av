//! The control protocol between the Wenle AV service and everything that talks
//! to it, written so that `cargo test` can run all of it.
//!
//! # The same split `av-driver-proto` makes, made again
//!
//! `crates/av-driver-proto` exists for one reason: a kernel driver can only be
//! *believed*, so everything about it that is ordinary logic (the protocol, the
//! decision state machine, the path arithmetic) was moved into user mode, where
//! a test runs it in a second. What was left in the driver crate is the part
//! that genuinely needs a kernel, and it is the only unverified part.
//!
//! This crate is that split applied to the other end of the product. A service
//! that only exists as an installed Windows service can also only be believed:
//! `sc create` needs administrator, the machine it would run on is the machine
//! somebody is using, and a control protocol whose framing is only exercised by
//! running the whole product is a control protocol whose framing is never
//! exercised at all.
//!
//! So this crate holds the protocol and nothing else: the frame format, the
//! header, the version check, the message vocabulary, and the state machine
//! each end runs over it. It has **no Windows API, no I/O and no threads**:
//! [`Connection`] is a byte-stream trait, and the only implementation in this
//! crate is an in-memory loopback used by its own tests. `av-service` is what is
//! left (the SCM host, the named-pipe listener, and the wiring of the scanner,
//! the vault and the watcher) and it is thin, because every line in it is a line
//! no test on this machine can reach.
//!
//! | Module | What it holds | Touches a system |
//! |---|---|---|
//! | [`wire`] | the length prefix, the header, the version check, the reassembling [`Decoder`] | no |
//! | [`message`] | the vocabulary: what a client asks, what a service answers, what a service says unasked | no |
//! | [`detect`] | the detection payload, and the [`Phase`] type that stops it claiming a block | no |
//! | [`report`] | status, progress, summaries and the disclosure of unhonoured settings | no |
//! | [`session`] | [`Client`] and [`Server`]: correlation, identifier ordering, direction | no |
//! | [`transport`] | the pipe name, [`Connection`], and the in-memory loopback the tests use | no |
//!
//! # Why a named pipe rather than a localhost socket
//!
//! There is one endpoint, `\\.\pipe\wenleav-control`, created with
//! `PIPE_REJECT_REMOTE_CLIENTS` so that it is not reachable over SMB. The
//! argument for a pipe over a TCP socket is not performance (neither carries
//! more than a few messages a second), it is that **the pipe's security is the
//! filesystem's**: whether a process may open this endpoint is decided by the
//! pipe's DACL, which is the same mechanism, over the same principals, that
//! already governs `%ProgramData%\WenleAV`. A localhost socket has no such
//! notion. Every process on the machine can connect to it, so the protocol
//! would have to invent a credential, hand it out to the graphical front end,
//! and keep it, and an invented credential that leaks turns "list my quarantine"
//! into "restore anything" for anything running as the user. There is also no
//! port to collide with: a number can be taken by another product or by a
//! previous version, and a pipe name cannot be occupied by anything that is not
//! already allowed to create it. And there is no firewall to negotiate, because
//! a pipe is not a network surface at all.
//!
//! The Windows calls behind that (`CreateNamedPipeW`, `ConnectNamedPipe`,
//! `CreateFileW`) are in `av-service::pipe`, which is the only file in the
//! workspace that names them.
//!
//! # The two hostile inputs the framing has to survive
//!
//! A length-prefixed protocol has two ways to fail that ordinary testing does
//! not reach, and both are tests here rather than hopes:
//!
//! * **A length larger than the maximum frame.** A `u32` length read off a
//!   socket is an attacker-controlled allocation size, which is the same class
//!   of bug `av_driver_proto::wire` documents avoiding and to which it gives
//!   the opposite answer. There, a length is a *used length into a buffer that
//!   already exists*, so `u32::MAX` produces a 1024-element slice. This crate
//!   has no such buffer, so the answer is [`MAX_FRAME_BYTES`]: a length above it
//!   is refused **on the four bytes that carry it**, before the payload arrives
//!   and therefore before anything is reserved for it.
//!   `wire::tests::a_length_larger_than_the_maximum_frame_is_rejected_before_it_is_reserved`
//!   asserts both halves, the error and that four bytes is all that is held, and
//!   `session::tests::a_framing_failure_ends_the_session_rather_than_desynchronising_it`
//!   asserts it again through the session, and again through a real pipe in
//!   `av-service`.
//! * **A payload split across reads.** A pipe delivers bytes, not messages: a
//!   frame can arrive across any number of reads and several can arrive in one.
//!   `wire::tests::a_payload_split_across_reads_decodes_to_the_same_messages_as_one_buffer`
//!   feeds the same stream one byte at a time, in two halves at every awkward
//!   split point, and in one buffer, and requires all of them to produce the
//!   same messages.
//!
//! # Versioning
//!
//! A magic number and a version are checked in the header **before the body is
//! handed to the deserialiser**, because a body is not self-describing: a build
//! that deserialised first and compared versions afterwards would have already
//! read one build's bytes as another build's structures. A mismatch is
//! [`IpcError::UnsupportedVersion`], a named error, and not a parse failure.
//! The message was fine and means something else. Same shape and same ordering
//! as `av_rules::database::RuleDatabase::from_bytes`.
//!
//! # Extensibility, and why nothing here is `#[non_exhaustive]`
//!
//! A service that matched three of nine request variants and then had `_ => {}`
//! would keep compiling when the tenth was added, would answer nothing, and the
//! user would find a button that does nothing with no error anywhere. Adding a
//! variant to [`Request`], [`Reply`], [`Event`], [`RequestKind`] or
//! [`ReplyKind`] instead **stops the build** in every place that has to decide
//! what to do about it, which is exactly the list a reviewer needs. See
//! [`message`] for the argument in full.
//!
//! What survives is the decoding side, which has to: a peer built against a
//! later version sends a variant index this build has never heard of, and
//! bincode rejects it as a decode error rather than transmuting it into
//! something. That is [`IpcError::Body`], and a server answers it by closing one
//! connection.
//!
//! # What is verified, and what is not
//!
//! Stated plainly, because the value of this crate is that everything outside
//! this list is tested:
//!
//! * **Verified here:** the frame format, the length cap and the byte-at-a-time
//!   reassembly; the header checks and the named version error; the whole
//!   vocabulary's round trip; the correlation rules, the identifier ordering,
//!   the direction checks and the outstanding-request bound; and the derivation
//!   that stops a component which blocks nothing from reporting that it did.
//! * **Verified in `av-service`, against a real named pipe:** that the Windows
//!   calls this protocol is designed around exist, that a client and a service
//!   can exchange real messages through them, and that the oversized length is
//!   refused by a server reading from a pipe rather than from a `Vec`.
//! * **Not verified anywhere:** the service as an installed Windows service.
//!   `StartServiceCtrlDispatcherW` is never called on this machine (it needs
//!   administrator and this machine is in use), so the SCM host is
//!   `#[ignore]`d and everything about how Windows actually starts, stops and
//!   reports on this service is unverified. `av-service` says so in its own
//!   documentation, in the terms `av-realtime` used when it reported what it
//!   could not do.
//! * **Not verified:** the driver's own side of the protocol. `av-driver-proto`
//!   exists and is tested and `crates/av-driver` implements the minifilter, but
//!   a driver needs a WDK to build and a kernel to load into, so no test run in
//!   this workspace ever exercises it. What is here is the service's half:
//!   `av-service`'s filter-port client connects to the port that crate names,
//!   answers its decision requests, and emits [`Event::Driver`] when the
//!   connection comes and goes. It is the one producer of that vocabulary in
//!   this build, and `#[cfg(windows)]` like the port itself.

#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod detect;
pub mod error;
pub mod memory;
pub mod message;
pub mod report;
pub mod session;
pub mod transport;
pub mod wire;

pub use detect::{Detection, DetectionAction, Phase, QuarantineListing};
pub use error::IpcError;
pub use memory::{MemoryCoverage, MemoryReport};
pub use message::{
    DriverEvent, DriverEventAction, DriverSubject, Event, Message, QuarantineChange, Reply,
    ReplyKind, Request, RequestKind, ScanCancel, ScanFinished, ScanStart,
};
pub use report::{
    BufferScan, ConfigReport, DatabaseStatus, DriverPresence, DriverStatus, LostRoot,
    ManifestVerdict, MissedWindow, RealtimeState, ScanId, ScanProgress, ScanSummary, ServiceState,
    SettingDisclosure, StatusReport, TamperState,
};
pub use session::{Client, Incoming, Server, MAX_OUTSTANDING_REQUESTS};
pub use transport::{
    is_valid_pipe_name, Connection, Read, MAX_PIPE_NAME_BYTES, PIPE_NAME, PIPE_PREFIX,
};
pub use wire::{
    Decoder, Header, MessageKind, RequestId, FRAME_PREFIX_BYTES, HEADER_BYTES, MAX_FRAME_BYTES,
    MIN_FRAME_BYTES, PROTOCOL_VERSION,
};
