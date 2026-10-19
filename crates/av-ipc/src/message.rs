//! The vocabulary: what a client asks, what the service answers, and what the
//! service says without being asked.
//!
//! # Exhaustive on purpose
//!
//! None of the enums here is `#[non_exhaustive]`, and there is no wildcard arm
//! anywhere in this workspace that consumes them. That is a deliberate choice
//! and it is the opposite of what a published protocol crate usually does.
//!
//! The reason is that a wildcard arm is where a message goes to be ignored. A
//! service that matched `Request::Status` and then had `_ => {}` would keep
//! compiling when `QuarantineRestore` was added, would answer nothing, and the
//! user would see a button that does nothing with no error anywhere. With an
//! exhaustive match, adding a variant stops the build in every place that has
//! to decide what to do about it — which is exactly the list of places a
//! reviewer needs to see. Within one workspace that trade is free; the enums
//! are not a library's public interface, they are this product's own skeleton.
//!
//! What survives from the usual reasoning is the *decoding* side: a peer built
//! against a later version sends a variant index this build has never heard of,
//! and bincode fails on it rather than transmuting it. That is a decode error
//! and not a panic, and there is a test that pins it — see
//! [`Message::decode`].
//!
//! # The correlation is in the header, not in the variants
//!
//! [`Message::Request`] and [`Message::Reply`] carry a [`RequestId`], and it is
//! the same value that was written into the header. The body does **not**
//! repeat it: two copies of one fact is two chances to disagree, and a reply
//! whose body named a different request from its header would be a
//! disagreement no reader could resolve.

use std::io::Cursor;
use std::path::PathBuf;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use av_core::config::AvConfig;
use av_core::scan::ScanOptions;
use av_quarantine::QuarantineId;

use crate::detect::{Detection, QuarantineListing};
use crate::error::IpcError;
use crate::memory::MemoryReport;
use crate::report::{
    BufferScan, ConfigReport, DriverStatus, RealtimeState, ScanId, ScanProgress, ScanSummary,
    StatusReport,
};
use crate::wire::{frame, Header, MessageKind, RequestId, PROTOCOL_VERSION};

/// One message, as it travels.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A client asking the service to do something.
    Request(RequestId, Request),
    /// The service's answer to exactly one request.
    Reply(RequestId, Reply),
    /// Something the service decided a client should know.
    ///
    /// Events carry no identifier: they are not answers, and a client never
    /// waits for one.
    Event(Event),
}

impl Message {
    /// Which of the three this is.
    pub const fn kind(&self) -> MessageKind {
        match self {
            Message::Request(..) => MessageKind::Request,
            Message::Reply(..) => MessageKind::Reply,
            Message::Event(_) => MessageKind::Event,
        }
    }

    /// The exchange this belongs to, or [`RequestId::NONE`] for an event.
    pub const fn correlation(&self) -> RequestId {
        match self {
            Message::Request(id, _) | Message::Reply(id, _) => *id,
            Message::Event(_) => RequestId::NONE,
        }
    }

    /// Encode to a payload: header then body.
    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        let (kind, correlation, body) = match self {
            Message::Request(id, request) => (
                MessageKind::Request,
                *id,
                bincode::serialize(request).map_err(|e| IpcError::Encode(e.to_string()))?,
            ),
            Message::Reply(id, reply) => (
                MessageKind::Reply,
                *id,
                bincode::serialize(reply).map_err(|e| IpcError::Encode(e.to_string()))?,
            ),
            Message::Event(event) => (
                MessageKind::Event,
                RequestId::NONE,
                bincode::serialize(event).map_err(|e| IpcError::Encode(e.to_string()))?,
            ),
        };
        let mut payload = Vec::with_capacity(crate::wire::HEADER_BYTES + body.len());
        Header {
            version: PROTOCOL_VERSION,
            kind,
            flags: 0,
            correlation,
        }
        .write(&mut payload);
        payload.extend_from_slice(&body);
        Ok(payload)
    }

    /// Encode and length-prefix, ready to write to the pipe.
    pub fn encode_framed(&self) -> Result<Vec<u8>, IpcError> {
        frame(&self.encode()?)
    }

    /// Read a payload: check the header, then decode the body.
    ///
    /// The header checks happen first and in this order, so a message from
    /// another build is refused by version rather than being read as structures
    /// that do not mean what they say.
    pub fn decode(payload: &[u8]) -> Result<Self, IpcError> {
        let header = Header::parse(payload)?;
        let body = &payload[crate::wire::HEADER_BYTES..];
        let mut cursor = Cursor::new(body);
        let message = match header.kind {
            MessageKind::Request => {
                if header.correlation.is_none() {
                    return Err(IpcError::MissingCorrelation);
                }
                Message::Request(header.correlation, decode_body(&mut cursor)?)
            }
            MessageKind::Reply => {
                if header.correlation.is_none() {
                    return Err(IpcError::MissingCorrelation);
                }
                Message::Reply(header.correlation, decode_body(&mut cursor)?)
            }
            // An event's correlation is zero by construction; a non-zero one is
            // written by a peer that has misunderstood what an event is, and it
            // is dropped rather than carried, because carrying it would make
            // two sources for a field that has only one meaning.
            MessageKind::Event => Message::Event(decode_body(&mut cursor)?),
        };
        let consumed = cursor.position() as usize;
        if consumed != body.len() {
            return Err(IpcError::TrailingBytes {
                trailing: body.len() - consumed,
            });
        }
        Ok(message)
    }
}

fn decode_body<T: DeserializeOwned>(cursor: &mut Cursor<&[u8]>) -> Result<T, IpcError> {
    bincode::deserialize_from(cursor).map_err(|e| IpcError::Body(e.to_string()))
}

/// What a client asks the service to do.
///
/// Adding a variant to this enum is a compile error in
/// [`crate::session::Server::reply`]'s caller and in every dispatcher over it,
/// which is the point — see this module's documentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    /// Is the service running, what is it watching, and what is it protecting
    /// with.
    Status,
    /// Start a scan. The reply carries the identifier the progress and finish
    /// events will refer to.
    ScanPath {
        /// The file or directory to scan.
        path: PathBuf,
        /// How to scan it. The service applies this rather than its own
        /// configuration, because a caller asking for one file by name has
        /// said more about what it wants than any setting has.
        options: ScanOptions,
    },
    /// Stop a running scan.
    CancelScan {
        /// The identifier from the reply to [`Request::ScanPath`].
        id: ScanId,
    },
    /// Scan the memory of one running process.
    ///
    /// A request of its own and not an option on [`Request::ScanPath`], because
    /// a path scan and a process scan share nothing but the engine: one walks a
    /// directory tree and reads files, the other walks an address space and
    /// reads regions, and neither produces the other's report. The file-scan
    /// options type has a `memory` field, and this request is where that flag
    /// was always headed — but a flag on a scan of a *path* cannot say which
    /// process to look at, and a scan of every process at once is not what a
    /// caller asking about one PID wants.
    ///
    /// Answered synchronously by [`Reply::MemoryScan`], with no progress events:
    /// one process is bounded by the scanner's byte budget for a process, which
    /// is a quarter of a gigabyte, and a stream of progress for a scan of that
    /// size is more protocol than the answer needs. The cost is that the
    /// service's control loop is busy for the duration, which is stated in
    /// `av_service::host` rather than hidden.
    ScanProcess {
        /// The process to scan. Zero is refused: it is the idle process, it has
        /// no address space to walk, and Windows answers every call about it
        /// with the code it uses for a PID that was never allocated.
        pid: u32,
    },
    /// Scan bytes the caller holds, that no file on disk contains.
    ///
    /// # Why this is not [`Request::ScanPath`] with a memory buffer
    ///
    /// Because the two differ in the one thing the engine keys its report on.
    /// A path scan opens a file, and everything downstream — the file kind
    /// decided from the extension, the archive recursion, the quarantine of
    /// what was found — is rooted in there being a file to open, name and take.
    /// The caller here has bytes and a name somebody else chose; there is
    /// nothing to open and, if a detection comes back, nothing this service may
    /// move into a vault. A finding about content that came out of a running
    /// PowerShell session is a finding about *that session*, and the honest
    /// answer is a verdict with a name attached, not a file quarantine.
    ///
    /// # What asks this
    ///
    /// `av-amsi`, which is the whole reason the variant exists. Windows hands
    /// an AMSI provider the text a scripting host is about to run, after the
    /// host's own de-obfuscation — so a PowerShell one-liner assembled from
    /// string concatenation and Base64 arrives here as the command it resolves
    /// to, and no file on disk ever held those bytes. That content is exactly
    /// what neither of the other two scan requests can express.
    ///
    /// # The name is the caller's, and it is not trusted
    ///
    /// `name` is whatever the AMSI provider read out of
    /// `AMSI_ATTRIBUTE_CONTENT_NAME`. It is used for reporting and for nothing
    /// else — in particular it is never resolved as a path, so a name that
    /// looks like `..\..\Windows\System32\cmd.exe` is a string in a report and
    /// not a file this service will touch.
    ScanBuffer {
        /// What to call this content in a report. See the variant's own note on
        /// why this is not treated as a path.
        name: String,
        /// The bytes to examine.
        data: Vec<u8>,
    },
    /// List what is in the vault.
    QuarantineList {
        /// How many entries to return at most. `None` means the service's own
        /// cap, and a reply that was cut short says so.
        limit: Option<u32>,
    },
    /// Put a quarantined file back where it came from.
    QuarantineRestore {
        /// Which item.
        id: QuarantineId,
    },
    /// Destroy a quarantined file.
    ///
    /// The record is kept and the status changes to deleted, so the quarantine
    /// list can still say what happened to that file.
    QuarantineDelete {
        /// Which item.
        id: QuarantineId,
    },
    /// Put a quarantined file back, and stop the product taking it again.
    ///
    /// # Why this is not [`Request::QuarantineRestore`] with a flag
    ///
    /// Because restore and allow differ in what they mean, not in how much of
    /// the work they do. A restore says "these bytes belong at that path"; an
    /// allow says "and this is not a mistake". A user who restores a file and
    /// is then stopped from running it — refused by the driver, quarantined
    /// again by the same rule — has been given the file back and not the use of
    /// it, and that is the loop this request exists to end.
    ///
    /// The service restores first and allows second, and only if the restore
    /// worked: an allow for a path whose bytes are still in the vault would
    /// suppress the detection of a file that is not there, which is a rule
    /// switched off in exchange for nothing.
    QuarantineAllow {
        /// Which item.
        id: QuarantineId,
        /// Whether the path should be excluded for good, or only until the
        /// service next starts.
        ///
        /// `true` writes the path to `general.exclusions`, which is also what
        /// makes it survive; `false` holds it in the running service's memory
        /// and nothing else. Both take effect immediately — the two differ in
        /// what a restart does, not in what happens next.
        permanent: bool,
    },
    /// Read the configuration in force.
    ConfigGet,
    /// Replace the configuration.
    ///
    /// The reply reports what was written *and* which of the settings this
    /// build does not act on, so a caller learns that its change was stored but
    /// not honoured rather than believing it took effect.
    ConfigSet {
        /// The document to write.
        config: Box<AvConfig>,
    },
    /// Turn the user-mode filesystem watcher on or off.
    ///
    /// A narrower switch than [`Request::ConfigSet`] on purpose: a user
    /// clicking "pause protection" in a notification area is not editing a
    /// configuration file, and making the two the same operation is how a
    /// temporary pause becomes permanent.
    RealtimeSet {
        /// Whether it should be watching when the reply is sent.
        enabled: bool,
    },
}

impl Request {
    /// Which request this is, for error messages and correlation checks.
    pub const fn kind(&self) -> RequestKind {
        match self {
            Request::Status => RequestKind::Status,
            Request::ScanPath { .. } => RequestKind::ScanPath,
            Request::CancelScan { .. } => RequestKind::CancelScan,
            Request::ScanProcess { .. } => RequestKind::ScanProcess,
            Request::ScanBuffer { .. } => RequestKind::ScanBuffer,
            Request::QuarantineList { .. } => RequestKind::QuarantineList,
            Request::QuarantineRestore { .. } => RequestKind::QuarantineRestore,
            Request::QuarantineDelete { .. } => RequestKind::QuarantineDelete,
            Request::QuarantineAllow { .. } => RequestKind::QuarantineAllow,
            Request::ConfigGet => RequestKind::ConfigGet,
            Request::ConfigSet { .. } => RequestKind::ConfigSet,
            Request::RealtimeSet { .. } => RequestKind::RealtimeSet,
        }
    }

    /// The reply kind this request is answered by.
    ///
    /// Exhaustive, and the reason it exists as a separate function is that it
    /// is where "every request has an answer" is stated. A request added
    /// without a decision about its reply stops this build, rather than
    /// reaching a client that waits forever for something nothing will send.
    pub const fn expected_reply(&self) -> ReplyKind {
        match self {
            Request::Status => ReplyKind::Status,
            Request::ScanPath { .. } => ReplyKind::ScanStarted,
            Request::CancelScan { .. } => ReplyKind::ScanCancelled,
            Request::ScanProcess { .. } => ReplyKind::MemoryScan,
            Request::ScanBuffer { .. } => ReplyKind::BufferScan,
            Request::QuarantineList { .. } => ReplyKind::QuarantineList,
            // Restore, delete and allow are one reply kind because they are one
            // decision — the item's life changed, or it did not — and a caller
            // reading a list afterwards is what tells the three apart.
            Request::QuarantineRestore { .. }
            | Request::QuarantineDelete { .. }
            | Request::QuarantineAllow { .. } => ReplyKind::QuarantineChange,
            Request::ConfigGet | Request::ConfigSet { .. } => ReplyKind::Config,
            Request::RealtimeSet { .. } => ReplyKind::Realtime,
        }
    }
}

/// Which request a [`Request`] is, without the payload.
///
/// Exists so that an error message and a correlation check can name a request
/// without owning one; the same role
/// `av_driver_proto::wire::MessageKind` plays on the driver's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// [`Request::Status`].
    Status,
    /// [`Request::ScanPath`].
    ScanPath,
    /// [`Request::CancelScan`].
    CancelScan,
    /// [`Request::ScanProcess`].
    ScanProcess,
    /// [`Request::ScanBuffer`].
    ScanBuffer,
    /// [`Request::QuarantineList`].
    QuarantineList,
    /// [`Request::QuarantineRestore`].
    QuarantineRestore,
    /// [`Request::QuarantineDelete`].
    QuarantineDelete,
    /// [`Request::QuarantineAllow`].
    QuarantineAllow,
    /// [`Request::ConfigGet`].
    ConfigGet,
    /// [`Request::ConfigSet`].
    ConfigSet,
    /// [`Request::RealtimeSet`].
    RealtimeSet,
}

impl RequestKind {
    /// The word used in an error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            RequestKind::Status => "status",
            RequestKind::ScanPath => "scan-path",
            RequestKind::CancelScan => "cancel-scan",
            RequestKind::ScanProcess => "scan-process",
            RequestKind::ScanBuffer => "scan-buffer",
            RequestKind::QuarantineList => "quarantine-list",
            RequestKind::QuarantineRestore => "quarantine-restore",
            RequestKind::QuarantineDelete => "quarantine-delete",
            RequestKind::QuarantineAllow => "quarantine-allow",
            RequestKind::ConfigGet => "config-get",
            RequestKind::ConfigSet => "config-set",
            RequestKind::RealtimeSet => "realtime-set",
        }
    }
}

impl std::fmt::Display for RequestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The service's answer to one request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    /// Answers [`Request::Status`].
    Status(StatusReport),
    /// Answers [`Request::ScanPath`].
    ScanStarted(ScanStart),
    /// Answers [`Request::CancelScan`].
    ScanCancelled(ScanCancel),
    /// Answers [`Request::ScanProcess`], when it has finished.
    ///
    /// Boxed for the same reason [`Reply::Config`] is: a `MemoryReport` carries
    /// a list of detections, and an unboxed variant would make every `Reply` in
    /// the program as large as the largest one, down to the ones answered on
    /// every status request.
    MemoryScan(Box<MemoryReport>),
    /// Answers [`Request::ScanBuffer`].
    ///
    /// A report rather than a bare verdict, for the reason the request is not a
    /// path scan: what came back has to be able to say *why*. An AMSI provider
    /// that answered only "malicious" would leave a user with a PowerShell
    /// command that did not run and no way to find out what in it was
    /// objectionable, which is the difference between a product and an obstacle.
    /// The provider does not use most of this; a support engineer reading a log
    /// does.
    ///
    /// Boxed for the same reason [`Reply::MemoryScan`] is: the report carries a
    /// rule list, and an unboxed variant would size every `Reply` in the
    /// program to the largest one.
    BufferScan(Box<BufferScan>),
    /// Answers [`Request::QuarantineList`].
    QuarantineList(QuarantineListing),
    /// Answers [`Request::QuarantineRestore`] and [`Request::QuarantineDelete`].
    QuarantineChange(QuarantineChange),
    /// Answers [`Request::ConfigGet`] and [`Request::ConfigSet`].
    Config(Box<ConfigReport>),
    /// Answers [`Request::RealtimeSet`].
    Realtime(RealtimeState),
    /// Answers **any** request, when the service will not do what it asked.
    ///
    /// # Why this is one reply and not one per request
    ///
    /// There is exactly one reason a request is refused, and it is about the
    /// connection rather than about the question: the account on the other end
    /// may read and may not change the product's state. That rule lives in
    /// `av-service`'s `peer` module and applies to the requests that *change*
    /// something — release a quarantined file, delete one, allow one for good,
    /// and write a setting. The same sentence covers all of them, so the
    /// protocol carries one reply carrying that sentence rather than five
    /// variants each saying the same thing in the shape of its own payload.
    ///
    /// # Why a reply, and not a dropped connection
    ///
    /// The transport could have expressed a refusal by closing the pipe, and
    /// this deliberately does not: a front end that saw the connection go away
    /// could not tell "you are not allowed to do that" from "the antivirus
    /// crashed", and those two want opposite things from a user — stop trying,
    /// and restart the service. The reason travels as text for the same cause:
    /// whoever is refused should be able to read *why*, including which account
    /// they are and which one is allowed, which is what
    /// [`av_service::peer::Peer::reason`] writes.
    ///
    /// [`av_service::peer::Peer::reason`]: https://docs.rs/av-service
    Refused {
        /// A sentence for a person, naming the account and the rule.
        reason: String,
    },
}

impl Reply {
    /// Which reply this is.
    pub const fn kind(&self) -> ReplyKind {
        match self {
            Reply::Status(_) => ReplyKind::Status,
            Reply::ScanStarted(_) => ReplyKind::ScanStarted,
            Reply::ScanCancelled(_) => ReplyKind::ScanCancelled,
            Reply::MemoryScan(_) => ReplyKind::MemoryScan,
            Reply::BufferScan(_) => ReplyKind::BufferScan,
            Reply::QuarantineList(_) => ReplyKind::QuarantineList,
            Reply::QuarantineChange(_) => ReplyKind::QuarantineChange,
            Reply::Config(_) => ReplyKind::Config,
            Reply::Realtime(_) => ReplyKind::Realtime,
            Reply::Refused { .. } => ReplyKind::Refused,
        }
    }
}

/// Which reply a [`Reply`] is, without the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplyKind {
    /// [`Reply::Status`].
    Status,
    /// [`Reply::ScanStarted`].
    ScanStarted,
    /// [`Reply::ScanCancelled`].
    ScanCancelled,
    /// [`Reply::MemoryScan`].
    MemoryScan,
    /// [`Reply::BufferScan`].
    BufferScan,
    /// [`Reply::QuarantineList`].
    QuarantineList,
    /// [`Reply::QuarantineChange`].
    QuarantineChange,
    /// [`Reply::Config`].
    Config,
    /// [`Reply::Realtime`].
    Realtime,
    /// [`Reply::Refused`].
    ///
    /// The one kind that is not tied to a request: a [`Client`] accepts it as
    /// the answer to whatever it is waiting for, which is what makes a refusal
    /// expressible at all without five more variants.
    ///
    /// [`Client`]: crate::Client
    Refused,
}

impl ReplyKind {
    /// The word used in an error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReplyKind::Status => "status",
            ReplyKind::ScanStarted => "scan-started",
            ReplyKind::ScanCancelled => "scan-cancelled",
            ReplyKind::MemoryScan => "memory-scan",
            ReplyKind::BufferScan => "buffer-scan",
            ReplyKind::QuarantineList => "quarantine-list",
            ReplyKind::QuarantineChange => "quarantine-change",
            ReplyKind::Config => "config",
            ReplyKind::Realtime => "realtime",
            ReplyKind::Refused => "refused",
        }
    }
}

impl std::fmt::Display for ReplyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a scan started, or why it did not.
///
/// Two variants rather than a boolean and an optional string, because "it
/// started" and "it was refused" are answers to different questions and a
/// caller that read only the boolean would have to guess what the `None` meant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStart {
    /// The scan is running. Progress events follow.
    Started {
        /// The identifier to watch for and to cancel with.
        id: ScanId,
        /// Where it is scanning.
        path: PathBuf,
    },
    /// The scan was not started.
    Refused {
        /// What was asked for.
        path: PathBuf,
        /// Why not, in a sentence a user can read.
        reason: String,
    },
}

/// What a cancel did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanCancel {
    /// The scan was running and has been asked to stop. The
    /// [`Event::ScanFinished`] that follows carries `cancelled`.
    Requested {
        /// Which scan.
        id: ScanId,
    },
    /// There was no such scan, which is the honest answer to a cancel that
    /// arrived after the scan had already finished.
    Unknown {
        /// Which scan was named.
        id: ScanId,
    },
}

/// What happened to a quarantined item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineChange {
    /// The bytes were written back.
    Restored {
        /// Which item.
        id: QuarantineId,
        /// Where they were written.
        path: PathBuf,
    },
    /// The bytes were written back and the path will not be scanned again.
    ///
    /// Answers [`Request::QuarantineAllow`], and distinct from
    /// [`QuarantineChange::Restored`] because the caller has something
    /// different to say about it: a restore is a file put back, and this is a
    /// file put back *and* a rule switched off for it.
    Allowed {
        /// Which item.
        id: QuarantineId,
        /// Where the bytes were written.
        path: PathBuf,
        /// Whether the exclusion will survive the service being restarted.
        ///
        /// True only when it was written to the configuration and the write
        /// succeeded. A caller that asked for a permanent allow and gets
        /// `false` is looking at an allow that holds for now and will be gone
        /// after a restart, which is a thing the user needs to be told rather
        /// than a failure to report: the file *is* back and *is* allowed.
        lasting: bool,
    },
    /// The bytes were destroyed and the record kept.
    Deleted {
        /// Which item.
        id: QuarantineId,
    },
    /// Nothing happened.
    Failed {
        /// Which item.
        id: QuarantineId,
        /// Why, in a sentence a user can read.
        reason: String,
    },
}

impl QuarantineChange {
    /// Which item this is about.
    ///
    /// Every variant carries one. A caller that wants to name the item in a
    /// message — or to look it up in its own listing before the change has been
    /// reflected there — would otherwise match on all four variants to read the
    /// same field out of each, and a fifth variant would then be a compile error
    /// in every such caller rather than in one place.
    pub fn id(&self) -> QuarantineId {
        match self {
            Self::Restored { id, .. }
            | Self::Allowed { id, .. }
            | Self::Deleted { id }
            | Self::Failed { id, .. } => *id,
        }
    }
}

/// Something the service decided a client should know, sent without being
/// asked.
///
/// This is the half of the protocol that carries the product's behaviour: the
/// notification in the corner of the screen, the progress bar, and the moment a
/// scan ends. Every variant here has to be handled by a client, because none of
/// them is a refinement of another — see this module's documentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// Something was found, and something was done about it.
    ///
    /// Everything the notification needs is in here, including the phase, so
    /// that the wording is not reconstructed somewhere else out of parts — see
    /// [`Detection`] and [`crate::detect::Phase`].
    Detection(Detection),
    /// How a running scan is getting on.
    ScanProgress(ScanProgress),
    /// A scan ended.
    ScanFinished(ScanFinished),
    /// The service's own state changed, or its picture of it did.
    ///
    /// Carries a whole [`StatusReport`] rather than a diff, because a client
    /// that missed one of these has no way to reconcile a diff with what it
    /// last saw, and status is small.
    StatusChanged(StatusReport),
    /// The kernel driver reported something.
    ///
    /// Passed through rather than interpreted: this is the driver's vocabulary
    /// arriving at a client that can display it, and the service is not a
    /// translator with opinions.
    Driver(DriverEvent),
}

/// A scan ended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanFinished {
    /// Which scan.
    pub id: ScanId,
    /// What it found and what it did.
    pub summary: ScanSummary,
}

/// One thing the driver reported.
///
/// A translated form of `av_driver_proto::wire::EventMessage`, and translated
/// rather than passed through as bytes for two reasons: the kernel structure is
/// a fixed 2120-byte layout with a `[u16; 1024]` path array that no
/// serialisation format can carry directly, and a client should not have to
/// know what `path_units` means to read a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverEvent {
    /// Monotonic within one driver load. A gap means the service missed events.
    pub sequence: u64,
    /// When it happened, in 100-nanosecond units since 1601-01-01, which is
    /// what the driver has without converting and what a client can render.
    pub timestamp_100ns: u64,
    /// What happened.
    pub action: DriverEventAction,
    /// What it happened to.
    pub subject: DriverSubject,
    /// The path, when the event names one.
    pub path: Option<PathBuf>,
    /// The process responsible, when there is one.
    pub process_id: u32,
    /// The process that created [`DriverEvent::process_id`], for a process
    /// start. Zero for every other action, and for a creation whose parent has
    /// already exited.
    ///
    /// Carried rather than looked up later by the consumer: `parent_process_id`
    /// is only knowable at creation time, and the creating process may be gone
    /// before anything reads the report.
    pub parent_process_id: u32,
    /// The thread responsible, when there is one.
    pub thread_id: u32,
    /// Action-specific detail. Meaningless without [`DriverEvent::action`],
    /// which is what says whether it is a lost-event count, a driver state or a
    /// byte count.
    pub detail: u32,
    /// The driver's own status picture, for the events that carry one.
    pub driver_state: Option<DriverStatus>,
}

/// What the driver did.
///
/// The names are `av_driver_proto::event::EventAction`'s, and the mapping is
/// exhaustive in `av-service` so that a new action on the driver's side stops
/// the build rather than being dropped. The one variant that is not the
/// driver's own is [`DriverEventAction::Unrecognised`], which exists because a
/// driver built against a later protocol sends an action this build has never
/// heard of, and a code is a better answer than silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriverEventAction {
    /// A process creation or a file execution was refused before it happened.
    ExecutionBlocked,
    /// Something was written to a file the rules care about.
    FileWritten,
    /// An image was mapped into a process.
    ImageLoaded,
    /// A process was created.
    ///
    /// Not [`DriverEventAction::ImageLoaded`]: that one describes a mapping
    /// into a process that already exists, and this one describes the process
    /// itself coming into being. It is the same distinction the driver's own
    /// enum draws, and for the same reason — the sentence a reader builds is
    /// made from the action.
    ProcessStarted,
    /// A write was refused.
    WriteBlocked,
    /// The driver is alive.
    Heartbeat,
    /// The driver's state changed, or the service connected or disconnected.
    StateChanged,
    /// The driver's event queue overflowed.
    EventsDropped,
    /// A file was renamed or moved, reported since 2026-10-18.
    ///
    /// `path` is the **new** name when the driver could resolve it. `detail` is
    /// 1 when it could not — a rename relative to a directory handle — and the
    /// path is then the old name.
    FileRenamed,
    /// A delete was requested on a file, reported since 2026-10-18.
    ///
    /// "A delete was asked for", not "the file is gone": the file goes when the
    /// last handle closes, which may be after the event and may be never.
    FileDeleted,
    /// A registry key or value changed, reported since 2026-10-18.
    ///
    /// `detail` says which change: 1 a key was created, 2 a key was deleted, 3 a
    /// value was set, 4 a value was deleted, 5 a key was renamed. The codes are
    /// `av_driver_proto::event::EventAction`'s `REGISTRY_*` constants.
    RegistryChanged,
    /// An action code this build does not define, carried rather than dropped.
    Unrecognised {
        /// The wire code, so a reader can log it and a later build can name it.
        code: u32,
    },
}

impl DriverEventAction {
    /// True when this is a refusal, and therefore worth a user's attention.
    ///
    /// The driver's own `EventAction::is_blocking_event`, restated here because
    /// the notification layer reads this enum and not the driver's, and the two
    /// have to agree — a test in `av-service` pins the mapping.
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            DriverEventAction::ExecutionBlocked | DriverEventAction::WriteBlocked
        )
    }
}

/// What the driver was talking about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriverSubject {
    /// A file being opened, written or executed.
    File,
    /// A process being created.
    Process,
    /// An image being loaded into an existing process.
    Image,
    /// The driver itself.
    Driver,
    /// The driver's own self-protection: a registration it made in order to
    /// defend this product, rather than something it observed.
    ///
    /// Separate from [`DriverSubject::Driver`] because the two carry different
    /// statuses about different mechanisms — the process-start notification and
    /// the object callbacks — and a report that could not say which had failed
    /// would send an operator to look at the wrong one.
    Protection,
    /// What the driver answered when this service sent it a configuration.
    ///
    /// # Why this is a subject of its own
    ///
    /// It is the one `DriverSubject` **no driver sends**: the wire has no code
    /// for it, and `crate::driver::translate` — which maps codes the driver
    /// sends onto this enum — therefore never produces it. It is made in
    /// `av-service`'s filter-port thread, from the reply the driver gives to a
    /// [`crate::DriverSubject::Protection`]-shaped question: *did you apply the
    /// self-protection I just asked you to arm?*
    ///
    /// It is separate from [`DriverSubject::Protection`] for the reason that one
    /// is separate from [`DriverSubject::Driver`]: both are `NTSTATUS` values
    /// about protection, and they are different mechanisms that fail
    /// independently. `Protection` is what the driver says about the object
    /// callbacks it registered at load; this is what it says about the write gate
    /// *this connection* asked it to arm. One slot holding "the last protection
    /// status" would report whichever arrived last as the state of both — and a
    /// driver whose callbacks registered while its write gate was refused (or the
    /// reverse) would read as fully protecting this product.
    ///
    /// A subject that names a *question this service asked* rather than
    /// something the driver observed is a kind of thing this enum did not have
    /// before. It is here rather than in a new field on [`DriverEvent`] because
    /// every consumer already reads `subject`, and a second field that only one
    /// producer fills is a field every match has to be extended for anyway.
    Configuration,
    /// A registry key or value, reported since 2026-10-18.
    ///
    /// Separate from [`DriverSubject::File`] because the `path` is in a
    /// different namespace — `\REGISTRY\MACHINE\...`, not a DOS path. For the
    /// two value classes the path is the key path with `\` and the value name
    /// appended, which is how `regedit` spells one.
    Registry,
    /// A subject code this build does not define.
    Unrecognised {
        /// The wire code.
        code: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::tests::sample_detection;
    use crate::report::tests::{sample_status, sample_summary};

    /// One of every request, so a test that must cover them all can.
    fn every_request() -> Vec<Request> {
        vec![
            Request::Status,
            Request::ScanPath {
                path: PathBuf::from(r"C:\Users\me\Downloads"),
                options: ScanOptions::default(),
            },
            Request::CancelScan { id: ScanId::new(1) },
            Request::QuarantineList { limit: Some(50) },
            Request::QuarantineRestore {
                id: QuarantineId::new(),
            },
            Request::QuarantineDelete {
                id: QuarantineId::new(),
            },
            Request::ConfigGet,
            Request::ConfigSet {
                config: Box::new(AvConfig::default()),
            },
            Request::RealtimeSet { enabled: false },
        ]
    }

    /// One of every reply.
    fn every_reply() -> Vec<Reply> {
        vec![
            Reply::Status(sample_status()),
            Reply::ScanStarted(ScanStart::Started {
                id: ScanId::new(1),
                path: PathBuf::from(r"C:\tmp"),
            }),
            Reply::ScanCancelled(ScanCancel::Unknown { id: ScanId::new(9) }),
            Reply::QuarantineList(QuarantineListing {
                entries: Vec::new(),
                total: 0,
                omitted: 0,
            }),
            Reply::QuarantineChange(QuarantineChange::Deleted {
                id: QuarantineId::new(),
            }),
            Reply::Config(Box::new(ConfigReport {
                config: Box::new(AvConfig::default()),
                load_error: None,
                unhonoured: Vec::new(),
                handled_elsewhere: Vec::new(),
            })),
            Reply::Realtime(RealtimeState {
                enabled: false,
                watching: false,
                roots: Vec::new(),
                disabled_by: Some("realtime.enabled is false".to_string()),
                disclosures: Vec::new(),
                lost_roots: Vec::new(),
                missed: None,
            }),
        ]
    }

    /// One of every event.
    fn every_event() -> Vec<Event> {
        vec![
            Event::Detection(sample_detection()),
            Event::ScanProgress(ScanProgress {
                id: ScanId::new(1),
                scanned: 10,
                total: Some(100),
                current: Some(PathBuf::from(r"C:\tmp\a.exe")),
                detections: 1,
                bytes: 4096,
            }),
            Event::ScanFinished(ScanFinished {
                id: ScanId::new(1),
                summary: sample_summary(),
            }),
            Event::StatusChanged(sample_status()),
            Event::Driver(DriverEvent {
                sequence: 4,
                timestamp_100ns: 133_000_000_000_000_000,
                action: DriverEventAction::ExecutionBlocked,
                subject: DriverSubject::Process,
                path: Some(PathBuf::from(r"C:\Users\me\evil.exe")),
                process_id: 1234,
                parent_process_id: 1200,
                thread_id: 5678,
                detail: 0,
                driver_state: None,
            }),
        ]
    }

    #[test]
    fn every_message_survives_the_round_trip_exactly() {
        // The whole vocabulary, through header and body and back. Not a
        // spot check: a variant that loses a field on the way is a notification
        // that says the wrong thing, and this is the only place that can catch
        // it for the variants no other test builds.
        let mut messages = Vec::new();
        for request in every_request() {
            messages.push(Message::Request(RequestId::new(1), request));
        }
        for reply in every_reply() {
            messages.push(Message::Reply(RequestId::new(2), reply));
        }
        for event in every_event() {
            messages.push(Message::Event(event));
        }
        assert!(messages.len() >= 20, "the vocabulary shrank");
        for message in messages {
            let payload = message.encode().expect("encodes");
            let decoded = Message::decode(&payload).expect("decodes");
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn every_request_expects_the_reply_that_answers_it() {
        // The correlation table, checked against itself: a request and a reply
        // built from the same intent must agree about which is which, and this
        // is what makes `WrongReply` meaningful rather than decorative.
        let pairs: Vec<(Request, Reply)> = vec![
            (Request::Status, Reply::Status(sample_status())),
            (
                Request::ScanPath {
                    path: PathBuf::from("x"),
                    options: ScanOptions::default(),
                },
                Reply::ScanStarted(ScanStart::Refused {
                    path: PathBuf::from("x"),
                    reason: "no".into(),
                }),
            ),
            (
                Request::CancelScan { id: ScanId::new(1) },
                Reply::ScanCancelled(ScanCancel::Unknown { id: ScanId::new(1) }),
            ),
            (
                Request::QuarantineList { limit: None },
                Reply::QuarantineList(QuarantineListing {
                    entries: Vec::new(),
                    total: 0,
                    omitted: 0,
                }),
            ),
            (
                Request::QuarantineRestore {
                    id: QuarantineId::new(),
                },
                Reply::QuarantineChange(QuarantineChange::Deleted {
                    id: QuarantineId::new(),
                }),
            ),
            (
                Request::QuarantineDelete {
                    id: QuarantineId::new(),
                },
                Reply::QuarantineChange(QuarantineChange::Deleted {
                    id: QuarantineId::new(),
                }),
            ),
            (
                Request::ConfigGet,
                Reply::Config(Box::new(ConfigReport {
                    config: Box::new(AvConfig::default()),
                    load_error: None,
                    unhonoured: Vec::new(),
                    handled_elsewhere: Vec::new(),
                })),
            ),
            // A write is answered with the configuration now in force, which is
            // the same reply `ConfigGet` gets and deliberately so: the caller
            // that has just written a setting is the caller that most needs to
            // be told what is actually in force.
            (
                Request::ConfigSet {
                    config: Box::new(AvConfig::default()),
                },
                Reply::Config(Box::new(ConfigReport {
                    config: Box::new(AvConfig::default()),
                    load_error: None,
                    unhonoured: Vec::new(),
                    handled_elsewhere: Vec::new(),
                })),
            ),
            (
                Request::RealtimeSet { enabled: true },
                Reply::Realtime(RealtimeState {
                    enabled: true,
                    watching: true,
                    roots: Vec::new(),
                    disabled_by: None,
                    disclosures: Vec::new(),
                    lost_roots: Vec::new(),
                    missed: None,
                }),
            ),
        ];
        // Every request in the vocabulary is in the table above, and every
        // reply. Clippy's `iter_over_hash_type` is the reason the kinds are
        // compared as sorted vectors rather than through a map.
        let mut expected: Vec<RequestKind> =
            pairs.iter().map(|(request, _)| request.kind()).collect();
        expected.sort_by_key(|kind| kind.as_str());
        expected.dedup();
        let mut actual: Vec<RequestKind> = every_request().iter().map(Request::kind).collect();
        actual.sort_by_key(|kind| kind.as_str());
        actual.dedup();
        assert_eq!(actual, expected, "a request is missing from the table");

        // `Refused` is the one kind this pairing cannot carry, and it is added
        // by hand on both sides for a reason rather than to make the assertion
        // pass: every other kind is the answer to one particular request and is
        // therefore *paired* below, while a refusal answers whatever was asked
        // and has no row to sit in. Both sides get it so that the comparison
        // still covers the whole vocabulary — a table that merely omitted it
        // would stop covering the vocabulary the moment the variant was added,
        // which is the failure this test exists to prevent. That a refusal is
        // *accepted* as the answer to any request is asserted in `session.rs`,
        // where the rule that makes it work lives.
        let mut reply_kinds: Vec<ReplyKind> = pairs.iter().map(|(_, reply)| reply.kind()).collect();
        reply_kinds.push(ReplyKind::Refused);
        reply_kinds.sort_by_key(|kind| kind.as_str());
        reply_kinds.dedup();
        let mut every: Vec<ReplyKind> = every_reply().iter().map(Reply::kind).collect();
        every.push(ReplyKind::Refused);
        every.sort_by_key(|kind| kind.as_str());
        every.dedup();
        assert_eq!(every, reply_kinds, "a reply is missing from the table");

        for (request, reply) in pairs {
            assert_eq!(
                reply.kind(),
                request.expected_reply(),
                "a {request:?} answered by a {reply:?}"
            );
        }
    }

    #[test]
    fn a_body_with_a_variant_this_build_does_not_have_is_an_error_and_not_a_panic() {
        // The decoding side of "exhaustive on purpose": a peer from a later
        // build sends a variant index that does not exist here. bincode rejects
        // it rather than transmuting it, and the rejection is an ordinary
        // decode failure a server can answer by closing one connection.
        let payload = Message::Request(RequestId::new(1), Request::Status)
            .encode()
            .expect("encodes");
        let mut forged = payload.clone();
        // The body's first four bytes are the variant index of `Request`.
        forged[crate::wire::HEADER_BYTES..crate::wire::HEADER_BYTES + 4]
            .copy_from_slice(&9_999u32.to_le_bytes());
        assert!(matches!(Message::decode(&forged), Err(IpcError::Body(_))));
        // And the same for a reply.
        let payload = Message::Reply(
            RequestId::new(1),
            Reply::Config(Box::new(ConfigReport {
                config: Box::new(AvConfig::default()),
                load_error: None,
                unhonoured: Vec::new(),
                handled_elsewhere: Vec::new(),
            })),
        )
        .encode()
        .expect("encodes");
        let mut forged = payload;
        forged[crate::wire::HEADER_BYTES..crate::wire::HEADER_BYTES + 4]
            .copy_from_slice(&9_999u32.to_le_bytes());
        assert!(matches!(Message::decode(&forged), Err(IpcError::Body(_))));
    }

    #[test]
    fn a_body_with_bytes_left_over_is_refused() {
        // The frame length and the body's own length are two independent
        // numbers, and the leftover room is where a second message hides.
        let mut payload = Message::Request(RequestId::new(1), Request::Status)
            .encode()
            .expect("encodes");
        payload.extend_from_slice(b"smuggled");
        assert!(matches!(
            Message::decode(&payload),
            Err(IpcError::TrailingBytes { trailing: 8 })
        ));
    }

    #[test]
    fn a_request_or_reply_with_correlation_zero_is_refused() {
        // Zero is an event's correlation. A request carrying it has no place in
        // any exchange, and answering it would be answering nobody.
        let payload = Message::Request(RequestId::new(1), Request::Status)
            .encode()
            .expect("encodes");
        let mut zeroed = payload;
        zeroed[16..24].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            Message::decode(&zeroed),
            Err(IpcError::MissingCorrelation)
        ));
    }

    #[test]
    fn an_event_carries_no_correlation_and_several_can_follow_one_request() {
        // The reason correlation exists at all: the pipe interleaves. An event
        // between a request and its reply is normal, not a protocol error.
        let event = Message::Event(Event::ScanProgress(ScanProgress {
            id: ScanId::new(1),
            scanned: 1,
            total: None,
            current: None,
            detections: 0,
            bytes: 0,
        }));
        assert_eq!(event.correlation(), RequestId::NONE);
        assert_eq!(event.kind(), MessageKind::Event);
        assert_eq!(
            Message::Request(RequestId::new(5), Request::Status).correlation(),
            RequestId::new(5)
        );
        assert_eq!(
            Message::Reply(RequestId::new(5), Reply::Status(sample_status())).correlation(),
            RequestId::new(5)
        );
    }

    #[test]
    fn the_driver_vocabulary_agrees_with_itself_about_what_a_block_is() {
        // `av-service` maps `av_driver_proto::event::EventAction` onto this
        // enum; the property that has to survive the mapping is which actions
        // are refusals, because that is what a notification is built from.
        assert!(DriverEventAction::ExecutionBlocked.is_blocking());
        assert!(DriverEventAction::WriteBlocked.is_blocking());
        assert!(!DriverEventAction::FileWritten.is_blocking());
        assert!(!DriverEventAction::Heartbeat.is_blocking());
        assert!(!DriverEventAction::ImageLoaded.is_blocking());
        // A process coming into being is not a refusal. The driver could refuse
        // one — `PS_CREATE_NOTIFY_INFO::CreationStatus` is a real lever — and
        // deliberately does not, so nothing that reads this enum may report it
        // as a block.
        assert!(!DriverEventAction::ProcessStarted.is_blocking());
        assert!(!DriverEventAction::StateChanged.is_blocking());
        assert!(!DriverEventAction::EventsDropped.is_blocking());
        // An action this build does not know is not a refusal. Claiming one
        // would be inventing a block the driver never reported.
        assert!(!DriverEventAction::Unrecognised { code: 4242 }.is_blocking());
    }
}
