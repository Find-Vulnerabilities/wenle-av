//! The state machine each end of the pipe runs.
//!
//! # What a state machine is doing in a protocol crate
//!
//! The framing and the vocabulary are not where a control protocol goes wrong.
//! What goes wrong is the bookkeeping around them, and every one of those
//! mistakes has the same shape: something that should have been refused was
//! accepted, and the two ends disagreed about what had happened.
//!
//! * A service that answers a request twice leaves a client that reads
//!   messages in order holding somebody else's answer, and every reply after
//!   that is off by one.
//! * A client that accepts a reply for a request it never sent has been
//!   desynchronised by something, and the reply it accepts next is the one that
//!   matters.
//! * A service that accepts a repeated request identifier runs the request
//!   twice. For [`crate::Request::QuarantineDelete`] that is not a no-op, and
//!   for [`crate::Request::ScanPath`] it is two scans of the same tree.
//! * A reply arriving for a request whose *kind* it does not answer — a
//!   `QuarantineList` answering a `Status` — is the two ends having drifted,
//!   and the drift is invisible if nobody checks.
//!
//! Each of those is a rule below, each has a named error, and each has a test.
//! That is the whole reason these two types exist rather than a pair of free
//! functions that write and read a message.
//!
//! # What is deliberately not here
//!
//! Timeouts. A client that waits forever for a reply it will never get is a
//! real problem, and the answer is not a timeout constant in a protocol crate —
//! it is the caller's, because the right value depends on what was asked
//! (`Status` and `ScanPath` have nothing in common) and on whether the caller
//! has anything else to do meanwhile. [`Client::recv`] blocks; a caller that
//! cannot afford to block runs it on a thread, which is what `av-service` does.

use std::collections::BTreeMap;

use crate::error::IpcError;
use crate::message::{Event, Message, Reply, ReplyKind, Request};
use crate::transport::{Connection, Read};
use crate::wire::{Decoder, RequestId};

/// How many requests a service will hold unanswered before it stops reading.
///
/// A bound the *peer* chooses the size of, which is why it exists. A client
/// that sends a thousand requests without reading a single reply would
/// otherwise make the service hold a thousand expected-reply entries and a
/// thousand decoded requests; the honest answer is to refuse the thousandth and
/// let the client notice, rather than to grow until something else fails.
///
/// Generous, because the legitimate case is a client that pipelines — asking
/// for status, the quarantine list and a config read before reading any of
/// them — and three or four is the realistic number.
pub const MAX_OUTSTANDING_REQUESTS: usize = 1024;

/// How many bytes are read from the transport at a time.
///
/// A frame is reassembled across reads anyway, so this is not a frame size and
/// does not need to be large. Eight kilobytes is four pages: enough that a
/// status reply or a small listing arrives in one read on a real pipe, and
/// small enough to sit on a thread's stack.
const READ_CHUNK_BYTES: usize = 8192;

/// What arrived at a client.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// The answer to one of this client's requests.
    Reply {
        /// Which request it answers.
        id: RequestId,
        /// The answer.
        reply: Reply,
    },
    /// Something the service decided to say.
    Event(Event),
}

/// A client's half of the protocol.
#[derive(Debug)]
pub struct Client<C: Connection> {
    connection: C,
    decoder: Decoder,
    /// The next identifier to use, or `None` once they are all gone.
    next_id: Option<RequestId>,
    /// Requests sent and not yet answered, with the reply kind each expects.
    outstanding: BTreeMap<RequestId, ReplyKind>,
    closed: bool,
}

impl<C: Connection> Client<C> {
    /// Wrap a connection.
    pub fn new(connection: C) -> Self {
        Self {
            connection,
            decoder: Decoder::new(),
            next_id: Some(RequestId::FIRST),
            outstanding: BTreeMap::new(),
            closed: false,
        }
    }

    /// The transport underneath, for a caller that needs to configure it.
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Send a request and get the identifier its reply will carry.
    pub fn send(&mut self, request: Request) -> Result<RequestId, IpcError> {
        let id = self.next_id.ok_or(IpcError::RequestIdsExhausted)?;
        let expected = request.expected_reply();
        let frame = Message::Request(id, request).encode_framed()?;
        self.connection.write_frame(&frame)?;
        // Recorded only after the write succeeded: a request that never left
        // this process has no reply coming, and waiting for one would be
        // waiting for something that does not exist.
        self.outstanding.insert(id, expected);
        self.next_id = id.next();
        Ok(id)
    }

    /// Block until something arrives, and take everything that arrived with it.
    ///
    /// Returns an empty vector when the transport handed over no bytes without
    /// closing, which a blocking pipe never does — it is there for a
    /// non-blocking transport and for the in-memory loopback this crate's tests
    /// run on. [`IpcError::PeerClosed`] means there will never be another
    /// message.
    pub fn recv(&mut self) -> Result<Vec<Incoming>, IpcError> {
        let messages = self.read_batch()?;
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            out.push(self.accept(message)?);
        }
        Ok(out)
    }

    /// Check one message and turn it into something a caller can use.
    ///
    /// This is the client half of the bookkeeping: an event is always welcome,
    /// and a reply has to be one this client is waiting for and of the kind the
    /// request asked for.
    fn accept(&mut self, message: Message) -> Result<Incoming, IpcError> {
        match message {
            Message::Event(event) => Ok(Incoming::Event(event)),
            Message::Reply(id, reply) => {
                let expected = self
                    .outstanding
                    .get(&id)
                    .copied()
                    .ok_or(IpcError::UnexpectedReply { id })?;
                let actual = reply.kind();
                // A refusal is the one reply that answers any request: it is
                // the service saying "not from this account", which is a fact
                // about the connection rather than about the question, so there
                // is no request whose expected kind it could be. It is still
                // checked against the request being answered — an identifier
                // nobody is waiting for is a protocol error either way — and it
                // is *not* checked against the kind, because refusing is the
                // one thing that is always in the vocabulary.
                if actual != expected && actual != ReplyKind::Refused {
                    return Err(IpcError::WrongReply {
                        id,
                        expected,
                        actual,
                    });
                }
                // Removed before the caller sees it: the reply is answered, and
                // a second one for the same identifier is now rejected rather
                // than silently replacing this one.
                self.outstanding.remove(&id);
                Ok(Incoming::Reply { id, reply })
            }
            // A client has no business receiving a request. If one arrives, the
            // peer believes it is a service and is not, and carrying on would
            // mean answering a question this end was never asked.
            Message::Request(_, request) => Err(IpcError::NotAServiceMessage {
                kind: request.kind(),
            }),
        }
    }

    /// Read until at least one message completes.
    fn read_batch(&mut self) -> Result<Vec<Message>, IpcError> {
        if self.closed {
            return Err(IpcError::PeerClosed);
        }
        let mut buf = [0u8; READ_CHUNK_BYTES];
        loop {
            match self.connection.read_chunk(&mut buf)? {
                Read::Bytes(0) => return Ok(Vec::new()),
                Read::Bytes(read) => {
                    let messages = self.decoder.push(&buf[..read])?;
                    if !messages.is_empty() {
                        return Ok(messages);
                    }
                    // A partial frame: keep reading.
                }
                Read::Closed => {
                    self.closed = true;
                    return Err(IpcError::PeerClosed);
                }
            }
        }
    }

    /// How many requests are sent and unanswered.
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// True when a reply for `id` is still expected.
    pub fn is_waiting_for(&self, id: RequestId) -> bool {
        self.outstanding.contains_key(&id)
    }

    /// Bytes of a partial frame the decoder is holding.
    pub fn buffered_bytes(&self) -> usize {
        self.decoder.buffered_bytes()
    }

    /// True once the peer has closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// A service's half of the protocol.
#[derive(Debug)]
pub struct Server<C: Connection> {
    connection: C,
    decoder: Decoder,
    /// The highest request identifier seen, so that a repeat is detectable
    /// without remembering every identifier that has ever arrived.
    highest: RequestId,
    /// Requests received and not yet answered.
    awaiting: BTreeMap<RequestId, ReplyKind>,
    closed: bool,
}

impl<C: Connection> Server<C> {
    /// Wrap a connection.
    pub fn new(connection: C) -> Self {
        Self {
            connection,
            decoder: Decoder::new(),
            highest: RequestId::NONE,
            awaiting: BTreeMap::new(),
            closed: false,
        }
    }

    /// The transport underneath.
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Block until at least one request arrives.
    ///
    /// `Ok` with an empty vector means the transport handed over nothing and
    /// did not close — see [`Client::recv`].
    pub fn recv(&mut self) -> Result<Vec<(RequestId, Request)>, IpcError> {
        let messages = self.read_batch()?;
        let mut out = Vec::with_capacity(messages.len());
        for message in messages {
            out.push(self.accept(message)?);
        }
        Ok(out)
    }

    fn accept(&mut self, message: Message) -> Result<(RequestId, Request), IpcError> {
        match message {
            Message::Request(id, request) => {
                // Strictly increasing, and the reason it is a rule rather than
                // a set of seen identifiers is that the set is unbounded state
                // whose size the peer chooses. A client numbers upward by
                // construction — see `Client::send` — so this costs a legitimate
                // client nothing and costs a hostile one the ability to make the
                // service allocate.
                if id <= self.highest && !self.highest.is_none() {
                    return Err(IpcError::RequestIdNotIncreasing {
                        id,
                        last: self.highest,
                    });
                }
                if self.awaiting.len() >= MAX_OUTSTANDING_REQUESTS {
                    return Err(IpcError::TooManyOutstanding {
                        max: MAX_OUTSTANDING_REQUESTS,
                    });
                }
                self.highest = id;
                self.awaiting.insert(id, request.expected_reply());
                Ok((id, request))
            }
            // A reply or an event travelling towards the service is the two
            // ends disagreeing about which one is the service.
            other => Err(IpcError::WrongDirection { kind: other.kind() }),
        }
    }

    /// Answer a request.
    ///
    /// Refuses a reply for a request this service does not have outstanding,
    /// which is both "never arrived" and "already answered" — and the second is
    /// the one that matters, because a second reply is what desynchronises a
    /// client for the rest of the connection.
    pub fn reply(&mut self, id: RequestId, reply: Reply) -> Result<(), IpcError> {
        let expected = self
            .awaiting
            .get(&id)
            .copied()
            .ok_or(IpcError::UnknownRequest { id })?;
        let actual = reply.kind();
        // The other half of the client's rule: a refusal is a legitimate answer
        // to any outstanding request, so a service can send one through the same
        // door as every other reply instead of needing a second one. The
        // identifier is still checked — see the client's `accept` for why — and
        // what is skipped is only the pairing of a question with its kind.
        if actual != expected && actual != ReplyKind::Refused {
            return Err(IpcError::WrongReply {
                id,
                expected,
                actual,
            });
        }
        let frame = Message::Reply(id, reply).encode_framed()?;
        self.connection.write_frame(&frame)?;
        self.awaiting.remove(&id);
        Ok(())
    }

    /// Tell the client something it did not ask about.
    ///
    /// Always allowed, and never correlated: an event is not an answer, and a
    /// client has nothing to match it against.
    pub fn publish(&mut self, event: &Event) -> Result<(), IpcError> {
        let frame = Message::Event(event.clone()).encode_framed()?;
        self.connection.write_frame(&frame)
    }

    /// How many requests are received and unanswered.
    pub fn awaiting(&self) -> usize {
        self.awaiting.len()
    }

    /// The highest request identifier seen.
    pub fn highest_request(&self) -> RequestId {
        self.highest
    }

    /// Bytes of a partial frame the decoder is holding.
    pub fn buffered_bytes(&self) -> usize {
        self.decoder.buffered_bytes()
    }

    /// True once the peer has closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn read_batch(&mut self) -> Result<Vec<Message>, IpcError> {
        if self.closed {
            return Err(IpcError::PeerClosed);
        }
        let mut buf = [0u8; READ_CHUNK_BYTES];
        loop {
            match self.connection.read_chunk(&mut buf)? {
                Read::Bytes(0) => return Ok(Vec::new()),
                Read::Bytes(read) => {
                    let messages = self.decoder.push(&buf[..read])?;
                    if !messages.is_empty() {
                        return Ok(messages);
                    }
                }
                Read::Closed => {
                    self.closed = true;
                    return Err(IpcError::PeerClosed);
                }
            }
        }
    }
}

/// One of every request, for the tests that must cover them all.
#[cfg(test)]
pub(crate) fn sample_requests() -> Vec<Request> {
    use std::path::PathBuf;

    use av_core::config::AvConfig;
    use av_core::scan::ScanOptions;
    use av_quarantine::QuarantineId;

    use crate::report::ScanId;

    vec![
        Request::Status,
        Request::ScanPath {
            path: PathBuf::from(r"C:\Users\me\Downloads"),
            options: ScanOptions::default(),
        },
        Request::CancelScan { id: ScanId::new(1) },
        Request::ScanProcess { pid: 4242 },
        Request::ScanBuffer {
            // A name with no path in it and bytes that are plainly not a file,
            // because that is what this request carries in production: content
            // out of a scripting host's memory.
            //
            // The script is deliberately dull, and that is not incidental. A
            // fixture holding a real download-and-run one-liner is a test
            // binary this machine's own anti-malware quarantines on sight, and
            // os error 225 takes down every test in the file from there on.
            // What this needs is bytes that parse as script, not bytes that are
            // dangerous.
            name: "Script Block".to_string(),
            data: b"Get-ChildItem -Path C:\\Users -Recurse | Measure-Object".to_vec(),
        },
        Request::QuarantineList { limit: None },
        Request::QuarantineRestore {
            id: QuarantineId::new(),
        },
        Request::QuarantineDelete {
            id: QuarantineId::new(),
        },
        // Both flags, because the one bit in this request decides whether the
        // exclusion is written to the configuration or held in the running
        // service's memory, and the two encode differently. A sample that only
        // ever built one of them would leave the other's encoding covered by
        // nothing.
        Request::QuarantineAllow {
            id: QuarantineId::new(),
            permanent: true,
        },
        Request::QuarantineAllow {
            id: QuarantineId::new(),
            permanent: false,
        },
        Request::ConfigGet,
        Request::ConfigSet {
            config: Box::new(AvConfig::default()),
        },
        Request::RealtimeSet { enabled: true },
    ]
}

/// A reply that answers `request`, for tests that need a pair.
#[cfg(test)]
pub(crate) fn sample_reply(request: &Request) -> Reply {
    use crate::detect::QuarantineListing;
    use crate::message::{QuarantineChange, ScanCancel, ScanStart};
    use crate::report::ConfigReport;
    use crate::report::RealtimeState;
    use crate::report::ScanId;

    use av_core::config::AvConfig;

    match request {
        Request::Status => Reply::Status(crate::report::tests::sample_status()),
        Request::ScanPath { path, .. } => Reply::ScanStarted(ScanStart::Started {
            id: ScanId::new(1),
            path: path.clone(),
        }),
        Request::CancelScan { id } => Reply::ScanCancelled(ScanCancel::Unknown { id: *id }),
        // A refusal rather than a clean report: a sample reply that claimed a
        // process had been scanned and found nothing would be the exact shape
        // this protocol works hardest to keep out of a client's hands. See
        // [`crate::MemoryReport`].
        Request::ScanProcess { pid } => Reply::MemoryScan(Box::new(crate::MemoryReport {
            pid: *pid,
            process: format!("pid {pid}"),
            findings: Vec::new(),
            coverage: crate::MemoryCoverage::default(),
            walk_complete: false,
            refused: Some("no memory scan was performed: this is a sample reply".to_string()),
            files_taken: 0,
            files_left: 0,
            without_a_file: 0,
            at: chrono::Utc::now(),
        })),
        // The same refusal, for the same reason. `Verdict::Unknown` with the
        // reason attached, never `Clean`: a sample reply that reported these
        // bytes examined and found clean would hand a client exactly the answer
        // that makes an AMSI provider wave content through.
        Request::ScanBuffer { name, data } => Reply::BufferScan(Box::new(crate::BufferScan {
            name: name.clone(),
            verdict: av_core::Verdict::Unknown,
            score: 0,
            severity: None,
            rules: Vec::new(),
            summary: format!("{name} was not examined: this is a sample reply"),
            error: Some("no buffer scan was performed: this is a sample reply".to_string()),
            size: data.len() as u64,
            duration_ms: 0,
        })),
        Request::QuarantineList { .. } => Reply::QuarantineList(QuarantineListing {
            entries: Vec::new(),
            total: 0,
            omitted: 0,
        }),
        Request::QuarantineRestore { id } | Request::QuarantineDelete { id } => {
            Reply::QuarantineChange(QuarantineChange::Deleted { id: *id })
        }
        // Answered by an allow rather than folded into the arm above. `Allowed`
        // is a variant of its own precisely because it carries something the
        // others do not — whether the exclusion outlives the service — and a
        // sample that answered this with `Deleted` would be a sample of the
        // wrong answer, with the field a client reads to find out what it got
        // left untested.
        Request::QuarantineAllow { id, permanent } => {
            Reply::QuarantineChange(QuarantineChange::Allowed {
                id: *id,
                path: std::path::PathBuf::from(r"C:\Users\me\allowed.exe"),
                lasting: *permanent,
            })
        }
        Request::ConfigGet | Request::ConfigSet { .. } => Reply::Config(Box::new(ConfigReport {
            config: Box::new(AvConfig::default()),
            load_error: None,
            unhonoured: Vec::new(),
            handled_elsewhere: Vec::new(),
        })),
        Request::RealtimeSet { enabled } => Reply::Realtime(RealtimeState {
            enabled: *enabled,
            watching: *enabled,
            roots: Vec::new(),
            disabled_by: None,
            disclosures: Vec::new(),
            lost_roots: Vec::new(),
            missed: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::tests::sample_detection;
    use crate::message::{ReplyKind, RequestKind};
    use crate::report::ScanId;
    use crate::transport::loopback::Loopback;
    use crate::wire::MessageKind;

    /// A request a test can make without building an engine.
    fn cancel(id: u64) -> Request {
        Request::CancelScan {
            id: ScanId::new(id),
        }
    }

    /// A connected client and server over the in-memory loopback.
    fn pair() -> (Client<Loopback>, Server<Loopback>) {
        let (client_end, server_end) = Loopback::pair();
        (Client::new(client_end), Server::new(server_end))
    }

    #[test]
    fn a_request_and_its_reply_travel_the_whole_way() {
        let (mut client, mut server) = pair();
        let id = client.send(Request::Status).expect("sends");
        assert_eq!(id, RequestId::FIRST);
        assert!(client.is_waiting_for(id));
        assert_eq!(client.outstanding(), 1);

        let received = server.recv().expect("receives");
        assert_eq!(received.len(), 1);
        let (server_id, request) = received.into_iter().next().expect("one request");
        assert_eq!(server_id, id);
        assert_eq!(request, Request::Status);
        assert_eq!(server.awaiting(), 1);

        server.reply(id, sample_reply(&request)).expect("replies");
        assert_eq!(server.awaiting(), 0);

        let incoming = client.recv().expect("receives the reply");
        assert_eq!(incoming.len(), 1);
        assert!(matches!(
            &incoming[0],
            Incoming::Reply { id: got, .. } if *got == id
        ));
        assert_eq!(client.outstanding(), 0);
    }

    #[test]
    fn events_arrive_between_a_request_and_its_reply() {
        // The reason correlation exists at all. A client that assumed the next
        // message was its answer would take the progress event for one.
        let (mut client, mut server) = pair();
        let id = client.send(cancel(1)).expect("sends");
        let (_, request) = server.recv().expect("receives").remove(0);
        server
            .publish(&Event::StatusChanged(crate::report::tests::sample_status()))
            .expect("publishes");
        server
            .publish(&Event::Detection(sample_detection()))
            .expect("publishes");
        server.reply(id, sample_reply(&request)).expect("replies");

        let incoming = client.recv().expect("receives");
        assert_eq!(incoming.len(), 3);
        assert!(matches!(
            incoming[0],
            Incoming::Event(Event::StatusChanged(_))
        ));
        assert!(matches!(incoming[1], Incoming::Event(Event::Detection(_))));
        assert!(matches!(incoming[2], Incoming::Reply { id: got, .. } if got == id));
        assert_eq!(client.outstanding(), 0);
    }

    #[test]
    fn everything_the_requests_in_the_vocabulary_are_is_answerable_by_a_matching_reply() {
        // Every request, sent and answered, over the real session types. This
        // is the test that a new variant has to be added to — and the compiler
        // is the one that insists, because `sample_reply` matches exhaustively.
        let (mut client, mut server) = pair();
        for request in sample_requests() {
            let id = client.send(request.clone()).expect("sends");
            let (server_id, received) = server.recv().expect("receives").remove(0);
            assert_eq!(server_id, id);
            assert_eq!(received, request);
            server
                .reply(id, sample_reply(&request))
                .unwrap_or_else(|e| panic!("{request:?} could not be answered: {e}"));
        }
        // All nine went out, so the client is waiting on all nine answers until
        // it reads them.
        assert_eq!(client.outstanding(), sample_requests().len());
        assert_eq!(server.awaiting(), 0);
    }

    #[test]
    fn a_client_refuses_a_reply_it_did_not_ask_for() {
        // A service that answers a request nobody made has been desynchronised
        // by something, and accepting the reply is how the client becomes
        // desynchronised too.
        let (mut client, mut server) = pair();
        let _id = client.send(Request::Status).expect("sends");
        server.recv().expect("receives");
        // The reply names identifier 99, which the client never used.
        server
            .connection
            .write_frame(
                &Message::Reply(RequestId::new(99), sample_reply(&Request::Status))
                    .encode_framed()
                    .expect("frames"),
            )
            .expect("writes");
        assert!(matches!(
            client.recv(),
            Err(IpcError::UnexpectedReply { id }) if id == RequestId::new(99)
        ));
    }

    #[test]
    fn a_client_refuses_a_reply_of_the_wrong_kind() {
        // A `QuarantineList` answering a `Status` is the two ends having
        // drifted, and nothing else in the protocol would notice.
        let (mut client, mut server) = pair();
        let id = client.send(Request::Status).expect("sends");
        server.recv().expect("receives");
        // The server's own rules catch this before it goes out...
        let wrong = Reply::QuarantineList(crate::detect::QuarantineListing {
            entries: Vec::new(),
            total: 0,
            omitted: 0,
        });
        assert!(matches!(
            server.reply(id, wrong.clone()),
            Err(IpcError::WrongReply {
                expected: ReplyKind::Status,
                actual: ReplyKind::QuarantineList,
                ..
            })
        ));
        // ...and the client's catch it even if a peer wrote it by hand.
        server
            .connection
            .write_frame(&Message::Reply(id, wrong).encode_framed().expect("frames"))
            .expect("writes");
        assert!(matches!(
            client.recv(),
            Err(IpcError::WrongReply {
                expected: ReplyKind::Status,
                actual: ReplyKind::QuarantineList,
                ..
            })
        ));
    }

    #[test]
    fn a_refusal_answers_any_request_and_still_has_to_name_a_real_one() {
        // The rule that makes [`Reply::Refused`] expressible at all: it is the
        // one reply whose kind does not have to match the request's expected
        // kind, because it says something about the connection rather than about
        // the question. If either half of the session enforced the pairing for
        // it, a service could not refuse anything — the refusal would be
        // rejected on its way out, and the connection dropped as if the service
        // had gone wrong.
        let (mut client, mut server) = pair();
        // A request whose expected reply is `QuarantineChange`, which is not
        // `Refused` and never will be: the point is precisely that the kinds do
        // not have to match. This is one of the five the service refuses when
        // the account on the connection may not change the product's state.
        let id = client
            .send(Request::QuarantineRestore {
                id: av_quarantine::QuarantineId::new(),
            })
            .expect("sends");
        server.recv().expect("receives");
        server
            .reply(
                id,
                Reply::Refused {
                    reason: "S-1-5-21-1-2-3-1002 is in session 2, and the account signed in at \
                             this machine's console is in session 1"
                        .to_string(),
                },
            )
            .expect("a refusal is a reply this service may send");
        assert_eq!(server.awaiting(), 0);

        let incoming = client.recv().expect("receives the refusal");
        match &incoming[0] {
            Incoming::Reply { id: got, reply } => {
                assert_eq!(*got, id);
                match reply {
                    Reply::Refused { reason } => assert!(reason.contains("session 2")),
                    other => panic!("expected a refusal, got {other:?}"),
                }
            }
            other => panic!("expected a reply, got {other:?}"),
        }
        // And the identifier is still checked: the exemption is from pairing a
        // request with a reply kind, not from correlating at all. A refusal for a
        // request nobody made would desynchronise a client exactly as any other
        // uncorrelated reply would.
        assert_eq!(client.outstanding(), 0);
        let (mut client, mut server) = pair();
        client.send(Request::Status).expect("sends");
        server.recv().expect("receives");
        server
            .connection
            .write_frame(
                &Message::Reply(
                    RequestId::new(99),
                    Reply::Refused {
                        reason: "not you".to_string(),
                    },
                )
                .encode_framed()
                .expect("frames"),
            )
            .expect("writes");
        assert!(matches!(
            client.recv(),
            Err(IpcError::UnexpectedReply { id }) if id == RequestId::new(99)
        ));
        // And the server refuses to answer a request it never received, refusal
        // or not.
        assert!(matches!(
            server.reply(
                RequestId::new(99),
                Reply::Refused {
                    reason: "not you".to_string()
                }
            ),
            Err(IpcError::UnknownRequest { .. })
        ));
    }

    #[test]
    fn a_reply_that_has_already_been_sent_cannot_be_sent_again() {
        // The failure this prevents is a client that reads messages in order
        // and is therefore off by one for the rest of the connection.
        let (mut client, mut server) = pair();
        let id = client.send(Request::Status).expect("sends");
        let (_, request) = server.recv().expect("receives").remove(0);
        server.reply(id, sample_reply(&request)).expect("replies");
        assert!(matches!(
            server.reply(id, sample_reply(&request)),
            Err(IpcError::UnknownRequest { id: again }) if again == id
        ));
        assert!(matches!(
            server.reply(RequestId::new(404), sample_reply(&request)),
            Err(IpcError::UnknownRequest { .. })
        ));
    }

    #[test]
    fn a_service_refuses_a_request_identifier_that_does_not_increase() {
        // A repeat would run the request twice; going backwards means the
        // client has lost track of what it has already asked for.
        let (mut client, mut server) = pair();
        client.send(Request::Status).expect("sends");
        client.send(Request::ConfigGet).expect("sends");
        let received = server.recv().expect("receives");
        assert_eq!(received.len(), 2);
        assert_eq!(server.highest_request(), RequestId::new(2));

        // Three requests, all with identifier 1: the first is accepted and the
        // next two are not.
        //
        // Written by hand onto the wire rather than through `Client::send`,
        // because a well-behaved client cannot produce a repeated identifier and
        // the point of the test is what happens when one arrives anyway.
        fn replay(client: &mut Client<Loopback>, id: RequestId) {
            client
                .connection
                .write_frame(
                    &Message::Request(id, Request::Status)
                        .encode_framed()
                        .expect("frames"),
                )
                .expect("writes");
        }
        replay(&mut client, RequestId::new(1));
        assert!(matches!(
            server.recv(),
            Err(IpcError::RequestIdNotIncreasing { id, last })
                if id == RequestId::new(1) && last == RequestId::new(2)
        ));
        replay(&mut client, RequestId::new(2));
        assert!(matches!(
            server.recv(),
            Err(IpcError::RequestIdNotIncreasing { .. })
        ));
        // Forward is fine.
        replay(&mut client, RequestId::new(3));
        assert_eq!(server.recv().expect("receives").len(), 1);
    }

    #[test]
    fn a_service_stops_reading_rather_than_holding_unbounded_state() {
        // `awaiting` is a map whose size the peer chooses. The bound is the
        // answer, and it is refused rather than grown.
        let (mut client, mut server) = pair();
        for _ in 0..MAX_OUTSTANDING_REQUESTS {
            client.send(Request::Status).expect("sends");
        }
        // One read is at most `READ_CHUNK_BYTES` worth of frames, so filling
        // the service's table takes several of them. The loop is bounded so
        // that a transport which handed over nothing could not hang the test.
        for _ in 0..=MAX_OUTSTANDING_REQUESTS {
            if server.awaiting() >= MAX_OUTSTANDING_REQUESTS {
                break;
            }
            server.recv().expect("receives");
        }
        assert_eq!(server.awaiting(), MAX_OUTSTANDING_REQUESTS);

        client.send(Request::Status).expect("sends");
        assert!(matches!(
            server.recv(),
            Err(IpcError::TooManyOutstanding { max }) if max == MAX_OUTSTANDING_REQUESTS
        ));
    }

    #[test]
    fn each_end_refuses_the_message_that_only_the_other_end_sends() {
        let (mut client, mut server) = pair();
        // A request arriving at a client: the peer believes it is a service.
        server
            .connection
            .write_frame(
                &Message::Request(RequestId::new(1), Request::Status)
                    .encode_framed()
                    .expect("frames"),
            )
            .expect("writes");
        assert!(matches!(
            client.recv(),
            Err(IpcError::NotAServiceMessage {
                kind: RequestKind::Status
            })
        ));

        // A reply or an event arriving at a service.
        let (mut client, mut server) = pair();
        client
            .connection
            .write_frame(
                &Message::Reply(RequestId::new(1), sample_reply(&Request::Status))
                    .encode_framed()
                    .expect("frames"),
            )
            .expect("writes");
        assert!(matches!(
            server.recv(),
            Err(IpcError::WrongDirection {
                kind: MessageKind::Reply
            })
        ));
        client
            .connection
            .write_frame(
                &Message::Event(Event::Detection(sample_detection()))
                    .encode_framed()
                    .expect("frames"),
            )
            .expect("writes");
        assert!(matches!(
            server.recv(),
            Err(IpcError::WrongDirection {
                kind: MessageKind::Event
            })
        ));
    }

    #[test]
    fn a_one_byte_transport_produces_exactly_the_same_session_as_a_whole_buffer_one() {
        // The split-payload case, through the session rather than only through
        // the decoder: a pipe that hands over one byte per read must produce
        // the same replies and the same correlation state.
        let (client_end, server_end) = Loopback::pair_with_chunk(1);
        let mut client = Client::new(client_end);
        let mut server = Server::new(server_end);

        let id = client
            .send(Request::QuarantineList { limit: Some(10) })
            .expect("sends");
        let received = server.recv().expect("receives");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0, id);
        assert_eq!(received[0].1, Request::QuarantineList { limit: Some(10) });
        server
            .reply(id, sample_reply(&received[0].1))
            .expect("replies");
        let incoming = client.recv().expect("receives");
        assert_eq!(incoming.len(), 1);
        assert_eq!(client.outstanding(), 0);
    }

    #[test]
    fn a_closed_connection_is_an_error_and_not_an_empty_batch() {
        // The distinction a caller needs: "nothing yet" and "never again" are
        // different, and a client that could not tell them apart would spin.
        let (mut client, server) = pair();
        client.send(Request::Status).expect("sends");
        server.connection.close();
        assert!(matches!(client.recv(), Err(IpcError::PeerClosed)));
        // And it stays closed.
        assert!(client.is_closed());
        assert!(matches!(client.recv(), Err(IpcError::PeerClosed)));
    }

    #[test]
    fn a_framing_failure_ends_the_session_rather_than_desynchronising_it() {
        // The oversized length, arriving at a session rather than at a decoder.
        // The answer is the same and the reason is the same: after a length
        // prefix that was a lie, the next four bytes are not a length.
        let (mut client, mut server) = pair();
        client
            .connection
            .write_frame(&u32::MAX.to_le_bytes())
            .expect("writes");
        let error = server.recv().expect_err("4 GiB is not a frame");
        assert!(matches!(error, IpcError::FrameTooLarge { .. }));
        assert!(error.poisons_connection());
        // Nothing was buffered for it: four bytes is what the peer sent and
        // four bytes is what is held.
        assert_eq!(server.buffered_bytes(), 4);
    }
}
