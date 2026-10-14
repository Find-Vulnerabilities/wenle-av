//! The end-to-end test two crates promise: a real named pipe, a real service
//! loop, and real messages over it.
//!
//! # Why this test has to exist
//!
//! `av-ipc` is tested exhaustively against an in-memory loopback, and that is
//! the right place for the protocol's rules — but it proves nothing about
//! whether the Windows calls this product is designed around behave the way the
//! design assumes. Three of those assumptions are load-bearing and only a real
//! pipe can check them:
//!
//! * **`CreateNamedPipeW` with `PIPE_TYPE_BYTE` and `PIPE_REJECT_REMOTE_CLIENTS`
//!   exists and connects.** A byte-mode pipe is what makes the length prefix
//!   necessary, and `PIPE_REJECT_REMOTE_CLIENTS` is what makes the endpoint
//!   reachable only by processes this machine's own security already allows.
//! * **`PeekNamedPipe` answers "nothing yet" without blocking.** The whole
//!   control loop — one thread, draining scans and answering clients — is built
//!   on a read that returns rather than parks. A transport that blocked would
//!   not fail this test; it would hang it, which is the honest signal.
//! * **A length larger than the frame cap is refused by a server reading from a
//!   pipe.** `av-ipc`'s own test proves the decoder refuses it before reserving
//!   anything, from a `Vec`. This proves the same refusal happens on the path a
//!   hostile client actually takes, and that the *service survives it* — the
//!   next client still gets an answer. A control pipe that any local process
//!   could switch off with four bytes would be an antivirus with an off switch.
//!
//! # What it does not test, said plainly
//!
//! Nothing here goes through the Service Control Manager. Each test runs the
//! service itself, on a pipe name of its own, so no installed service and no
//! second run of this test can collide with it — see `unique_name` for why that
//! matters and why two listeners on one name present as neither test failing.
//! That a service the SCM starts behaves the same way is
//! `service_control_manager.rs`'s business, and it is `#[ignore]`d because it
//! needs administrator rights.
//!
//! # One client at a time, and why that shapes almost every test here
//!
//! [`av_service::control::serve`] serves one connection to completion before it
//! accepts another — the vault has one writer and a second client answering
//! concurrently would be a second writer. A test that opens a second connection
//! while the first is still open is therefore not testing a slow service, it is
//! testing a service that is *correctly* ignoring it: nothing reads the second
//! connection, so the request sent on it is never answered and the test fails
//! on its own patience. Every test below that reconnects drops the previous
//! client first, and [`Running::client`] says so where a caller will see it
//! before writing the same mistake again.

// An integration test is its own crate root, so the allowance `src/lib.rs` makes
// under `cfg(test)` does not reach it: without this line every `expect` below is
// a clippy warning, and a file of thirty warnings is a file where the thirty-
// first, which matters, is not read. The same allowance the library makes, for
// the same reason — in a test, unwrapping *is* the assertion.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use av_core::paths::AvPaths;
use av_core::{AvConfig, Verdict};
use av_ipc::{
    Client, Connection, Incoming, Message, QuarantineChange, Read, Reply, Request, RequestId,
    StatusReport, MAX_FRAME_BYTES,
};
use av_service::engine::{self, CatalogStatus};
use av_service::host::Host;
use av_service::pipe::{unique_name, PipeConnection};
use av_service::{config, control, ServiceError};

/// How long a test waits for something a healthy machine does in microseconds.
///
/// Generous, because the machine running this may be loading a rule database or
/// under a build, and a test that fails because a scheduler was busy is a test
/// that gets `#[ignore]`d rather than fixed. Ten seconds outlasts anything here
/// and is short enough that a genuine hang is reported rather than waited out.
const PATIENCE: Duration = Duration::from_secs(10);

/// How long between polls while waiting for one.
const POLL: Duration = Duration::from_millis(10);

/// A service, running on a pipe of its own, with the flag that stops it.
struct Running {
    name: String,
    stop: Arc<AtomicBool>,
    /// The first connection, made while waiting for the listener to appear and
    /// kept rather than thrown away. See [`Running::start`].
    ready: Option<Client<PipeConnection>>,
    thread: Option<std::thread::JoinHandle<Result<Host, ServiceError>>>,
    /// The host, after the service has stopped: kept so that a test can look at
    /// what the service left behind.
    stopped: Option<Host>,
    /// Held so the data directory lives exactly as long as the service does.
    /// Declared last, so it is dropped after the host and not before it — a
    /// vault whose directory was deleted underneath it is a shutdown that fails
    /// silently inside a `Drop`. Never read, which is what the underscore says:
    /// the value of this field is its lifetime and nothing else.
    _data: tempfile::TempDir,
}

impl Running {
    /// Start a service over a temporary data directory.
    ///
    /// The catalog is `None` and its status is `default`, which is the whole
    /// reason `engine::load_with` exists: building the real engine reads this
    /// machine's catalog store, and none of what these tests assert is about
    /// trust. The installation directory is inside the temporary directory too,
    /// so the service's own tree — which it refuses to scan — is somewhere this
    /// test owns rather than wherever `cargo` put the test binary.
    fn start(tag: &str) -> Self {
        Self::start_with(tag, |_| ()).0
    }

    /// Start a service over a data directory that `seed` writes to first.
    ///
    /// The window between [`AvPaths::ensure_dirs`] and `Host::open_with` is the
    /// only one in which a test can put something in the vault: the host owns
    /// the vault once it exists, and its fields are private. `seed` runs in that
    /// window — the same order a real machine has, where the vault was written
    /// by an earlier run of the product and the service opens what it finds —
    /// and whatever it returns comes back to the caller.
    fn start_with<T>(tag: &str, seed: impl FnOnce(&AvPaths) -> T) -> (Self, T) {
        let data = tempfile::tempdir().expect("a temporary directory");
        let install = data.path().join("install");
        std::fs::create_dir_all(&install).expect("the install directory");
        let paths = AvPaths::with_data_dir(install, data.path());
        paths.ensure_dirs().expect("the data directories");
        let seeded = seed(&paths);
        let loaded = config::load(&paths);
        let engine = engine::load_with(
            &paths,
            &loaded.config.scanning,
            None,
            CatalogStatus::default(),
        );
        let host = Host::open_with(paths, loaded, engine).expect("a host");

        let name = unique_name(tag);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let serving = name.clone();
        let thread = std::thread::spawn(move || control::serve_on(host, &flag, &serving));

        // Wait for the listener to exist, by being the first client. The
        // connection is kept rather than dropped: `CreateNamedPipeW` happens on
        // the service thread, so a client that connects immediately can find no
        // pipe at all — which is the same error a machine with no service gives,
        // and would make this test's first assertion a race rather than a fact.
        // A probe that connected and vanished would also be a client arriving
        // and leaving before `ConnectNamedPipe`, which is a case the loop has to
        // survive but this test has no business creating.
        let deadline = Instant::now() + PATIENCE;
        let ready = loop {
            match PipeConnection::connect_to(&name) {
                Ok(connection) => break Client::new(connection),
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "the service never created {name}: {error}"
                    );
                    std::thread::sleep(POLL);
                }
            }
        };

        let running = Self {
            name,
            stop,
            ready: Some(ready),
            thread: Some(thread),
            stopped: None,
            _data: data,
        };
        (running, seeded)
    }

    /// A client connected to this service.
    ///
    /// The first call hands back the connection [`Running::start`] made while
    /// waiting; later ones make a real second connection, which is what proves
    /// the listener creates a fresh instance after a client goes.
    ///
    /// **The previous client has to have been dropped first.** The service
    /// serves one client at a time — [`av_service::control`] documents why, and
    /// the reason is a single-writer vault rather than a shortcut — so a second
    /// client that connects while the first is still open is a client nothing
    /// is reading. It does not fail, it waits: in a test that is a timeout, and
    /// to a person it is a front end that appears to hang. Dropping the first
    /// client is what lets the loop come round and accept the second.
    fn client(&mut self) -> Client<PipeConnection> {
        if let Some(ready) = self.ready.take() {
            return ready;
        }
        let connection = PipeConnection::connect_to(&self.name).expect("the service is listening");
        Client::new(connection)
    }

    /// Stop the service, and give back the host it returns.
    ///
    /// Takes `&mut self` rather than consuming it so that the temporary
    /// directory outlives the host; the host is moved into `self.stopped` and
    /// is dropped before the directory is.
    fn stop(&mut self) -> &Host {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let mut host = thread
                .join()
                .expect("the service thread did not panic")
                .expect("the service returned its host");
            host.shut_down();
            self.stopped = Some(host);
        }
        self.stopped.as_ref().expect("the service stopped")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // A test that fails before `stop` still has to end the thread, or the
        // process would not exit and a failing assertion would look like a
        // hang. The panic is already in flight and takes precedence, so nothing
        // here is reported.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Ask a client for the status report, and wait for the answer.
///
/// The poll loop is the caller's, deliberately: `av-ipc` says a timeout belongs
/// to whoever knows what was asked, and `Client::recv` on this transport is a
/// question rather than a wait.
fn status_of(client: &mut Client<PipeConnection>) -> StatusReport {
    let id = client.send(Request::Status).expect("the request went out");
    let deadline = Instant::now() + PATIENCE;
    loop {
        for incoming in client.recv().expect("the session stayed sound") {
            if let Incoming::Reply { id: got, reply } = incoming {
                if got == id {
                    return match reply {
                        Reply::Status(report) => report,
                        other => panic!(
                            "a status request was answered by a {}",
                            other.kind().as_str()
                        ),
                    };
                }
            }
        }
        assert!(Instant::now() < deadline, "no reply to request {id}");
        std::thread::sleep(POLL);
    }
}

/// Ask a client for one of the three decisions about a quarantined item.
///
/// The same poll loop as [`status_of`]. Here it is the *answer* that matters
/// rather than the fact of one: `QuarantineChange::Failed` is a legitimate
/// reply, so a helper that only checked that something came back would pass on
/// a service that refused every request.
fn change_of(client: &mut Client<PipeConnection>, request: Request) -> QuarantineChange {
    let id = client.send(request).expect("the request went out");
    let deadline = Instant::now() + PATIENCE;
    loop {
        for incoming in client.recv().expect("the session stayed sound") {
            if let Incoming::Reply { id: got, reply } = incoming {
                if got == id {
                    return match reply {
                        Reply::QuarantineChange(change) => change,
                        other => panic!(
                            "a quarantine request was answered by a {}",
                            other.kind().as_str()
                        ),
                    };
                }
            }
        }
        assert!(Instant::now() < deadline, "no reply to request {id}");
        std::thread::sleep(POLL);
    }
}

/// Ask a client for the configuration the service is running with.
///
/// The in-force copy and not the file: a service that wrote an exclusion and
/// did not act on it would pass a test that read `config.toml` off the disk,
/// and that is the failure this is here to catch.
fn config_of(client: &mut Client<PipeConnection>) -> AvConfig {
    let id = client.send(Request::ConfigGet).expect("the request went out");
    let deadline = Instant::now() + PATIENCE;
    loop {
        for incoming in client.recv().expect("the session stayed sound") {
            if let Incoming::Reply { id: got, reply } = incoming {
                if got == id {
                    return match reply {
                        Reply::Config(report) => *report.config,
                        other => panic!(
                            "a configuration request was answered by a {}",
                            other.kind().as_str()
                        ),
                    };
                }
            }
        }
        assert!(Instant::now() < deadline, "no reply to request {id}");
        std::thread::sleep(POLL);
    }
}

/// Ask a client to examine a process's memory, and wait for the answer.
///
/// The same poll loop as [`status_of`], and for the same reason. It waits longer
/// than the other requests here because this one is not a question about the
/// service's own state: the service opens the process, walks its address space
/// and reads what is worth reading, which is hundreds of milliseconds of kernel
/// work even on a quiet machine.
fn memory_report_of(client: &mut Client<PipeConnection>, pid: u32) -> av_ipc::MemoryReport {
    let id = client
        .send(Request::ScanProcess { pid })
        .expect("the request went out");
    let deadline = Instant::now() + PATIENCE * 6;
    loop {
        for incoming in client.recv().expect("the session stayed sound") {
            if let Incoming::Reply { id: got, reply } = incoming {
                if got == id {
                    return match reply {
                        Reply::MemoryScan(report) => *report,
                        other => {
                            panic!("a process scan was answered by a {}", other.kind().as_str())
                        }
                    };
                }
            }
        }
        assert!(Instant::now() < deadline, "no reply to request {id}");
        std::thread::sleep(POLL);
    }
}

/// A page of private, writable, executable memory in this process.
///
/// # Why a test needs one
///
/// `av_memory::region::classify` reads a region only when it is executable and
/// either unbacked or writable — the shape of injected or self-modifying code.
/// Every executable page a Rust test binary owns is file-backed and read-only,
/// so a walk of it reports the truth and proves nothing useful: measured here,
/// "324 regions walked, 0 worth reading". That is a correct walk and a
/// complete one, and it exercises the decision to *stop* rather than the read
/// path this test exists to check.
///
/// So the test plants one. `PAGE_EXECUTE_READWRITE` and private is exactly what
/// the classifier is looking for, which makes this both the setup and a
/// statement of what the interest test means.
///
/// # Why `VirtualAlloc` is declared rather than imported
///
/// This is an integration test, and an integration test can see the crate's
/// public API and its dev-dependencies — `windows` is neither, it is a target
/// dependency of the library. Five lines of declaration is cheaper than a second
/// dependency edge, and the signature is one that cannot be got wrong quietly:
/// a wrong `VirtualAlloc` returns null and the assert below says so.
///
/// # Safety
///
/// The returned page is leaked deliberately: nothing frees it, so it stays
/// committed and executable for as long as the process lives, which is exactly
/// as long as the service needs to be able to read it. A test process that exits
/// releases it.
#[cfg(windows)]
fn plant_executable_page() -> *mut core::ffi::c_void {
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(
            address: *const core::ffi::c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
    }

    // SAFETY: a null requested address asks the system to choose one, which is
    // the only safe thing to ask for; the size is one page; and the result is
    // checked before anything writes through it.
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    assert!(
        !page.is_null(),
        "VirtualAlloc failed: {}",
        std::io::Error::last_os_error()
    );
    // Written through so that the read the service performs has bytes to bring
    // back, which is what makes `bytes_read` a measurement rather than a
    // constant the report could be producing on its own.
    // SAFETY: `page` is a freshly committed page of at least 4096 bytes that
    // nothing else in this process refers to.
    unsafe { std::ptr::write_bytes(page as *mut u8, 0x90, 4096) };
    page
}

/// Wait for the far end of `connection` to go away.
fn wait_for_close(connection: &mut PipeConnection, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    let mut buf = [0u8; 1024];
    loop {
        match connection
            .read_chunk(&mut buf)
            .expect("the transport stayed sound")
        {
            Read::Closed => return,
            Read::Bytes(_) => {
                assert!(Instant::now() < deadline, "{what}");
                std::thread::sleep(POLL);
            }
        }
    }
}

#[test]
fn a_client_and_a_service_exchange_real_messages_through_a_real_pipe() {
    let mut service = Running::start("exchange");
    let mut client = service.client();

    let report = status_of(&mut client);
    // The service reports itself running because `serve_on` sets that before it
    // creates the listener: a client that can connect at all is a client
    // talking to a service that is up.
    assert_eq!(report.state, av_ipc::ServiceState::Running);
    // The version is this build's, which is what makes the field a fact about
    // the far end rather than a constant the protocol carries.
    assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
    // The temporary data directory has an empty vault and no rule database, and
    // both are reported as what they are: no items, and no database at all.
    assert_eq!(report.quarantine_items, 0);
    assert!(report.database.is_none(), "{:?}", report.database);
    assert_eq!(report.scans_running, 0);
    assert!(report.uptime_secs < 3_600);
    // The driver is not on this machine, and `Unknown` and `Absent` are
    // different answers — which one this is depends on whether the build looks,
    // and both are honest. What must not happen is a `Loaded`.
    assert!(!report.driver.presence.is_loaded());

    // Several requests on one connection, because the session's strictly
    // increasing identifiers only show up on the second one.
    for _ in 0..3 {
        assert_eq!(status_of(&mut client).state, av_ipc::ServiceState::Running);
    }

    // The first client goes, and only then is a second one served. That is the
    // documented shape of this control plane and not a limitation of the test:
    // a second connection made while the first is still open is a connection
    // nothing reads. Dropping first also proves the loop comes round — a
    // service that served exactly one client and then waited forever would fail
    // here rather than silently, which is the failure worth catching.
    drop(client);
    let mut second = service.client();
    assert_eq!(status_of(&mut second).state, av_ipc::ServiceState::Running);

    drop(second);
    assert_eq!(service.stop().state(), av_ipc::ServiceState::Stopped);
}

#[test]
fn a_client_can_ask_the_service_to_examine_a_process_and_gets_a_real_answer() {
    // The memory path, through the whole machine: a request on a named pipe, the
    // service's own `Host::scan_process`, the real `av-memory` walk over a real
    // process, and a report back over the same pipe. Nothing is stubbed except
    // the rule set, which is empty because this service's data directory has no
    // database — and an empty rule set is exactly right for this test, because
    // what it is about is whether the *walk* happens and whether the answer is
    // honest about it.
    //
    // The process examined is this one. A test cannot assume any other process
    // on the machine is openable — measured on this machine, over half of them
    // are not — and its own PID is the one handle that cannot be refused.
    let mut service = Running::start("process");
    let mut client = service.client();
    let pid = std::process::id();

    // A region this process would otherwise not have, held for the length of the
    // scan. See `plant_executable_page` for why a test binary has none of its
    // own and why that makes the difference between checking the walk and
    // checking the read.
    #[cfg(windows)]
    let _planted = plant_executable_page();

    let report = memory_report_of(&mut client, pid);
    assert_eq!(report.pid, pid);
    assert!(
        report.process.contains(&pid.to_string()),
        "the report names the process it examined: {}",
        report.process
    );
    assert!(report.refused.is_none(), "{:?}", report.refused);
    // The walk happened, and it says so with numbers rather than with a verdict:
    // this is what distinguishes an examined process from one that was refused.
    assert!(
        report.coverage.regions_walked > 0,
        "no region of this process was walked: {:?}",
        report.coverage
    );
    assert!(
        report.coverage.regions_examined > 0,
        "this process has executable private memory and none of it was read: {:?}",
        report.coverage
    );
    assert!(
        report.coverage.bytes_read > 0,
        "nothing was read out of the regions that were examined: {:?}",
        report.coverage
    );
    assert!(report.walk_complete, "the walk stopped early");

    // The rule set is empty, so nothing can be found and nothing can be taken.
    // The counts are still present and still zero, which is the distinction the
    // report type exists to keep: no findings is an answer, and it is not the
    // same answer as a refusal.
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.files_taken, 0);
    assert_eq!(report.files_left, 0);
    assert_eq!(report.without_a_file, 0);

    // And the service is still serving, which is the part a memory scan could
    // plausibly have broken: it is the only request here that reads another
    // process, and a service that died inside one would be an antivirus that any
    // single request could switch off.
    assert_eq!(status_of(&mut client).state, av_ipc::ServiceState::Running);

    // A PID that names nothing is answered, not dropped: the client is told what
    // was wrong rather than left waiting. `u32::MAX` is the value Windows itself
    // returns from a call that found no process, which makes it the right stand-in
    // for "this PID is not a process" — and it can never be a real one.
    let missing = memory_report_of(&mut client, u32::MAX);
    assert_eq!(missing.pid, u32::MAX);
    assert!(missing.refused.is_some(), "{missing:?}");
    assert!(missing.coverage.is_complete(), "nothing was attempted");
    assert!(
        !av_ipc::MemoryReport::is_complete(&missing),
        "a refused scan must never read as a complete one"
    );

    drop(client);
    assert_eq!(service.stop().state(), av_ipc::ServiceState::Stopped);
}

#[test]
fn an_oversized_length_is_refused_by_a_server_reading_from_a_pipe() {
    let mut service = Running::start("oversized");

    // The connection `start` made while waiting for the listener goes before
    // the forged frame does. The service serves one client at a time, so a
    // frame sent while that one is still open would sit in an instance nothing
    // is reading — and this test would report a timeout where it means to
    // report a refusal.
    drop(service.client());

    // A well-formed frame whose length prefix claims more than the protocol's
    // ceiling. This is the hostile input the framing has to survive: a `u32`
    // length read off a pipe is a peer-controlled allocation size, and a server
    // that trusted it would reserve sixteen million times what the frame
    // actually is — or, at `u32::MAX`, fail to allocate at all.
    let mut forged = Message::Request(RequestId::new(1), Request::Status)
        .encode_framed()
        .expect("a frame");
    let absurd = (MAX_FRAME_BYTES as u32) + 1;
    forged[..4].copy_from_slice(&absurd.to_le_bytes());

    let mut raw = PipeConnection::connect_to(&service.name).expect("the service is listening");
    raw.write_frame(&forged).expect("the forged frame went out");

    // The service refuses it and drops the connection rather than reading on
    // from an offset it cannot trust. The client learns that the only way a
    // pipe says it: a read that returns nothing, which `av-service::pipe`
    // reports as `Read::Closed`.
    wait_for_close(&mut raw, "the service kept reading a frame it had refused");
    drop(raw);

    // And the part that matters most: the service is still there, and still
    // answering.
    let mut client = service.client();
    assert_eq!(status_of(&mut client).state, av_ipc::ServiceState::Running);
    drop(client);
    assert_eq!(service.stop().state(), av_ipc::ServiceState::Stopped);
}

#[test]
fn a_client_that_goes_away_does_not_stop_the_service() {
    // The failure this prevents is a service that ends when a front end's
    // window closes. The control loop is supposed to notice a disconnected peer
    // and go back to waiting — but only after anything that matters has been
    // written, which is why the shutdown goes through `shut_down`.
    let mut service = Running::start("gone");
    {
        let mut client = service.client();
        assert_eq!(status_of(&mut client).state, av_ipc::ServiceState::Running);
        // Dropped without a word: `PipeConnection::drop` disconnects and closes
        // the handle, which is the only close a pipe has.
    }
    let mut client = service.client();
    assert_eq!(status_of(&mut client).state, av_ipc::ServiceState::Running);
    drop(client);
    assert_eq!(service.stop().state(), av_ipc::ServiceState::Stopped);
}

#[test]
fn an_instance_a_client_abandoned_is_replaced_rather_than_waited_on_for_ever() {
    // The accept loop creates an instance and only later calls
    // `ConnectNamedPipe`, so there is a window — `host.drain()` plus a poll
    // interval — in which a client can arrive and leave again without ever
    // being accepted. The instance it touched accepts no one afterwards, and
    // `PeekNamedPipe` reports it exactly as it reports a fresh one, so a loop
    // that only polled would wait on it for ever: a service the SCM calls
    // `RUNNING` that answers nobody, reachable by one `CreateFileW` and a
    // `CloseHandle` from any process on this machine.
    //
    // This is the test that would have caught that, and it is also where the
    // first attempt at the fix was measured not to work: `DisconnectNamedPipe`
    // on this instance leaves it one no client can reach, so `connect_to` below
    // spends its full five seconds and then reports "no instance became
    // available". Replacing the instance is what works, and the assertion at
    // the end is the one that says so.
    let name = unique_name("abandoned");
    let mut listener = av_service::pipe::PipeListener::create(&name).expect("a listener");

    drop(PipeConnection::connect_to(&name).expect("the client connected"));

    // The poll cannot see the difference, and this is that fact written down:
    // the abandoned instance reads as an instance nobody has visited, which is
    // why polling alone cannot be the whole accept step.
    assert!(
        !listener.wait_for_client(Duration::from_millis(50)),
        "an abandoned instance is expected to be invisible to the poll"
    );

    // The replacement is what makes the next client's arrival possible at all.
    // It is a `CreateNamedPipeW` and a `CloseHandle` rather than a repair,
    // because there is no repair for this state — see `PipeListener::refresh`.
    listener.refresh().expect("the instance is replaced");

    // And now the pipe takes clients again: this is the whole point, and the
    // assertion that fails if the abandoned state is not cleared.
    let client = PipeConnection::connect_to(&name).expect("the pipe accepts clients again");
    assert!(
        listener.wait_for_client(PATIENCE),
        "the replacement instance is waitable"
    );
    let accepted = listener.connect().expect("the client is accepted");
    drop(accepted);
    drop(client);
}

#[test]
fn a_replacement_does_not_drop_a_client_that_has_already_arrived() {
    // `refresh` is asked on every idle pass, so it runs constantly on a service
    // nobody is talking to — which is exactly when a client turns up. The last
    // look before the old instance is closed is what keeps that from dropping
    // the connection of whoever arrived in the moment since the poll, and this
    // is what fails if that look is ever removed as redundant.
    let name = unique_name("arrived");
    let mut listener = av_service::pipe::PipeListener::create(&name).expect("a listener");

    let client = PipeConnection::connect_to(&name).expect("the client connected");
    assert!(
        listener.wait_for_client(PATIENCE),
        "the arriving client is visible to the poll"
    );

    listener
        .refresh()
        .expect("a refresh with a client attached is not an error");

    // The instance the client is on is the one the listener still holds, so the
    // connection is still good. `Read::Bytes(0)` is what a connected and quiet
    // peer reads as and `Read::Closed` is what a dropped one reads as, so this
    // is the difference being asserted rather than assumed.
    let mut accepted = listener.connect().expect("the client is still accepted");
    let mut buf = [0u8; 8];
    assert!(
        matches!(accepted.read_chunk(&mut buf), Ok(Read::Bytes(_))),
        "the client that arrived before the replacement was dropped by it"
    );
    drop(accepted);
    drop(client);
}

#[test]
fn a_name_the_transport_cannot_create_is_refused_before_the_system_is_asked() {
    // The one check that has to happen before a Win32 call, because
    // `CreateNamedPipeW` truncates an over-long name instead of refusing it: a
    // service that truncated its own name would listen on a pipe no client
    // looks at, and would present as "the service is not running". No service
    // is started, because the refusal is supposed to come from the check rather
    // than from the operating system.
    let too_long = format!("{}{}", av_ipc::PIPE_PREFIX, "x".repeat(300));
    let error = av_service::pipe::PipeListener::create(&too_long).expect_err("refused");
    assert!(matches!(error, ServiceError::Pipe { .. }), "{error}");
    // And a name with a second separator, which no client would ever build.
    let nested = format!("{}{}", av_ipc::PIPE_PREFIX, r"a\b");
    assert!(av_service::pipe::PipeListener::create(&nested).is_err());
    // But the product's own name is one this transport can create, which is the
    // fact that keeps the two crates agreeing about what the endpoint is.
    assert!(av_ipc::is_valid_pipe_name(av_ipc::PIPE_NAME));
}

/// The three decisions a user makes about a quarantined file, over a real pipe,
/// against a real vault.
///
/// # What this is for
///
/// The window asks the service to put a file back, destroy it, or leave it
/// alone, because the vault's index has one writer and the service is it — see
/// `av-gui`'s `service` module. The protocol's own tests prove the requests
/// encode and decode; this proves the *vault changes*. A service that answered
/// every request with `Failed`, or one that restored a file and left the
/// exclusion unwritten, would pass every test that stopped at the wire.
///
/// # The fixture
///
/// Three files are taken into the vault before the service opens it, which is
/// the order a real machine has: the vault was written by an earlier run, and
/// the service opens what it finds. That is the only window in which a test can
/// put something there — once the host exists it owns the vault and its fields
/// are private.
#[test]
fn the_three_decisions_a_user_makes_reach_the_vault_through_a_real_pipe() {
    let (mut running, planted) = Running::start_with("quarantine-decisions", |paths| {
        let policy = av_quarantine::QuarantinePolicy::from(
            &av_core::AvConfig::default().quarantine,
        );
        let mut vault =
            av_quarantine::QuarantineVault::open(&paths.quarantine_dir, policy).expect("a vault");
        ["restore", "delete", "allow"]
            .into_iter()
            .map(|what| {
                let victim = paths.data_dir.join(format!("{what}.exe"));
                std::fs::write(&victim, format!("the bytes of {what}")).expect("written");
                let entry = vault
                    .quarantine_file(&victim, &av_quarantine::QuarantineContext::default())
                    .expect("taken");
                assert!(!victim.is_file(), "a quarantined file is off the disk");
                (what, entry.id, victim)
            })
            .collect::<Vec<_>>()
    });

    let mut client = running.client();
    assert_eq!(
        config_of(&mut client).general.exclusions.len(),
        0,
        "nothing is excluded before anything is allowed"
    );

    let (_, restore_id, restore_me) = planted[0].clone();
    let (_, delete_id, delete_me) = planted[1].clone();
    let (_, allow_id, allow_me) = planted[2].clone();

    // -- put it back -------------------------------------------------------
    match change_of(
        &mut client,
        Request::QuarantineRestore { id: restore_id },
    ) {
        QuarantineChange::Restored { path, .. } => {
            assert_eq!(path, restore_me, "back to the path it was taken from");
        }
        other => panic!("a restore was answered with {other:?}"),
    }
    assert!(restore_me.is_file(), "the bytes are on the disk again");

    // -- destroy it --------------------------------------------------------
    match change_of(&mut client, Request::QuarantineDelete { id: delete_id }) {
        QuarantineChange::Deleted { .. } => {}
        other => panic!("a delete was answered with {other:?}"),
    }
    assert!(
        !delete_me.is_file(),
        "a delete destroys the bytes and does not put them back"
    );

    // -- leave it alone ----------------------------------------------------
    match change_of(
        &mut client,
        Request::QuarantineAllow {
            id: allow_id,
            permanent: true,
        },
    ) {
        QuarantineChange::Allowed { path, lasting, .. } => {
            assert_eq!(path, allow_me);
            assert!(
                lasting,
                "a permanent allow that could not be written has to say so, and this one                  was asked for on a data directory the test owns"
            );
        }
        other => panic!("an allow was answered with {other:?}"),
    }
    assert!(allow_me.is_file(), "an allow puts the file back as well");
    let exclusions = config_of(&mut client).general.exclusions;
    assert!(
        exclusions.iter().any(|held| held == &allow_me),
        "the allow is not in the service's own configuration: {exclusions:?}"
    );
    assert!(
        !exclusions.iter().any(|held| held == &restore_me),
        "putting a file back is not allowing it: {exclusions:?}"
    );

    running.stop();
}

/// The AMSI path end to end: this product's own provider, its real worker
/// thread, the real protocol, the real host, one pipe.
///
/// # Why this is here rather than in `av-amsi`
///
/// Every test in `av-amsi` runs against a machine with *no* service. That is an
/// important case — it is the one where a script host must not be made to wait,
/// and it is where the answer has to be "no opinion" rather than "clean" — but
/// it is the opposite of the case a user is in. What a script host actually gets
/// when this product is installed is a verdict from an engine holding ten
/// thousand rules, and before this test nothing in the workspace had ever put a
/// [`Request::ScanBuffer`] on a pipe at all.
///
/// # The one client slot, and the window after it is given up
///
/// [`Running::start`] connects while it waits for the listener to appear and
/// keeps that connection. The service serves one client at a time, so that
/// connection is the one it is reading, and the scanner has to have it instead:
/// it is dropped first.
///
/// The scan is then retried, and that is not defensive padding.
/// `PipeListener::connect` hands its instance to the client and creates the next
/// one immediately, so a free instance exists the moment the probe goes — but
/// `control::serve_on` calls `PipeListener::refresh` whenever a poll finds
/// nobody connected, and `refresh` *closes* that free instance. A scanner that
/// connected inside that window holds a handle to a pipe the service has just
/// closed, and is told `Unavailable`. Retrying is exactly what a person would
/// have to do here, so the loop below does it rather than pretending the window
/// is not there.
#[test]
fn the_amsi_provider_reaches_the_service_and_gets_a_real_verdict() {
    // The seed returns nothing; the `.0` is the service, the same way
    // `Running::start` takes it.
    let (mut running, ()) = Running::start_with("amsi-provider", |paths| {
        // Written in the window before the host opens, which is where a real
        // machine has it too: the database is a file an earlier run left behind.
        let source = "rule Test_Finds_Marker {\n  meta:\n    severity = \"high\"\n  strings:\n    \
                      $a = \"WENLE-SCRIPT-MARKER\"\n  condition:\n    $a\n}\n";
        let database = av_rules::database::RuleDatabase::compile(source).0;
        assert_eq!(database.len(), 1, "the rule must compile");
        database
            .save(paths.db_dir.join(av_service::engine::DATABASE_FILE))
            .expect("the database is written");
    });

    // The service's one client is the scanner, so the probe connection it made
    // while waiting has to go. See the doc comment.
    drop(running.ready.take());

    let scanner = av_amsi::Scanner::with_pipe(&running.name, Duration::from_millis(500));
    let script = b"Write-Host 'WENLE-SCRIPT-MARKER'";

    let deadline = Instant::now() + PATIENCE;
    let scan = loop {
        match scanner.scan("Script Block", script) {
            av_amsi::Scan::Reported(scan) => break scan,
            av_amsi::Scan::Unavailable(reason) => {
                assert!(
                    Instant::now() < deadline,
                    "the scanner was never answered: {reason}"
                );
                std::thread::sleep(POLL);
            }
        }
    };

    // The verdict is the engine's, reached through the provider's worker, the
    // protocol and the host — the same chain a script host drives, minus the
    // COM plumbing that Windows performs and `av-amsi`'s own tests cover.
    assert_eq!(scan.verdict, Verdict::Malicious, "{scan:?}");
    assert_eq!(scan.rules, vec!["Test_Finds_Marker".to_string()], "{scan:?}");
    // The label came back as one, and the size is the bytes that were sent.
    assert_eq!(scan.name, "Script Block");
    assert_eq!(scan.size, script.len() as u64);
    assert!(scan.error.is_none(), "{scan:?}");

    running.stop();
}
