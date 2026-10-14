//! Who is on the other end of a control connection, and what they may do.
//!
//! # The question, and why a permission list cannot answer it
//!
//! Until this module existed, every client that could open the control pipe
//! could do everything the pipe offers: restore a quarantined file, delete one,
//! allow one permanently, and write any setting in `config.toml` — including
//! the ones that switch protection off. [`crate::pipe::CONTROL_PIPE_SDDL`] grants
//! read and write to `NT AUTHORITY\INTERACTIVE`, which is not a set of one: it
//! contains `BUILTIN\Users`, so every account that can sign on to this machine is
//! on it. That is deliberate — a control channel the product's own front ends
//! cannot reach is a product with no front end — and it means the separation
//! between one signed-in user and another cannot be made by the pipe's
//! permission list at all. It has to be made per connection, from the identity
//! of the process on the other end, and that is what this module is.
//!
//! The split is the one `av-quarantine`'s vault already documents: **the threat
//! is the *other* user, not a malicious program running as this one.** A
//! signed-in user's own processes are outside what any of this can stop, and
//! saying otherwise would be a claim this code cannot keep.
//!
//! # Who may change things
//!
//! Two accounts, and the second is the one that makes the product usable:
//!
//! * **An administrator**, by membership of `BUILTIN\Administrators` *as the
//!   operating system reports it for this token*. A filtered token — what a
//!   program gets when a user who is an administrator starts it without
//!   agreeing to elevation — does **not** count, which is what
//!   `CheckTokenMembership` answers and is the whole reason UAC works.
//!   Administrators are outside every protection this product has by design;
//!   `av-guard`'s documentation says so at length and this refuses to pretend
//!   otherwise.
//! * **The account signed in at this machine's console** — that is, the client's
//!   token is in the session the physical console is on. This clause exists
//!   because without it nothing works: the service runs as `LocalSystem`, the
//!   window and the command-line tool run as whoever is at the keyboard, and
//!   "the service's own account" would therefore match nobody. Measured on this
//!   machine, the two are in different sessions and the client is not an
//!   administrator, so a rule that named only those two would refuse the
//!   product's own front end.
//!
//! Everything else reads and does not write. That is not a partial answer: a
//! second signed-in user can still see the quarantine listing, the status and
//! the reports — which is what a status window on a shared machine should be
//! able to do — and cannot release a file this product took away.
//!
//! # What this does not do
//!
//! * It does not distinguish a signed-in user's own malicious program from that
//!   user. Nothing here can: they share a token. Stated because a
//!   self-protection feature that implied otherwise would be advertising a
//!   property it does not have.
//! * It does not survive a client that can execute code as an administrator.
//!   Nor should it try — see `av-guard`.
//! * It makes no decision about *remote* clients, because there are none:
//!   `PIPE_REJECT_REMOTE_CLIENTS` keeps the channel off the network, and this is
//!   the second lock on a door that is already shut rather than the only one.

/// What the service learned about the account on the other end of a connection.
///
/// Split from the decision below so that the decision is an ordinary function
/// over ordinary values and can be tested without a pipe, a token or an
/// operating system — the same arrangement [`crate::pipe`] uses for the
/// transport and `av-driver-proto` uses for the driver's logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The account, as `S-1-5-...`.
    pub sid: String,
    /// The session the client's token belongs to.
    ///
    /// A token's session, not a process's: the two are the same for any process
    /// a person can start, and the token is what the access check will use.
    pub session: u32,
    /// Whether `BUILTIN\Administrators` is *enabled* in this token.
    ///
    /// False for a filtered administrator token, deliberately: see this
    /// module's documentation.
    pub administrator: bool,
}

/// What a connection is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    /// May read and may change the product's state.
    MayChange {
        /// Why, for the service's log and for a client that asks.
        reason: String,
    },
    /// May read and may not change.
    ReadOnly {
        /// Why, in a sentence a support log can be read against.
        reason: String,
    },
    /// The identity could not be established at all.
    ///
    /// A separate arm from [`Peer::ReadOnly`] because the two send a reader to
    /// different places: one says "this account is not the one at the console",
    /// the other says "the service could not ask". Neither may change anything —
    /// an identity that could not be read is not an identity that was allowed —
    /// but only one of them is a security decision.
    Unknown {
        /// What went wrong.
        reason: String,
    },
}

impl Peer {
    /// Whether this connection may change the product's state.
    pub fn may_change(&self) -> bool {
        matches!(self, Peer::MayChange { .. })
    }

    /// The sentence explaining this answer.
    pub fn reason(&self) -> &str {
        match self {
            Peer::MayChange { reason } | Peer::ReadOnly { reason } | Peer::Unknown { reason } => {
                reason
            }
        }
    }

    /// One line for the service's log.
    pub fn describe(&self) -> String {
        match self {
            Peer::MayChange { reason } => {
                format!("this client may change the product's state: {reason}")
            }
            Peer::ReadOnly { reason } => {
                format!("this client may read and may not change anything: {reason}")
            }
            Peer::Unknown { reason } => {
                format!("this client's account could not be established: {reason}")
            }
        }
    }
}

/// Decide what a client may do, from its identity and the console's session.
///
/// `console_session` is `None` when the system reports no active console
/// session — a machine with nobody signed in at the keyboard. Then only an
/// administrator may change anything, which is the answer that cannot be wrong:
/// there is no "account at the console" to be.
///
/// Session `0` is never the console. It is where services live, so a client in
/// it is a service or something started by one, and matching it against a
/// console session that the system did not report would be reading an error
/// code as an identity.
pub fn decide(identity: &Identity, console_session: Option<u32>) -> Peer {
    if identity.administrator {
        return Peer::MayChange {
            reason: format!(
                "{} is an administrator: BUILTIN\\Administrators is enabled in this token",
                identity.sid
            ),
        };
    }
    match console_session {
        Some(console) if console != 0 && console == identity.session => Peer::MayChange {
            reason: format!(
                "{} is the account signed in at this machine's console, in session {console}",
                identity.sid
            ),
        },
        Some(console) => Peer::ReadOnly {
            reason: format!(
                "{} is in session {}, and the account signed in at this machine's console is in \
                 session {console}. Release a file this product took away from that account's own \
                 session, or from an elevated prompt as an administrator",
                identity.sid, identity.session
            ),
        },
        None => Peer::ReadOnly {
            reason: format!(
                "{} is in session {}, and no session is signed in at this machine's console, so \
                 there is no account this product can take an instruction from. An administrator \
                 may still change things",
                identity.sid, identity.session
            ),
        },
    }
}

/// Establish who is on the other end of a connected control pipe.
///
/// The whole of the Windows-ness of this module, and deliberately one function:
/// everything above is exercised by `cargo test` on any machine, and this is the
/// part whose behaviour is the operating system's.
#[cfg(windows)]
pub fn identify_connection(connection: &crate::pipe::PipeConnection) -> Peer {
    match learn(connection.handle()) {
        Ok(identity) => decide(&identity, console_session()),
        Err(reason) => Peer::Unknown { reason },
    }
}

/// The same question on a build without a Windows to ask.
///
/// A blanket "may not change anything" rather than a compile error, because the
/// alternative is a service that does not build off Windows at all — this crate
/// keeps a `cfg(not(windows))` transport for the tests that do not need one —
/// and a refusal is the answer that cannot be wrong. There is no such build of
/// this product, so this is a shape the code has rather than a machine it runs
/// on.
#[cfg(not(windows))]
pub fn identify_connection(_connection: &crate::pipe::PipeConnection) -> Peer {
    Peer::Unknown {
        reason: "connection identities are a Windows concept and this build has none".to_string(),
    }
}

/// The client's identity, read from the impersonation token on this thread.
///
/// # Why impersonation rather than the client's process
///
/// `GetNamedPipeClientProcessId` gives a process id, and a process id is not an
/// identity: it has to be opened, and it can be gone by the time it is. The
/// token the kernel captured when the client connected is the thing the access
/// check itself would use, and `ImpersonateNamedPipeClient` is the one call that
/// hands it over without needing any right on the client's process — which
/// matters, because the client is a user's program and this is running as
/// `LocalSystem`.
///
/// # The revert, and why it is not on the success path only
///
/// While the thread is impersonating, it *is* the client: every file it opens
/// and every registry key it reads is checked against the client's token. This
/// function reads a token and then reverts, whatever happened, before returning
/// — the revert is outside the closure that does the work precisely so that the
/// error path cannot skip it. A service left impersonating an ordinary user
/// would be a service whose next write to its own database is refused.
#[cfg(windows)]
fn learn(handle: windows::Win32::Foundation::HANDLE) -> Result<Identity, String> {
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;

    // SAFETY: `handle` is a live connected pipe handle owned by the caller.
    unsafe { ImpersonateNamedPipeClient(handle) }
        .map_err(|error| format!("the client could not be impersonated ({error})"))?;
    let identity = read_identity();
    // SAFETY: balances the impersonation above; called on every path, success
    // or failure, and the token has been closed by `read_identity` by now.
    unsafe {
        let _ = windows::Win32::Security::RevertToSelf();
    }
    identity
}

/// Read the session, the account and the administrator bit off the thread token.
///
/// Only ever called while this thread is impersonating a client.
#[cfg(windows)]
fn read_identity() -> Result<Identity, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    use windows::Win32::Security::TOKEN_QUERY;

    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: this thread is impersonating, which is what makes a thread token
    // exist at all; `token` is a live out-parameter. `false` asks for the token
    // as it is rather than for an impersonation-level copy of it — the token is
    // read and never used to act as anybody.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &mut token) }
        .map_err(|error| format!("the client's token could not be opened ({error})"))?;

    let mut identity = Err("the client's identity was not read".to_string());
    if let Ok(session) = session_of(token) {
        if let Ok(sid) = account_of(token) {
            identity = is_administrator(token).map(|administrator| Identity {
                sid,
                session,
                administrator,
            });
        } else {
            identity = Err("the client's account could not be named".to_string());
        }
    }
    // SAFETY: the handle came from `OpenThreadToken` and is closed exactly once,
    // here, after its last use above.
    unsafe {
        let _ = CloseHandle(token);
    }
    identity
}

/// The session the token belongs to.
#[cfg(windows)]
fn session_of(token: windows::Win32::Foundation::HANDLE) -> Result<u32, String> {
    use windows::Win32::Security::{GetTokenInformation, TokenSessionId};

    let mut session = 0u32;
    let mut needed = 0u32;
    // SAFETY: `token` is a live token handle open for `TOKEN_QUERY`, and
    // `session` is a `u32` of exactly the size this information class returns.
    unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            Some(&mut session as *mut u32 as *mut std::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
            &mut needed,
        )
    }
    .map_err(|error| format!("the client's session could not be read ({error})"))?;
    Ok(session)
}

/// The account the token belongs to, as `S-1-5-...`.
#[cfg(windows)]
fn account_of(token: windows::Win32::Foundation::HANDLE) -> Result<String, String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    // The two-call idiom: the first asks how large the answer is, the second
    // asks for it. A `TOKEN_USER` holds a `SID` of no fixed size — an account
    // SID's sub-authorities depend on how many groups the machine has issued —
    // so there is no constant to allocate.
    let mut needed = 0u32;
    // SAFETY: `token` is live and open for `TOKEN_QUERY`; a null buffer with a
    // zero length is the documented way to ask for the required size, and the
    // call is expected to fail here.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return Err("the client's token reported no account".to_string());
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: the buffer is exactly the size the call just asked for.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        )
    }
    .map_err(|error| format!("the client's account could not be read ({error})"))?;

    // SAFETY: the call succeeded, so the buffer holds a `TOKEN_USER` whose
    // `User.Sid` points into that same buffer, which is alive here.
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut text = windows::core::PWSTR::null();
    // SAFETY: `user.User.Sid` points at a SID inside `buffer`, and `text` is an
    // out-parameter the API points at a `LocalAlloc` string on success.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }
        .map_err(|error| format!("the client's account could not be named ({error})"))?;
    // SAFETY: on success `text` is a NUL-terminated wide string owned by us.
    let named = unsafe { text.to_string() }
        .map_err(|_| "the client's account was not text".to_string());
    // SAFETY: the string came from `LocalAlloc` and has been copied.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            text.0 as *mut std::ffi::c_void,
        )));
    }
    named
}

/// Whether `BUILTIN\Administrators` is enabled in the token.
///
/// `CheckTokenMembership` rather than a search of the token's group list, for
/// the same reason `av_guard::acl::Dacl::effective` uses
/// `GetEffectiveRightsFromAclW`: the operating system's own evaluation is the
/// one the access check will use, and the answer it gives for a filtered token
/// is the answer that makes UAC work. Looking for the SID in the group list
/// would find it in every administrator's filtered token and say yes to all of
/// them, which is the opposite of this product's whole position on
/// administrators.
#[cfg(windows)]
fn is_administrator(token: windows::Win32::Foundation::HANDLE) -> Result<bool, String> {
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, PSID, WinBuiltinAdministratorsSid,
        SECURITY_MAX_SID_SIZE,
    };

    // A `u32` array rather than a byte array: a SID has to be four-byte aligned,
    // and `[u8; 68]` is aligned to one.
    let mut storage =
        [0u32; SECURITY_MAX_SID_SIZE as usize / std::mem::size_of::<u32>()];
    let mut size = SECURITY_MAX_SID_SIZE;
    let sid = PSID(storage.as_mut_ptr() as *mut std::ffi::c_void);
    // SAFETY: the buffer is `SECURITY_MAX_SID_SIZE` bytes, which is the size
    // this call documents every well-known SID fits in, and `size` starts at
    // that size and is set to what was used.
    unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut size) }
        .map_err(|error| format!("the administrators' SID could not be built ({error})"))?;

    let mut member = windows::core::BOOL(0);
    // SAFETY: `token` is live and open for `TOKEN_QUERY`, `sid` points at a
    // well-known SID in a live buffer, and `member` is a live out-parameter.
    unsafe { CheckTokenMembership(Some(token), sid, &mut member) }
        .map_err(|error| format!("the client's group membership could not be checked ({error})"))?;
    Ok(member.as_bool())
}

/// The session the physical console is on, or `None` when there is none.
///
/// `WTSGetActiveConsoleSessionId` documents `0xFFFFFFFF` as "no active
/// session", which is a machine with nobody signed in at the keyboard — a
/// server, or a workstation at the lock screen before anybody has ever signed
/// in. That value is a sentinel and not a session, and it is turned into `None`
/// here rather than compared: a client that happened to report session
/// `4294967295` would otherwise be read as being at the console.
#[cfg(windows)]
fn console_session() -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

    // SAFETY: no arguments and no output beyond the return value.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        None
    } else {
        Some(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(sid: &str, session: u32, administrator: bool) -> Identity {
        Identity {
            sid: sid.to_string(),
            session,
            administrator,
        }
    }

    #[test]
    fn an_administrator_may_change_things_from_anywhere() {
        // The clause exists for the case the console clause cannot cover: an
        // administrator working on the machine from a session that is not the
        // console — a remote session, or a scheduled task.
        let peer = decide(&identity("S-1-5-21-1-2-3-500", 4, true), Some(1));
        assert!(peer.may_change(), "{}", peer.describe());
        // And with nobody at the console at all.
        assert!(decide(&identity("S-1-5-21-1-2-3-500", 4, true), None).may_change());
    }

    #[test]
    fn the_account_at_the_console_may_change_things() {
        // The clause that makes the product work: the window and the
        // command-line tool run as the person at the keyboard, and the service
        // runs as LocalSystem, so they are never the same account.
        let peer = decide(&identity("S-1-5-21-1-2-3-1001", 1, false), Some(1));
        assert!(peer.may_change(), "{}", peer.describe());
        assert!(peer.reason().contains("S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn another_signed_in_user_may_read_and_not_change() {
        // The threat this exists for, and the one measurement that made the rule
        // what it is: a second account signed in by Fast User Switching or over
        // a remote session is in a session that is not the console's.
        let peer = decide(&identity("S-1-5-21-1-2-3-1002", 2, false), Some(1));
        assert!(!peer.may_change(), "{}", peer.describe());
        // The sentence has to send a reader somewhere useful, not just say no:
        // it names both sessions, so "refused" comes with "and here is where it
        // would have been allowed".
        assert!(peer.reason().contains("session 2"), "{}", peer.reason());
        assert!(peer.reason().contains("session 1"), "{}", peer.reason());
    }

    #[test]
    fn a_filtered_administrator_is_not_an_administrator() {
        // The measurement behind `CheckTokenMembership`: a program started by an
        // administrator who did not agree to elevation holds a token where
        // `BUILTIN\Administrators` is present but not enabled, and the operating
        // system reports it as not a member. `Identity::administrator` is that
        // answer, so this is the shape a non-elevated administrator's window
        // arrives in — and it is allowed by the console clause, not by this one.
        let filtered = identity("S-1-5-21-1-2-3-1001", 1, false);
        let peer = decide(&filtered, Some(1));
        assert!(peer.may_change());
        assert!(
            !peer.reason().contains("administrator:"),
            "this must be the console clause that allowed it, not the administrator one: {}",
            peer.reason()
        );
    }

    #[test]
    fn no_console_session_means_only_administrators() {
        // A machine with nobody signed in at the keyboard. There is no account
        // to take an instruction from, so an ordinary one does not get to give
        // one — and the sentence says so rather than leaving a reader to work
        // out why they were refused.
        let peer = decide(&identity("S-1-5-21-1-2-3-1001", 1, false), None);
        assert!(!peer.may_change());
        assert!(peer.reason().contains("console"), "{}", peer.reason());
    }

    #[test]
    fn session_zero_is_never_the_console() {
        // `0xFFFFFFFF` is `WTSGetActiveConsoleSessionId`'s "no session", and
        // session `0` is where services live. Neither can be a person, and a
        // service that matched `0` against a console session it did not read
        // would let every service on the machine change the product's state.
        let service = identity("S-1-5-18", 0, false);
        assert!(!decide(&service, None).may_change());
        assert!(!decide(&service, Some(0)).may_change());
        assert!(!decide(&service, Some(1)).may_change());
        // …and SYSTEM *is* a member of Administrators on a real machine, so the
        // honest answer for it comes through the administrator clause. Spelled
        // out because "the service may not change things" would otherwise read
        // as a bug.
        assert!(decide(&identity("S-1-5-18", 0, true), None).may_change());
    }

    #[test]
    fn an_identity_that_could_not_be_read_may_change_nothing() {
        // The failure this is written against: a check that returns "yes" when
        // it cannot tell. Every arm that is not `MayChange` refuses, and the
        // three describe themselves differently so that a support log says which
        // one happened.
        let unknown = Peer::Unknown {
            reason: "the client's token could not be opened (Win32 error 5)".to_string(),
        };
        assert!(!unknown.may_change());
        assert!(unknown.describe().contains("could not be established"));
        let read_only = Peer::ReadOnly {
            reason: "someone else".to_string(),
        };
        assert!(!read_only.may_change());
        assert!(read_only.describe().contains("may not change anything"));
    }

    /// A live control connection with one request already delivered.
    ///
    /// The request is not scenery. `learn` cannot answer anything until the
    /// operating system has captured the client's token, and the system does
    /// that on the first read from the connection rather than at connect — so a
    /// pair with nothing written yet is a pair in which the question is not yet
    /// askable. This reproduces the exact state [`serve_client`] is in when it
    /// asks: a client that has sent a request, and a server that has read it.
    ///
    /// The listener is returned so that it stays alive; the connections have to
    /// stay alive for the same kind of reason, since `learn` asks the client's
    /// token and a client that has gone is a token nothing can be asked of.
    #[cfg(windows)]
    fn live_pair() -> (
        av_ipc::Server<crate::pipe::PipeConnection>,
        av_ipc::Client<crate::pipe::PipeConnection>,
        crate::pipe::PipeListener,
    ) {
        use crate::pipe::{unique_name, PipeConnection, PipeListener};

        let name = unique_name("peer");
        let mut listener = PipeListener::create(&name).expect("a pipe this process may create");
        let (sender, receiver) = std::sync::mpsc::channel();
        let client_name = name.clone();
        // On its own thread because `PipeListener::connect` blocks until a
        // client arrives, and the client half cannot be opened on the thread
        // that is waiting for it.
        let client_thread = std::thread::spawn(move || {
            let connection = PipeConnection::connect_to(&client_name).expect("the client connects");
            sender.send(connection).expect("the test is waiting");
        });
        let server_connection = listener.connect().expect("the listener accepts");
        let client_connection = receiver.recv().expect("the client connected");
        client_thread.join().expect("the client thread finished");

        let mut server = av_ipc::Server::new(server_connection);
        let mut client = av_ipc::Client::new(client_connection);
        client
            .send(av_ipc::Request::Status)
            .expect("the client asks something");
        // `Server::recv` is a question rather than a wait — see `control`'s
        // module documentation — so the write above may not have landed on the
        // first ask. Bounded, so a failure to deliver is a failed test rather
        // than a hung one.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let received = server.recv().expect("the service reads");
            if !received.is_empty() {
                assert_eq!(received.len(), 1, "the request arrived whole");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the request never arrived"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        (server, client, listener)
    }

    /// This process's own account and session, read the ordinary way.
    ///
    /// The control for the test below: the same two facts asked for through the
    /// process token instead of through an impersonation, so that a
    /// `GetTokenInformation` call reading the wrong field has something to
    /// disagree with.
    #[cfg(windows)]
    fn own_identity() -> (String, u32) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = windows::Win32::Foundation::HANDLE::default();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle that needs no closing,
        // and `token` is a live out-parameter.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .expect("this process's own token may be opened");
        let sid = account_of(token).expect("this process's own account may be named");
        // SAFETY: the handle came from `OpenProcessToken` and is closed exactly
        // once, here, after its last use.
        unsafe {
            let _ = CloseHandle(token);
        }

        let mut session = 0u32;
        // SAFETY: `session` is a live out-parameter and the process id is this
        // process's, so no right is needed to ask about it.
        unsafe { ProcessIdToSessionId(std::process::id(), &mut session) }
            .expect("this process is in a session");
        (sid, session)
    }

    #[cfg(windows)]
    #[test]
    fn a_live_connection_is_identified_as_the_account_on_the_other_end() {
        // The half of this module whose behaviour is the operating system's, and
        // therefore the half that a pure test cannot reach: the impersonation,
        // the two `GetTokenInformation` reads, the SID's text, and the session.
        // Both ends of this pipe are this process, so the answer has a known
        // value — which is what makes this a test rather than a smoke check.
        let (server, _client, _listener) = live_pair();
        let identity =
            learn(server.connection().handle()).expect("a connected client can be identified");
        let (own_sid, own_session) = own_identity();

        assert_eq!(
            identity.session, own_session,
            "the client of this pipe is this process, so its session is this process's session"
        );
        assert_eq!(
            identity.sid, own_sid,
            "the account read through an impersonation must be the account read through the \
             process token"
        );
        assert!(identity.sid.starts_with("S-1-"), "{}", identity.sid);

        // And the decision over that identity is one of the two real answers,
        // never `Unknown` — the failure that would make this feature refuse
        // everybody, including the window, without saying why.
        let peer = decide(&identity, console_session());
        assert!(
            matches!(peer, Peer::MayChange { .. } | Peer::ReadOnly { .. }),
            "{}",
            peer.describe()
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_impersonation_is_reverted_before_the_answer_comes_back() {
        // Not decoration. While a thread is impersonating, every file it opens
        // is checked against the client's token, so a service left impersonating
        // an ordinary user is a service whose next write to its own vault is
        // refused — and the failure appears somewhere else entirely, hours
        // later, as a disk error. `learn` states the discipline in its
        // documentation; this measures it.
        //
        // A thread that is not impersonating has no thread token, so
        // `OpenThreadToken` failing with `ERROR_NO_TOKEN` is the observable form
        // of "the impersonation ended". It is asked on this thread, immediately
        // after `learn` returned on it.
        let (server, _client, _listener) = live_pair();
        learn(server.connection().handle()).expect("a connected client can be identified");

        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        let mut token = windows::Win32::Foundation::HANDLE::default();
        // SAFETY: `GetCurrentThread` is a pseudo-handle that needs no closing and
        // `token` is a live out-parameter; the call is expected to fail here,
        // which is the assertion.
        let opened = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                windows::Win32::Security::TOKEN_QUERY,
                false,
                &mut token,
            )
        };
        let error = opened.expect_err("this thread must not still be impersonating anybody");
        assert_eq!(
            crate::win32::code(&error),
            crate::win32::ERROR_NO_TOKEN,
            "the thread token should be absent, not merely unopenable: {error}"
        );
    }
}
