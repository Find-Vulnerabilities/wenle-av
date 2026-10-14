//! Registering this product as an AMSI provider.
//!
//! # What the registration is, exactly
//!
//! Windows asks every registered AMSI provider about script content, and it
//! finds them through the registry. A provider that is not registered is a DLL
//! nothing loads. Two keys make one, and both are needed:
//!
//! | Key | What it says |
//! |---|---|
//! | `HKLM\SOFTWARE\Classes\CLSID\{...}` with an `InprocServer32` subkey | which DLL to load, and how to create it |
//! | `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{...}` | that this CLSID is a provider at all |
//!
//! The second key has **no values**. Its existence is the entire registration,
//! which is why [`SiteState::Present`] carries a [`Detail::Provider`] with
//! nothing in it: a report that expected to read something back from that key
//! would find an empty key and conclude the registration was broken.
//!
//! # Machine-wide, and there is no smaller option
//!
//! Both keys are under `HKEY_LOCAL_MACHINE`, and that is not a choice this
//! module makes: AMSI enumerates its providers from there and nowhere else.
//! There is no per-user AMSI, because the point of an AMSI provider is to cover
//! every account on the machine: a provider registered for one user is absent
//! for an administrator's `powershell.exe`, which is the process an attacker
//! most wants.
//!
//! So unlike the Explorer verbs in [`crate::shell`], this command has no
//! `--user`/`--machine` pair and no fallback scope. It needs elevation, always,
//! and says so before it writes anything.
//!
//! # The DLL path is a privilege boundary, not a preference
//!
//! A registered provider DLL is loaded into **every scripting host on the
//! machine**, including hosts running elevated. A path under a directory an
//! ordinary user can write is therefore a way to put code into an
//! administrator's PowerShell: write over the file, wait for a script to run.
//! That is a privilege escalation performed by the antivirus, and it is why
//! [`av_amsi::is_trusted_dll_path`] is consulted *before* the first key is
//! created; see `check_dll`. A refusal leaves the registry untouched, so a
//! user who sees the message has nothing to undo.
//!
//! # Four sites are read and two are written
//!
//! `SOFTWARE\WOW6432Node` is the 32-bit process's view of `SOFTWARE`, so
//! `HKLM\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers` is where a 32-bit host
//! looks for this list. All four sites are therefore *read*, because a leftover
//! entry under `WOW6432Node` (from an older 32-bit build, or from something
//! else entirely) is a registration this machine has and the report must not
//! be blind to. [`AmsiStatus::other_views`] is what surfaces it.
//!
//! Only the two native sites are **written**, and the reason is that this
//! build's DLL is 64-bit. Registering a 64-bit DLL under `WOW6432Node` would
//! tell every 32-bit host to load a module it cannot load: `CoCreateInstance`
//! fails, the provider is never created, and the registry says the machine is
//! fully protected. A silent absence that looks like coverage is worse than a
//! documented gap, so the gap is what this build leaves, and `status` prints
//! it rather than leaving a user to discover it.
//!
//! # Why the write is here and not in the DLL
//!
//! `av-amsi` is loaded into other people's processes. A module that other
//! processes load has no business writing `HKLM`, and an antivirus that
//! registers itself the first time it is invoked is one nobody can audit. The
//! decision belongs to a person at a command line, and this module is the
//! command's hands; `av-amsi`'s `registration` module owns only the facts (the
//! CLSID, the key names, the path check), so that the DLL and the installer
//! cannot each write down a different answer.

use std::path::{Path, PathBuf};

use av_amsi::{
    clsid_string, dll_path, is_trusted_dll_path, CLASSES_KEY, CLASSES_KEY_WOW64, DISPLAY_NAME,
    INPROC_SERVER_KEY, PROVIDERS_KEY, PROVIDERS_KEY_WOW64, THREADING_MODEL,
};

use crate::registry::{Hive, Key, RegistryError};
use crate::shell::is_elevated;

/// One of the four registry keys a provider registration is made of.
///
/// Two of them are the registration and two are the 32-bit view of it. Named as
/// a set rather than as two constants because the report has to be able to say
/// "three of four" about a machine, and because the WOW64 pair is exactly what
/// a reader will not think to look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Site {
    /// The COM class registration `CoCreateInstance` resolves, 64-bit view.
    ClientNative,
    /// The same, as a 32-bit host sees it.
    ClientWow64,
    /// The key AMSI enumerates providers from, 64-bit view.
    ProviderNative,
    /// The same, as a 32-bit host sees it.
    ProviderWow64,
}

/// Which half of the registration a [`Site`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteKind {
    /// The COM side: a CLSID key with an `InprocServer32` subkey naming the DLL.
    Client,
    /// The AMSI side: a key with no values.
    Provider,
}

impl Site {
    /// Every site, native pair first.
    ///
    /// Read order and not write order — see this module's header for why the
    /// two differ.
    pub const ALL: [Site; 4] = [
        Site::ClientNative,
        Site::ProviderNative,
        Site::ClientWow64,
        Site::ProviderWow64,
    ];

    /// The two sites an install writes.
    pub const NATIVE: [Site; 2] = [Site::ClientNative, Site::ProviderNative];

    /// The two sites only a 32-bit build may write.
    pub const OTHER_VIEW: [Site; 2] = [Site::ClientWow64, Site::ProviderWow64];

    /// Which half of the registration this is.
    pub const fn kind(self) -> SiteKind {
        match self {
            Site::ClientNative | Site::ClientWow64 => SiteKind::Client,
            Site::ProviderNative | Site::ProviderWow64 => SiteKind::Provider,
        }
    }

    /// True for the two sites a 64-bit build may write.
    pub const fn is_native(self) -> bool {
        matches!(self, Site::ClientNative | Site::ProviderNative)
    }

    /// The key, under whichever hive the caller is using.
    ///
    /// A `String` rather than a `&'static str` because the CLSID is part of it
    /// and the CLSID comes from [`clsid_string`], which formats it. Writing the
    /// brace-and-hyphen form out as a literal here would be a second copy of an
    /// identifier that must match [`av_amsi::CLSID`] exactly, and the failure
    /// mode of the two drifting apart is a registration that installs cleanly
    /// and is never enumerated.
    pub fn key_path(self) -> String {
        let clsid = clsid_string();
        match self {
            Site::ClientNative => format!(r"{CLASSES_KEY}\{clsid}"),
            Site::ClientWow64 => format!(r"{CLASSES_KEY_WOW64}\{clsid}"),
            Site::ProviderNative => format!(r"{PROVIDERS_KEY}\{clsid}"),
            Site::ProviderWow64 => format!(r"{PROVIDERS_KEY_WOW64}\{clsid}"),
        }
    }

    /// The `InprocServer32` subkey of a client site.
    ///
    /// # Panics
    ///
    /// Panics on a provider site, which has no such subkey. A `Result` was
    /// considered and rejected: every caller knows which kind of site it holds
    /// — the two are told apart by [`Site::kind`] one line earlier — so the
    /// error would be handled by unwrapping or by a branch that cannot be
    /// taken, and a panic in a test that got it wrong is a clearer failure than
    /// a status line reading "no DLL is named" about a key that never names one.
    pub fn inproc_server_path(self) -> String {
        assert_eq!(
            self.kind(),
            SiteKind::Client,
            "a provider site has no InprocServer32 subkey"
        );
        format!(r"{}\{INPROC_SERVER_KEY}", self.key_path())
    }

    /// The hive this site lives in. Always [`Hive::LocalMachine`].
    ///
    /// A method rather than a constant so that the reason is written once, next
    /// to the only place that could change it — see this module's header for
    /// why there is no per-user AMSI.
    pub const fn hive(self) -> Hive {
        Hive::LocalMachine
    }

    /// The word for this site in a report.
    pub const fn describe(self) -> &'static str {
        match self {
            Site::ClientNative => "COM class, 64-bit view",
            Site::ClientWow64 => "COM class, 32-bit view",
            Site::ProviderNative => "AMSI provider list, 64-bit view",
            Site::ProviderWow64 => "AMSI provider list, 32-bit view",
        }
    }
}

/// Something that went wrong while reading or writing the registration.
#[derive(Debug, thiserror::Error)]
pub enum AmsiError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// The registration is machine-wide and this process may not write there.
    ///
    /// Worded about *changing* rather than about installing, because the
    /// removal path raises it too and a user running `remove` should not be
    /// told that "installing" was refused.
    #[error(
        "an AMSI provider is registered for the whole machine, which needs administrator rights, \
         and this process is not elevated; run the command from an elevated prompt"
    )]
    NeedsElevation,

    /// This executable's own directory could not be determined.
    #[error("this executable's own path could not be determined: {detail}")]
    NoExecutable {
        /// What the operating system said.
        detail: String,
    },

    /// There is no provider DLL beside this executable.
    ///
    /// A hard refusal and not a warning. A registration naming a file that is
    /// not there is one AMSI tries to load on every script and fails; the
    /// machine is not protected and the registry claims it is.
    #[error(
        "there is no {name} beside this executable (looked in {directory}), so there is nothing to \
         register. An entry naming a DLL that is not there is a registration that fails on every \
         script while looking correct in the registry",
        name = av_amsi::DLL_NAME,
        directory = .directory.display()
    )]
    DllMissing {
        /// The directory that was searched.
        directory: PathBuf,
    },

    /// The DLL is somewhere an AMSI provider must not be loaded from.
    #[error(
        "{} is not a directory an AMSI provider may be loaded from: the provider DLL is loaded \
         into every scripting host on this machine, including elevated ones, so a path an \
         ordinary user can write is a way to put code into an administrator's shell. Install the \
         product somewhere only administrators can write, such as Program Files",
        .path.display()
    )]
    UnsafeDllPath {
        /// The path that was refused.
        path: PathBuf,
    },
}

impl From<AmsiError> for av_core::AvError {
    /// The registry code survives; the rest becomes a sentence.
    ///
    /// [`AmsiError::NeedsElevation`] is [`av_core::AvError::Other`] and not
    /// [`av_core::AvError::AccessDenied`], for the reason
    /// [`crate::shell::ShellError`]'s conversion gives: nothing was attempted,
    /// so there is no failing call for a caller to go looking for.
    fn from(error: AmsiError) -> Self {
        match error {
            AmsiError::Registry(registry) => av_core::AvError::from(registry),
            other => av_core::AvError::Other(other.to_string()),
        }
    }
}

/// The provider DLL this build would register, from this executable's directory.
///
/// Taken from `current_exe` and never from the caller, for the reason
/// [`crate::shell::install`] gives about the verb's command line: the only path
/// that can be right is the one this process is running from. A caller-supplied
/// path would let a mistyped command register a provider that does not exist,
/// and the resulting failure appears on a user's screen as scripts running
/// unscanned.
pub fn product_dll() -> Result<PathBuf, AmsiError> {
    let exe = std::env::current_exe().map_err(|error| AmsiError::NoExecutable {
        detail: error.to_string(),
    })?;
    let directory = exe.parent().ok_or_else(|| AmsiError::NoExecutable {
        detail: format!("{} has no parent directory", exe.display()),
    })?;
    Ok(dll_path(directory))
}

/// Refuse a DLL that is somewhere a provider must not be loaded from.
///
/// The one check that is a fact about the *machine's* safety, and the only one
/// [`install_under`] performs before writing — see [`check_present`] for the
/// other half, and why the two are separate functions.
fn check_trusted(dll: &Path) -> Result<(), AmsiError> {
    if !is_trusted_dll_path(dll) {
        return Err(AmsiError::UnsafeDllPath {
            path: dll.to_path_buf(),
        });
    }
    Ok(())
}

/// Refuse a DLL that is not there.
///
/// Separate from [`check_trusted`] because the two answer questions about
/// different things. Trust is a property of the path alone, so it holds whether
/// the file exists and whoever is writing; existence is a property of *this
/// product's installation*, which only [`install`] knows anything about —
/// `install_under` is handed a path and has no business asserting the file
/// ought to be there, since the tests hand it one that deliberately is not.
fn check_present(dll: &Path) -> Result<(), AmsiError> {
    if !dll.is_file() {
        let directory = dll
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Err(AmsiError::DllMissing { directory });
    }
    Ok(())
}

/// Both checks, in the order a user's message depends on.
///
/// Trust first, deliberately. A DLL under a profile that also does not exist is
/// refused by either, and the message the user should get is the one about the
/// writable directory: that is a decision they have to make about where the
/// product is installed, where a missing file is a packaging problem with no
/// decision in it. Nothing is written until both have passed.
fn check_dll(dll: &Path) -> Result<(), AmsiError> {
    check_trusted(dll)?;
    check_present(dll)
}

/// Register this build's provider DLL for the whole machine.
///
/// Returns the DLL that was registered, which is the path a caller wants to
/// print and the path [`status`] will read back.
///
/// Idempotent: running it twice leaves the same registry as running it once, so
/// it is also how a half-finished registration is repaired.
///
/// # Errors
///
/// [`AmsiError::NeedsElevation`] when this process is not elevated,
/// [`AmsiError::DllMissing`] when the DLL is not beside this executable,
/// [`AmsiError::UnsafeDllPath`] when it is somewhere a user can write, and
/// [`AmsiError::Registry`] when the machine refuses the write. Nothing is
/// written until all three of the first checks have passed.
pub fn install() -> Result<PathBuf, AmsiError> {
    let dll = product_dll()?;
    check_dll(&dll)?;
    install_under(Hive::LocalMachine, &dll)?;
    Ok(dll)
}

/// [`install`] against a hive the caller names.
///
/// Exists so the tests can run the same code against `HKCU`, where a write is a
/// fact about a temporary key rather than about the machine. The production
/// entry point passes [`Hive::LocalMachine`] and takes no hive from its caller:
/// see this module's header for why there is no per-user AMSI, and note that a
/// per-user value here would be a registration the product cannot honour.
pub(crate) fn install_under(hive: Hive, dll: &Path) -> Result<(), AmsiError> {
    ensure_writable(hive)?;
    check_trusted(dll)?;

    let client = Key::create(hive, &Site::ClientNative.key_path())?;
    // The default value is the name COM shows for the class, and the only
    // string here a person reads.
    client.set_string("", DISPLAY_NAME)?;

    let server = Key::create(hive, &Site::ClientNative.inproc_server_path())?;
    server.set_string("", &dll.to_string_lossy())?;
    // `Both` because a provider is created on whichever thread the host is
    // running script on. Left unset, COM assumes `Apartment` and a host that
    // creates the object from an MTA thread needs a marshaller — which works,
    // so the failure is not a missing provider but a slower one, and it is not
    // the kind of thing anybody notices.
    server.set_string("ThreadingModel", THREADING_MODEL)?;

    // No values at all. The key's existence is the registration; see this
    // module's header. The binding is dropped immediately and deliberately,
    // because a reader might otherwise expect values to be written through it.
    Key::create(hive, &Site::ProviderNative.key_path())?;

    log::info!(
        "registered {} as an AMSI provider under {}",
        dll.display(),
        hive
    );
    Ok(())
}

/// Remove the registration.
///
/// # All four sites, including the two this build never writes
///
/// The two `WOW6432Node` sites are removed here even though [`install`] does not
/// create them. The question `remove` answers is "is this CLSID registered as an
/// AMSI provider on this machine", and after it returns the answer has to be no
/// — a leftover 32-bit entry from an older build still names *this* CLSID, and
/// leaving it behind with the DLL deleted is exactly the broken registration
/// this module refuses to create. The CLSID is this product's, so deleting the
/// key that names it is not reaching into anybody else's.
///
/// A key that was never there is not an error, which is what makes `remove`
/// usable as the cleanup step of a failed install as well as the uninstall step
/// of a successful one.
pub fn remove() -> Result<(), AmsiError> {
    remove_under(Hive::LocalMachine)
}

/// [`remove`] against a hive the caller names. See [`install_under`].
pub(crate) fn remove_under(hive: Hive) -> Result<(), AmsiError> {
    ensure_writable(hive)?;
    for site in Site::ALL {
        Key::delete_tree(hive, &site.key_path())?;
    }
    log::info!("removed the AMSI provider registration from {hive}");
    Ok(())
}

/// What is registered on this machine, read back from the registry.
///
/// # Errors
///
/// [`AmsiError::Registry`] when a key cannot be read. A machine with an unusual
/// policy can produce that, and it is reported rather than rounded to "nothing
/// is registered" — those two are different facts and only one of them is a
/// reason to install.
pub fn status() -> Result<AmsiStatus, AmsiError> {
    status_under(Hive::LocalMachine)
}

/// [`status`] against a hive the caller names. See [`install_under`].
pub(crate) fn status_under(hive: Hive) -> Result<AmsiStatus, AmsiError> {
    let mut sites = Vec::with_capacity(Site::ALL.len());
    for site in Site::ALL {
        sites.push(SiteStatus {
            site,
            state: read_site(hive, site)?,
        });
    }
    Ok(AmsiStatus { sites })
}

/// What is under one site.
fn read_site(hive: Hive, site: Site) -> Result<SiteState, AmsiError> {
    let Some(key) = Key::open(hive, &site.key_path())? else {
        return Ok(SiteState::Absent);
    };
    let _ = key;

    match site.kind() {
        // Present and nothing more to ask. An empty key is a *correct* provider
        // entry, so there is no second question here.
        SiteKind::Provider => Ok(SiteState::Present(Detail::Provider)),

        SiteKind::Client => {
            let Some(server) = Key::open(hive, &site.inproc_server_path())? else {
                return Ok(SiteState::Incomplete {
                    detail: format!(
                        "there is no `{INPROC_SERVER_KEY}` subkey under it, so nothing says which \
                         DLL to load"
                    ),
                });
            };
            // An empty default value is `Incomplete` and not `Absent`: the key
            // is there, and a `CoCreateInstance` against it fails with a
            // complaint about the path rather than about the class. Reporting
            // it as absent would send a user to install something that is
            // already half there.
            let dll = match server.string("")? {
                Some(text) if !text.trim().is_empty() => PathBuf::from(text),
                Some(_) => {
                    return Ok(SiteState::Incomplete {
                        detail: format!(
                            "the `{INPROC_SERVER_KEY}` subkey has an empty default value, so no \
                             DLL is named"
                        ),
                    })
                }
                None => {
                    return Ok(SiteState::Incomplete {
                        detail: format!(
                            "the `{INPROC_SERVER_KEY}` subkey has no default value, so no DLL is \
                             named"
                        ),
                    })
                }
            };
            Ok(SiteState::Present(Detail::Client {
                on_disk: dll.is_file(),
                trusted: is_trusted_dll_path(&dll),
                threading_model: server.string("ThreadingModel")?,
                dll,
            }))
        }
    }
}

/// What was found under one site.
///
/// Three states and not two, for the reason [`crate::shell::Registration`]
/// gives: "registered" and "not registered" would have to file a key that
/// exists with nothing usable under it under one of them, and both answers
/// mislead — one promises a provider that will never be created, the other
/// sends a user to install something that is already there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteState {
    /// No key at this site.
    Absent,
    /// A key with what it needs.
    Present(Detail),
    /// A key at this site with no usable registration under it.
    Incomplete {
        /// What is missing, as a sentence a report can print.
        detail: String,
    },
}

impl SiteState {
    /// True when this site is there and usable.
    pub fn is_present(&self) -> bool {
        matches!(self, SiteState::Present(_))
    }

    /// The DLL this site names, when it names one.
    pub fn dll(&self) -> Option<&Path> {
        match self {
            SiteState::Present(Detail::Client { dll, .. }) => Some(dll),
            _ => None,
        }
    }
}

/// What a present site says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    /// The COM side: which DLL, how to create it, and whether that path is
    /// somewhere it may be loaded from.
    Client {
        /// The DLL named in the `InprocServer32` default value, verbatim.
        dll: PathBuf,
        /// The `ThreadingModel` value, when the subkey has one.
        threading_model: Option<String>,
        /// Whether that file is there now.
        on_disk: bool,
        /// Whether it is somewhere an AMSI provider may be loaded from.
        trusted: bool,
    },
    /// The AMSI side: a key with no values, whose existence is the whole
    /// registration.
    Provider,
}

/// One site's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteStatus {
    /// Which site this is about.
    pub site: Site,
    /// What is there.
    pub state: SiteState,
}

/// What is registered on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmsiStatus {
    sites: Vec<SiteStatus>,
}

impl AmsiStatus {
    /// One entry per site, in [`Site::ALL`]'s order.
    pub fn sites(&self) -> &[SiteStatus] {
        &self.sites
    }

    /// One site's state.
    ///
    /// # Panics
    ///
    /// Panics if `site` was not read, which cannot happen: `status_under`
    /// reads all four. A `Result` here would be an error no caller could act on.
    ///
    /// The `expect` is allowed rather than removed, and the reason it is a
    /// deliberate exception to this workspace's rule is that the rule exists to
    /// catch a panic on a path a *file* can reach. This one is unreachable by
    /// construction — the set of sites is a constant and the reader walks all of
    /// it — and the structurally total alternative, indexing a
    /// `[SiteState; Site::COUNT]`, is the right fix and a larger change to this
    /// module than one warning is worth today. Recorded here so that whoever
    /// does make that change knows this line is what it removes.
    #[allow(clippy::expect_used)]
    pub fn state(&self, site: Site) -> &SiteState {
        &self
            .sites
            .iter()
            .find(|entry| entry.site == site)
            .expect("every site is read")
            .state
    }

    /// How many of the two native sites are present.
    pub fn registered(&self) -> usize {
        Site::NATIVE
            .iter()
            .filter(|site| self.state(**site).is_present())
            .count()
    }

    /// The sites in the 32-bit view that something registered.
    ///
    /// Anything here was not written by this build — see this module's header.
    /// It is not reported as a fault, because it may be perfectly deliberate on
    /// a machine that also has a 32-bit copy of the product; it is reported at
    /// all because a 32-bit entry naming a 64-bit DLL is a provider that fails
    /// to load while the registry looks complete.
    pub fn other_views(&self) -> Vec<Site> {
        Site::OTHER_VIEW
            .iter()
            .copied()
            .filter(|site| !matches!(self.state(*site), SiteState::Absent))
            .collect()
    }

    /// True when nothing at all is registered.
    pub fn is_absent(&self) -> bool {
        self.sites
            .iter()
            .all(|entry| entry.state == SiteState::Absent)
    }

    /// True when AMSI would actually load this provider.
    ///
    /// Four things, and all of them, because each alone produces a machine that
    /// looks registered and scans no script: both native keys present, the DLL
    /// named by the client site is on disk, it is somewhere a provider may be
    /// loaded from, and its threading model is the one that does not need a
    /// marshaller. [`problems`](AmsiStatus::problems) says which of them failed.
    pub fn is_complete(&self) -> bool {
        self.registered() == Site::NATIVE.len() && self.problems().is_empty()
    }

    /// Every reason this machine would not load the provider, as sentences.
    ///
    /// Empty when [`is_complete`](AmsiStatus::is_complete). Ordered
    /// native-first, so the first line is about the registration a user just
    /// performed rather than about a 32-bit leftover.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for entry in &self.sites {
            match &entry.state {
                SiteState::Absent | SiteState::Present(Detail::Provider) => {}
                SiteState::Incomplete { detail } => {
                    problems.push(format!("{}: {detail}", entry.site.describe()));
                }
                SiteState::Present(Detail::Client {
                    dll,
                    threading_model,
                    on_disk,
                    trusted,
                }) => {
                    if !trusted {
                        problems.push(format!(
                            "{}: {} is in a directory an ordinary user can write, so loading it \
                             would run their code inside every scripting host on this machine",
                            entry.site.describe(),
                            dll.display()
                        ));
                    }
                    if !on_disk {
                        problems.push(format!(
                            "{}: {} is not there, so the provider cannot be created",
                            entry.site.describe(),
                            dll.display()
                        ));
                    }
                    if threading_model.as_deref() != Some(THREADING_MODEL) {
                        problems.push(format!(
                            "{}: the threading model is {}, and a provider is created on whichever \
                             thread the host is running script on; it should be {THREADING_MODEL}",
                            entry.site.describe(),
                            threading_model.as_deref().unwrap_or("not set"),
                        ));
                    }
                }
            }
        }
        problems
    }
}

/// Refuse a hive this process cannot write, before anything is attempted.
///
/// The same shape as [`crate::shell`]'s check and for the same reason: a
/// pre-check can name the remedy, where a failing registry call can only name
/// the key. [`Hive::CurrentUser`] is accepted unconditionally because it is
/// what the tests use; nothing in this module's production paths passes it —
/// see this module's header.
///
/// [`Hive::ClassesRoot`] is grouped with [`Hive::LocalMachine`] rather than
/// given its own arm, and it is worth saying why rather than leaving it to look
/// like an oversight. It is a *merged* view of the machine's and the current
/// user's `Software\Classes`, half of which is machine-wide — so writing
/// through it needs the same right — and it is also unreachable here, because
/// [`Site::hive`] answers [`Hive::LocalMachine`] for every site. The arm is
/// there because [`Hive`] is exhaustive and a wildcard would silently accept a
/// fourth variant somebody adds later.
fn ensure_writable(hive: Hive) -> Result<(), AmsiError> {
    match hive {
        Hive::CurrentUser => Ok(()),
        Hive::LocalMachine | Hive::ClassesRoot if is_elevated() => Ok(()),
        Hive::LocalMachine | Hive::ClassesRoot => Err(AmsiError::NeedsElevation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four keys, removed when this is dropped.
    ///
    /// A guard rather than a line at the end of each test, because a failing
    /// assertion unwinds past the cleanup and leaves the keys behind — and the
    /// keys this writes are real ones under `HKCU\Software\Classes\CLSID`,
    /// where a leftover entry is a per-user COM registration for this CLSID.
    /// Inert, since AMSI never reads the user's half, and still not something a
    /// test suite should leave on a developer's machine.
    struct Cleanup;

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for site in Site::ALL {
                let _ = Key::delete_tree(Hive::CurrentUser, &site.key_path());
            }
        }
    }

    /// Held for the whole of every test that touches the registry.
    ///
    /// # Why the tests cannot run in parallel
    ///
    /// Because the key paths are not the tests' to choose. [`Site::key_path`]
    /// is derived from the product's CLSID and the operating system's key
    /// names, and it has to be, because a test that wrote its keys somewhere
    /// else would prove nothing about the keys the product writes. So every
    /// test in this module shares one set of four keys, and `cargo test` runs
    /// them on separate threads: without this, one test's [`Cleanup`] deletes
    /// the tree while another is halfway through writing it.
    ///
    /// That is not hypothetical — it is what this module's first run did, and
    /// it failed as `ERROR_KEY_DELETED` from a `RegSetValueExW` whose key had
    /// been created two statements earlier, plus a status read that reported a
    /// site present that the reading test never wrote. Both looked like bugs in
    /// the module and were bugs in the tests.
    ///
    /// Poisoning is ignored rather than propagated: a test that panicked has
    /// already reported the failure, and turning that into a lock error in
    /// every *other* test would bury the one real message under a dozen false
    /// ones.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Take the lock and clear the four keys, in that order.
    ///
    /// One call rather than two lines at every test, because the order is the
    /// part that has to be right: clearing before taking the lock is the race
    /// the lock exists to prevent.
    fn guard() -> (std::sync::MutexGuard<'static, ()>, Cleanup) {
        let lock = serial();
        let guard = Cleanup;
        // A run that was killed before its guard ran would otherwise leave keys
        // that make the "nothing is registered" test fail for a reason that has
        // nothing to do with the code.
        for site in Site::ALL {
            let _ = Key::delete_tree(Hive::CurrentUser, &site.key_path());
        }
        (lock, guard)
    }

    /// A path that passes [`is_trusted_dll_path`] and is not there.
    ///
    /// # Why the tests have no DLL that is both trusted and real
    ///
    /// Because no directory an unelevated test can write to is trusted, and
    /// that is the check working: the trusted locations are the ones only an
    /// administrator can write, which is the whole point of the rule. So the
    /// tests use a path spelled like a real installation — under `Program
    /// Files`, the directory the product would actually live in — and the
    /// consequence is that a status read of an installed fixture reports
    /// `on_disk: false`. The test that asserts it says so and explains why.
    ///
    /// [`check_present`] is therefore tested by calling it, and the existence
    /// check never runs inside [`install_under`] — see its documentation.
    fn trusted_path() -> PathBuf {
        PathBuf::from(r"C:\Program Files\Wenle AV\av_amsi.dll")
    }

    #[test]
    fn the_two_registration_keys_are_the_ones_amsi_and_com_read() {
        // The paths, spelled out, because a typo in either is a registration
        // that installs cleanly and is never enumerated by anything. `Classes`
        // and `Microsoft\AMSI` are the operating system's own key names and are
        // not this crate's to change; `clsid_string` is asserted separately.
        assert_eq!(
            Site::ClientNative.key_path(),
            format!(r"SOFTWARE\Classes\CLSID\{}", clsid_string())
        );
        assert_eq!(
            Site::ProviderNative.key_path(),
            format!(r"SOFTWARE\Microsoft\AMSI\Providers\{}", clsid_string())
        );
        assert_eq!(
            Site::ClientNative.inproc_server_path(),
            format!(r"SOFTWARE\Classes\CLSID\{}\InprocServer32", clsid_string())
        );
    }

    #[test]
    fn the_two_views_differ_only_by_where_the_32_bit_one_lives() {
        // The 32-bit sites are the same keys under `WOW6432Node`, and that is
        // the whole of the difference. Asserted rather than assumed because the
        // alternative spelling — writing the native key and passing a WOW64
        // flag to the registry call — produces the same machine state by a
        // different route, and the two must not both be used.
        assert_eq!(
            Site::ClientWow64.key_path(),
            format!(r"SOFTWARE\WOW6432Node\Classes\CLSID\{}", clsid_string())
        );
        assert_eq!(
            Site::ProviderWow64.key_path(),
            format!(
                r"SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers\{}",
                clsid_string()
            )
        );
        for site in Site::ALL {
            assert_eq!(site.hive(), Hive::LocalMachine, "{site:?}");
        }
    }

    #[test]
    fn every_site_is_classified_and_the_native_pair_is_the_one_an_install_writes() {
        assert_eq!(Site::NATIVE.len() + Site::OTHER_VIEW.len(), Site::ALL.len());
        for site in Site::NATIVE {
            assert!(site.is_native(), "{site:?}");
        }
        for site in Site::OTHER_VIEW {
            assert!(!site.is_native(), "{site:?}");
            assert!(site.key_path().contains("WOW6432Node"), "{site:?}");
            assert!(Site::ALL.contains(&site));
        }
        // The native pair is the first two, so a report reads 64-bit first.
        assert_eq!(&Site::ALL[..2], &Site::NATIVE);
        assert_eq!(
            Site::ClientNative.kind(),
            Site::ClientWow64.kind(),
            "the views are the same kind of site"
        );
    }

    #[test]
    #[should_panic(expected = "a provider site has no InprocServer32 subkey")]
    fn asking_a_provider_site_for_a_dll_subkey_is_a_programming_error() {
        // The one misuse the type system cannot rule out, and it is a bug in
        // this crate rather than something a machine can cause.
        let _ = Site::ProviderNative.inproc_server_path();
    }

    #[test]
    fn a_machine_with_nothing_registered_says_absent_and_not_broken() {
        let (_lock, _guard) = guard();
        let status = status_under(Hive::CurrentUser).expect("the user's half is readable");
        assert!(status.is_absent());
        assert_eq!(status.registered(), 0);
        assert!(!status.is_complete());
        assert!(status.problems().is_empty(), "absence is not a problem");
        assert!(status.other_views().is_empty());
    }

    #[test]
    fn a_key_with_no_dll_under_it_is_incomplete_and_not_absent() {
        // The distinction the whole three-state enum exists for. Written by
        // hand rather than through `install`, because `install` cannot produce
        // this state — which is the point: it is the state a half-finished
        // install by something else leaves behind.
        let (_lock, _guard) = guard();
        Key::create(Hive::CurrentUser, &Site::ClientNative.key_path())
            .expect("the CLSID key");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert!(!status.is_absent());
        assert_eq!(status.registered(), 0);
        assert!(matches!(
            status.state(Site::ClientNative),
            SiteState::Incomplete { .. }
        ));
        assert!(
            !status.problems().is_empty(),
            "a key naming no DLL is a problem"
        );
        assert!(status.problems()[0].contains("InprocServer32"));
    }

    #[test]
    fn an_empty_default_value_is_incomplete_rather_than_a_registration() {
        // `Some("")` is a value that is there and says nothing, and it must not
        // be read as a path. `PathBuf::from("")` is an empty path, and a report
        // that printed it would show a blank where a file name should be.
        let (_lock, _guard) = guard();
        Key::create(Hive::CurrentUser, &Site::ClientNative.key_path()).expect("the CLSID key");
        Key::create(
            Hive::CurrentUser,
            &Site::ClientNative.inproc_server_path(),
        )
        .expect("the InprocServer32 subkey")
        .set_string("", "")
        .expect("an empty default value");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert!(matches!(
            status.state(Site::ClientNative),
            SiteState::Incomplete { .. }
        ));
    }

    #[test]
    fn the_dll_a_registration_names_is_reported_verbatim_and_not_re_derived() {
        // The question a status answers is what Windows will load, and the
        // answer is a string somebody else wrote — a different version of the
        // product, in a different directory, or not this product at all. A
        // report that substituted this process's own path would answer a
        // question nobody asked and hide the one they did.
        let (_lock, _guard) = guard();
        let elsewhere = PathBuf::from(r"D:\somewhere\other\av_amsi.dll");
        Key::create(Hive::CurrentUser, &Site::ClientNative.key_path()).expect("the CLSID key");
        let server = Key::create(
            Hive::CurrentUser,
            &Site::ClientNative.inproc_server_path(),
        )
        .expect("the InprocServer32 subkey");
        server
            .set_string("", &elsewhere.to_string_lossy())
            .expect("the DLL path");
        server
            .set_string("ThreadingModel", THREADING_MODEL)
            .expect("the threading model");
        Key::create(Hive::CurrentUser, &Site::ProviderNative.key_path())
            .expect("the provider key");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert_eq!(status.registered(), 2);
        assert_eq!(
            status.state(Site::ClientNative).dll(),
            Some(elsewhere.as_path())
        );
        // And it is reported as a problem, because that file is not there: the
        // provider would fail to load.
        let problems = status.problems();
        assert!(
            problems.iter().any(|line| line.contains("is not there")),
            "{problems:?}"
        );
        assert!(
            !status.is_complete(),
            "a registration naming a missing DLL is not a working one"
        );
    }

    #[test]
    fn a_provider_key_with_no_values_is_a_complete_registration_for_that_site() {
        // The half of the registration that has nothing to read back. A report
        // that expected values here would call a correct machine broken.
        let (_lock, _guard) = guard();
        Key::create(Hive::CurrentUser, &Site::ProviderNative.key_path())
            .expect("the provider key");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert!(matches!(
            status.state(Site::ProviderNative),
            SiteState::Present(Detail::Provider)
        ));
        assert_eq!(status.registered(), 1);
        assert!(status.state(Site::ProviderNative).dll().is_none());
    }

    #[test]
    fn installing_writes_the_two_native_keys_and_neither_of_the_other_view() {
        let (_lock, _guard) = guard();
        install_under(Hive::CurrentUser, &trusted_path()).expect("the install");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert_eq!(status.registered(), 2);
        assert!(
            status.other_views().is_empty(),
            "this build is 64-bit and must not claim the 32-bit view: {:?}",
            status.other_views()
        );
        assert_eq!(
            status.state(Site::ClientNative).dll(),
            Some(trusted_path().as_path())
        );
        assert!(matches!(
            status.state(Site::ProviderNative),
            SiteState::Present(Detail::Provider)
        ));
        // The DLL was never written, so `on_disk` is false — and that is the
        // honest reading, not a bug in the install: the tests run a DLL that
        // does not exist because a path that passes the trust check cannot also
        // be a temporary directory.
        if let SiteState::Present(Detail::Client {
            on_disk, trusted, ..
        }) = status.state(Site::ClientNative)
        {
            assert!(!on_disk);
            assert!(trusted);
        } else {
            panic!("the client site is present");
        }
    }

    #[test]
    fn installing_twice_leaves_the_registry_the_same_as_installing_once() {
        // What makes `install` the repair for a half-finished registration as
        // well as the first step of a complete one.
        let (_lock, _guard) = guard();
        install_under(Hive::CurrentUser, &trusted_path()).expect("the first install");
        let once = status_under(Hive::CurrentUser).expect("readable");
        install_under(Hive::CurrentUser, &trusted_path()).expect("the second install");
        let twice = status_under(Hive::CurrentUser).expect("readable");
        assert_eq!(once, twice);
    }

    #[test]
    fn removing_takes_the_other_view_too_because_it_names_this_clsid() {
        // `remove` answers "is this CLSID registered here", and the answer has
        // to be no afterwards. A 32-bit entry left behind names our CLSID and
        // points at a DLL this build cannot load.
        let (_lock, _guard) = guard();
        for site in [Site::ClientNative, Site::ProviderNative, Site::ClientWow64] {
            Key::create(Hive::CurrentUser, &site.key_path()).expect("a key to remove");
        }

        remove_under(Hive::CurrentUser).expect("the removal");
        let status = status_under(Hive::CurrentUser).expect("readable");
        assert!(status.is_absent(), "{:?}", status.sites());
        assert!(status.other_views().is_empty());
    }

    #[test]
    fn removing_a_registration_that_was_never_there_is_not_an_error() {
        // What makes `remove` usable as the cleanup step of a failed install.
        let (_lock, _guard) = guard();
        remove_under(Hive::CurrentUser).expect("removing nothing");
    }

    #[test]
    fn a_dll_in_a_directory_a_user_can_write_is_refused_before_anything_is_written() {
        // The privilege boundary. Nothing may be created on this path: a key
        // that appeared and was then refused for the path would leave a
        // registration a user has to know to remove.
        let (_lock, _guard) = guard();
        let writable = PathBuf::from(r"C:\Users\me\Downloads\wenle\av_amsi.dll");
        let error = install_under(Hive::CurrentUser, &writable).expect_err("the refusal");
        assert!(
            matches!(&error, AmsiError::UnsafeDllPath { path } if path == &writable),
            "{error:?}"
        );
        assert!(status_under(Hive::CurrentUser).expect("readable").is_absent());
    }

    #[test]
    fn a_dll_that_is_not_there_is_refused_and_the_message_names_the_directory() {
        // The existence check, tested where it lives rather than through
        // `install_under` — which deliberately does not perform it, so that a
        // test can hand it a path that is not there. What this asserts is that
        // `install` would refuse, and the error carries the directory so the
        // message can say where it looked: "there is no av_amsi.dll" without a
        // directory is a message about a file the user cannot find.
        let missing = PathBuf::from(r"C:\Program Files\Wenle AV\not_built_yet.dll");
        let error = check_present(&missing).expect_err("the refusal");
        match error {
            AmsiError::DllMissing { directory } => {
                assert_eq!(directory, PathBuf::from(r"C:\Program Files\Wenle AV"));
            }
            other => panic!("{other:?}"),
        }
        // And the whole check a real install performs refuses it too.
        assert!(matches!(
            check_dll(&missing),
            Err(AmsiError::DllMissing { .. })
        ));
    }

    #[test]
    fn a_dll_that_is_there_passes_the_existence_check() {
        // The other half, without which the test above would pass against a
        // function that refused everything. The test binary is a file that is
        // certainly there and certainly not a DLL, which is the right fixture:
        // this check asks whether a path names an existing file and has no
        // opinion about what is in it.
        let here = std::env::current_exe().expect("this test binary's own path");
        check_present(&here).expect("an existing file passes");
    }

    #[test]
    fn the_path_check_is_asked_before_the_file_is_looked_for() {
        // Both are wrong with this path — it is under a profile *and* the file
        // is not there — and the message a user gets has to be about the
        // writable directory, because that is the decision they have to make.
        // A missing-file message would send them looking for a packaging
        // problem that does not exist.
        let both_wrong = PathBuf::from(r"C:\Users\me\nowhere\av_amsi.dll");
        assert!(
            matches!(check_dll(&both_wrong), Err(AmsiError::UnsafeDllPath { .. })),
            "the trust check is not asked first"
        );
    }

    #[test]
    fn a_wrong_threading_model_is_reported_as_a_problem() {
        // COM assumes `Apartment` when the value is missing, and an in-proc
        // server registered that way needs a marshaller when the host creates
        // it from an MTA thread. It works — which is why nobody notices, and
        // why the report has to say it.
        let (_lock, _guard) = guard();
        Key::create(Hive::CurrentUser, &Site::ClientNative.key_path()).expect("the CLSID key");
        let server = Key::create(
            Hive::CurrentUser,
            &Site::ClientNative.inproc_server_path(),
        )
        .expect("the InprocServer32 subkey");
        server
            .set_string("", &trusted_path().to_string_lossy())
            .expect("the DLL path");
        server
            .set_string("ThreadingModel", "Apartment")
            .expect("the wrong threading model");

        let status = status_under(Hive::CurrentUser).expect("readable");
        let problems = status.problems();
        assert!(
            problems
                .iter()
                .any(|line| line.contains("threading model is Apartment")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_other_view_is_reported_when_something_registered_it() {
        // Not a fault — a machine with a 32-bit copy of the product is entitled
        // to have one — but it must be visible, because a 32-bit entry naming a
        // 64-bit DLL is a provider that fails to load while the registry looks
        // complete.
        let (_lock, _guard) = guard();
        Key::create(Hive::CurrentUser, &Site::ProviderWow64.key_path())
            .expect("a 32-bit provider entry");

        let status = status_under(Hive::CurrentUser).expect("readable");
        assert_eq!(status.other_views(), vec![Site::ProviderWow64]);
        assert_eq!(status.registered(), 0, "the native half is still empty");
        assert!(!status.is_complete());
        assert!(
            status.problems().is_empty(),
            "a 32-bit entry is not itself a problem: {:?}",
            status.problems()
        );
    }
}
