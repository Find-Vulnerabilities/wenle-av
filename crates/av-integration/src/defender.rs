//! Windows Defender's real-time monitoring: reporting it, turning it off, and
//! putting back exactly what was there.
//!
//! # Why a machine should not run two real-time scanners
//!
//! Real-time monitoring is an on-access filter. Every file that is opened,
//! written, executed or renamed is handed to it before the operation completes,
//! and both products in that position pay for the other: two kernel callbacks on
//! the same operation, two caches of the same file, and two answers to a question
//! that has one. What a user sees is a machine that takes seconds to open a
//! document, and what a support desk sees is two vendors each able to say the
//! other one is at fault.
//!
//! So this product would rather be the only one. That is the whole purpose of
//! this module, and it is worth saying at the top that it is a *preference the
//! owner of the machine has to act on* and not anything the product does for
//! them: see the next section.
//!
//! # What is given up, in plain words
//!
//! **While Defender's real-time monitoring is off, this product's own real-time
//! protection is the only thing examining file operations on this machine.** If
//! that protection is not running (the service is stopped, the product is
//! uninstalled, the machine is in a state where nothing of ours starts), then
//! nothing is examining them, and the machine is unprotected in a way that no
//! window will tell the user about. Defender's on-demand scanning can still be
//! invoked by hand, and its signature updates still arrive, but nothing watches
//! a file as it is written.
//!
//! That is a real loss of protection and it is stated here, in
//! `wenle integrate defender --help`, and on the screen of the person who runs
//! the command. It is not stated anywhere as a benefit.
//!
//! # Nothing here runs by itself
//!
//! There is exactly one way to reach the code that changes this setting: a
//! person typing `wenle integrate defender disable`. It is **not** called from an
//! installer, from `wenle service install`, from service start, from a scan,
//! from the graphical front end, or from any first-run path. Nothing in this
//! crate calls [`disable`] except the command handler.
//!
//! That is a deliberate structural choice and not a comment about intent. An
//! antivirus that turned off a competitor as a side effect of being installed
//! would be doing to its users something it exists to prevent other software
//! from doing to them, and it would be doing it to every user rather than to the
//! ones who asked.
//!
//! # The keys, and which of them can be written at all
//!
//! Two different keys hold a value called `DisableRealtimeMonitoring`, and they
//! are not two spellings of one setting:
//!
//! | Key below `HKEY_LOCAL_MACHINE` | What it is |
//! |---|---|
//! | `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` | Defender's own record of the setting. This is what the Windows Security toggle writes, and what `Set-MpPreference -DisableRealtimeMonitoring` writes. |
//! | `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` | The Group Policy control: *Computer Configuration → Administrative Templates → Microsoft Defender Antivirus → Real-time Protection → Turn off real-time protection*. A value here is a policy that the Defender service applies. |
//!
//! In both, the value is a `REG_DWORD`, `1` means real-time monitoring is off,
//! and `0` or an absent value means it is not off. Absence is the ordinary
//! state: a machine nobody has configured has no such value in either key, which
//! is why this module reads "absent" as "on" rather than as "unknown".
//!
//! **Only the second of the two is written.** The first is the natural place to
//! write (it is the setting rather than a policy about it), and this module does
//! not write it, because on the machine this was measured on it cannot be
//! written by an administrator at all. Its ACL grants `BUILTIN\Administrators`
//! `ReadKey` and `CreateLink` and nothing else, so `RegSetValueExW` against it
//! comes back `ERROR_ACCESS_DENIED` however elevated the caller is:
//!
//! ```text
//! HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
//!   NT SERVICE\TrustedInstaller   FullControl
//!   NT SERVICE\WinDefend          FullControl
//!   NT AUTHORITY\SYSTEM           FullControl
//!   BUILTIN\Administrators        CreateLink, ReadKey      <- no KEY_SET_VALUE
//!   Everyone                      CreateLink, ReadKey
//! ```
//!
//! That is one machine's ACL, read with `Get-Acl` on a stock Windows 11 install,
//! and it is reported here rather than generalised: the claim this module acts on
//! is the weak one (*this key is not reliably writable, so nothing depends on
//! writing it*) and not the strong one, that no machine anywhere permits it. A
//! future Windows that loosened the ACL would not make anything here wrong; it
//! would only mean a write this module does not attempt would have worked.
//!
//! The policy key, by contrast, grants `BUILTIN\Administrators` `FullControl`,
//! and writing one value into it is a complete and self-contained policy: there
//! is no accompanying value, no service restart and no `gpupdate` needed.
//!
//! The ACL has a second consequence, and it is the reason every read in this
//! module goes through [`Key::open_read_only`] rather than [`Key::open`]. The
//! registry layer's ordinary `open` asks for `KEY_READ | KEY_WRITE` so that every
//! method on the handle it returns works, and `RegOpenKeyExW` with `KEY_WRITE`
//! against a key that grants only `ReadKey` fails with code 5, before anything
//! is read. A `status` that opened the setting for writing would therefore be
//! refused on exactly the machines somebody was trying to ask about, elevated or
//! not, and `reg query` succeeds on the same key because it asks only to read.
//!
//! The same ACLs are why [`status`] can, on one machine, still be refused. The
//! keys measured above say it should not happen: `Authenticated Users` holds
//! `ReadKey` on `SOFTWARE\Policies\Microsoft\Windows Defender`, inherited, so a
//! subkey created below it inherits a read for an ordinary user, which is what
//! makes an unelevated `status` possible on a machine this product has already
//! changed. But that is an *inference* from an inheritable entry and not a
//! measurement of a key this product created, and the measurement that would
//! settle it can only be made by creating a key in Defender's policy tree, which
//! is a write to the exact place this command exists to change deliberately.
//! There is also a counterexample next to it: the sibling key
//! `SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager` refuses an
//! ordinary reader outright (`reg query` against it returns `Access is denied`
//! unelevated, and `Get-Acl` reads back no entries at all), so "a subkey under
//! that parent is readable" is not something to assume.
//!
//! So the possibility is named rather than assumed away: when the policy key is
//! there and this process may not read it, `status` returns
//! [`DefenderError::PolicyUnreadable`] instead of a report. A report that printed
//! "(not set)" because it could not look would describe a machine nobody has, and
//! a bare Win32 code would leave the user without the remedy, which is to run the
//! same command from an elevated prompt.
//!
//! # What the registry cannot be asked
//!
//! **The registry holds settings; it does not hold the running state.** Nothing
//! in either key says whether the Defender service is, at this moment, filtering
//! file operations. The supported way to ask that is the WMI class
//! `MSFT_MpComputerStatus` in `root\Microsoft\Windows Defender` and its
//! `RealTimeProtectionEnabled` property, which is what `Get-MpComputerStatus`
//! reads, which goes through the service rather than through the registry, and
//! which this module does not call.
//!
//! So the report [`status`] produces is a report about *settings*, and it says so
//! in its own output rather than leaving a user to infer protection from a
//! number. Three specific things it therefore cannot tell you:
//!
//! * Whether a policy value that is present has been applied yet. A policy is
//!   read by the service; this module can see that it is there.
//! * Whether the service is running at all. [`DefenderStatus::passive`] reads
//!   `PassiveMode`, which is Defender's own record that another antivirus is
//!   registered and that it is not doing on-access scanning, but that is a
//!   setting too, not a measurement.
//! * Whether an unrelated mechanism (a licensing state, an outdated platform, a
//!   managed deployment's own policy) has already stopped monitoring for
//!   reasons of its own. Real-time monitoring can be configured on and not be
//!   running, and this module cannot distinguish the two.
//!
//! # Tamper protection, and what it does to the write
//!
//! Defender has an anti-tamper feature of its own, recorded at
//! `SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection`. When it is in
//! force, Defender treats changes to its settings, including a policy value,
//! as an attack: the change is refused or reverted, and an event (5013) is
//! logged. It is on by default on current Windows, and it is the single most
//! likely reason a `disable` on a real machine does nothing.
//!
//! This module reads that value and reports it, and it does not attempt to
//! change it: turning off a security feature in order to turn off a second one
//! is a different and much worse operation than the one this module exists for.
//!
//! The reading is conservative. Microsoft documents one value (`5`, "tamper
//! protection is deployed"), and other numbers appear in the field with meanings
//! that are not documented in one place. So anything other than
//! zero is reported as [`Tamper::InForce`] carrying the raw number, and the raw
//! number is printed. Treating an unrecognised number as "off" would produce the
//! dangerous error (a user told their write will stick when Defender is about to
//! revert it), and the cost of the other direction is a warning somebody did not
//! need.
//!
//! The authoritative answer to "is tamper protection on" is the toggle in
//! Windows Security, and this module says so rather than claiming to replace it.
//!
//! # The undo, and why it is a record rather than a rule
//!
//! [`restore`] does not turn real-time monitoring on. It puts back **the value
//! that was there before this product changed it**, and the difference matters:
//! a machine can have real-time monitoring off for a reason that is not this
//! product's to override (an administrator's policy, a deliberate choice, a
//! second security product mid-installation), and a `restore` that switched it on
//! would be quietly undoing somebody else's decision.
//!
//! So the previous state is written down before anything is changed, in a key
//! this product owns:
//!
//! ```text
//! HKLM\SOFTWARE\WenleAV\Defender
//!   PreviousDisableRealtimeMonitoring   REG_SZ   "absent" | "<decimal>"
//! ```
//!
//! One string, with two shapes and no third: the word `absent` when the policy
//! value was not there at all, or the decimal number it held (`0` or `1` in
//! practice, but the exact `REG_DWORD` that was found is what is stored, so a
//! value somebody set to something else is put back as what it was). A value that
//! is neither of those is refused rather than interpreted, by [`Previous::decode`]
//! and therefore by [`restore`]. Nothing here guesses at a trailing byte or
//! treats an unparseable string as "on".
//!
//! The record's *presence* is what makes it the record: there is no separate flag
//! saying "this product disabled it", because a second piece of state that can
//! disagree with the first is a second way to be wrong. A record that exists
//! means this command made the change and knows what to put back; no record means
//! it did not.
//!
//! Three orderings in the code below exist for this and are worth naming:
//!
//! * **The record is written before the setting is changed.** An interruption
//!   between the two leaves a record and an unchanged machine, and `restore` on
//!   that machine writes back the value that is already there. The other order
//!   leaves a machine with monitoring off and nothing that says what to put back.
//! * **`disable` refuses when a record already exists.** Running it twice would
//!   otherwise record what the *first* run wrote (its own value) and destroy
//!   the only copy of the original setting.
//! * **The record is cleared only after the value has been put back.** A
//!   `restore` whose write failed keeps the record, so running it again is the
//!   remedy, and a `restore` that succeeded does not leave a stale record that a
//!   later `disable` would refuse over.
//!
//! The record is a registry value and not a file, because the two have to have
//! the same lifetime: the undo has to survive a reboot, an update and a
//! reinstall, and a file under the product's data directory does not survive an
//! uninstall.
//!
//! # What is left behind
//!
//! * **The `Real-Time Protection` key under the policy path is not deleted.** If
//!   it was not there before, it is there afterwards and empty. An empty policy
//!   key applies no setting (a policy is a value), and deleting the key would
//!   risk taking a value something else had put in it, because this crate's
//!   registry layer enumerates subkeys and has no way to enumerate values. Two
//!   empty keys are a smaller price than that, which is the same trade the
//!   registry round-trip test in this crate makes about its own scratch key.
//! * **`HKLM\SOFTWARE\WenleAV\Defender` is not deleted either**, for the same
//!   reason: the product owns it, and it is where a later `disable` will write.
//!   Its value is what is removed.
//! * **A policy value that is present changes what a user sees.** Windows
//!   Security reports the setting as managed by an administrator and stops
//!   offering the toggle. That is not a side effect a user should discover
//!   afterwards, which is why the command says it before it acts.
//!
//! # Elevation
//!
//! Everything this module writes is under `HKEY_LOCAL_MACHINE`, so both
//! [`disable`] and [`restore`] ask [`is_elevated`] first and refuse with
//! [`DefenderError::NeedsElevation`] rather than attempting a write that the
//! machine will refuse deeper down. [`status`] reads, which is why it is
//! expected to work from an ordinary prompt, and why a user can find out what
//! is set before deciding whether to elevate.
//!
//! Elevation is necessary and may not be sufficient. The policy key's ACL grants
//! an administrator `FullControl`, but an ACL is not a promise, and a code 5 that
//! arrives anyway is reported as what it is: a refusal by the machine's own
//! permissions rather than by this process's elevation, which no amount of
//! elevating will change.

use crate::registry::{Hive, Key, RegistryError};
use crate::shell::is_elevated;

/// `ERROR_ACCESS_DENIED`.
///
/// The one Win32 code this module turns into a sentence of its own rather than
/// passing through [`RegistryError`]. See [`unreadable_policy`].
const ERROR_ACCESS_DENIED: u32 = 5;

/// Defender's own record of the setting, below `HKEY_LOCAL_MACHINE`.
pub const SETTINGS_KEY: &str = r"Software\Microsoft\Windows Defender\Real-Time Protection";

/// The Group Policy control, below `HKEY_LOCAL_MACHINE`.
pub const POLICY_KEY: &str = r"Software\Policies\Microsoft\Windows Defender\Real-Time Protection";

/// The key `TamperProtection` lives in.
const FEATURES_KEY: &str = r"Software\Microsoft\Windows Defender\Features";

/// The root of Defender's own key, where `PassiveMode` lives.
const DEFENDER_KEY: &str = r"Software\Microsoft\Windows Defender";

/// The value both of the two setting keys hold.
///
/// One constant and not two, because it is one value name: the two keys differ
/// in who may write them, not in what they store.
pub const DISABLE_VALUE: &str = "DisableRealtimeMonitoring";

/// The value that records whether Defender's own anti-tamper is in force.
pub const TAMPER_VALUE: &str = "TamperProtection";

/// The value that records whether Defender is a passive provider.
pub const PASSIVE_VALUE: &str = "PassiveMode";

/// This product's own key, below `HKEY_LOCAL_MACHINE`.
pub const RECORD_KEY: &str = r"Software\WenleAV\Defender";

/// The value in [`RECORD_KEY`] that holds the state to restore.
pub const RECORD_VALUE: &str = "PreviousDisableRealtimeMonitoring";

/// What the setting was before this product changed it.
///
/// Stored as text rather than as a number, because the state it has to represent
/// is not a number: "the value was not there" and "the value was 0" are
/// different, they have different undos, and a `REG_DWORD` cannot hold both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Previous {
    /// The value was not there. Putting it back means removing the value.
    Absent,
    /// The value was there and held this. Putting it back means writing it.
    Dword(u32),
}

impl Previous {
    /// The text this state is stored as.
    ///
    /// `absent`, or the number in decimal. Pure, so that the round trip through
    /// the registry is a property of two functions rather than of a machine.
    pub fn encode(self) -> String {
        match self {
            Self::Absent => "absent".to_string(),
            Self::Dword(value) => value.to_string(),
        }
    }

    /// The state a stored string names, or `None` for one this module will not
    /// interpret.
    ///
    /// Strict on purpose. `Some(0)` for anything that is not the word `absent`
    /// and does not parse as a `u32` would make a corrupted or hand-edited
    /// record a silent instruction to turn real-time monitoring off, and
    /// `unwrap_or(0)` would make it a silent instruction to do nothing. A
    /// refusal is the only answer that leaves the decision with the person who
    /// can look at the value and see what it says.
    pub fn decode(text: &str) -> Option<Self> {
        if text == "absent" {
            return Some(Self::Absent);
        }
        text.parse::<u32>().ok().map(Self::Dword)
    }

    /// How this state reads in a sentence.
    pub fn describe(self) -> String {
        match self {
            Self::Absent => "the value was not there".to_string(),
            Self::Dword(value) => format!("the value was {value}"),
        }
    }
}

/// What the registry says about real-time monitoring, settings only.
///
/// See the module documentation for what this is *not*: it is derived from two
/// values that record what has been asked for, and it is not a measurement of
/// whether anything is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Monitoring {
    /// Neither key has a value that turns it off.
    On,
    /// Defender's own key has the value set.
    OffBySetting,
    /// The policy key has the value set. A policy asked for this, which is a
    /// different fact from a user having chosen it — and the one this product
    /// creates.
    OffByPolicy,
}

impl Monitoring {
    /// How this reads in a sentence.
    pub fn describe(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::OffBySetting => "off",
            Self::OffByPolicy => "off, by policy",
        }
    }

    /// Whether anything has asked for it to be off.
    pub fn is_off(self) -> bool {
        !matches!(self, Self::On)
    }
}

/// What `TamperProtection` says, and how much of it this module will read into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    /// The value is there and is zero.
    Off,
    /// The value is there and is not zero, so anti-tamper is treated as in
    /// force. The raw number is carried because this module does not claim to
    /// know what each one means — see the module documentation.
    InForce {
        /// The number that was found.
        raw: u32,
    },
    /// The value is not there at all, which is the ordinary state of a Windows
    /// old enough not to have the feature, and is not a claim that it is off.
    NotReported,
}

impl Tamper {
    /// Whether a change to Defender's settings should be expected to survive.
    pub fn may_revert_writes(self) -> bool {
        matches!(self, Self::InForce { .. })
    }

    /// How this reads in a sentence.
    pub fn describe(self) -> String {
        match self {
            Self::Off => "off".to_string(),
            Self::InForce { raw } => format!("in force (TamperProtection is {raw})"),
            Self::NotReported => "not reported by this machine".to_string(),
        }
    }
}

/// What the registry says about Defender on this machine.
///
/// Read-only, and read unelevated: every value below is one `Everyone` may read,
/// which is what makes `wenle integrate defender status` useful to somebody who
/// has not decided whether to elevate yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenderStatus {
    /// The policy value, when it is there.
    policy: Option<u32>,
    /// Defender's own value, when it is there.
    setting: Option<u32>,
    /// What `TamperProtection` says.
    tamper: Tamper,
    /// `PassiveMode`, when it is there.
    passive: Option<u32>,
    /// This product's record of what it changed, when there is one.
    record: Option<Previous>,
}

impl DefenderStatus {
    /// What the two setting keys add up to.
    ///
    /// The policy wins, because that is what a policy is: a machine where the
    /// policy asks for monitoring off and Defender's own value says on is a
    /// machine where monitoring is off, and a report that read the setting first
    /// would describe it as on.
    pub fn monitoring(&self) -> Monitoring {
        if matches!(self.policy, Some(value) if value != 0) {
            Monitoring::OffByPolicy
        } else if matches!(self.setting, Some(value) if value != 0) {
            Monitoring::OffBySetting
        } else {
            Monitoring::On
        }
    }

    /// The policy value as it was read, for printing verbatim.
    pub fn policy(&self) -> Option<u32> {
        self.policy
    }

    /// Defender's own value as it was read, for printing verbatim.
    pub fn setting(&self) -> Option<u32> {
        self.setting
    }

    /// What `TamperProtection` says.
    pub fn tamper(&self) -> Tamper {
        self.tamper
    }

    /// `PassiveMode` as it was read, for printing verbatim.
    pub fn passive(&self) -> Option<u32> {
        self.passive
    }

    /// What this product recorded before it changed the setting, when it has.
    pub fn record(&self) -> Option<Previous> {
        self.record
    }

    /// Whether this product is holding the setting off.
    pub fn is_held_off_by_this_product(&self) -> bool {
        self.record.is_some()
    }
}

/// The ways this module refuses, and the two ways a registry call fails.
#[derive(Debug, thiserror::Error)]
pub enum DefenderError {
    /// A registry call failed. See [`RegistryError`], which names the key.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// This process may not write `HKEY_LOCAL_MACHINE`.
    ///
    /// Raised before anything is attempted, for the reason
    /// [`crate::shell::ShellError::NeedsElevation`] gives: nothing was tried, so
    /// there is no failing call for a caller to go looking for, and the sentence
    /// a user needs is the remedy rather than a Win32 code.
    #[error(
        "changing Windows Defender's real-time monitoring writes to HKEY_LOCAL_MACHINE, which \
         needs administrator rights, and this process is not elevated; run the command from an \
         elevated prompt"
    )]
    NeedsElevation,

    /// This product has a record that it already turned it off.
    ///
    /// Refused rather than repeated, because repeating it would write down what
    /// this command itself wrote a moment ago and lose the only copy of what was
    /// there before.
    #[error(
        "this product has already turned Windows Defender's real-time monitoring off, and \
         {RECORD_KEY} holds the record of what was there before; running this again would \
         overwrite that record with the value this command wrote, and the original setting would \
         be lost. Run `wenle integrate defender restore` first if you want to put it back"
    )]
    AlreadyDisabled,

    /// There is no record to restore from.
    ///
    /// Not an error about the machine, and not a failure to restore: it means
    /// this product did not make the change, so this product has nothing to undo.
    /// Restoring by *turning real-time monitoring on* would be overriding
    /// whatever else turned it off, which is the one thing this module will not
    /// do.
    #[error(
        "this product has no record of turning Windows Defender's real-time monitoring off, so \
         there is nothing here to put back. If it is off, something else turned it off — a user, \
         an administrator's policy, or another security product — and this command will not \
         override that decision"
    )]
    NothingToRestore,

    /// The record is there and says something this module will not interpret.
    #[error(
        "the record at {hive}\\{path}, value `{name}`, says `{found}`, which this command does \
         not understand. It expects `absent` or a decimal number. Nothing was changed: edit or \
         delete that value if you know what the setting was"
    )]
    UnreadableRecord {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
        /// The value's name.
        name: String,
        /// What the value actually said.
        found: String,
    },

    /// The value was written and does not read back as what was written.
    #[error(
        "the policy value was written but reads back as {found}, so it did not take. Nothing was \
         left behind: the real-time monitoring setting is whatever it was"
    )]
    NotApplied {
        /// What the value reads back as, as a person would write it.
        found: String,
    },

    /// The policy key is there and this process may not read it.
    ///
    /// The one read this module makes that an ordinary user might be refused,
    /// and therefore the one refusal that gets a sentence rather than a Win32
    /// code. See the module documentation for what is and is not known about the
    /// ACL on a key this product created.
    #[error(
        "the policy key {hive}\\{path} is there and this process is not allowed to read it, so \
         whether real-time monitoring is off cannot be reported from here. Nothing was changed. \
         Run the command again from an elevated prompt for the full report — the setting this \
         module turns off is the one value in that key, and a report that guessed at it would be \
         a report about a machine nobody has"
    )]
    PolicyUnreadable {
        /// The root.
        hive: Hive,
        /// The path below the root.
        path: String,
    },
}

/// A read of the policy key, with a refusal by its ACL named as itself.
///
/// Pure, and separate from [`status`] for the reason [`writable`] is separate
/// from [`ensure_elevated`]: the mapping from a Win32 code to the sentence a user
/// needs is the whole content of the function, and a test can hand it a code
/// without needing a key on this machine that refuses one — which would mean
/// creating a key in Defender's policy tree, the one thing this module must not
/// do from a test.
///
/// Only the policy read goes through this. A refused read of Defender's own keys
/// is a different fact — `Everyone` is granted `ReadKey` there, so code 5 is an
/// accident rather than the ordinary state of the key, and it should surface as
/// the failing call that [`RegistryError`] names. The same is true of every other
/// code: this maps exactly one of them.
fn unreadable_policy(
    read: Result<Option<u32>, DefenderError>,
) -> Result<Option<u32>, DefenderError> {
    match read {
        Err(DefenderError::Registry(
            RegistryError::Key {
                code: ERROR_ACCESS_DENIED,
                ..
            }
            | RegistryError::Value {
                code: ERROR_ACCESS_DENIED,
                ..
            },
        )) => Err(DefenderError::PolicyUnreadable {
            hive: Hive::LocalMachine,
            path: POLICY_KEY.to_string(),
        }),
        other => other,
    }
}

/// A `REG_DWORD` read back, as a person would write it.
///
/// `Option<u32>`'s own `Display` is `Some(1)`, which is a fact about this
/// program rather than about the machine, and the one message that uses this is
/// already an unexplained state — it does not need a second one.
fn describe_value(value: Option<u32>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "not there".to_string(),
    }
}

impl From<DefenderError> for av_core::AvError {
    /// The registry code survives; the rest becomes a sentence.
    ///
    /// [`DefenderError::NeedsElevation`] is [`av_core::AvError::Other`] and not
    /// [`av_core::AvError::AccessDenied`], for the reason
    /// [`crate::shell::ShellError`]'s conversion gives: nothing was attempted,
    /// so there is no failing call for a caller to go looking for.
    fn from(error: DefenderError) -> Self {
        match error {
            DefenderError::Registry(registry) => av_core::AvError::from(registry),
            other => av_core::AvError::Other(other.to_string()),
        }
    }
}

/// Refuse a write this process may not make, before anything is attempted.
fn ensure_elevated() -> Result<(), DefenderError> {
    writable(is_elevated())
}

/// The decision [`ensure_elevated`] makes, as a function of the answer alone.
///
/// Split out so that the refusal can be tested without a machine that is or is
/// not elevated — and, more to the point, so that a test of the refusal cannot
/// accidentally be a test that changes whether this machine is protected. A
/// `disable` that got as far as a registry call because the test happened to run
/// from an elevated prompt is the one failure mode this module must not have.
fn writable(elevated: bool) -> Result<(), DefenderError> {
    if elevated {
        Ok(())
    } else {
        Err(DefenderError::NeedsElevation)
    }
}

/// Refuse a second `disable` that would destroy the first one's record.
///
/// Pure for the reason [`writable`] is: the decision is about a value that was
/// read, and the consequence of getting it wrong — the only copy of what was
/// there before, overwritten with what this command itself wrote — is silent.
fn not_already_disabled(record: Option<Previous>) -> Result<(), DefenderError> {
    if record.is_some() {
        Err(DefenderError::AlreadyDisabled)
    } else {
        Ok(())
    }
}

/// The state [`restore`] has to put back, out of a record that may not be there.
///
/// Pure for the reason [`writable`] is, and because this is the refusal that
/// keeps the module honest: no record means this product did not make the
/// change, and the answer to that is a refusal and not a write of `0`.
fn restore_target(record: Option<Previous>) -> Result<Previous, DefenderError> {
    record.ok_or(DefenderError::NothingToRestore)
}

/// Read the setting out of `key`, as the state that would have to be put back.
///
/// Takes an open key rather than opening the real one, and that is not a
/// convenience: this and [`write_previous`] are the two halves of the undo, and
/// the only part of this module that can be exercised against a real registry
/// without changing whether the machine running the test is protected. The
/// integration test beside this crate opens a key under
/// `HKCU\Software\WenleAV\IntegrationTest` and gives it to both of them, so what
/// is verified is the reading, the encoding and the writing against the real
/// API, and what is not touched is `HKEY_LOCAL_MACHINE`.
pub fn read_previous(key: &Key) -> Result<Previous, DefenderError> {
    match key.dword(DISABLE_VALUE)? {
        Some(value) => Ok(Previous::Dword(value)),
        None => Ok(Previous::Absent),
    }
}

/// Put `previous` back into `key`, which is the whole of the undo.
///
/// [`Previous::Absent`] deletes the value rather than writing a zero, because
/// that is the state that was there and this module's job is to put back what it
/// found. The two states are the same setting to Defender and not the same
/// registry, and a user comparing the key before and after would be right to
/// notice the difference.
pub fn write_previous(key: &Key, previous: Previous) -> Result<(), DefenderError> {
    match previous {
        Previous::Absent => key.delete_value(DISABLE_VALUE)?,
        Previous::Dword(value) => key.set_dword(DISABLE_VALUE, value)?,
    }
    Ok(())
}

/// Read this product's record of what the setting was.
///
/// `None` is "this product has no record", which is a different thing from a
/// record that cannot be read — see [`DefenderError::UnreadableRecord`].
pub fn read_record(key: &Key) -> Result<Option<Previous>, DefenderError> {
    let Some(text) = key.string(RECORD_VALUE)? else {
        return Ok(None);
    };
    Previous::decode(&text).map(Some).ok_or_else(|| {
        DefenderError::UnreadableRecord {
            // Asked of the key rather than written down from this constant: the
            // caller is not always [`RECORD_KEY`] — a test points this at a
            // scratch key of its own — and a message naming `HKLM` for a value
            // under `HKCU` would send a user looking in the wrong hive, which is
            // the one thing an error about an unreadable record has to get right.
            hive: key.hive(),
            path: key.path().to_string(),
            name: RECORD_VALUE.to_string(),
            found: text,
        }
    })
}

/// Write the record down.
///
/// The string form of [`Previous`], written as a `REG_SZ` so that a person can
/// read it in `regedit` and know what `restore` is going to do. This is the
/// discoverability half of the undo: a record that only this program could read
/// would make the undo something a user has to take on faith.
pub fn write_record(key: &Key, previous: Previous) -> Result<(), DefenderError> {
    key.set_string(RECORD_VALUE, &previous.encode())?;
    Ok(())
}

/// Remove the record, once the value has been put back.
pub fn clear_record(key: &Key) -> Result<(), DefenderError> {
    key.delete_value(RECORD_VALUE)?;
    Ok(())
}

/// Read one of the DWORD settings, treating an absent key as an absent value.
///
/// Read-only, and that is not tidiness: `Software\Microsoft\Windows Defender`'s
/// keys grant an ordinary user — and an administrator — `ReadKey` and nothing
/// else, so a handle opened for writing is refused with code 5 before a single
/// value can be read out of it. Asking only to read is what makes a report
/// possible on the machine a user is actually asking about.
fn read_value(path: &str, name: &str) -> Result<Option<u32>, DefenderError> {
    match Key::open_read_only(Hive::LocalMachine, path)? {
        Some(key) => Ok(key.dword(name)?),
        None => Ok(None),
    }
}

/// What is set on this machine.
///
/// Read-only and unelevated. See the module documentation for what it does not
/// answer: this reports settings, and the registry holds settings rather than
/// running state.
pub fn status() -> Result<DefenderStatus, DefenderError> {
    let setting = read_value(SETTINGS_KEY, DISABLE_VALUE)?;
    let policy = unreadable_policy(read_value(POLICY_KEY, DISABLE_VALUE))?;
    let passive = read_value(DEFENDER_KEY, PASSIVE_VALUE)?;
    let tamper = match read_value(FEATURES_KEY, TAMPER_VALUE)? {
        None => Tamper::NotReported,
        Some(0) => Tamper::Off,
        // Anything else, including the documented `5` and the `1` this was
        // measured with. See the module documentation for why this direction is
        // the safe one.
        Some(raw) => Tamper::InForce { raw },
    };
    let record = match Key::open_read_only(Hive::LocalMachine, RECORD_KEY)? {
        Some(key) => read_record(&key)?,
        None => None,
    };

    Ok(DefenderStatus {
        policy,
        setting,
        tamper,
        passive,
        record,
    })
}

/// Turn Defender's real-time monitoring off, recording what was there.
///
/// Returns the state that was recorded, which is what [`restore`] will put back.
/// See the module documentation for the ordering of the three writes and the two
/// refusals, and for what a caller should not read into a success: the value is
/// in the registry, and whether the Defender service honours it is not something
/// this command can see.
pub fn disable() -> Result<Previous, DefenderError> {
    ensure_elevated()?;

    // Refused before the policy key is touched, so that a second `disable` on a
    // machine this product has already changed leaves that machine exactly as it
    // found it rather than creating an empty key on the way to a refusal. Read
    // only, because this half of the command only reads: the write to this key
    // happens below, through a handle opened for it.
    let existing = match Key::open_read_only(Hive::LocalMachine, RECORD_KEY)? {
        Some(key) => read_record(&key)?,
        None => None,
    };
    not_already_disabled(existing)?;

    let policy = Key::create(Hive::LocalMachine, POLICY_KEY)?;
    let previous = read_previous(&policy)?;

    // The record goes in first. See the module documentation: an interruption
    // after this line leaves a machine that is unchanged and knows what it would
    // have had to put back, which is the recoverable half of the pair.
    let record = Key::create(Hive::LocalMachine, RECORD_KEY)?;
    write_record(&record, previous)?;

    // From here on, a failure has to take the record back out: the record means
    // "this product changed the setting", and if the setting did not change then
    // the record is a claim that is not true, and a later `disable` would refuse
    // over it.
    //
    // Clearing it is best-effort and its failure is discarded deliberately. The
    // error worth reporting is the one that stopped the change; a second error
    // about the cleanup would replace it, and a caller reading "could not clear
    // the record" would have no way to know what had actually gone wrong. If the
    // clear does fail, the record is still there and `restore` removes it — which
    // writes back the value that is already in the key, and is harmless.
    if let Err(error) = policy.set_dword(DISABLE_VALUE, 1) {
        let _ = clear_record(&record);
        return Err(error.into());
    }

    // Read back, for the reason `wenle integrate shell install` reads back: a
    // write that did not take should be reported as one. This proves the value
    // landed and nothing more — see the module documentation on tamper
    // protection, which reverts a change *after* it has landed and leaves no
    // trace in this call.
    match policy.dword(DISABLE_VALUE) {
        Ok(Some(1)) => {}
        Ok(found) => {
            let _ = clear_record(&record);
            return Err(DefenderError::NotApplied {
                found: describe_value(found),
            });
        }
        Err(error) => {
            let _ = clear_record(&record);
            return Err(error.into());
        }
    }

    log::info!(
        "recorded {RECORD_KEY}\\{RECORD_VALUE} and wrote {DISABLE_VALUE}=1 into {POLICY_KEY}"
    );
    Ok(previous)
}

/// Put back what was there before this product changed it.
///
/// Returns the state that was restored, so that the command can say what it put
/// back rather than that it "turned it on". See the module documentation for why
/// this is a record rather than a rule.
pub fn restore() -> Result<Previous, DefenderError> {
    ensure_elevated()?;

    let record = Key::open(Hive::LocalMachine, RECORD_KEY)?;
    // A record key that is not there and a record key with nothing in it are the
    // same answer to the only question being asked — did this product make this
    // change — so they are collapsed here rather than being given two refusals
    // that would read as two different problems.
    let recorded = match &record {
        Some(key) => read_record(key)?,
        None => None,
    };
    let previous = restore_target(recorded)?;

    match Key::open(Hive::LocalMachine, POLICY_KEY)? {
        Some(policy) => write_previous(&policy, previous)?,
        // The key is not there, so there is no value in it to put back — unless
        // the record says there was one, in which case the key has to be made
        // again to hold it. `Key::create` is used rather than assuming, because
        // the record is the authority on what was there and the key's absence
        // is a fact about now.
        None if previous == Previous::Absent => {}
        None => {
            let policy = Key::create(Hive::LocalMachine, POLICY_KEY)?;
            write_previous(&policy, previous)?;
        }
    }

    // Only after the value is back. A `restore` that failed above keeps the
    // record, so that running it again is the remedy. The `Option` is unwrapped
    // here rather than earlier because reaching this line at all means the
    // record existed and was readable, so a key that is somehow not there now has
    // nothing left to clear and no reason to fail.
    if let Some(record) = &record {
        clear_record(record)?;
    }

    log::info!("restored {DISABLE_VALUE} in {POLICY_KEY} to {previous:?}");
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_setting_keys_are_different_keys() {
        // They hold one value name between them, and two paths that ever became
        // the same string would make this module's whole account of which one it
        // writes meaningless. Cheap to assert, and it is the one thing a typo in
        // either constant would break while everything still compiled.
        assert_ne!(SETTINGS_KEY, POLICY_KEY);
        assert!(SETTINGS_KEY.starts_with(r"Software\Microsoft\Windows Defender"));
        assert!(POLICY_KEY.starts_with(r"Software\Policies\Microsoft\Windows Defender"));
    }

    #[test]
    fn a_state_survives_being_written_down_and_read_back() {
        // The record's whole purpose, as a property of two pure functions rather
        // than of a machine. `Absent` against `Dword(0)` is the case that makes
        // this worth testing: they are the same setting to Defender, different
        // registries, and confusing them would make `restore` write a value where
        // it should have deleted one.
        for state in [
            Previous::Absent,
            Previous::Dword(0),
            Previous::Dword(1),
            Previous::Dword(u32::MAX),
        ] {
            assert_eq!(Previous::decode(&state.encode()), Some(state));
        }
    }

    #[test]
    fn a_record_this_module_did_not_write_is_refused_rather_than_interpreted() {
        // Strictness that matters: every one of these is a string that some
        // plausible `unwrap_or` would turn into a silent instruction, and a
        // silent instruction here is either "turn monitoring off" or "delete a
        // setting nobody asked you to touch".
        for text in [
            "",
            " ",
            "ABSENT",
            "Absent",
            "absent ",
            "-1",
            "1.0",
            "0x1",
            "true",
            "no",
            "4294967296",
            "absent\n",
        ] {
            assert_eq!(Previous::decode(text), None, "decoded {text:?}");
        }
    }

    #[test]
    fn a_decode_of_something_this_module_did_not_write_is_case_sensitive() {
        // Spelled out separately from the list above because it is the one a
        // well-meaning change would relax, and relaxing it would put back a
        // setting on the strength of a value this product never wrote.
        assert_eq!(Previous::decode("absent"), Some(Previous::Absent));
        assert_eq!(Previous::decode("Absent"), None);
        assert_eq!(Previous::decode("0"), Some(Previous::Dword(0)));
        assert_eq!(Previous::decode("00"), Some(Previous::Dword(0)));
    }

    /// A status built out of values a test chose, without a registry.
    fn status_with(policy: Option<u32>, setting: Option<u32>) -> DefenderStatus {
        DefenderStatus {
            policy,
            setting,
            tamper: Tamper::NotReported,
            passive: Some(0),
            record: None,
        }
    }

    #[test]
    fn an_absent_value_is_not_a_value_that_turns_anything_off() {
        // The ordinary machine: nobody has configured this, and neither key has
        // the value. Reading absence as "off" would report every unconfigured
        // machine in the world as unprotected.
        assert_eq!(status_with(None, None).monitoring(), Monitoring::On);
    }

    #[test]
    fn a_zero_means_the_same_thing_as_an_absent_value() {
        // `0` is what a user who turned it back on leaves behind, and a report
        // that called that off would be wrong about the machine it is describing.
        assert_eq!(status_with(None, Some(0)).monitoring(), Monitoring::On);
        assert_eq!(status_with(Some(0), None).monitoring(), Monitoring::On);
        assert_eq!(status_with(Some(0), Some(0)).monitoring(), Monitoring::On);
        assert!(!status_with(Some(0), Some(0)).monitoring().is_off());
    }

    #[test]
    fn the_policy_wins_over_defenders_own_value() {
        // A machine where the policy asks for off and the setting says on is a
        // machine where monitoring is off, and reading the setting first would
        // describe it as the opposite of what a policy is going to do.
        assert_eq!(
            status_with(Some(1), Some(0)).monitoring(),
            Monitoring::OffByPolicy
        );
        assert_eq!(
            status_with(Some(1), None).monitoring(),
            Monitoring::OffByPolicy
        );
        assert_eq!(
            status_with(None, Some(1)).monitoring(),
            Monitoring::OffBySetting
        );
        assert_eq!(
            status_with(Some(1), Some(1)).monitoring(),
            Monitoring::OffByPolicy
        );
    }

    #[test]
    fn any_non_zero_value_that_disables_is_read_as_disabling() {
        // These values are flags, and a value nobody documented is still a value
        // somebody set. The direction matters: reading `7` as "on" would tell a
        // user their machine is protected when a policy has asked for it not to
        // be.
        assert_eq!(
            status_with(None, Some(7)).monitoring(),
            Monitoring::OffBySetting
        );
        assert_eq!(
            status_with(Some(u32::MAX), None).monitoring(),
            Monitoring::OffByPolicy
        );
    }

    #[test]
    fn a_record_is_what_says_this_product_did_it() {
        // Not the value in the key: a user who sets the same value by hand, or
        // an administrator's policy that happens to match, must not make
        // `restore` believe it has something to undo.
        let mut status = status_with(Some(1), None);
        assert!(!status.is_held_off_by_this_product());
        status.record = Some(Previous::Absent);
        assert!(status.is_held_off_by_this_product());
        assert_eq!(status.record(), Some(Previous::Absent));
    }

    #[test]
    fn tamper_protection_is_treated_as_in_force_for_every_number_but_zero() {
        // The conservative reading, and the one that matters: a number this
        // module does not recognise must not be reported as "off", because the
        // user's next action is to trust a write that Defender is about to
        // revert.
        assert!(!Tamper::Off.may_revert_writes());
        assert!(!Tamper::NotReported.may_revert_writes());
        assert!(Tamper::InForce { raw: 1 }.may_revert_writes());
        assert!(Tamper::InForce { raw: 4 }.may_revert_writes());
        assert!(Tamper::InForce { raw: 5 }.may_revert_writes());
        assert!(Tamper::InForce { raw: u32::MAX }.may_revert_writes());
    }

    #[test]
    fn what_is_reported_carries_the_number_it_was_read_from() {
        // A report that said "in force" without the number would leave a user
        // unable to tell a documented state from an unrecognised one, and this
        // module does not claim to know what each number means.
        assert!(Tamper::InForce { raw: 5 }.describe().contains('5'));
        assert_eq!(Tamper::Off.describe(), "off");
        assert!(Tamper::NotReported.describe().contains("not reported"));
    }

    #[test]
    fn a_state_describes_itself_as_what_it_is() {
        assert_eq!(Previous::Dword(0).describe(), "the value was 0");
        assert_eq!(Previous::Absent.describe(), "the value was not there");
    }

    #[test]
    fn an_unelevated_process_is_refused_before_it_can_write_anything() {
        // The refusal that stands between a mistyped command and a change to the
        // machine. Tested through the decision and not through `disable()`,
        // because `disable()` on an *elevated* test run would do the thing this
        // module exists to make deliberate.
        let refused = writable(false).expect_err("nothing may be written unelevated");
        match refused {
            DefenderError::NeedsElevation => {}
            other => panic!("expected NeedsElevation, got {other:?}"),
        }
        let message = refused.to_string();
        assert!(message.contains("elevated"), "{message}");
        // The remedy, named, because a refusal a user cannot act on is a dead end.
        assert!(message.contains("administrator"), "{message}");

        assert!(writable(true).is_ok());
    }

    #[test]
    fn a_second_disable_is_refused_rather_than_recording_its_own_value() {
        // The bug this exists to prevent is silent and unrecoverable: the second
        // run would read the value the first run wrote, record *that* as the
        // previous state, and the only copy of the original setting would be
        // gone.
        let refused = not_already_disabled(Some(Previous::Absent))
            .expect_err("a record that exists means this was already done");
        match refused {
            DefenderError::AlreadyDisabled => {}
            other => panic!("expected AlreadyDisabled, got {other:?}"),
        }
        assert!(refused.to_string().contains("restore"), "{refused}");

        assert!(not_already_disabled(None).is_ok());
    }

    #[test]
    fn nothing_to_restore_is_a_refusal_and_never_a_write() {
        // The distinction the whole module turns on. `Previous::Dword(0)` here
        // would be a program that decided on its own to turn a security feature
        // on, over whatever else had turned it off.
        let refused = restore_target(None).expect_err("there is nothing to put back");
        match refused {
            DefenderError::NothingToRestore => {}
            other => panic!("expected NothingToRestore, got {other:?}"),
        }
        let message = refused.to_string();
        assert!(message.contains("no record"), "{message}");
        // And it says what it will not do, rather than leaving the user to guess
        // why a command called `restore` declined to restore anything.
        assert!(message.contains("will not override"), "{message}");

        for state in [Previous::Absent, Previous::Dword(0), Previous::Dword(1)] {
            assert!(
                matches!(restore_target(Some(state)), Ok(found) if found == state),
                "a record of {state:?} must be put back as itself"
            );
        }
    }

    #[test]
    fn a_denied_read_of_the_policy_key_is_named_and_anything_else_is_passed_through() {
        // The one place in this module where a Win32 code is replaced by a
        // sentence, and the lines on either side of that: code 5 becomes the
        // named refusal, every other code keeps the failing call that
        // `RegistryError` reports.
        let denied = |call| {
            DefenderError::Registry(RegistryError::Key {
                call,
                hive: Hive::LocalMachine,
                path: POLICY_KEY.to_string(),
                code: ERROR_ACCESS_DENIED,
            })
        };

        let refused = unreadable_policy(Err(denied("RegOpenKeyExW")))
            .expect_err("a key this process may not read is a refusal");
        match refused {
            DefenderError::PolicyUnreadable { hive, ref path } => {
                assert_eq!(hive, Hive::LocalMachine);
                assert_eq!(path, POLICY_KEY);
            }
            other => panic!("expected PolicyUnreadable, got {other:?}"),
        }
        // The two things a user needs: what could not be read, and what to do.
        let message = refused.to_string();
        assert!(message.contains(POLICY_KEY), "{message}");
        assert!(message.contains("elevated prompt"), "{message}");

        // Anything that is not a refusal is left alone. A code 2 — the key is
        // not there — is `read_value`'s ordinary success path, and a code 5 from
        // somewhere else in the module is a fact about a different key.
        let missing = DefenderError::Registry(RegistryError::Key {
            call: "RegOpenKeyExW",
            hive: Hive::LocalMachine,
            path: POLICY_KEY.to_string(),
            code: 2,
        });
        assert!(matches!(
            unreadable_policy(Err(missing)),
            Err(DefenderError::Registry(_))
        ));
        assert_eq!(unreadable_policy(Ok(None)).unwrap(), None);
        assert_eq!(unreadable_policy(Ok(Some(1))).unwrap(), Some(1));

        // And a value read, as opposed to a key open, is mapped the same way:
        // which call was refused is not the question, whether this process may
        // look is.
        let denied_value = DefenderError::Registry(RegistryError::Value {
            call: "RegQueryValueExW",
            hive: Hive::LocalMachine,
            path: POLICY_KEY.to_string(),
            name: DISABLE_VALUE.to_string(),
            code: ERROR_ACCESS_DENIED,
        });
        assert!(matches!(
            unreadable_policy(Err(denied_value)),
            Err(DefenderError::PolicyUnreadable { .. })
        ));
    }

    #[test]
    fn a_dword_read_back_is_described_in_words_rather_than_in_rust() {
        // The one message in this module that reports a state nobody expects, so
        // it must not be the one message that reads like a debug print.
        assert_eq!(describe_value(Some(1)), "1");
        assert_eq!(describe_value(Some(0)), "0");
        assert_eq!(describe_value(None), "not there");
    }

    #[test]
    fn the_value_name_is_one_name_for_both_keys() {
        // One constant, used for both keys, asserted here so that a change that
        // gave the policy key a value name of its own would have to be a change
        // somebody made on purpose.
        assert_eq!(DISABLE_VALUE, "DisableRealtimeMonitoring");
        assert_eq!(TAMPER_VALUE, "TamperProtection");
        assert_eq!(PASSIVE_VALUE, "PassiveMode");
        assert_eq!(RECORD_KEY, r"Software\WenleAV\Defender");
    }
}
