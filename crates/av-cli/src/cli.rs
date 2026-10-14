//! The command line, declared once.
//!
//! Every option is declared here with its help text, and the parser, the
//! `--help` output and the shell completions are all generated from that one
//! declaration. That is the reason for the derive macros rather than a
//! hand-written matcher: the previous generation of this tool documented an
//! option that no longer existed for eleven months, and no test caught it
//! because the two were separate code.

use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};

// The `--user`/`--machine` choice is a registry scope, and the registry scope is
// `av-integration`'s to define: it is the crate that knows which hive each one
// writes to. Importing it here rather than declaring a second enum keeps a third
// scope — `HKEY_CLASSES_ROOT`, say — from being addable in the command line
// without existing anywhere the code that writes it can see.
use av_integration::shell::Scope;

/// Wenle Antivirus command-line scanner.
#[derive(Debug, Parser)]
#[command(
    name = "wenle",
    version,
    about = "Wenle Antivirus — scan files, build rule databases, inspect them",
    long_about = None,
    // `--help` on a subcommand that takes no further arguments should not print
    // a page, and an unknown subcommand should say what the alternatives are.
    arg_required_else_help = true,
    disable_help_subcommand = true,
)]
pub struct Args {
    /// Increase log verbosity. Repeat for more.
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress everything except findings and errors.
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// Write no colour, whatever the terminal is.
    ///
    /// There is no `--colour=always`: the `console` crate already honours
    /// `NO_COLOR`, `CLICOLOR_FORCE` and whether the stream is a terminal, and a
    /// fourth way to say the same thing is a fourth thing to get wrong.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Keep all product state — configuration, rule database, quarantine
    /// vault, logs — under this directory instead of `%ProgramData%\WenleAV`.
    ///
    /// This is what makes a portable install possible: a copy of the product on
    /// a USB stick with `--data-dir .\data` keeps everything on the stick and
    /// leaves nothing on the host. It is also the only way to point the tool at
    /// a vault or a rule set that belongs to something else, which is what a
    /// support engineer examining a customer's exported state needs.
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files, directories, or both.
    Scan(Box<ScanArgs>),
    /// Examine what running processes are holding in memory.
    ///
    /// The one thing a file scan cannot see: code written into a process that
    /// was never on disk. `wenle scan --memory <path>` does the same sweep as
    /// part of a file scan; this does it on its own, without walking any
    /// directory.
    Memory(MemoryArgs),
    /// Compile rule sources into a rule database (`.avdb`).
    Build(BuildArgs),
    /// Inspect a rule database.
    Db(DbArgs),
    /// Look at, and act on, what the product has taken off this machine.
    Quarantine(Box<QuarantineArgs>),
    /// Install, remove, start and stop the background service, and ask it what
    /// it is doing.
    Service(ServiceArgs),
    /// Put this product into Windows itself: the right-click scan verbs, the
    /// AMSI provider that examines script before a host runs it, Windows
    /// Defender's real-time monitoring, and the kernel driver.
    Integrate(IntegrateArgs),
    /// Look at, and set up, the product's protection of itself.
    Protect(ProtectArgs),
    /// Show the configuration in force, and which of its keys this build acts
    /// on.
    ///
    /// The one command whose subject is `config.toml` itself, and that is also
    /// why it is the one command that still runs when the file cannot be
    /// parsed: it reports the error and then describes the defaults that are in
    /// force in its place. Every other command needs a configuration and stops
    /// when it cannot have one.
    Config(ConfigArgs),
}

/// The `config` command's arguments.
///
/// A flag rather than a group of verbs, unlike every other command added since
/// `service`. There is one subject and one question about it, and the second
/// mode is a widening of the first rather than a different job: `--check` says
/// which keys are in force, where the listing says what they are.
#[derive(Debug, ClapArgs)]
pub struct ConfigArgs {
    /// Say which of these keys this build acts on, and which it does not.
    ///
    /// Replaces the listing with two lists: the settings that are stored and
    /// not in force as written, each with a sentence saying what is missing,
    /// and the settings that another part of the product reads. The reasons are
    /// the point — a key that does nothing and a key that waits for a restart
    /// are both "not in force", and only the reason tells them apart.
    ///
    /// Exits 2 only when the file exists and could not be used. That is the
    /// only failure here: every configuration this product ships with leaves
    /// some keys unhonoured, so a check that failed on those would fail on a
    /// correct installation and be a check nobody could run in a script.
    #[arg(long)]
    pub check: bool,

    /// Print the whole report as one JSON document.
    ///
    /// The configuration in force, the parse error if there was one, and both
    /// lists — everything `--check` prints and everything it does not, so that
    /// `--check` changes nothing about this output and a script has one shape
    /// to read.
    #[arg(long)]
    pub json: bool,
}

/// The `protect` subcommand's own arguments.
///
/// A group rather than a flat list of verbs, matching `service`, `quarantine`,
/// `db` and `integrate`. "Protection of the product" is one subject, and it has
/// two halves that are always confused for each other: what the machine is
/// configured to *allow* (permissions, the service's start type and recovery)
/// and what the product's own files *are* (the manifest). `status` is the only
/// verb that reports both, which is why it exists.
#[derive(Debug, ClapArgs)]
pub struct ProtectArgs {
    #[command(subcommand)]
    pub command: ProtectCommand,
}

/// What can be asked of, and done to, the product's self-protection.
///
/// # Which verbs change the machine
///
/// Three of the six do, and they say so in their own help text: `apply` rewrites
/// the permissions of the product's directories, `manifest` writes a record of
/// the product's own files, and `restore` puts back the permissions `apply`
/// replaced. All three need administrator rights.
///
/// `apply` and `manifest` are idempotent — running either twice leaves the
/// machine as running it once did, which is what makes them the repair step for
/// a half-finished install as well as the setup step for a new one. `restore` is
/// deliberately not: it consumes the record it applies, so that it undoes the
/// `apply` that wrote that record rather than some later one, and running it a
/// second time has nothing to do and says so.
///
/// The other three read and change nothing. `status` and `verify` need no
/// elevation at all, which is deliberate: the command somebody runs when they do
/// not know what is wrong has to be one they can run.
#[derive(Debug, Subcommand)]
pub enum ProtectCommand {
    /// Say what the product's self-protection looks like on this machine.
    ///
    /// Three answers in one report, because they fail independently and any one
    /// of them being wrong is enough to make the product useless: whether the
    /// product's directories still have the permissions `apply` gave them,
    /// whether the product's own files still match the recorded manifest, and
    /// what the Service Control Manager says about the service — its start type,
    /// its recovery policy, the account it runs as, and whether it is running.
    ///
    /// Needs no special rights, so it is the command to run first.
    Status,
    /// Say what a path's permissions actually allow, trustee by trustee.
    ///
    /// Answers the question a permission report usually cannot: **which
    /// accounts can write this**, and in particular whether an ordinary,
    /// non-elevated user can. With no path, every directory the product owns is
    /// audited — the ones `apply` protects, and the quarantine vault, which is
    /// `av-quarantine`'s to restrict and is reported here rather than changed.
    ///
    /// Reads the permissions back off the object rather than repeating what
    /// `apply` intended, so it is the check on `apply` and not a restatement of
    /// it.
    Audit {
        /// The file or directory to audit. Defaults to every directory the
        /// product owns.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Give the product's directories their permissions, and the service its
    /// start type. CHANGES THIS MACHINE.
    ///
    /// Needs administrator rights. Rewrites the DACL of the install, database,
    /// rules, cache, log and configuration directories: full control for
    /// SYSTEM and Administrators, read and execute for ordinary users, and
    /// nothing for anyone else.
    ///
    /// It also makes the service start by itself, if it does not already: a
    /// start type of manual, disabled or unrecognised is set to automatic
    /// shortly after boot, and the value found is printed. A service that
    /// already starts by itself is left alone. Unlike the permissions, this one
    /// has no recorded undo — the printed value is what
    /// `sc.exe config WenleAvService start= …` puts back.
    ///
    /// The quarantine vault is deliberately not touched — it is
    /// `av-quarantine`'s to restrict, and it is restricted to its creator and
    /// the two system accounts — and this verb refuses a layout that points it
    /// at the vault rather than quietly granting SYSTEM access to quarantined
    /// samples.
    ///
    /// Idempotent. It reports what it changed and then reads every directory
    /// back, so a run that reported success and left a directory open is a
    /// failure this command would show you itself.
    ///
    /// Refuses to run when the executable is inside a cargo build tree, because
    /// an installation's permissions strip write access from the account that
    /// has to rebuild there. It changes nothing when it refuses.
    Apply,
    /// Record a manifest of the product's own files. CHANGES THIS MACHINE.
    ///
    /// Needs administrator rights. Hashes the service binary, the command-line
    /// tool, the desktop application and the rule database, and writes their
    /// sizes, SHA-256 digests and signature states under the data directory.
    ///
    /// This is what `verify` and `status` compare against, so a machine with no
    /// manifest has nothing to detect tampering with. Take a new one after every
    /// upgrade: a manifest recorded before an upgrade reports every file the
    /// upgrade replaced as changed, which is true and is not a finding.
    Manifest,
    /// Check the product's own files against the recorded manifest.
    ///
    /// Needs no special rights. Reports what is missing, what has appeared, what
    /// changed length, and what is the same length and a different file — and
    /// for a changed program, whether it is still signed the way it was.
    ///
    /// Exits 3 when anything has changed, so a scheduled task or an inventory
    /// script can act on the answer without parsing the output. A manifest that
    /// was never taken is reported and is not a change; `status` is the verb that
    /// treats it as a problem.
    Verify,
    /// Put back the permissions `apply` replaced. CHANGES THIS MACHINE.
    ///
    /// Needs administrator rights. `apply` reads every directory's permissions
    /// into a record under the data directory *before* it changes anything, and
    /// this puts that record back — the same shape as
    /// `wenle integrate defender restore`, and for the same reason: a command
    /// that changes the machine should have a command that changes it back.
    ///
    /// A directory that did not exist when the record was taken is left alone; a
    /// directory that has appeared since is left alone too, because this verb is
    /// about permissions and a `restore` that deleted a directory would be a
    /// verb with a second effect nobody asked for. The record is removed once it
    /// has been applied, so that the cycle is `restore` then `apply` and never
    /// two records over one another.
    ///
    /// The undo for `apply` and for nothing else. It does not touch the manifest,
    /// the service registration, the shell verbs or anything under `HKLM`.
    Restore,
}

/// The `integrate` subcommand's own arguments.
///
/// A group rather than a flat list of verbs, matching `service`, `quarantine`
/// and `db`. "Integration" is the word for everything this product does to the
/// machine it is installed on rather than to a file on it, and the shell verbs
/// are the first of those; a name that said "shell" would have to be renamed the
/// day a second kind of integration arrives.
#[derive(Debug, ClapArgs)]
pub struct IntegrateArgs {
    #[command(subcommand)]
    pub command: IntegrateCommand,
}

/// What can be integrated.
#[derive(Debug, Subcommand)]
pub enum IntegrateCommand {
    /// Explorer's right-click "Scan with Wenle Antivirus" verbs.
    ///
    /// Four registry keys, one for each kind of thing that can be right-clicked:
    /// a file, a folder, the empty space inside a folder, and a drive. The verbs
    /// add a menu item and nothing else — they do not protect anything, and a
    /// user who never right-clicks a file loses no protection by leaving them
    /// unregistered.
    Shell(ShellArgs),
    /// The AMSI provider: script content examined before a host runs it.
    ///
    /// Two machine-wide keys that make Windows hand this product the text of
    /// every script a supporting host is about to execute — after that host's
    /// own de-obfuscation. Unlike the Explorer verbs, this is not cosmetic:
    /// with it registered, an encoded PowerShell command is examined before it
    /// runs, and without it the command runs and nothing sees it.
    #[cfg(windows)]
    Amsi(AmsiArgs),
    /// Windows Defender's real-time monitoring: report it, turn it off, and put
    /// back what was there.
    ///
    /// A machine running two on-access scanners hands every file operation to
    /// both of them and pays for both, which is the whole reason for this
    /// command. It is also the most dangerous thing this product can do.
    ///
    /// **While Defender's real-time monitoring is off, this product is the only
    /// thing examining files as they are written.** If its service is stopped,
    /// or the product is removed, then nothing is — and neither Windows nor this
    /// product will tell anybody. `wenle integrate defender disable --help` says
    /// so again, in the place a person reads before running it.
    ///
    /// **Nothing here runs by itself.** This command is the only thing in the
    /// product that changes this setting: no installer reaches it, no service
    /// start reaches it, and no scan reaches it. It happens when somebody types
    /// it, and not otherwise.
    #[cfg(windows)]
    Defender(DefenderArgs),
    /// The kernel driver: the minifilter that sees file operations before they
    /// happen, and reports them to this product's service.
    ///
    /// This is the part of the product that runs inside the kernel, and it is the
    /// only part that is not in a user-mode process. `crates/av-driver` builds it;
    /// nothing else installs it. Until this command has been run, that driver is
    /// a file on disk that nothing loads, and everything the product does is
    /// done from user mode.
    ///
    /// **It needs administrator rights, and on a machine that has never loaded a
    /// driver of its own it needs test-signing or a signature Windows trusts.**
    /// A driver that is refused by the loader is refused silently at boot and
    /// this command cannot tell you that from here — check `fltmc` afterwards.
    #[cfg(windows)]
    Driver(DriverArgs),
    /// The name and icon this product's notifications are attributed to.
    ///
    /// One key under `HKEY_CURRENT_USER\Software\Classes\AppUserModelId`: a
    /// display name and the path to an icon. It is what makes a notification
    /// say "Wenle Antivirus" rather than the path of the executable that posted
    /// it.
    ///
    /// **A notification does not need this to appear.** That was measured: an
    /// unregistered identifier posts successfully, and the toast is shown and is
    /// recorded in the notification history. What is missing without this key is
    /// the name and the icon, which is a real difference to a user and not a
    /// difference to whether they are told about a block. So nothing in the
    /// product requires this to have been run, and nothing fails when it has
    /// not — which is also why `status` exits 0 on a machine where nothing is
    /// registered.
    ///
    /// No administrator rights, and no `--machine`: notifications belong to the
    /// account whose shell draws them, and a machine-wide entry would name a
    /// display name for accounts that cannot post under it.
    Notifications(NotificationsArgs),
    /// The entry that starts the window when this user signs in.
    ///
    /// One value under `HKEY_CURRENT_USER\Software\Microsoft\Windows\
    /// CurrentVersion\Run`, launching the graphical front end with
    /// `--minimized` so that it waits in the notification area rather than
    /// opening a window at every sign-in.
    ///
    /// **`remove` deletes one value and not the key.** That key is shared with
    /// every other program on the machine that starts at sign-in; a `remove`
    /// that deleted it would take all of them with it. Nothing else in the
    /// product removes this entry, so an uninstall has to run
    /// `wenle integrate startup remove`.
    ///
    /// No administrator rights: this starts a window in the session of the user
    /// who signed in, and only that user's own registry is involved.
    Startup(StartupArgs),
    /// Say what is registered in both scopes.
    ///
    /// Reads the machine's half and the current user's half and reports on each,
    /// because a verb registered in only one of them is invisible from the other
    /// and there is no way to tell which from the inside.
    Status,
}

/// The `amsi` subcommand's own arguments.
///
/// A group rather than a flat list, matching `shell`. There is no
/// `--user`/`--machine` pair here and its absence is the point: AMSI enumerates
/// its providers from `HKEY_LOCAL_MACHINE` and nowhere else, so a per-user
/// registration would be one Windows never reads. See
/// [`av_integration::amsi`] for why that is not an oversight.
#[cfg(windows)]
#[derive(Debug, ClapArgs)]
pub struct AmsiArgs {
    #[command(subcommand)]
    pub command: AmsiCommand,
}

/// What can be done to the AMSI provider registration.
#[cfg(windows)]
#[derive(Debug, Subcommand)]
pub enum AmsiCommand {
    /// Register the provider DLL for every account on this machine.
    ///
    /// Needs administrator rights, because both keys are machine-wide.
    ///
    /// Idempotent: running it twice leaves the same registry as running it once,
    /// so it is also how a half-finished registration is repaired.
    Install,
    /// Unregister the provider.
    ///
    /// Removes the 32-bit view as well, even though this build never writes it:
    /// a leftover entry there names the same CLSID and would point at a DLL
    /// that is no longer installed.
    Remove,
    /// Say what is registered.
    ///
    /// Reads all four keys — the two that make the registration and the two
    /// 32-bit views of them — because an entry under `WOW6432Node` that this
    /// build did not write is one this machine has and no other command would
    /// tell you about.
    Status,
}

/// The `defender` subcommand's own arguments.
///
/// A group rather than a flat list, matching `shell` and `amsi`. There is no
/// `--user`/`--machine` pair here and its absence is the point: Defender's
/// settings are `HKEY_LOCAL_MACHINE` keys that a machine has one of, so a
/// per-user variant would be a variant nothing reads. See
/// [`av_integration::defender`] for the two keys, which of them this product
/// writes, and why.
#[cfg(windows)]
#[derive(Debug, ClapArgs)]
pub struct DefenderArgs {
    #[command(subcommand)]
    pub command: DefenderCommand,
}

/// What can be done about Windows Defender's real-time monitoring.
#[cfg(windows)]
#[derive(Debug, Subcommand)]
pub enum DefenderCommand {
    /// Say what Defender's real-time monitoring is set to.
    ///
    /// Read-only, and it works from an ordinary prompt: every value it reads is
    /// one an ordinary user may read. Run it before deciding whether to elevate,
    /// and run it again afterwards — it is the check on whether a change took.
    ///
    /// It reports settings, and it says so in its own output. The registry
    /// records what has been asked for; it does not record whether the Defender
    /// service is running or honouring any of it, and that is what Windows
    /// Security is for.
    Status,
    /// Turn Defender's real-time monitoring off.
    ///
    /// Needs administrator rights, because the key it writes is machine-wide.
    ///
    /// **This turns off a security feature on this machine.** While it is off,
    /// this product's own real-time protection is the only thing examining files
    /// as they are written; if that is not running, nothing is. Nothing else in
    /// the product does this, and nothing does it without this command being
    /// typed.
    ///
    /// It writes down what was in the key *before* it changes anything, so that
    /// `restore` can put that exact value back. Running it a second time is
    /// refused rather than repeated, because repeating it would overwrite that
    /// record with the value this command itself wrote.
    ///
    /// Defender's own tamper protection, if it is in force, will usually refuse
    /// or revert the change. This command reports that and does not attempt to
    /// turn tamper protection off.
    ///
    /// It also makes Windows Security show the setting as managed by an
    /// administrator, which is what a policy is, and which the user can no longer
    /// switch back from there.
    Disable,
    /// Put back the value that was there before `disable` changed it.
    ///
    /// Not the same thing as turning real-time monitoring on. This writes back
    /// the exact value `disable` recorded — including removing the value
    /// altogether, if that is what was there. A machine can have real-time
    /// monitoring off for a reason that is not this product's, and a command that
    /// switched it on would be quietly undoing somebody else's decision.
    ///
    /// Refuses when there is no record, which is how a user finds out that the
    /// change was not this product's to undo.
    Restore,
}

/// The `notifications` subcommand's own arguments.
///
/// A group rather than a flat list, matching `shell`, `amsi`, `defender` and
/// `driver`. There is no `--user`/`--machine` pair here and its absence is the
/// point: Windows reads notification registration from the signed-in account's
/// own hive, so a machine-wide variant would be one Windows never looks at. See
/// [`av_integration::notifications`] for the two values the key carries, and for
/// the key Windows writes afterwards that this product reads and never changes.
#[derive(Debug, ClapArgs)]
pub struct NotificationsArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

/// The `startup` subcommand's own arguments.
///
/// The same shape as `notifications`, and for the same reason: a program that
/// starts when a user signs in belongs to that user, so there is no scope to
/// choose and no flag that would pick one.
///
/// The difference between the two is in what `remove` does, and it is a
/// difference a user should know before running it — see
/// [`av_integration::startup`]'s documentation, and the `remove` line in the
/// command's own help.
#[derive(Debug, ClapArgs)]
pub struct StartupArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

/// What can be done to one of the per-user registrations.
///
/// One enum for both, because the three operations are the same three and mean
/// the same thing in both: write the registration, delete the registration, and
/// read back what the machine holds. What differs between them is which
/// registration and what "delete" has to delete, and that is documented on each
/// of the two commands rather than here.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Write the registration, pointing at this executable's own directory.
    ///
    /// Idempotent: running it twice leaves the same registry as running it once,
    /// so it is also how a half-finished registration is repaired, and — for
    /// `startup` — how a stale path is corrected after the product has moved.
    ///
    /// Nothing here takes a path from the caller. The only program path that can
    /// be right is the one this command is running from.
    Install,
    /// Delete the registration.
    ///
    /// A registration that was never made is not an error, which is what makes
    /// this usable as the cleanup step of a failed install as well as the undo
    /// of a successful one.
    ///
    /// `startup remove` deletes one *value* from a key every other autostarting
    /// program also uses, and never the key itself.
    Remove,
    /// Say what is registered, read back from the registry.
    ///
    /// Reports what is in the machine rather than what a previous install
    /// intended, which is why the command line and the icon path are printed
    /// verbatim: they may have been written by a different build, in a different
    /// directory, or by nothing of ours at all.
    ///
    /// Exits 0 when nothing is registered. Neither registration is required for
    /// the product to protect the machine, so a machine without one is not a
    /// machine with a fault — the same rule the Explorer verbs follow, and the
    /// opposite of `driver status`, which reports on the one thing here that
    /// protection depends on.
    Status,
}

/// The `driver` subcommand's own arguments.
///
/// A group rather than a flat list, matching `shell`, `amsi` and `defender`.
/// There is no `--driver <path>` here and its absence is the point: the only
/// driver image that can be right is one this process finds for itself, and a
/// caller-supplied path would let a mistyped command register a file that is not
/// this product's — into the kernel, where the mistake is not reversible by
/// typing the opposite command. See
/// [`av_integration::driver::product_driver`] for the two places it looks and
/// why that is not the same as taking an argument.
#[cfg(windows)]
#[derive(Debug, ClapArgs)]
pub struct DriverArgs {
    #[command(subcommand)]
    pub command: DriverCommand,
}

/// What can be done to the kernel driver.
#[cfg(windows)]
#[derive(Debug, Subcommand)]
pub enum DriverCommand {
    /// Copy the driver into `System32\drivers` and register it as a service.
    ///
    /// Needs administrator rights, because a kernel service is machine-wide.
    ///
    /// **This is the one command in the product that puts code into the
    /// kernel.** It writes one file and one service key with two subkeys under
    /// it, and `remove` undoes exactly that. Nothing here runs until the machine
    /// loads the driver, which is at the next boot — see the lines this command
    /// prints for how to start it now instead.
    ///
    /// Idempotent: running it twice leaves the same registry and the same file as
    /// running it once, so it is also how a half-finished install is repaired.
    ///
    /// It checks that the file is a native x86_64 image before writing anything,
    /// because that is the one failure the loader will not describe: a service
    /// created for a user-mode DLL is created successfully, starts, and stops
    /// immediately with an error naming neither the file nor the reason.
    Install,
    /// Unregister the driver and delete its image.
    ///
    /// **A filter that is already loaded stays loaded until the machine
    /// restarts.** Deleting the key stops it being loaded next time; it does not
    /// unload it now, and nothing this command can do would. Run
    /// `fltmc unload WenleAvFilter` first if it needs to be gone before then.
    ///
    /// Succeeds on a machine where the driver was never installed, so it can be
    /// used as the cleanup step of a failed install as well as the uninstall step
    /// of a successful one.
    Remove,
    /// Say what is registered, and what this build would register.
    ///
    /// Read-only, and it works from an ordinary prompt: every value it reads is
    /// one an ordinary user may read, which is how `sc query` works from a prompt
    /// nobody elevated. It reports the registry and whether the image is on disk,
    /// and it is honest about what it cannot see — a driver whose service is
    /// registered and whose file is present may still have been refused by the
    /// kernel at load time, and only `fltmc` can tell you that.
    Status,
}

/// The `shell` subcommand's own arguments.
#[derive(Debug, ClapArgs)]
pub struct ShellArgs {
    #[command(subcommand)]
    pub command: ShellCommand,
}

/// What can be done to the shell verbs.
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    /// Add the verbs to Explorer's right-click menu.
    ///
    /// Idempotent: running it twice leaves the same registry as running it once,
    /// so it is also how a half-finished registration is repaired.
    Install(ScopeArgs),
    /// Take the verbs out of Explorer's right-click menu.
    ///
    /// Succeeds on a machine where they were never registered, so it can be used
    /// as the cleanup step of a failed install as well as the uninstall step of
    /// a successful one.
    Remove(ScopeArgs),
    /// Say what is registered, per kind of thing that can be right-clicked.
    ///
    /// Reads back the exact command line found rather than re-deriving what this
    /// build would write, so it answers "what will Explorer run when this is
    /// clicked" and not "what did this command intend".
    Status(ScopeArgs),
}

/// Which half of the registry a verb is registered in.
///
/// `--user` and `--machine` are mutually exclusive, which clap enforces by
/// declaration rather than by a check that could be forgotten. With neither
/// given, the scope is the one this process can actually write — machine when
/// it is elevated, the current user otherwise — and that choice is printed
/// rather than left implicit, because it is the difference between a verb every
/// account on the machine sees and one only the caller does.
#[derive(Debug, ClapArgs)]
pub struct ScopeArgs {
    /// Register for every account on this machine. Needs administrator rights.
    #[arg(long, conflicts_with = "user")]
    pub machine: bool,

    /// Register for this account only. Needs no elevation.
    #[arg(long, conflicts_with = "machine")]
    pub user: bool,
}

impl ScopeArgs {
    /// The scope asked for, or `None` for the sensible default.
    ///
    /// Returns the shell-integration crate's own [`Scope`] rather than a local
    /// mirror of it. A command-line flag whose meaning is "write to
    /// `HKEY_LOCAL_MACHINE`" is the same fact the rest of the product names, and
    /// two enums for it would be two places to add a third scope.
    pub fn scope(&self) -> Option<Scope> {
        match (self.machine, self.user) {
            (true, _) => Some(Scope::Machine),
            (_, true) => Some(Scope::User),
            _ => None,
        }
    }
}

/// The `memory` subcommand's own arguments.
#[derive(Debug, ClapArgs)]
pub struct MemoryArgs {
    /// Examine this process only, instead of every process.
    ///
    /// Needs the right to read another process's memory, which Windows refuses
    /// for anything running as another account or protected as a system process;
    /// a refusal is reported as a refusal and never as a clean process.
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,

    /// Put the files these findings point at into the quarantine vault.
    ///
    /// A finding in memory is about a process; what is taken is the *file* the
    /// bytes came from, and only when that file is malicious on its own
    /// evidence. Nothing is ever taken on a memory match alone, and the reason
    /// is not caution: the loader relocates an image as it maps it, so a match
    /// at an address in memory is often not a match at the same offset in the
    /// file. The report says, under each finding, what became of its file.
    #[arg(long)]
    pub quarantine: bool,

    /// Take the exit code as 3 rather than 0 when something is suspicious.
    #[arg(long)]
    pub fail_on_suspicious: bool,

    /// Machine-readable output: one JSON document.
    #[arg(long)]
    pub json: bool,

    /// Use the rule database at this path instead of the installed one.
    #[arg(long, short, value_name = "FILE")]
    pub db: Option<PathBuf>,
}

/// The `service` subcommand's own arguments.
///
/// A group rather than a flat list of verbs, matching `quarantine` and `db`, so
/// that a per-command option — here, where the service's executable is — has
/// somewhere to live that is not the global scope.
#[derive(Debug, ClapArgs)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

/// What can be done to the service.
///
/// Five verbs, and the split between them is the split between the two things
/// that know about this product: the Service Control Manager knows whether it
/// is installed and whether it is running, and the service itself knows what it
/// is doing. `install`, `remove`, `start` and `stop` are the four that talk to
/// the SCM and need administrator rights; `status` asks both and needs none.
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Put the service in the Service Control Manager, starting at boot.
    ///
    /// Needs administrator rights. `--data-dir` is ignored: the service reads
    /// its state from `%ProgramData%\WenleAV`, derived from where the service's
    /// own executable is, and a command line cannot move another process's
    /// `%ProgramData%`.
    Install {
        /// The service's executable.
        ///
        /// Defaults to `wenle-av-service.exe` beside this one, which is where
        /// an install and a build tree both put it.
        #[arg(long, value_name = "FILE")]
        binary: Option<PathBuf>,
    },
    /// Take the service out of the Service Control Manager.
    ///
    /// Needs administrator rights. A running service is stopped first; the
    /// name stays in the SCM's database until it has finished stopping, and
    /// this reports what it finds afterwards rather than what it asked for.
    Remove,
    /// Ask the Service Control Manager to start the service.
    ///
    /// Needs administrator rights. Succeeds if it is already running.
    Start,
    /// Ask the Service Control Manager to stop the service.
    ///
    /// Needs administrator rights. Succeeds if it is not running.
    Stop,
    /// Say what the Service Control Manager and the service itself report.
    ///
    /// Needs no special rights, and is the only one of the five that can be run
    /// by an ordinary user — which is the point: it is the command somebody
    /// runs when they do not know what is wrong.
    Status {
        /// Machine-readable output: one JSON document describing both answers.
        #[arg(long)]
        json: bool,
    },
}

/// The flags that apply to every subcommand.
///
/// Split out from [`Args`] so that a command takes the three settings that
/// affect how it speaks and nothing else. A command handed the whole parsed
/// command line would be a command that could read a sibling's arguments, and
/// the first one to do it would be a bug nobody noticed until the two commands
/// disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Globals {
    /// Suppress everything except findings and errors.
    pub quiet: bool,
    /// How many times `--verbose` was given.
    pub verbose: u8,
    /// Write no colour, whatever the terminal is.
    pub no_color: bool,
}

impl Globals {
    /// The globals from a parsed command line.
    pub fn of(args: &Args) -> Self {
        Self {
            quiet: args.quiet,
            verbose: args.verbose,
            no_color: args.no_color,
        }
    }
}

/// How to behave when a target cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnError {
    /// Report it and carry on. The default, because one locked file in a
    /// directory of ten thousand is not a reason to stop.
    Report,
    /// Stop the scan at the first target that could not be read.
    Stop,
    /// Say nothing about targets that could not be read.
    Ignore,
}

#[derive(Debug, ClapArgs)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Descend into subdirectories.
    ///
    /// On unless the configuration says otherwise, so this is only needed to
    /// override a configuration that turned it off. `--no-recursive` is the
    /// other direction, and the two cancel each other out in the order they
    /// are written.
    #[arg(long, short, overrides_with = "no_recursive")]
    pub recursive: bool,

    /// Scan only the immediate entries of each directory.
    #[arg(long, overrides_with = "recursive")]
    pub no_recursive: bool,

    /// Follow symbolic links and directory junctions.
    ///
    /// Off by default: a link that points at its own parent is an infinite
    /// directory tree, and a scan that follows one never finishes.
    #[arg(long)]
    pub follow_links: bool,

    /// Skip files larger than this many bytes. Accepts `64K`, `10M`, `1G`.
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    pub max_size: Option<u64>,

    /// Give up on a single file after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    /// Skip any path matching this pattern. Repeatable.
    ///
    /// `*` stands for any run of characters except a separator, `**` for any
    /// run at all, and `?` for one character. Matched against the whole path
    /// and against the file name, case-insensitively.
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Use the rule database at this path instead of the installed one.
    #[arg(long, short, value_name = "FILE")]
    pub db: Option<PathBuf>,

    /// Scan in the deepest, slowest configuration available.
    #[arg(long)]
    pub deep: bool,

    /// Skip the structural heuristics, leaving only rule detections.
    #[arg(long)]
    pub no_heuristics: bool,

    /// Do not let a valid signature discount heuristic detections.
    #[arg(long)]
    pub no_trust: bool,

    /// Skip the catalog store, which is the evidence trust is strongest on.
    ///
    /// Reading it costs about a second and 1.1 GB of reads at the start of a
    /// scan, which is worth paying once for a full scan and is not worth paying
    /// for a scan of three files. Skipping it leaves the trust layer able to see
    /// only embedded certificates, so a scan run this way reports Microsoft's
    /// own binaries as suspicious — which is the honest answer to the weaker
    /// question, and the reason this is a flag a user chooses rather than a
    /// default the product picks.
    #[arg(long)]
    pub no_catalog: bool,

    /// Move every malicious finding into the quarantine vault.
    ///
    /// Only the malicious band. Anything the engine called suspicious is
    /// reported and left where it is, because that is what the band means
    /// everywhere else in this product, and a scan that acted on it would be a
    /// scan that deleted a file the engine explicitly declined to condemn.
    ///
    /// This is the one option here that changes the machine it is run on.
    #[arg(long)]
    pub quarantine: bool,

    /// Worker threads. Defaults to the number of processors.
    #[arg(long, short = 'j', value_name = "N")]
    pub threads: Option<usize>,

    /// Examine the memory of every running process as well as the files.
    ///
    /// # Why this is a flag pair rather than a flag
    ///
    /// `--memory` and `--no-memory` override each other, and either one overrides
    /// the configuration. A flag that could only turn the feature on would leave
    /// a user whose configuration asked for it with no way to run one scan
    /// without it — and running without it is the common case: a memory sweep of
    /// this machine reads tens of megabytes out of a few hundred processes and
    /// takes tens of seconds, which nobody wants in the middle of a scan of a
    /// directory of downloads. The other direction matters just as much, because
    /// the configuration is read by the service and the graphical front end as
    /// well as by this command, so a machine-wide setting is not the place to
    /// decide what one command-line run does. Both directions of override, in the
    /// order written, is the same shape `--recursive` and `--no-recursive`
    /// already have; a third shape here would be a third thing to remember.
    ///
    /// # What it costs and what it needs
    ///
    /// No administrator rights: the processes this can read are exactly the ones
    /// the account running the scan can already read, and the ones it cannot are
    /// reported as gaps rather than skipped silently. Only committed, executable
    /// regions are read, because a rule is a byte pattern and a string on a heap
    /// is not the code that is running.
    #[arg(long, overrides_with = "no_memory")]
    pub memory: bool,

    /// Do not examine running processes, whatever the configuration says.
    #[arg(long, overrides_with = "memory")]
    pub no_memory: bool,

    /// Stop a target's scan at the first detection.
    #[arg(long)]
    pub stop_on_first: bool,

    /// What to do about a target that cannot be read.
    #[arg(long, value_enum, default_value_t = OnError::Report)]
    pub on_error: OnError,

    /// Machine-readable output: one JSON document per finding, then a summary.
    #[arg(long)]
    pub json: bool,

    /// Exit 3 when something suspicious was found and nothing malicious was.
    #[arg(long)]
    pub fail_on_suspicious: bool,

    /// Do not draw the progress line, even on a terminal.
    #[arg(long)]
    pub no_progress: bool,
}

#[derive(Debug, ClapArgs)]
pub struct BuildArgs {
    /// Rule sources: `.avrule` files, `.yar` files, or directories of them.
    ///
    /// With none named, the installed rule directory is compiled — which is
    /// what a release build runs, and the reason it can be run at all without
    /// knowing where the product put its own rules.
    #[arg(value_name = "SOURCE")]
    pub sources: Vec<PathBuf>,

    /// Where to write the database. Defaults to the installed location.
    #[arg(long, short, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Print the distribution of refused rules by construct.
    #[arg(long)]
    pub report: bool,

    /// Fail rather than warn when a rule is refused.
    ///
    /// The default is to warn: the corpus contains rules that use constructs
    /// this engine does not implement, and refusing a handful of them is not a
    /// reason to have no rule database at all. A release build wants the
    /// opposite, and says so with this flag.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, ClapArgs)]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommand,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Summarise a rule database: size, rule count, and what it can detect.
    Info {
        /// The database to inspect.
        ///
        /// With none named, the installed one is inspected. That default is the
        /// point of the subcommand rather than a convenience: the question
        /// `db info` exists to answer is "which rules am I running", and a user
        /// who has to be told the path before they can ask it is being asked to
        /// know the answer already.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },
    /// List the rules in a database.
    List {
        /// The database to read. With none named, the installed one is read;
        /// see `db info`.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Show at most this many.
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Only rules whose category is this.
        #[arg(long, value_name = "CATEGORY")]
        category: Option<String>,
    },
}

#[derive(Debug, ClapArgs)]
pub struct QuarantineArgs {
    /// Use the vault at this directory instead of the installed one.
    ///
    /// Needed more often than it looks: the installed vault sits under
    /// `%ProgramData%` and is owned by the service, so an administrator
    /// examining a quarantined sample, or a support engineer working on a
    /// customer's exported vault, is usually pointing at a directory somewhere
    /// else entirely.
    #[arg(long, value_name = "DIR", global = true)]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: QuarantineCommand,
}

#[derive(Debug, Subcommand)]
pub enum QuarantineCommand {
    /// Show what is in the vault.
    List {
        /// Include items that were restored or deleted, not just live ones.
        #[arg(long)]
        all: bool,
        /// Show at most this many.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Only items whose original path contains this text.
        #[arg(long, value_name = "TEXT")]
        path: Option<String>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Show everything recorded about one item.
    Show {
        /// The item's identifier, or enough of a prefix to be unambiguous.
        #[arg(value_name = "ID")]
        id: String,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Put an item back on disk.
    Restore {
        /// The item's identifier, or enough of a prefix to be unambiguous.
        #[arg(value_name = "ID")]
        id: String,
        /// Write it here instead of back where it came from.
        #[arg(long, value_name = "PATH")]
        to: Option<PathBuf>,
        /// Replace a file that is already at the destination.
        #[arg(long)]
        overwrite: bool,
        /// Leave the sealed copy in the vault as well.
        #[arg(long)]
        keep_copy: bool,
    },
    /// Destroy items, keeping the record of what they were.
    Delete {
        /// Identifiers, or unambiguous prefixes. None is needed with `--all`.
        #[arg(value_name = "ID", required_unless_present = "all")]
        ids: Vec<String>,
        /// Every live item.
        #[arg(long, conflicts_with = "ids")]
        all: bool,
        /// Do not ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Write an item's bytes out as a file, leaving the vault untouched.
    ///
    /// This hands live malware back to whoever asked for it. That is the point
    /// — submitting a sample to a lab, or examining one by hand — and it is why
    /// it is its own verb rather than a flag on `restore`.
    Export {
        /// The item's identifier, or enough of a prefix to be unambiguous.
        #[arg(value_name = "ID")]
        id: String,
        /// Where to write it. Required: there is no sensible default for
        /// putting a live sample back on a filesystem.
        #[arg(long, short, value_name = "PATH")]
        to: PathBuf,
        /// Replace a file that is already there.
        #[arg(long)]
        force: bool,
    },
    /// Re-read the sealed payloads and check them against their recorded hashes.
    Verify {
        /// Identifiers, or unambiguous prefixes. Check everything without them.
        #[arg(value_name = "ID")]
        ids: Vec<String>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Apply retention, size limits, the deletion retry list, and history
    /// compaction.
    Maintain {
        /// Report what would happen without doing any of it.
        #[arg(long)]
        dry_run: bool,
        /// Forget records that finished more than this many days ago. Defaults
        /// to the vault policy's retention.
        #[arg(long, value_name = "DAYS")]
        compact_after: Option<u64>,
    },
}

/// Parse a size with an optional `K`, `M`, `G` or `T` suffix.
///
/// Decimal multipliers and not binary ones, because that is what every disk
/// tool a user has met already means by `10M`, and a scanner whose `--max-size
/// 10M` skipped a file of 10.4 MiB without saying so would be a scanner that
/// silently did not scan something.
fn parse_size(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let (digits, multiplier) = match trimmed.chars().last() {
        Some('k' | 'K') => (&trimmed[..trimmed.len() - 1], 1_000u64),
        Some('m' | 'M') => (&trimmed[..trimmed.len() - 1], 1_000_000),
        Some('g' | 'G') => (&trimmed[..trimmed.len() - 1], 1_000_000_000),
        Some('t' | 'T') => (&trimmed[..trimmed.len() - 1], 1_000_000_000_000),
        _ => (trimmed, 1),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("`{text}` is not a size"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("`{text}` is larger than a file can be"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The declaration has to be internally consistent, and clap can only tell
    /// us that by being asked to build it.
    #[test]
    fn the_command_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn a_size_suffix_is_a_decimal_multiplier() {
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("10K"), Ok(10_000));
        assert_eq!(parse_size("10k"), Ok(10_000));
        assert_eq!(parse_size("2M"), Ok(2_000_000));
        assert_eq!(parse_size("3G"), Ok(3_000_000_000));
        assert_eq!(parse_size(" 1T "), Ok(1_000_000_000_000));
    }

    #[test]
    fn a_size_that_is_not_one_is_an_error_rather_than_a_default() {
        assert!(parse_size("").is_err());
        assert!(parse_size("ten").is_err());
        assert!(parse_size("10X").is_err());
        assert!(parse_size("-1").is_err());
        // Not a panic and not a wrapped number.
        assert!(parse_size("99999999999T").is_err());
    }

    #[test]
    fn a_size_with_no_suffix_is_bytes() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("4096"), Ok(4096));
    }
}
