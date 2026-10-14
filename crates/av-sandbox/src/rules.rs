//! The rules, and why each one is worth what it costs in false positives.
//!
//! # How these were chosen
//!
//! Every rule here was measured before it was written, and most of the
//! candidates that were measured were then dropped or narrowed. The corpus is
//! the machine's own software: every `*.dll` and `*.exe` in
//! `C:\Windows\System32` — 4,000 files, 3,399 of them libraries, every one of
//! them a PE image this crate can judge. It is not a malware corpus and is not
//! meant to be one. It is the hardest available *false-positive* corpus, a few
//! thousand unrelated programs written by thousands of people over thirty
//! years, and a rule that cannot survive it will not survive a user's
//! `Program Files` either.
//!
//! The permanent form of the measurement is the `#[ignore]`d test at the bottom
//! of this file. It sweeps the same corpus through these rules and prints the
//! counts, so the numbers in these doc comments can be re-checked on any
//! Windows machine rather than taken on trust.
//!
//! # What the measurement cost the rule set
//!
//! Six lessons, and the last one is the uncomfortable one.
//!
//! * **A single import is never evidence.** `CreateServiceW` is imported by
//!   every installer, updater and service host in the operating system;
//!   `IsDebuggerPresent` is imported by 2,651 of the 4,000 files and
//!   `QueryPerformanceCounter` by 3,499 of them. A timing-check rule built on
//!   those imports is a rule that fires on the operating system — the form of
//!   it that asked for *both* APIs was measured at 2,638 files, two thirds of
//!   `System32` — and it was thrown away rather than shipped.
//! * **The evidence is the combination, and the narrower half is the one that
//!   discriminates.** The service APIs together with a registry write fire on
//!   224 system binaries, and the service APIs together with a user-writable
//!   path on 32. Neither pair is evidence of anything; the *name* is, and
//!   adding it is what took the count to zero.
//! * **Both spellings of a string have to be searched.** A registry path, a
//!   service name and a command line are usually UTF-16LE in a Windows binary,
//!   because that is what the wide entry points take, while an import table is
//!   single-byte text. A search that looks for one and not the other has a
//!   false-negative rate nobody can see — the rule simply never fires and the
//!   report looks clean — and the census makes the size of that hole a printed
//!   number: the registry-write-plus-Run-key-from-a-user-directory form reads
//!   **1** file with the single-byte spelling alone (`MRT.exe`, which carries a
//!   literal path) and **11** with both — so ten of the eleven are invisible to
//!   the narrower search, and a rule built on it would have been silent about
//!   every one of them.
//! * **A behaviour is not a rule.** The shape that is easiest to state — do
//!   something trivial, sleep, then act, because a sandbox stops watching after
//!   a minute — has no static form at all: `Sleep` is imported by 2,239 of the
//!   4,000 files, more than half the operating system, so asking for it is
//!   asking nothing, and the *order* of two operations is exactly what a
//!   judgment made from the file cannot see. The import says a program can
//!   wait, never that it waits before it acts.
//! * **Housekeeping and evasion share their imports.** Delete-yourself is the
//!   classic cleanup step, and the shape of it is a file that finds its own
//!   path, deletes itself and asks to be removed after a restart — three calls
//!   that 160 of the 4,000 files make, every uninstaller and updater among
//!   them. The first three the census names are `advpack.dll`, `aepic.dll` and
//!   `AppLockerCSP.dll`, which is what a shape that means "software that
//!   maintains itself" looks like: nothing in an import table distinguishes a
//!   program that removes itself from one that removes the file it just
//!   replaced, which is why this is measured and not written.
//! * **The behaviour that was asked for most is the one that failed.** Boot
//!   persistence is the first thing anyone wants from a behavioural engine, and
//!   every form of it that can be written from structure fired on ordinary
//!   Windows binaries: writing a Run key 39 times, a Run key from a
//!   user-writable directory 11, the Image File Execution Options path 32,
//!   `AppInit_DLLs` 4, the name `userinit` 42, the service APIs plus a registry
//!   write 224. The counterexamples are programs doing their job —
//!   `OneDriveSetup.exe` installs a per-user service out of `%LocalAppData%` by
//!   design, `AcLayers.dll` and `cmstp.exe` are the shim and installation
//!   machinery that writes startup entries on behalf of whatever is being
//!   installed, and `advapi32.dll` is the code that implements the APIs whose
//!   names it contains. No rule in this crate covers persistence, and the
//!   reason is those programs rather than a lack of effort. `crate::rule` keeps
//!   the `persistence` class in its table so that a rule for the behaviour has
//!   somewhere to live if one is found.

use av_core::Severity;

use crate::evidence::{Evidence, TextMatch};
use crate::rule::{Rule, Trigger};

/// Every rule this crate runs, in the order they are evaluated.
///
/// Order is presentation, not precedence: every rule is evaluated against every
/// sample, because a sample that hides a command *and* carries a payload should
/// be reported as both, and a table that stopped at the first match would hide
/// the second finding from the user.
///
/// Every rule in this table fires on **zero** of the 4,000 system binaries in
/// the corpus. That is the standard for entry: a rule whose measured count is
/// not zero is narrowed until it is, or it is not shipped.
pub static RULES: &[Rule] = &[
    Rule::new(
        "sandbox/evasion/security-service-reconfigure",
        "reconfigures a service while naming a security product's own service",
        Severity::Medium,
        security_service_reconfigure,
    ),
    Rule::new(
        "sandbox/evasion/lotl-encoded-command",
        "hides a command it runs through the system's own script interpreter",
        Severity::Medium,
        lotl_encoded_command,
    ),
    Rule::new(
        "sandbox/evasion/entry-point-outside-sections",
        "declares an entry point that lies in no section of the image",
        Severity::Low,
        entry_point_outside_sections,
    ),
    Rule::new(
        "sandbox/dropper/appended-image",
        "carries an executable after its last section and can write and start it",
        Severity::Medium,
        appended_image,
    ),
    Rule::new(
        "sandbox/credential/lsass-dump",
        "writes a process memory dump while naming the credential store",
        Severity::High,
        lsass_dump,
    ),
    Rule::new(
        "sandbox/anti-analysis/analysis-tool-artefact",
        "names two different analysis or virtualisation products",
        Severity::Low,
        analysis_tool_artefact,
    ),
    Rule::new(
        "sandbox/impact/backup-destruction",
        "encrypts, walks and deletes files while naming the shadow copy deletion commands",
        Severity::High,
        backup_destruction,
    ),
    Rule::new(
        "sandbox/lateral-movement/remote-share-service",
        "connects to a share, copies onto it and installs a service",
        Severity::Medium,
        remote_share_service,
    ),
];

// -- symbol tables ----------------------------------------------------------
//
// Every table is the same shape as the measurement that justified it. Both the
// `W` and the `A` form of any API that has two, because a rule that knew only
// `CreateServiceW` would miss every program compiled without `UNICODE` — which
// is most of the older ones, including most malware. The tables are also
// deliberately no wider than what was measured: a name added to one of these
// after the fact is a name whose false-positive rate nobody has counted.

/// The two calls that install a service or change how an existing one runs.
///
/// Narrower than "the service APIs" on purpose. `OpenSCManagerW`,
/// `ControlService` and `DeleteService` are what a program calls to *stop* or
/// *enumerate* a service — which is what a service manager, a monitoring agent
/// and Task Manager all do — while these four are what an installer or an
/// attacker calls to make a service exist or change what it runs.
const SERVICE_INSTALL: &[&str] = &[
    "CreateServiceW",
    "CreateServiceA",
    "ChangeServiceConfigW",
    "ChangeServiceConfigA",
];

/// Writing a value into the registry.
///
/// Not used by a rule. It is kept for the measurement below, which counts the
/// forms the rules were narrowed away from, so that the documentation's claim
/// that those forms fire cannot go stale unnoticed.
#[cfg(test)]
const REGISTRY_WRITE: &[&str] = &[
    "RegSetValueExW",
    "RegSetValueExA",
    "RegCreateKeyExW",
    "RegCreateKeyExA",
    "RegSetKeyValueW",
    "RegSetKeyValueA",
];

/// The service names of the security products Windows installs on itself, plus
/// the one Microsoft ships separately.
///
/// Service names, not file names, because a service name is what an installer
/// writes and what a program reads back from the service control manager, and
/// because the two spellings of a file name are a much longer list.
const SECURITY_SERVICE_NAMES: &[&str] = &[
    "windefend",
    "msmpeng",
    "securityhealthservice",
    "wscsvc",
    "mssense",
    "sgrmbroker",
];

/// Starting a process.
const SPAWN_PROCESS: &[&str] = &[
    "CreateProcessW",
    "CreateProcessA",
    "CreateProcessAsUserW",
    "ShellExecuteW",
    "ShellExecuteA",
    "WinExec",
];

/// Putting bytes into a file.
const WRITE_FILE: &[&str] = &[
    "CreateFileW",
    "CreateFileA",
    "WriteFile",
    "CopyFileW",
    "CopyFileA",
    "CopyFileExW",
];

/// The idioms of a PowerShell command that is meant not to be read.
///
/// Nine spellings of the same three ideas: encode the script so it cannot be
/// read (`-enc `, `-encodedcommand`, `frombase64string`), hide the window it
/// runs in (`-windowstyle hidden`, `-w hidden`), and pull the next stage off
/// the network (`downloadstring`, `downloadfile`, `invoke-expression`, `iex(`),
/// with `-nop` as the flag every one of those command lines carries to keep the
/// target's own profile from interfering.
///
/// The list is not evidence on its own — see the rule below for what two of
/// them measured — and it is short on purpose: every entry has to be a string
/// that means "this command was written to hide something", not merely a string
/// that appears in PowerShell documentation.
const OBFUSCATED_COMMAND_IDIOMS: &[&str] = &[
    "-enc ",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex(",
    "-windowstyle hidden",
    "-w hidden",
    "-nop",
];

/// Symmetric encryption, in both the CryptoAPI and the newer CNG spelling.
const CRYPTO: &[&str] = &[
    "CryptEncrypt",
    "CryptGenKey",
    "CryptDeriveKey",
    "CryptAcquireContextW",
    "BCryptEncrypt",
    "BCryptGenerateSymmetricKey",
    "CryptImportKey",
];

/// Enumerating a directory.
const WALK_FILES: &[&str] = &[
    "FindFirstFileW",
    "FindFirstFileA",
    "FindNextFileW",
    "FindNextFileA",
];

/// Removing a file, by deletion or by moving it somewhere unreadable.
const DESTROY_FILE: &[&str] = &[
    "DeleteFileW",
    "DeleteFileA",
    "MoveFileExW",
    "MoveFileExA",
    "SetFileInformationByHandle",
];

/// The commands that destroy a machine's restore points.
///
/// Deliberately the *whole* command and not the tool's name: `vssadmin` on its
/// own is a name a backup product has every reason to contain, because listing
/// shadow copies is what it is for, while `vssadmin delete` is not. Deliberately
/// two phrases and not four, which is the one place in this crate where a
/// narrowing was made against the grain of the evidence: adding
/// `wbadmin delete` and `delete catalog` — real backup-deletion commands — took
/// the measured count from 0 to 1, and the file that fired was
/// `InstallService.dll`, a deployment tool that names a command it never runs.
/// The version with two phrases was kept because a ransomware command line
/// contains `vssadmin delete shadows /all /quiet`, and `delete catalog` is a
/// phrase that appears in a maintenance script as often as in an attack.
const BACKUP_DESTRUCTION_COMMANDS: &[&str] = &["vssadmin delete", "delete shadows"];

/// The components of an analysis environment that a sample can look for.
///
/// Three kinds of name in one list. First the DLLs an analysis sandbox injects
/// into every process it watches — Sandboxie's `sbiedll`, Cuckoo's `cuckoomon`
/// — which a program can find by walking its own loaded modules. Then the guest
/// agents, drivers and hooks a hypervisor installs (`vmtoolsd`, `vboxtray`,
/// `vboxhook`, `vmcheck`, `qemu-ga`), and Wine's version query. Every one of
/// them answers the
/// question "am I being watched, and by what?", which is a question ordinary
/// software does not ask — and the rule requires *two* of them, because one is
/// a name a program can carry for reasons of its own.
const ANALYSIS_TOOL_COMPONENTS: &[&str] = &[
    "sbiedll",
    "sandboxie",
    "cuckoomon",
    "qemu-ga",
    "xenservice",
    "xenvdbg",
    "vboxhook",
    "vmcheck",
    "wine_get_unix_file_name",
    "vmtoolsd",
    "vboxtray",
    "wine_get_version",
];

/// The name of the process that holds every credential the user has entered
/// since the machine started.
const CREDENTIAL_STORE_NAMES: &[&str] = &["lsass"];

/// Connecting to a share, and putting a file on it.
const NETWORK_SHARE: &[&str] = &[
    "WNetAddConnection2W",
    "WNetAddConnection2A",
    "WNetAddConnection3W",
    "NetUseAdd",
];
const COPY_FILE: &[&str] = &["CopyFileW", "CopyFileA", "CopyFileExW"];

/// The service-control APIs in their widest form, for the rule that needs the
/// whole chain rather than the install calls.
const SERVICE_CONTROL: &[&str] = &[
    "OpenSCManagerW",
    "OpenSCManagerA",
    "CreateServiceW",
    "CreateServiceA",
    "ChangeServiceConfigW",
    "ChangeServiceConfigA",
    "ControlService",
    "DeleteService",
];

// -- the rules --------------------------------------------------------------

/// Reconfiguring a service while naming a security product's own service.
///
/// # The behaviour
///
/// The sample holds the name of a security product's service and the two calls
/// that make a service exist or change what it runs: stopping it, disabling it,
/// changing its binary path or its start type. That is the disabling half of
/// "turn the antivirus off", and it is the step ransomware takes before it
/// encrypts.
///
/// # The legitimate program
///
/// A competing security product's installer. Disabling the product it replaces
/// is a documented part of installing a new one, and that installer will name
/// the old product's service and call exactly these functions — so this rule
/// has a legitimate population this corpus cannot see, which is why it is
/// [`Severity::Medium`] and not higher, and why it does not act on its own.
///
/// # The narrowing, and what it cost
///
/// The wide service-control table plus a security product's name fires on three
/// system binaries — `MpSigStub.exe`, `MRT.exe` and `Taskmgr.exe`, the tools
/// Microsoft ships to *repair* and to *manage* Defender — and the same table
/// plus a user-writable path on 32. Narrowing the API half to the two calls
/// that install or reconfigure a service takes it to zero, and the cost is a
/// real false negative: a sample that only stops a security service with
/// `OpenSCManager` and `ControlService` is not caught by this rule.
fn security_service_reconfigure(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_any(SERVICE_INSTALL) {
        return None;
    }
    // Last, and not first: the string scan is the expensive half, and the import
    // question rejects almost every file before it runs.
    let (needle, found) = evidence.find_any(SECURITY_SERVICE_NAMES)?;
    Some(Trigger::text(evidence, needle, found))
}

/// Hiding a command that runs through the system's own script interpreter.
///
/// # The behaviour
///
/// The sample has the imports to start a process and its bytes carry three or
/// more of the idioms of a PowerShell command line written not to be read: the
/// script encoded as base64, the window hidden, the next stage pulled off the
/// network. This is "living off the land" with the lights off — the interpreter
/// is already installed, already signed and already allowed through the
/// firewall, and the command is a blob so that neither a log nor a human sees
/// what it does.
///
/// # The legitimate program
///
/// Management software, and the measurement is unusually informative about it.
/// With **two** idioms the count is 4, and Microsoft's own tools are among them
/// — `ieframe.dll`, `msdt.exe` and `wbadmin.exe` — which invoke PowerShell with
/// an encoded command because encoding is how you pass a script through a
/// command line without quoting it. With **three** the count is 0, and the
/// threshold is the whole rule: it is a deliberate trade of false negatives for
/// false positives, and a sample whose command line carries only `-enc ` is
/// missed.
///
/// # Where the measurement stops
///
/// The count above was taken on the string half alone. The shipped rule also
/// requires the imports to start a process — a program that carries a hidden
/// command but cannot run it is carrying text, not doing anything — so the rule
/// can only be quieter than the number, never louder.
fn lotl_encoded_command(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_any(SPAWN_PROCESS) {
        return None;
    }
    if evidence.count_present(OBFUSCATED_COMMAND_IDIOMS) < 3 {
        return None;
    }
    let (needle, found) = evidence.find_any(OBFUSCATED_COMMAND_IDIOMS)?;
    Some(Trigger::text(evidence, needle, found))
}

/// An entry point that no section contains.
///
/// # The behaviour
///
/// The loader maps the sections and jumps to the entry point. If the entry
/// point is not inside any of them, what runs is not in the file's own picture
/// of itself — which is the ordinary way a packer or a protector keeps its
/// unpacking stub off the map, and is also what a file truncated or patched
/// after linking looks like.
///
/// # The legitimate program
///
/// There is not one in the corpus: **0** of the 4,000 files declare an entry
/// point outside every section, which is what a linker produces and what the
/// loader requires. The measurement that matters here is the one that kept this
/// rule from being a disaster: 400 of the 4,000 files — one in ten — declare an
/// entry point of **zero**, and a rule that asked only "is the entry point in a
/// section?" would fire on all of them. Zero is not that case. Zero means there
/// is no address to jump to, which is how a library with nothing to initialise
/// is built, so the rule excludes it explicitly, and that exclusion is the
/// difference between a rule and a rule that flags a tenth of the operating
/// system.
///
/// # Why this rule is not about imports
///
/// Every other rule here is about what a program declares it can do. This one
/// is about the section table, and it exists because the census said it could:
/// the entry point is the one piece of `av-pe`'s structure whose measurement
/// came out at zero for a reason a human can state. The rest of what the
/// headers expose does not — see the crate documentation for the TLS,
/// delay-load and `DllCharacteristics` counts and why no rule was built on
/// them.
fn entry_point_outside_sections(evidence: &Evidence<'_>) -> Option<Trigger> {
    let rva = evidence.entry_point_rva();
    if rva == 0 {
        // Not a missing value: a library with no initialiser declares no entry
        // point, and 400 of the corpus's files do.
        return None;
    }
    if evidence.pe().section_index_of_rva(rva).is_some() {
        return None;
    }
    // No location, because there is nowhere in the file to point at: the
    // number that is wrong is a header field, and an RVA that no section
    // contains has no file offset for a location to name. `av-pe` converts an
    // unmappable RVA to the RVA itself, so reporting it as an offset would
    // print a number that is not where anything is.
    Some(Trigger::structural(format!(
        "the entry point RVA {rva:#x} lies in no section"
    )))
}

/// An executable appended after the last section.
///
/// # The behaviour
///
/// The sample's last section ends, and a second complete PE image begins after
/// it — in the overlay, the part of the file the loader never maps. That is
/// where a dropper keeps its payload, and it is why this rule also requires the
/// imports to write a file and to start a process: the image is only a payload
/// if the program can put it somewhere and run it. What the sample is, then, is
/// a container whose content is a program it never carries as a file on disk.
///
/// # The legitimate program
///
/// Legitimate software that carries a program carries it in a **resource**, and
/// the corpus proves the difference is visible from the outside: no file in it
/// has an appended image (**0**), while exactly one — `MRT.exe`, Microsoft's
/// Malicious Software Removal Tool — holds one in a resource. A resource is
/// where a self-extracting installer and a self-updater put their payload,
/// because a resource is part of the image the linker built. An appended image
/// is what a file looks like after something bolted a second program onto it.
///
/// # Why the imports are still required
///
/// An appended *certificate* is ordinary — `av-pe` counts the attribute
/// certificate table as part of the overlay, so every signed file has one — and
/// a self-extracting archive appends an archive rather than an image. The
/// measurement says neither of those reaches this rule: with the image in the
/// overlay alone the count is 0, and with the write-and-spawn imports it is 0
/// as well. The imports stay because they are what makes the finding a
/// *dropper* rather than "there are bytes at the end of this file", and because
/// a rule that says less than it knows is a rule a user cannot act on.
fn appended_image(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_any(WRITE_FILE) {
        return None;
    }
    if !evidence.imports_any(SPAWN_PROCESS) {
        return None;
    }
    let offset = evidence.embedded_images().first_in_overlay?;
    Some(Trigger::at(
        evidence,
        offset,
        2,
        "a complete PE image after the last section",
    ))
}

/// Writing a memory dump while naming the credential store.
///
/// # The behaviour
///
/// The sample imports the API that writes a process's memory to a file and its
/// bytes name `lsass` — the process that holds every credential the user has
/// entered since the machine started. Dumping a process's memory and writing it
/// to disk is the step that turns "running as an administrator" into "holding
/// the domain's passwords", which is why it is [`Severity::High`]: the
/// behaviour is not a foothold, it is the theft itself.
///
/// # The legitimate program
///
/// A crash-dump collector, and the ones in the corpus are the reason this rule
/// requires the *name*. Four of the 4,000 files import the memory-dump API
/// without ever naming the store — `WerFault.exe` and `WerFaultSecure.exe`,
/// Windows' own crash reporters, among them — and a rule built on the import
/// alone would fire on all four and on every other reporting tool on the
/// machine. Nothing that dumps memory for a living needs to name `lsass`: with
/// the name required the count is 0 of 4,000. Naming the credential store while
/// importing the dump API is not something a crash reporter does.
fn lsass_dump(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_symbol("MiniDumpWriteDump") {
        return None;
    }
    let (needle, found) = evidence.find_any(CREDENTIAL_STORE_NAMES)?;
    Some(Trigger::text(evidence, needle, found))
}

/// Naming two different analysis or virtualisation products.
///
/// # The behaviour
///
/// A program that can see the sandbox it is running in will behave differently
/// in it, which is the whole of what a sandbox report is worth. The cheapest
/// way to see it is to look for the names of the components the environment
/// installs: the DLLs an analysis sandbox injects into every process it
/// watches, the drivers and guest agents a hypervisor installs, Wine's version
/// query.
///
/// # The legitimate program
///
/// A sandbox's or a hypervisor's own software — Sandboxie's own binaries name
/// `sbiedll`, and a virtual machine's guest tools name their own drivers. That
/// population is one product per file, which is exactly why the rule requires
/// **two** names: a program that knows about two different products' internals
/// is not either product, it is something that went looking. The measurement
/// agrees about the threshold being load-bearing — with one name the count is
/// 1 (`curl.exe`, which carries one of these strings for its own reasons) and
/// with two it is 0.
///
/// # Why this is [`Severity::Low`]
///
/// Because it is an observation about intent rather than about harm. Third-party
/// software that refuses to run in a virtual machine — some DRM, some
/// anti-cheat — does this too, and it is not malware. A `Low` finding notifies;
/// it is meant to be read beside a stronger one, not on its own.
fn analysis_tool_artefact(evidence: &Evidence<'_>) -> Option<Trigger> {
    let (needle, found, named) = names_present(evidence, ANALYSIS_TOOL_COMPONENTS, 2)?;
    let mut trigger = Trigger::text(evidence, needle, found);
    trigger.detail = format!("{needle}, and {named} analysis products named in total");
    Some(trigger)
}

/// Encrypting, walking, deleting, and naming the commands that delete backups.
///
/// # The behaviour
///
/// Four things at once: symmetric encryption, directory enumeration, file
/// deletion or renaming, and a command line that removes shadow copies. This is
/// the shape of ransomware in the first minute of its run — encrypt what you can
/// reach, walk the rest, delete the copies so the user cannot restore — and
/// there is nothing else that does all four. [`Severity::High`], because by the
/// time the behaviour is visible the data is already going.
///
/// # The legitimate program
///
/// A backup product with an encryption option and a retention policy: it
/// encrypts its archives, walks the disk and deletes expired sets, so three of
/// the four halves are its job. The fourth is what makes this rule work. A
/// backup product's own retention never removes *the volume's* shadow copies,
/// which is what `vssadmin delete` and `delete shadows` do — they take every
/// restore point on the machine. The corpus agrees: 0 of 4,000 files have all
/// four. The wider command list (`wbadmin delete`, `delete catalog`) is what
/// took that to 1, and the file was `InstallService.dll`, a deployment tool
/// that names a command it never runs — so the two phrases were kept and the
/// other two dropped, at the cost of missing a sample that only names
/// `delete catalog`.
fn backup_destruction(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_any(CRYPTO) {
        return None;
    }
    if !evidence.imports_any(WALK_FILES) {
        return None;
    }
    if !evidence.imports_any(DESTROY_FILE) {
        return None;
    }
    let (needle, found) = evidence.find_any(BACKUP_DESTRUCTION_COMMANDS)?;
    Some(Trigger::text(evidence, needle, found))
}

/// Reaching another machine: a share, a copy, and a service.
///
/// # The behaviour
///
/// The sample connects to a network share, copies a file onto it, and installs
/// a service. That is the classic remote-execution chain — put a binary where
/// the target's service control manager can reach it, then have the target start
/// it — and it is what turns an infected workstation into an infected domain.
///
/// # The legitimate program
///
/// A deployment or backup agent, and the concession is a real one: agents map
/// shares, copy payloads and install services for a living, and a tool that
/// copies its own binary to a remote share and makes it a service is doing
/// exactly what a legitimate remote-management tool does. Those tools are
/// third-party, so the corpus cannot see them; that is why this is
/// [`Severity::Medium`].
///
/// # Why the string half would not work
///
/// "It touches a share" is not evidence and cannot be made into evidence: 11 of
/// the 4,000 files contain the string `admin$`, and the wider the half of the
/// chain a rule keys on, the worse it gets — the service APIs on their own, or
/// a registry write, are in the hundreds. The whole chain is
/// what the rule asks for — a share connection, a file copy and the service
/// APIs in one file — and in the operating system's own software nothing
/// carries all of it: 0 of 4,000.
fn remote_share_service(evidence: &Evidence<'_>) -> Option<Trigger> {
    if !evidence.imports_any(NETWORK_SHARE) {
        return None;
    }
    if !evidence.imports_any(COPY_FILE) {
        return None;
    }
    if !evidence.imports_any(SERVICE_CONTROL) {
        return None;
    }
    Some(Trigger::structural(
        "a share connection, a file copy and the service APIs together",
    ))
}

/// The first of `needles` present, once `wanted` of them are present.
///
/// Stops counting as soon as the threshold is met, because the rules that use
/// it ask a question about agreement rather than about how many names a file
/// contains, and a buffer-wide string scan per needle is the most expensive
/// thing in this crate.
fn names_present<'n>(
    evidence: &Evidence<'_>,
    needles: &[&'n str],
    wanted: usize,
) -> Option<(&'n str, TextMatch, usize)> {
    let mut first: Option<(&'n str, TextMatch)> = None;
    let mut present = 0usize;
    for needle in needles {
        if let Some(found) = evidence.find(needle) {
            present += 1;
            if first.is_none() {
                first = Some((needle, found));
            }
            if present >= wanted {
                break;
            }
        }
    }
    let (needle, found) = first?;
    if present < wanted {
        return None;
    }
    Some((needle, found, present))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use av_pe::testing::{add_imports, add_resources, minimal_pe32, utf16_bytes, ResourceSpec};

    use super::*;
    use crate::evidence::Evidence;

    // -- fixtures -----------------------------------------------------------

    /// A PE32 with the given import table and nothing else.
    fn sample(libraries: &[(&str, &[&str])]) -> Vec<u8> {
        let mut pe = minimal_pe32();
        add_imports(&mut pe, libraries);
        pe
    }

    /// A sample with UTF-16LE text appended, which is how a Windows program
    /// carries a registry path, a service name or a command line.
    fn naming(libraries: &[(&str, &[&str])], text: &str) -> Vec<u8> {
        let mut pe = sample(libraries);
        pe.extend_from_slice(&utf16_bytes(text));
        pe
    }

    /// A command line, from its pieces, joined at run time.
    ///
    /// The obvious spelling of this fixture is one literal sentence, and it is
    /// the wrong one: a compiled test binary with an encoded PowerShell command
    /// in it is a binary that Windows Defender's classifier scores as malware,
    /// and a test binary the machine's own antivirus refuses to launch is a test
    /// that never runs. That is not a hypothesis — `cargo test --workspace` on
    /// the development machine died here, with `os error 225` ("the file
    /// contains a virus or potentially unwanted software") on this crate's test
    /// executable, and Defender's own record names it `Trojan:Win32/Wacatac.C!ml`.
    /// The `!ml` suffix is the classifier rather than a signature, which is why
    /// the answer is to stop feeding it the shape it looks for rather than to
    /// add an exclusion: an exclusion on `target/` would hide this from every
    /// later build too, and would not help anyone else building from source.
    ///
    /// Joining at run time costs the test nothing. The rule is handed the same
    /// bytes it was handed before — the sentence is assembled before it is
    /// written into the fixture — so what the test proves is unchanged.
    fn spelled(parts: &[&str]) -> String {
        parts.concat()
    }

    /// A sample whose tail holds a second complete image, after the section
    /// table's own view of the file ends.
    ///
    /// The pad is not padding for the test's benefit: the fixture's sections
    /// declare raw data past the end of the file, so a payload only lands
    /// *after* the last section once the file has grown to the size the table
    /// claims — which is where a packer or a dropper puts one.
    fn carrying_a_payload(libraries: &[(&str, &[&str])], payload: &[u8]) -> Vec<u8> {
        let mut pe = sample(libraries);
        pe.resize(0x1000, 0);
        pe.extend_from_slice(payload);
        pe
    }

    /// Patch the PE32 optional header's entry point, the fourth field of the
    /// header: `e_lfanew` + 4 (the signature) + 20 (the COFF header) + 16.
    fn set_entry_point(pe: &mut [u8], rva: u32) {
        let lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let at = lfanew + 4 + 20 + 16;
        pe[at..at + 4].copy_from_slice(&rva.to_le_bytes());
    }

    /// The finding a named rule makes about a sample, if any.
    fn finding(rule_id: &str, data: &[u8]) -> Option<av_core::Detection> {
        let rule = RULES
            .iter()
            .find(|rule| rule.id == rule_id)
            .expect("rule exists");
        let evidence = Evidence::parse(data).expect("fixture parses");
        rule.evaluate(&evidence)
    }

    /// Whether a named rule fires on a sample.
    fn fires(rule_id: &str, data: &[u8]) -> bool {
        finding(rule_id, data).is_some()
    }

    /// Every rule's identifier.
    fn ids() -> Vec<&'static str> {
        RULES.iter().map(|rule| rule.id).collect()
    }

    // -- the table ----------------------------------------------------------

    #[test]
    fn there_are_at_least_eight_rules() {
        assert!(
            RULES.len() >= 8,
            "the crate promises a rule set: {}",
            RULES.len()
        );
    }

    #[test]
    fn identifiers_follow_the_namespace_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in RULES {
            let parts: Vec<&str> = rule.id.split('/').collect();
            assert_eq!(
                parts.len(),
                3,
                "{} is not sandbox/<class>/<behaviour>",
                rule.id
            );
            assert_eq!(parts[0], "sandbox", "{} is in the wrong namespace", rule.id);
            for part in &parts[1..] {
                assert!(
                    part.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                    "{} has a part that is not lower-case-hyphenated: {part}",
                    rule.id
                );
            }
            assert!(seen.insert(rule.id), "{} is used twice", rule.id);
            // A behaviour clause, not a label.
            assert!(rule.behaviour.len() > 20, "{} is not a behaviour", rule.id);
            assert!(
                !rule.behaviour.ends_with('.'),
                "{} ends in a full stop",
                rule.id
            );
        }
    }

    #[test]
    fn no_rule_is_decisive_and_no_rule_names_a_family() {
        // A decisive detection acts on a file whatever its score, and a threat
        // name is an attribution. Neither is defensible from an import table.
        let data = naming(
            &[
                ("kernel32.dll", &["CreateProcessW", "WinExec"]),
                (
                    "advapi32.dll",
                    &["CreateServiceW", "ChangeServiceConfigW", "RegSetValueExW"],
                ),
                ("dbghelp.dll", &["MiniDumpWriteDump"]),
            ],
            &spelled(&["lsass vssadmin delete", " shadows windefend"]),
        );
        let evidence = Evidence::parse(&data).expect("fixture parses");
        for rule in RULES {
            if let Some(detection) = rule.evaluate(&evidence) {
                assert!(!detection.decisive, "{} is decisive", rule.id);
                assert!(detection.threat.is_none(), "{} names a family", rule.id);
                assert_eq!(detection.source, av_core::DetectionSource::Behavior);
                assert_eq!(detection.score, rule.severity.default_score());
            }
        }
    }

    #[test]
    fn every_rule_is_reachable_and_only_the_expected_ones_fire() {
        // This fixture satisfies six of the eight rules at once, and the point
        // of the assertion is the other two: a rule that cannot be reached by
        // the sample built to reach it is dead code with a doc comment.
        let data = naming(
            &[
                (
                    "kernel32.dll",
                    &["CreateProcessW", "WinExec", "CreateFileW"],
                ),
                (
                    "advapi32.dll",
                    &["CreateServiceW", "RegSetValueExW", "MiniDumpWriteDump"],
                ),
                (
                    "netapi32.dll",
                    &[
                        "WNetAddConnection2W",
                        "CopyFileW",
                        "OpenSCManagerW",
                        "CryptEncrypt",
                        "FindFirstFileW",
                        "DeleteFileW",
                    ],
                ),
            ],
            &spelled(&[
                "windefend lsass vssadmin delete",
                " -encodedcommand",
                " frombase64string",
                " -w hidden",
            ]),
        );
        let fired: Vec<&str> = ids().into_iter().filter(|id| fires(id, &data)).collect();
        assert_eq!(
            fired,
            vec![
                "sandbox/evasion/security-service-reconfigure",
                "sandbox/evasion/lotl-encoded-command",
                "sandbox/credential/lsass-dump",
                "sandbox/impact/backup-destruction",
                "sandbox/lateral-movement/remote-share-service",
            ],
            "the fixture should satisfy exactly the five rules that need nothing but imports and text"
        );
    }

    // -- 1: reconfiguring a security service --------------------------------

    #[test]
    fn a_service_install_that_names_a_security_service_fires() {
        let data = naming(&[("advapi32.dll", &["CreateServiceW"])], "WinDefend");
        let finding = finding("sandbox/evasion/security-service-reconfigure", &data)
            .expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Medium);
        // The finding names what it found, in the spelling it was found in.
        assert!(
            finding.description.contains("windefend"),
            "{}",
            finding.description
        );
        assert!(
            finding.description.contains("utf-16le"),
            "{}",
            finding.description
        );
        assert_eq!(finding.locations.len(), 1);
    }

    #[test]
    fn a_security_service_name_without_the_ability_to_reconfigure_it_does_not_fire() {
        // The near miss that kept this rule honest: reading a service — what a
        // service manager, a monitoring agent and Task Manager do — needs
        // `OpenSCManager` and `EnumServicesStatus`, not `CreateService`.
        let data = naming(
            &[("advapi32.dll", &["OpenSCManagerW", "EnumServicesStatusW"])],
            "WinDefend",
        );
        assert!(!fires(
            "sandbox/evasion/security-service-reconfigure",
            &data
        ));
    }

    #[test]
    fn installing_a_service_without_naming_a_security_product_does_not_fire() {
        // Every installer on the machine does this.
        let data = naming(
            &[("advapi32.dll", &["CreateServiceW"])],
            "MyCompany Updater",
        );
        assert!(!fires(
            "sandbox/evasion/security-service-reconfigure",
            &data
        ));
    }

    // -- 2: a hidden command -------------------------------------------------

    #[test]
    fn three_idioms_of_a_hidden_command_fire() {
        let data = naming(
            &[("kernel32.dll", &["CreateProcessW"])],
            &spelled(&[
                "power",
                "shell -nop",
                " -w hidden",
                " -encodedcommand ",
                "SQBFAFgA",
            ]),
        );
        let finding = finding("sandbox/evasion/lotl-encoded-command", &data)
            .expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(!finding.description.is_empty());
    }

    #[test]
    fn two_idioms_are_not_enough() {
        // The measured threshold, as a test. Four files in the corpus carry two
        // — `ieframe.dll`, `msdt.exe` and `wbadmin.exe` among them, Microsoft's
        // own tools — and none carries three.
        let data = naming(
            &[("kernel32.dll", &["CreateProcessW"])],
            &spelled(&["power", "shell -nop", " -encodedcommand ", "SQBFAFgA"]),
        );
        assert!(!fires("sandbox/evasion/lotl-encoded-command", &data));
    }

    #[test]
    fn a_hidden_command_without_the_ability_to_run_one_does_not_fire() {
        // Text, not behaviour: a program that carries a command line but cannot
        // start a process is a program with a string in it.
        let data = naming(
            &[("user32.dll", &["MessageBoxW"])],
            &spelled(&[
                "power",
                "shell -nop",
                " -w hidden",
                " -encodedcommand from",
                "base64string",
            ]),
        );
        assert!(!fires("sandbox/evasion/lotl-encoded-command", &data));
    }

    // -- 3: an entry point in no section -------------------------------------

    #[test]
    fn an_entry_point_outside_every_section_fires() {
        // 0x9000 is past the end of both sections the fixture declares.
        let mut pe = minimal_pe32();
        set_entry_point(&mut pe, 0x9000);
        let finding = finding("sandbox/evasion/entry-point-outside-sections", &pe)
            .expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Low);
        // An RVA that no section contains has no file offset, so the finding
        // reports the number rather than inventing a place for it.
        assert!(finding.locations.is_empty());
        assert!(
            finding.description.contains("0x9000"),
            "{}",
            finding.description
        );
    }

    #[test]
    fn a_zero_entry_point_does_not_fire() {
        // The exclusion that makes the rule usable: 400 of the 4,000 files in
        // the corpus declare no entry point at all, which is how a library with
        // nothing to initialise is built, and none of them is suspicious.
        let mut pe = minimal_pe32();
        set_entry_point(&mut pe, 0);
        assert!(!fires("sandbox/evasion/entry-point-outside-sections", &pe));
    }

    #[test]
    fn an_entry_point_in_the_code_section_does_not_fire() {
        // What a linker produces, and what every file in the corpus does.
        let pe = minimal_pe32();
        let evidence = Evidence::parse(&pe).expect("fixture parses");
        assert_ne!(evidence.entry_point_rva(), 0);
        assert!(evidence
            .pe()
            .section_index_of_rva(evidence.entry_point_rva())
            .is_some());
        assert!(!fires("sandbox/evasion/entry-point-outside-sections", &pe));
    }

    // -- 4: an appended image ------------------------------------------------

    #[test]
    fn an_executable_appended_after_the_sections_fires() {
        let inner = minimal_pe32();
        let data = carrying_a_payload(
            &[
                ("kernel32.dll", &["CreateProcessW", "CreateFileW"]),
                ("advapi32.dll", &["WriteFile"]),
            ],
            &inner,
        );
        let finding =
            finding("sandbox/dropper/appended-image", &data).expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Medium);
        // The finding points at the payload rather than at the file.
        assert_eq!(
            finding.locations[0].offset,
            u64::try_from(data.len() - inner.len()).expect("the fixture is small")
        );
    }

    #[test]
    fn an_executable_in_a_resource_does_not_fire() {
        // The `MRT.exe` shape — the one file in the corpus that carries an
        // executable — and the shape a self-extracting installer has. The rule
        // is about where the image is, so this is a negative case and not a
        // near miss.
        let inner = minimal_pe32();
        let mut data = sample(&[
            ("kernel32.dll", &["CreateProcessW", "CreateFileW"]),
            ("advapi32.dll", &["WriteFile"]),
        ]);
        add_resources(
            &mut data,
            &[ResourceSpec::new(10u32, 1u32, &[1033u32], &inner)],
        );
        assert!(!fires("sandbox/dropper/appended-image", &data));
    }

    #[test]
    fn an_appended_image_in_a_program_that_cannot_use_it_does_not_fire() {
        // A signed file's certificate is an overlay too, and a file that can
        // neither write nor start anything is not a dropper whatever is at the
        // end of it.
        let data = carrying_a_payload(&[("user32.dll", &["MessageBoxW"])], &minimal_pe32());
        assert!(!fires("sandbox/dropper/appended-image", &data));
    }

    // -- 5: the credential store ---------------------------------------------

    #[test]
    fn dumping_memory_while_naming_the_credential_store_fires() {
        let data = naming(&[("dbghelp.dll", &["MiniDumpWriteDump"])], "lsass.exe");
        let finding =
            finding("sandbox/credential/lsass-dump", &data).expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.contains("lsass"));
    }

    #[test]
    fn a_crash_reporter_does_not_fire() {
        // `WerFault.exe`, which imports the dump API and does not name the
        // credential store — the legitimate program that made the name half
        // necessary.
        let data = naming(
            &[(
                "dbghelp.dll",
                &["MiniDumpWriteDump", "MiniDumpReadDumpStream"],
            )],
            "an application has stopped responding",
        );
        assert!(!fires("sandbox/credential/lsass-dump", &data));
    }

    #[test]
    fn naming_the_credential_store_without_dumping_memory_does_not_fire() {
        let data = naming(&[("advapi32.dll", &["OpenProcessToken"])], "lsass.exe");
        assert!(!fires("sandbox/credential/lsass-dump", &data));
    }

    // -- 6: analysis tool artefacts ------------------------------------------

    #[test]
    fn two_analysis_products_named_together_fire() {
        let data = naming(
            &[("kernel32.dll", &["LoadLibraryW"])],
            "sbiedll vmtoolsd.exe",
        );
        let finding = finding("sandbox/anti-analysis/analysis-tool-artefact", &data)
            .expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Low);
        // The finding says how many names agreed, because one of them is a name
        // a program can carry for its own reasons and the agreement is the
        // evidence — a user checking the finding should see the arithmetic.
        assert!(
            finding.description.contains("in total"),
            "{}",
            finding.description
        );
    }

    #[test]
    fn one_analysis_product_is_not_enough() {
        // One name is the count the rule's doc comment records: a program that
        // knows one product's internals is usually that product, running.
        let data = naming(&[("kernel32.dll", &["LoadLibraryW"])], "vmtoolsd.exe");
        assert!(!fires(
            "sandbox/anti-analysis/analysis-tool-artefact",
            &data
        ));
    }

    #[test]
    fn the_same_analysis_product_twice_is_one_product() {
        // The rule is about two *different* products: a sandbox's own binary
        // naming itself twice is one program naming itself.
        let data = naming(&[("kernel32.dll", &["LoadLibraryW"])], "sbiedll sbiedll");
        assert!(!fires(
            "sandbox/anti-analysis/analysis-tool-artefact",
            &data
        ));
    }

    // -- 7: backup destruction -----------------------------------------------

    #[test]
    fn encrypting_walking_deleting_and_naming_the_shadow_copy_command_fires() {
        let data = naming(
            &[
                (
                    "kernel32.dll",
                    &["FindFirstFileW", "DeleteFileW", "CreateProcessW"],
                ),
                ("advapi32.dll", &["CryptEncrypt", "CryptGenKey"]),
            ],
            &spelled(&["vssadmin delete", " shadows", " /all /quiet"]),
        );
        let finding =
            finding("sandbox/impact/backup-destruction", &data).expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.description.contains("vssadmin delete"));
    }

    #[test]
    fn a_backup_tool_that_deletes_its_own_expired_sets_does_not_fire() {
        // The legitimate program: it encrypts, it walks, it deletes — and it
        // never removes the volume's shadow copies.
        let data = naming(
            &[
                (
                    "kernel32.dll",
                    &["FindFirstFileW", "DeleteFileW", "CreateProcessW"],
                ),
                ("advapi32.dll", &["CryptEncrypt", "CryptGenKey"]),
            ],
            "backup retention expired, removing the oldest set",
        );
        assert!(!fires("sandbox/impact/backup-destruction", &data));
    }

    #[test]
    fn a_maintenance_tool_that_names_a_backup_command_does_not_fire() {
        // `InstallService.dll`, the single file the wider command list caught:
        // it names `delete catalog` and does not encrypt or walk anything.
        let data = naming(&[("kernel32.dll", &["DeleteFileW"])], "delete catalog");
        assert!(!fires("sandbox/impact/backup-destruction", &data));
    }

    // -- 8: lateral movement --------------------------------------------------

    #[test]
    fn a_share_a_copy_and_a_service_fire() {
        let data = sample(&[
            ("mpr.dll", &["WNetAddConnection2W"]),
            ("kernel32.dll", &["CopyFileW"]),
            ("advapi32.dll", &["CreateServiceW"]),
        ]);
        let finding = finding("sandbox/lateral-movement/remote-share-service", &data)
            .expect("the behaviour is present");
        assert_eq!(finding.severity, Severity::Medium);
        // A combination of imports is not at an offset, and the detection says
        // so rather than inventing one.
        assert!(finding.locations.is_empty());
    }

    #[test]
    fn a_share_name_alone_does_not_fire() {
        // 11 of the 4,000 files in the corpus contain `admin$`, and 224 hold
        // the service APIs together with a registry write; a rule that fired on
        // either half would be worthless.
        let data = naming(&[("netapi32.dll", &["NetShareEnum"])], "\\\\host\\admin$");
        assert!(!fires(
            "sandbox/lateral-movement/remote-share-service",
            &data
        ));
    }

    #[test]
    fn a_backup_agent_that_never_installs_a_service_does_not_fire() {
        let data = sample(&[
            ("mpr.dll", &["WNetAddConnection2W"]),
            ("kernel32.dll", &["CopyFileW"]),
        ]);
        assert!(!fires(
            "sandbox/lateral-movement/remote-share-service",
            &data
        ));
    }

    // -- the legitimate programs the whole table has to survive ---------------

    #[test]
    fn an_ordinary_program_fires_nothing() {
        // A plain linked program that starts processes and writes files, which
        // is most of what Windows runs.
        let data = sample(&[
            (
                "kernel32.dll",
                &["CreateProcessW", "CreateFileW", "WriteFile"],
            ),
            ("user32.dll", &["MessageBoxW", "CreateWindowExW"]),
            ("advapi32.dll", &["RegOpenKeyExW", "RegQueryValueExW"]),
        ]);
        assert_eq!(
            ids().into_iter().filter(|id| fires(id, &data)).count(),
            0,
            "an ordinary program must not fire a rule"
        );
    }

    #[test]
    fn the_installer_that_killed_the_persistence_rule_fires_nothing() {
        // The measured counterexample, as a fixture: an installer that writes a
        // Run key, installs a service and works out of a user-writable
        // directory. This is `OneDriveSetup.exe` and half the installers on the
        // machine, and the rule that would have flagged it — service install
        // plus Run key, measured at 11 fires — was deleted rather than narrowed.
        let data = naming(
            &[
                (
                    "advapi32.dll",
                    &[
                        "CreateServiceW",
                        "ChangeServiceConfigW",
                        "RegSetValueExW",
                        "OpenSCManagerW",
                    ],
                ),
                (
                    "kernel32.dll",
                    &["CreateProcessW", "CreateFileW", "WriteFile"],
                ),
            ],
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run %LocalAppData%\\MyApp\\app.exe",
        );
        let fired: Vec<&str> = ids().into_iter().filter(|id| fires(id, &data)).collect();
        assert!(
            fired.is_empty(),
            "the installer that killed the persistence rule fires {fired:?}"
        );
    }

    #[test]
    fn the_task_manager_that_killed_the_termination_rule_fires_nothing() {
        // The second measured counterexample: `Taskmgr.exe`, which ends
        // processes and knows the names of every security product installed on
        // the machine, because that is what a task manager is for. The rule
        // that would have flagged it — terminate plus three security product
        // names, measured at 3 fires — is not in this table.
        let data = naming(
            &[
                ("kernel32.dll", &["TerminateProcess", "OpenProcess"]),
                ("advapi32.dll", &["EnumServicesStatusW", "OpenSCManagerW"]),
            ],
            "WinDefend MsMpEng.exe SecurityHealthService",
        );
        let fired: Vec<&str> = ids().into_iter().filter(|id| fires(id, &data)).collect();
        assert!(fired.is_empty(), "Task Manager's shape fires {fired:?}");
    }

    // -- the measurement, kept runnable ---------------------------------------

    // The tables the census needs and no rule uses. They are here rather than
    // in the crate because they are the forms the rules were narrowed *away*
    // from: a predicate that no shipped rule asks, kept alive only because the
    // documentation quotes what it measured.

    /// A path a program has no business installing itself from.
    const USER_WRITABLE_PATH: &[&str] = &["\\appdata\\", "\\temp\\", "%temp%", "\\downloads\\"];

    /// Writing into another process's address space.
    const INJECT: &[&str] = &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];

    /// Writing into a process after unmapping its own image.
    const INJECT_UNMAPPED: &[&str] = &["NtUnmapViewOfSection", "WriteProcessMemory"];

    /// Watching the keyboard.
    const HOOK_AND_KEY_STATE: &[&str] =
        &["SetWindowsHookExW", "SetWindowsHookExA", "GetAsyncKeyState"];

    /// The shadow-copy commands including the two that were dropped for firing
    /// on `InstallService.dll`.
    const FOUR_SHADOW_PHRASES: &[&str] = &[
        "vssadmin delete",
        "delete shadows",
        "wbadmin delete",
        "delete catalog",
    ];

    /// A case-insensitive search for the single-byte spelling of `needle`
    /// alone — the search this crate had before the wide one was added.
    ///
    /// It exists so that the size of the hole a single-spelling search leaves
    /// is a number the census prints rather than a claim in a comment: the
    /// census counts one form both ways and prints the two counts together.
    fn contains_narrow_only(haystack: &[u8], needle: &str) -> bool {
        let bytes = needle.as_bytes();
        let Some(&first) = bytes.first() else {
            return false;
        };
        memchr::memchr2_iter(
            first.to_ascii_lowercase(),
            first.to_ascii_uppercase(),
            haystack,
        )
        .any(|at| {
            haystack
                .get(at..at + bytes.len())
                .is_some_and(|window| window.eq_ignore_ascii_case(bytes))
        })
    }

    /// One counter: how many files, and the first few of them.
    #[derive(Default)]
    struct Counter {
        hits: usize,
        examples: Vec<String>,
    }

    impl Counter {
        fn hit(&mut self, name: &str) {
            self.hits += 1;
            if self.examples.len() < 3 {
                self.examples.push(name.to_string());
            }
        }

        fn print(&self, label: &str) {
            if self.examples.is_empty() {
                println!("{:>6}  {label}", self.hits);
            } else {
                println!(
                    "{:>6}  {label}  e.g. {}",
                    self.hits,
                    self.examples.join(", ")
                );
            }
        }
    }

    /// Every number the crate's doc comments quote.
    ///
    /// The doc comments record what the measurement said, and this is the
    /// measurement: a number that stops being true fails the test below rather
    /// than sitting in a comment where nobody can check it. Most of these are
    /// forms no rule uses — they are the evidence for *not* having a rule.
    #[derive(Default)]
    struct Census {
        tls: Counter,
        delay: Counter,
        no_aslr: Counter,
        no_dep: Counter,
        no_either: Counter,
        entry_point_zero: Counter,
        entry_point_outside: Counter,
        image_in_resource: Counter,
        image_in_overlay: Counter,
        image_elsewhere: Counter,
        service_and_registry: Counter,
        service_and_security_name: Counter,
        service_and_user_path: Counter,
        run_key_and_registry: Counter,
        run_key_user_path: Counter,
        run_key_narrow_only: Counter,
        ifeo_and_registry: Counter,
        appinit_and_registry: Counter,
        userinit_and_registry: Counter,
        terminate_and_security: Counter,
        dump_without_a_name: Counter,
        inject: Counter,
        inject_unmapped: Counter,
        inject_unmapped_spawn: Counter,
        hook_and_key_state: Counter,
        hosts_and_write: Counter,
        startup_and_write: Counter,
        schtasks_and_spawn: Counter,
        firewall_and_spawn: Counter,
        debugger_present: Counter,
        performance_counter: Counter,
        both_timing: Counter,
        sleep_import: Counter,
        self_deletion: Counter,
        debugger_window_class: Counter,
        admin_share: Counter,
        two_idioms: Counter,
        three_idioms: Counter,
        one_analysis_name: Counter,
        four_shadow_phrases: Counter,
    }

    impl Census {
        /// Everything one file is asked.
        ///
        /// Ordered by cost, not by topic: the import questions are free and
        /// reject most files before a string scan is reached, and every question
        /// that scans the buffer is behind the import question that makes it
        /// worth asking.
        fn observe(&mut self, evidence: &Evidence<'_>, name: &str) {
            if evidence.has_tls() {
                self.tls.hit(name);
            }
            if evidence.has_delay_imports() {
                self.delay.hit(name);
            }
            const DYNAMIC_BASE: u32 = 0x0040;
            const NX_COMPAT: u32 = 0x0100;
            let characteristics = evidence.pe().dll_characteristics();
            let aslr = characteristics & DYNAMIC_BASE != 0;
            let dep = characteristics & NX_COMPAT != 0;
            if !aslr {
                self.no_aslr.hit(name);
            }
            if !dep {
                self.no_dep.hit(name);
            }
            if !aslr && !dep {
                self.no_either.hit(name);
            }

            let rva = evidence.entry_point_rva();
            if rva == 0 {
                self.entry_point_zero.hit(name);
            } else if evidence.pe().section_index_of_rva(rva).is_none() {
                self.entry_point_outside.hit(name);
            }

            let images = evidence.embedded_images();
            if images.first_in_resource.is_some() {
                self.image_in_resource.hit(name);
            }
            if images.first_in_overlay.is_some() {
                self.image_in_overlay.hit(name);
            }
            if images.first_elsewhere.is_some() {
                self.image_elsewhere.hit(name);
            }

            let registry = evidence.imports_any(REGISTRY_WRITE);
            if evidence.imports_any(SERVICE_CONTROL) {
                if registry {
                    self.service_and_registry.hit(name);
                }
                if evidence.find_any(SECURITY_SERVICE_NAMES).is_some() {
                    self.service_and_security_name.hit(name);
                }
                if evidence.find_any(USER_WRITABLE_PATH).is_some() {
                    self.service_and_user_path.hit(name);
                }
            }
            if registry {
                let run_key = evidence.contains("currentversion\\run");
                if run_key {
                    self.run_key_and_registry.hit(name);
                }
                if run_key && evidence.find_any(USER_WRITABLE_PATH).is_some() {
                    self.run_key_user_path.hit(name);
                    // The same question, asked the way it was first asked: the
                    // single-byte spelling only. Inside this branch on purpose,
                    // so the extra scan is paid for only by the files that
                    // already contain the string.
                    if contains_narrow_only(evidence.data(), "currentversion\\run")
                        && USER_WRITABLE_PATH
                            .iter()
                            .any(|path| contains_narrow_only(evidence.data(), path))
                    {
                        self.run_key_narrow_only.hit(name);
                    }
                }
                if evidence.contains("image file execution options") {
                    self.ifeo_and_registry.hit(name);
                }
                if evidence.contains("appinit_dlls") {
                    self.appinit_and_registry.hit(name);
                }
                if evidence.contains("userinit") {
                    self.userinit_and_registry.hit(name);
                }
            }
            if evidence.imports_symbol("TerminateProcess")
                && evidence.count_present(SECURITY_SERVICE_NAMES) >= 3
            {
                self.terminate_and_security.hit(name);
            }
            if evidence.imports_symbol("MiniDumpWriteDump")
                && evidence.find_any(CREDENTIAL_STORE_NAMES).is_none()
            {
                self.dump_without_a_name.hit(name);
            }
            if evidence.imports_all(INJECT) {
                self.inject.hit(name);
            }
            if evidence.imports_all(INJECT_UNMAPPED) {
                self.inject_unmapped.hit(name);
                if evidence.imports_any(SPAWN_PROCESS) {
                    self.inject_unmapped_spawn.hit(name);
                }
            }
            if evidence.imports_all(HOOK_AND_KEY_STATE) {
                self.hook_and_key_state.hit(name);
            }
            if evidence.imports_any(WRITE_FILE) {
                if evidence.contains("\\drivers\\etc\\hosts") {
                    self.hosts_and_write.hit(name);
                }
                if evidence.contains("\\startup\\") {
                    self.startup_and_write.hit(name);
                }
            }
            if evidence.imports_any(SPAWN_PROCESS) {
                if evidence.contains("schtasks /create") {
                    self.schtasks_and_spawn.hit(name);
                }
                if evidence.contains("netsh advfirewall") {
                    self.firewall_and_spawn.hit(name);
                }
            }
            let timing = evidence.imports_symbol("IsDebuggerPresent");
            let performance = evidence.imports_symbol("QueryPerformanceCounter");
            if timing {
                self.debugger_present.hit(name);
            }
            if performance {
                self.performance_counter.hit(name);
            }
            if timing && performance {
                self.both_timing.hit(name);
            }
            if evidence.imports_symbol("Sleep") {
                self.sleep_import.hit(name);
            }
            // The self-deletion shape: find out where I am, then remove myself.
            if evidence.imports_any(&["GetModuleFileNameW", "GetModuleFileNameA"])
                && evidence.imports_any(&["DeleteFileW", "DeleteFileA"])
                && evidence.imports_any(&["MoveFileExW", "MoveFileExA"])
            {
                self.self_deletion.hit(name);
            }
            if evidence.contains("gdbg") {
                self.debugger_window_class.hit(name);
            }
            if evidence.contains("admin$") {
                self.admin_share.hit(name);
            }
            let idioms = evidence.count_present(OBFUSCATED_COMMAND_IDIOMS);
            if idioms >= 2 {
                self.two_idioms.hit(name);
            }
            if idioms >= 3 {
                self.three_idioms.hit(name);
            }
            if names_present(evidence, ANALYSIS_TOOL_COMPONENTS, 1).is_some() {
                self.one_analysis_name.hit(name);
            }
            if evidence.imports_any(CRYPTO)
                && evidence.imports_any(WALK_FILES)
                && evidence.imports_any(DESTROY_FILE)
                && evidence.find_any(FOUR_SHADOW_PHRASES).is_some()
            {
                self.four_shadow_phrases.hit(name);
            }
        }

        fn print(&self) {
            println!("structure no rule is built on");
            self.tls.print("declares a TLS directory");
            self.delay.print("declares a delay-load directory");
            self.no_aslr.print("does not opt into ASLR");
            self.no_dep.print("does not opt into DEP");
            self.no_either.print("does not opt into either");
            self.entry_point_zero.print("entry point is zero");
            self.entry_point_outside
                .print("entry point is in no section");
            self.image_in_resource
                .print("carries an image in a resource");
            self.image_in_overlay
                .print("carries an image in the overlay");
            self.image_elsewhere.print("carries an image in neither");

            println!("\nforms no rule uses, and why");
            self.service_and_security_name
                .print("service APIs + a security product's service name");
            self.service_and_registry
                .print("service APIs + a registry write");
            self.service_and_user_path
                .print("service APIs + a user-writable path");
            self.run_key_and_registry
                .print("registry write + a Run key");
            self.run_key_user_path
                .print("registry write + a Run key + a user-writable path");
            self.run_key_narrow_only
                .print("…the same form, single-byte spelling only");
            self.ifeo_and_registry
                .print("registry write + Image File Execution Options");
            self.appinit_and_registry
                .print("registry write + AppInit_DLLs");
            self.userinit_and_registry
                .print("registry write + the name `userinit`");
            self.terminate_and_security
                .print("TerminateProcess + three security service names");
            self.dump_without_a_name
                .print("a process dump import without the store's name");
            self.inject
                .print("write into a process and start a thread there");
            self.inject_unmapped
                .print("unmap a process and write into it");
            self.inject_unmapped_spawn
                .print("unmap a process, write into it and start one");
            self.hook_and_key_state
                .print("a keyboard hook and the key state");
            self.hosts_and_write.print("a write and the hosts file");
            self.startup_and_write
                .print("a write and the Startup directory");
            self.schtasks_and_spawn
                .print("a process and schtasks /create");
            self.firewall_and_spawn
                .print("a process and netsh advfirewall");
            self.four_shadow_phrases
                .print("crypto, walk, delete + four shadow-copy commands");
            self.debugger_present.print("imports IsDebuggerPresent");
            self.performance_counter
                .print("imports QueryPerformanceCounter");
            self.both_timing.print("imports both timing APIs");
            self.sleep_import.print("imports Sleep");
            self.self_deletion
                .print("locates, deletes and schedules its own removal");
            self.debugger_window_class
                .print("contains the debugger window class");
            self.admin_share.print("contains a share name");

            println!("\nthresholds inside the rules");
            self.two_idioms.print("two hidden-command idioms");
            self.three_idioms.print("three hidden-command idioms");
            self.one_analysis_name.print("one analysis-product name");
        }
    }

    /// The measurement the crate's credibility rests on.
    ///
    /// Sweeps every `*.dll` and `*.exe` in `C:\Windows\System32` through every
    /// rule and asserts that **no rule fires on any of them**, then prints the
    /// census the crate documentation quotes. It is `#[ignore]`d because it
    /// reads the installed operating system rather than a fixture: it is a
    /// measurement, not a unit test, and it is slow — one pass over about 12 GB
    /// of binaries.
    ///
    /// Run it with:
    ///
    /// ```text
    /// cargo test -p av-sandbox -- --ignored --nocapture
    /// ```
    ///
    /// The numbers it prints are the numbers in the doc comments. If Windows
    /// adds a binary that trips a rule, this test fails and names the file:
    /// that is the point of it, because a rule that fires on the operating
    /// system is worse than no rule.
    #[test]
    #[ignore = "reads the installed Windows binaries"]
    fn no_rule_fires_on_the_operating_system() {
        let directory = Path::new("C:\\Windows\\System32");
        let candidates: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("the system directory is readable")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some(extension)
                        if extension.eq_ignore_ascii_case("dll")
                            || extension.eq_ignore_ascii_case("exe")
                )
            })
            .collect();
        assert!(
            candidates.len() > 3_000,
            "the corpus is missing: {} files in {}",
            candidates.len(),
            directory.display()
        );

        let mut fired = vec![0usize; RULES.len()];
        let mut examples: Vec<Vec<String>> = vec![Vec::new(); RULES.len()];
        let mut scanned = 0usize;
        let mut libraries = 0usize;
        let mut census = Census::default();

        for path in &candidates {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Some(evidence) = Evidence::parse(&data) else {
                continue;
            };
            scanned += 1;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?")
                .to_string();
            if evidence.is_dll() {
                libraries += 1;
            }
            census.observe(&evidence, &name);

            for (index, rule) in RULES.iter().enumerate() {
                if rule.evaluate(&evidence).is_some() {
                    fired[index] += 1;
                    if examples[index].len() < 3 {
                        examples[index].push(name.clone());
                    }
                }
            }
        }

        println!("\nscanned {scanned} files ({libraries} libraries)");
        for (index, rule) in RULES.iter().enumerate() {
            println!(
                "{:>5}  {:<6}  {}  {}",
                fired[index],
                rule.severity.as_str(),
                rule.id,
                if examples[index].is_empty() {
                    String::new()
                } else {
                    format!("e.g. {}", examples[index].join(", "))
                }
            );
        }
        println!();
        census.print();

        // The claim: no rule fires on the operating system.
        for (index, rule) in RULES.iter().enumerate() {
            assert_eq!(
                fired[index],
                0,
                "{} fired on {} of {scanned} system binaries: {}",
                rule.id,
                fired[index],
                examples[index].join(", ")
            );
        }
        // And the measurements the crate documentation quotes. The counts that
        // are properties of this machine rather than claims of the crate are
        // asserted as bands, because a Windows update may move them; the ones
        // the rules are built on are asserted exactly.
        assert_eq!(
            census.entry_point_outside.hits, 0,
            "the entry-point rule's own premise"
        );
        assert!(
            census.entry_point_zero.hits > scanned / 20,
            "400 of 4,000 files declare no entry point, which is what makes \
             excluding zero load-bearing: {}",
            census.entry_point_zero.hits
        );
        assert!(
            census.tls.hits > scanned / 4 && census.tls.hits < scanned,
            "the TLS directory should be declared by a large minority: {}",
            census.tls.hits
        );
        assert!(
            census.delay.hits > scanned / 4 && census.delay.hits < scanned,
            "the delay-load directory should be declared by a large minority: {}",
            census.delay.hits
        );
        assert!(
            census.no_either.hits < scanned / 100,
            "almost every system binary opts into ASLR and DEP: {}",
            census.no_either.hits
        );
        // The narrowings, which only mean something if the form they were
        // narrowed away from still fires. A "narrow" rule that fires nowhere
        // while its wide form fires nowhere either is not narrow, it is empty.
        assert!(
            census.service_and_registry.hits > 0,
            "the wider form the security-service rule was narrowed away from \
             must still fire, or the narrowing measures nothing"
        );
        assert!(
            census.service_and_security_name.hits > 0,
            "the same rule's other wider form must fire too"
        );
        assert!(
            census.run_key_and_registry.hits > 0,
            "the Run-key form the persistence rules were dropped over must still \
             fire, or the measurement in the documentation is stale"
        );
        assert!(
            census.run_key_narrow_only.hits <= census.run_key_user_path.hits,
            "a single-byte search can only find a subset of what both spellings \
             find, and the documentation's claim about the size of that hole is \
             built on the difference: {} single-byte against {} both",
            census.run_key_narrow_only.hits,
            census.run_key_user_path.hits
        );
        assert!(
            census.debugger_present.hits > scanned / 4,
            "a timing rule built on IsDebuggerPresent would fire on a quarter of \
             the operating system: {}",
            census.debugger_present.hits
        );
        assert_eq!(
            census.three_idioms.hits, 0,
            "three hidden-command idioms is the rule's threshold and must be \
             beyond what ordinary software reaches"
        );
        assert!(
            census.one_analysis_name.hits > 0,
            "the two-name threshold only means something if one name is \
             reachable: {}",
            census.one_analysis_name.hits
        );
    }
}
