# Wenle Antivirus

A complete antivirus engine written in Rust: a scanner, a rule engine of its own,
a kernel driver, realtime protection, memory scanning, a quarantine vault, a
service, and a graphical front end.

There is no cloud component and no machine learning. Every decision is made on
the machine it runs on, from bytes the product read itself, and can be explained
afterwards in terms the user can check.

## Status

This is a working product, not a prototype. Where it is incomplete, the table
below says so.

| Area | State |
|---|---|
| Rule engine, compiler, database | Working. Compiles the full 10,764-rule corpus with no refusals. |
| Scanner (`wenle scan`) | Working. Rule detections, PE and archive structure, heuristics, the trust layer. |
| Quarantine vault | Working. Sealing, restore, export, retention, integrity verification. |
| Realtime protection | Working. Filesystem watchers, on-access decisions, the block path. |
| Memory scanning | Working. `wenle memory`, `wenle scan --memory`, and a process-scan request over the service pipe. With the driver loaded the service also walks each process as it starts, and a process holding code from a file that is malicious on its own evidence is terminated, with that file quarantined. A region no file backs is reported and never acted on: those bytes say nothing about which program wrote them. What stops something *before* it runs is the driver, not this. |
| Kernel driver | Working, and written against KMDF in its own workspace. It needs the WDK to build, and it has been installed, loaded and exercised in a Windows 11 guest under test signing. [Limitations](#limitations) says what those runs measured and what is still unmeasured. `wenle integrate driver install` puts it on the machine and `remove` takes it off again; the registration is checked by reading the machine back rather than by trusting what was written. |
| Integration with Windows | Working. Explorer's right-click scan verbs, the AMSI provider that examines script before a host runs it, and Defender's real-time monitoring. Every one of them is a command that has to be typed and one that undoes it; see [What this changes on the machine](#what-this-changes-on-the-machine). |
| Service and IPC | Working. Same protocol and decision logic tested in user mode. |
| GUI (`wenle-gui`) | Working. A window over the same engine the console drives. |
| Self-protection | Working. Directory permissions, the service's start type and recovery policy, and a manifest of the product's own files that reports any of them that changes. `wenle protect status` reports all of it and needs no elevation. |
| Sandbox | Structure-only analysis by design: it answers what a sample's headers, imports, sections and resources imply it would do, and **nothing in it executes anything**. Eight behaviour rules, each measured against every PE file in `System32` before it was written. Off by default. |
| Scan throughput | Working. See [Performance](#performance) for the measured cost and what removed it. |

## Build

Stable Rust 1.82 or newer, Windows.

```
cargo build --release
```

That builds every crate except the driver, which needs the WDK, a nightly
toolchain and `-Z build-std`, and therefore lives in its own workspace so an
ordinary build never tries to compile it.

It produces three executables and one DLL, all in the same directory:
`wenle.exe`, `wenle-av-service.exe`, `wenle-gui.exe` and `av_amsi.dll`. They
have to be built together, because the provider is a separate `cdylib`:
`cargo build -p av-cli` links the CLI against the provider's `rlib` and leaves
the DLL unbuilt, so a product assembled that way registers a provider that is
not there.

The driver directory carries its own `rust-toolchain.toml` and
`.cargo/config.toml`, so it is built by going there. It is not optional: the
driver is the fifth program and the sixth file the product's tamper manifest
covers.

```
cd crates/av-driver
cargo build
```

That writes `crates/av-driver/target/x86_64-pc-windows-msvc/debug/av_driver.dll`,
a native x86_64 image under a `.dll` name, because the linker arguments that
make it a driver are `cdylib` arguments and cargo names the artifact for the
crate type. What an installed machine gets is `WenleAvFilter.sys`; the extension
is the loader's convention, not the compiler's. `wenle integrate driver install`
finds either name, and `wenle protect manifest` records all six files
(`wenle.exe`, `wenle-av-service.exe`, `wenle-gui.exe`, `av_amsi.dll`, the driver
and the compiled rule database) and reports any of them that later goes missing.
It refuses to run from a checkout: the driver is a cargo workspace of its own
with its artifact under a second `target` directory, so a build tree holds
neither of the driver's names, and a baseline taken there would name files an
installation does not have while replacing the baseline the installation
compares itself against.

## Quick start

Compile the rule sources into a database, then scan with it.

```
wenle build                          # compiles the installed rules
wenle scan C:\Users\you\Downloads    # scan something
wenle scan . --json                  # machine-readable findings
```

`wenle build` with no arguments compiles the rules installed at
`%ProgramData%\WenleAV\rules` and writes `%ProgramData%\WenleAV\db\rules.avdb`.
That directory holds two source trees: `converted/`, which is the shipped rule
corpus, and `core/`, which is where rules written by hand in this product's own
language go. The corpus in `converted/` is the detection the product ships;
`core/` is read by the same build and is empty until someone puts a rule in it.
Naming sources explicitly overrides the default and reads only what is named:

```
wenle build rules\converted          # just the shipped corpus
wenle build rules\core --strict      # just your own rules, refusing any bad one
wenle build --output test.avdb --report
```

`--strict` turns every refused rule into a build failure. A release build uses
it, because a release whose rule set is quietly smaller than it claims is a
release that ships a smaller product than it says.

Other commands:

```
wenle db info <FILE>          # what a database contains and can detect
wenle db list <FILE>          # the rules in it
wenle quarantine list         # what the product has taken off this machine
wenle quarantine restore <id> # put something back
```

Memory is its own command, because it answers a question no file scan can and it
comes up when there is no directory to point at:

```
wenle memory                  # every process this account can open
wenle memory --pid 4242       # just one
wenle memory --pid 4242 --quarantine
```

A finding in a process is attributed to `process:address`, and what gets dealt
with is the *file* its bytes came from: that file is examined in its own right
and taken into the vault only if it is malicious on its own evidence. A memory
match is a lead, not a verdict about a file, because the loader relocates an
image as it maps it, so bytes at `libfoo.dll+0x1234` in memory may match nothing
at `0x1234` on disk. When the bytes came from no file at all (injected code,
which is the case this exists for) there is nothing to put in a vault, and the
report says so rather than staying quiet.

Setting the product up on a machine is a sequence of commands that each do one
thing, in the order they depend on each other. From an elevated prompt:

```
wenle protect apply                  # permissions on the product's directories, and
                                     # the service's start type once it exists
wenle protect manifest               # record what the product's own files are
wenle service install                # the service, starting at boot
wenle integrate shell install --machine   # the right-click verbs
wenle integrate amsi install         # examine script before a host runs it
wenle integrate driver install       # the kernel driver
```

Each of those is independent and each is undone by its partner; see
[What this changes on the machine](#what-this-changes-on-the-machine) before
running any of them. `wenle protect status` afterwards reports all of it at once
and needs no elevation.

## What this changes on the machine

An antivirus product that will not say what it did to your computer is not one
you should install. Every command below changes the machine it is run on, every
one of them needs administrator rights, and every one is undone by the command
next to it. Nothing else in this product writes outside
`%ProgramData%\WenleAV`.

| Command | What it writes | Undone by |
|---|---|---|
| `wenle service install` | One service in the Service Control Manager, starting at boot. | `wenle service remove` |
| `wenle integrate shell install --machine` | Four verbs under `HKLM\SOFTWARE\Classes`: `Scan with Wenle Antivirus` on a file, on a folder, on the empty space inside a folder, and on a drive. | `wenle integrate shell remove --machine` |
| `wenle integrate shell install --user` | The same four verbs under `HKCU\SOFTWARE\Classes`, for one account only. | `wenle integrate shell remove --user` |
| `wenle integrate amsi install` | Two keys under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`, registering `av_amsi.dll`. | `wenle integrate amsi remove` |
| `wenle integrate defender disable` | One value under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`. **This turns off a Windows security feature.** The previous value is recorded first. | `wenle integrate defender restore` |
| `wenle integrate driver install` | One file, `System32\drivers\WenleAvFilter.sys`, and one service key with two subkeys. **This is the only command that puts code into the kernel.** | `wenle integrate driver remove` |
| `wenle protect apply` | The DACL of the install, database, rules, cache, log and configuration directories; and the `WenleAvService` start type, if it was not already one that starts by itself. The value it found is printed when it changes it. | `wenle protect restore` for the permissions, and `sc.exe config WenleAvService start= <what it was>` for the start type |
| `wenle protect manifest` | A record of the product's own files under the product's data directory. | Deleting that record |

Three of these are worth more than a table row.

**Defender.** `disable` is the only command in the product that switches off
something that was protecting the machine. It is never run as a side effect of
anything, including `service install`, and it writes down what the key held
*before* it changes it, so that `restore` can put that exact value back,
including removing the value entirely if that is what was there. Running
`disable` twice is refused rather than repeated, because repeating it would
overwrite the record with the value it wrote itself. Defender's tamper
protection, if it is on, will usually refuse or revert the write; the command
reports that and does not try to turn tamper protection off.

**The driver.** `integrate driver install` copies the driver into
`System32\drivers` and registers it as a filesystem filter with altitude 321000,
in the Anti-Virus range. Two details of that registration are choices rather
than defaults. Its start type is boot-start and its error control is `NORMAL`,
not `CRITICAL`: a driver whose own initialisation fails is logged and not loaded,
rather than being allowed to bugcheck the machine, which is the difference
between a protection layer that is absent and a computer that will not start.
And the filter is registered but not *running*: a filter that is already loaded
stays loaded until the machine restarts, so `remove` stops it being loaded next
time and does not unload it now. Run `fltmc unload WenleAvFilter` first if it
needs to be gone before then.

The kernel loads an image only if it can verify it, and this build has no
verification to offer. On a normal machine the kernel will therefore accept the
registration and then decline to load the driver, which is why
`integrate driver status` reports the registration and says in the same breath
that the registry does not record whether the kernel took it. `fltmc filters` is
what answers that. Loading this build means `bcdedit /set testsigning on` and a
reboot, which is a change to the machine's boot configuration and not something
this product will do for you.

**Permissions, and the gap that used to be here.** This section once said that
`protect apply` had no paired command, and that this was the one gap in the
table above with no way back, on the grounds that permissions are not a setting
the product can hold a copy of. That reasoning was wrong, and the cost of it
being wrong was the one thing in this product that changed the machine's access
control irreversibly. A DACL can be read and written as text, which is exactly what
`wenle integrate defender disable` already did with the value it replaced.

So `apply` now reads and records every directory's permissions *before* it
changes them, the same shape as the Defender pair, recorded in `dacl.record`
under the data directory. `wenle protect restore` puts them back and removes the
record. The record is taken only if there is not one already, because
overwriting it would capture the hardened permissions and destroy the only copy
of the originals; running `apply` twice therefore keeps the first record rather
than replacing it. A machine whose permissions could not be read is still
repaired, and says out loud that there is now no undo.

`restore` verifies rather than trusts: it writes each recorded DACL and then
reads the directory back, because a security-descriptor write that returned
success is not the same fact as a directory that now has those permissions, and
it says which of the two it found. It also refuses to apply a record taken
against a *different* installation, for the same reason `verify` refuses a
mismatched manifest, and there the consequence is worse than a wrong report: it
would write another machine's permissions onto these directories.

`apply` also writes one thing that is not a permission. If the service exists
and its start type is one that does *not* start by itself (manual, disabled, or
a value this build cannot name) it is set to start automatically shortly after
boot, and the value it found is printed. That is the state `wenle protect status`
fails on, and until 2026-10-11 it was the one failure in this product whose
remedy was a command outside it, `sc config WenleAvService start= delayed-auto`.
A service that already starts by itself is left exactly as it is, which is what
`wenle service install` produces: a plain automatic service is a machine that is
protected, and rewriting it to a delayed one would be this command changing a
decision somebody made about their own machine. There is no recorded undo for
this one, unlike the DACLs, because a start type is not a value the product
keeps a copy of, so the printed old value is what
`sc.exe config WenleAvService start= …` puts back.

`apply` refuses to run at all when the executable is inside a cargo build tree,
because an installation's permissions strip write access from the account that
has to rebuild there. `manifest` refuses in the same place for a worse reason:
it would write a build tree's baseline to the path an *installed* copy compares
itself against, which reports every one of that installation's own files as
missing rather than unchanged.

`wenle protect status` reports the state of all of it without changing anything,
and `wenle protect audit` reads the permissions back off the objects rather than
repeating what `apply` intended.

## Layout

| Crate | What it is |
|---|---|
| `av-core` | Shared types: errors, threat naming, verdict scoring, paths, configuration. |
| `av-fs` | Reading files a scanner would otherwise be refused. |
| `av-patterns` | Fixed-length atom matching for the rule prefilter. |
| `av-rules` | The rule engine: parser, compiler, the compiled database, matching. |
| `av-pe` | PE parsing, answering exactly the questions the `pe` module asks. |
| `av-signatures` | Authenticode signatures, read far enough to answer what a rule asks. |
| `av-authenticode` | Verified Authenticode: the signature over the file, checked against a chain the platform built. |
| `av-archive` | Container readers. What is inside a file, and what could not be read. |
| `av-scan` | The scan engine: a rule set and a file become a verdict. |
| `av-quarantine` | The vault. Sealed payloads, restore, retention, integrity. |
| `av-memory` | Scanning what a running process holds, not just what is on disk. |
| `av-realtime` | Catching a file when it appears, rather than when someone asks. |
| `av-sandbox` | What a sample would do, judged from its structure, without running it. |
| `av-driver-proto` | The driver's protocol and decision logic, tested in user mode. |
| `av-ipc` | The control protocol between the service and everything that talks to it. |
| `av-service` | The Windows service that ties realtime, memory and IPC together. |
| `av-guard` | Self-protection: hardening the service, its directories and its files, and noticing when any of it is undone. |
| `av-integration` | Putting the product into Windows: the typed registry wrapper, the Explorer verbs, the AMSI registration, Defender's settings, and the driver's service key. |
| `av-amsi` | The AMSI provider. Script content handed to the engine before the host runs it. |
| `av-cli` | The `wenle` command-line front end. |
| `av-gui` | The graphical front end, `wenle-gui`. |
| `av-driver` | The KMDF driver. Separate workspace; see Build. |

## The rule engine

The engine is written from scratch. It is not YARA and does not link YARA. It
reads YARA-*syntax* sources because that syntax is a superset of what it needs,
and because a corpus written for another engine is a corpus worth compiling
rather than rewriting. It accepts `.avrule`, `.yar` and `.yara` files for that
reason.

The language is implemented, not interpreted: sources are parsed, compiled to a
plan, and serialised into a `.avdb` database. Loading a database is roughly 0.6×
the cost of compiling the same sources, and the matchers are rebuilt on load
rather than stored, which keeps the on-disk format free of anything that is a
detail of one build.

**A refused rule is named, not ignored.** When a source uses a construct the
engine does not implement, the compiler refuses that rule, records the construct
that would fix it, and carries on with the rest. `wenle build --report` groups
the refusals by missing capability, most common first, which is a work queue
ordered by how much each entry buys. On the corpus this product ships, the
refusal count is zero.

Rule sources live in two directories under `%ProgramData%\WenleAV\rules`:
`converted/`, for the upstream corpus this product imports, and `core/`, for
rules written for this engine. `core/` is currently empty, and that is a state
this product chose rather than an omission: a detection rule that has never been
tested against the behaviour it claims to catch is a liability, not coverage,
and this product does not ship rules it cannot demonstrate. What goes in `core/`
is corrections. The licensing note at the end lists the ones applied so far.

## Detection, and the three bands

A verdict is not a boolean. Findings fall into three bands:

- **Clean**: nothing to say.
- **Suspicious**: reported and *never acted on*. This is the band that means
  "worth a look". Packing, high entropy, unusual sections and single weak
  signature hits accumulate here.
- **Malicious**: corroborated. Only this band is ever quarantined.

Accumulation alone is not meant to reach that threshold. On a clean Windows
install an over-eager heuristic produces hundreds of
warnings, and hundreds of warnings is the same as none, because the user learns
to dismiss all of them including the one that mattered.

### One match that identifies the sample convicts alone

"Hard to reach by accumulation" is not the same as "hard to reach". A single
detection is enough when the rule that produced it identifies *this* sample
rather than its shape, and there are exactly four ways that happens:

- the file's hash is one the rule set already knows;
- the rule's author rated it **90 or above out of 100** for confidence *and*
  **80 or above** for construction;
- the rule's **name** identifies a family *and* one of its instances:
  `SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver` is a named rootkit,
  `SIGNATURE_BASE_WEBSHELL` is a shape of webshell. This route exists because
  the alternative was measured and rejected. A file matching a named rootkit's
  signature was reported *suspicious*, a band that never acts, so the one match
  that identified the malware was the one match nothing could be done about;
- the rule's **condition** cannot be satisfied by anything ordinary. A rule
  saying `$marker` where `$marker` is a fifty-byte build string convicts on its
  own, because nothing but that family writes the string down. A rule saying
  `any of them` over `shell_exec`, `base64_decode` and a probe does not, because
  an ordinary installer contains the first two and the rule is one short of
  firing whatever the probe is. This is read out of the condition itself: an
  algebra over the strings it can be satisfied by, with every unknown answered
  towards the weaker side. It is never read out of the rule's metadata.

Of the 10,764 shipped rules, **3,645 convict on a single match**, 33.9% of the
corpus. 46 do it on the author's rating, and the remaining 3,599 on a *reading*
of the rule: its name, or a condition nothing ordinary satisfies.

The two readings are the weaker pair, on purpose. A name is the corpus's own
title for a rule and its author still rated that rule an ordinary 75, and a
condition is a shape this product inferred rather than a claim the author made.
A conviction resting on either can therefore be argued with by evidence about
who published the file, and a conviction resting on an author's rating or a hash
cannot. That asymmetry is what keeps the false-positive surface small: a reading
cannot convict a file whose identity is proven, so the population at risk is
unsigned software, and the reading has to be narrow enough that ordinary
unsigned software does not fall in.

The line is drawn by measurement, and the first measurement was wrong. The
condition reading shipped with a twelve-byte line, chosen by argument, and a
scan of 80,638 installed files under `Program Files`, `Program Files (x86)` and
`%LOCALAPPDATA%\Programs` put **54 of them in the malicious band**. Every one of
them was a conviction that reading had reached, 46 of them Microsoft Office's
own bundled JavaScript, matched on thirty-three bytes of a Babel error message.
The line is now 36 bytes, the smallest value that clears every rule that scan
convicted with, and the number of rules the condition reading alone promotes
falls from 8,034 to 2,979.

The same scan at 36 bytes reports **no file in the malicious band**, and no rule
convicting on a reading at all. What it does not report is a machine with 54
fewer findings: those files are still detected, at a score that puts them in the
suspicious band, which warns and never acts. A line that clears a false positive
moves it out of the band that acts, not out of the report, and saying which of
the two happened is the difference between a measurement and a boast.

That is the shape of the trade. A length is a *proxy* for "ordinary", the proxy
is wrong at both ends, and the only defence is to keep measuring it against real
software. `av_rules::content` records the numbers and `target/fp-probe.sh` is
the probe. Re-run it after any change to what convicts.

### The trust layer

The strongest evidence available about a file is not what it contains but *which
file it is*. A match against a Windows catalog is proof of identity: catalog
membership is verified by finding a SHA-1 or SHA-256 preimage, so a file that is
in a catalog is the file Microsoft shipped, byte for byte. Nothing inside the
file can forge that.

So when **every** detection on a file is generic, that is, no rule claimed to
recognise *this* sample and each claimed only its shape, the trust layer has an
answer. If the file's identity is *proven*, by catalog membership or a verified
signature, the detections are cleared and the file is reported clean; the
detections stay in the report, marked as suppressed, so the decision can be read
back. If the identity is only *claimed*, by a certificate nobody verified, the
verdict is capped at `suspicious` and removal is withheld: the file is
described, never touched.

When only *some* detections are generic, neither of those happens. Nothing is
cleared, nothing is capped. The generic detections are discounted, which lowers
the score, and the verdict is whatever the specific rule made it.

Specificity is therefore part of the test, and the two kinds of specificity are
treated differently:

- a rule whose **author rated it** 90/100 or better is not generic, and nothing
  about who published the file may discount it. Signing real malware with a
  stolen certificate is a thing that happens, and "the publisher is known" is no
  answer to a rule its author staked their confidence on;
- a rule that convicts on a **reading** (its name, or a condition nothing
  ordinary satisfies) *is* generic, because a title and a shape are both this
  product's inference and neither is the author staking their confidence. This
  is not a loophole; it is the measurement. `System32\MRT.exe` matches
  `SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1` and is **right to**: MRT's own
  signature database stores LockBit's URLs, XOR-encoded. Trust may
  demote that verdict to *suspicious* and withhold removal. Without that escape
  hatch, a rule engine that convicts on a reading would quarantine Microsoft's
  Malicious Software Removal Tool on a stock Windows install.

The layer is weaker for embedded signatures. A certificate sitting inside a file
is a *claim*, not proof, until something verifies it cryptographically. The
product reads certificates and uses them as evidence, and knows the difference.

Both front ends have to be able to say that this happened, because "why was this
not detected" is the question a user asks when they are told a file is clean and
do not believe it. The console prints the rules it threw away under the finding,
and the window shows them as `Remediation` and `Suppressed` rows in the detail
pane. A run reports how many files were cleared rather than passed (`cleared` in
`--json`, a sentence in the summary of both front ends), because a scan that
threw matches away and then said *nothing found* would be answering a question
nobody asked. Nothing is ever done about a cleared file: clearing is a statement
about identity, not a permission to act.

## One window per installation

`wenle-gui.exe` is a file on the desktop, so it gets double-clicked, pinned to
the taskbar, and launched from the right-click menu. All of those start the same
executable, and none of them should produce a second window. Two windows over
one rule database, one configuration and one quarantine vault are two answers to
every question the product asks, and nothing on screen says which one is which.

So the first launch claims a named mutex and the second hands over what it
wanted instead of opening anything. The name is derived from the data directory,
which means an installed copy and a portable one beside it are two separate
products and get a window each, while two spellings of one path
(`C:\ProgramData\WenleAV` and `c:\programdata\wenleav`) are one window.

The second launch's *arguments* are handed over, not just its existence. That
matters for exactly one case, and it is the case the feature is judged on:
`wenle-gui.exe --scan "%1"` from the Explorer verb, run against a window that is
already open, has to scan rather than come to the front. A right-click that
raises a window and does nothing shows the user an answer that is wrong, which
is worse than showing them a second window. The path goes over a named pipe in
message mode; the running window drains it once per frame, raises itself, and
starts the scan. A request that arrives while a scan is already running cannot
be honoured at that instant, because two scans over one findings list is the
same problem as two windows, so the path waits in the target field and the
status line says so.

There is no `WM_COPYDATA` and no `FindWindowW` anywhere in it. `eframe` does not
expose the window procedure, so there is nowhere for a posted message to arrive;
and the process that owns the window is the only one that knows whether it is
behind something, minimised, or on another virtual desktop, so raising it is
done with `egui`'s own `ViewportCommand::Focus` rather than by a stranger
guessing at a window title.

## Running out of memory

A scanner reads whole files into memory, and a scan of a whole disk runs for
long enough to meet a machine that is running out of commit charge. This used to
end the process. Rust's allocator is infallible: when `vec![0u8; size]` cannot
be satisfied it calls `handle_alloc_error`, which prints one line and calls
`abort()`, an uncatchable `__fastfail`. There is no error to return, no report
to write, and a window that simply vanishes. The failure is also *invisible to
Windows*: an abort raised this way leaves no `APPCRASH` entry in the Event Log.
The one witness is `%ProgramData%\WenleAV\logs\crash.log`, which records the size
that was asked for and the commit that was left.

Nothing about that is a scanning bug and everything about it is a product bug,
so three things changed:

- **the read path is fallible.** A file is read through `try_reserve_exact`, and
  a refusal becomes a skipped file with a reason (see `Why::OutOfMemory` in
  `av-fs`) rather than an abort. A scan that reports a file as unexamined is
  worth more than a scan that stops;
- **the rule database is checked before it is loaded.** It is 25 MiB on disk and
  about 469 MB resident, so `Database::load` measures the machine's free commit
  first and refuses with a sentence naming all three numbers, rather than failing
  part-way through building the tables;
- **the check happens before the walk.** Both front ends counted the files and
  *then* loaded the database, so a load that could not be afforded arrived after
  the file count: a window that counted to ten thousand and then disappeared.
  `Database::check_file` now performs the same check the loader does, so the
  answer comes in the same second as the click.

The measurements behind the guard are 469 MB resident against 25.3 MiB on disk,
18.5×, rounded to 20× and charged as such, plus 64 MiB of headroom; the budget
in `av-fs` charges its headroom on the same principle. On a machine that cannot
afford the rules, the answer is a sentence and an exit code, not a scan that dies
halfway through.

## Performance

A scan's cost was `(strings needing a full search) × (file size)`, and that
product was the whole problem. On `shell32.dll` the first working version spent
**9.87 s** on one 8 MB file, of which 1,569 strings were searched one at a time:
12.57 GB of memory traffic to answer a question about 8 MB of bytes. The same
model predicted 509 s for `MRT.exe`, and it was right to within a few percent,
which is how it was known to be a structural cost rather than a tuning problem.

Three changes removed it, and each targets a different term:

1. **A rule-level prefilter, not a string-level one.** Atoms say what a *string*
   must contain; whether a rule can be dropped when a string is absent is a
   question about its *condition*, and reading the condition's required slots is
   what makes the filter selective. Read as "some string might be present" the
   filter selected 51% to 72% of the rule set; read as "every required slot is
   still possible" it selects 5.8% on `notepad.exe`, 8.1% on `kernel32.dll` and
   12.7% on `shell32.dll`.
2. **One pass instead of 1,569.** Every literal form in the rule set goes into a
   single Aho-Corasick pass over the buffer, so the per-string term disappears
   for literals. Hex and regex strings keep the ordinary path: they are a fixed
   pattern's minority and their atoms are what the prefilter exists for.
3. **A matcher built for the only pattern shape that matters.** Every atom is
   three or four bytes, and a matcher that knows its patterns are all one short
   fixed length need not carry automaton state between bytes. Two tables keyed
   on the window's own bytes answer "which atoms start here" without the
   transition table that spilled out of cache. Measured on the real atom set in
   one process, the search costs **208 ms** with the new matcher against
   **336 ms** with Aho-Corasick. The old search ran at 154 MB/s at a thousand
   patterns, 84 at ten thousand and 22 at sixty-seven thousand, which is the
   shape of a cache miss charged per input byte.

Current cost on the same file, `shell32.dll`: **2.04 s**, split 558 ms prefilter,
151 ms sweep, and 1.33 s on the strings that survived the gate. That is four
times faster than the version the number above came from, on a rule set eight
times larger than a reporting engine would carry.

The split is the point of reporting it this way. The three stages have different
fixes, and an aggregate timing cannot tell them apart. What is left is not the
search: it is the 10.8 million atom matches a set of three- and four-byte atoms
finds in an 8 MB binary, and reducing *that* is a question about which atoms are
chosen, not about how fast they are found. There is a second pass over the rule
set that could score atoms by rarity instead of by their own bytes. It is
described in `crates/av-rules/src/prefilter.rs` and not built, because building
it before something measures the end-to-end scan is guessing.

Every one of these is a filter, and a filter that is wrong loses detections
silently. `examples/verify_filters.rs` scans the same buffer twice, once
filtered and once through a scanner that decides nothing, and compares the
reported matches rule by rule and offset by offset. That differential check, not
the timings, is what makes the numbers above safe to quote.

## Limitations

Written down rather than left to be discovered. Every one of these is a real
edge of this build, and the ones that can be measured say what was measured.

**The kernel path has run, in a VM, and not on a stock machine.** The driver has
been installed, loaded and exercised in a Windows 11 guest under test signing:
its create gate has reported convictions on files being opened to execute, its
process-notify callback has reported process starts and the service has walked
and terminated on those reports, and its registration set is checked against the
machine rather than trusted. What has not been established is the thing the
create gate was written for. A refusal of the section gate is answered with
`STATUS_ACCESS_DENIED`, which the WDK does not list as an allowed failure for a
section creation, and on 2026-10-13 a *data* file mapped `PAGE_EXECUTE_READWRITE`
by a test program was mapped anyway, in the same second the refusal was logged.
What stopped that process was the memory walk, one to two seconds later. Nothing
on record measures that an image section is stopped either; the one run that
logged the refusal for an executable did not check whether the process started.
So what can be said is this: the gates report, one of them has been measured not
to stop what it was aimed at, and pre-execution blocking on a stock machine is a
claim this build does not make.

**The window hears about a service block about a second late.** The service
serves one pipe client at a time and finishes with it before taking the next, so
a window that held the pipe open to receive notifications would lock out
`wenle service status` for as long as it was running. The window polls the
vault's index instead, once a second, re-reading it when the file's length or
modification time has moved (`crates/av-gui/src/vault_poll.rs`). A block made by
the service therefore reaches the corner within about a second rather than at
once, and the poll costs one `stat` per second when nothing is happening.
Nothing announces a block when no window is running: `wenle-gui.exe` is the only
thing in the product that posts a notification, so a machine running the service
and the console alone has no toast surface at all.

**A burst of concurrent opens can cost the decision its answer.** The service's
decision port thread reads one request, waits up to 3.5 s for the scan behind
it, and answers. A request that arrives while it is waiting sits in the filter
manager's queue with the driver's own five-second clock already running, so once
the port thread is more than 1.5 s behind, the answer arrives after the driver
has stopped waiting and the file is allowed rather than blocked. A conviction
that finishes late is still reported and still quarantined; it is reported
*after* the file was allowed to run. A Defender definition update makes this
routine for a few seconds: the log shows the pair of lines
(`was allowed with no answer …` then `a decision could not be delivered`) over
definition files and `MpEngine.dll`. The fix is to answer from the worker thread
rather than from the port thread, which puts a second thread on the port. That
port is the part of this product that has bugchecked the test machine three
times, so it gets a change of its own rather than a footnote to this one.

**Two writers on one index is narrowed, not closed.** The vault's index is a
single file that the service, the console and the window all rewrite, and each
of them re-reads it before writing. There is no lock. Two processes writing in
the same instant can lose one of the two updates: the last writer wins, and an
entry the other one had just taken is missing from the index until something
writes it again. The re-read makes that a race rather than a certainty, and a
lock is what would close it. This is the one known way this product can lose
*track* of a file it has already taken, and it is track, not data: the sealed
payload and its record both remain on disk, which is why the re-read reports
such an entry as absent from the index rather than as deleted, and why nothing
is destroyed by it.

**Vault maintenance runs only when it is asked for.** `wenle quarantine maintain`
applies retention, the size limit, the deletion retry list and compaction. The
service never calls it, so a machine that is left running accumulates records
until somebody types that command. The service does retry a deletion that lost a
race with a handle, which is a different sweep.

**The product reports its own console binary as suspicious.** Run a scan of a
staged directory with the build in it and `wenle.exe` comes back **suspicious**,
score 60, on two heuristic detections, for importing several ways of asking
whether it is being debugged and for writing the registry and creating a
service. The console legitimately does both. That is a false positive on the
friendliest binary there is, and the mechanism is this: the
trust layer discounts a *generic* detection only for a file whose identity it
can prove, by membership in a Windows catalog or an embedded signature that
verifies, and a locally built binary has neither to offer. The same applies to
any unsigned third-party program, which is why the heuristics stay in the middle
band.

**No installer.** Distribution is a directory of six files, and putting it on a
machine is a command someone types. There is no setup program, no upgrade path
and no uninstall entry in Programs and Features. `wenle service remove`,
`integrate ... remove` and `protect restore` are the undo, and they are one
command each.

**Defender cannot be switched off by this build.** That section says what
`integrate defender disable` writes and how it is undone; the edge is that
Windows ignores those keys for a product it has not verified. They record an
intent and do not achieve it, and Defender's tamper protection, when it is on,
will usually refuse the write outright. The direction this build does support is
the other one: the AMSI provider, which examines script where Windows already
asks for a second opinion, and the two products running side by side.

**Memory scanning at process start needs the driver.** The walk is driven by
process-start events, and those come from the driver's notify callback. Without
the driver there is no standing sweep: `wenle memory` and the memory phase of a
scan examine what processes are holding at that moment, and that is all. The
walk is also a race by construction. The creation notification fires before the
program runs, so roughly half the walks used to see a 37-to-41-region address
space and find nothing; every process that came back clean is now walked a
second time after two seconds, counted separately, and the count of walks that
were dropped in between is reported. Late injection, after that second walk, is
still uncovered.

**The sandbox is built and switched off**, as specified. Its rules are compiled
and tested against every PE file in `System32`; nothing runs them.

**Detection is a snapshot of one corpus.** The engine implements a large subset
of the rule language and refuses the rest; `wenle build --report` lists what was
refused by construct, and `--strict` turns a refusal into a failure. The rules
in the database are the ones the engine can actually evaluate. Beyond that,
there is no cloud and no learning by design: this product cannot detect what no
rule in its corpus describes, and the corpus is a file on disk, only as new as
the build that shipped it.

**The rule set costs memory to have ready.** The compiled database is about
25 MB on disk, and a loaded database over the full corpus occupies a fixed
footprint of roughly 468 MB. That is the price of matching against 65,000
patterns locally rather than asking a server. It is paid once per process that
scans, and it is why the service exists as a long-lived process rather than a
scan per invocation.

**The window is English only, and has no file picker.** The language was
specified; there is no string table and no locale detection, so a translation
means introducing that indirection first. The scan target is a text field a path
is typed or pasted into, and `--scan` is what the Explorer verbs use.

## Licensing and attribution

The source code in this repository is MIT licensed; see `LICENSE`. That grant
covers the code, and not the rule text under `rules/`.

`rules/converted/yara-forge-extended-0.9.1.yar` and `rules/core/yara-rules-core.yar`
are packages produced by **YARA-Forge** (Apache-2.0), which merges rules from
many upstream repositories. Each package carries a header per upstream
repository naming it, its commit and its license, followed by that license's
full text, and those headers are intact inside the files. The upstreams are not
all under one license: some are MIT or Apache-2.0, and some state no license at
all. The bundled text therefore stays under whatever its own header says, and
its authors retain copyright. Read a package's headers before redistributing it.

Vendored rules are curated rather than used verbatim: where a rule is
structurally wrong, it is corrected in place and the correction is recorded in
that rule's `curation` metadata field. Every such change is described there,
with the evidence that motivated it.
