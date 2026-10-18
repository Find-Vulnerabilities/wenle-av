# Wenle Antivirus

A self-contained antivirus for Windows, written in Rust: scanner, rule engine,
kernel filter driver, realtime protection, memory scanning, quarantine vault,
service and GUI. No cloud, no telemetry, no machine learning — every verdict is
explained by evidence read on this machine.

## Build

```
cargo build --release                  # wenle.exe, wenle-av-service.exe, wenle-gui.exe, av_amsi.dll
cd crates/av-driver && cargo build     # the filter driver; needs the WDK and its own toolchain
```

The four user-mode programs must be built together; the AMSI provider is a
separate `cdylib`.

## Quick start

```
wenle build                            # compile the installed rules
wenle scan C:\Users\you\Downloads      # scan a file or directory
wenle memory                           # scan every process this account can open
wenle-gui                              # the window
```

`wenle build` compiles `%ProgramData%\WenleAV\rules` into
`%ProgramData%\WenleAV\db\rules.avdb`. `--strict` refuses a release with any
rule the engine cannot compile.

## What this changes on the machine

Every command below needs administrator rights and is undone by the command
next to it. Nothing else writes outside `%ProgramData%\WenleAV`.

| Command | What it writes | Undone by |
|---|---|---|
| `wenle service install` | One service, starting at boot. | `wenle service remove` |
| `wenle integrate shell install --machine` | Four Explorer verbs under `HKLM\SOFTWARE\Classes`. | `wenle integrate shell remove --machine` |
| `wenle integrate shell install --user` | The same four verbs under `HKCU\SOFTWARE\Classes`. | `wenle integrate shell remove --user` |
| `wenle integrate amsi install` | The AMSI provider keys for `av_amsi.dll`. | `wenle integrate amsi remove` |
| `wenle integrate defender disable` | **Turns off Defender's real-time protection.** The previous value is recorded first. | `wenle integrate defender restore` |
| `wenle integrate driver install` | `System32\drivers\WenleAvFilter.sys` and its filter service key. **Code in the kernel.** | `wenle integrate driver remove` |
| `wenle protect apply` | The DACLs of the product's own directories; records them first. | `wenle protect restore` |

`wenle protect status` reports all of the above without changing anything.

The driver is unsigned, so the kernel will load it only under
`bcdedit /set testsigning on` plus a reboot. A filter already loaded stays
loaded until the machine restarts; `remove` stops it loading next time.

## Status

A working product, not a prototype. The kernel driver has been installed,
loaded and exercised in a Windows 11 guest under test signing. The rule engine
compiles the shipped 10,764-rule corpus without refusals; detecting what no
rule in that corpus describes is outside what this build claims. The compiled
database is ~25 MB on disk and ~468 MB resident — the price of matching
locally. The window is English only.

## Licensing

The code is MIT (`LICENSE`). That grant does not cover `rules/`: the vendored
YARA-Forge packages (Apache-2.0) merge upstream rules whose individual licenses
are recorded in each package's headers, some of which state no license. Read
those headers before redistributing a package. Hand corrections to vendored
rules are recorded in each rule's `curation` metadata.

