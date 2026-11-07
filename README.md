# Wenle EDR

An endpoint agent for Windows written in Rust: a kernel minifilter that sees file
operations before they happen, a decision service, a behaviour engine, a
quarantine vault, a CLI and a window.

This branch is the earlier line of work. The current one lives on the `v2`
branch: it adds the behaviour engine's cross-rule conviction, the four
self-protection gates that can refuse an operation, and the update channel.

## Build

```
cargo build --release
cd crates/av-driver && cargo build
```

The rule database is compiled rather than vendored; copy `assets/rules.avdb`
beside the executables. The driver is signed with a test certificate, so Windows
loads it only under `bcdedit /set testsigning on`.
