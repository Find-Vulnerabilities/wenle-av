//! Hands the WDK to `wdk-build`, which does all of the work.
//!
//! `configure_wdk_binary_build` runs `cargo metadata`, reads the
//! `[package.metadata.wdk.driver-model]` section of this crate's manifest, and
//! then emits the linker directives a WDM driver needs: `ntoskrnl.lib`,
//! `hal.lib`, `BufferOverflowFastFailK.lib`, `wmilib.lib`, the `/KERNEL` and
//! `/SUBSYSTEM:NATIVE` flags, and `/ENTRY:DriverEntry` — the routine this crate
//! exports, which is why the manifest says WDM and not KMDF.
//!
//! The two models differ in more than a library list, and the driver paid for
//! finding that out: KMDF mode names `/ENTRY:FxDriverEntry`, which binds the
//! image to `WDFLDR.SYS` before calling `DriverEntry` and expects a
//! `WdfDriverCreate` that this crate never makes. The manifest carries the whole
//! argument; the short version is that a minifilter that calls no WDF API should
//! not be entered through the framework, and that `fltmc unload` bugchecked the
//! test VM while the framework's binding was in the unload path and unpaired.
//!
//! It also runs `bindgen` for `wdk-sys`. That is the slow part and the part
//! that needs `libclang`; if the build fails before compiling anything of ours,
//! that is where to look.
//!
//! This exists as a file rather than as inline logic so that the driver's build
//! has exactly one place it can fail for environmental reasons.
//!
//! # Why this crate is built with optimisations on
//!
//! `opt-level = 0` is the default for a dev profile and it does not link as a
//! driver, for a reason that cost more time to find than it should have. Nothing
//! here is a workaround for a fault in this crate: the unresolved symbol is in a
//! function nothing calls.
//!
//! Three things have to be true together, and each of them is measured rather
//! than assumed:
//!
//! 1. `wdk-build` links the driver with `/NODEFAULTLIB`. The link line rustc
//!    actually runs carries `"/defaultlib:libcmt"` — the CRT that `+crt-static`
//!    asks for — and then `/NODEFAULTLIB`, which cancels it. A kernel driver
//!    must not link a user-mode CRT, so that cancellation is correct.
//! 2. `compiler_builtins` does not define the libm math symbols on Windows.
//!    Its `src/math/mod.rs` gates them with
//!    `#[cfg(all(not(windows), not(target_vendor = "apple")))]` and says why:
//!    "weak linkage is unreliable on Windows and Apple, so we don't expose
//!    symbols that we know the system libc provides". On Windows it expects
//!    `libcmt` to supply `fma`, and `libcmt` is exactly what point 1 removes.
//!    The kernel-mode subset of the CRT is not a substitute: `libcntpr.lib`
//!    exports no `_fma` and no `_fmaf`.
//! 3. `compiler_builtins` sets `intrinsics_enabled` to true unconditionally for
//!    itself (`libm/configure.rs`, the `Library::CompilerBuiltins` arm, with the
//!    comment "Intrinsics are always enabled when a part of c-b"). So libm's
//!    `<f64 as Float>::fma` compiles to `core::intrinsics::fmaf64`, which LLVM
//!    lowers to a libcall named `fma` on any target without the `fma` feature —
//!    and the x86-64 baseline has no FMA.
//!
//! The callers of that trait method inside libm are `hypot` and `cbrt`. Nothing
//! in this driver calls either, so at `opt-level = 1` or above LLVM's global DCE
//! drops them before code generation and no `fma` reference is ever emitted.
//! At `opt-level = 0` they are still emitted, and `/OPT:REF` cannot remove them:
//! it eliminates unreferenced COMDATs, and a section the linker keeps still has
//! to have its relocations resolved, so `LNK2019: unresolved external symbol fma`
//! is reported for a function that can never run. A driver is also the last place
//! at `opt-level = 0` would be defensible; a filesystem filter runs on every I/O
//! in the system.
//!
//! What is deliberately *not* done here is defining `fma` for the linker's
//! benefit. A `fma` that quietly does not fuse is a rounding bug with no symptom,
//! and the kernel has no correct implementation to borrow.

//! # The callback check, and why it is not a comment
//!
//! `src/flt.rs` declares the filter manager's seven callback types by hand,
//! because `wdk-sys` 0.5.1 has no filter-manager binding at all -- its
//! `constants.rs` is the only file that mentions `FLT_REGISTRATION`, and there
//! is no `FltCreateCommunicationPort` in it. Hand-transcribing C declarations is
//! what this build script is here to police.
//!
//! Three of those seven were wrong on 2026-09-26, and all three had been wrong
//! for as long as they had existed. They were invisible for the same reason: the
//! code that called them had never run. `PFLT_CONNECT_NOTIFY` took its
//! `ClientPort` -- a `PFLT_PORT`, a value -- as a `*mut FltPort` and
//! dereferenced it, which was unreachable while the port's null security
//! descriptor refused every client; `PFLT_MESSAGE_NOTIFY` was declared with five
//! parameters where the header has six, so the `ULONG OutputBufferLength` landed
//! in a `*mut u32` slot and the handler wrote through it; and
//! `PFLT_FILTER_UNLOAD_CALLBACK` took a `FltFilter` where the header passes
//! `FLT_FILTER_UNLOAD_FLAGS`. Fixing the security descriptor made the first two
//! reachable for the first time, and the machine bugchecked within a second of
//! the service connecting.
//!
//! A doc comment quoting the header did not prevent any of that, and neither
//! would a layout assertion: the file's own assertions had already been shown to
//! be restatements rather than checks. So the header is read here, at build time,
//! and each declaration is compared with the typedef it claims to transcribe.
//!
//! What it compares is arity and the pointer-or-scalar shape of each parameter
//! -- which is what the three defects got wrong. What it does *not* compare is
//! the declared type of a parameter that is a pointer either way: `*mut c_void`
//! and `*mut *mut c_void` are both pointers, and telling those apart would need
//! the WDK's typedefs resolved to a depth this does not attempt. A parameter
//! whose level of indirection is wrong still has to be caught by reading the
//! header.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn main() -> Result<(), wdk_build::ConfigError> {
    check_callback_declarations();
    check_import_declarations();
    wdk_build::configure_wdk_binary_build()
}

/// One hand-written callback type and the header typedef it transcribes.
struct Alias {
    rust: &'static str,
    header: &'static str,
}

/// Every `unsafe extern "system" fn` type in `src/flt.rs` that stands for a
/// filter-manager callback, paired with the `fltKernel.h` typedef it has to
/// match.
const ALIASES: &[Alias] = &[
    Alias { rust: "PreOperationCallback", header: "PFLT_PRE_OPERATION_CALLBACK" },
    Alias { rust: "PostOperationCallback", header: "PFLT_POST_OPERATION_CALLBACK" },
    Alias { rust: "FilterUnloadCallback", header: "PFLT_FILTER_UNLOAD_CALLBACK" },
    Alias { rust: "InstanceSetupCallback", header: "PFLT_INSTANCE_SETUP_CALLBACK" },
    Alias { rust: "ConnectNotifyCallback", header: "PFLT_CONNECT_NOTIFY" },
    Alias { rust: "DisconnectNotifyCallback", header: "PFLT_DISCONNECT_NOTIFY" },
    Alias { rust: "MessageNotifyCallback", header: "PFLT_MESSAGE_NOTIFY" },
    Alias { rust: "GenericWorkItemRoutine", header: "PFLT_GENERIC_WORKITEM_ROUTINE" },
];

/// One hand-written `extern "system"` declaration of a kernel API, and the
/// header prototype it transcribes.
struct Import {
    /// The name in our source. Spelled the same as the header's in all but one
    /// case, which is not laziness on the author's part -- it is why a wrong
    /// declaration is easy to miss, and why the check has to look at the
    /// parameter list rather than at the name.
    name: &'static str,
    /// The name to look up in the header, when that is not `name`.
    ///
    /// `ObDereferenceObject` is the one that needs it: `wdm.h` does not
    /// prototype that name, it `#define`s it as two lines forwarding to
    /// `ObfDereferenceObject`. The function actually called is the one whose
    /// prototype matters, so the macro is followed rather than the name.
    prototype: Option<&'static str>,
    /// The file that declares it. `src/flt.rs` and `src/lib.rs` are the only
    /// places in the crate that declare a kernel API by hand -- everything else
    /// comes from `wdk-sys`, which is generated from the same headers.
    source: &'static str,
    /// The WDK header under `km` that prototypes it.
    header: &'static str,
}

/// Every hand-written kernel API declaration in the crate.
///
/// # Why it is exhaustive rather than a sample
///
/// A table of two out of twenty-three would report "checked 2 declarations",
/// which is true and reads as "the hand-written declarations are checked". The
/// list below is the check, so it is the whole list: adding a declaration to
/// `src/flt.rs` without adding it here leaves it unchecked, and the only thing
/// standing between that and a repeat of the bug is that the next person sees
/// the table next to the code.
const IMPORTS: &[Import] = &[
    Import { name: "FltRegisterFilter", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltStartFiltering", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltUnregisterFilter", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltCreateCommunicationPort", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltCloseCommunicationPort", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltBuildDefaultSecurityDescriptor", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltFreeSecurityDescriptor", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltSendMessage", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltAllocateGenericWorkItem", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltFreeGenericWorkItem", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltQueueGenericWorkItem", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltGetFileNameInformation", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltReleaseFileNameInformation", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltGetVolumeFromName", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltGetDiskDeviceObject", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "FltGetVolumeName", prototype: None, source: "src/flt.rs", header: "fltKernel.h" },
    Import { name: "KeGetCurrentIrql", prototype: None, source: "src/flt.rs", header: "wdm.h" },
    Import { name: "IoVolumeDeviceToDosName", prototype: None, source: "src/flt.rs", header: "ntddk.h" },
    Import { name: "PsGetCurrentProcessId", prototype: None, source: "src/flt.rs", header: "ntddk.h" },
    Import { name: "ObDereferenceObject", prototype: Some("ObfDereferenceObject"), source: "src/flt.rs", header: "wdm.h" },
    Import { name: "ExAllocatePool2", prototype: None, source: "src/flt.rs", header: "wdm.h" },
    Import { name: "ExFreePoolWithTag", prototype: None, source: "src/flt.rs", header: "wdm.h" },
    Import { name: "KeQueryInterruptTimePrecise", prototype: None, source: "src/lib.rs", header: "wdm.h" },
];

/// A declaration that no WDK header prototypes, so there is nothing to compare
/// it against.
///
/// Named rather than left out. The check prints how many declarations it covered
/// and how many it could not; a declaration missing from both tables would make
/// that second number a lie, which is the failure mode this whole check exists to
/// stop repeating.
struct Unprototyped {
    name: &'static str,
    source: &'static str,
    /// Why no header can be asked about it. Said here instead of in the build
    /// output, which would be noise on every build.
    reason: &'static str,
}

const UNPROTOTYPED: &[Unprototyped] = &[Unprototyped {
    name: "PsGetProcessImageFileName",
    source: "src/flt.rs",
    reason: "no WDK header declares it. `src/flt.rs` records the measurement: zero occurrences \
             under `Include\\10.0.26100.0`, three in `ntoskrnl.lib`, with `KeGetCurrentIrql` and \
             a deliberately absent name as controls on the same search. The name links and the \
             header does not describe it, so its parameter list is unchecked by anything here.",
}];

/// What a parameter list looks like from the outside.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    /// How many parameters there are.
    arity: usize,
    /// How many of them carry an address as their value.
    pointers: usize,
}

/// Reads `src/flt.rs` and the WDK's `fltKernel.h` and compares them.
///
/// Returns `()` or panics: a build script that panics fails the build, which is
/// the only outcome that is any use here. The message lists every mismatch at
/// once, so one run of `cargo build` is enough to see all of them.
fn check_callback_declarations() {
    println!("cargo:rerun-if-changed=src/flt.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let source = std::fs::read_to_string("src/flt.rs")
        .expect("build.rs: cannot read src/flt.rs, which is the file this check is about");
    let header = read_flt_kernel_h();
    let own_types = rust_type_aliases(&source);

    let mut complaints: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for alias in ALIASES {
        let Some(ours) = rust_callback_params(&source, alias.rust) else {
            complaints.push(format!(
                "  {} -- no `pub type {} = ... fn(` in src/flt.rs",
                alias.rust, alias.rust
            ));
            continue;
        };
        let Some(theirs) = header_typedef_params(&header, alias.header) else {
            complaints.push(format!(
                "  {} -- no `*{}) (` in fltKernel.h; has the typedef been renamed?",
                alias.header, alias.header
            ));
            continue;
        };

        let mine = shape_of_rust(&ours, &own_types);
        let real = shape_of_header(&theirs);
        checked += 1;
        if mine != real {
            complaints.push(format!(
                "  src/flt.rs `{}` vs fltKernel.h `{}`\n    \
                 declared: {} parameter(s), {} a pointer\n    \
                 header:   {} parameter(s), {} a pointer",
                alias.rust, alias.header,
                mine.arity, mine.pointers,
                real.arity, real.pointers,
            ));
        }
    }

    if !complaints.is_empty() {
        panic!(
            "the filter-manager callback declarations in src/flt.rs do not match \
             fltKernel.h:\n{}\n\n\
             Fix src/flt.rs to match the header, not the other way round -- the header \
             is what the filter manager compiled against. The parameter list of each \
             typedef is quoted verbatim in that type's doc comment; read it there, or \
             read the header itself at {}.",
            complaints.join("\n"),
            header_path_for("fltKernel.h")
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<not found>".to_string())
        );
    }

    // Printed, not silent. A check whose only output is the absence of output is
    // a check nobody can tell ran -- which is how this crate's earlier
    // assertions came to agree with the bugs they were guarding.
    println!("cargo:warning=checked {checked} filter-manager callback declarations against fltKernel.h");
}

/// Reads every source file that declares a kernel API by hand and compares each
/// declaration with its `wdm.h` prototype.
///
/// # Why the parameter list is the thing being checked
///
/// A Rust declaration of a foreign function is a promise about an ABI, and a
/// wrong promise is not a compile error -- it is a call that hands the callee
/// arguments it did not ask for. `KeQueryInterruptTimePrecise` was declared with
/// no parameters where `wdm.h` gives it one out-parameter, so the kernel stored
/// eight bytes through whatever `rcx` happened to hold. On the process-creation
/// path `rcx` held the sequence counter the previous instruction had just
/// fetched, and the first process created after the driver loaded bugchecked the
/// machine with `0x3B` inside `ntoskrnl`.
///
/// What had been taken as proof the declaration was right was that the *name*
/// resolves in `ntoskrnl.lib` -- which it does, and which says nothing about the
/// parameter list. A parameter list is answerable by the header and not by the
/// compiler, so it is answered here, at build time, from the header.
///
/// # What it cannot catch
///
/// It compares arity and which parameters carry an address, not types. A
/// declaration that swapped `PULONG64` for `PVOID` would pass. That is the limit
/// of what a header can be asked without writing a C parser, and it covers the
/// failure that happened: an argument that was not written down at all.
fn check_import_declarations() {
    for import in IMPORTS {
        println!("cargo:rerun-if-changed={}", import.source);
    }
    println!("cargo:rerun-if-changed=build.rs");

    for entry in UNPROTOTYPED {
        assert!(
            !entry.reason.trim().is_empty(),
            "build.rs: {} is listed as having no header prototype and no reason is given. The \
             reason is what makes an exclusion reviewable instead of a place to put something \
             that failed the check.",
            entry.name
        );
    }

    let mut sources: BTreeMap<&str, String> = BTreeMap::new();
    let mut headers: BTreeMap<&str, (PathBuf, String)> = BTreeMap::new();
    let mut complaints: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for import in IMPORTS {
        let source = sources
            .entry(import.source)
            .or_insert_with(|| read_source(import.source));
        let (header_path, header) = headers
            .entry(import.header)
            .or_insert_with(|| read_km_header(import.header));
        let prototype = import.prototype.unwrap_or(import.name);

        let Some(ours) = rust_foreign_params(source, import.name) else {
            complaints.push(format!(
                "  {} -- no `fn {}(` in {}",
                import.name, import.name, import.source
            ));
            continue;
        };
        let Some(theirs) = header_function_params(header, prototype) else {
            complaints.push(format!(
                "  {} -- no line-initial `{} (` in {}\n    \
                 has it been renamed, or does it now live in another header?",
                import.name, prototype, import.header
            ));
            continue;
        };

        let theirs = normalised_c_parameters(&theirs);
        let mine = shape_of_rust(&ours, &rust_type_aliases(source));
        let real = shape_of_header(&theirs);
        checked += 1;
        if mine != real {
            complaints.push(format!(
                "  {} -- declared in {}, prototype `{}` in {}\n    \
                 declared: {} parameter(s), {} a pointer  ({})\n    \
                 header:   {} parameter(s), {} a pointer  ({})",
                import.name,
                import.source,
                prototype,
                header_path.display(),
                mine.arity,
                mine.pointers,
                ours.join(", "),
                real.arity,
                real.pointers,
                theirs.join(", "),
            ));
        }
    }

    if !complaints.is_empty() {
        panic!(
            "the hand-written kernel API declarations do not match the WDK headers:\n{}\n\n\
             Fix the declaration to match the header, not the other way round -- the \
             header is what the kernel was compiled against, and a parameter the caller \
             does not pass is not a compile error, it is the callee writing through a \
             register that held something else. The prototype is quoted above, with the \
             file it was read from.",
            complaints.join("\n")
        );
    }

    // Printed, not silent, and split into what was checked and what could not be.
    // A single "checked 22" would be read as "all of them".
    println!(
        "cargo:warning=checked {checked} hand-written kernel API declarations against the WDK \
         headers; {} {} no header to check against -- {}",
        UNPROTOTYPED.len(),
        if UNPROTOTYPED.len() == 1 { "has" } else { "have" },
        UNPROTOTYPED
            .iter()
            .map(|entry| format!("{} in {}", entry.name, entry.source))
            .collect::<Vec<_>>()
            .join(", "),
    );
}

/// The parameter list of a `fn Name( ... )` declaration in one of our sources.
///
/// The needle includes the `(`, so `KeQueryInterruptTimePrecise` cannot be found
/// by looking for `KeQueryInterruptTime`. A declaration inside an `extern` block
/// has no `pub` and no return type before the name, so `fn {name}(` is the whole
/// of it.
fn rust_foreign_params(source: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("fn {name}(");
    let at = source.find(&needle)?;
    Some(split_parameters(&balanced_after(source, at + needle.len() - 1)?))
}

/// The parameter list of a function prototype in `wdm.h`.
///
/// Not simply the first occurrence of the name. The same header defines
/// `KeQueryInterruptTime()` as a macro over `KUSER_SHARED_DATA`, and mentions
/// `KeGetCurrentIrql()` inside inline helpers, where what follows the name is a
/// call rather than a declaration. Every prototype in this header, though, is
/// written with the name beginning a line of its own, so taking the first
/// occurrence that does picks the declaration out of the macro bodies.
///
/// `KeGetCurrentIrql` is declared five times, once per arch and per linkage
/// guard; they agree, and the first is the one the x64 `km` build uses.
fn header_function_params(header: &str, name: &str) -> Option<Vec<String>> {
    let mut from = 0usize;
    while let Some(found) = whole_word(&header[from..], name) {
        let at = from + found;
        if starts_a_logical_line(header, at) {
            return Some(split_parameters(&balanced_after(header, at + name.len())?));
        }
        from = at + name.len();
    }
    None
}

/// Whether only whitespace separates `at` from the start of its *logical* line.
///
/// Logical, not physical, and the difference is the whole of this function.
/// `wdm.h` writes its forwarding macros as
///
/// ```text
/// #define ObDereferenceObject(a)                                     \
///         ObfDereferenceObject(a)
/// ```
///
/// so the macro body begins a physical line of its own and a physical-line test
/// accepts it. That is the wrong reading, and it was made: the macro's `(a)` was
/// compared against a declaration that is correct. Walking back over the
/// backslash continuations to the `#define` is what tells a body apart from a
/// prototype.
fn starts_a_logical_line(text: &str, at: usize) -> bool {
    let mut end = at;
    loop {
        let before = &text[..end];
        let Some(newline) = before.rfind('\n') else {
            return before.trim().is_empty();
        };
        if !before[..newline].trim_end().ends_with('\\') {
            return text[newline + 1..at].trim().is_empty();
        }
        end = newline;
    }
}

/// A C parameter list with the one spelling that is not a parameter removed.
///
/// `KeGetCurrentIrql(VOID)` takes no arguments; C writes that as a parameter list
/// holding the single word `VOID`. Left alone, every zero-argument prototype in
/// the header would look like it takes one argument, and the check would fail on
/// declarations that are right.
fn normalised_c_parameters(params: &[String]) -> Vec<String> {
    if params.len() == 1 && params[0].trim() == "VOID" {
        return Vec::new();
    }
    params.to_vec()
}

/// The text between the first `(` at or after `from` and the `)` that closes it.
fn balanced_after(text: &str, from: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let start = i + 1;
    let mut depth = 1i32;
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split a parameter list on the commas that are not inside brackets.
///
/// The nesting is not decoration: `fltKernel.h` writes SAL annotations as
/// macros that take arguments, and
/// `_Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength)`
/// contains a comma inside its own parentheses. A plain `split(',')` finds six
/// parameters in a five-parameter typedef.
fn split_parameters(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in body.chars() {
        match ch {
            '(' | '[' | '<' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    out.push(current);
    out.into_iter()
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

/// The parameter list of a `pub type Name = ... fn( ... ) -> ...;` in `src/flt.rs`.
fn rust_callback_params(source: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("pub type {name} ");
    let at = source.find(&needle)?;
    Some(split_parameters(&balanced_after(source, at + needle.len())?))
}

/// The parameter list of a `(FLTAPI *NAME) ( ... )` typedef in `fltKernel.h`.
fn header_typedef_params(header: &str, name: &str) -> Option<Vec<String>> {
    let needle = format!("*{name})");
    let at = header.find(&needle)?;
    Some(split_parameters(&balanced_after(header, at + needle.len())?))
}

/// Every `pub type NAME = TEXT;` in the crate's source, so that a parameter
/// written as `FltPort` can be seen to be a pointer.
fn rust_type_aliases(source: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut rest = source;
    while let Some(at) = rest.find("pub type ") {
        let tail = &rest[at + "pub type ".len()..];
        let (Some(equals), Some(semi)) = (tail.find(" = "), tail.find(';')) else {
            break;
        };
        if equals > semi {
            break;
        }
        found.insert(tail[..equals].trim().to_string(), tail[equals + 3..semi].trim().to_string());
        rest = &tail[semi..];
    }
    found
}

/// `Shape` for one of our declarations.
///
/// A parameter's value is an address when its type mentions `*` after the
/// crate's own aliases have been substituted in: `*mut c_void` is obvious,
/// `FltPort` is not, and `FltPort` is exactly how the two that matter are
/// spelled.
fn shape_of_rust(params: &[String], own_types: &BTreeMap<String, String>) -> Shape {
    let mut pointers = 0;
    for param in params {
        let type_text = param.split_once(':').map(|(_, ty)| ty.trim()).unwrap_or(param.as_str());
        let mut expanded = type_text.to_string();
        // Four passes, because an alias can name another: `FltPort` is
        // `*mut c_void` in one, and a chain longer than four would be a
        // deliberate puzzle rather than a declaration.
        for _ in 0..4 {
            let mut substituted = false;
            for (name, target) in own_types {
                if let Some(at) = whole_word(&expanded, name) {
                    expanded
                        .replace_range(at..at + name.len(), target);
                    substituted = true;
                }
            }
            if !substituted {
                break;
            }
        }
        if expanded.contains('*') {
            pointers += 1;
        }
    }
    Shape { arity: params.len(), pointers }
}

/// `Shape` for a header typedef.
fn shape_of_header(params: &[String]) -> Shape {
    Shape {
        arity: params.len(),
        pointers: params.iter().filter(|param| carries_a_pointer(param)).count(),
    }
}

/// Whether a C parameter's *value* is an address.
///
/// Two ways to be one. A `*` anywhere in the declaration is the obvious one. The
/// other is a type that is itself a pointer typedef: `PVOID`, `PFLT_PORT`,
/// `PCFLT_RELATED_OBJECTS`, `PULONG` -- the WDK spells those with a leading `P`,
/// and no by-value type in this API does. The scalars here are `ULONG`,
/// `FLT_*_FLAGS`, `DEVICE_TYPE`, `FLT_FILESYSTEM_TYPE` and `FLT_CONTEXT_TYPE`.
/// Every SAL annotation in the header is `_`-prefixed, so trimming a leading
/// `_` before the test keeps them out of the way.
fn carries_a_pointer(param: &str) -> bool {
    if param.contains('*') {
        return true;
    }
    param
        .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .map(|word| word.trim_start_matches(['*', '_']))
        .any(|word| {
            if NOT_POINTERS.contains(&word) {
                return false;
            }
            let mut chars = word.chars();
            matches!(chars.next(), Some('P'))
                && chars.next().is_some_and(|c| c.is_ascii_uppercase())
        })
}

/// Types that begin `P` and a capital and are nevertheless not addresses.
///
/// The `P` test above is a heuristic, and this is the list of places the WDK
/// proves it wrong. `POOL_FLAGS` is `typedef ULONG64 POOL_FLAGS;` at `wdm.h`
/// 18173 -- a bitmask -- so reading it as a pointer makes the check disagree with
/// a declaration that is right, and a build gate that fails on correct code is a
/// build gate someone deletes.
///
/// Every entry has to quote the typedef it comes from. An entry without one is
/// how this list would turn into a way of silencing a real mismatch, and the
/// quoting is what makes that visible on the page rather than in a review.
const NOT_POINTERS: &[&str] = &["POOL_FLAGS"];

/// Where the first occurrence of `name` is, if it is a whole identifier there.
fn whole_word(text: &str, name: &str) -> Option<usize> {
    let (bytes, needle) = (text.as_bytes(), name.as_bytes());
    if needle.is_empty() || needle.len() > bytes.len() {
        return None;
    }
    let identifier = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (0..=bytes.len() - needle.len()).find(|&i| {
        &bytes[i..i + needle.len()] == needle
            && (i == 0 || !identifier(bytes[i - 1]))
            && (i + needle.len() == bytes.len() || !identifier(bytes[i + needle.len()]))
    })
}

/// `fltKernel.h`, from the newest WDK that has one.
fn read_flt_kernel_h() -> String {
    let path = header_path_for("fltKernel.h").unwrap_or_else(|| {
        panic!(
            "build.rs cannot find the WDK's km\\fltKernel.h, so it cannot check the \
             hand-written filter-manager callback types in src/flt.rs against the header \
             they transcribe.\n\
             Looked under {}.\n\
             Set WDKContentRoot to the Windows Kits 10 root to point it there.\n\
             This is a hard failure rather than a skip on purpose: a check that quietly \
             does not run is how three wrong declarations came to ship.",
            searched_roots()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    println!("cargo:rerun-if-changed={}", path.display());
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("build.rs: cannot read {}: {e}", path.display()))
}

/// A WDK header under the newest version's `km` directory, and the path it came
/// from.
///
/// The path comes back out because the failure message has to name the file it
/// read: a header that moved between WDK versions is the first thing to suspect
/// when a declaration that used to match stops matching.
fn read_km_header(file: &str) -> (PathBuf, String) {
    let path = header_path_for(file).unwrap_or_else(|| {
        panic!(
            "build.rs cannot find the WDK's km\\{file}, so it cannot check the hand-written \
             kernel API declarations that header prototypes.\n\
             Looked under {}.\n\
             Set WDKContentRoot to the Windows Kits 10 root to point it there.\n\
             This is a hard failure rather than a skip on purpose: a check that quietly \
             does not run is how a parameter came to be left off a declaration, and how a \
             machine came to bugcheck on every boot.",
            searched_roots()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {e}", path.display()));
    (path, text)
}

/// A source file of ours that declares a foreign function.
fn read_source(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("build.rs: cannot read {path}: {e}"))
}

/// The `Include` roots this check looks in, in order.
fn searched_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["WDKContentRoot", "WDK_DIR"] {
        if let Ok(value) = std::env::var(var) {
            let base = PathBuf::from(value);
            roots.push(base.join("Include"));
            roots.push(base);
        }
    }
    roots.push(PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Include"));
    roots.push(PathBuf::from(r"C:\Program Files\Windows Kits\10\Include"));
    roots
}

/// A header under the `km` directory of the newest WDK that has it.
fn header_path_for(file: &str) -> Option<PathBuf> {
    for root in searched_roots() {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.join("km").join(file).is_file())
            .collect();
        // Newest wins, compared as numbers: the string order would put
        // `10.0.9999.0` below `10.0.26100.0`.
        versions.sort_by_key(|path| version_key(path));
        if let Some(newest) = versions.pop() {
            return Some(newest.join("km").join(file));
        }
    }
    None
}

fn version_key(path: &Path) -> Vec<u32> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.split('.').filter_map(|part| part.parse().ok()).collect())
        .unwrap_or_default()
}
