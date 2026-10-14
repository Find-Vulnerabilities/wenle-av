//! Names the module behind a Windows bugcheck.
//!
//! Reads a kernel minidump (`C:\Windows\Minidump\*.dmp`) and reports which
//! loaded module contains the faulting instruction, and at what offset inside
//! it. That is the line `!analyze -v` gives you that matters most --
//! `MODULE_NAME` -- without the Debugging Tools installed.
//!
//! Usage:  dumpwho [--code 0x<bugcheck>] [--at 0x<address>] [--drivers <substr>]
//!                 [--frame <words>] <dump.dmp> [...]
//!         dumpwho --scan <hex> [--scan <hex> ...] [--around <bytes>] <file> [...]
//!         dumpwho --hexdump 0x<offset> [--hexdump ...] [--len <bytes>] <file> [...]
//!
//! Build:  rustc --edition 2021 -O -C target-feature=+crt-static -o dumpwho.exe tools/dumpwho.rs
//! Test:   rustc --edition 2021 --test -O -C target-feature=+crt-static -o dumpwho_test.exe tools/dumpwho.rs && ./dumpwho_test.exe
//!
//! `--edition 2021` is part of the build, not a preference: this file uses
//! `try_into` on a slice and `into_iter` on an array, both of which rustc's
//! default edition 2015 rejects. Without the flag the build fails with five
//! errors in code that is fine, and the obvious reading of that is "my edit
//! broke it".
//!
//! `+crt-static` is not optional: without it the binary imports
//! `VCRUNTIME140.dll`, which a bare VM does not have, and it will not start.
//!
//! **Two layouts, and the difference is the whole reason this took six crashes
//! to get right.** A *user-mode* minidump is `MINIDUMP_HEADER` +
//! `MINIDUMP_DIRECTORY` + streams (module list = stream type 4, exception =
//! type 6); there, every RVA is measured from the `MINIDUMP_HEADER`, which is
//! not necessarily at offset 0. A *kernel* minidump -- what `C:\Windows\Minidump`
//! actually holds -- is not that: it is `DUMP_HEADER64` (0x2000 bytes) followed
//! by a `TRIAGE_DUMP64` directory, with the loaded-driver list in the directory
//! and no `MINIDUMP_HEADER` anywhere. Both are handled; see [`load`].
//!
//! The bugcheck code and the faulting address are not reliably in the file, so
//! Event 1001 supplies them:
//!
//! ```text
//! wevtutil qe System /q:"*[System[(EventID=1001)]]" /c:8 /rd:true /f:text
//! ```
//!
//! Pass `--code` and the dump's own header is checked against it, which is what
//! validates the `DUMP_HEADER64` offsets; pass `--at` for the faulting
//! instruction (parameter 2 for `0x3B`/`0x7E`, parameter 3 for `0x50`).
//!
//! The addresses in a kernel dump are KASLR'd, so the same fault shows a
//! different address on every boot. Only the module plus the offset inside it
//! is stable, which is exactly what this prints.
//!
//! `--scan` is the other half of that: it answers questions the module list
//! cannot, by searching the dump's own bytes for a pattern taken from a file on
//! disk. A full kernel dump contains the *loaded code pages*, so searching it
//! for a function's exact bytes distinguishes "the image running on this machine
//! is this file" from "the image running is something else" -- without any VA
//! translation, because the bytes of a function and its rip-relative
//! displacements are identical in the file and in memory. RIP-relative
//! operands are the reason this works at all: their displacement is fixed at
//! link time, so a pattern cut out of the file is a valid search pattern.
//!
//! `--hexdump` prints the bytes at an absolute file offset, which is the other
//! half of that question: a hit says *where* to look, and only the bytes say
//! *what is there*. It exists because of a rule I got wrong and then measured.
//! A hit's residue follows the file's own offsets only when the section's raw
//! offset is congruent to its virtual address -- `.text` with `Raw == VA` (so
//! file offset == RVA) makes the two agree, while a section laid out as `VA
//! 0x1000 Raw 0x400` does not: there the *image* page holding file offset F sits
//! at a dump offset ≡ F + 0xC00 (mod 0x1000), so a hit whose residue disagrees
//! with F is still a real hit of that image. Both readings were observed, and
//! the arithmetic that separates them is:
//!
//! ```text
//! image hit:  dump offset ≡ RVA (mod 0x1000),  RVA = file offset + (VA - Raw)
//! cache hit:  dump offset ≡ file offset (mod 0x1000)
//! ```
//!
//! Reading the bytes is how that gets settled without trusting either rule.

use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::panic;
use std::process::ExitCode;

const MODULE_LIST_STREAM: u32 = 4;
const EXCEPTION_STREAM: u32 = 6;

/// `sizeof(MINIDUMP_MODULE)`: 8 + 4 + 4 + 4 + 4 + 52 + 8 + 8 + 8 + 8.
const MODULE_ENTRY_SIZE: usize = 108;

/// `MDMP`, the `MINIDUMP_HEADER` signature.
const MDMP: u32 = 0x504D_444D;
/// `PAGE`, the first field of `DUMP_HEADER64` (`Signature`).
const PAGE: u32 = 0x4547_4150;
/// `DU64`, the second field of `DUMP_HEADER64` (`ValidDump`).
const DU64: u32 = 0x3436_5544;

/// How far in to look for the `MINIDUMP_HEADER`.
///
/// The reason this is not simply 0: a kernel dump is a *triage* dump, and a
/// triage dump can carry a `DUMP_HEADER64` ahead of the minidump streams. Which
/// of the two a `C:\Windows\Minidump\*.dmp` actually begins with is exactly the
/// kind of detail that has been guessed wrong four times in this project, so
/// this does not guess -- it looks for the signature and says where it found
/// it. If the file begins with `PAGE`/`DU64` at 0, `DUMP_HEADER64` is parsed
/// from there as well and its bugcheck code is printed.
const SCAN_LIMIT: usize = 0x40_000;

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Where the `MINIDUMP_HEADER` starts, if this file has one.
///
/// Checked at 0 first, then every 4 bytes up to [`SCAN_LIMIT`] -- every
/// structure in the file is 4-aligned, so nothing can be missed by stepping 4.
fn find_mdmp(b: &[u8]) -> Option<usize> {
    let limit = SCAN_LIMIT.min(b.len());
    let mut o = 0usize;
    while o + 4 <= limit {
        if u32_at(b, o) == MDMP {
            return Some(o);
        }
        o += 4;
    }
    None
}

/// A `MINIDUMP_STRING`: a byte count, then that many bytes of UTF-16.
fn read_string(b: &[u8], base: usize, rva: u32) -> String {
    let rva = base + rva as usize;
    if rva + 4 > b.len() {
        return "<out of range>".into();
    }
    let bytes = u32_at(b, rva) as usize;
    let start = rva + 4;
    if start + bytes > b.len() {
        return "<truncated>".into();
    }
    let units: Vec<u16> = b[start..start + bytes]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The fields of `DUMP_HEADER64` that say what happened.
struct KernelHeader {
    bugcheck: u32,
    parameters: [u64; 4],
}

/// Parse `DUMP_HEADER64`, if the file begins with one.
///
/// Offsets, from the struct's declaration order and the alignment the `ULONG64`
/// members force:
///
/// ```text
///   0x00 Signature       ULONG      'PAGE'
///   0x04 ValidDump       ULONG      'DU64'
///   0x08 MajorVersion    ULONG
///   0x0C MinorVersion    ULONG
///   0x10 DirectoryTableBase  ULONG64
///   0x18 PfnDataBase         ULONG64
///   0x20 PsLoadedModuleList  ULONG64
///   0x28 PsActiveProcessHead ULONG64
///   0x30 MachineImageType    ULONG
///   0x34 NumberProcessors    ULONG
///   0x38 BugCheckCode        ULONG
///   0x3C (padding, so the ULONG64 below is 8-aligned)
///   0x40 BugCheckParameter1  ULONG64
///   0x48 BugCheckParameter2  ULONG64
///   0x50 BugCheckParameter3  ULONG64
///   0x58 BugCheckParameter4  ULONG64
///   0x60 VersionUser[32]
/// ```
///
/// **Those offsets are a claim, and a wrong one would still print a
/// confident-looking number** -- which is the failure this project keeps
/// repeating. So the report cross-checks what this reads against the bugcheck
/// code from Event 1001 whenever one is supplied, and says so when they
/// disagree. A dump whose header says `0x3b` when Event 1001 says `0x3b` is
/// evidence the layout is right; a dump that says something else is evidence it
/// is wrong, and either way the answer is not taken on trust.
fn parse_kernel_header(b: &[u8]) -> Option<KernelHeader> {
    if b.len() < 0x60 || u32_at(b, 0) != PAGE || u32_at(b, 4) != DU64 {
        return None;
    }
    Some(KernelHeader {
        bugcheck: u32_at(b, 0x38),
        parameters: [
            u64_at(b, 0x40),
            u64_at(b, 0x48),
            u64_at(b, 0x50),
            u64_at(b, 0x58),
        ],
    })
}

/// An `EXCEPTION_RECORD64` found inside a `DUMP_HEADER64`.
///
/// ```text
///   0x00 ExceptionCode      ULONG
///   0x04 ExceptionFlags     ULONG
///   0x08 ExceptionRecord    ULONG64   chained record, 0 when there is none
///   0x10 ExceptionAddress   ULONG64   the faulting instruction
///   0x18 NumberParameters   ULONG
///   0x1C (padding)
///   0x20 ExceptionInformation[15]  ULONG64
/// ```
///
/// **This is the only thing in a triage dump that carries the faulting *data*
/// address.** A `0x3B` gives the faulting *instruction* in its second parameter
/// and nothing about what that instruction touched -- and `CrashDumpEnabled: 3`
/// means there is no memory in the file to recover it from either. For a fault
/// whose instruction dereferences a pointer, the data address is the whole
/// answer: it says whether the pointer was null, a small number, a user address,
/// or freed pool. `ExceptionInformation[0]` is 0 for a read, 1 for a write and 8
/// for an execute; `[1]` is the address.
/// `sizeof(EXCEPTION_RECORD64)`: 0x18 of header + 15 eight-byte entries + the
/// padding that makes it 8-aligned.
const EXCEPTION_RECORD_SIZE: usize = 0x98;

/// The registers out of an x64 `CONTEXT` -- the ones that matter for a fault
/// whose first instruction dereferences its first argument.
///
/// Offsets are the documented `CONTEXT` layout, and the reader **checks itself
/// against the dump** rather than trusting them: `SegCs` must be `0x10` (the
/// x64 kernel code selector), `EFlags` must have bit 1 set, and `Rip` is
/// compared against the bugcheck's instruction address. A wrong idea of the
/// layout fails those three and is reported as a failure, not as registers.
#[derive(Debug, Clone, PartialEq)]
struct FaultContext {
    at: usize,
    rip: u64,
    rsp: u64,
    rbp: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    seg_cs: u16,
    seg_ss: u16,
    eflags: u32,
}

impl FaultContext {
    /// The named registers, in the order a human reads a fault report.
    fn registers(&self) -> [(&'static str, u64); 16] {
        [
            ("Rax", self.rax),
            ("Rbx", self.rbx),
            ("Rcx", self.rcx),
            ("Rdx", self.rdx),
            ("Rsi", self.rsi),
            ("Rdi", self.rdi),
            ("Rbp", self.rbp),
            ("Rsp", self.rsp),
            ("R8", self.r8),
            ("R9", self.r9),
            ("R10", self.r10),
            ("R11", self.r11),
            ("R12", self.r12),
            ("R13", self.r13),
            ("R14", self.r14),
            ("R15", self.r15),
        ]
    }
}

/// A `CONTEXT` read out of the dump at `at`, checked for **layout only**:
/// `SegCs` must be the x64 kernel code selector and `EFlags` bit 1 must be set.
///
/// It makes no claim about *which* fault the context belongs to. That claim is
/// the separate `Rip` comparison in `fault_context_at`, and the two are kept
/// apart on purpose: a context that fails the `Rip` check is a **finding**, not
/// noise. Measured on the real dump, the context the triage directory names is
/// the *bugcheck's* -- and that can only be said if it can still be read.
///
/// Returns `Err` naming which check failed, so a layout that does not fit shows
/// up as a named failure instead of as plausible-looking register values.
fn context_at(b: &[u8], at: usize) -> Result<FaultContext, String> {
    const CONTEXT_SIZE: usize = 0x100;
    let fits = match at.checked_add(CONTEXT_SIZE) {
        Some(end) => end <= b.len(),
        None => false,
    };
    if !fits {
        return Err(format!(
            "ContextOffset says {at:#x}, which cannot hold a {CONTEXT_SIZE:#x} byte CONTEXT \
             inside a {} byte file",
            b.len()
        ));
    }
    let seg_cs = u16_at(b, at + 0x38);
    let eflags = u32_at(b, at + 0x44);
    let rip = u64_at(b, at + 0xf8);
    if seg_cs != 0x10 {
        return Err(format!(
            "the blob at {at:#x} has SegCs {seg_cs:#06x} where an x64 kernel context has 0x0010 \
             -- this is not a CONTEXT, or the field offsets in this tool do not fit this file"
        ));
    }
    if eflags & 0x2 == 0 {
        return Err(format!(
            "the blob at {at:#x} has EFlags {eflags:#010x} with bit 1 clear, which no real \
             context has -- the field offsets in this tool do not fit this file"
        ));
    }
    Ok(FaultContext {
        at,
        rip,
        rsp: u64_at(b, at + 0x98),
        rbp: u64_at(b, at + 0xa0),
        rax: u64_at(b, at + 0x78),
        rcx: u64_at(b, at + 0x80),
        rdx: u64_at(b, at + 0x88),
        rbx: u64_at(b, at + 0x90),
        rsi: u64_at(b, at + 0xa8),
        rdi: u64_at(b, at + 0xb0),
        r8: u64_at(b, at + 0xb8),
        r9: u64_at(b, at + 0xc0),
        r10: u64_at(b, at + 0xc8),
        r11: u64_at(b, at + 0xd0),
        r12: u64_at(b, at + 0xd8),
        r13: u64_at(b, at + 0xe0),
        r14: u64_at(b, at + 0xe8),
        r15: u64_at(b, at + 0xf0),
        seg_cs,
        seg_ss: u16_at(b, at + 0x42),
        eflags,
    })
}

/// The `CONTEXT` at `at`, accepted as **this fault's** only when its `Rip` is the
/// faulting instruction.
///
/// This is the claim the reader is not allowed to skip: without it, a context
/// belonging to a different thread or a different moment prints as the fault's
/// registers, and `Rcx` from it would be read as the bad pointer.
fn fault_context_at(b: &[u8], at: usize, instruction: u64) -> Result<FaultContext, String> {
    let c = context_at(b, at)?;
    if c.rip != instruction {
        return Err(format!(
            "the CONTEXT at {at:#x} has Rip {:#018x}, which is **not** the faulting \
             instruction {instruction:#018x} -- so this is a different thread's or a different \
             moment's context, and its registers are not the fault's registers",
            c.rip
        ));
    }
    Ok(c)
}

/// The file offset `TRIAGE_DUMP64`'s `ContextOffset` names.
fn pointed_context_offset(b: &[u8]) -> Result<usize, String> {
    if b.len() < TRIAGE_HDR + 0x40 {
        return Err("too small to hold a DUMP_HEADER64 plus a TRIAGE_DUMP64 directory".into());
    }
    let at = u32_at(b, TRIAGE_HDR + TRIAGE_CONTEXT_OFFSET) as usize;
    if at == 0 {
        return Err(format!(
            "TRIAGE_DUMP64+{TRIAGE_CONTEXT_OFFSET:#x} (ContextOffset) is 0 -- this dump kept no \
             context record"
        ));
    }
    Ok(at)
}

#[derive(Debug, Clone, PartialEq)]
struct ExceptionRecord {
    /// File offset it was found at. Printed, because **this offset is not from a
    /// header this project can read** -- Windows publishes no layout for it, so
    /// the offset is something the scan discovered rather than something the
    /// format promised, and a reader should be able to see which one it was.
    at: usize,
    code: u32,
    address: u64,
    number_parameters: u32,
    information: Vec<u64>,
}

/// Every `EXCEPTION_RECORD64`-shaped blob in a `DUMP_HEADER64` carrying `code`.
///
/// **The offset is scanned for, not hardcoded, and the acceptance test is
/// agreement with a value already known from Event 1001.** A record is taken
/// only if its `ExceptionCode` is the exception code the bugcheck reported and
/// its parameter count is one the 15-entry array can hold; the caller then
/// checks `ExceptionAddress` against the bugcheck's own instruction address. A
/// wrong idea of the layout therefore finds *nothing*, rather than finding
/// something plausible and printing it as a fact -- which is the failure mode
/// this project has already paid for twice.
fn find_exception_records(b: &[u8], code: u32) -> Vec<ExceptionRecord> {
    // The triage directory starts at 0x2000, so the header -- and with it any
    // exception record the writer put there -- ends where that begins.
    let end = b.len().min(0x2000);
    let mut out = Vec::new();
    // Step 4, not 8. `ExceptionCode` is a `ULONG`, so a record starts on a
    // 4-byte boundary -- but the *file offset* it lands on is whatever the
    // writer put before it, and is under no obligation to be 8-aligned. An
    // 8-byte scan can therefore walk past a record that is really there and
    // report "none", which is this tool's oldest failure mode. The tests caught
    // exactly that: a fixture record at 0x344 (4-aligned, not 8) was invisible.
    let mut at = 0x60;
    while at + EXCEPTION_RECORD_SIZE <= end {
        if let Some(r) = exception_record_at(b, at, code) {
            out.push(r);
        }
        at += 4;
    }
    out
}

/// The blob at absolute file offset `at`, read as an `EXCEPTION_RECORD64` for
/// `code` -- or `None` if it is not one.
///
/// **One definition of "is this a record", used by both readers**, so that a
/// record found by the directory's pointer and one found by the scan are
/// accepted on exactly the same terms.
fn exception_record_at(b: &[u8], at: usize, code: u32) -> Option<ExceptionRecord> {
    if at.checked_add(EXCEPTION_RECORD_SIZE)? > b.len() {
        return None;
    }
    if u32_at(b, at) != code {
        return None;
    }
    // `ExceptionInformation` holds 15 entries. A count past that cannot be a
    // record, whatever else matches.
    let number = u32_at(b, at + 0x18);
    if number as usize > 15 {
        return None;
    }
    let mut information = Vec::new();
    for i in 0..number as usize {
        information.push(u64_at(b, at + 0x20 + i * 8));
    }
    Some(ExceptionRecord {
        at,
        code,
        address: u64_at(b, at + 0x10),
        number_parameters: number,
        information,
    })
}

/// The `EXCEPTION_RECORD64` that the triage directory **points at**, and the
/// offset it pointed at.
///
/// The scan above looks for a record inside the 0x2000-byte header, which is
/// where a record would be if the writer copied one in. On this VM's dumps it is
/// not there -- and the directory says so: `ExceptionOffset` names a file offset
/// elsewhere in the dump. Checking the pointer first is therefore both the
/// documented route and, on a real file, the one that finds anything.
///
/// Returns `Err` with the reason when the pointer is unusable, so that a
/// failure here is one of "the field said 0", "it points past the end" or "what
/// it points at is not a record for this code" -- three different findings that
/// must not be printed as one "none".
fn pointed_exception_record(b: &[u8], code: u32) -> Result<(usize, ExceptionRecord), String> {
    if b.len() < TRIAGE_HDR + 0x40 {
        return Err("too small to hold a DUMP_HEADER64 plus a TRIAGE_DUMP64 directory".into());
    }
    let at = u32_at(b, TRIAGE_HDR + TRIAGE_EXCEPTION_OFFSET) as usize;
    if at == 0 {
        return Err(format!(
            "TRIAGE_DUMP64+{TRIAGE_EXCEPTION_OFFSET:#x} (ExceptionOffset) is 0 -- this dump has \
             no exception record to point at"
        ));
    }
    if at + EXCEPTION_RECORD_SIZE > b.len() {
        return Err(format!(
            "ExceptionOffset says {at:#x}, which cannot hold a {EXCEPTION_RECORD_SIZE:#x} byte \
             record inside a {} byte file",
            b.len()
        ));
    }
    match exception_record_at(b, at, code) {
        Some(r) => Ok((at, r)),
        None => Err(format!(
            "ExceptionOffset says {at:#x}; the blob there has ExceptionCode {:#010x} and \
             NumberParameters {}, which is not a record for code {code:#010x} -- so the field \
             or the layout is wrong, and this dump does not identify its exception record here",
            u32_at(b, at),
            u32_at(b, at + 0x18)
        )),
    }
}

/// The raw kernel stack at the fault, validated, as 8-byte words.
///
/// This is **not** a frame list and is not presented as one: a triage dump
/// writes a window of raw stack bytes, so the words in it are return addresses
/// mixed with locals and saved registers. What it is good for is the one
/// question this project cannot otherwise answer -- *who called the faulting
/// function* -- because the caller's return address is in there. Every word that
/// resolves into a module is printed, and each is labelled a candidate.
fn call_stack(b: &[u8]) -> Result<Vec<u64>, String> {
    if b.len() < TRIAGE_HDR + 0x40 {
        return Err("no TRIAGE_DUMP64 directory in this file".into());
    }
    let at = u32_at(b, TRIAGE_HDR + TRIAGE_CALL_STACK_OFFSET) as usize;
    let size = u32_at(b, TRIAGE_HDR + TRIAGE_CALL_STACK_SIZE) as usize;
    if at == 0 || size == 0 {
        return Err(format!(
            "CallStackOffset {at:#x} / SizeOfCallStack {size:#x} -- this dump kept no call stack"
        ));
    }
    if size % 8 != 0 {
        return Err(format!(
            "SizeOfCallStack {size:#x} is not a multiple of 8, so the field offsets in this \
             tool do not fit this file"
        ));
    }
    if at + size > b.len() {
        return Err(format!(
            "the call stack at {at:#x}+{size:#x} runs past the end of a {} byte file",
            b.len()
        ));
    }
    Ok((0..size / 8).map(|i| u64_at(b, at + i * 8)).collect())
}

/// Where the raw stack window is: the **virtual address** it starts at, its file
/// offset, and its length in bytes.
///
/// The virtual address matters as much as the offset. The question a context in
/// there answers -- *what was `Rsp`, and what return address did the fault push
/// onto it?* -- is a question about addresses, and without `TopOfStack` a hit
/// could not be turned back into one.
fn stack_window(b: &[u8]) -> Option<(u64, usize, usize)> {
    if b.len() < TRIAGE_HDR + 0x50 {
        return None;
    }
    let at = u32_at(b, TRIAGE_HDR + TRIAGE_CALL_STACK_OFFSET) as usize;
    let size = u32_at(b, TRIAGE_HDR + TRIAGE_CALL_STACK_SIZE) as usize;
    let top = u64_at(b, TRIAGE_HDR + TRIAGE_TOP_OF_STACK);
    if at == 0 || size == 0 || top == 0 || at + size > b.len() {
        return None;
    }
    Some((top, at, size))
}

/// `va` as a file offset, when it falls inside the stack window.
fn window_offset(top: u64, at: usize, size: usize, va: u64) -> Option<usize> {
    if va < top || va >= top + size as u64 {
        return None;
    }
    Some(at + (va - top) as usize)
}

/// The raw stack words around a fault context's `Rsp`, each annotated with the
/// registers of *that same fault* which hold the very same value.
///
/// **Why this exists.** A fault at a function's first instruction pushes the
/// caller's return address, so the word at `Rsp` should name the caller -- and on
/// the real dump it does not: it reads `FLTMGR.SYS +0x1776d`, where the `call` in
/// the only function that can reach the faulting one returns to `0x17768`, five
/// bytes earlier. `0x1776d` is an instruction boundary (`add rsp,0x28`) but the
/// return address of *no call at all*: every instruction length that could end
/// there was enumerated against the file's bytes, and none of them is a call.
/// So the word is not a return address, and the question becomes *whether the
/// context's `Rsp` is the fault-time `Rsp` at all* -- a question a `KTRAP_FRAME`
/// in this window would answer, because the kernel writes the fault's registers
/// into one at the fault and copies the context out of it afterwards.
///
/// The annotation is what makes that findable mechanically instead of by eye:
/// this fault's registers include values nothing else on a stack would hold, and
/// a copy of them appears as a run of equal-value words at a fixed stride. The
/// run is **printed, not interpreted** -- the tool does not know the trap frame's
/// field offsets, and guessing them is how this file has been wrong before.
fn frame_lines(
    d: &Dump,
    b: &[u8],
    top: u64,
    at: usize,
    size: usize,
    c: &FaultContext,
    half: usize,
) -> Vec<String> {
    if window_offset(top, at, size, c.rsp).is_none() {
        return vec![format!(
            "        the frame is not in this file: Rsp {:#018x} is outside the stack window",
            c.rsp
        )];
    }
    // `Rip` is chained in rather than added to `registers()`, which the context
    // report prints with its own trailing line. It matters here more than any
    // other register: a trap frame's `Rip` field is the faulting instruction, so
    // it is the anchor that says *where* in the frame a run of registers starts.
    let regs: Vec<(&str, u64)> = c
        .registers()
        .into_iter()
        .chain(std::iter::once(("Rip", c.rip)))
        .collect();
    let end = top + size as u64;
    let mut out = Vec::new();
    out.push(format!(
        "        --- the raw stack, {half} words either side of Rsp; a word the fault's own \
         registers also hold is named ---"
    ));
    let mut annotated = 0usize;
    let mut printed = 0usize;
    for k in -(half as isize)..=(half as isize) {
        // Each word is placed by its *virtual address*, and read at the offset
        // that address maps to. The bound is the window's own end, not the file's
        // -- a word past `TopOfStack + SizeOfCallStack` is not captured stack at
        // all, and printing the file's next bytes as though it were would invent
        // a frame out of whatever happens to follow.
        let va = if k < 0 {
            c.rsp.saturating_sub((-k) as u64 * 8)
        } else {
            c.rsp + (k as u64) * 8
        };
        if va < top || va.checked_add(8).is_none_or(|e| e > end) {
            continue;
        }
        let file_off = at + (va - top) as usize;
        if file_off + 8 > b.len() {
            continue;
        }
        printed += 1;
        let value = u64_at(b, file_off);
        let i = ((va - top) / 8) as usize;
        // A register whose value is zero is skipped: zero is everywhere on a
        // stack, so it identifies nothing and would annotate half the frame.
        let mut eq: Vec<&str> = regs
            .iter()
            .filter(|(_, v)| *v != 0 && *v == value)
            .map(|(n, _)| *n)
            .collect();
        eq.dedup();
        let where_ = match d.owner(value) {
            Some(m) => format!("   {} +{:#x}", m.name, value - m.base),
            None => String::new(),
        };
        let note = if eq.is_empty() {
            String::new()
        } else {
            annotated += 1;
            format!("   == {}", eq.join(" "))
        };
        let mark = if va == c.rsp {
            "   <- Rsp: the word the faulting call pushed"
        } else {
            ""
        };
        out.push(format!(
            "      [{i:4}] {va:#018x}  {value:#018x}{where_}{note}{mark}"
        ));
    }
    out.push(format!(
        "        ({annotated} of the {printed} words printed are values this fault's registers also \
         hold. A trap frame for this fault shows up as a run of those at a fixed stride; the field \
         offsets of one are not assumed here, only counted.)"
    ));
    out
}

/// The lines `--frame` produces for one context -- or the line explaining why it
/// produced none, because **a flag must never be silently ignored**: with no
/// stack window in the dump, "no frame was printed" and "the frame had nothing
/// in it" are different findings, and only one of them means the dump is short.
fn frame_section(
    d: &Dump,
    b: &[u8],
    window: Option<(u64, usize, usize)>,
    c: &FaultContext,
    frame: Option<usize>,
) -> Vec<String> {
    let Some(half) = frame else {
        return Vec::new();
    };
    match window {
        Some((top, at, size)) => frame_lines(d, b, top, at, size, c, half),
        None => vec![
            "        --frame was asked for, but this dump has no stack window at all \
             (CallStackOffset or SizeOfCallStack is empty), so there is no frame to print -- \
             that is the dump's shape, and not an empty frame."
                .to_string(),
        ],
    }
}

/// Every `CONTEXT` in the raw stack window whose `Rip` is the faulting
/// instruction -- the fault's own registers, when the dump kept them.
///
/// **The directory's `ContextOffset` is not this.** A fault is dispatched long
/// before the bugcheck is taken, and the context the triage directory names is
/// the one from the crash path, whose `Rip` is inside ntoskrnl. The exception
/// dispatcher's copy is further up the same stack, inside this window.
///
/// Acceptance is `fault_context_at`, the *same* function the directory's pointer
/// is put through, so neither route can accept a blob the other would refuse, and
/// a wrong idea of the layout finds nothing rather than something plausible.
///
/// The 8-byte step is **complete at that step** and the reason is not assumed:
/// `top` is the virtual address of file offset `at`, both are stack addresses, so
/// every context position in the window differs from `at` by a multiple of 8. (An
/// 8-byte step over a *file* offset is not complete in general -- an
/// `EXCEPTION_RECORD64` test in this file caught exactly that -- but here the
/// alignment is carried by `top` rather than assumed about the file.)
fn contexts_in_stack(
    b: &[u8],
    top: u64,
    at: usize,
    size: usize,
    instruction: u64,
) -> Vec<(u64, FaultContext)> {
    let mut found = Vec::new();
    let mut off = at;
    while off + 0x100 <= at + size {
        if let Ok(c) = fault_context_at(b, off, instruction) {
            found.push((top + (off - at) as u64, c));
        }
        off += 8;
    }
    found
}

/// What an `ExceptionInformation[0]` means for an access violation.
fn access_kind(information: &[u64]) -> &'static str {
    match information.first() {
        Some(0) => "read",
        Some(1) => "write",
        Some(8) => "execute (an instruction fetch)",
        Some(_) => "unrecognised -- not 0, 1 or 8",
        None => "not recorded",
    }
}

#[derive(Debug)]
struct Module {
    base: u64,
    size: u32,
    /// `TimeDateStamp` from the image's PE header, at `MINIDUMP_MODULE` + 16.
    /// This is what makes a dump name its own build: every build of our driver
    /// so far has a distinct stamp, so the module list says which one was
    /// loaded without trusting the file on disk.
    timestamp: u32,
    /// The entry point, as a **virtual address** -- `DRIVER_ENTRY64.EntryPoint`
    /// at 0x40. Minus `base` that is the entry point RVA, which is `0x1000` for
    /// every WDM build of this driver and `0x3540` for the KMDF one, so a dump
    /// checked against a file on disk validates this offset. Zero for a
    /// user-mode minidump, whose module list has no entry point field at all.
    entry: u64,
    name: String,
}

impl Module {
    fn end(&self) -> u64 {
        self.base + self.size as u64
    }

    /// The entry point as an RVA, when it is one. Empty for a minidump and for a
    /// nonsense value, so the printed line never shows `ep +0xffff...`.
    fn entry_rva(&self) -> String {
        if self.entry >= self.base && self.entry - self.base < self.size as u64 {
            format!("  ep +{:#x}", self.entry - self.base)
        } else {
            String::new()
        }
    }
}

/// Which build of our driver a `TimeDateStamp` belongs to.
///
/// Read out of each file with `dumpbin /headers` on 2026-09-27. `SizeOfImage` is
/// in the dump too but only separates KMDF (0x14000) from WDM (0x12000) -- all
/// four WDM builds share 0x12000, so the timestamp is the only field that tells
/// them apart.
fn build_name(timestamp: u32) -> &'static str {
    match timestamp {
        0x6AB8_7FBF => "WDM, IRQL fix, signed -- the build staged 2026-09-27 10:30",
        0x6AB7_5DBE => "WDM, IRQL fix, unsigned -- the build that crashed 2026-09-27 10:25",
        0x6AB7_579A => "WDM, before the IRQL fix -- crashed 2026-09-26 13:44",
        0x6AB7_511A => "WDM, earlier still -- crashed 2026-09-26 13:18",
        0x6AB1_B71D => "KMDF -- crashed 2026-09-26 12:07",
        _ => "an unrecognised build",
    }
}

/// Whether a module name is one of ours, rather than a Windows component or a
/// third party's. `build_name` means nothing for a module that is not ours, so
/// this is what stops it from being printed beside `ntoskrnl.exe`.
fn is_product(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("wenle") || lower.contains("av_driver") || lower.contains("av_amsi")
}

#[derive(Debug)]
struct Dump {
    base: usize,
    stream_count: usize,
    exception_code: Option<u32>,
    exception_address: Option<u64>,
    parameters: Vec<u64>,
    modules: Vec<Module>,
    /// Only a triage dump has a string pool, and only then is there anything to
    /// say about how the names were decoded.
    pool: Option<PoolReport>,
}

impl Dump {
    /// The module whose image contains `address`, if any.
    fn owner(&self, address: u64) -> Option<&Module> {
        // Scan the whole list rather than taking `rev().find(base <= address)`.
        // That shortcut returns the module **last in list order** with a base at
        // or below the address, not the nearest one below it, so it is only
        // correct while the list happens to be sorted by base -- which the
        // kernel's triage list is nowhere documented to be. On an unsorted list
        // it can land on a module that does not contain the address and then
        // report the module that *does* as absent. That is the same
        // silent-absence failure as the `no 'fltmgr' in the list` false alarm,
        // and it is worth the extra pass to not repeat it: when several modules
        // contain the address, the smallest wins, which is also the right answer
        // if two images ever overlap.
        self.modules
            .iter()
            .filter(|m| m.base <= address && address < m.end())
            .min_by_key(|m| m.size)
    }

    /// The module with the highest base at or below `address`, containing it or not.
    ///
    /// This is what "the nearest module below the address" means, and unlike
    /// [`Self::owner`] it is defined even when nothing contains the address.
    fn nearest_below(&self, address: u64) -> Option<&Module> {
        self.modules
            .iter()
            .filter(|m| m.base <= address)
            .max_by_key(|m| m.base)
    }

    /// Render "module +offset" or an explanation of why nothing owns it.
    fn describe(&self, address: u64) -> String {
        match self.owner(address) {
            Some(m) => format!("{} +{:#x}", m.name, address - m.base),
            None => {
                let beyond = self.nearest_below(address);
                match beyond {
                    // Past the end of the nearest module below it. For a
                    // minifilter this is where a call through a wild pointer
                    // lands, so the gap is the finding rather than a miss.
                    Some(m) => format!(
                        // The `+` matters: without it this reads as an address,
                        // and the number is a distance past the module's end.
                        "NOT IN ANY MODULE -- +{:#x} past the end of {} ({:#x} + {:#x})",
                        address - m.end(),
                        m.name,
                        m.base,
                        m.size
                    ),
                    None => "NOT IN ANY MODULE -- below every loaded module's base".into(),
                }
            }
        }
    }
}

fn parse(b: &[u8]) -> Result<Dump, String> {
    if b.len() < 32 {
        return Err("too small to be a minidump".into());
    }
    let base = find_mdmp(b).ok_or_else(|| {
        let head: Vec<String> = b[..b.len().min(8)].iter().map(|c| format!("{c:02X}")).collect();
        format!(
            "no 'MDMP' signature in the first {} bytes (first bytes: {}) -- \
             not a minidump, or a layout this does not cover",
            SCAN_LIMIT.min(b.len()),
            head.join(" ")
        )
    })?;

    let stream_count = u32_at(b, base + 8) as usize;
    let dir = base + u32_at(b, base + 12) as usize;

    let mut exception_code = None;
    let mut exception_address = None;
    let mut parameters = Vec::new();
    let mut modules = Vec::new();

    for i in 0..stream_count {
        let e = dir + i * 12;
        if e + 12 > b.len() {
            return Err(format!("stream directory entry {i} runs past the end"));
        }
        let kind = u32_at(b, e);
        let rva = base + u32_at(b, e + 8) as usize;
        match kind {
            EXCEPTION_STREAM => {
                // MINIDUMP_EXCEPTION begins 8 bytes into the stream:
                // code at +8, address at +24, count at +32, values at +40.
                if rva + 40 > b.len() {
                    continue;
                }
                exception_code = Some(u32_at(b, rva + 8));
                exception_address = Some(u64_at(b, rva + 24));
                // `NumberParameters` comes out of the file, and the array holds
                // 15 -- but the check above only covers the first 40 bytes, so
                // capping at 15 still read up to 120 bytes past the end on a
                // truncated dump. Bound it by the file as well as the array.
                let n = (u32_at(b, rva + 32) as usize).min(15);
                let n = n.min(b.len().saturating_sub(rva + 40) / 8);
                parameters.clear();
                for k in 0..n {
                    parameters.push(u64_at(b, rva + 40 + k * 8));
                }
            }
            MODULE_LIST_STREAM => {
                if rva + 4 > b.len() {
                    continue;
                }
                let count = u32_at(b, rva) as usize;
                for m in 0..count {
                    let o = rva + 4 + m * MODULE_ENTRY_SIZE;
                    if o + MODULE_ENTRY_SIZE > b.len() {
                        break;
                    }
                    modules.push(Module {
                        base: u64_at(b, o),
                        size: u32_at(b, o + 8),
                        timestamp: u32_at(b, o + 16),
                        // `MINIDUMP_MODULE` has no entry point field.
                        entry: 0,
                        name: read_string(b, base, u32_at(b, o + 20)),
                    });
                }
            }
            _ => {}
        }
    }

    modules.sort_by_key(|m| m.base);
    Ok(Dump {
        base,
        stream_count,
        exception_code,
        exception_address,
        parameters,
        modules,
        pool: None,
    })
}

// ---------------------------------------------------------------------------
// PAGEDU64 triage dumps -- what `C:\Windows\Minidump\*.dmp` actually is
// ---------------------------------------------------------------------------
//
// This is the part that was missing for six crashes. A *kernel* minidump is not
// a user-mode `MINIDUMP`: there is no `MINIDUMP_HEADER`, no stream directory and
// no `MINIDUMP_MODULE_LIST`. Windows writes `DUMP_HEADER64` (0x2000 bytes)
// followed by a `TRIAGE_DUMP64` directory, and the loaded-driver list lives in
// that directory. `parse` above reads the user-mode layout, so every one of the
// six dumps failed with "no 'MDMP' signature" -- which is the real reason no
// dump was ever read.
//
// The field offsets below are **not** from a header this project can read.
// Windows publishes no such header, and the two parsers consulted
// (`ntoseye`'s `triage.rs`, rizin's `bin_dmp64.c`) agree with each other but
// agreeing summaries are not evidence about a particular file. So nothing here
// is taken on trust: `check_driver_list` validates the result against things
// that are true of every Windows kernel, and `read_pool_string` has a fallback
// for the other reading of the string pool. A wrong offset has to show up as a
// named failure, not as a plausible wrong module.

/// `DUMP_HEADER64` is 0x2000 bytes; the `TRIAGE_DUMP64` directory follows it.
const TRIAGE_HDR: usize = 0x2000;

// Field offsets *within* `TRIAGE_DUMP64` -- i.e. relative to [`TRIAGE_HDR`].
// The **values** stored at them are absolute file offsets.
const TRIAGE_DRIVER_LIST_OFFSET: usize = 0x30;
const TRIAGE_DRIVER_COUNT: usize = 0x34;
const TRIAGE_STRING_POOL_OFFSET: usize = 0x38;
const TRIAGE_STRING_POOL_SIZE: usize = 0x3c;
/// Where the `EXCEPTION_RECORD64` is -- **a pointer to it, not the record.**
///
/// `TRIAGE_DUMP64` opens with a run of ULONGs: `ServicePackBuild` 0x00,
/// `SizeOfDump` 0x04, `ValidOffset` 0x08, `ContextOffset` 0x0c,
/// `ExceptionOffset` 0x10, `MmOffset` 0x14, `UnloadedDriversOffset` 0x18,
/// `PrcbOffset` 0x1c, `ProcessOffset` 0x20, `ThreadOffset` 0x24,
/// `CallStackOffset` 0x28, `SizeOfCallStack` 0x2c, `DriverListOffset` 0x30,
/// `DriverCount` 0x34, `StringPoolOffset` 0x38, `StringPoolSize` 0x3c.
///
/// The last four are already validated against a real dump -- 192 entries,
/// 192/192 bases 64 KB aligned, 192/192 sizes plausible -- and they land exactly
/// where this layout puts them, ending at 0x40 with `BrokenDriverOffset`. **That
/// is the evidence for the fields at 0x10 and 0x28**: the same run of ULONGs,
/// confirmed at its far end. It is not a header this project can read, so the
/// reads below still check what they find instead of trusting the offset.
const TRIAGE_EXCEPTION_OFFSET: usize = 0x10;
/// `ContextOffset` (0x0c), immediately before `ExceptionOffset` in the same run
/// of ULONGs -- and the field that matters most for this project's fault.
///
/// For bugcheck `0x3B`, `0x7E` and `0x1E` the **third** parameter is the address
/// of the `CONTEXT` record of the faulting thread, and a context holds every
/// register. On an access violation inside `IoGetRequestorProcess` the register
/// that answers the whole question is `Rcx`: the function's first instruction is
/// `test dword ptr [rcx+10h], 2000h`, so **`Rcx` is the bad `PIRP` itself**. Null,
/// a small integer, a user address or freed pool are four different bugs, and
/// this field is where the difference is written down.
const TRIAGE_CONTEXT_OFFSET: usize = 0x0c;
/// `TopOfStack` (0x48): the stack pointer the call-stack window was taken
/// around. Without it the window's word 0 cannot be placed in the stack, and
/// "the caller is not in the window" cannot be told from "the window starts in
/// the wrong place".
const TRIAGE_TOP_OF_STACK: usize = 0x48;
/// `CallStackOffset` (0x28) / `SizeOfCallStack` (0x2c): the raw kernel stack at
/// the fault. It is not a frame list, but the **return address of the caller of
/// the faulting function is in it**, which is the one thing that names who
/// supplied the bad argument.
const TRIAGE_CALL_STACK_OFFSET: usize = 0x28;
const TRIAGE_CALL_STACK_SIZE: usize = 0x2c;

/// `DRIVER_ENTRY64`: `NameOffset` u32, `reserved[52]`, `DllBase` u64,
/// `EntryPoint` u64, `SizeOfImage` u64, `reserved[56]`, `TimeDateStamp` u64.
/// 4 + 52 + 8 + 8 + 8 + 56 + 8 = 0x90, which is why the size is the check that
/// the field offsets are self-consistent.
const DRIVER_ENTRY_SIZE: usize = 0x90;
const ENTRY_NAME_OFFSET: usize = 0x00;
const ENTRY_DLL_BASE: usize = 0x38;
const ENTRY_ENTRY_POINT: usize = 0x40;
const ENTRY_SIZE_OF_IMAGE: usize = 0x48;
const ENTRY_TIMESTAMP: usize = 0x88;

/// Whether a decoded pool string could be a Windows driver name.
///
/// This is the switch between the two readings of the string pool, so it has to
/// accept real names and reject the bytes of one reading misread as the other.
/// A bare `ntoskrnl.exe` read as `u32 count` gives 0x746E = 29806 characters,
/// which the length bound rejects.
/// Could this be a name at all -- printable, and not absurdly long?
///
/// Weak on purpose, and it is the **only** test the count-prefixed reading has
/// to pass, because that reading is the documented one.
///
/// It was stricter than this once: it demanded `.sys`, `.exe` or a backslash,
/// **case-sensitively**. On the first real dump that rejected `FLTMGR.SYS` and
/// every `.dll` entry -- `hal.dll`, `kdcom.dll`, `mcupdate.dll`, `PSHED.dll`,
/// `BOOTVID.dll` are all really in the pool -- so 29 of 192 names fell through
/// to the NUL-terminated fallback, which read the length prefix's first byte as
/// the first character and returned a bare newline as a module name. The module
/// that faulted in two crashes printed with no name because of it.
fn is_plausible_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=260).contains(&n) && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Does this look like the kind of path the pool holds?
///
/// The strict test, kept for the two **fallback** readings only. Neither is
/// documented anywhere, so one of them winning has to be plausible on its own
/// terms; the documented reading does not, and applying this to it is what hid
/// 29 real names.
fn looks_like_a_driver_name(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    is_plausible_name(s) && (l.contains(".sys") || l.contains(".exe") || s.contains('\\'))
}

/// How a pool string was decoded.
///
/// Reported in aggregate, because a wrong guess about the pool that still yields
/// plausible names is exactly the kind of thing that goes unnoticed. If the mode
/// that dominates on a real dump is not the one the format is documented to use,
/// that is worth seeing.
#[derive(Debug, PartialEq, Clone, Copy)]
enum PoolMode {
    /// A `u32` character count, then that many UTF-16 code units.
    Counted,
    /// A `UNICODE_STRING`-shaped header: `u16` byte length, `u16` maximum.
    UnicodeString,
    /// A bare NUL-terminated UTF-16 string at the offset.
    NulTerminated,
    /// None of the readings produced something name-shaped.
    Undecodable,
}

impl PoolMode {
    fn label(self) -> &'static str {
        match self {
            PoolMode::Counted => "count-prefixed",
            PoolMode::UnicodeString => "UNICODE_STRING-shaped",
            PoolMode::NulTerminated => "NUL-terminated",
            PoolMode::Undecodable => "undecodable",
        }
    }
}

/// Decode `units` UTF-16 code units starting at a byte offset.
fn utf16_at(b: &[u8], at: usize, units: usize) -> String {
    let v: Vec<u16> = (0..units)
        .map(|i| u16::from_le_bytes([b[at + i * 2], b[at + i * 2 + 1]]))
        .collect();
    String::from_utf16_lossy(&v)
}

/// Read one driver name out of the string pool, trying every reading.
///
/// `at` is the file offset a `DRIVER_ENTRY64.NameOffset` gives. The format is
/// documented as a `u32` character count followed by that many UTF-16 code
/// units, but that came from elsewhere and the first real dump showed entries
/// whose name did not decode, so all three readings are tried and the winning
/// one is reported. A reading only wins by producing something name-shaped, so
/// the other two cannot quietly take over.
fn read_pool_string(b: &[u8], pool: (usize, usize), at: usize) -> (String, PoolMode) {
    let (start, size) = pool;
    let end = start.saturating_add(size).min(b.len());
    if at < start || at + 2 > end {
        return (
            format!("<NameOffset {at:#x} is outside the pool {start:#x}+{size:#x}>"),
            PoolMode::Undecodable,
        );
    }

    // 1. `u32` character count, then that many code units. This is the reading
    //    the real dumps confirm: every sampled `NameOffset` held a 4-byte count
    //    followed by exactly that many units, `0A 00 00 00` + `FLTMGR.SYS`
    //    among them.
    if at + 4 <= end {
        let units = u32_at(b, at) as usize;
        if (1..=260).contains(&units) && at + 4 + units * 2 <= end {
            let s = utf16_at(b, at + 4, units);
            if is_plausible_name(&s) {
                return (s, PoolMode::Counted);
            }
        }
    }

    // 2. A bare NUL-terminated string at the offset.
    //
    //    This can safely use the weak test, and the reason is specific: when the
    //    pool *is* count-prefixed, the first unit of this read is the low half of
    //    the count, and every count a real pool holds is a control character
    //    (`0x0A` for a ten-character name). `is_plausible_name` rejects control
    //    characters, so this reading cannot quietly take over from the real one.
    let nul = {
        let mut v = Vec::new();
        let mut o = at;
        while o + 2 <= end {
            let u = u16::from_le_bytes([b[o], b[o + 1]]);
            if u == 0 {
                break;
            }
            v.push(u);
            o += 2;
        }
        String::from_utf16_lossy(&v)
    };
    if is_plausible_name(&nul) {
        return (nul, PoolMode::NulTerminated);
    }

    // 3. Last resort: a `UNICODE_STRING`-shaped header, `u16` Length in bytes
    //    and `u16` MaximumLength, then the buffer.
    //
    //    Tried last on purpose. Its output does not have to begin at the offset
    //    with a printable unit, so it is the one reading that can turn arbitrary
    //    bytes into a plausible-looking name -- so it only gets a say where the
    //    other two produced nothing, and then its result has to look like a real
    //    driver path rather than merely being printable.
    if at + 4 <= end {
        let len = u16::from_le_bytes([b[at], b[at + 1]]) as usize;
        let max = u16::from_le_bytes([b[at + 2], b[at + 3]]) as usize;
        if len >= 4 && len % 2 == 0 && len <= max && at + 4 + len <= end {
            let s = utf16_at(b, at + 4, len / 2);
            if looks_like_a_driver_name(&s) {
                return (s, PoolMode::UnicodeString);
            }
        }
    }

    // Nothing worked. Do **not** hand back the junk read.
    //
    // That read can contain control characters, and a name with a newline in it
    // is precisely what put the `<-` marker on its own line and made the module
    // that faulted print nameless in the first real dump. Refusing to accept a
    // reading is only half the fix if the rejected bytes are still returned as
    // though they were a name; the other half is not returning them. The raw
    // bytes for this offset get printed in their own section, which is where a
    // human should be reading them anyway.
    (
        format!("<name did not decode, offset {at:#x}>"),
        PoolMode::Undecodable,
    )
}

/// What the string pool looked like, so a wrong guess is visible rather than
/// silent.
#[derive(Debug, Default, PartialEq)]
struct PoolReport {
    counted: usize,
    unicode_string: usize,
    nul_terminated: usize,
    /// `(entry index, NameOffset, 32 raw bytes)` for names that did not decode.
    undecodable: Vec<(usize, usize, String)>,
    pool: (usize, usize),
    min_offset: usize,
    max_offset: usize,
}

impl PoolReport {
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (mode, n) in [
            (PoolMode::Counted, self.counted),
            (PoolMode::UnicodeString, self.unicode_string),
            (PoolMode::NulTerminated, self.nul_terminated),
            (PoolMode::Undecodable, self.undecodable.len()),
        ] {
            if n > 0 {
                parts.push(format!("{n} {}", mode.label()));
            }
        }
        format!(
            "{}; NameOffsets {:#x}..{:#x} in a pool of {:#x}+{:#x}",
            parts.join(", "),
            self.min_offset,
            self.max_offset,
            self.pool.0,
            self.pool.1
        )
    }
}

/// Hex bytes, for showing what a pool entry actually contains.
fn hex(b: &[u8], at: usize, n: usize) -> String {
    let end = (at + n).min(b.len());
    if at >= end {
        return "<past the end>".into();
    }
    b[at..end]
        .iter()
        .map(|c| format!("{c:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}


/// The loaded-driver list out of a `PAGEDU64` triage dump, plus what the string
/// pool looked like on the way through.
fn parse_triage_drivers(b: &[u8]) -> Result<(Vec<Module>, PoolReport), String> {
    if b.len() < TRIAGE_HDR + 0x40 {
        return Err("too small to hold a DUMP_HEADER64 plus a TRIAGE_DUMP64 directory".into());
    }
    let list = u32_at(b, TRIAGE_HDR + TRIAGE_DRIVER_LIST_OFFSET) as usize;
    let count = u32_at(b, TRIAGE_HDR + TRIAGE_DRIVER_COUNT) as usize;
    let pool = u32_at(b, TRIAGE_HDR + TRIAGE_STRING_POOL_OFFSET) as usize;
    let pool_size = u32_at(b, TRIAGE_HDR + TRIAGE_STRING_POOL_SIZE) as usize;

    // A plausible count is the cheapest test that the field offsets are right:
    // a wrong offset lands in padding or in another field and gives a number
    // that is obviously not a number of drivers.
    if count == 0 || count > 4096 {
        return Err(format!(
            "the triage directory gives {count} drivers, which is not a plausible count -- \
             the TRIAGE_DUMP64 field offsets in this tool do not fit this file"
        ));
    }
    let end = list
        .checked_add(count * DRIVER_ENTRY_SIZE)
        .ok_or("the driver list offset overflows")?;
    if end > b.len() {
        return Err(format!(
            "the driver list at {list:#x} ({count} entries of {DRIVER_ENTRY_SIZE:#x}) runs past \
             the end of a {} byte file",
            b.len()
        ));
    }
    if pool + pool_size > b.len() {
        return Err(format!(
            "the string pool at {pool:#x}+{pool_size:#x} runs past the end of a {} byte file",
            b.len()
        ));
    }

    let mut modules = Vec::with_capacity(count);
    let mut pr = PoolReport {
        pool: (pool, pool_size),
        min_offset: usize::MAX,
        ..PoolReport::default()
    };
    for i in 0..count {
        let o = list + i * DRIVER_ENTRY_SIZE;
        let name_at = u32_at(b, o + ENTRY_NAME_OFFSET) as usize;
        let (name, mode) = read_pool_string(b, (pool, pool_size), name_at);
        match mode {
            PoolMode::Counted => pr.counted += 1,
            PoolMode::UnicodeString => pr.unicode_string += 1,
            PoolMode::NulTerminated => pr.nul_terminated += 1,
            PoolMode::Undecodable => pr
                .undecodable
                .push((i, name_at, hex(b, name_at, 32))),
        }
        pr.min_offset = pr.min_offset.min(name_at);
        pr.max_offset = pr.max_offset.max(name_at);
        modules.push(Module {
            base: u64_at(b, o + ENTRY_DLL_BASE),
            size: u32_at(b, o + ENTRY_SIZE_OF_IMAGE),
            timestamp: u32_at(b, o + ENTRY_TIMESTAMP),
            entry: u64_at(b, o + ENTRY_ENTRY_POINT),
            name,
        });
    }
    if pr.min_offset == usize::MAX {
        pr.min_offset = 0;
    }
    modules.sort_by_key(|m| m.base);
    Ok((modules, pr))
}

/// Check a parsed driver list against what is true of every Windows kernel.
///
/// Returns the lines to print. The offsets this parser uses came from elsewhere,
/// so "the list parsed" is not the claim -- "the list is a driver list" is, and
/// that is what this decides. A failure here is meant to be loud enough to stop
/// a wrong module being named.
fn check_driver_list(mods: &[Module], pool: &PoolReport) -> Vec<String> {
    let mut out = Vec::new();
    let has = |want: &str| mods.iter().any(|m| m.name.to_ascii_lowercase().contains(want));

    if mods.is_empty() {
        out.push("      ** the driver list is empty -- the layout is wrong **".into());
        return out;
    }
    // ntoskrnl is in every kernel; fltmgr is in every kernel that can load this
    // filter at all. Either missing means the entries are not driver entries --
    // unless names failed to decode, in which case a missing name proves nothing
    // about the entries and the two readings have to be kept apart.
    for (want, why) in [
        ("ntoskrnl", "every kernel has ntoskrnl"),
        ("fltmgr", "a minifilter cannot load without the filter manager"),
    ] {
        if !has(want) {
            if pool.undecodable.is_empty() {
                out.push(format!(
                    "      ** no '{want}' in the list, but {why} -- \
                     the TRIAGE_DUMP64 offsets in this tool do not fit this file **"
                ));
            } else {
                out.push(format!(
                    "      ** no '{want}' in the list, but {} of {} names did not decode, so this \
                     is not evidence about the entries: the name is missing, not the driver. \
                     The entry structure itself fits. **",
                    pool.undecodable.len(),
                    mods.len()
                ));
            }
        }
    }

    let aligned = mods.iter().filter(|m| m.base & 0xFFFF == 0).count();
    let sized = mods
        .iter()
        .filter(|m| m.size > 0 && m.size < 0x1000_0000)
        .count();
    out.push(format!(
        "      {} entries, {aligned}/{} bases 64 KB aligned, {sized}/{} sizes plausible",
        mods.len(),
        mods.len(),
        mods.len()
    ));
    if aligned * 4 < mods.len() || sized * 2 < mods.len() {
        out.push(
            "      ** too many entries are not shaped like loaded modules -- \
             do not trust the names below **"
                .into(),
        );
    }
    out
}

/// One line per driver in the triage list whose name contains `filter`
/// (case-insensitive; an empty filter matches every entry), plus a closing line
/// that says how many were searched.
///
/// **Why this exists.** The offsets a disassembler reads out of a file on disk are
/// the offsets of *that build*. A dump names the build it was running in
/// `DRIVER_ENTRY64.TimeDateStamp`, so when an address out of the stack window
/// resolves to `SOMEDRV.SYS +0x1776d` and `0x1776d` is not an instruction this
/// host's copy of that driver has, the first question is whether the two files are
/// the same build -- and the dump can answer that by itself, without another
/// round trip into the VM.
fn driver_lines(mods: &[Module], filter: &str) -> Vec<String> {
    let want = filter.to_ascii_lowercase();
    let hits: Vec<&Module> = mods
        .iter()
        .filter(|m| m.name.to_ascii_lowercase().contains(&want))
        .collect();

    let mut out = Vec::new();
    let what = if want.is_empty() {
        "every driver in the list".to_string()
    } else {
        format!("drivers matching {filter:?}")
    };
    out.push(format!("  --- {what}: {} of {} ---", hits.len(), mods.len()));
    if hits.is_empty() {
        // A checked absence, in the shape this project keeps having to relearn:
        // say what was searched, not just that nothing was found.
        //
        // But an *empty* list is not a checked absence -- nothing was searched,
        // so a "none" here would be the fifth occurrence of the same overreach.
        // The test below is what caught that: the first draft printed
        // "searched all 0 names ... so this is not a decode failure".
        if mods.is_empty() {
            out.push(
                "      ** the triage driver list is empty, so this says nothing about whether \
                 that driver was loaded -- the list is the problem, not the driver **"
                    .into(),
            );
        } else {
            out.push(format!(
                "      none -- searched all {} names in the triage list, so this is not a \
                 decode failure unless the name did not decode (see the pool line above)",
                mods.len()
            ));
        }
        return out;
    }
    for m in hits {
        // The build name only means something for our own images -- attached to
        // `ntoskrnl.exe` it would read as a claim about Windows.
        let build = if is_product(&m.name) {
            format!("   -- {}", build_name(m.timestamp))
        } else {
            String::new()
        };
        out.push(format!(
            "      {:#018x}  size {:#010x}  stamp {:#010x}{}  {}{build}",
            m.base,
            m.size,
            m.timestamp,
            m.entry_rva(),
            m.name
        ));
    }
    out
}

/// Which of the two dump layouts a file turned out to be.
#[derive(Debug, PartialEq)]
enum Source {
    MiniDump,
    Triage,
}

/// Get the module list out of a dump, whichever layout it is.
///
/// A `MINIDUMP_HEADER` anywhere wins, because that is the layout with streams.
/// Otherwise a `PAGEDU64` header means the triage layout, whose driver list is
/// in a directory at 0x2000 and whose exception record -- when the writer put
/// one in the header -- has no published offset and is found by scanning for a
/// record that agrees with the bugcheck parameters
/// ([`find_exception_records`]).
fn load(b: &[u8]) -> Result<(Dump, Source), String> {
    if find_mdmp(b).is_some() {
        return parse(b).map(|d| (d, Source::MiniDump));
    }
    if parse_kernel_header(b).is_some() {
        let (modules, pool) = parse_triage_drivers(b)?;
        return Ok((
            Dump {
                base: 0,
                stream_count: 0,
                exception_code: None,
                exception_address: None,
                parameters: Vec::new(),
                modules,
                pool: Some(pool),
            },
            Source::Triage,
        ));
    }
    Err("neither a MINIDUMP_HEADER nor a DUMP_HEADER64 -- not a dump this reads".into())
}

/// The exception codes a bugcheck of this shape can carry.
fn exception_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "STATUS_ACCESS_VIOLATION -- read or write to an address that is not mapped",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_0096 => "STATUS_PRIVILEGED_INSTRUCTION",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        0x8000_0003 => "STATUS_BREAKPOINT -- an assertion or a debug break",
        _ => "not one of the common ones",
    }
}

/// The bugcheck codes this project's crashes have produced, for the header.
fn bugcheck_name(code: u32) -> &'static str {
    match code {
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xC2 => "BAD_POOL_CALLER",
        0xC4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0xC5 => "DRIVER_CORRUPTED_EXPOOL",
        0xC6 => "DRIVER_CAUGHT_MODIFYING_FREED_POOL",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        _ => "unrecognised",
    }
}

fn report(
    path: &str,
    expected: Option<u32>,
    at: &[u64],
    drivers: &[String],
    frame: Option<usize>,
) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    println!("=== {path} ===");
    let head: Vec<String> = bytes[..bytes.len().min(8)]
        .iter()
        .map(|c| {
            if c.is_ascii_graphic() {
                (*c as char).to_string()
            } else {
                format!("{c:02X}")
            }
        })
        .collect();
    println!("  first 8 bytes: {}", head.join(" "));

    // The kernel header first: it carries the bugcheck code, and reading it
    // before the streams means a file whose stream layout this does not cover
    // still yields the parameters.
    match parse_kernel_header(&bytes) {
        Some(k) => {
            println!(
                "  DUMP_HEADER64 bugcheck {:#06x}  {}",
                k.bugcheck,
                bugcheck_name(k.bugcheck)
            );
            match expected {
                Some(want) if want == k.bugcheck => {
                    println!("    agrees with the code from Event 1001 -- the header offsets are right")
                }
                // The 09-26 12:07 dump reads 0x1000007e where Event 1001 says
                // 0x7e: the low 16 bits match and bit 28 is set. Bugcheck codes
                // are all below 0x1000, so the code is right and the extra bit
                // is something this does not interpret -- say that rather than
                // either shouting "wrong offsets" or inventing a meaning.
                Some(want) if want & 0xFFFF == k.bugcheck & 0xFFFF => println!(
                    "    agrees with Event 1001 ({want:#06x}) in the low 16 bits; the header has \
                     extra bits set. The extra {:#x} is not interpreted.",
                    k.bugcheck & !0xFFFF
                ),
                Some(want) => println!(
                    "    ** DISAGREES with Event 1001, which says {want:#06x}. \
                     The DUMP_HEADER64 offsets in this tool are wrong; do not trust \
                     the parameters below. **"
                ),
                None => println!(
                    "    (no code given on the command line to check this against -- \
                     pass one from Event 1001 with --code and this becomes a real check)"
                ),
            }
        }
        None => println!("  no DUMP_HEADER64 at offset 0 (not a kernel triage dump, or not one of these)"),
    }
    println!();

    let (d, source) = load(&bytes)?;
    // Before anything that resolves an address to a module: which *build* of that
    // module the dump was running. Offsets read out of a file on disk are that
    // file's offsets, so a mismatch here invalidates every offset comparison
    // downstream and is worth one line up front.
    if !drivers.is_empty() {
        println!();
        for filter in drivers {
            for line in driver_lines(&d.modules, filter) {
                println!("{line}");
            }
        }
    }
    match source {
        Source::MiniDump => println!(
            "  {} bytes, MINIDUMP_HEADER at {:#x}, {} streams, {} modules loaded",
            bytes.len(),
            d.base,
            d.stream_count,
            d.modules.len()
        ),
        Source::Triage => {
            println!(
                "  {} bytes, PAGEDU64 triage dump -- {} drivers in the triage list",
                bytes.len(),
                d.modules.len()
            );
            let empty = PoolReport::default();
            let pool = d.pool.as_ref().unwrap_or(&empty);
            println!("      pool: {}", pool.summary());
            for line in check_driver_list(&d.modules, pool) {
                println!("{line}");
            }
            // A name that did not decode is a fact about this tool, not about
            // the dump, so it gets the raw bytes rather than a guess. One line
            // per entry, capped: the point is to settle the layout question from
            // data, not to dump the pool.
            for (i, at, raw) in pool.undecodable.iter().take(8) {
                println!("      entry {i}: NameOffset {at:#x}, 32 bytes: {raw}");
            }
            if pool.undecodable.len() > 8 {
                println!(
                    "      ... and {} more undecodable entries",
                    pool.undecodable.len() - 8
                );
            }
        }
    }

    // Every address worth naming: the bugcheck parameters. For `0x3B` the
    // instruction address is a parameter rather than the exception address, and
    // for `0x50` the parameter that is *not* in any module is the whole answer.
    if let Some(k) = parse_kernel_header(&bytes) {
        println!("  --- bugcheck parameters, each resolved to a module ---");
        for (n, p) in k.parameters.iter().enumerate() {
            println!("      p{} = {:#018x}   {}", n + 1, p, d.describe(*p));
        }
        println!();

        // For `0x3B`, `0x7E` and `0x1E` the first parameter is the exception code
        // and the second is the faulting instruction -- the same two values an
        // `EXCEPTION_RECORD64` records. That is what makes this a check rather
        // than a guess: a record is only believed when it agrees with them.
        if matches!(k.bugcheck & 0xFFFF, 0x3B | 0x7E | 0x1E) {
            let code = k.parameters[0] as u32;
            let instruction = k.parameters[1];
            println!("  --- exception record: the faulting *data* address ---");
            // The directory's pointer first: it is the documented route, and it
            // is where a record actually is. The scan is the fallback for a
            // writer that copied one into the header instead.
            let mut records: Vec<(usize, ExceptionRecord)> = Vec::new();
            match pointed_exception_record(&bytes, code) {
                Ok((at, r)) => {
                    println!("      via TRIAGE_DUMP64 ExceptionOffset -> {at:#x}");
                    records.push((at, r));
                }
                Err(why) => {
                    println!("      by the directory's ExceptionOffset: {why}");
                    for r in find_exception_records(&bytes, code) {
                        println!("      via a scan of the header -> {:#x}", r.at);
                        records.push((r.at, r));
                    }
                    if records.is_empty() {
                        println!(
                            "      and no 4-byte-aligned blob in the first {:#x} bytes of the \
                             header reads as a record for {code:#010x} either.",
                            0x2000
                        );
                        println!(
                            "      That is a **checked** absence **of both routes**: the address \
                             the faulting instruction touched is not in this file."
                        );
                    }
                }
            }
            for (at, r) in &records {
                println!(
                    "      at file offset {:#x}: code {:#010x}, faulting instruction {:#018x}{}",
                    at,
                    r.code,
                    r.address,
                    if r.address == instruction {
                        "  <- agrees with p2"
                    } else {
                        "  ** disagrees with p2 -- this is not the record for that fault **"
                    }
                );
                println!("      operation: {}", access_kind(&r.information));
                match r.information.get(1) {
                    Some(data) if *data != 0 => println!(
                        "      faulting DATA address {:#018x}   {}",
                        data,
                        d.describe(*data)
                    ),
                    Some(_) => println!(
                        "      faulting DATA address 0x0000000000000000 -- a null dereference"
                    ),
                    None => {}
                }
            }
            println!();

            // The registers, if the dump kept a context for this fault. `Rcx`
            // is the argument the faulting instruction dereferenced, which for
            // this bug is the bad pointer itself.
            //
            // There are two context records in a triage dump and only one of them
            // is about this fault: the directory's `ContextOffset` is the
            // *bugcheck's*, taken inside the crash path long after the fault, and
            // the fault's is the copy the exception dispatcher built further up
            // the same stack. So the directory's is reported as what it is -- a
            // finding, not a failure -- and the fault's is looked for in the
            // stack window by two routes.
            println!("  --- context: the registers at the fault ---");
            let window = stack_window(&bytes);
            let mut contexts: Vec<(String, Option<u64>, FaultContext)> = Vec::new();
            match pointed_context_offset(&bytes) {
                Err(why) => println!("      the directory's ContextOffset: {why}"),
                Ok(at) => match fault_context_at(&bytes, at, instruction) {
                    Ok(c) => {
                        println!(
                            "      the directory's ContextOffset ({at:#x}) holds a CONTEXT whose \
                             Rip **is** the faulting instruction."
                        );
                        contexts.push((format!("the directory's CONTEXT at {at:#x}"), None, c));
                    }
                    Err(why) => {
                        println!("      the directory's ContextOffset ({at:#x}): {why}");
                        // What that context *is* can be said without claiming it
                        // is this fault's: if its `Rsp` is exactly `TopOfStack`
                        // then it and the stack window below are one moment.
                        if let (Ok(any), Some((top, _, _))) = (context_at(&bytes, at), window) {
                            if any.rsp == top {
                                println!(
                                    "      and that context's Rsp ({:#018x}) is exactly \
                                     TopOfStack, so it and the stack window below it are the \
                                     *same moment* -- both were taken in the crash path, after \
                                     the fault rather than at it.",
                                    any.rsp
                                );
                            }
                        }
                    }
                },
            }

            if let Some((top, at, size)) = window {
                println!(
                    "      the stack window holds {:#x} bytes of virtual address {top:#018x}..{:#018x}",
                    size,
                    top + size as u64
                );
                // Route one is the format's own: a bugcheck parameter that points
                // into the window. For `0x3B` the third parameter is documented to
                // be the address of the exception's context record.
                for (n, p) in k.parameters.iter().enumerate() {
                    let Some(off) = window_offset(top, at, size, *p) else {
                        continue;
                    };
                    match fault_context_at(&bytes, off, instruction) {
                        Ok(c) => {
                            println!(
                                "      p{} = {p:#018x} points into the window and reads as a \
                                 CONTEXT for this fault.",
                                n + 1
                            );
                            contexts.push((format!("p{} = {p:#018x}", n + 1), Some(*p), c));
                        }
                        Err(why) => println!(
                            "      p{} = {p:#018x} points into the window but is not a context \
                             for this fault: {why}",
                            n + 1
                        ),
                    }
                }
                // Route two is the scan, which is what covers a dump whose
                // parameters do not name the record at all.
                for (va, c) in contexts_in_stack(&bytes, top, at, size, instruction) {
                    if contexts.iter().any(|(_, v, _)| *v == Some(va)) {
                        continue;
                    }
                    contexts.push((format!("a CONTEXT in the window at {va:#018x}"), Some(va), c));
                }
                if contexts.is_empty() {
                    println!(
                        "      and no CONTEXT anywhere in that window has Rip {instruction:#018x} \
                         -- a **checked** absence: the fault's registers are not in this file."
                    );
                }
            }

            for (label, va, c) in &contexts {
                match va {
                    Some(va) => println!("      {label}   (virtual address {va:#018x})"),
                    None => println!("      {label}"),
                }
                println!(
                    "        SegCs {:#06x}, SegSs {:#06x}, EFlags {:#010x}",
                    c.seg_cs, c.seg_ss, c.eflags
                );
                for (name, value) in c.registers() {
                    let mark = if name == "Rcx" {
                        "   <- the first argument: what the faulting instruction dereferenced"
                    } else {
                        ""
                    };
                    println!("        {name:<4} {value:#018x}   {}{mark}", d.describe(value));
                }
                println!("        Rip  {:#018x}   {}", c.rip, d.describe(c.rip));
                // The caller, when the fault is at a function's *first*
                // instruction -- which is what puts the caller's return address
                // in the first word at `Rsp`.
                match window.map(|(top, at, size)| window_offset(top, at, size, c.rsp)) {
                    Some(Some(off)) => {
                        let ret = u64_at(&bytes, off);
                        println!(
                            "        the word at Rsp ({:#018x}) is {ret:#018x}   {}",
                            c.rsp,
                            d.describe(ret)
                        );
                        println!(
                            "        -- and a fault on a function's *first* instruction is \
                             exactly the case where that word is the caller's return address."
                        );
                    }
                    _ => println!(
                        "        Rsp {:#018x} is outside the stack window, so the return address \
                         the fault pushed is not in this file",
                        c.rsp
                    ),
                }
                for line in frame_section(&d, &bytes, window, c, frame) {
                    println!("{line}");
                }
            }
            println!();

            // Who called the faulting function. The caller's return address is
            // in the raw stack window; on this fault it is the only thing that
            // can turn a narrowed list of suspects into one name.
            println!("  --- call stack: whose return address is in the stack window? ---");
            // `TopOfStack` is what places the window: without it, "the caller is
            // not in the window" cannot be told from "the window is in the wrong
            // place", and those are different findings.
            // `TopOfStack` is a ULONG64 -- 0x48, right after the ULONG run ends
            // at `BrokenDriverOffset` 0x40 and `TriageOptions` 0x44.
            let top = if bytes.len() >= TRIAGE_HDR + 0x50 {
                u64_at(&bytes, TRIAGE_HDR + TRIAGE_TOP_OF_STACK)
            } else {
                0
            };
            if top != 0 {
                println!(
                    "      TopOfStack (the stack pointer the window was taken around) {top:#018x}"
                );
            }
            match call_stack(&bytes) {
                Err(why) => println!("      {why}"),
                Ok(words) => {
                    let mut named = 0;
                    for (i, w) in words.iter().enumerate() {
                        let where_ = d.describe(*w);
                        if where_.contains("NOT IN ANY MODULE") {
                            continue;
                        }
                        named += 1;
                        println!("      [{:3}] {:#018x}   {}", i, w, where_);
                    }
                    if named == 0 {
                        println!(
                            "      {} words, none of them inside a loaded module -- a raw stack \
                             window is mostly locals, so this is possible, but it means the \
                             caller cannot be named from here.",
                            words.len()
                        );
                    } else {
                        println!(
                            "      ({} of {} words resolve into a module. This is a raw stack \
                             window, not a frame list: the entries are candidates, and the \
                             caller of the faulting function is the one nearest the top that \
                             belongs to the same module as the fault.)",
                            named,
                            words.len()
                        );
                    }
                }
            }
            println!();
        }
    }

    // The exception record of a *user-mode* minidump, which is a stream. A
    // kernel dump's is not a stream at all: it sits in the `DUMP_HEADER64`, and
    // for a triage dump it is printed above, located by agreement with the
    // bugcheck parameters rather than by an offset.
    if let Some(code) = d.exception_code {
        println!("  exception {code:#010x}  {}", exception_name(code));
        if !d.parameters.is_empty() {
            let rendered: Vec<String> = d.parameters.iter().map(|p| format!("{p:#018x}")).collect();
            println!("  exception parameters: {}", rendered.join(", "));
        }
    }

    let mut addresses: Vec<u64> = Vec::new();
    if let Some(a) = d.exception_address {
        addresses.push(a);
    }
    for a in at {
        if !addresses.contains(a) {
            addresses.push(*a);
        }
    }
    if addresses.is_empty() {
        println!(
            "  no address to locate -- pass the faulting instruction address from Event 1001 \
             as --at 0x..."
        );
        return Ok(());
    }

    for a in &addresses {
        println!("  >>> {a:#018x} is {}", d.describe(*a));
        if let Some(m) = d.owner(*a) {
            println!(
                "      that module's PE timestamp is {:#010x}{}",
                m.timestamp,
                if is_product(&m.name) {
                    format!("  -- {}", build_name(m.timestamp))
                } else {
                    String::new()
                }
            );
        }
    }

    // The sections below describe the position of one address; when several were
    // given they are usually the same fault read from different places, so the
    // first is the one shown in context.
    let address = addresses[0];

    // The module the address falls in, or the nearest one below it: the window
    // is the same either way, and both are defined without assuming the list is
    // sorted by base. On a real boot the bases are distinct, so this is the
    // highest base at or below the address.
    let index = d
        .modules
        .iter()
        .enumerate()
        .filter(|(_, m)| m.base <= address)
        .max_by_key(|(_, m)| (m.base, std::cmp::Reverse(m.size)))
        .map(|(i, _)| i);
    if let Some(i) = index {
        let lo = i.saturating_sub(3);
        let hi = (i + 4).min(d.modules.len());
        println!("  --- modules around the address ---");
        for (n, m) in d.modules[lo..hi].iter().enumerate() {
            let here = if lo + n == i { " <-" } else { "" };
            println!(
                "      {:#018x} +{:#08x}  {}{}{}",
                m.base,
                m.size,
                m.name,
                m.entry_rva(),
                here
            );
        }
    }

    // Always name our own driver if it is in the dump, wherever the fault was:
    // knowing whether it was even loaded settles a lot.
    println!("  --- product modules in this dump ---");
    let mut found = false;
    for m in &d.modules {
        if is_product(&m.name) {
            println!(
                "      {:#018x} +{:#08x}  ts {:#010x}  {}{}{}",
                m.base,
                m.size,
                m.timestamp,
                m.name,
                m.entry_rva(),
                if d.owner(address).map(|o| o.base) == Some(m.base) {
                    "   <-- AND IT IS THE ONE THAT FAULTED"
                } else {
                    ""
                }
            );
            println!("          which is {}", build_name(m.timestamp));
            found = true;
        }
    }
    if !found {
        println!("      (none -- our driver was not loaded at the time)");
    }
    println!();
    Ok(())
}

/// Report one file's outcome and say whether it failed, however it failed.
///
/// A dump whose layout this does not cover must not take the whole run down
/// with it: the user gets one pass at the files on that machine, and the part
/// that names the module -- the `DUMP_HEADER64` header and the exception
/// address -- has usually printed before anything goes wrong.
///
/// Every offset read out of the file is bounds-checked, so a panic here means a
/// path that check missed. Panicking is still the *right* response to that (a
/// silent 0 would be a confident lie, which is the failure this project keeps
/// repeating), so this does not suppress it -- it catches it, flushes what was
/// already printed, and names the file. The stdout buffer survives unwinding,
/// so nothing printed before the panic is lost, and the default hook still
/// prints the panic site, which is what fixing the layout needs.
///
/// Split out of the loop so the panic branch is reachable from a test; a path
/// only a real crash dump can reach is a path that has never run.
fn absorb(outcome: std::thread::Result<Result<(), String>>, path: &str) -> bool {
    match outcome {
        Ok(Ok(())) => false,
        Ok(Err(e)) => {
            eprintln!("ERROR: {e}");
            true
        }
        Err(_) => {
            let _ = std::io::stdout().flush();
            eprintln!(
                "ERROR: {path}: this tool's idea of the dump layout does not fit this file \
                 (the panic above names where)."
            );
            eprintln!(
                "       Anything printed for it before that point is still valid -- the \
                 DUMP_HEADER64 bugcheck and parameters do not depend on the streams."
            );
            true
        }
    }
}

fn usage() {
    eprintln!(
        "usage: dumpwho [--code 0x<bugcheck>] [--at 0x<address>] [--drivers <substr>] \
         [--frame <words>] <dump.dmp> [<dump.dmp> ...]"
    );
    eprintln!(
        "       dumpwho --scan <hex> [--scan <hex> ...] [--around <bytes>] \
         [--max <hits>] <file> [<file> ...]"
    );
    eprintln!(
        "       dumpwho --hexdump 0x<offset> [--hexdump ...] [--len <bytes>] <file> [<file> ...]"
    );
    eprintln!();
    eprintln!("Names the module behind a bugcheck, from a kernel minidump.");
    eprintln!("Handles both layouts: the MINIDUMP streams of a user-mode dump, and the");
    eprintln!("PAGEDU64 triage dump that C:\\Windows\\Minidump\\*.dmp actually is.");
    eprintln!();
    eprintln!("The bugcheck code and the faulting address are not in every dump --");
    eprintln!("Event 1001 has both:");
    eprintln!(r#"  wevtutil qe System /q:"*[System[(EventID=1001)]]" /c:8 /rd:true /f:text"#);
    eprintln!("  --code checks this tool's DUMP_HEADER64 offsets against that code.");
    eprintln!("  --at   is the faulting instruction address to resolve. For 0x3B and 0x7E");
    eprintln!("         that is parameter 2; for 0x50 it is parameter 3.");
    eprintln!("  --drivers <substr> prints the triage driver list -- base, SizeOfImage,");
    eprintln!("         TimeDateStamp, entry point -- for every name containing <substr>.");
    eprintln!("         Pass \"\" to list all of them. The timestamp is how a dump names");
    eprintln!("         the build it ran: use it before trusting offsets read out of a");
    eprintln!("         file on disk for this machine.");
    eprintln!("  --frame <words> prints the raw stack that many words either side of the");
    eprintln!("         fault's Rsp, naming any word whose value one of the fault's own");
    eprintln!("         registers also holds. Use it when the word at Rsp is not a return");
    eprintln!("         address: a trap frame for the fault would show as a run of those.");
    eprintln!();
    eprintln!("--scan <hex> searches any file for a byte pattern -- one per --scan -- and");
    eprintln!("prints each hit's offset with context. No dump parsing happens; a full");
    eprintln!("kernel dump holds the loaded code pages, so cutting a function's bytes out");
    eprintln!("of the .sys on disk and searching the dump for them says whether the image");
    eprintln!("that crashed is that file or something else. Rip-relative operands keep the");
    eprintln!("same displacement in memory as on disk, so the file's bytes are a valid");
    eprintln!("needle. An odd number of hex digits is an error, never a short needle.");
    eprintln!("  --around <bytes> context either side of a hit (default {DEFAULT_AROUND}).");
    eprintln!("  --max <hits>     hits listed per pattern (default {DEFAULT_MAX_HITS}); the");
    eprintln!("                   count is always printed in full.");
    eprintln!();
    eprintln!("--hexdump 0x<offset> prints the bytes at an absolute file offset -- one per");
    eprintln!("--hexdump -- and marks the byte at that offset. A hit tells you where to");
    eprintln!("look; this is what says what is there. An offset past the end of the file is");
    eprintln!("an error naming the size, never an empty print, because an empty window would");
    eprintln!("read as \"nothing is there\" while meaning \"wrong offset\".");
    eprintln!("  --len <bytes>    bytes printed per window (default {DEFAULT_DUMP_LEN}, at most");
    eprintln!("                   {MAX_DUMP_LEN}); a count outside that is refused, not clamped.");
}

// ---------------------------------------------------------------------------
// Raw byte-pattern scanning (`--scan`)
// ---------------------------------------------------------------------------

/// How much of a file is read at a time by [`find_hits`].
///
/// A full kernel dump is 574 MB on this VM. Reading it whole would work here
/// and not on the next machine, so it is walked in pieces instead.
const SCAN_CHUNK: usize = 4 << 20;

/// Bytes of context printed either side of a hit, unless `--around` says.
const DEFAULT_AROUND: usize = 32;

/// Hits printed per pattern, unless `--max` says. A short pattern can match
/// once per byte -- four zero bytes inside a page of zeros match thousands of
/// times -- and the count is the interesting part, not the listing.
const DEFAULT_MAX_HITS: usize = 64;

/// Bytes one `--hexdump` window prints, unless `--len` says. Sixteen rows: a PE
/// header, a function's prologue and a page's first four lines all fit, which is
/// the scale every offset in this investigation is reasoned about at.
const DEFAULT_DUMP_LEN: usize = 0x100;

/// The largest window `--len` may ask for, refused above rather than clamped.
/// Two pages is enough to hold a function and its neighbours, and the refusal is
/// what keeps a mistyped `--len 4096000` from being an empty terminal and a
/// support question.
const MAX_DUMP_LEN: usize = 0x2000;

/// One place a pattern was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hit {
    /// Index into the needle list.
    pattern: usize,
    /// Absolute offset in the file.
    offset: u64,
}

/// Bytes from hex, with whitespace or `-` allowed between pairs.
///
/// Patterns here are pasted out of a disassembler, so `4883ec28...` and
/// `48 83 ec 28 ...` both have to work. An odd number of digits is an error
/// rather than a silently truncated needle: a truncated needle searches for
/// the wrong bytes and reports "no hits", which reads exactly like a real
/// negative, and that is the one outcome this tool must never produce.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect();
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned.as_str());
    if hex.is_empty() {
        return Err("empty byte pattern".into());
    }
    if hex.len() % 2 != 0 {
        return Err(format!(
            "byte pattern {s} has an odd number of hex digits ({} of them)",
            hex.len()
        ));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let pair = &hex[i..i + 2];
        match u8::from_str_radix(pair, 16) {
            Ok(b) => out.push(b),
            Err(_) => return Err(format!("byte pattern {s} is not hex at {pair}")),
        }
    }
    Ok(out)
}

/// The first index of `needle` in `hay`, or `None`.
///
/// Naive, with a first-byte prefilter, because this file is built with a bare
/// `rustc` and `memchr` is a dependency. The prefilter is what keeps 574 MB
/// against a handful of short patterns at seconds rather than minutes.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|b| *b == first) {
            Some(rel) => {
                let at = i + rel;
                if &hay[at..at + needle.len()] == needle {
                    return Some(at);
                }
                i = at + 1;
            }
            None => return None,
        }
    }
    None
}

/// Every offset where one of `needles` occurs in `reader`, streamed.
///
/// Each piece carries over the last `longest - 1` bytes, which is what keeps a
/// pattern straddling a piece boundary from being missed -- the failure mode
/// that would produce a confident, wrong "the running image is not this file".
///
/// A hit that begins in the carried region *and* ended before the previous
/// piece's end is found twice, once by each piece. That case is real whenever
/// the needles differ in length (`longest - 1` bytes of carry is more than a
/// shorter needle needs), so duplicates are removed by comparison afterwards
/// rather than argued away here.
fn find_hits<R: Read>(reader: &mut R, needles: &[Vec<u8>], chunk: usize) -> std::io::Result<Vec<Hit>> {
    let longest = needles.iter().map(Vec::len).max().unwrap_or(0);
    let mut hits = Vec::new();
    if longest == 0 {
        return Ok(hits);
    }
    // A piece smaller than a needle would carry the whole piece forward and
    // make no progress, so the piece is at least one needle long.
    let chunk = chunk.max(longest);
    let mut buf = vec![0u8; chunk];
    let mut carry: Vec<u8> = Vec::new();
    // Absolute offset of `carry[0]`.
    let mut base: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + n);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buf[..n]);
        for (pattern, needle) in needles.iter().enumerate() {
            if needle.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(rel) = find_sub(&window[from..], needle) {
                let start = from + rel;
                hits.push(Hit {
                    pattern,
                    offset: base + start as u64,
                });
                from = start + 1;
            }
        }
        let keep = longest.saturating_sub(1).min(window.len());
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
        base += (window.len() - keep) as u64;
    }
    hits.sort_by_key(|h| (h.offset, h.pattern));
    hits.dedup_by(|a, b| a.offset == b.offset && a.pattern == b.pattern);
    Ok(hits)
}

/// Hex, no separators, for printing a pattern back.
fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `len` bytes of `reader` at `offset`, or as many as the file has left.
///
/// The short read is deliberate and is *reported* by every caller as the byte
/// count it got: a window that reached the end of the file is a fact about the
/// file, while a window silently padded to the length asked for would be this
/// tool inventing bytes.
fn read_window<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    reader.take(len as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Where a `--hexdump` window starts and how long it can be, or why it cannot be
/// taken at all.
///
/// An offset at or past the end is an error rather than an empty print. This
/// tool answers "is this page in the dump", and a window that printed nothing
/// would read as "no" while meaning "you asked for the wrong offset" -- the same
/// silent-negative failure the `--scan` help goes out of its way to avoid.
fn window(size: u64, offset: u64, len: usize) -> Result<(u64, usize), String> {
    if offset >= size {
        return Err(format!(
            "offset 0x{offset:x} is past the end of this {size}-byte file, so there is nothing to \
             print. Its last page starts at 0x{:x}.",
            size.saturating_sub(1) & !0xFFF
        ));
    }
    let available = size - offset;
    Ok((offset, len.min(available as usize)))
}

/// The hex and ASCII rows of a window, with every byte `mark` accepts marked.
///
/// One formatter for both callers, because the two asks are the same ask: a
/// `--scan` hit marks the pattern's own bytes so a replacement at that spot is
/// visible without counting columns, and a `--hexdump` marks the single byte at
/// the offset that was asked for. Rows are aligned to 16-byte boundaries of the
/// file offset, so two windows at different offsets can be compared column by
/// column -- which is how a page that is present-but-different is told from one
/// that is absent.
fn hex_rows(start: u64, bytes: &[u8], mark: &dyn Fn(u64) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let end = start + bytes.len() as u64;
    let mut p = start & !0xF;
    while p < end {
        let mut hex = String::new();
        let mut ascii = String::new();
        let mut marks = String::new();
        let mut marked = false;
        for k in 0..16u64 {
            let off = p + k;
            if off >= start && off < end {
                let b = bytes[(off - start) as usize];
                hex.push_str(&format!("{b:02x} "));
                ascii.push(if (32..127).contains(&b) { b as char } else { '.' });
                let inside = mark(off);
                marks.push_str(if inside { "^^ " } else { "   " });
                marked |= inside;
            } else {
                hex.push_str("   ");
                ascii.push(' ');
                marks.push_str("   ");
            }
        }
        out.push(format!("    {p:08x}  {hex:<48} |{ascii}|"));
        if marked {
            out.push(format!("              {marks}"));
        }
        p += 16;
    }
    out
}

/// Hex and ASCII of `around` bytes either side of a hit, with the pattern's own
/// bytes marked, so a replacement at that spot is visible without counting
/// columns.
fn print_hit(f: &mut fs::File, hit: &Hit, needle_len: usize, around: usize) -> std::io::Result<()> {
    let before = around.min(hit.offset as usize);
    let start = hit.offset - before as u64;
    let want = before + needle_len + around;
    let bytes = read_window(f, start, want)?;
    println!(
        "  hit at 0x{:x} ({} byte(s) of context {} it)",
        hit.offset,
        bytes.len(),
        if start == 0 { "from" } else { "around" }
    );
    for line in hex_rows(start, &bytes, &|off| {
        off >= hit.offset && off < hit.offset + needle_len as u64
    }) {
        println!("{line}");
    }
    Ok(())
}

/// Run every pattern over one file and print where each of them lands.
fn report_scan(path: &str, needles: &[Vec<u8>], around: usize, max: usize) -> std::io::Result<()> {
    let size = fs::metadata(path)?.len();
    let mut file = fs::File::open(path)?;
    println!("{path}  ({size} bytes)");
    for (i, n) in needles.iter().enumerate() {
        println!("  pattern {}: {} bytes, {}", i + 1, n.len(), hex_string(n));
    }
    println!();
    let hits = find_hits(&mut file, needles, SCAN_CHUNK)?;
    for (i, needle) in needles.iter().enumerate() {
        let mine: Vec<&Hit> = hits.iter().filter(|h| h.pattern == i).collect();
        println!(
            "pattern {} ({} bytes): {} hit(s)",
            i + 1,
            needle.len(),
            mine.len()
        );
        for hit in mine.iter().take(max) {
            print_hit(&mut file, hit, needle.len(), around)?;
        }
        if mine.len() > max {
            println!("  ... and {} more, not printed", mine.len() - max);
        }
        println!();
    }
    Ok(())
}

/// Print the bytes at each `--hexdump` offset.
///
/// A bad offset is printed as a sentence under its own heading and the run
/// continues: several windows in one command is the point, and one of them
/// landing wrong should not hide the others' bytes.
fn report_hexdumps(path: &str, offsets: &[u64], len: usize) -> std::io::Result<()> {
    let size = fs::metadata(path)?.len();
    let mut file = fs::File::open(path)?;
    println!("{path}  ({size} bytes)");
    for &offset in offsets {
        println!();
        match window(size, offset, len) {
            Ok((start, length)) => {
                let bytes = read_window(&mut file, start, length)?;
                println!("=== 0x{start:x}  ({length} byte(s) of {len} asked for) ===");
                for line in hex_rows(start, &bytes, &|off| off == start) {
                    println!("{line}");
                }
            }
            Err(message) => {
                println!("=== 0x{offset:x} ===");
                println!("  {message}");
            }
        }
    }
    Ok(())
}

/// `0x`-prefixed hex, with or without the prefix.
fn parse_hex(s: &str) -> Option<u64> {
    let t = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(t, 16).ok()
}

/// The command line, once parsed.
#[derive(Debug, Default, PartialEq)]
struct Args {
    bugcheck: Option<u32>,
    at: Vec<u64>,
    /// `--drivers <substr>`, repeatable: print the triage driver list, filtered.
    /// An empty substring means every entry. A value is **required**, so that
    /// `--drivers kept.dmp` cannot silently swallow the dump's filename as the
    /// filter and then report the file as missing -- the mirror image of the
    /// `--code`-as-a-filename bug this parser already has a test for.
    drivers: Vec<String>,
    /// `--frame <words>`: print the raw stack that many words either side of the
    /// fault's `Rsp`, annotated with the fault's own register values. A value is
    /// **required** for the same reason `--drivers` requires one.
    frame: Option<usize>,
    /// `--scan <hex>`, repeatable: search the files for these bytes instead of
    /// parsing them as dumps. Held as decoded bytes, not as the text, so a
    /// pattern that does not parse is rejected at the command line rather than
    /// at the point of use.
    scan: Vec<Vec<u8>>,
    /// `--around <bytes>`: context either side of a hit.
    around: Option<usize>,
    /// `--max <hits>`: hits listed per pattern; the count is printed regardless.
    max_hits: Option<usize>,
    /// `--hexdump 0x<offset>`, repeatable: print the raw bytes at these absolute
    /// file offsets. The complement of `--scan`, which says where to look and not
    /// what is there.
    hexdump: Vec<u64>,
    /// `--len <bytes>`: how much each `--hexdump` window prints.
    len: Option<usize>,
    files: Vec<String>,
}

/// Parse the command line.
///
/// The legacy form was `dumpwho 0x3b <dump>`; a bare leading code still works.
/// It has to be `0x`-prefixed to count. An earlier version instead pushed any
/// first argument that did not parse as hex into the file list, which swallowed
/// `--code` itself and reported it as a missing file -- in the VM, where the
/// round-trip to find that out is a manual copy. Hence a function, and a test.
fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.peekable();

    if it
        .peek()
        .is_some_and(|f| f.starts_with("0x") || f.starts_with("0X"))
    {
        let f = it.next().unwrap_or_default();
        match parse_hex(&f) {
            Some(code) => out.bugcheck = Some(code as u32),
            None => return Err(format!("{f} looks like a bugcheck code but does not parse")),
        }
    }

    while let Some(a) = it.next() {
        match a.as_str() {
            "--code" => match it.next().as_deref().and_then(parse_hex) {
                Some(v) => out.bugcheck = Some(v as u32),
                None => return Err("--code needs a hex value".into()),
            },
            "--at" => match it.next().as_deref().and_then(parse_hex) {
                Some(v) => out.at.push(v),
                None => return Err("--at needs a hex address".into()),
            },
            "--drivers" => match it.next() {
                Some(v) => out.drivers.push(v),
                None => {
                    return Err(
                        "--drivers needs a name substring; pass \"\" to list every driver".into(),
                    )
                }
            },
            "--frame" => match it.next().as_deref().map(str::parse::<usize>) {
                Some(Ok(v)) => out.frame = Some(v),
                _ => {
                    return Err(
                        "--frame needs a decimal word count, e.g. --frame 40: the number of \
                         words either side of Rsp to print"
                            .into(),
                    )
                }
            },
            "--scan" => match it.next() {
                Some(v) => out.scan.push(parse_hex_bytes(&v)?),
                None => return Err("--scan needs a hex byte pattern, e.g. --scan 4883ec28".into()),
            },
            "--around" => match it.next().as_deref().map(str::parse::<usize>) {
                Some(Ok(v)) => out.around = Some(v),
                _ => {
                    return Err(
                        "--around needs a decimal byte count, e.g. --around 32: the context \
                         printed either side of each hit"
                            .into(),
                    )
                }
            },
            "--max" => match it.next().as_deref().map(str::parse::<usize>) {
                Some(Ok(v)) => out.max_hits = Some(v),
                _ => {
                    return Err(
                        "--max needs a decimal hit count, e.g. --max 8: how many hits per \
                         pattern are listed"
                            .into(),
                    )
                }
            },
            "--hexdump" => match it.next().as_deref().and_then(parse_hex) {
                Some(v) => out.hexdump.push(v),
                None => {
                    return Err(
                        "--hexdump needs a file offset in hex, e.g. --hexdump 0x10971750: the \
                         absolute offset whose bytes should be printed"
                            .into(),
                    )
                }
            },
            "--len" => match it.next().as_deref().map(str::parse::<usize>) {
                // Refused, not clamped, and refused here rather than at the
                // point of use: a window shortened by a guard is a window whose
                // byte count the reader has to notice, and zero bytes is a print
                // that reads as "nothing is there".
                Some(Ok(v)) if v == 0 || v > MAX_DUMP_LEN => {
                    return Err(format!(
                        "--len {v} is outside the 1..={MAX_DUMP_LEN} bytes each --hexdump window \
                         prints. The count was refused rather than truncated, because a shortened \
                         window is a window that reads as a wrong answer."
                    ))
                }
                Some(Ok(v)) => out.len = Some(v),
                _ => {
                    return Err(format!(
                        "--len needs a decimal byte count up to {MAX_DUMP_LEN}, e.g. --len 64: how \
                         many bytes each --hexdump prints"
                    ))
                }
            },
            _ => out.files.push(a),
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return ExitCode::from(if args.is_empty() { 2 } else { 0 });
    }

    let Args {
        bugcheck,
        at,
        drivers,
        frame,
        scan,
        around,
        max_hits,
        hexdump,
        len,
        files,
    } = match parse_args(args.into_iter()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    if files.is_empty() {
        eprintln!("no dump files given");
        usage();
        return ExitCode::from(2);
    }

    // `--scan` and `--hexdump` take over completely: the files are byte-searched
    // or read raw, not parsed, so a dump's directory walk never runs and
    // `--code`/`--at` do not apply. Both together, in that order, because the
    // scan is what says which offset to read.
    if !scan.is_empty() || !hexdump.is_empty() {
        let mut failed = false;
        for f in &files {
            // The return type is written out: `?` on an `io::Error` can convert
            // into any `E: From<io::Error>`, so a closure ending in a bare
            // `Ok(())` leaves `E` unconstrained and the build fails with an
            // inference error that names the `Ok(())` and not the ambiguity.
            let outcome = panic::catch_unwind(|| -> std::io::Result<()> {
                if !scan.is_empty() {
                    report_scan(
                        f,
                        &scan,
                        around.unwrap_or(DEFAULT_AROUND),
                        max_hits.unwrap_or(DEFAULT_MAX_HITS),
                    )?;
                }
                if !hexdump.is_empty() {
                    report_hexdumps(f, &hexdump, len.unwrap_or(DEFAULT_DUMP_LEN))?;
                }
                Ok(())
            });
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    eprintln!("{f}: {e}");
                    failed = true;
                }
                Err(_) => {
                    eprintln!("{f}: panicked while scanning");
                    failed = true;
                }
            }
        }
        return if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }
    if let Some(code) = bugcheck {
        println!("bugcheck {code:#06x}  {}", bugcheck_name(code));
        println!();
    }

    let mut failed = false;
    for f in &files {
        let outcome = panic::catch_unwind(|| report(f, bugcheck, &at, &drivers, frame));
        failed |= absorb(outcome, f);
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minidump with one exception stream and one module list, so the
    /// parser is exercised against the byte layout rather than against hope.
    ///
    /// `prefix` bytes are placed ahead of the `MINIDUMP_HEADER`, so the same
    /// builder covers both the "header at 0" and the "header after a
    /// `DUMP_HEADER64`" case.
    fn synthetic_at(prefix: usize, address: u64) -> Vec<u8> {
        // Layout: prefix | MINIDUMP_HEADER (32) | dir (2 * 12) | exception
        // stream (168) | module list (4 + 108) | module name string.
        //
        // `mdmp` is where the MINIDUMP_HEADER starts, and it is the origin every
        // RVA in the file is measured from -- not the start of the file. That
        // distinction is the whole point of `a_header_past_a_dump_header64_...`,
        // and getting it wrong in this builder is what made three tests fail the
        // first time it ran.
        let mdmp = prefix;
        let dir = mdmp + 32;
        let exc = dir + 24;
        let mods = exc + 168;
        let name = mods + 4 + MODULE_ENTRY_SIZE;
        let total = name + 4 + 24; // "C:\x.sys" is 8 UTF-16 units
        let mut b = vec![0u8; total];

        b[mdmp..mdmp + 4].copy_from_slice(&MDMP.to_le_bytes());
        b[mdmp + 8..mdmp + 12].copy_from_slice(&2u32.to_le_bytes());
        b[mdmp + 12..mdmp + 16].copy_from_slice(&((dir - mdmp) as u32).to_le_bytes());

        b[dir..dir + 4].copy_from_slice(&EXCEPTION_STREAM.to_le_bytes());
        b[dir + 4..dir + 8].copy_from_slice(&168u32.to_le_bytes());
        b[dir + 8..dir + 12].copy_from_slice(&((exc - mdmp) as u32).to_le_bytes());
        b[dir + 12..dir + 16].copy_from_slice(&MODULE_LIST_STREAM.to_le_bytes());
        b[dir + 16..dir + 20].copy_from_slice(&(4u32 + MODULE_ENTRY_SIZE as u32).to_le_bytes());
        b[dir + 20..dir + 24].copy_from_slice(&((mods - mdmp) as u32).to_le_bytes());

        b[exc + 8..exc + 12].copy_from_slice(&0xC000_0005u32.to_le_bytes());
        b[exc + 24..exc + 32].copy_from_slice(&address.to_le_bytes());
        b[exc + 32..exc + 36].copy_from_slice(&1u32.to_le_bytes());
        b[exc + 40..exc + 48].copy_from_slice(&0u64.to_le_bytes());

        b[mods..mods + 4].copy_from_slice(&1u32.to_le_bytes());
        let m = mods + 4;
        b[m..m + 8].copy_from_slice(&0xfffff800_0bf30000u64.to_le_bytes());
        b[m + 8..m + 12].copy_from_slice(&0x5000u32.to_le_bytes());
        // A real stamp, so the offset is pinned against a value that also has to
        // survive `build_name`.
        b[m + 16..m + 20].copy_from_slice(&0x6AB8_7FBFu32.to_le_bytes());
        b[m + 20..m + 24].copy_from_slice(&((name - mdmp) as u32).to_le_bytes());

        let text: Vec<u16> = "C:\\x.sys".encode_utf16().collect();
        b[name..name + 4].copy_from_slice(&((text.len() * 2) as u32).to_le_bytes());
        for (i, u) in text.iter().enumerate() {
            let o = name + 4 + i * 2;
            b[o..o + 2].copy_from_slice(&u.to_le_bytes());
        }
        b
    }

    fn synthetic(address: u64) -> Vec<u8> {
        synthetic_at(0, address)
    }

    /// The `PAGEDU64` layout, written out a second time from the format
    /// description rather than from the parser's constants.
    ///
    /// This duplication is the point, and it is not a style choice. A fixture
    /// that writes its fields through [`TRIAGE_DRIVER_LIST_OFFSET`] and friends
    /// moves with them: it reads whatever the parser reads, passes whatever the
    /// parser says, and detects nothing. That was true of this fixture's first
    /// version -- changing four of the parser's offsets to wrong values left
    /// every triage test still passing. Restating the numbers here is what makes
    /// the tests able to fail.
    const HDR: usize = 0x2000;
    const HDR_LIST: usize = 0x30;
    const HDR_COUNT: usize = 0x34;
    const HDR_POOL: usize = 0x38;
    const HDR_POOL_SIZE: usize = 0x3c;
    const ENTRY: usize = 0x90;
    const E_NAME: usize = 0x00;
    const E_BASE: usize = 0x38;
    const E_ENTRY: usize = 0x40;
    const E_SIZE: usize = 0x48;
    const E_STAMP: usize = 0x88;

    /// A `PAGEDU64` triage dump: `DUMP_HEADER64` (0x2000 bytes), then a
    /// `TRIAGE_DUMP64` directory whose fields are absolute file offsets, then
    /// the driver list and the string pool.
    ///
    /// The three drivers are a kernel, the filter manager and our own, because
    /// `check_driver_list` requires the first two -- a fixture without them
    /// would let the parser look correct while the validator rejected every real
    /// file.
    fn synthetic_triage() -> Vec<u8> {
        let list = HDR + 0x40;
        let pool = list + 4 * ENTRY;
        let mut b = vec![0u8; pool + 0x400];

        b[0..4].copy_from_slice(&PAGE.to_le_bytes());
        b[4..8].copy_from_slice(&DU64.to_le_bytes());
        // The bugcheck code, at the offset `parse_kernel_header` reads.
        b[0x38..0x3c].copy_from_slice(&0x3bu32.to_le_bytes());
        for (i, p) in [0x0000_0000_c000_0005u64, 0xffff_f800_1000_26f0, 0, 0]
            .iter()
            .enumerate()
        {
            b[0x40 + i * 8..0x48 + i * 8].copy_from_slice(&p.to_le_bytes());
        }

        b[HDR + HDR_LIST..HDR + HDR_LIST + 4].copy_from_slice(&(list as u32).to_le_bytes());
        b[HDR + HDR_COUNT..HDR + HDR_COUNT + 4].copy_from_slice(&4u32.to_le_bytes());
        b[HDR + HDR_POOL..HDR + HDR_POOL + 4].copy_from_slice(&(pool as u32).to_le_bytes());
        b[HDR + HDR_POOL_SIZE..HDR + HDR_POOL_SIZE + 4].copy_from_slice(&0x400u32.to_le_bytes());

        // The strings are the ones a real dump holds, so that the fixture
        // exercises the shape that broke the name filter: `FLTMGR.SYS` in
        // capitals, and a `.dll` entry, neither of which the old test accepted.
        let entries = [
            ("ntoskrnl.exe", 0xffff_f800_0000_0000u64, 0x0100_0000u32, 0x1111_1111u32),
            ("FLTMGR.SYS", 0xffff_f800_0400_0000u64, 0x0004_0000u32, 0x2222_2222u32),
            ("hal.dll", 0xffff_f800_0800_0000u64, 0x0002_0000u32, 0x3333_3333u32),
            (
                "\\SystemRoot\\System32\\drivers\\WenleAvFilter.sys",
                0xffff_f800_1000_0000u64,
                0x0001_2000u32,
                // The stamp `dumpbin /headers` reports for the build deployed on
                // 09-26 13:44, so this fixture also pins "which build was this".
                0x6AB7_579Au32,
            ),
        ];

        let mut n = pool;
        for (i, (name, base, size, ts)) in entries.iter().enumerate() {
            let o = list + i * ENTRY;
            b[o + E_NAME..o + E_NAME + 4].copy_from_slice(&(n as u32).to_le_bytes());
            b[o + E_BASE..o + E_BASE + 8].copy_from_slice(&base.to_le_bytes());
            b[o + E_SIZE..o + E_SIZE + 4].copy_from_slice(&size.to_le_bytes());
            b[o + E_STAMP..o + E_STAMP + 4].copy_from_slice(&ts.to_le_bytes());
            // `EntryPoint` is a VA. `+0x1000` is the WDM entry RVA, which is
            // what a real dump of our driver must show.
            b[o + E_ENTRY..o + E_ENTRY + 8].copy_from_slice(&(base + 0x1000).to_le_bytes());

            let u: Vec<u16> = name.encode_utf16().collect();
            b[n..n + 4].copy_from_slice(&(u.len() as u32).to_le_bytes());
            for (k, c) in u.iter().enumerate() {
                b[n + 4 + k * 2..n + 4 + k * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
            n += 4 + u.len() * 2 + 8;
        }
        b
    }

    /// The layout claimed for `DRIVER_ENTRY64` has to add up to its own size, or
    /// one of the four offsets is wrong. This is arithmetic on the constants, so
    /// it catches an edit to one of them and not a wrong claim about Windows.
    #[test]
    fn the_driver_entry_offsets_fill_the_driver_entry() {
        assert_eq!(DRIVER_ENTRY_SIZE, 0x90);
        assert_eq!(ENTRY_DLL_BASE, 0x38, "NameOffset u32 + reserved[52]");
        assert_eq!(ENTRY_SIZE_OF_IMAGE, ENTRY_DLL_BASE + 16, "DllBase + EntryPoint");
        assert_eq!(
            ENTRY_TIMESTAMP + 8,
            DRIVER_ENTRY_SIZE,
            "TimeDateStamp u64 + reserved[56] must reach the end"
        );
    }

    #[test]
    fn a_pagedu64_triage_dump_yields_its_driver_list() {
        let b = synthetic_triage();
        let (mods, pr) = parse_triage_drivers(&b).unwrap();
        assert_eq!(mods.len(), 4);
        // The fixture writes count-prefixed strings, so every name must come out
        // of that reading -- if the order of the readings changes and a later one
        // starts winning, this says so instead of the names quietly changing.
        assert_eq!(pr.counted, 4, "{}", pr.summary());
        assert!(pr.undecodable.is_empty(), "{}", pr.summary());
        assert!(check_driver_list(&mods, &pr)
            .iter()
            .all(|l| !l.contains("**")), "sanity checks should pass: {mods:#?}");

        // A capitalised `.SYS` and a `.dll`: the two shapes the old name filter
        // rejected, which is what made the module that faulted print nameless.
        assert!(mods.iter().any(|m| m.name == "FLTMGR.SYS"), "{mods:#?}");
        assert!(mods.iter().any(|m| m.name == "hal.dll"), "{mods:#?}");

        let ours = mods.iter().find(|m| is_product(&m.name)).expect("our driver");
        assert_eq!(ours.base, 0xffff_f800_1000_0000);
        assert_eq!(ours.size, 0x1_2000);
        assert_eq!(ours.timestamp, 0x6AB7_579A);
        assert!(build_name(ours.timestamp).contains("13:44"));
        // `DRIVER_ENTRY64.EntryPoint` at 0x40, read as a VA: this is the field
        // that was never read before, so the assertion is what makes it real.
        assert_eq!(ours.entry, 0xffff_f800_1000_1000);
        assert_eq!(ours.entry_rva(), "  ep +0x1000");

        // The whole point: an address from Event 1001 resolves to a module name.
        let (d, source) = load(&b).unwrap();
        assert_eq!(source, Source::Triage);
        assert_eq!(d.describe(0xffff_f800_1000_26f0), "\\SystemRoot\\System32\\drivers\\WenleAvFilter.sys +0x26f0");
    }

    /// The question `--drivers` exists for: is the module the dump was running
    /// the same build as the file whose offsets are being read on the host? The
    /// fixture's `FLTMGR.SYS` carries a stamp, and the line must carry it too --
    /// a list without stamps answers nothing.
    #[test]
    fn the_driver_list_names_the_build_the_dump_was_running() {
        let b = synthetic_triage();
        let (mods, _) = parse_triage_drivers(&b).unwrap();
        let lines = driver_lines(&mods, "fltmgr");
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert!(lines[0].contains("1 of 4"), "{}", lines[0]);
        // The fixture's stamp is written as a literal in the entry table above;
        // if the parser reads the wrong offset this line goes blank or wrong.
        assert!(lines[1].contains("0x22222222"), "{}", lines[1]);
        assert!(lines[1].contains("size 0x00040000"), "{}", lines[1]);
        assert!(lines[1].contains("FLTMGR.SYS"), "{}", lines[1]);
        // Matching is case-insensitive both ways, or `--drivers FLTMGR` on a
        // real pool (which spells it in capitals) would find nothing.
        assert_eq!(driver_lines(&mods, "FLTMGR").len(), 2);

        // A stamp is a fact about *this* image, so the build name is attached
        // only to ours -- printed beside `ntoskrnl.exe` it would read as a claim
        // about Windows.
        let ours = driver_lines(&mods, "wenleavfilter");
        assert!(ours[1].contains("13:44"), "{}", ours[1]);
        assert!(!driver_lines(&mods, "ntoskrnl")[1].contains("--"), "{:?}", driver_lines(&mods, "ntoskrnl"));
    }

    /// An empty filter lists everything, and a filter that matches nothing has to
    /// say *how many* names it searched -- the checked-absence rule this file has
    /// had to relearn five times. A tool that answers "absent" without that number
    /// cannot be told apart from one that looked at the wrong list.
    #[test]
    fn a_driver_filter_that_matches_nothing_says_what_it_searched() {
        let b = synthetic_triage();
        let (mods, _) = parse_triage_drivers(&b).unwrap();
        assert_eq!(driver_lines(&mods, "").len(), 5, "4 entries plus the header");
        let none = driver_lines(&mods, "nosuchdriver");
        assert_eq!(none.len(), 2);
        assert!(none[1].contains("searched all 4 names"), "{}", none[1]);

        // And an empty list cannot claim to have searched anything.
        let empty = driver_lines(&[], "fltmgr");
        assert!(empty[0].contains("0 of 0"), "{}", empty[0]);
        assert!(!empty[1].contains("searched all 0"), "{}", empty[1]);
    }

    /// `--drivers` takes a value, so a dump filename after it cannot be eaten as
    /// the filter -- the mirror image of the `--code` bug, which left the user
    /// with "no such file: --code" from inside the VM.
    #[test]
    fn drivers_takes_a_value_and_never_eats_the_filename() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string())).unwrap();
        let got = a(&["--drivers", "fltmgr", "kept.dmp"]);
        assert_eq!(got.drivers, vec!["fltmgr"]);
        assert_eq!(got.files, vec!["kept.dmp"]);
        // The empty filter is a real request ("list them all"), not a mistake.
        assert_eq!(a(&["--drivers", "", "d.dmp"]).drivers, vec![""]);
        // Repeatable, so one run can ask about fltMgr, ntoskrnl and our own
        // driver at once -- the whole point is a single round trip into the VM.
        assert_eq!(
            a(&["--drivers", "fltmgr", "--drivers", "ntoskrnl", "d.dmp"]).drivers,
            vec!["fltmgr", "ntoskrnl"]
        );
        // A missing value is refused rather than silently listing everything.
        assert!(parse_args(["--drivers"].iter().map(|s| s.to_string())).is_err());
        assert!(a(&["d.dmp"]).drivers.is_empty());
    }

    /// The name filter's two halves, at the boundary that actually bit: a
    /// capitalised `.SYS` and a `.dll` are names a real pool holds, and the
    /// strict test exists only to judge the two undocumented fallback readings.
    #[test]
    fn a_capitalised_or_dll_name_is_still_a_name() {
        assert!(is_plausible_name("FLTMGR.SYS"));
        assert!(is_plausible_name("hal.dll"));
        assert!(is_plausible_name("BOOTVID.dll"));
        // Non-vacuous the other way: the weak test still refuses junk, or it
        // would accept any counted read as a name.
        assert!(!is_plausible_name(""));
        assert!(!is_plausible_name("\n"));
        assert!(!is_plausible_name(&"a".repeat(300)));
        assert!(!is_plausible_name("has a \u{1} control char"));

        // The strict test keeps the extension requirement, case-insensitively,
        // because a fallback winning has to be plausible on its own terms.
        assert!(looks_like_a_driver_name("FLTMGR.SYS"));
        assert!(looks_like_a_driver_name("\\SystemRoot\\x.sys"));
        assert!(!looks_like_a_driver_name("hal.dll"));
        assert!(!looks_like_a_driver_name("\n"));
    }

    /// A kernel whose driver list has no ntoskrnl is not a kernel. This is the
    /// check that keeps a wrong `TRIAGE_DUMP64` offset from producing a
    /// confident wrong module name -- the failure mode this project has already
    /// paid for twice.
    #[test]
    fn a_driver_list_without_a_kernel_is_flagged() {
        let b = synthetic_triage();
        let (mut mods, pr) = parse_triage_drivers(&b).unwrap();
        // Assert it passes *before* breaking it, so this cannot pass for the
        // wrong reason -- a garbage list would be flagged anyway.
        assert!(
            check_driver_list(&mods, &pr).iter().all(|l| !l.contains("**")),
            "the intact list must pass first"
        );
        mods.retain(|m| !m.name.contains("ntoskrnl"));
        let lines = check_driver_list(&mods, &pr);
        assert!(
            lines.iter().any(|l| l.contains("ntoskrnl")),
            "a missing kernel must be reported"
        );
        // With every name decoded, a missing ntoskrnl is a claim about the
        // *offsets* -- that reading must still be the one printed.
        assert!(
            lines.iter().any(|l| l.contains("do not fit this file")),
            "a decodable list with no kernel indicts the offsets: {lines:?}"
        );
    }

    /// A missing name and a missing entry are different findings, and the whole
    /// point of the pool report is to keep them apart. The first real dump
    /// printed `no 'fltmgr' in the list` next to `192/192 bases 64 KB aligned`
    /// -- both facts at once, which the old single message could not express.
    #[test]
    fn an_undecodable_name_is_not_reported_as_wrong_offsets() {
        let b = synthetic_triage();
        let (mut mods, mut pr) = parse_triage_drivers(&b).unwrap();
        // Drop fltmgr's *name* while leaving its entry in place -- which is what
        // the first real dump looked like. Case-insensitively: the real pool
        // spells it `FLTMGR.SYS`, and a case-sensitive match here silently
        // removed nothing and made the test pass for the wrong reason.
        mods.retain(|m| !m.name.to_ascii_lowercase().contains("fltmgr"));
        pr.undecodable.push((1, 0x40, "DE AD BE EF".into()));
        let lines = check_driver_list(&mods, &pr);
        assert!(
            lines.iter().any(|l| l.contains("did not decode")),
            "an undecodable name must be said out loud: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("do not fit this file")),
            "and must not be blamed on the offsets: {lines:?}"
        );
    }

    #[test]
    fn a_triage_dump_with_an_implausible_driver_count_is_refused() {
        let mut b = synthetic_triage();
        let c = HDR + HDR_COUNT;
        for bad in [0u32, 0xFFFF_FFFF] {
            b[c..c + 4].copy_from_slice(&bad.to_le_bytes());
            let e = parse_triage_drivers(&b).unwrap_err();
            assert!(e.contains("not a plausible count"), "{bad:#x} gave: {e}");
        }
        // And a list that would run past the end of the file is refused too,
        // rather than indexed.
        b[c..c + 4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(parse_triage_drivers(&b).unwrap_err().contains("past the end"));
    }

    /// The string pool is documented as a `u32` count followed by that many
    /// UTF-16 units. Two parsers agreeing on that is not evidence about a
    /// particular file, so the other reading -- a bare NUL-terminated string --
    /// has to degrade to names rather than to mojibake.
    #[test]
    fn a_string_pool_without_length_prefixes_still_yields_names() {
        let mut b = synthetic_triage();
        let pool = u32_at(&b, HDR + HDR_POOL) as usize;
        let list = u32_at(&b, HDR + HDR_LIST) as usize;
        let names = [
            "ntoskrnl.exe",
            "FLTMGR.SYS",
            "hal.dll",
            "\\SystemRoot\\System32\\drivers\\WenleAvFilter.sys",
        ];

        let mut n = pool;
        for (i, name) in names.iter().enumerate() {
            let o = list + i * ENTRY;
            b[o + E_NAME..o + E_NAME + 4].copy_from_slice(&(n as u32).to_le_bytes());
            let u: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            for (k, c) in u.iter().enumerate() {
                b[n + k * 2..n + k * 2 + 2].copy_from_slice(&c.to_le_bytes());
            }
            n += u.len() * 2 + 8;
        }

        let (mods, pr) = parse_triage_drivers(&b).unwrap();
        let got: Vec<&str> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(got, names, "the fallback reading must recover the names");
        // And it must be *reported* as the fallback, so a dump that needs it is
        // distinguishable from one that does not.
        assert_eq!(pr.nul_terminated, 4, "{}", pr.summary());
    }

    #[test]
    fn finds_the_module_that_owns_the_address() {
        let d = parse(&synthetic(0xfffff800_0bf326f0)).unwrap();
        assert_eq!(d.exception_code, Some(0xC000_0005));
        assert_eq!(d.exception_address, Some(0xfffff800_0bf326f0));
        assert_eq!(d.modules.len(), 1);
        assert_eq!(d.modules[0].name, "C:\\x.sys");
        assert_eq!(d.modules[0].size, 0x5000);
        // Read at MINIDUMP_MODULE + 16. If this offset drifts, the dump stops
        // naming its own build and quietly reports a wrong one.
        assert_eq!(d.modules[0].timestamp, 0x6AB8_7FBF);
    }

    /// The module list is not documented as sorted by base, and the old lookup
    /// returned the module *last in list order* with a base at or below the
    /// address. Here the module that contains the address comes **first** and a
    /// module based below it comes second, which is exactly the shape that made
    /// the old code report a loaded driver as not loaded.
    #[test]
    fn an_unsorted_module_list_still_finds_the_owner() {
        let m = |name: &str, base: u64, size: u32| Module {
            name: name.into(),
            base,
            size,
            timestamp: 0,
            entry: 0,
        };
        let d = Dump {
            base: 0,
            stream_count: 0,
            exception_code: Some(0xC000_0005),
            exception_address: Some(0xffff_f802_707e_8417),
            parameters: Vec::new(),
            // fltMgr first, then a module based *below* it: `rev().find` sees
            // ntoskrnl (0xfffff800_0000_0000 <= the address) and stops there.
            modules: vec![
                m("FLTMGR.SYS", 0xffff_f802_7079_0000, 0x9a000),
                m("ntoskrnl.exe", 0xffff_f800_0000_0000, 0x1c00_0000),
            ],
            pool: None,
        };
        assert_eq!(d.describe(0xffff_f802_707e_8417), "FLTMGR.SYS +0x58417");
        assert_eq!(
            d.owner(0xffff_f802_707e_8417).map(|m| m.name.as_str()),
            Some("FLTMGR.SYS"),
            "the module that contains the address is the one named, \
             wherever it sits in the list"
        );

        // Past the end of the highest module below it: the distance is measured
        // from that one, not from whatever came last in the list. fltMgr ends at
        // 0xfffff802_7079_0000 + 0x9a000 = 0xfffff802_7082_a000.
        assert_eq!(
            d.describe(0xffff_f802_7082_b000),
            "NOT IN ANY MODULE -- +0x1000 past the end of FLTMGR.SYS \
             (0xfffff80270790000 + 0x9a000)"
        );
    }

    /// The stamps that identify a build have to be distinct from each other, or
    /// "which build was loaded" is not a question the dump can answer. Two
    /// builds sharing one would make this whole mechanism silently useless.
    #[test]
    fn every_known_build_has_its_own_stamp() {
        let stamps = [
            0x6AB8_7FBF, 0x6AB7_5DBE, 0x6AB7_579A, 0x6AB7_511A, 0x6AB1_B71D,
        ];
        for (i, a) in stamps.iter().enumerate() {
            assert_ne!(*a, 0, "a zero stamp is not a build of ours");
            assert!(
                !build_name(*a).contains("unrecognised"),
                "{a:#010x} is in the list but build_name does not know it"
            );
            for b in &stamps[i + 1..] {
                assert_ne!(a, b, "two builds share a stamp");
            }
        }
        assert!(build_name(0x1234_5678).contains("unrecognised"));
        assert!(is_product("\\SystemRoot\\System32\\drivers\\WenleAvFilter.sys"));
        assert!(is_product("av_amsi.dll"));
        assert!(!is_product("ntoskrnl.exe"), "not everything is ours");
    }

    #[test]
    fn the_command_line_puts_flags_where_they_belong() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string())).unwrap();

        // The form actually used in the VM.
        assert_eq!(
            a(&["--code", "0x3b", "--at", "0xfffff8000bf326f0", "d.dmp"]),
            Args {
                bugcheck: Some(0x3b),
                at: vec![0xffff_f800_0bf3_26f0],
                drivers: Vec::new(),
                frame: None,
                scan: Vec::new(),
                around: None,
                max_hits: None,
                hexdump: Vec::new(),
                len: None,
                files: vec!["d.dmp".into()],
            }
        );
        // The legacy form, and a bare address without 0x.
        assert_eq!(a(&["0x7e", "d.dmp"]).bugcheck, Some(0x7e));
        assert_eq!(a(&["--at", "fffff80431200000", "d.dmp"]).at, vec![0xffff_f804_3120_0000]);
        // Several dumps in one run, which is how the three are read at once.
        assert_eq!(a(&["a.dmp", "b.dmp"]).files, vec!["a.dmp", "b.dmp"]);

        // The regression: `--code` must never be taken for a filename.
        assert!(a(&["--code", "0x3b", "d.dmp"]).files == vec!["d.dmp"]);
        // A leading argument that is not a code is a file, not a code.
        assert_eq!(a(&["d.dmp", "e.dmp"]).bugcheck, None);
        assert!(parse_args(["--code"].iter().map(|s| s.to_string())).is_err());
        assert!(parse_args(["--at", "zzz"].iter().map(|s| s.to_string())).is_err());

        // `--hexdump` takes offsets in hex with or without `0x`, repeatable, and
        // `--len` is separate from `--around` because the two windows are asked
        // for different reasons.
        let got = a(&[
            "--hexdump", "0x10971750", "--hexdump", "10971a00", "--len", "64", "m.dmp",
        ]);
        assert_eq!(got.hexdump, vec![0x1097_1750, 0x1097_1a00]);
        assert_eq!(got.len, Some(64));
        assert_eq!(got.files, vec!["m.dmp"]);
        assert_eq!(got.around, None, "--len must not be read as --around");
        assert!(parse_args(["--hexdump"].iter().map(|s| s.to_string())).is_err());
        assert!(parse_args(["--hexdump", "zz"].iter().map(|s| s.to_string())).is_err());
    }

    /// A window of zero bytes, or one longer than the tool prints, is refused at
    /// the command line rather than truncated at the point of use: both readings
    /// of a shortened window are wrong, and one of them is "nothing is there".
    #[test]
    fn a_window_length_outside_the_range_is_refused_rather_than_clamped() {
        let p = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string()));
        let max = MAX_DUMP_LEN.to_string();
        let over = (MAX_DUMP_LEN + 1).to_string();
        assert!(p(&["--len", "0"]).is_err(), "a zero-byte window prints nothing");
        assert!(p(&["--len", over.as_str()]).is_err());
        assert!(p(&["--len", "abc"]).is_err());
        // The boundary itself is allowed, and the default applies when `--len`
        // is absent: an edge that refuses its own maximum fails only on the one
        // command somebody actually needed.
        assert_eq!(p(&["--len", max.as_str()]).unwrap().len, Some(MAX_DUMP_LEN));
        assert_eq!(p(&["--hexdump", "0x10"]).unwrap().len, None);
        let refused = p(&["--len", "99999"]).unwrap_err();
        assert!(refused.contains("truncated"), "{refused}");
    }

    /// `--frame` takes a value for the same reason `--drivers` does: without one
    /// it would eat the dump's filename, and the run would then report the *file*
    /// as missing rather than the flag as unset.
    #[test]
    fn frame_takes_a_value_and_never_eats_the_filename() {
        let a = |v: &[&str]| parse_args(v.iter().map(|s| s.to_string())).unwrap();
        let got = a(&["--frame", "40", "kept.dmp"]);
        assert_eq!(got.frame, Some(40));
        assert_eq!(got.files, vec!["kept.dmp"]);
        assert_eq!(a(&["d.dmp"]).frame, None, "absent means print no frame");
        assert!(parse_args(["--frame"].iter().map(|s| s.to_string())).is_err());
        assert!(parse_args(["--frame", "kept.dmp"].iter().map(|s| s.to_string())).is_err());
        assert!(parse_args(["--frame", "0x28"].iter().map(|s| s.to_string())).is_err());
    }

    /// A stack window: `size` bytes of virtual address `top`, at file offset 0.
    fn window_of(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    /// A `Dump` whose only job is to resolve addresses, for the frame tests.
    fn resolving_dump() -> Dump {
        Dump {
            base: 0,
            stream_count: 0,
            exception_code: None,
            exception_address: None,
            parameters: Vec::new(),
            modules: vec![Module {
                name: "FAKE.SYS".into(),
                base: 0xffff_f800_2000_0000,
                size: 0x1000,
                timestamp: 0,
                entry: 0,
            }],
            pool: None,
        }
    }

    /// A fault context with values nothing else on a stack would hold, so that an
    /// annotation can only come from a real match.
    fn frame_context(rsp: u64) -> FaultContext {
        FaultContext {
            at: 0,
            // Deliberately *not* the return address at `Rsp`: the two are
            // separate anchors, and a fixture where they coincided could not tell
            // a `Rip` annotation from a return address being mistaken for one.
            rip: 0xffff_f800_2000_0200,
            rsp,
            // `Rsi == Rbp` is the shape the real fault had (`Rsi`, `Rbp` and
            // `R12` all held one pool pointer), and it is what makes a
            // two-register annotation possible to test at all.
            rbp: 0xdddd_0000_0000_0005,
            rax: 0x1111_2222_3333_4444,
            rcx: 0,
            rdx: 0xdddd_0000_0000_0003,
            rbx: 0xdddd_0000_0000_0004,
            rsi: 0xdddd_0000_0000_0005,
            rdi: 0xdddd_0000_0000_0006,
            r8: 0,
            r9: 0xdddd_0000_0000_0007,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            seg_cs: 0x10,
            seg_ss: 0x18,
            eflags: 0x2,
        }
    }

    /// The whole point of `--frame`: the word at `Rsp`, resolved, and *named* when
    /// it is also sitting in one of the fault's registers -- which is how a trap
    /// frame for this fault is found without assuming its field offsets. Byte
    /// offsets here are written out literally; a helper that computed them from
    /// the reader's own arithmetic would move with the reader and detect nothing.
    #[test]
    fn the_frame_names_the_registers_a_word_equals() {
        let top = 0xffff_cb09_91a0_5000u64;
        // 0x200 bytes, so nothing in the printed range runs past the end of the
        // file and the "of the N words" count is decided by `Rsp`'s position
        // alone: 16 words below Rsp are real, the other 4 are before the window.
        let size = 0x200;
        let mut w = window_of(size);
        let c = frame_context(top + 0x80);
        // Rsp: the caller's return address, inside the fake module.
        w[0x80..0x88].copy_from_slice(&0xffff_f800_2000_0100u64.to_le_bytes());
        // The word *below* Rsp holds a value one of the registers also holds --
        // the shape a trap frame copy of this fault makes.
        w[0x70..0x78].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        // Two words in a row hold the value that both `Rsi` and `Rbp` hold, which
        // is what singled the real fault's registers out from ordinary locals.
        w[0x88..0x90].copy_from_slice(&0xdddd_0000_0000_0005u64.to_le_bytes());
        w[0x90..0x98].copy_from_slice(&0xdddd_0000_0000_0005u64.to_le_bytes());
        // And the faulting instruction, two words above that -- the anchor a real
        // trap frame carries. `Rip` is annotated like any other register.
        w[0x98..0xa0].copy_from_slice(&0xffff_f800_2000_0200u64.to_le_bytes());

        let out = frame_lines(&resolving_dump(), &w, top, 0, size, &c, 20).join("\n");
        assert!(out.contains("FAKE.SYS +0x100"), "the return address is resolved: {out}");
        assert!(
            out.contains("== Rax"),
            "the word below Rsp holds Rax's value and must say so: {out}"
        );
        assert!(
            out.contains("== Rsi Rbp"),
            "both registers holding that value are named: {out}"
        );
        assert!(
            out.contains("== Rip"),
            "the faulting instruction is an anchor and must be named as one: {out}"
        );
        assert_eq!(
            out.matches("<- Rsp").count(),
            1,
            "exactly one word is the word at Rsp: {out}"
        );
        // The marker has to be on the *resolved* line, or a shifted index would
        // point at a neighbouring word and still look plausible.
        let rsp_line = out.lines().find(|l| l.contains("<- Rsp")).unwrap_or("");
        assert!(rsp_line.contains("FAKE.SYS +0x100"), "{rsp_line}");
        // The count is stated over exactly the words printed, so a frame with no
        // matches cannot be mistaken for one that was not searched.
        assert!(out.contains("4 of the 37 words"), "four words match: {out}");
        // A value no register holds is printed without a claim.
        assert!(out.contains("0x0000000000000000"), "raw words are printed: {out}");
    }

    /// When `Rsp` is outside the window the honest answer is one line naming the
    /// address -- **not** the "0 of N words" summary, which would report a
    /// searched-and-found-nothing over a range that was never looked at. That is
    /// this tool's oldest failure shape, in the newest feature.
    #[test]
    fn a_frame_outside_the_window_claims_nothing_about_the_window() {
        let top = 0xffff_cb09_91a0_5000u64;
        let w = window_of(0x100);
        let c = frame_context(top + 0x4000);
        let out = frame_lines(&resolving_dump(), &w, top, 0, 0x100, &c, 20).join("\n");
        assert!(out.contains("outside the stack window"), "{out}");
        assert!(!out.contains("of the"), "no count over a range nobody read: {out}");
        assert!(!out.contains("<- Rsp"), "{out}");
    }

    /// Words past the end of the file are skipped rather than read, and the count
    /// that follows says how many were really printed -- a window whose top half
    /// is not in the file must not claim to have searched it.
    #[test]
    fn the_frame_stops_at_the_windows_end() {
        let top = 0xffff_cb09_91a0_5000u64;
        let size = 0x40;
        let mut w = window_of(size);
        // Rsp is the *last* word of the window, so the words above it are not in
        // the file at all.
        let c = frame_context(top + (size as u64 - 8));
        w[size - 8..size].copy_from_slice(&0xffff_f800_2000_0100u64.to_le_bytes());
        let lines = frame_lines(&resolving_dump(), &w, top, 0, size, &c, 3);
        let out = lines.join("\n");
        assert!(out.contains("<- Rsp"), "{out}");
        let words = lines.iter().filter(|l| l.contains('[')).count();
        assert_eq!(words, 4, "only the words that are in the file: {out}");
        assert!(
            out.contains("(0 of the 4 words"),
            "the count must be the words printed, not the range asked for: {out}"
        );
        // And a word *past* the window's end is refused even though the file
        // continues: a word beyond `TopOfStack + SizeOfCallStack` is not captured
        // stack, and printing the file's next bytes as though it were would invent
        // a frame. The bytes inside the window here are zero and everything after
        // them in the file is `0xff`, so a read past the end is unmissable.
        let mut longer = vec![0xffu8; 0x200];
        for byte in longer[0x100..0x140].iter_mut() {
            *byte = 0;
        }
        let c2 = frame_context(top + size as u64 - 8);
        let out2 = frame_lines(&resolving_dump(), &longer, top, 0x100, size, &c2, 3).join("\n");
        assert!(
            !out2.contains("0xffffffffffffffff"),
            "no byte outside the window may be printed as a stack word: {out2}"
        );
        assert!(
            out2.contains("0x0000000000000000"),
            "the window's own bytes are what gets printed: {out2}"
        );
    }

    /// A `--frame` request the dump cannot satisfy must come back as a sentence,
    /// not as nothing: "no frame was printed" and "the frame was empty" are
    /// different findings, and only one of them means the dump is short.
    #[test]
    fn a_frame_request_without_a_window_says_so_instead_of_printing_nothing() {
        let c = frame_context(0xffff_cb09_91a0_5080);
        let out = frame_section(&resolving_dump(), &[], None, &c, Some(40)).join("\n");
        assert!(out.contains("no stack window"), "{out}");
        assert!(out.contains("--frame"), "the flag is echoed back: {out}");
        // Without the flag, nothing is printed at all -- the flag is the only
        // thing that turns this section on.
        assert!(frame_section(&resolving_dump(), &[], None, &c, None).is_empty());
    }

    #[test]
    fn a_rejected_file_says_why() {
        assert!(parse(&[0u8; 8]).unwrap_err().contains("too small"));
        let mut bad = synthetic(0);
        bad[0] = b'X';
        assert!(parse(&bad).unwrap_err().contains("no 'MDMP' signature"));
    }

    /// `NumberParameters` is read out of the file and indexes an array of 15.
    /// The bounds check only covered the first 40 bytes of the stream, so a dump
    /// truncated mid-array read up to 120 bytes past the end and panicked --
    /// which in `main` would have cost every *later* dump in the same run.
    #[test]
    fn a_truncated_exception_stream_reads_only_what_the_file_holds() {
        let mut d = synthetic(0xfffff800_0bf326f0);
        // The exception stream starts at 56 in this layout (header 32 + two
        // 12-byte directory entries); `NumberParameters` is at stream + 32 and
        // the array at stream + 40.
        d[56 + 32..56 + 36].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Cut the file off exactly one parameter in, so the honest answer is 1.
        d.truncate(56 + 40 + 8);

        let parsed = parse(&d).expect("a truncated stream is still parsable");
        assert_eq!(parsed.exception_code, Some(0xC000_0005));
        assert_eq!(parsed.exception_address, Some(0xfffff800_0bf326f0));
        assert_eq!(parsed.parameters.len(), 1, "only one parameter fits");
    }

    /// The per-file isolation in `main`: however one file fails, it must cost
    /// that file and not the rest of the run. Every offset read is
    /// bounds-checked, so no real dump reaches the panic arm -- which is
    /// exactly why it needs a test that does not go through a file.
    #[test]
    fn a_panicking_dump_costs_that_file_and_not_the_run() {
        let ok: std::thread::Result<Result<(), String>> = Ok(Ok(()));
        assert!(!absorb(ok, "a.dmp"));
        assert!(absorb(Ok(Err("bad file".into())), "a.dmp"));
        let panicked = panic::catch_unwind(|| -> Result<(), String> {
            panic!("simulated layout mismatch")
        });
        assert!(panicked.is_err(), "the panic should have been caught");
        assert!(absorb(panicked, "a.dmp"));
    }

    #[test]
    fn an_address_past_the_last_module_is_reported_as_a_hole() {
        let d = parse(&synthetic(0xfffff800_0bff0000)).unwrap();
        assert!(d.owner(0xfffff800_0bff0000).is_none());
        assert!(d.describe(0xfffff800_0bff0000).contains("NOT IN ANY MODULE"));
    }

    /// The case the tool must not get wrong: a `MINIDUMP_HEADER` that is not at
    /// offset 0, because a `DUMP_HEADER64` precedes it. Before this, every RVA
    /// was read from the file start and the module name would have come back as
    /// `<out of range>` -- a wrong answer that still looked like an answer.
    #[test]
    fn a_header_past_a_dump_header64_is_still_parsed() {
        let d = parse(&synthetic_at(0x2000, 0xfffff800_0bf326f0)).unwrap();
        assert_eq!(d.base, 0x2000);
        assert_eq!(d.exception_code, Some(0xC000_0005));
        assert_eq!(d.modules.len(), 1);
        assert_eq!(d.modules[0].name, "C:\\x.sys");
        assert_eq!(
            d.describe(0xfffff800_0bf326f0),
            "C:\\x.sys +0x26f0".to_string()
        );
    }

    /// The bugcheck fields of `DUMP_HEADER64`.
    ///
    /// **This test is a change-detector, not a verification.** It writes the
    /// fields at the same offsets [`parse_kernel_header`] reads them from, so it
    /// cannot tell whether those offsets match the real struct -- it can only
    /// notice if someone edits one side and not the other. That is a restatement,
    /// which is the failure mode this project keeps hitting.
    ///
    /// The only real check on these offsets is the one in `report`: read the
    /// code out of a genuine kernel dump and compare it against the code Event
    /// 1001 recorded for the same crash. Two independent sources agreeing is
    /// evidence; this test is not.
    #[test]
    fn dump_header64_bugcheck_and_parameters() {
        let mut b = vec![0u8; 0x100];
        b[0..4].copy_from_slice(&PAGE.to_le_bytes());
        b[4..8].copy_from_slice(&DU64.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes()); // MachineImageType
        b[0x34..0x38].copy_from_slice(&4u32.to_le_bytes()); // NumberProcessors
        b[0x38..0x3C].copy_from_slice(&0x3Bu32.to_le_bytes()); // BugCheckCode
        b[0x40..0x48].copy_from_slice(&0xC000_0005u64.to_le_bytes());
        b[0x48..0x50].copy_from_slice(&0xfffff804_ae20b080u64.to_le_bytes());
        b[0x50..0x58].copy_from_slice(&0xffff820e_93cfa9e0u64.to_le_bytes());
        b[0x58..0x60].copy_from_slice(&0u64.to_le_bytes());

        let k = parse_kernel_header(&b).expect("a PAGE/DU64 file has a kernel header");
        assert_eq!(k.bugcheck, 0x3B);
        assert_eq!(k.parameters[0], 0xC000_0005);
        assert_eq!(k.parameters[1], 0xfffff804_ae20b080);
        assert_eq!(k.parameters[2], 0xffff820e_93cfa9e0);
        assert_eq!(k.parameters[3], 0);

        // A file that is not a kernel dump at all must not claim to be one.
        let plain = synthetic(0);
        assert!(parse_kernel_header(&plain).is_none());
    }

    /// A `DUMP_HEADER64` whose bugcheck and `EXCEPTION_RECORD64` describe the
    /// same fault, with the record at `record_at`.
    ///
    /// The record's field offsets are written here as **literals**, so that
    /// changing the parser cannot move this fixture with it. The one thing the
    /// fixture and the parser must agree on is the contract itself: a record
    /// whose code and address match the bugcheck parameters is the record of
    /// that fault. That contract is checked against a real dump in `report`,
    /// where the parameters come from Event 1001 and not from this file.
    fn kernel_dump_with_exception(record_at: usize, code: u32, instruction: u64, data: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x2000];
        b[0..4].copy_from_slice(b"PAGE");
        b[4..8].copy_from_slice(b"DU64");
        b[0x38..0x3C].copy_from_slice(&0x3Bu32.to_le_bytes());
        b[0x40..0x48].copy_from_slice(&(code as u64).to_le_bytes());
        b[0x48..0x50].copy_from_slice(&instruction.to_le_bytes());
        write_exception_record(&mut b, record_at, code, instruction, data);
        b
    }

    /// An `EXCEPTION_RECORD64` written into `b` at `at`, field by field, in
    /// **literal** offsets -- the record's own layout, shared by the fixtures but
    /// written out rather than taken from the parser.
    fn write_exception_record(b: &mut [u8], at: usize, code: u32, instruction: u64, data: u64) {
        b[at..at + 4].copy_from_slice(&code.to_le_bytes());
        b[at + 0x10..at + 0x18].copy_from_slice(&instruction.to_le_bytes());
        b[at + 0x18..at + 0x1C].copy_from_slice(&2u32.to_le_bytes());
        b[at + 0x20..at + 0x28].copy_from_slice(&0u64.to_le_bytes()); // read
        b[at + 0x28..at + 0x30].copy_from_slice(&data.to_le_bytes());
    }

    #[test]
    fn the_exception_record_is_found_at_whatever_offset_the_header_puts_it() {
        // Two offsets, neither of them one this tool was told: the scan is the
        // mechanism, so both must be found. This is the property that makes the
        // layout question moot rather than answered by a guess.
        for at in [0x344usize, 0x600] {
            let b = kernel_dump_with_exception(at, 0xC000_0005, 0xfffff801_9e00b080, 0x10);
            let found = find_exception_records(&b, 0xC000_0005);
            assert_eq!(found.len(), 1, "one record at {at:#x}");
            assert_eq!(found[0].at, at);
            assert_eq!(found[0].address, 0xfffff801_9e00b080);
            assert_eq!(found[0].information[1], 0x10);
            assert_eq!(access_kind(&found[0].information), "read");
        }
    }

    #[test]
    fn a_record_whose_instruction_disagrees_with_p2_is_still_returned() {
        // Returned, not dropped: the report has to be able to say "found, and it
        // does not match", which is a different finding from "not found".
        let mut b = kernel_dump_with_exception(0x344, 0xC000_0005, 0xfffff801_9e00b080, 0x10);
        b[0x344 + 0x10..0x344 + 0x18].copy_from_slice(&0xdead_beef_dead_beefu64.to_le_bytes());
        let found = find_exception_records(&b, 0xC000_0005);
        assert_eq!(found.len(), 1);
        assert_ne!(found[0].address, 0xfffff801_9e00b080);
    }

    #[test]
    fn a_header_with_no_exception_record_finds_none() {
        // The absence this project asserted for days without looking. Now it is
        // what the scan returns when there is nothing, which is checkable.
        let mut b = vec![0u8; 0x2000];
        b[0..4].copy_from_slice(b"PAGE");
        b[4..8].copy_from_slice(b"DU64");
        b[0x38..0x3C].copy_from_slice(&0x3Bu32.to_le_bytes());
        assert!(find_exception_records(&b, 0xC000_0005).is_empty());
    }

    #[test]
    fn a_parameter_count_the_information_array_cannot_hold_is_not_a_record() {
        // The one field that could make an unrelated blob pass the code test.
        // `ExceptionInformation` holds 15 entries, so 16 is not a record.
        let mut b = kernel_dump_with_exception(0x344, 0xC000_0005, 0x1000, 0x10);
        b[0x344 + 0x18..0x344 + 0x1C].copy_from_slice(&16u32.to_le_bytes());
        assert!(find_exception_records(&b, 0xC000_0005).is_empty());
    }

    /// A `PAGE`/`DU64` file with a `TRIAGE_DUMP64` directory at 0x2000 holding
    /// `ExceptionOffset`, `CallStackOffset` and `SizeOfCallStack` at **literal**
    /// offsets -- 0x2010, 0x2028, 0x202c -- so the parser cannot move them.
    fn triage_with_pointers(exception: u32, stack: u32, stack_size: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x3000];
        b[0..4].copy_from_slice(b"PAGE");
        b[4..8].copy_from_slice(b"DU64");
        b[0x38..0x3C].copy_from_slice(&0x3Bu32.to_le_bytes());
        b[0x40..0x48].copy_from_slice(&0xC000_0005u64.to_le_bytes());
        b[0x48..0x50].copy_from_slice(&0xfffff801_9e00b080u64.to_le_bytes());
        b[0x2010..0x2014].copy_from_slice(&exception.to_le_bytes());
        b[0x2028..0x202c].copy_from_slice(&stack.to_le_bytes());
        b[0x202c..0x2030].copy_from_slice(&stack_size.to_le_bytes());
        b
    }

    #[test]
    fn the_directorys_pointer_finds_a_record_the_scan_would_miss() {
        // The real case this was written for: the record is past 0x2000, so a
        // scan of the header cannot see it however it steps, and the pointer is
        // the only route to it.
        let at = 0x2080usize;
        let mut b = triage_with_pointers(at as u32, 0, 0);
        write_exception_record(&mut b, at, 0xC000_0005, 0xfffff801_9e00b080, 0x18);

        let (found_at, r) = pointed_exception_record(&b, 0xC000_0005).expect("the pointer is good");
        assert_eq!(found_at, at);
        assert_eq!(r.address, 0xfffff801_9e00b080);
        assert_eq!(r.information[1], 0x18);
        // And the scan of the header, given the same file, finds nothing --
        // which is why the pointer has to be tried first.
        assert!(find_exception_records(&b, 0xC000_0005).is_empty());
    }

    #[test]
    fn a_zero_exception_offset_says_zero_and_not_absent() {
        // "the field is 0" and "the record is not there" are different
        // findings. Printing the second for the first is how this project
        // wasted days.
        let b = triage_with_pointers(0, 0, 0);
        let why = pointed_exception_record(&b, 0xC000_0005).unwrap_err();
        assert!(why.contains("is 0"), "said: {why}");
        assert!(why.contains("ExceptionOffset"), "said: {why}");
    }

    #[test]
    fn a_pointer_at_a_blob_that_is_not_a_record_says_what_it_found() {
        let b = triage_with_pointers(0x2100, 0, 0); // zeros there, not a record
        let why = pointed_exception_record(&b, 0xC000_0005).unwrap_err();
        assert!(why.contains("ExceptionCode"), "said: {why}");
        assert!(why.contains("0x2100"), "said: {why}");
    }

    #[test]
    fn a_pointer_past_the_end_of_the_file_is_refused() {
        let b = triage_with_pointers(0x9000, 0, 0);
        let why = pointed_exception_record(&b, 0xC000_0005).unwrap_err();
        assert!(why.contains("cannot hold"), "said: {why}");
    }

    #[test]
    fn the_call_stack_is_read_from_the_directory() {
        let mut b = triage_with_pointers(0, 0x2200, 24);
        for (i, w) in [0xfffff801_9e017f65u64, 0xfffff801_9e017761, 0x0]
            .iter()
            .enumerate()
        {
            b[0x2200 + i * 8..0x2208 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
        let words = call_stack(&b).expect("a validated window");
        assert_eq!(words, vec![0xfffff801_9e017f65, 0xfffff801_9e017761, 0]);
    }

    #[test]
    fn a_call_stack_size_that_is_not_a_multiple_of_8_is_refused() {
        // The check that catches a wrong field offset: a size that cannot be a
        // count of 8-byte words means the layout does not fit this file.
        let b = triage_with_pointers(0, 0x2200, 20);
        let why = call_stack(&b).unwrap_err();
        assert!(why.contains("not a multiple of 8"), "said: {why}");
    }

    #[test]
    fn a_call_stack_window_past_the_end_of_the_file_is_refused() {
        let b = triage_with_pointers(0, 0x2f00, 0x800);
        let why = call_stack(&b).unwrap_err();
        assert!(why.contains("runs past the end"), "said: {why}");
    }

    /// A `CONTEXT` written at `at` in literal offsets, with `SegCs`/`EFlags` set
    /// to what a real x64 kernel context has so the reader's own checks pass.
    fn write_context(b: &mut [u8], at: usize, rip: u64, rcx: u64, rsp: u64) {
        b[at + 0x38..at + 0x3a].copy_from_slice(&0x10u16.to_le_bytes()); // SegCs
        b[at + 0x42..at + 0x44].copy_from_slice(&0x18u16.to_le_bytes()); // SegSs
        b[at + 0x44..at + 0x48].copy_from_slice(&0x10202u32.to_le_bytes()); // EFlags
        b[at + 0x80..at + 0x88].copy_from_slice(&rcx.to_le_bytes());
        b[at + 0x98..at + 0xa0].copy_from_slice(&rsp.to_le_bytes());
        b[at + 0xf8..at + 0x100].copy_from_slice(&rip.to_le_bytes());
    }

    #[test]
    fn the_contexts_rcx_is_the_argument_the_faulting_instruction_dereferenced() {
        let at = 0x2400usize;
        let mut b = triage_with_pointers(0, 0, 0);
        b[0x200c..0x2010].copy_from_slice(&(at as u32).to_le_bytes()); // ContextOffset @0x0c
        write_context(&mut b, at, 0xfffff801_9e00b080, 0xdead_beef_00000000, 0xffffcb09_91a05800);

        let found_at = pointed_context_offset(&b).expect("the directory names a context");
        let c = fault_context_at(&b, found_at, 0xfffff801_9e00b080).expect("a validated context");
        assert_eq!(found_at, at);
        assert_eq!(c.rcx, 0xdead_beef_00000000);
        assert_eq!(c.rsp, 0xffffcb09_91a05800);
        assert_eq!(c.rip, 0xfffff801_9e00b080);
        assert_eq!(c.seg_cs, 0x10);
    }

    #[test]
    fn a_context_whose_rip_is_not_the_faulting_instruction_is_refused() {
        // The check that makes the reader safe to believe: a context for a
        // different thread or a different moment would otherwise print as this
        // fault's registers.
        let at = 0x2400usize;
        let mut b = triage_with_pointers(0, 0, 0);
        b[0x200c..0x2010].copy_from_slice(&(at as u32).to_le_bytes());
        write_context(&mut b, at, 0xfffff801_9e00b999, 0x1, 0x2);
        let why = fault_context_at(&b, at, 0xfffff801_9e00b080).unwrap_err();
        assert!(why.contains("not** the faulting"), "said: {why}");
    }

    #[test]
    fn a_context_that_is_not_the_faults_can_still_be_read_as_what_it_is() {
        // The split this needed: the `Rip` comparison says a context is not this
        // fault's, and `context_at` still reads its registers. Without that split
        // the only thing a wrong context could produce was an error, and the
        // finding -- "the directory names the *bugcheck's* context" -- could not
        // be stated at all.
        let at = 0x2400usize;
        let mut b = triage_with_pointers(0, 0, 0);
        write_context(&mut b, at, 0xfffff801_9e2fd130, 0xabc, 0xffffcb09_91a05088);
        assert!(fault_context_at(&b, at, 0xfffff801_9e00b080).is_err());
        let any = context_at(&b, at).expect("a well-formed CONTEXT either way");
        assert_eq!(any.rip, 0xfffff801_9e2fd130);
        assert_eq!(any.rsp, 0xffffcb09_91a05088);
    }

    #[test]
    fn a_blob_without_the_kernel_code_selector_is_not_a_context() {
        // `SegCs` is the field a wrong layout cannot fake: 0x10 is the x64
        // kernel code selector, and a blob of zeros gives 0.
        let b = triage_with_pointers(0, 0, 0);
        let why = fault_context_at(&b, 0x2400, 0xfffff801_9e00b080).unwrap_err();
        assert!(why.contains("SegCs"), "said: {why}");
    }

    #[test]
    fn a_zero_context_offset_says_zero_and_not_absent() {
        let b = triage_with_pointers(0, 0, 0);
        let why = pointed_context_offset(&b).unwrap_err();
        assert!(why.contains("is 0"), "said: {why}");
        assert!(why.contains("ContextOffset"), "said: {why}");
    }

    /// A `PAGE`/`DU64` triage file with a raw stack window: `TopOfStack` written
    /// at the **literal** 0x2048, the window at file `at` covering `size` bytes,
    /// and `ContextOffset` naming `exception_at`. All offsets literal, so a
    /// constant moved in the parser cannot move them too.
    fn triage_with_stack(top: u64, at: u32, size: u32, exception_at: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x4000];
        b[0..4].copy_from_slice(b"PAGE");
        b[4..8].copy_from_slice(b"DU64");
        b[0x38..0x3C].copy_from_slice(&0x3Bu32.to_le_bytes());
        b[0x40..0x48].copy_from_slice(&0xC000_0005u64.to_le_bytes());
        b[0x48..0x50].copy_from_slice(&0xfffff801_9e00b080u64.to_le_bytes());
        b[0x2010..0x2014].copy_from_slice(&exception_at.to_le_bytes());
        b[0x2028..0x202c].copy_from_slice(&at.to_le_bytes());
        b[0x202c..0x2030].copy_from_slice(&size.to_le_bytes());
        b[0x2048..0x2050].copy_from_slice(&top.to_le_bytes());
        b
    }

    const WINDOW_TOP: u64 = 0xffff_cb09_91a0_5088;
    const WINDOW_AT: usize = 0x2400;
    const WINDOW_SIZE: usize = 0x800;
    const FAULT_RIP: u64 = 0xffff_f801_9e00_b080;

    #[test]
    fn the_faults_own_context_comes_out_of_the_stack_window() {
        // The real shape: the directory names a *valid* context whose `Rip` is in
        // the crash path, and the fault's own copy is further up the same stack.
        // Both are in the file; only one is about the fault.
        let mut b = triage_with_stack(WINDOW_TOP, WINDOW_AT as u32, WINDOW_SIZE as u32, 0x2200);
        write_context(&mut b, 0x2200, 0xfffff801_9e2fd130, 0x1111, 0x2222); // the bugcheck's
        let rsp = WINDOW_TOP + 0x180;
        write_context(&mut b, WINDOW_AT + 0x100, FAULT_RIP, 0xdead_beef_00000000, rsp);

        // The directory's is refused, and named as a different moment's.
        let why = fault_context_at(&b, 0x2200, FAULT_RIP).unwrap_err();
        assert!(why.contains("not** the faulting"), "said: {why}");

        let found = contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP);
        assert_eq!(found.len(), 1, "found {found:?}");
        assert_eq!(found[0].0, WINDOW_TOP + 0x100);
        assert_eq!(found[0].1.rcx, 0xdead_beef_00000000);
        assert_eq!(found[0].1.rsp, rsp);
    }

    #[test]
    fn a_window_context_with_a_different_rip_is_not_the_faults() {
        // The scan must not match on shape alone: a `CONTEXT` in the window that
        // belongs to some other moment has to be refused, or the first plausible
        // blob in the window would be printed as this fault's registers.
        let mut b = triage_with_stack(WINDOW_TOP, WINDOW_AT as u32, WINDOW_SIZE as u32, 0x2200);
        write_context(&mut b, WINDOW_AT + 0x100, 0xfffff801_9e00b999, 0x1, 0x2);
        assert!(contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP).is_empty());
        // ... but it *is* a context, so the emptiness above is about the `Rip`
        // and not about the blob failing the layout checks.
        assert!(context_at(&b, WINDOW_AT + 0x100).is_ok());
    }

    #[test]
    fn a_parameter_naming_the_context_lands_where_the_scan_finds_it() {
        // The two routes accept on identical terms, so a bugcheck parameter that
        // carries the context record's address has to resolve to the same bytes
        // the scan reports -- otherwise one of them is reading a different layout.
        let mut b = triage_with_stack(WINDOW_TOP, WINDOW_AT as u32, WINDOW_SIZE as u32, 0x2200);
        let ctx_va = WINDOW_TOP + 0x100;
        write_context(&mut b, WINDOW_AT + 0x100, FAULT_RIP, 0xdead_beef_00000000, 0x40);
        b[0x50..0x58].copy_from_slice(&ctx_va.to_le_bytes()); // p3

        let off = window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, ctx_va).expect("p3 is in it");
        assert_eq!(off, WINDOW_AT + 0x100);
        let by_parameter = fault_context_at(&b, off, FAULT_RIP).expect("same acceptance test");
        let by_scan = contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP);
        assert_eq!(by_scan.len(), 1);
        assert_eq!(by_parameter, by_scan[0].1);
    }

    #[test]
    fn the_word_at_the_contexts_rsp_is_the_return_address_the_fault_pushed() {
        // The payload: a fault on a function's *first* instruction leaves the
        // caller's return address as the first word at `Rsp`, so this is what
        // turns "one of six call sites" into a name.
        let mut b = triage_with_stack(WINDOW_TOP, WINDOW_AT as u32, WINDOW_SIZE as u32, 0x2200);
        let rsp_va = WINDOW_TOP + 0x180;
        let ret = 0xffff_f801_2f7f_7768u64; // fltMgr, just past a call
        write_context(&mut b, WINDOW_AT + 0x100, FAULT_RIP, 0xdead_beef, rsp_va);
        b[WINDOW_AT + 0x180..WINDOW_AT + 0x188].copy_from_slice(&ret.to_le_bytes());

        let found = contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP);
        let off = window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, found[0].1.rsp).expect("in it");
        assert_eq!(u64_at(&b, off), ret);
    }

    #[test]
    fn the_windows_ends_are_half_open() {
        // `TopOfStack` is the address of the window's *first* byte and the window
        // covers `SizeOfCallStack` bytes, so the last addressable byte is
        // `top + size - 1`. An off-by-one here would silently drop the context a
        // bugcheck parameter points at when it sits at either end.
        assert_eq!(window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, WINDOW_TOP), Some(WINDOW_AT));
        assert_eq!(
            window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, WINDOW_TOP + WINDOW_SIZE as u64 - 1),
            Some(WINDOW_AT + WINDOW_SIZE - 1)
        );
        assert_eq!(window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, WINDOW_TOP + WINDOW_SIZE as u64), None);
        assert_eq!(window_offset(WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, WINDOW_TOP - 1), None);
    }

    #[test]
    fn a_window_with_no_context_for_this_fault_says_so_from_a_full_scan() {
        // "There is no context for this fault" is a claim about a scan that ran;
        // the window in this file is 0x800 bytes of zeros, and the only context
        // in the whole file is one whose `Rip` is elsewhere.
        let mut b = triage_with_stack(WINDOW_TOP, WINDOW_AT as u32, WINDOW_SIZE as u32, 0x2200);
        write_context(&mut b, 0x2200, 0xfffff801_9e2fd130, 0x1, 0x2);
        assert!(contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP).is_empty());
        // And the window really was read: a context planted at its last valid
        // position is found, so the emptiness above is not a scan that never ran.
        write_context(&mut b, WINDOW_AT + WINDOW_SIZE - 0x100, FAULT_RIP, 0x7, 0x8);
        assert_eq!(
            contexts_in_stack(&b, WINDOW_TOP, WINDOW_AT, WINDOW_SIZE, FAULT_RIP).len(),
            1
        );
    }

    // -- byte-pattern scanning (`--scan`) ----------------------------------

    /// The first twelve bytes of `fltMgr!FltGetRequestorProcess`, the function
    /// whose return address sat 5 bytes past its `call` on the faulting stack.
    fn fltmgr_prefix() -> Vec<u8> {
        parse_hex_bytes("4883ec288b01a8017419").unwrap()
    }

    #[test]
    fn hex_byte_patterns_are_read_with_or_without_separators() {
        let want = vec![0x48, 0x83, 0xec, 0x28];
        assert_eq!(parse_hex_bytes("4883ec28").unwrap(), want);
        assert_eq!(parse_hex_bytes("48 83 ec 28").unwrap(), want);
        assert_eq!(parse_hex_bytes("48-83-EC-28").unwrap(), want);
        assert_eq!(parse_hex_bytes("0x4883EC28").unwrap(), want);
    }

    #[test]
    fn a_pattern_with_an_odd_digit_count_is_an_error_not_a_short_needle() {
        // A truncated needle searches for the wrong bytes and answers "no
        // hits", which is indistinguishable from a real negative -- and "no
        // hits" is the answer that decides whether the running image is the
        // file on disk. So this has to be an error, and it has to be one the
        // user sees, not a warning in a comment.
        let e = parse_hex_bytes("4883ec2").unwrap_err();
        assert!(e.contains("odd"), "{e}");
        assert!(parse_hex_bytes("4883ec2g").is_err());
        assert!(parse_hex_bytes("").is_err());
        assert!(parse_hex_bytes("   ").is_err());
    }

    #[test]
    fn a_pattern_at_offset_zero_is_found() {
        let needle = fltmgr_prefix();
        let mut data = needle.clone();
        data.extend_from_slice(&[0xAA; 40]);
        let mut r: &[u8] = &data;
        assert_eq!(
            find_hits(&mut r, &[needle.clone()], 16).unwrap(),
            vec![Hit { pattern: 0, offset: 0 }]
        );
    }

    #[test]
    fn a_pattern_that_straddles_a_read_boundary_is_found() {
        // The needle starts 3 bytes before the 16-byte read boundary, so no
        // single piece of the file contains it. A scan that did not carry the
        // tail forward would call the running image "not this file".
        let needle = fltmgr_prefix();
        assert!(needle.len() > 3);
        let mut data = vec![0u8; 13];
        data.extend_from_slice(&needle);
        data.extend_from_slice(&[0u8; 32]);
        let mut r: &[u8] = &data;
        assert_eq!(
            find_hits(&mut r, &[needle], 16).unwrap(),
            vec![Hit { pattern: 0, offset: 13 }]
        );
    }

    #[test]
    fn a_hit_inside_the_carried_bytes_is_not_reported_twice() {
        // Two needles of different lengths is what makes the carry longer than
        // the shorter needle. The 10-byte needle carries 9 bytes forward, so a
        // later piece starts at offset 7 while the first piece ran to offset 16.
        // A 5-byte hit at 8 ends at 13: inside the first piece, so that piece
        // finds it, and also inside the carried region, so the second piece
        // finds it again. The count is what the user reads, so it has to be one.
        //
        // The offset is not free: 8 is the first multiple-of-16 boundary minus
        // the needle lengths that satisfies both. Written at 6 this test passed
        // with the dedup deleted -- 6 is before the carry, so there was no
        // duplicate to remove, and the test was checking nothing. Verified by
        // deleting the `dedup_by` line and watching this fail with [8, 8].
        let long = fltmgr_prefix();
        let short = parse_hex_bytes("0f1f440000").unwrap();
        assert!(!long.windows(short.len()).any(|w| w == &short[..]));
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&short);
        data.extend_from_slice(&[0u8; 40]);
        let long_at = data.len() as u64;
        data.extend_from_slice(&long);
        let mut r: &[u8] = &data;
        let hits = find_hits(&mut r, &[long, short], 16).unwrap();
        let of = |p: usize| -> Vec<u64> {
            hits.iter().filter(|h| h.pattern == p).map(|h| h.offset).collect()
        };
        assert_eq!(of(1), vec![8]);
        assert_eq!(of(0), vec![long_at]);
    }

    #[test]
    fn every_occurrence_of_an_overlapping_pattern_is_counted() {
        // Four zero bytes in a run of zeros match once per offset, which is why
        // `--max` exists and why the total is printed separately: the count is
        // the answer, the listing is not.
        let data = vec![0u8; 64];
        let mut r: &[u8] = &data;
        let hits = find_hits(&mut r, &[vec![0, 0, 0, 0]], 16).unwrap();
        assert_eq!(hits.len(), 64 - 4 + 1);
    }

    #[test]
    fn an_absent_pattern_reports_no_hits() {
        // The negative has to be trustworthy, so it is taken from a scan that
        // really ran over the whole input, not from an empty one.
        let needle = fltmgr_prefix();
        let data = vec![0u8; 4096];
        let mut r: &[u8] = &data;
        assert!(find_hits(&mut r, &[needle], 16).unwrap().is_empty());
    }

    // -- reading bytes at an offset (`--hexdump`) ---------------------------

    /// The other half of a scan: a hit says *where* to look, and only the bytes
    /// say *what is there*. A hit's residue rule can say a page is this file's,
    /// but a page that is present and *different* -- patched in memory -- shows
    /// up only here. A window that ran past the end comes back short and the
    /// callers print that count: padding to the length asked for would print
    /// bytes the file does not have, which is the one thing this mode is for.
    #[test]
    fn a_read_window_returns_the_bytes_it_has_and_invents_none() {
        use std::io::Cursor;
        let data: Vec<u8> = (0u8..=255).collect();
        let mut c = Cursor::new(&data);
        assert_eq!(read_window(&mut c, 0x10, 4).unwrap(), vec![0x10, 0x11, 0x12, 0x13]);
        // Past the end of the file, but starting inside it.
        assert_eq!(read_window(&mut c, 0xFE, 8).unwrap(), vec![0xFE, 0xFF]);
        assert!(read_window(&mut c, 0x100, 1).unwrap().is_empty());
        // Seeking back is not assumed: the second read above starts at a lower
        // offset than where the first one left the cursor.
        assert_eq!(read_window(&mut c, 0, 2).unwrap(), vec![0, 1]);
    }

    /// An offset past the end is an error naming the size, never an empty print.
    /// `--hexdump` is asked "is this page in the dump"; a window that printed
    /// nothing would read as *no* while meaning *wrong offset* -- the same silent
    /// negative the `--scan` help exists to prevent.
    #[test]
    fn an_offset_past_the_end_names_the_size_instead_of_printing_nothing() {
        let why = window(0x1000, 0x1000, 0x40).unwrap_err();
        assert!(why.contains("4096-byte file"), "{why}");
        assert!(why.contains("past the end"), "{why}");
        // The sentence has to be usable: it names where the file's last page
        // starts, so the next attempt is a different number rather than a guess.
        assert!(why.contains("last page starts at 0x0"), "{why}");
        let why2 = window(0x2300, 0x3000, 0x40).unwrap_err();
        assert!(why2.contains("last page starts at 0x2000"), "{why2}");
    }

    /// A window that reaches the end is shortened and the caller prints how
    /// short, and the last byte of the file is addressable.
    #[test]
    fn a_window_that_reaches_the_end_is_short_rather_than_refused() {
        assert_eq!(window(0x1000, 0xFF0, 0x40).unwrap(), (0xFF0, 0x10));
        assert_eq!(window(0x1000, 0, 0x40).unwrap(), (0, 0x40));
        // Exactly the end: the offset of the last byte of the window is
        // `size - len`, and refusing it would fail on the one page somebody
        // asked about.
        assert_eq!(window(0x1000, 0x1000 - 0x40, 0x40).unwrap(), (0xFC0, 0x40));
        assert_eq!(window(0x1000, 0xFFF, 0x40).unwrap(), (0xFFF, 1));
    }

    /// The marker line has to sit *under* the byte it marks. Two windows at
    /// different offsets can only be compared column by column if the rows are
    /// aligned to the file's 16-byte boundaries, which is the property that makes
    /// "present but different" visible at all.
    #[test]
    fn the_marker_line_sits_under_the_byte_it_marks() {
        let bytes: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".to_vec(); // 32
        let rows = hex_rows(0x1000, &bytes, &|off| off == 0x1003);
        assert_eq!(rows.len(), 3, "two hex rows and one marker row: {rows:?}");
        let col = 14 + 3 * 3;
        assert_eq!(&rows[0][col..col + 2], "44", "the byte at 0x1003 is 'D'");
        assert_eq!(&rows[1][col..col + 2], "^^", "the mark is in that column");
        assert!(rows[0].contains("|ABCDEFGHIJKLMNOP|"), "{:?}", rows[0]);
        // A window with nothing marked prints no marker line at all, rather than
        // an empty one that could be read as "marked, but the byte is blank".
        let none = hex_rows(0x1000, &bytes, &|_| false);
        assert_eq!(none.len(), 2, "{none:?}");
    }

    /// A window whose offset is not 16-aligned begins at the boundary below it,
    /// and the bytes before the offset print as blanks -- not as bytes the file
    /// does not have there.
    #[test]
    fn a_window_that_starts_mid_row_still_lines_up() {
        let bytes = vec![0xAAu8; 8];
        let rows = hex_rows(0x1005, &bytes, &|off| off == 0x1005);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows[0].starts_with("    00001000  "), "{:?}", rows[0]);
        assert!(rows[0][14..14 + 15].trim().is_empty(), "{:?}", rows[0]);
        assert_eq!(&rows[0][14 + 15..14 + 18], "aa ");
        let col = 14 + 3 * 5;
        assert_eq!(&rows[1][col..col + 2], "^^");
        // An empty window prints no rows: an empty print in this mode would be
        // indistinguishable from a page that is not in the dump.
        assert!(hex_rows(0x1000, &[], &|_| true).is_empty());
    }
}
