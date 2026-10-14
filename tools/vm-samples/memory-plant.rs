//! A process that holds, in its memory, bytes this engine convicts.
//!
//! Round C's acceptance list has one item about a running process being stopped
//! where it stands, and this is the sample for it. It has two shapes, because
//! the product has two, and the difference between them is the whole point of
//! the item rather than a detail of it.
//!
//! ```text
//! memory-plant.exe              an anonymous page, nothing on disk behind it
//! memory-plant.exe <file>       a file on disk, mapped executable and writable
//! ```
//!
//! # The two shapes, and why they do not get the same answer
//!
//! `av_service::process_watch::stop_if_justified` stops a process only when a
//! finding points at a **file** that is malicious in its own right, and it says
//! why in a test named
//! `injected_code_is_reported_and_the_process_is_not_killed_for_it`: a region no
//! file backs says nothing about which program wrote those bytes, so the process
//! holding them could be the victim. That is the first mode. It is a real
//! detection, it is reported, and the process is deliberately left alone.
//!
//! The second mode is what the stop is for. A file that is malicious on its own
//! evidence, mapped into a process executable *and* writable, is the shape of a
//! loader: `av_memory::region::classify` passes over a normally loaded image
//! (`Skip::BackedByFile`), so a program whose own `.text` contains the pattern
//! is invisible to the memory walk. What the walk does read is a region that is
//! executable and writable whatever backs it -- `Interest::WritableCode` -- and
//! for a mapped file the kernel names that file, which is `Origin::File`, which
//! is what makes the finding actionable rather than merely interesting.
//!
//! # Why the pattern is obscured rather than merely split
//!
//! The first build kept the literal out of the source by writing it as three
//! adjacent fragments -- and the **built sample contained it anyway**, readable
//! at one offset in `.rodata`, because LLVM packs string constants together.
//! `black_box` on each fragment did not change that. Both were measured.
//!
//! That mattered more than it first looked: this product's own realtime watcher
//! scans a file when it appears, so a sample that carries the signature in the
//! clear is a sample **this product quarantines the moment it is copied into
//! the machine running the test**. The payload is therefore stored XORed and
//! rebuilt through a volatile read, which is what the compiler will not fold
//! back into the literal.
//!
//! Obscured, not encrypted: the key is right here and the sample is not hiding
//! from anyone. What it must not do is contain the pattern in the clear.
//!
//! The host's own antivirus is a separate matter and a much weaker one -- with
//! EICAR in its overlay, `block-test.exe` has sat in the deploy directory for a
//! month untouched -- but the file written in file mode is padded anyway, since
//! a file that *is* EICAR is a file Defender really does remove.
//!
//! # What a pass looks like
//!
//! | mode | expected |
//! |---|---|
//! | no argument | the process keeps running; the report (and the log) names the finding and says no file was taken |
//! | with a file | the process is gone within a second or two, the file is in the vault, and a toast has been shown |
//!
//! Neither mode prints a heartbeat after the first second if it worked, which is
//! why the heartbeat exists: a console window that closed on its own looks
//! exactly like a crash, a mistyped path, or a sample that never ran.

#![windows_subsystem = "console"]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_SIZE: usize = 4096;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
/// Required for an executable section, and the one that is easy to leave out.
///
/// Measured on this machine, because the failure does not look like this cause:
/// `CreateFileMappingW(PAGE_EXECUTE_READWRITE)` on a handle opened
/// `GENERIC_READ | GENERIC_WRITE` fails with **access denied**, which reads as a
/// permissions problem rather than as a missing right. Adding `GENERIC_EXECUTE`
/// is what makes it succeed.
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// What `MapViewOfFile` wants for an executable view, and what it must not be
/// given.
///
/// `FILE_MAP_ALL_ACCESS` is the obvious argument and it is the wrong one: on a
/// section created `PAGE_EXECUTE_READWRITE` it produces a view whose protection
/// `VirtualQuery` reports as `0x04`, plain read-write, and 8,192 bytes of the
/// file become a region `classify` passes over as not-executable. Measured on
/// this machine: `FILE_MAP_EXECUTE | FILE_MAP_WRITE` gives `protect=0x40` /
/// `type=0x40000` -- `MEM_MAPPED` and `PAGE_EXECUTE_READWRITE`, which is
/// `Interest::WritableCode`, which is what the memory walk reads.
const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_EXECUTE: u32 = 0x0020;

type Handle = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        address: *const u8,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut u8;

    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template: Handle,
    ) -> Handle;

    fn CreateFileMappingW(
        file: Handle,
        attributes: *const c_void,
        protect: u32,
        maximum_size_high: u32,
        maximum_size_low: u32,
        name: *const u16,
    ) -> Handle;

    fn MapViewOfFile(
        mapping: Handle,
        desired_access: u32,
        offset_high: u32,
        offset_low: u32,
        bytes_to_map: usize,
    ) -> *mut c_void;
}

/// The bytes the engine convicts, XORed so that nothing on disk carries them.
const OBSCURED: [u8; 68] = [
    0x02, 0x6F, 0x15, 0x7B, 0x0A, 0x7F, 0x1A, 0x1B, 0x0A, 0x01, 0x6E, 0x06, 0x0A, 0x00, 0x02, 0x6F,
    0x6E, 0x72, 0x0A, 0x04, 0x73, 0x6D, 0x19, 0x19, 0x73, 0x6D, 0x27, 0x7E, 0x1F, 0x13, 0x19, 0x1B,
    0x08, 0x77, 0x09, 0x0E, 0x1B, 0x14, 0x1E, 0x1B, 0x08, 0x1E, 0x77, 0x1B, 0x14, 0x0E, 0x13, 0x0C,
    0x13, 0x08, 0x0F, 0x09, 0x77, 0x0E, 0x1F, 0x09, 0x0E, 0x77, 0x1C, 0x13, 0x16, 0x1F, 0x7B, 0x7E,
    0x12, 0x71, 0x12, 0x70,
];

/// The key the payload is stored under. Not a secret; see the note at the top.
const KEY: u8 = 0x5A;

/// The bytes the engine convicts, rebuilt so that no intermediate form of them
/// is a constant the compiler can put in the binary.
fn planted_pattern() -> Vec<u8> {
    let mut pattern = Vec::with_capacity(OBSCURED.len());
    for index in 0..OBSCURED.len() {
        // SAFETY: `index` is in range by construction.
        //
        // `read_volatile` is load-bearing rather than decorative: with a plain
        // read the whole loop is a constant and LLVM writes the decoded pattern
        // into `.rodata`, which is the exact thing the obfuscation is for. A
        // volatile load is observable, so it cannot be folded away.
        let byte = unsafe { std::ptr::read_volatile(&OBSCURED[index]) };
        pattern.push(byte ^ KEY);
    }
    pattern
}

/// The body of the file the second mode maps.
///
/// Padded, because EICAR in a file that *is* EICAR is a file this host's own
/// antivirus removes -- which would make the sample fail for a reason that has
/// nothing to do with the product.
///
/// The padding is `nop` bytes and not `'A'`, and the reason is known rather
/// than merely measured. The rule that convicts this pattern is
/// `TRELLIX_ARC_Malw_Eicar`, whose only string is declared `fullword ascii`;
/// `fullword` is satisfied only when the bytes on **both** sides of the match
/// are non-word, where a word byte is `[A-Za-z0-9_]` (see
/// `av-rules/src/matcher/mod.rs`, and `text.rs`'s `is_whole_word`). A fill of
/// `'A'` or `'B'` puts a word byte against the pattern and suppresses the
/// match, and so does a random fill that happens to land on a letter at that
/// one position. `0x90`, `0x00`, `0x01`, `0x20` and `0xFF` are all non-word,
/// so they match.
///
/// Measured 2026-10-10 and explained 2026-10-11: a 4,096-byte file of `'A'` is
/// not convicted, and the same file with the two bytes neighbouring the
/// pattern forced to `0x00` is. So this is the vendored rule's own modifier
/// doing what it says, not an engine defect — and a fixture whose whole purpose
/// is to be convicted has to be built on a fill that lets the rule fire.
fn file_body() -> Vec<u8> {
    let mut body = vec![0x90u8; PAGE_SIZE];
    body.extend_from_slice(&planted_pattern());
    body
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Wait, saying what the wait means, so a dead process cannot be mistaken for a
/// crash. Never returns under its own power in a run that is going well.
fn heartbeat() -> ! {
    for tick in 1..=600u32 {
        std::thread::sleep(Duration::from_secs(1));
        println!("alive {tick}");
    }
    std::process::exit(0)
}

/// The injected-code shape: bytes in a page no file backs.
fn plant_anonymous() {
    // SAFETY: a null requested address asks the system to choose one, the size
    // is one page, and the result is checked before anything writes through it.
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            PAGE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if page.is_null() {
        eprintln!(
            "memory-plant: VirtualAlloc failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // SAFETY: `page` is a freshly committed page of `PAGE_SIZE` bytes that
    // nothing else refers to. `0x90` is `nop`, so the region is executable
    // throughout, and the pattern goes in the middle.
    unsafe {
        std::ptr::write_bytes(page, 0x90, PAGE_SIZE);
        let pattern = planted_pattern();
        std::ptr::copy_nonoverlapping(pattern.as_ptr(), page.add(PAGE_SIZE / 2), pattern.len());
    }

    println!(
        "memory-plant: pid {} holds a {PAGE_SIZE}-byte executable page at {page:p}",
        std::process::id()
    );
    println!(
        "memory-plant: no file on disk holds these bytes, so the product must find the finding \
         and leave this process alone. If this process disappears, that is a defect."
    );
    heartbeat()
}

/// The dropped-file shape: a malicious file on disk, mapped executable and
/// writable.
fn plant_mapped(path: &Path) {
    if !path.is_file() {
        if let Err(e) = std::fs::write(path, file_body()) {
            eprintln!("memory-plant: could not write {}: {e}", path.display());
            std::process::exit(1);
        }
        println!(
            "memory-plant: wrote {} ({} bytes, the pattern after {PAGE_SIZE} of padding)",
            path.display(),
            file_body().len()
        );
    }

    let name = wide(path);
    // SAFETY: `name` is a NUL-terminated wide string owned by this frame, the
    // remaining arguments are the documented constants for opening an existing
    // file, and every handle below is checked before use. The share mode denies
    // write and delete for as long as this process lives, which is deliberate:
    // it keeps the file where the memory finding says it is, so that what is
    // being tested is the stop rather than a race with the vault.
    //
    // `GENERIC_EXECUTE` is in the mask for the reason recorded on its
    // definition: without it the mapping below is refused as access denied.
    let file = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if file as isize == -1 {
        eprintln!(
            "memory-plant: could not open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // SAFETY: `file` is a handle to the file just opened, held open for the life
    // of this process; the protection is the one this mode exists to ask for.
    let mapping = unsafe {
        CreateFileMappingW(
            file,
            std::ptr::null(),
            PAGE_EXECUTE_READWRITE,
            0,
            0,
            std::ptr::null(),
        )
    };
    if mapping.is_null() {
        eprintln!(
            "memory-plant: could not create the mapping: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // SAFETY: `mapping` is the section just created, and the view is for the
    // whole of it, which is one page plus the pattern. The access mask is the
    // measured one from the constants above, not `FILE_MAP_ALL_ACCESS`.
    let view = unsafe {
        MapViewOfFile(
            mapping,
            FILE_MAP_EXECUTE | FILE_MAP_WRITE,
            0,
            0,
            0,
        )
    };
    if view.is_null() {
        eprintln!(
            "memory-plant: could not map a view: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    println!(
        "memory-plant: pid {} maps {} executable and writable at {view:p}",
        std::process::id(),
        path.display()
    );
    println!(
        "memory-plant: the file is malicious on its own evidence and this region is attributed \
         to it, so the product must stop this process, take the file, and say so."
    );
    heartbeat()
}

fn main() {
    match std::env::args_os().nth(1) {
        Some(path) => plant_mapped(Path::new(&path)),
        None => plant_anonymous(),
    }
}
