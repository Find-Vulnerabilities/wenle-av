//! A harmless stand-in for a trojan, for measuring the behaviour monitor.
//!
//! It does the four things the driver's telemetry is supposed to see, and
//! nothing else:
//!
//! * renames forty files in a burst, to an extension ransomware leaves behind,
//!   which is BEH-0001 and BEH-0003;
//! * deletes seventy files in a burst, which is BEH-0004;
//! * sets and then removes a value under the per-user `Run` key, which is
//!   BEH-0010;
//! * renames a file into the per-user Startup folder and removes it again,
//!   which is BEH-0007;
//! * drops one ordinary text file in `%APPDATA%`, `%PUBLIC%`, `%ProgramData%`
//!   and, when writable, `C:\Windows\Temp`, then removes them — the "a trojan
//!   writes files in system folders" shape, without a payload.
//!
//! Started from `%TEMP%` it is also BEH-0033 (a process started from a
//! temporary folder).
//!
//! # What it never does
//!
//! It does not encrypt, open a socket, write outside its own scratch
//! directory except for the two renames and one registry value listed above,
//! or leave anything behind. Every path it touches is removed before it exits,
//! including on the failure paths. It is not a dropper: the files it writes
//! are four bytes of text.
//!
//! # Why the strings are assembled at run time
//!
//! The product scans the image before the driver lets it execute. A file whose
//! bytes carry a persistence path and a ransomware extension is exactly what
//! the 10,764-rule database is for, and a static conviction would stop the
//! fixture at the gate — where the behaviour engine never sees an event. So
//! the `Run` key, the Startup folder and the extension are built from two or
//! three pieces each. Check before shipping it to a guest:
//!
//! ```text
//! wenle scan behtest.exe            # must not be malicious
//! ```
//!
//! Build: rustc --edition 2021 -O -C target-feature=+crt-static -o tools/behtest.exe tools/behtest.rs
//! Test:  rustc --edition 2021 --test -O -C target-feature=+crt-static -o tools/behtest-test.exe tools/behtest.rs && ./tools/behtest-test.exe
//!
//! Usage: behtest.exe [--files] [--registry] [--startup] [--scatter] [--all]
//!
//! With no arguments every stage runs. One stage at a time is the way to
//! attribute a log line: `--registry` alone touches nothing but one value.

use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};

#[link(name = "advapi32")]
extern "system" {
    fn RegSetKeyValueW(
        hkey: isize,
        subkey: *const u16,
        value: *const u16,
        ty: u32,
        data: *const c_void,
        cb: u32,
    ) -> i32;
    fn RegDeleteKeyValueW(hkey: isize, subkey: *const u16, value: *const u16) -> i32;
}

/// `HKEY_CURRENT_USER`, as the pre-defined handle rather than an opened one.
const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
const REG_SZ: u32 = 1;

const RENAMES: usize = 40;
const DELETES: usize = 30;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The byte key every stored string is XORed with.
///
/// Splitting a literal into pieces is not enough — the compiler may place two
/// pieces next to each other in `.rdata` and the forward string is in the
/// image after all — and plain reversal is worse: the engine has a rule for
/// exactly that (`SIGNATURE_BASE_Typical_Malware_String_Transforms`) and
/// convicts the fixture at 40 the moment it is reversed. XORed bytes match no
/// string rule at all.
const XOR: u8 = 0x5A;

fn decode(bytes: &[u8]) -> String {
    String::from_utf8(bytes.iter().map(|byte| byte ^ XOR).collect())
        .expect("the stored strings are ASCII")
}

/// The per-user `Run` key, stored encoded. See the module comment.
fn run_key() -> String {
    decode(&[
        0x09, 0x35, 0x3c, 0x2e, 0x2d, 0x3b, 0x28, 0x3f, 0x06, 0x17, 0x33, 0x39, 0x28, 0x35, 0x29,
        0x35, 0x3c, 0x2e, 0x06, 0x0d, 0x33, 0x34, 0x3e, 0x35, 0x2d, 0x29, 0x06, 0x19, 0x2f, 0x28,
        0x28, 0x3f, 0x34, 0x2e, 0x0c, 0x3f, 0x28, 0x29, 0x33, 0x35, 0x34, 0x06, 0x08, 0x2f, 0x34,
    ])
}

/// The part of the per-user Startup folder below `%APPDATA%`, stored encoded.
fn startup_folder(appdata: &str) -> String {
    format!(
        "{}{}",
        appdata,
        decode(&[
            0x06, 0x17, 0x33, 0x39, 0x28, 0x35, 0x29, 0x35, 0x3c, 0x2e, 0x06, 0x0d, 0x33, 0x34,
            0x3e, 0x35, 0x2d, 0x29, 0x06, 0x09, 0x2e, 0x3b, 0x28, 0x2e, 0x7a, 0x17, 0x3f, 0x34,
            0x2f, 0x06, 0x0a, 0x28, 0x35, 0x3d, 0x28, 0x3b, 0x37, 0x29, 0x06, 0x09, 0x2e, 0x3b,
            0x28, 0x2e, 0x2f, 0x2a,
        ])
    )
}

/// `.wncry`, stored encoded.
fn payload_extension() -> String {
    decode(&[0x74, 0x2d, 0x34, 0x39, 0x28, 0x23])
}

fn write_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, b"the behaviour fixture wrote this\n")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let want = |flag: &str| args.is_empty() || args.iter().any(|a| a == flag) || args.iter().any(|a| a == "--all");
    let do_files = want("--files");
    let do_registry = want("--registry");
    let do_startup = want("--startup");
    let do_scatter = want("--scatter");

    let pid = std::process::id();
    println!(
        "behtest pid {pid}: files={do_files} registry={do_registry} startup={do_startup} scatter={do_scatter}"
    );
    println!("image {}", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default());

    let mut errors: Vec<String> = Vec::new();
    let mut to_remove: Vec<PathBuf> = Vec::new();
    let mut staged: Vec<PathBuf> = Vec::new();

    let scratch = std::env::temp_dir().join(format!("behtest-{pid}"));

    // ---- renames: the ransomware shape, and a burst over the count rule ----
    if do_files {
        if let Err(error) = fs::create_dir_all(&scratch) {
            errors.push(format!("create {}: {error}", scratch.display()));
        } else {
            let extension = payload_extension();
            for index in 0..RENAMES {
                let from = scratch.join(format!("doc{index:02}.txt"));
                let to = scratch.join(format!("doc{index:02}{extension}"));
                match write_file(&from).and_then(|()| fs::rename(&from, &to)) {
                    Ok(()) => staged.push(to),
                    Err(error) => errors.push(format!("rename {}: {error}", from.display())),
                }
            }
            println!("renamed {} of {RENAMES} files to *{extension}", staged.len());
        }

        // ---- deletions: files of their own, then the renamed ones ----
        for index in 0..DELETES {
            let path = scratch.join(format!("del{index:02}.tmp"));
            if let Err(error) = write_file(&path) {
                errors.push(format!("write {}: {error}", path.display()));
            }
            staged.push(path);
        }
        let mut deleted = 0usize;
        for path in &staged {
            match fs::remove_file(path) {
                Ok(()) => deleted += 1,
                Err(error) => errors.push(format!("delete {}: {error}", path.display())),
            }
        }
        println!("deleted {deleted} of {} files", staged.len());
        staged.clear();
    }

    // ---- the registry: one value under the per-user Run key ----
    if do_registry {
        let key = run_key();
        let name = format!("WenleFixture{pid}");
        let data = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| String::from("behtest"));
        let key_w = wide(&key);
        let name_w = wide(&name);
        let data_w = wide(&data);
        let set = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key_w.as_ptr(),
                name_w.as_ptr(),
                REG_SZ,
                data_w.as_ptr() as *const c_void,
                (data_w.len() * 2) as u32,
            )
        };
        if set == 0 {
            println!("set HKCU\\{key}\\{name}");
        } else {
            errors.push(format!("RegSetKeyValueW returned {set}"));
        }
        let removed = unsafe {
            RegDeleteKeyValueW(HKEY_CURRENT_USER, key_w.as_ptr(), name_w.as_ptr())
        };
        if removed == 0 {
            println!("removed HKCU\\{key}\\{name}");
        } else {
            errors.push(format!("RegDeleteKeyValueW returned {removed}"));
        }
    }

    // ---- the Startup folder: a rename in, and the file removed again ----
    if do_startup {
        // A `.dll`, not a script: it matches the rule's suffix list and can
        // never be executed by the shell if the run dies before the cleanup.
        let name = format!("wenle-fixture-{pid}.dll");
        let source = std::env::temp_dir().join(format!("behtest-{pid}-startup-source.dll"));
        match std::env::var("APPDATA") {
            Err(error) => errors.push(format!("APPDATA: {error}")),
            Ok(appdata) => {
                let folder = startup_folder(&appdata);
                let target = Path::new(&folder).join(&name);
                match write_file(&source).and_then(|()| fs::rename(&source, &target)) {
                    Ok(()) => {
                        println!("renamed into {folder}: {name}");
                        to_remove.push(target);
                    }
                    Err(error) => {
                        errors.push(format!("startup rename {}: {error}", target.display()));
                        let _ = fs::remove_file(&source);
                    }
                }
            }
        }
    }

    // ---- ordinary files in system folders, removed at once ----
    if do_scatter {
        let mut places: Vec<PathBuf> = Vec::new();
        for variable in ["APPDATA", "PUBLIC"] {
            if let Ok(base) = std::env::var(variable) {
                places.push(PathBuf::from(base));
            }
        }
        if let Ok(base) = std::env::var("ProgramData") {
            places.push(PathBuf::from(base));
        }
        places.push(PathBuf::from(r"C:\Windows\Temp"));

        for base in places {
            let path = base.join(format!("wenle-fixture-{pid}.txt"));
            match write_file(&path) {
                Ok(()) => {
                    println!("wrote {}", path.display());
                    to_remove.push(path);
                }
                // `C:\Windows\Temp` needs elevation; not being able to write
                // there is not a failure of the fixture.
                Err(error) => println!("skipped {}: {error}", path.display()),
            }
        }
    }

    // ---- cleanup, whatever happened above ----
    for path in &to_remove {
        if let Err(error) = fs::remove_file(path) {
            if path.exists() {
                errors.push(format!("cleanup {}: {error}", path.display()));
            }
        } else {
            println!("removed {}", path.display());
        }
    }
    if do_files {
        if let Err(error) = fs::remove_dir_all(&scratch) {
            if scratch.exists() {
                errors.push(format!("cleanup {}: {error}", scratch.display()));
            }
        }
    }

    if errors.is_empty() {
        println!("all stages ran; nothing left behind");
    } else {
        println!("{} problem(s):", errors.len());
        for error in &errors {
            println!("  {error}");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_run_key_is_the_per_user_one() {
        assert_eq!(
            run_key(),
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn the_startup_folder_is_the_per_user_one() {
        assert_eq!(
            startup_folder(r"C:\Users\probe\AppData\Roaming"),
            r"C:\Users\probe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        );
    }

    #[test]
    fn the_extension_is_the_one_the_rule_names() {
        assert_eq!(payload_extension(), ".wncry");
    }

    #[test]
    fn a_wide_string_is_nul_terminated() {
        let text = wide("ab");
        assert_eq!(text, vec![b'a' as u16, b'b' as u16, 0]);
    }

    #[test]
    fn the_image_does_not_carry_the_paths_it_builds() {
        // The reason the pieces exist: a scan of the fixture's own bytes must
        // not find the persistence path or the extension as one literal.
        //
        // This reads the *shipped* image, not the test binary, because this
        // test's own literals would be found in the test binary and prove
        // nothing. Point at the built fixture and run the tests:
        //
        //     BEHTEST_IMAGE=tools/behtest.exe ./tools/behtest-test.exe
        //
        // Without the variable the test does nothing, which is the same
        // contract the corpus-backed tests follow.
        let Ok(path) = std::env::var("BEHTEST_IMAGE") else {
            eprintln!("BEHTEST_IMAGE is not set; not checking an image");
            return;
        };
        let image = std::fs::read(&path).expect("the named image is readable");
        let needle = |text: &str| {
            let bytes = text.as_bytes();
            image.windows(bytes.len()).any(|window| window == bytes)
        };
        assert!(!needle(r"Software\Microsoft\Windows\CurrentVersion\Run"));
        assert!(!needle(".wncry"));
        assert!(!needle(r"Start Menu\Programs\Startup"));
    }
}
