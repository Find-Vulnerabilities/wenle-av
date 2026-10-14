//! SCRATCH. Delete after the measurement is recorded.
//!
//! Compares the two routes for answering "is this file's Authenticode signature
//! good?" over a real corpus of signed binaries:
//!
//! * `av_authenticode::verify_bytes` — this crate's own digest and RSA
//!   arithmetic, with the platform asked only to build a chain.
//! * `WinVerifyTrust`, the OS call that answers the whole question at once,
//!   with `WTD_UI_NONE | WTD_REVOKE_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL |
//!   WTD_DISABLE_MD2_MD4`.
//!
//! It reports wall time for each and a taxonomy of the `TRUST_E_*` / `CERT_E_*`
//! codes the OS call returns, with a count per code and a crosstab against this
//! crate's verdict, so that a disagreement is visible rather than averaged away.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// `WinVerifyTrust`'s answer for one file, as the raw `i32` the API returns.
fn win_verify_trust(path: &Path) -> i32 {
    // The path as UTF-16 with a terminator, alive for the whole call.
    let mut wide: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().collect();
    wide.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE(ptr::null_mut()),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };

    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };

    // The state data `WTD_STATEACTION_VERIFY` allocated is released by a second
    // call with `WTD_STATEACTION_CLOSE`. Both calls are inside the measured
    // region, because a caller that skipped this would leak on every file.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        );
    }

    status
}

/// What an `HRESULT` from `WinVerifyTrust` means for a real system.
///
/// This is the part of the measurement worth keeping: the difference between
/// "there is no signature here" (a miss, and harmless) and "there is one and
/// this machine cannot verify it" (which must never be read as malicious).
fn meaning(code: i32) -> &'static str {
    match code as u32 {
        0x0000_0000 => "S_OK — accepted",
        0x800B_0100 => "TRUST_E_NOSIGNATURE — no signature, and no catalog entry either",
        0x800B_0001 => "TRUST_E_PROVIDER_UNKNOWN — MSDN groups this under 'no signature'",
        0x800B_0003 => "TRUST_E_SUBJECT_FORM_UNKNOWN — MSDN groups this under 'no signature'",
        0x800B_0004 => "TRUST_E_SUBJECT_NOT_TRUSTED — the SIP refused it on policy, not on maths",
        0x8009_6010 => "TRUST_E_BAD_DIGEST — the file does not hash to what the signature says",
        0x800B_0111 => "TRUST_E_EXPLICIT_DISTRUST — the signer is on the disallowed list",
        0x800B_0109 => {
            "CERT_E_UNTRUSTEDROOT — the chain reached a root this machine does not trust"
        }
        0x800B_010A => "CERT_E_CHAINING — no path could be built at all",
        0x800B_0101 => "CERT_E_EXPIRED — a certificate in the path is outside its dates",
        0x800B_010B => "CERT_E_VALIDITYPERIODNESTING — a path certificate outlives its issuer",
        0x800B_010C => "CERT_E_REVOKED — a certificate in the path is revoked",
        0x800B_010E => "CERT_E_REVOCATION_FAILURE — the revocation check itself failed",
        0x800B_0110 => "CERT_E_WRONG_USAGE — the certificate is not for code signing",
        0x8009_6004 => "TRUST_E_CERT_SIGNATURE — a certificate's own signature is bad",
        0x8009_2001 => "CRYPT_E_NOT_FOUND — a needed certificate is absent",
        0x8009_2026 => "CRYPT_E_SECURITY_SETTINGS — a local security policy blocked it",
        other => {
            let _ = other;
            "UNCLASSIFIED"
        }
    }
}

/// Whether the file has an attribute certificate table with something in it.
///
/// The one question that separates "this file is catalog-signed, so there is
/// nothing embedded to read" from "this file has an embedded signature and this
/// crate failed to find it".
fn carries_embedded_signature(bytes: &[u8]) -> bool {
    match av_pe::PeFile::parse(bytes) {
        Ok(pe) => pe
            .security_directory_data()
            .map(|t| !t.is_empty())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Where in the pipeline a file that carries a signature stops looking signed.
fn diagnose(path: &Path) {
    let Ok(bytes) = std::fs::read(path) else {
        println!("  unreadable");
        return;
    };
    let pe = match av_pe::PeFile::parse(&bytes) {
        Ok(pe) => pe,
        Err(error) => {
            println!("  PeFile::parse failed: {error:?}");
            return;
        }
    };
    let table = match pe.security_directory_data() {
        Ok(table) => table,
        Err(error) => {
            println!("  security_directory_data failed: {error:?}");
            return;
        }
    };
    println!("  table: {} bytes", table.len());
    println!("  verdict: {:?}", av_authenticode::verify(&pe));
    let Some(blob) = av_signatures::authenticode::first_blob(table) else {
        println!("  first_blob: None");
        return;
    };
    println!("  first_blob: {} bytes", blob.len());
    match av_authenticode::cms::SignedData::parse(blob) {
        Ok(signed) => println!(
            "  SignedData::parse: ok, {} signers, {} certificates",
            signed.signers.len(),
            signed.certificates.len()
        ),
        Err(error) => println!("  SignedData::parse failed: {error:?}"),
    }
}

/// Every file under `root` whose extension is one Authenticode signs.
fn candidates(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            candidates(&path, out);
            continue;
        }
        let signed_extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| {
                matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "exe" | "dll" | "sys" | "ocx" | "cpl" | "efi" | "msi" | "ps1"
                )
            })
            .unwrap_or(false);
        if signed_extension {
            out.push(path);
        }
    }
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| r"C:\Windows\System32".to_owned());
    let limit: usize = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(usize::MAX);

    let mut paths = Vec::new();
    candidates(Path::new(&root), &mut paths);
    paths.sort();
    paths.truncate(limit);

    let mut ours = Duration::ZERO;
    let mut theirs = Duration::ZERO;
    let mut verdicts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut codes: BTreeMap<i32, usize> = BTreeMap::new();
    // code -> (our verdict -> count), so a disagreement is visible.
    let mut crosstab: BTreeMap<i32, BTreeMap<&'static str, usize>> = BTreeMap::new();
    // The files the OS accepts and we do not, split by whether the file carries
    // an embedded signature at all. A file with no attribute certificate table
    // that the OS accepts is catalog-signed — an expected divergence, because
    // this crate reads the embedded signature and nothing else. A file that
    // *does* carry one and still reads as `unsigned` here is a bug in this
    // crate, and the two must not be added together.
    let mut catalog_signed = 0usize;
    let mut embedded_but_unsigned: Vec<PathBuf> = Vec::new();
    let mut undetermined_but_ok: Vec<PathBuf> = Vec::new();
    let mut unreadable = 0usize;

    for (index, path) in paths.iter().enumerate() {
        let Ok(bytes) = std::fs::read(path) else {
            unreadable += 1;
            continue;
        };

        let started = Instant::now();
        let verdict = av_authenticode::verify_bytes(&bytes);
        ours += started.elapsed();
        let verdict = verdict.code();

        let started = Instant::now();
        let code = win_verify_trust(path);
        theirs += started.elapsed();

        if code == 0 && verdict == "unsigned" {
            if carries_embedded_signature(&bytes) {
                embedded_but_unsigned.push(path.clone());
            } else {
                catalog_signed += 1;
            }
        }
        if code == 0 && verdict == "undetermined" {
            undetermined_but_ok.push(path.clone());
        }

        *verdicts.entry(verdict).or_default() += 1;
        *codes.entry(code).or_default() += 1;
        *crosstab
            .entry(code)
            .or_default()
            .entry(verdict)
            .or_default() += 1;

        if index % 500 == 0 {
            eprintln!("  {index}/{}", paths.len());
        }
    }

    println!(
        "# probe: {root}, {} files, {unreadable} unreadable",
        paths.len()
    );
    println!();
    println!("wall time, ours        : {:?}", ours);
    println!("wall time, WinVerifyTrust: {:?}", theirs);
    println!();
    println!("## our verdicts");
    for (verdict, count) in &verdicts {
        println!("{count:8}  {verdict}");
    }
    println!();
    println!("## WinVerifyTrust codes");
    for (code, count) in &codes {
        println!("{count:8}  0x{:08X}  {}", *code as u32, meaning(*code));
    }
    println!();
    println!("## crosstab: code -> our verdict");
    for (code, row) in &crosstab {
        println!("0x{:08X}  {}", *code as u32, meaning(*code));
        for (verdict, count) in row {
            println!("            {count:8}  {verdict}");
        }
    }

    // The two answers that matter, called out so they cannot be lost in a table.
    let mut ours_trusted_theirs_ok = 0usize;
    let mut ours_trusted_theirs_not = 0usize;
    let mut ours_not_trusted_theirs_ok = 0usize;
    for (code, row) in &crosstab {
        let trusted = row.get("trusted").copied().unwrap_or(0);
        if *code == 0 {
            ours_trusted_theirs_ok += trusted;
            ours_not_trusted_theirs_ok += row
                .iter()
                .filter(|(verdict, _)| **verdict != "trusted")
                .map(|(_, count)| *count)
                .sum::<usize>();
        } else {
            ours_trusted_theirs_not += trusted;
        }
    }
    println!();
    println!("both trusted (agreement, the expected majority) : {ours_trusted_theirs_ok}");
    println!("we trusted, the OS did not (we are the permissive one): {ours_trusted_theirs_not}");
    println!(
        "the OS trusted, we did not (we are the strict one)    : {ours_not_trusted_theirs_ok}"
    );
    println!();
    println!("of those, catalog-signed, no embedded signature (expected): {catalog_signed}");
    println!(
        "of those, a signature IS embedded and we missed it (a bug) : {}",
        embedded_but_unsigned.len()
    );
    for path in embedded_but_unsigned.iter().take(3) {
        println!("    {}", path.display());
        diagnose(path);
    }
    println!();
    println!(
        "the OS trusted and we stopped short of a verdict: {}",
        undetermined_but_ok.len()
    );
    for path in undetermined_but_ok.iter().take(3) {
        println!("    {}", path.display());
        println!(
            "      embedded signature: {}",
            carries_embedded_signature(&std::fs::read(path).unwrap_or_default())
        );
        diagnose(path);
    }
}
