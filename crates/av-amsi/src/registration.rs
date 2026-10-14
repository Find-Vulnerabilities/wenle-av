//! Where Windows is told this provider exists, and the one rule about *where
//! the DLL may live*.
//!
//! # The two keys
//!
//! An AMSI provider is registered in two places, and both are required:
//!
//! ```text
//! HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}          presence is the registration
//! HKLM\SOFTWARE\Classes\CLSID\{CLSID}
//!     (Default)              = "Wenle Antivirus"
//!     \InprocServer32
//!         (Default)          = C:\Program Files\Wenle AV\av_amsi.dll
//!         ThreadingModel     = Both
//! ```
//!
//! The first is what AMSI enumerates; the second is what `CoCreateInstance`
//! needs in order to turn that CLSID into this DLL. A machine with only the
//! first has a provider that is listed and cannot be created, which presents as
//! every scripting host failing to start — see the note on failure below.
//!
//! `ThreadingModel` is `Both`, not `Free` and not `Apartment`. A provider is
//! created on whichever thread the host is running script on, which is not
//! knowable in advance, and `Both` is the model that says so.
//!
//! # The 32-bit view
//!
//! `HKLM\SOFTWARE` is redirected for 32-bit processes. A 32-bit host — 32-bit
//! Office, the SysWOW64 PowerShell — reads
//! `HKLM\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers`, and a 64-bit DLL
//! registered only under the native key is invisible to it. Both views are
//! named here rather than one, so that whoever writes the installer has to
//! decide about the second instead of discovering it in the field.
//!
//! # The rule about the DLL's location
//!
//! **The DLL must not live in a directory a non-administrator can write to.**
//! This is not a hardening nicety, it is the whole security of the mechanism.
//! The registration is machine-wide, and what it does is cause *every* process
//! that asks AMSI a question — including processes running as other users, and
//! including elevated ones — to load a DLL from a path written into `HKLM`. A
//! path under `%LOCALAPPDATA%`, a user profile, a temp directory or any
//! directory whose ACL allows a user to create files there turns this feature
//! into a local privilege escalation: whoever can write to the path gets code
//! execution in every scripting host on the machine.
//!
//! [`is_trusted_dll_path`] is the check, and it is deliberately a refusal of a
//! small set of known-bad prefixes rather than an allow-list of one directory —
//! a product directory is the installer's decision, and a check that hard-coded
//! it would refuse a legitimate deployment to `D:\Apps`.
//!
//! # What this module deliberately does not do
//!
//! It does not write the registry. A library that a scripting host has already
//! loaded has no business modifying `HKLM`, and the decision above is exactly
//! the kind that needs an elevated writer and a human being who can be told
//! what happened. `wenle integrate` owns the write; this module owns the facts
//! it needs.

use windows::core::GUID;

/// This provider's class identifier.
///
/// Fixed for the life of the product. Changing it orphans the registration
/// under the old value — a provider that is still enumerated, still created,
/// and no longer anything this build knows about.
pub const CLSID: GUID = GUID::from_u128(0x3f1d8a52_6b4e_4c07_9a71_2d5f0c8b4e19);

/// The file name of the DLL this crate builds.
pub const DLL_NAME: &str = "av_amsi.dll";

/// The key AMSI enumerates, in the native (64-bit) registry view.
pub const PROVIDERS_KEY: &str = r"SOFTWARE\Microsoft\AMSI\Providers";

/// The same key as a 32-bit process sees it.
///
/// Not a separate registration: it is the redirected view of the one above, and
/// a 32-bit host looks here. Named so that an installer writes both rather than
/// assuming one.
pub const PROVIDERS_KEY_WOW64: &str = r"SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers";

/// The key `CoCreateInstance` resolves the CLSID through, native view.
pub const CLASSES_KEY: &str = r"SOFTWARE\Classes\CLSID";

/// The same key as a 32-bit process sees it.
pub const CLASSES_KEY_WOW64: &str = r"SOFTWARE\WOW6432Node\Classes\CLSID";

/// The subkey under the CLSID that names the DLL.
pub const INPROC_SERVER_KEY: &str = "InprocServer32";

/// The COM threading model, and the value it must have.
///
/// `Both`, because a provider is created on whichever thread the host happens
/// to be running script on.
pub const THREADING_MODEL: &str = "Both";

/// This provider's CLSID in the brace-and-hyphen form the registry uses.
///
/// Derived from [`CLSID`] rather than written down a second time: the two forms
/// agreeing is a fact about a formatting function, and a second literal is a
/// fact about somebody having typed carefully.
pub fn clsid_string() -> String {
    format!("{{{:?}}}", CLSID)
        .to_uppercase()
        .replace("GUID(", "")
        // `GUID`'s `Debug` prints `GUID(...)` around the hyphenated form on
        // some versions and the bare form on others, so the wrapper is stripped
        // rather than assumed absent. The closing paren and any space go in one
        // pass: two `replace` calls that each walk the string are the same
        // answer more slowly, and this runs once per registration.
        .replace([')', ' '], "")
}

/// The full path of the DLL this registration would name, given its directory.
pub fn dll_path(directory: &std::path::Path) -> std::path::PathBuf {
    directory.join(DLL_NAME)
}

/// The directory locations an AMSI provider must never be loaded from.
///
/// Each entry is a sequence of **whole path components anchored at the root**,
/// not a substring. That distinction is the whole correctness of the check, and
/// it was got wrong once: `\Users\` as a substring refuses
/// `C:\Program Files\Wenle AV\Users\av_amsi.dll`, which is a perfectly good
/// product directory, and — worse in the other direction — does *not* refuse
/// `C:\$Recycle.Bin\`, because the character before `Recycle` is `$` and not a
/// separator.
///
/// Only root-level locations are listed. `C:\Users\` is here; `Downloads` and
/// `AppData` are not, because they are always *inside* a profile and the
/// `users` entry already refuses everything under one. `Temp` and
/// `Windows\Temp` are separate entries because both are root-relative and the
/// second is not covered by the first.
///
/// See this module's documentation for what a writable provider path costs.
const WRITABLE_ROOTS: &[&[&str]] = &[
    &["users"],
    &["documents and settings"],
    &["temp"],
    &["windows", "temp"],
    &["programdata"],
    &["recycle.bin"],
    &["$recycle.bin"],
];

/// True when `path` is somewhere an AMSI provider may be registered from.
///
/// A refusal of known-bad locations rather than an allow-list — see this
/// module's documentation for why the choice is that way round.
///
/// The comparison is case-insensitive because Windows paths are, and it is by
/// whole components from the root because a substring rule is wrong in both
/// directions: it refuses `C:\Program Files\Wenle AV\Users\` and it accepts
/// `C:\$Recycle.Bin\`.
///
/// A path with no drive or UNC prefix is refused outright. A relative path
/// resolves against whatever directory the loader happens to be in, and a
/// drive-relative one (`C:av_amsi.dll`) resolves against the current directory
/// *on that drive*, which is a different directory in every process. Neither is
/// a place a machine-wide registration can honestly point at.
///
/// A UNC path is matched the same way, on the components after the share, so
/// `\\server\share\Users\av_amsi.dll` is refused. That errs toward refusing a
/// share layout that might be perfectly safe, which is the right direction for
/// this particular check.
pub fn is_trusted_dll_path(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy().to_lowercase().replace('/', "\\");
    // `C:\` and not `C:`. The second is drive-relative, and the byte after the
    // colon is what tells them apart.
    let rooted = text.starts_with(r"\\")
        || (text.len() >= 3 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'\\');
    if !rooted {
        return false;
    }
    let Some(directory) = path.parent() else {
        return false;
    };
    // `Normal` and nothing else: the prefix and the root separator are not
    // directory names, and a UNC path's server and share live in the prefix
    // rather than here, which is what makes the UNC rule above fall out.
    let components: Vec<String> = directory
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    !WRITABLE_ROOTS.iter().any(|root| {
        components.len() >= root.len() && root.iter().zip(&components).all(|(want, got)| got == want)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_clsid_renders_the_way_the_registry_spells_it() {
        let text = clsid_string();
        assert!(text.starts_with('{'), "{text}");
        assert!(text.ends_with('}'), "{text}");
        // 38 characters: two braces and thirty-six for the canonical form.
        assert_eq!(text.len(), 38, "{text}");
        assert_eq!(text.matches('-').count(), 4, "{text}");
        assert!(!text.contains("GUID"), "{text}");
        assert_eq!(text, text.to_uppercase());
        // Derived from the constant, so changing one changes the other.
        assert!(text.contains("3F1D8A52"), "{text}");
    }

    #[test]
    fn a_product_directory_is_accepted() {
        for path in [
            r"C:\Program Files\Wenle AV\av_amsi.dll",
            r"C:\Program Files (x86)\Wenle AV\av_amsi.dll",
            r"D:\Apps\Wenle\av_amsi.dll",
            r"\\server\share\Wenle AV\av_amsi.dll",
        ] {
            assert!(is_trusted_dll_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn a_directory_a_user_can_write_to_is_refused() {
        // Every one of these is a local privilege escalation as a provider
        // path: machine-wide registration, DLL loaded into every scripting host
        // on the machine, including other users' and including elevated ones.
        for path in [
            r"C:\Users\me\Downloads\av_amsi.dll",
            r"C:\Users\me\AppData\Local\Temp\av_amsi.dll",
            r"C:\Documents and Settings\me\av_amsi.dll",
            r"C:\Windows\Temp\av_amsi.dll",
            r"C:\Temp\av_amsi.dll",
            r"C:\ProgramData\av_amsi.dll",
            r"C:\$Recycle.Bin\av_amsi.dll",
        ] {
            assert!(!is_trusted_dll_path(Path::new(path)), "{path}");
        }
        // Case-insensitively, because Windows paths are.
        assert!(!is_trusted_dll_path(Path::new(
            r"c:\USERS\me\downloads\AV_AMSI.DLL"
        )));
    }

    #[test]
    fn a_path_with_no_root_or_no_directory_is_refused() {
        // Relative: resolves against whatever directory the loader is in, which
        // is not a thing a machine-wide registration can name.
        assert!(!is_trusted_dll_path(Path::new("av_amsi.dll")));
        assert!(!is_trusted_dll_path(Path::new(r"Wenle\av_amsi.dll")));
        // A bare drive-relative path.
        assert!(!is_trusted_dll_path(Path::new(r"C:av_amsi.dll")));
    }

    #[test]
    fn the_prefix_rules_match_whole_components_and_not_substrings() {
        // A legitimate product directory whose name happens to contain a
        // forbidden word. `\Users\` as a substring rule would refuse it, which
        // is the failure mode of writing this check the easy way.
        assert!(is_trusted_dll_path(Path::new(
            r"C:\Program Files\Wenle AV\Users\av_amsi.dll"
        )));
        assert!(is_trusted_dll_path(Path::new(
            r"C:\Program Files\Temp\av_amsi.dll"
        )));
    }

    #[test]
    fn the_two_registry_views_are_named_and_differ() {
        assert_ne!(PROVIDERS_KEY, PROVIDERS_KEY_WOW64);
        assert_ne!(CLASSES_KEY, CLASSES_KEY_WOW64);
        assert!(PROVIDERS_KEY_WOW64.contains("WOW6432Node"));
        assert!(CLASSES_KEY_WOW64.contains("WOW6432Node"));
        // The native view must not be the redirected one, or a 64-bit host
        // reads a key nothing wrote.
        assert!(!PROVIDERS_KEY.contains("WOW6432Node"));
        assert!(!CLASSES_KEY.contains("WOW6432Node"));
    }

    #[test]
    fn the_dll_name_is_the_one_the_crate_builds() {
        // `av-amsi` has a hyphen and a Rust cdylib is named after the crate
        // with underscores. A registration naming the wrong one is a provider
        // that never loads.
        assert_eq!(DLL_NAME, "av_amsi.dll");
        assert!(!DLL_NAME.contains('-'));
        assert_eq!(
            dll_path(Path::new(r"C:\Program Files\Wenle AV")),
            Path::new(r"C:\Program Files\Wenle AV\av_amsi.dll")
        );
    }
}
