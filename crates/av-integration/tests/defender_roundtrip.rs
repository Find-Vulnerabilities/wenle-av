//! The undo, against the real registry, under a key this product owns.
//!
//! # What this file does not do, and why that is the point
//!
//! It does not call [`av_integration::defender::disable`] or
//! [`av_integration::defender::restore`]. Those two write
//! `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`, and a test
//! that called them would change whether the machine running it is protected —
//! which is the one thing a test in this repository must never do. The owner of
//! the machine makes that change by hand, and nobody makes it by running
//! `cargo test`.
//!
//! What it does instead is the same trade [`super::registry_roundtrip`] makes:
//! the *shape* of what the real path does, exercised against the real API, at a
//! location that belongs to this product —
//!
//! ```text
//! HKCU\Software\WenleAV\IntegrationTest\<pid>-<test name>
//! ```
//!
//! — so that the reading, the encoding, the write and the delete are verified
//! against `RegQueryValueExW` and `RegSetValueExW` rather than against a mock,
//! and `HKEY_LOCAL_MACHINE` is not touched at all.
//!
//! # Why the functions take a key
//!
//! [`av_integration::defender::read_previous`], `write_previous`, `read_record`,
//! `write_record` and `clear_record` take an already-open [`Key`] rather than
//! opening `HKLM` themselves, and this file is why: they are the two halves of
//! the undo — read what was there, put it back — and a version that opened its
//! own key would be a version that could not be tested without disarming the
//! machine. The module's own documentation says the same thing from the other
//! side.
//!
//! # What is read from the real thing
//!
//! [`av_integration::defender::status`] reads `HKEY_LOCAL_MACHINE` and this file
//! calls it, because it only reads: every value it touches is one `Everyone` may
//! read, which is exactly the property that makes
//! `wenle integrate defender status` usable from an ordinary prompt. Nothing in
//! this file asserts anything about how *this* machine is configured — a
//! developer's machine is entitled to have real-time monitoring off, or a policy
//! set, or Defender absent altogether — only that the status it produces is
//! consistent with the values it reports.

#![cfg(windows)]
// A separate crate root: the library's `cfg(test)` allowance does not reach here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use av_integration::defender::{
    self, clear_record, read_previous, read_record, write_previous, write_record, DefenderError,
    Monitoring, Previous, DISABLE_VALUE, RECORD_VALUE,
};
use av_integration::registry::{Hive, Key};

/// Where the scratch keys live, below `HKCU`.
///
/// The same root [`super::registry_roundtrip`] uses, and deliberately not a
/// second one: two test files that each invented their own product-owned key
/// would leave two keys behind instead of one.
const SCRATCH_ROOT: &str = r"Software\WenleAV\IntegrationTest";

/// Removes the scratch key when it goes out of scope, whatever happened.
///
/// A guard rather than a call at the end of the test, for the reason the other
/// test file gives: the interesting endings are the ones where an assertion
/// failed halfway, and a test that left a key behind would be a worse bug than
/// the one it was reporting. Every result inside `drop` is discarded — this runs
/// during a panic, and a second panic would abort the process rather than report
/// the first failure.
struct Cleanup {
    /// The leaf, below [`SCRATCH_ROOT`].
    path: String,
}

impl Cleanup {
    /// Claim a leaf named after this process and this test.
    fn new(test: &str) -> Self {
        Self {
            path: format!("{SCRATCH_ROOT}\\{}-{test}", std::process::id()),
        }
    }

    /// The key path this guard will remove.
    fn path(&self) -> &str {
        &self.path
    }

    /// The scratch key, created.
    fn key(&self) -> Key {
        Key::create(Hive::CurrentUser, self.path()).expect("creating the scratch key")
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Key::delete_tree(Hive::CurrentUser, &self.path);
    }
}

/// A NUL-terminated UTF-16 copy of `text`, for a `PCWSTR` argument.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A NUL-terminated UTF-16 copy of `text`, as the bytes a `REG_SZ` holds.
///
/// The terminator is part of the stored length, which is why it is here and not
/// left to the caller: a raw `REG_SZ` written without one is a value some readers
/// see one character longer than others do, and this file's whole purpose is to
/// produce values another writer really could have produced.
fn wide_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

/// Write a raw value at a path, bypassing this crate's API.
///
/// The one thing in this file that is not a call into the code under test. It is
/// here so that the values this module *refuses* can be produced by a writer it
/// does not control — a string where a number belongs, a `REG_DWORD` that is not
/// four bytes long — because the point of those tests is that this crate's reader
/// refuses what another writer left behind.
fn write_raw_at(path: &str, name: &str, kind: u32, bytes: &[u8]) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
        REG_VALUE_TYPE,
    };

    let path_wide = wide(path);
    let name_wide = wide(name);
    let mut raw = HKEY::default();
    // SAFETY: `path_wide` is NUL-terminated and outlives the call; `raw` is an
    // out-parameter the API fills on success. The options argument is documented
    // as reserved and must be zero, which `None` is.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path_wide.as_ptr()),
            None,
            KEY_WRITE,
            &mut raw,
        )
    };
    assert_eq!(status, ERROR_SUCCESS, "opening {path} to write a raw value");

    // SAFETY: `name_wide` is NUL-terminated and `bytes` is a slice the API only
    // reads; both outlive the call. The reserved argument must be zero.
    let status = unsafe {
        RegSetValueExW(
            raw,
            PCWSTR(name_wide.as_ptr()),
            None,
            REG_VALUE_TYPE(kind),
            Some(bytes),
        )
    };
    // SAFETY: `raw` came from `RegOpenKeyExW` above and is closed here, once.
    unsafe {
        let _ = RegCloseKey(raw);
    }
    assert_eq!(status, ERROR_SUCCESS, "writing a raw value named {name}");
}

#[test]
fn the_state_that_was_there_survives_the_whole_round_trip() {
    // The undo, end to end, at a scratch key: read what is there, write it down,
    // change the value, put the recorded state back, drop the record. Every step
    // is a call the real `disable` and `restore` make, in the order they make
    // them, against the real API.
    let cleanup = Cleanup::new("state");
    let key = cleanup.key();

    // 1. An untouched key has nothing in it, and "nothing" is `Absent` — not
    //    zero. This is the distinction the record exists to preserve.
    assert_eq!(read_previous(&key).unwrap(), Previous::Absent);
    assert_eq!(read_record(&key).unwrap(), None);

    // 2. Record it, exactly as `disable` does before it writes anything.
    write_record(&key, Previous::Absent).expect("recording the previous state");
    assert_eq!(read_record(&key).unwrap(), Some(Previous::Absent));

    // 3. Make the change the real command makes.
    key.set_dword(DISABLE_VALUE, 1).expect("disabling");

    // 4. Read it back through a *second* handle, so that what is read is what is
    //    in the registry rather than anything this process remembered.
    drop(key);
    let key = Key::open(Hive::CurrentUser, cleanup.path())
        .unwrap()
        .expect("the scratch key is there");
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), Some(1));
    assert_eq!(read_previous(&key).unwrap(), Previous::Dword(1));
    // The record is still what it was: the change did not overwrite it, which is
    // the property that makes a second `disable` worth refusing over.
    assert_eq!(read_record(&key).unwrap(), Some(Previous::Absent));

    // 5. Put the recorded state back, which for `Absent` means removing the
    //    value rather than writing a zero.
    write_previous(&key, Previous::Absent).expect("restoring");
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), None);
    // Removing it twice is the state the caller asked for, so it is not an error.
    write_previous(&key, Previous::Absent).expect("restoring an absent value");

    // 6. And the other direction: a previous state that was a value is written
    //    back as that value, not as `1` and not as an absence.
    write_previous(&key, Previous::Dword(0)).expect("restoring a zero");
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), Some(0));
    assert_eq!(read_previous(&key).unwrap(), Previous::Dword(0));

    // 7. Drop the record, once the value is back. Two calls, because `restore`
    //    can be run twice and the second one must not fail on a record that is
    //    already gone.
    clear_record(&key).expect("clearing the record");
    assert_eq!(read_record(&key).unwrap(), None);
    clear_record(&key).expect("clearing an absent record");
    // The value that was put back is untouched by any of that.
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), Some(0));
}

#[test]
fn a_value_that_is_not_the_number_this_module_wrote_is_put_back_as_itself() {
    // The promise the module makes in its documentation: not "turn it on", but
    // "put back what was there". A value somebody set to something other than 0
    // or 1 is a value this module has no business rounding to either.
    let cleanup = Cleanup::new("verbatim");
    let key = cleanup.key();

    key.set_dword(DISABLE_VALUE, 0xDEAD_BEEF).expect("a value");
    let previous = read_previous(&key).unwrap();
    assert_eq!(previous, Previous::Dword(0xDEAD_BEEF));

    write_record(&key, previous).expect("recording it");
    key.set_dword(DISABLE_VALUE, 1).expect("disabling");

    // Somebody else changes it while this product has it off.
    key.set_dword(DISABLE_VALUE, 7).expect("somebody else's value");

    // `restore` writes the recorded state regardless — that is what "put back
    // what was there" means — and the record is what made that possible.
    let recorded = read_record(&key).unwrap().expect("a record");
    assert_eq!(recorded, Previous::Dword(0xDEAD_BEEF));
    write_previous(&key, recorded).expect("restoring");
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), Some(0xDEAD_BEEF));
}

#[test]
fn a_record_this_module_did_not_write_is_refused_by_where_it_is() {
    // The refusal that keeps a corrupted or hand-edited record from being read as
    // an instruction. The text is written raw, because the point of the test is
    // that this crate's decoder refuses what another writer produced.
    let cleanup = Cleanup::new("record");
    let path = cleanup.path().to_string();
    let key = cleanup.key();
    write_raw_at(&path, RECORD_VALUE, 1, &wide_bytes("yes"));

    let error = read_record(&key).expect_err("`yes` is not a state");
    match error {
        DefenderError::UnreadableRecord {
            hive,
            ref path,
            ref name,
            ref found,
        } => {
            // The hive and the path are the ones the key was opened with, not
            // constants: a message naming `HKLM` for a value under `HKCU` would
            // send a user looking in the wrong place.
            assert_eq!(hive, Hive::CurrentUser);
            assert_eq!(path, &cleanup.path().to_string());
            assert_eq!(name, RECORD_VALUE);
            assert_eq!(found, "yes");
        }
        other => panic!("expected UnreadableRecord, got {other:?}"),
    }
    // Both facts a user needs are in the sentence: what it says, and what it
    // would have accepted.
    let message = error.to_string();
    assert!(message.contains("yes"), "{message}");
    assert!(message.contains("absent"), "{message}");
}

#[test]
fn a_string_where_the_setting_belongs_is_refused_as_a_number() {
    // The mirror of the check the other test file makes about `Key::string`. A
    // `REG_SZ` in the setting's place is a value somebody wrote by hand with the
    // wrong type, and reading it as a number — or reading it as text and
    // guessing — would make this module act on something nobody said.
    let cleanup = Cleanup::new("wrongtype");
    let path = cleanup.path().to_string();
    let key = cleanup.key();
    write_raw_at(&path, DISABLE_VALUE, 1, &wide_bytes("1"));

    let error = read_previous(&key).expect_err("a string is not a number");
    match &error {
        DefenderError::Registry(registry) => match registry {
            av_integration::RegistryError::NotNumeric { found, bytes, .. } => {
                assert_eq!(*found, 1, "a REG_SZ is type 1");
                assert_eq!(*bytes, 4, "`1` and its terminator are four bytes");
            }
            other => panic!("expected NotNumeric, got {other:?}"),
        },
        other => panic!("expected a registry failure, got {other:?}"),
    }
    // Every state this module acts on is one it read as a number, so a value it
    // could not read that way has to be a refusal rather than a default.
    assert!(error.to_string().contains("not a 32-bit number"), "{error}");
}

#[test]
fn a_dword_that_is_not_four_bytes_long_is_refused_as_a_number() {
    // The check that a type alone does not make: `RegSetValueExW` will happily
    // store a `REG_DWORD` of any length, and a reader that trusted the type would
    // take whatever the first four bytes happened to be and report it as the
    // setting. Eight bytes here, with the number four bytes in.
    let cleanup = Cleanup::new("longword");
    let path = cleanup.path().to_string();
    let key = cleanup.key();
    let mut eight = [0u8; 8];
    eight[..4].copy_from_slice(&5u32.to_le_bytes());
    write_raw_at(&path, DISABLE_VALUE, 4, &eight);

    let error = key.dword(DISABLE_VALUE).expect_err("eight bytes is not a u32");
    match &error {
        av_integration::RegistryError::NotNumeric { found, bytes, .. } => {
            assert_eq!(*found, 4, "the type really is REG_DWORD");
            assert_eq!(*bytes, 8, "and it is twice as long as one");
        }
        other => panic!("expected NotNumeric, got {other:?}"),
    }

    // And the writer this module has cannot produce one: four bytes, every time.
    key.set_dword(DISABLE_VALUE, 5).expect("writing a dword");
    assert_eq!(key.dword(DISABLE_VALUE).unwrap(), Some(5));
}

#[test]
fn a_real_key_with_nothing_in_it_reads_as_absent_rather_than_as_a_failure() {
    // `read_previous` against a key that exists and has no such value, which is
    // the ordinary state of the machine this runs on. `Key::open` on a key that
    // is not there at all is the other half, and `status` covers it.
    let cleanup = Cleanup::new("empty");
    let key = cleanup.key();
    key.set_string("SomethingElse", "not the setting")
        .expect("another value");
    assert_eq!(read_previous(&key).unwrap(), Previous::Absent);
    assert_eq!(read_record(&key).unwrap(), None);
}

#[test]
fn the_status_of_this_machine_is_consistent_with_the_values_it_reports() {
    // A read of the real thing, and the only test in this file that touches
    // `HKEY_LOCAL_MACHINE` — which it may, because it only reads.
    //
    // Nothing here asserts how this machine is configured. A developer's machine
    // is entitled to have real-time monitoring off, a policy set, Defender in
    // passive mode, or Defender absent altogether, and a test that pinned any of
    // those would be a test that failed on somebody else's computer. What is
    // asserted is that the report agrees with itself: the verdict is the one the
    // two raw values imply, and it is a verdict this module can name.
    let status = defender::status().expect("the status of this machine is readable");
    let expected = match (status.policy(), status.setting()) {
        (Some(policy), _) if policy != 0 => Monitoring::OffByPolicy,
        (_, Some(setting)) if setting != 0 => Monitoring::OffBySetting,
        _ => Monitoring::On,
    };
    assert_eq!(status.monitoring(), expected);
    assert_eq!(status.monitoring().is_off(), status.monitoring() != Monitoring::On);
    // There is no assertion here about elevation, and the absence is deliberate.
    // The call above is the whole claim: it succeeded in whichever kind of
    // process `cargo test` was typed into, which is what "this works from an
    // ordinary prompt" means. An assertion that read the token and compared it to
    // itself would be a test that passes whatever the machine does.

    // Whatever the machine says, the three sentences have to exist and have to
    // be different from each other, or the report is unreadable.
    let described = [
        Monitoring::On.describe(),
        Monitoring::OffBySetting.describe(),
        Monitoring::OffByPolicy.describe(),
    ];
    assert_eq!(described.len(), 3);
    assert_ne!(described[0], described[1]);
    assert_ne!(described[1], described[2]);
    assert_ne!(described[0], described[2]);

    // And a status whose record is present is one this product is holding off.
    assert_eq!(
        status.is_held_off_by_this_product(),
        status.record().is_some()
    );
}
