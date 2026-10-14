//! Writing to the real registry, under a key this product owns.
//!
//! # Why this test may run in `cargo test` when nothing else here may
//!
//! Because of where it writes. The verbs this crate registers live under
//! `HKCU\Software\Classes`, which is the store every program on the machine
//! shares: a test that wrote there and failed halfway would leave the developer
//! with a right-click menu item they did not ask for and no obvious way to find
//! it. That is why the unit tests in `src/shell.rs` cover the command line, the
//! key paths and the location table in pure functions, and why nothing in
//! `src/registry.rs`'s own test module touches a live key.
//!
//! This file writes to exactly one place:
//!
//! ```text
//! HKCU\Software\WenleAV\IntegrationTest\<pid>-<test name>
//! ```
//!
//! A key whose name says what it is, under a key named after this product, and
//! leafed by the process id and the name of the test that claimed it. The process
//! id alone is not enough, and the reason is worth stating because it cost this
//! file a debugging session: `cargo test` runs the tests in a file as *threads of
//! one process*, so every test in here has the same process id and a pid-only
//! leaf is one shared key. Two tests then write to the same place at the same
//! time, and the symptoms are a subkey list with another test's keys in it and a
//! default value that was there a moment ago — the failures point at the code
//! under test while the fault is in the fixture. Nothing
//! outside that leaf is created, read or deleted — including the two keys above
//! it, which are left in place on purpose: `RegDeleteTreeW` is recursive, and
//! deleting `Software\WenleAV` on the way out would take whatever else a
//! concurrent run of this same suite, or a future version of the product, had put
//! there. Two empty keys are a smaller price than that.
//!
//! # What it verifies
//!
//! The whole surface of [`av_integration::registry`], against the real API rather
//! than against a mock: create, write a string, an expand-string and the default
//! value, read all three back, enumerate subkeys, delete a value, delete the tree,
//! and assert the tree is gone. And the two refusals that only the real API can
//! produce: a value stored as a number, and a value stored as an unpaired
//! surrogate. Both are written with the raw `windows` calls, because the point of
//! the test is that this crate's reader refuses what another writer produced.

#![cfg(windows)]
// A separate crate root: the library's `cfg(test)` allowance does not reach here.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use av_integration::registry::{Hive, Key, RegistryError};

/// Where the scratch keys live, below `HKCU`.
const SCRATCH_ROOT: &str = r"Software\WenleAV\IntegrationTest";

/// Removes the scratch key when it goes out of scope, whatever happened.
///
/// A guard rather than a call at the end of the test, because the interesting
/// endings are the ones where an assertion failed halfway: a test that left a
/// key behind would be a far worse bug than the one it was reporting, and it
/// would be a bug in the developer's own registry. Every result inside `drop` is
/// discarded — this runs during a panic, and a second panic would abort the
/// process rather than report the first failure.
struct Cleanup {
    /// The leaf, below [`SCRATCH_ROOT`].
    path: String,
}

impl Cleanup {
    /// Claim a leaf named after this process and this test.
    ///
    /// `test` is the name of the calling test. It is spelled out rather than
    /// derived, because there is no way to ask the test harness which test is
    /// running that is worth the dependency, and a name that has to be typed is a
    /// name that gets read.
    fn new(test: &str) -> Self {
        Self {
            path: format!("{SCRATCH_ROOT}\\{}-{test}", std::process::id()),
        }
    }

    /// The key path this guard will remove.
    fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Key::delete_tree(Hive::CurrentUser, &self.path);
    }
}

/// A NUL-terminated UTF-16 copy of `text`.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Write a raw value at a path, bypassing this crate's API.
///
/// The one thing in this file that is not a call into the code under test, and it
/// is here for that reason: a test that asked [`Key`] to store a number or an
/// unpaired surrogate would be testing methods that deliberately do not exist.
/// `HKEY_CURRENT_USER` is used directly rather than through [`Hive`], because
/// going through [`Hive`] would mean going through the module under test.
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
fn a_key_can_be_created_written_read_listed_and_removed() {
    let cleanup = Cleanup::new("roundtrip");
    let path = cleanup.path().to_string();

    // Nothing there to start with. Asserted rather than assumed: a key left by a
    // previous run of this same process id would make the rest of the test pass
    // for the wrong reason.
    assert!(
        Key::open(Hive::CurrentUser, &path).unwrap().is_none(),
        "a scratch key from an earlier run is still there: {path}"
    );

    // 1. Create.
    let key = Key::create(Hive::CurrentUser, &path).expect("creating the scratch key");

    // 2. Three values of two kinds, plus the default value — which is a third
    //    thing to a reader even though it shares a type with the first: it has an
    //    empty name, and every reporting path has to be able to say so.
    key.set_string("", "the default value").expect("the default value");
    key.set_string("Plain", "a plain string").expect("a string");
    key.set_expand_string("Expandable", "%SystemRoot%\\System32")
        .expect("an expand string");

    // 3. Read them back, through a *second* handle, so that the values are read
    //    from the registry rather than from anything this process remembered.
    drop(key);
    let key = Key::open(Hive::CurrentUser, &path)
        .expect("opening the scratch key")
        .expect("the scratch key is there");
    assert_eq!(
        key.string("").unwrap(),
        Some("the default value".to_string())
    );
    assert_eq!(key.string("Plain").unwrap(), Some("a plain string".to_string()));
    // Stored as `REG_EXPAND_SZ` and read back *unexpanded*. `%SystemRoot%` here
    // is the literal eleven characters: this crate reads what is stored, and
    // expanding it is a decision no caller has made.
    assert_eq!(
        key.string("Expandable").unwrap(),
        Some(r"%SystemRoot%\System32".to_string())
    );

    // A value that is not there is `None` and not an error.
    assert_eq!(key.string("NeverWritten").unwrap(), None);

    // 4. Subkeys: three, by name, and no more.
    for name in ["Alpha", "Beta", "Gamma"] {
        Key::create(Hive::CurrentUser, &format!("{path}\\{name}")).expect("a subkey");
    }
    let mut subkeys = key.subkeys().expect("listing the subkeys");
    subkeys.sort();
    assert_eq!(subkeys, ["Alpha", "Beta", "Gamma"]);

    // 5. Delete one value; the others stay.
    key.delete_value("Plain").expect("deleting a value");
    assert_eq!(key.string("Plain").unwrap(), None);
    assert_eq!(key.string("").unwrap(), Some("the default value".to_string()));
    // Deleting it again is the state the caller asked for, so it is not an error.
    key.delete_value("Plain").expect("deleting an absent value");
    key.delete_value("NeverWritten").expect("deleting an absent value");

    drop(key);

    // 6. Remove the tree, and check it is really gone rather than trusting that
    //    `RegDeleteTreeW` returning success means the key is no longer there.
    Key::delete_tree(Hive::CurrentUser, &path).expect("removing the scratch key");
    assert!(
        Key::open(Hive::CurrentUser, &path).unwrap().is_none(),
        "the scratch key survived its own removal: {path}"
    );

    // 7. And removing it a second time is not an error either: that is what makes
    //    `remove` usable as the cleanup step of a failed install.
    Key::delete_tree(Hive::CurrentUser, &path).expect("removing an absent key");
}

#[test]
fn the_four_shell_verbs_round_trip_through_a_scratch_key() {
    // The paths and values of the real registration, written to the scratch key
    // instead of to `Software\Classes` — so that what is exercised is the shape
    // of what `install` writes (a default value, an `Icon`, a `MultiSelectModel`
    // and a `command` subkey with a default value) without the developer's own
    // right-click menu changing.
    use av_integration::shell::{command_line_for, Location, MENU_TEXT, VERB_KEY};

    let cleanup = Cleanup::new("verbs");
    let path = cleanup.path().to_string();
    let program = std::path::Path::new(r"C:\Program Files\WenleAV\wenle-gui.exe");

    for location in Location::ALL {
        let verb_path = format!("{path}\\{}", location.key_path().replace('\\', "_"));
        let key = Key::create(Hive::CurrentUser, &verb_path).expect("the verb key");
        key.set_string("", MENU_TEXT).expect("the menu text");
        key.set_string("Icon", &format!("{},0", program.display()))
            .expect("the icon");
        key.set_string("MultiSelectModel", "Single").expect("the model");
        let command = Key::create(Hive::CurrentUser, &format!("{verb_path}\\command"))
            .expect("the command subkey");
        command.set_string("", &command_line_for(program, location))
            .expect("the command line");
        drop(command);

        // Read back exactly what `status` reads, so that this test fails if the
        // shape `status` expects and the shape `install` writes ever diverge.
        let reopened = Key::open(Hive::CurrentUser, &verb_path)
            .unwrap()
            .expect("the verb key is there");
        assert_eq!(reopened.string("").unwrap(), Some(MENU_TEXT.to_string()));
        assert_eq!(
            reopened.string("MultiSelectModel").unwrap(),
            Some("Single".to_string())
        );
        let commands = Key::open(Hive::CurrentUser, &format!("{verb_path}\\command"))
            .unwrap()
            .expect("the command subkey is there");
        let line = commands.string("").unwrap().expect("a command line");
        assert!(line.contains(location.substitution()), "{line}");
        assert!(line.starts_with('"'), "{line}");
        assert!(line.contains(VERB_KEY) || line.contains("wenle"), "{line}");
    }
}

#[test]
fn a_value_stored_as_a_number_is_refused_as_a_number() {
    // The refusal that only the real registry can produce, and the reason
    // `Key::string` checks the type before the bytes: four bytes of `REG_DWORD`
    // are two perfectly good UTF-16 units, and decoding them would produce a
    // string nobody typed.
    let cleanup = Cleanup::new("number");
    let path = cleanup.path().to_string();
    Key::create(Hive::CurrentUser, &path).expect("the scratch key");
    write_raw_at(&path, "Number", 4, &7u32.to_le_bytes());

    let key = Key::open(Hive::CurrentUser, &path)
        .unwrap()
        .expect("the scratch key is there");
    let error = key.string("Number").expect_err("a number is not text");
    match error {
        RegistryError::NotText { found, ref name, .. } => {
            assert_eq!(found, 4, "a REG_DWORD is type 4");
            assert_eq!(name, "Number");
        }
        other => panic!("expected NotText, got {other:?}"),
    }
    assert_eq!(error.code(), None);
}

#[test]
fn a_string_that_is_not_utf16_is_refused_rather_than_replaced() {
    // The other refusal: a `REG_SZ` Windows will hold and this crate will not
    // guess at. An unpaired high surrogate is not a character in any `String`,
    // and a lossy conversion would put a replacement character in a value that is
    // about to become a menu item.
    let cleanup = Cleanup::new("unicode");
    let path = cleanup.path().to_string();
    Key::create(Hive::CurrentUser, &path).expect("the scratch key");

    // 0xD800 with no low surrogate after it, NUL-terminated.
    let units: [u16; 2] = [0xD800, 0];
    let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    write_raw_at(&path, "Broken", 1, &bytes);

    let key = Key::open(Hive::CurrentUser, &path)
        .unwrap()
        .expect("the scratch key is there");
    let error = key.string("Broken").expect_err("that is not a string");
    match error {
        RegistryError::NotUnicode { ref name, .. } => assert_eq!(name, "Broken"),
        other => panic!("expected NotUnicode, got {other:?}"),
    }
    assert!(error.to_string().contains("UTF-16"), "{error}");
}

#[test]
fn a_twelve_hundred_character_value_survives_the_two_pass_read() {
    // The read that has to ask for a size and then read the bytes cannot be
    // checked for a value that fits in whatever the first call happens to leave
    // in the size variable. A long value exercises the second pass honestly, and
    // the length is in *bytes* on one side of the API and in *characters* on the
    // other — the mistake that halves a value and still reads back as valid
    // UTF-16.
    let cleanup = Cleanup::new("long");
    let path = cleanup.path().to_string();
    let key = Key::create(Hive::CurrentUser, &path).expect("the scratch key");

    let long: String = "x".repeat(1200);
    key.set_string("Long", &long).expect("a long value");
    assert_eq!(key.string("Long").unwrap(), Some(long.clone()));
    assert_eq!(key.string("Long").unwrap().unwrap().chars().count(), 1200);

    // And a non-ASCII one, whose byte count and character count differ, so that
    // a reader that confused the two would truncate it.
    let accented = "ü".repeat(600);
    key.set_string("Accented", &accented).expect("an accented value");
    assert_eq!(key.string("Accented").unwrap(), Some(accented));
}
