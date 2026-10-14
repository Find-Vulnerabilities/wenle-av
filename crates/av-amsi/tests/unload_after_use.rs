//! Once a scan has run, the module is pinned for the life of the process.
//!
//! One scenario, one process — see `unload_before_use.rs` for why these are
//! separate files.
//!
//! This is the permanent half of the answer, and the reason it is permanent is
//! the worker thread: it has a program counter inside this image and sits in
//! `recv` between jobs, so unloading the module under it is a crash the next
//! time a script is run. `S_FALSE` from here on is not a leak to be fixed, it
//! is the only sound answer, and it is what every AMSI provider on the machine
//! answers after its first scan.
//!
//! The scan itself is expected to fail — there is no service behind the pipe
//! name in a test process. That is the point of using it here: the pin comes
//! from the thread having been *created*, not from the scan having succeeded.

use std::time::Duration;

use av_amsi::{can_unload, DllCanUnloadNow, Scan, Scanner};
use windows::Win32::Foundation::{S_FALSE, S_OK};

#[test]
fn a_scan_pins_the_module_for_the_rest_of_the_process() {
    assert!(can_unload(), "nothing has happened yet");
    assert_eq!(DllCanUnloadNow(), S_OK);

    let scanner = Scanner::with_budget(Duration::from_millis(200));
    let scan = scanner.scan("Script Block", b"Get-ChildItem");
    assert!(
        matches!(scan, Scan::Unavailable(_)),
        "no service answers in a test process: {scan:?}"
    );

    assert!(
        !can_unload(),
        "a thread with a program counter in this image pins it for ever"
    );
    assert_eq!(DllCanUnloadNow(), S_FALSE);

    // And it stays pinned: a second scan changes nothing, because the thread
    // that pins it was never going to be stopped.
    let _ = scanner.scan("Script Block", b"Get-ChildItem");
    assert!(!can_unload());
    assert_eq!(DllCanUnloadNow(), S_FALSE);
}
