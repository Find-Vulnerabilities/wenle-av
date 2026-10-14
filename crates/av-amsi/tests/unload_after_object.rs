//! A live provider pins the module; releasing it lets the module go again.
//!
//! One scenario, one process — see `unload_before_use.rs` for why these are
//! separate files.
//!
//! This is the test that proves the object counter is decremented and not only
//! incremented. A `Provider` is a pointer into this module's code, so `S_OK`
//! while one is alive is COM unloading an image that a live vtable points into.
//! The other direction matters just as much and is easier to get wrong: a
//! counter that never goes back down means the DLL is pinned for the life of
//! every host that ever asked it a question.
//!
//! Nothing here starts the worker thread — `Scanner::start` deliberately does
//! not — so the only thing this process-global can be reacting to is the object
//! count.

use av_amsi::{can_unload, DllCanUnloadNow, Provider, Scanner};
use windows::Win32::Foundation::{S_FALSE, S_OK};

#[test]
fn a_live_provider_pins_the_module_until_it_is_released() {
    assert!(can_unload(), "nothing has been made yet");

    let provider = Provider::new(Scanner::start());
    assert!(!can_unload(), "a live object is a pointer into this image");
    assert_eq!(DllCanUnloadNow(), S_FALSE);

    drop(provider);
    assert!(can_unload(), "the only object was released");
    assert_eq!(DllCanUnloadNow(), S_OK);
}
