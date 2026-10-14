//! A module nothing has touched may be unloaded.
//!
//! # Why this is its own file, and its own process
//!
//! `can_unload` reads two process-globals: how many COM objects are alive,
//! and whether the worker thread has been started. Cargo runs every test in one
//! binary as threads of one process, so a test asserting "nothing has happened
//! yet" races every other test in the same binary that makes something happen.
//!
//! These assertions were inline unit tests until they were seen to fail for
//! exactly that reason: `a_real_class_object_comes_back_for_this_servers_own_clsid`
//! creates a factory and `scan`'s tests start the worker, and whether the
//! pristine test ran before or after them was up to the scheduler.
//!
//! A test file is a test binary, and a test binary is a process. One scenario
//! per file is the only way to state a fact about process-global state without
//! lying about it — so that is what these three files are, and each holds
//! exactly one test for the same reason.

use av_amsi::{can_unload, DllCanUnloadNow};
use windows::Win32::Foundation::S_OK;

#[test]
fn a_module_nothing_has_touched_may_be_unloaded() {
    // A host that loads this DLL to look at it — an installer verifying its own
    // registration, a provider enumeration — and never asks it a question must
    // be able to unload it again. If this answer were `S_FALSE` from the start,
    // every such host would leak the image for the life of its process.
    assert!(can_unload());
    assert_eq!(DllCanUnloadNow(), S_OK);
}
