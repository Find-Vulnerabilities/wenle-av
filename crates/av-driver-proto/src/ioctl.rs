//! The IOCTL control codes this product exposes, derived the way `CTL_CODE`
//! derives them.
//!
//! # The arithmetic
//!
//! `wdm.h` line 7190 on the machine this was written on reads:
//!
//! ```text
//! #define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
//!     ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
//! )
//! ```
//!
//! That macro is copied here as [`ctl_code`] — a `const fn` rather than a
//! literal per code, because a literal is a number nobody can check and a call
//! is a number whose derivation is visible. The comment above the macro in the
//! same header says the rest of what matters: *"function codes 0-2047 are
//! reserved for Microsoft Corporation, and 2048-4095 are reserved for
//! customers"*. So every function below starts at `0x800`, and the tests pin
//! both that and the exact value of each code, so a typo in a shift shows up as
//! a failing assertion rather than as an IOCTL that silently returns
//! `STATUS_INVALID_DEVICE_REQUEST` on a machine nobody is watching.
//!
//! # Why `FILE_DEVICE_UNKNOWN`
//!
//! The header defines a large set of `FILE_DEVICE_*` values for Microsoft's own
//! stacks. Third-party drivers either take one of those (usually
//! `FILE_DEVICE_UNKNOWN`, `0x22`) and rely on the symbolic link name for
//! uniqueness, or invent a value in the `0x8000..=0xFFFF` range that Microsoft
//! reserves for vendors. This product uses `FILE_DEVICE_UNKNOWN`: the control
//! device is reached through the named symbolic link `\\.\WenleAvFilter`, the
//! device type plays no part in routing, and a made-up vendor range would only
//! be meaningful if we had a vendor ID to register it under. The value is
//! pinned by a test so nobody "tidies" it into a vendor range later without
//! noticing that it changes every code below.
//!
//! # Why `METHOD_BUFFERED` for all of them
//!
//! This is the decision the whole crate's buffer discipline hangs off, so it is
//! worth stating in full.
//!
//! | Method | Who copies | Who validates the user pointer |
//! |---|---|---|
//! | `METHOD_BUFFERED` | the I/O manager | the I/O manager |
//! | `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT` | the I/O manager, via MDLs | the I/O manager |
//! | `METHOD_NEITHER` | nobody | **the driver** |
//!
//! Only `METHOD_NEITHER` hands the driver a raw user-mode virtual address, and
//! it does so for both the input and the output buffer, at whatever IRQL the
//! caller's thread happens to be at. Handling that correctly means a
//! `ProbeForRead`/`ProbeForWrite` pair for the right length and alignment,
//! wrapping the access in `try`/`except` because probing is not a guarantee,
//! and then a second validation pass because the buffer can be unmapped by
//! another thread in the originating process between the probe and the read.
//! That is a well-known source of kernel vulnerabilities, and it buys a copy
//! saved on payloads that are a few hundred bytes.
//!
//! `METHOD_IN_DIRECT` and `METHOD_OUT_DIRECT` exist to avoid a copy for bulk
//! transfer, and they still require the driver to reach through an MDL. The
//! largest structure defined in [`crate::wire`] is a little over 2 KB. The copy
//! is not a cost worth a single line of pointer validation.
//!
//! What `METHOD_BUFFERED` does *not* do is make the lengths trustworthy. The
//! I/O manager allocates `max(InputBufferLength, OutputBufferLength)` bytes of
//! nonpaged pool and copies the input in — and both lengths come from
//! `Parameters.DeviceIoControl` in an IRP that any process with a handle to the
//! control device can construct. A driver that allocates on
//! `InputBufferLength` has handed an attacker an unbounded pool allocation.
//! Every length in this protocol is therefore checked against the fixed size of
//! the structure it is supposed to be, never used as an allocation size, and
//! [`crate::wire`] states that as a rule for the messages too.

/// `FILE_DEVICE_UNKNOWN` from `wdm.h`. See the module documentation for why
/// this product uses it rather than a vendor range.
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;

/// `METHOD_BUFFERED` from `wdm.h`. The only method this protocol uses.
pub const METHOD_BUFFERED: u32 = 0;

/// `FILE_ANY_ACCESS` from `wdm.h`. Any handle to the control device may issue
/// the request; the device object's security descriptor is what restricts it.
pub const FILE_ANY_ACCESS: u32 = 0;

/// `FILE_READ_DATA` from `wdm.h`, used as the `Access` field.
pub const FILE_READ_DATA: u32 = 0x0001;

/// `FILE_WRITE_DATA` from `wdm.h`, used as the `Access` field.
pub const FILE_WRITE_DATA: u32 = 0x0002;

/// The `CTL_CODE` macro, transcribed from `wdm.h`.
///
/// `const` so that a control code can be a `match` arm and a `static`, and so
/// that the derivation is checkable at a glance instead of hidden behind a
/// hex literal.
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

// --- the decoder half of `wdm.h` -------------------------------------------
//
// `wdm.h` also defines `DEVICE_TYPE_FROM_CTL_CODE`, `METHOD_FROM_CTL_CODE` and
// friends. They exist for the same reason these do: a driver that agrees with
// user mode about which code it is looking at, and can prove it. The tests
// below round-trip every code through the decoder.

/// `DEVICE_TYPE_FROM_CTL_CODE`: the top 16 bits.
pub const fn device_type_from(code: u32) -> u32 {
    (code & 0xffff_0000) >> 16
}

/// `METHOD_FROM_CTL_CODE`: the bottom 2 bits.
pub const fn method_from(code: u32) -> u32 {
    code & 0x3
}

/// The `Access` field: bits 14 and 15.
pub const fn access_from(code: u32) -> u32 {
    (code >> 14) & 0x3
}

/// The `Function` field: bits 2 through 13.
pub const fn function_from(code: u32) -> u32 {
    (code >> 2) & 0x0fff
}

/// The lowest function code the header leaves to anyone but Microsoft.
pub const FIRST_CUSTOMER_FUNCTION: u32 = 0x800;

// --- the control surface ---------------------------------------------------
//
// These are the user-initiated requests only. The decision path — the driver
// asking user mode for a verdict and waiting for the answer — does not use an
// IOCTL at all; it uses the filter communication port, because an IOCTL is
// initiated by user mode and there is no way for a driver to "call out" with
// one. See the crate documentation for the full argument.

/// Query the driver's liveness counters. `wire::DriverStatus` out.
///
/// `FILE_ANY_ACCESS`: the service probes this to decide whether the driver is
/// loaded and healthy, and it carries no information an unprivileged caller
/// could use against the machine.
pub const IOCTL_QUERY_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Query the enforcement counters. `wire::DriverStats` out.
pub const IOCTL_GET_STATS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Set the enforcement mode and the decision timeout. `wire::SetModeRequest` in.
///
/// `FILE_WRITE_DATA` rather than `FILE_ANY_ACCESS`, and deliberately so: this is
/// the request that can turn a blocking filter into an observational one, and
/// the `Access` field is a second, independent check that survives a mistake in
/// the device object's ACL. A caller that can only read the device cannot
/// weaken the product.
pub const IOCTL_SET_MODE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA);

/// Replace the exclusion table. `wire::ExclusionBuffer` in.
///
/// `FILE_WRITE_DATA`, for the same reason as [`IOCTL_SET_MODE`] and more of it:
/// an exclusion is a hole in the filter, and the only thing standing between a
/// user-mode process and "make the filter ignore `C:\`" is this check plus the
/// device ACL.
pub const IOCTL_SET_EXCLUSIONS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA);

/// Drain queued events. `wire::EventBatch` out.
///
/// `FILE_READ_DATA`: the events name files and processes the user has been
/// running.
pub const IOCTL_READ_EVENTS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA);

/// Query the protocol version this driver speaks. `u32` out.
///
/// Exists so that a service and a driver that were installed at different times
/// can find out before they exchange a single fixed-layout message. A driver
/// from a newer build and a service from an older one agree on nothing about
/// [`crate::wire`]'s layout, and the failure mode without this check is a
/// misinterpreted verdict rather than a clean error.
pub const IOCTL_GET_VERSION: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Every control code this driver answers, for a test to walk and a driver's
/// `IRP_MJ_DEVICE_CONTROL` handler to sanity-check its own table against.
pub const ALL_CONTROL_CODES: [u32; 6] = [
    IOCTL_QUERY_STATUS,
    IOCTL_SET_MODE,
    IOCTL_GET_STATS,
    IOCTL_SET_EXCLUSIONS,
    IOCTL_READ_EVENTS,
    IOCTL_GET_VERSION,
];

/// The protocol version. Bumped whenever a structure in [`crate::wire`] changes
/// shape.
///
/// A version and not a hash of the layout: the driver has to compare this
/// against a constant compiled into the service, and the service needs to be
/// able to say *which* version it wanted in an error message a human reads.
/// `0x0001_0001` — major in the high half, minor in the low — so that a service
/// can require "same major, any minor" once the protocol has a compatibility
/// story worth having. It does not have one yet, and [`crate::wire::is_compatible`]
/// refuses anything but an exact match until it does.
///
/// `0x0001_0001` (2026-10-18) added `EventMessage::parent_process_id` and
/// `_reserved`: every event grew by 8 bytes and every field after
/// `process_id` moved. A driver and a service of different minor versions
/// would read each other's events at the wrong offsets, so the exact-match
/// rule is what keeps this safe — deploy both halves together.
///
/// `0x0001_0002` (2026-10-18) added vocabulary rather than layout:
/// [`crate::event::EventAction::FileRenamed`],
/// [`crate::event::EventAction::FileDeleted`] and
/// [`crate::event::EventAction::RegistryChanged`] (wire codes 9, 10 and 11), and
/// [`crate::event::SubjectKind::Registry`] (wire code 6). No offset moved, so an old service
/// *could* survive this pair — it would report those events as `Unrecognised`.
/// It is bumped anyway because the exact-match rule refuses that pairing
/// outright, and "the two halves are from the same build" is a stronger
/// statement than "the offsets happen to agree".
pub const PROTOCOL_VERSION: u32 = 0x0001_0002;

#[cfg(test)]
mod tests {
    use super::*;

    /// The published values, computed by hand from the macro rather than by
    /// calling [`ctl_code`] — otherwise this test would only prove that the
    /// function agrees with itself.
    ///
    /// `0x22 << 16` is `0x0022_0000`; a function code of `0x800` shifted left
    /// two is `0x2000`; `METHOD_BUFFERED` is zero; `FILE_WRITE_DATA` is `2`, and
    /// `2 << 14` is `0x8000`; `FILE_READ_DATA` is `1`, and `1 << 14` is
    /// `0x4000`.
    #[test]
    fn control_codes_have_the_values_the_macro_produces() {
        assert_eq!(IOCTL_QUERY_STATUS, 0x0022_2000);
        assert_eq!(IOCTL_GET_STATS, 0x0022_2008);
        assert_eq!(IOCTL_SET_MODE, 0x0022_A004);
        assert_eq!(IOCTL_SET_EXCLUSIONS, 0x0022_A00C);
        assert_eq!(IOCTL_READ_EVENTS, 0x0022_6010);
        assert_eq!(IOCTL_GET_VERSION, 0x0022_2014);
    }

    /// The `Access` field is not decoration. `SET_MODE` and `SET_EXCLUSIONS`
    /// must be distinguishable from read-only requests by the field alone,
    /// because that field is what the I/O manager checks against the handle's
    /// granted access.
    #[test]
    fn access_bits_separate_the_privileged_requests_from_the_read_only_ones() {
        assert_eq!(access_from(IOCTL_SET_MODE), FILE_WRITE_DATA);
        assert_eq!(access_from(IOCTL_SET_EXCLUSIONS), FILE_WRITE_DATA);
        assert_eq!(access_from(IOCTL_READ_EVENTS), FILE_READ_DATA);
        assert_eq!(access_from(IOCTL_QUERY_STATUS), FILE_ANY_ACCESS);
        assert_ne!(access_from(IOCTL_SET_MODE), access_from(IOCTL_QUERY_STATUS));
    }

    /// Every code decodes back to what it was built from. If a field ever
    /// overlapped another this is what catches it.
    #[test]
    fn every_code_round_trips_through_the_decoders() {
        // One array of triples, not two parallel arrays. Two parallel arrays
        // is how this test first went wrong: `functions` was written in
        // declaration order while `accesses` was written in number order, and
        // the two drifted by one entry without either looking wrong.
        let expected = [
            (0x800u32, FILE_ANY_ACCESS),
            (0x801, FILE_WRITE_DATA),
            (0x802, FILE_ANY_ACCESS),
            (0x803, FILE_WRITE_DATA),
            (0x804, FILE_READ_DATA),
            (0x805, FILE_ANY_ACCESS),
        ];
        assert_eq!(ALL_CONTROL_CODES.len(), expected.len());
        for (code, &(function, access)) in ALL_CONTROL_CODES.iter().zip(expected.iter()) {
            assert_eq!(device_type_from(*code), FILE_DEVICE_UNKNOWN, "{code:#010X}");
            assert_eq!(function_from(*code), function, "{code:#010X}");
            assert_eq!(method_from(*code), METHOD_BUFFERED, "{code:#010X}");
            assert_eq!(access_from(*code), access, "{code:#010X}");
        }
    }

    /// The header reserves functions below `0x800` for Microsoft. A code that
    /// strayed into that range would collide with a Windows stack's own request
    /// and the failure would be a `STATUS_INVALID_DEVICE_REQUEST` that looks
    /// like a driver bug rather than a numbering mistake.
    #[test]
    fn no_control_code_uses_a_reserved_function_number() {
        for code in ALL_CONTROL_CODES {
            assert!(
                function_from(code) >= FIRST_CUSTOMER_FUNCTION,
                "{code:#010X} uses a function code Microsoft reserves"
            );
            assert!(
                function_from(code) <= 0x0fff,
                "{code:#010X} overflows Function"
            );
        }
    }

    /// Two requests must never share a control code: the handler is a `match`
    /// on this value, and a duplicate would make one of them unreachable.
    #[test]
    fn control_codes_are_distinct() {
        for (i, a) in ALL_CONTROL_CODES.iter().enumerate() {
            for b in &ALL_CONTROL_CODES[i + 1..] {
                assert_ne!(a, b, "duplicate control code {a:#010X}");
            }
        }
    }

    /// `METHOD_BUFFERED` is zero, so a code built with it has its low two bits
    /// clear. Asserted through the decoder rather than the constant so the test
    /// would notice if someone switched a request to `METHOD_NEITHER` without
    /// also reading the module documentation about who validates pointers.
    #[test]
    fn every_request_is_buffered() {
        assert_eq!(METHOD_BUFFERED, 0);
        for code in ALL_CONTROL_CODES {
            assert_eq!(
                method_from(code),
                METHOD_BUFFERED,
                "{code:#010X} is not a buffered request"
            );
            assert_eq!(
                code & 0x3,
                0,
                "{code:#010X} has a non-buffered method field"
            );
        }
    }
}
