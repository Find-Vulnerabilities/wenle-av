//! The name of the filter communication port, spelled once.
//!
//! # Why this is a module and not two literals
//!
//! The driver creates the port and user mode connects to it, and the two are in
//! different crates that cannot see each other's constants — the driver is
//! `no_std` and links nothing from this workspace except this crate. So the name
//! would naturally be written twice, and it was: the driver created
//! `\WenleAvFilterPort` while `av_core::DRIVER_PORT_NAME`, documented as the
//! port "the user-mode scanner connects to", said `\WenleAVPort`. Three
//! characters apart, referenced by nothing but its own test, and a user-mode
//! client written against it would have called `FilterConnectCommunicationPort`
//! on a port that does not exist.
//!
//! That failure is worth spelling out because of how it looks from outside: the
//! connect fails, the client reports no driver, the driver's `CLIENT_PORT` stays
//! null, every decision takes the "there is nobody to ask" path, and the product
//! runs with the filter attached and blocking nothing. No error is raised
//! anywhere, because a driver with no service connected is a supported state
//! rather than a fault. A name that disagrees with itself is therefore not a
//! typo that shows up in testing; it is a silent loss of the entire real-time
//! path.
//!
//! Both sides now read it from here. [`NAME_BYTES`] is derived from [`NAME`]
//! rather than written out, so the two forms cannot drift.
//!
//! # The namespace, and what a name here may contain
//!
//! The name lives in the filter manager's own namespace — it is not a DOS device
//! name and has no `\??\` prefix — and the object manager matches it
//! case-insensitively, which is why [`NAME`]'s exact casing is not load-bearing
//! and is nonetheless fixed: it is what appears in a debugger.
//!
//! It is ASCII by construction and must stay that way: the driver encodes it
//! into a counted `UNICODE_STRING` one `u16` at a time without an allocator, and
//! the fixup for a non-ASCII character is a code-page guess the kernel driver
//! has no business making. [`NAME_BYTES`] having no interior NUL is what makes
//! the byte form usable as a counted string at all.

/// The name of the filter communication port the driver creates.
///
/// The leading backslash is part of the name and not a path separator: the
/// filter manager's namespace is flat, and a name without it is a different
/// name.
pub const NAME: &str = r"\WenleAvFilterPort";

/// [`NAME`] as the ASCII bytes the driver encodes into a `UNICODE_STRING`.
///
/// Derived, not repeated. `str::as_bytes` is a `const fn`, so this costs
/// nothing and one string literal still has one spelling.
pub const NAME_BYTES: &[u8] = NAME.as_bytes();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_a_single_component_of_the_filter_namespace() {
        // One leading backslash and no others. A name that read
        // `\Device\WenleAvFilterPort` would be a name in the object manager's
        // namespace, which is not where `FltCreateCommunicationPort` puts it.
        assert!(NAME.starts_with('\\'), "{NAME}");
        assert_eq!(
            NAME.trim_start_matches('\\').matches('\\').count(),
            0,
            "{NAME} has a separator in it"
        );
        assert!(NAME.len() > 1, "{NAME} is only a root");
    }

    #[test]
    fn the_byte_form_is_ascii_and_has_no_interior_nul() {
        // What the driver needs to build a counted string that means what it
        // says. A byte above 0x7F would be encoded per a code page, and an
        // interior NUL would silently shorten the name to whatever precedes it.
        assert!(
            NAME_BYTES.is_ascii(),
            "the port name must be ASCII, because the driver encodes it without an allocator"
        );
        assert!(
            !NAME_BYTES.contains(&0),
            "a NUL in the name would truncate it"
        );
        assert_eq!(NAME_BYTES.len(), NAME.len(), "one byte per ASCII character");
    }

    #[test]
    fn the_name_fits_the_buffer_the_driver_encodes_it_into() {
        // `create_port` builds a `[u16; 32]` on the kernel stack and passes the
        // used length to `FltCreateCommunicationPort`. A longer name would be
        // truncated there, and a truncated port name is a port nobody connects
        // to -- the same silent failure this module exists to prevent, arriving
        // by a different route.
        const KERNEL_NAME_UNITS: usize = 32;
        assert!(
            NAME_BYTES.len() <= KERNEL_NAME_UNITS,
            "the port name is {} characters and the driver's buffer holds {KERNEL_NAME_UNITS}",
            NAME_BYTES.len()
        );
    }
}
