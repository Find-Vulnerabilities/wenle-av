//! What this service knows about the kernel driver, and how it found out.
//!
//! # Three answers, not two
//!
//! [`av_ipc::DriverPresence`] has three states and this module is why: a build
//! that cannot check must say so rather than answer "no driver" about something
//! it never looked at. This build *can* check — the control device's name is in
//! `av_driver_proto::ioctl`'s module documentation, and opening it is an
//! ordinary `CreateFileW` — so the honest answer here is `Loaded` or `Absent`,
//! both with a sentence saying which call produced it. `Unknown` remains for the
//! case where the check itself failed for a reason that is neither.
//!
//! # What opening the device proves, and what it does not
//!
//! It proves the driver is loaded and its control device exists. It does **not**
//! prove the driver is doing anything useful: a driver can be loaded with its
//! filter detached, or attached and in a mode that logs without blocking, or
//! attached and enforcing with nobody connected to its decision port — in which
//! case it blocks nothing at all. So the status this service reports is "the
//! driver is loaded" and never "you are protected by it" — the distinction
//! `av_realtime::finding`'s module documentation is built around, one layer down.
//!
//! What the driver is *doing* is [`crate::filter_port`]'s to say, and it says it
//! twice: `av_driver_proto::event::DriverState` arrives in the driver's status
//! messages and is recorded there, and the connection itself is published as a
//! `DriverEventAction::StateChanged` event when it comes and goes. This module
//! and that one answer different questions and are deliberately not merged.
//!
//! # The device name
//!
//! `\\.\WenleAvFilter`, which is the symbolic link `av-driver-proto`'s
//! documentation names as the control device's. The crate defines the *codes*
//! this device answers ([`av_driver_proto::ioctl`]) but not the link name, so it
//! is spelled once here and nowhere else.

use av_ipc::{DriverEvent, DriverEventAction, DriverPresence, DriverStatus, DriverSubject};

/// The symbolic link the driver's control device is reached through.
pub const CONTROL_DEVICE: &str = r"\\.\WenleAvFilter";

/// Ask the operating system whether the driver is loaded.
///
/// Opens the control device with read access and closes it immediately. The
/// open is the check: there is no cheaper way to ask, and a driver that created
/// its symbolic link and then failed to initialise is still reported as loaded,
/// which is why the detail sentence says what was opened rather than claiming
/// the driver works.
pub fn check() -> DriverStatus {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::GENERIC_READ;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let wide = crate::win32::to_wide_str(CONTROL_DEVICE);
        // SAFETY: `wide` is NUL-terminated and outlives the call; the remaining
        // arguments are values. `CreateFileW` signals failure through `Err`.
        let opened = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match opened {
            Ok(handle) => {
                // SAFETY: the handle came from `CreateFileW` and is used once,
                // here, to close it.
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                }
                DriverStatus {
                    presence: DriverPresence::Loaded,
                    detail: format!("{CONTROL_DEVICE} was opened, so the filter driver is loaded"),
                    device: Some(CONTROL_DEVICE.to_string()),
                }
            }
            // `ERROR_FILE_NOT_FOUND` and `ERROR_PATH_NOT_FOUND` are the two a
            // missing symbolic link produces, and they are an answer rather than
            // a failure.
            Err(error)
                if matches!(
                    crate::win32::code(&error),
                    crate::win32::ERROR_FILE_NOT_FOUND | crate::win32::ERROR_PATH_NOT_FOUND
                ) =>
            {
                DriverStatus {
                    presence: DriverPresence::Absent,
                    // The sentence used to end "so the driver is not loaded",
                    // and that is not what this measured. It measured that the
                    // control device does not exist — and this build's driver
                    // creates no control device at all (it registers a
                    // minifilter and a filter port, and `IoCreateDevice` occurs
                    // nowhere in `av-driver`), so a missing device is the
                    // expected answer on a machine where the driver *is* loaded.
                    // `Host::driver_status` is what turns this together with the
                    // port connection into the answer a reader wants.
                    detail: format!(
                        "{CONTROL_DEVICE} does not exist, so this service has no control device \
                         to ask"
                    ),
                    device: Some(CONTROL_DEVICE.to_string()),
                }
            }
            // Anything else — an access denial, a sharing conflict with another
            // opener — is the device being there and not answering, which is
            // neither "loaded" nor "not loaded". Reporting either one would be
            // inventing a fact.
            Err(error) => DriverStatus {
                presence: DriverPresence::Unknown,
                detail: format!(
                    "{CONTROL_DEVICE} could not be opened and the failure is neither a missing \
                     device nor a success: {error}"
                ),
                device: Some(CONTROL_DEVICE.to_string()),
            },
        }
    }
    #[cfg(not(windows))]
    {
        DriverStatus::unknown("this build has no Windows driver to check for")
    }
}

/// Translate one driver event into the protocol's vocabulary.
///
/// # Why the mapping is exhaustive on both sides
///
/// `av_driver_proto::event::EventAction` has no `#[non_exhaustive]` and neither
/// does [`DriverEventAction`], so adding an action on the driver's side stops
/// this build. That is the intent: the alternative is a wildcard arm that turns
/// a new driver action into silence, and silence from a security driver is
/// indistinguishable from a quiet machine.
///
/// The two *wire* fields are numbers, though, and a driver built against a later
/// protocol sends codes this build has no name for. Those land on
/// `Unrecognised { code }` — carried rather than dropped, so that a client can
/// show it and a log can record the number that would have to be added.
pub fn translate(message: &av_driver_proto::wire::EventMessage) -> DriverEvent {
    let mut event = DriverEvent {
        sequence: message.sequence,
        timestamp_100ns: message.timestamp_100ns,
        action: action_from_wire(message.action),
        subject: subject_from_wire(message.subject),
        path: path_of(message),
        process_id: message.process_id,
        parent_process_id: message.parent_process_id,
        thread_id: message.thread_id,
        detail: message.detail,
        value: value_of(message),
        command_line: None,
        // The driver's own status picture travels in a `Status` message of its
        // own rather than inside an event, and `crate::filter_port` is where it
        // is recorded. An `EventMessage` carries none, so `None` says "this
        // event carried none", which is true, rather than a status invented
        // here from an event that had nothing to do with one.
        driver_state: None,
    };
    // The one fact this function adds that the driver did not send. It happens
    // here, on the port thread, and not in the host loop, because the process
    // has to be alive for the question to be answerable: measured in the test
    // VM on 2026-10-23, `vssadmin delete shadows` finished in a few hundred
    // milliseconds and the host loop reached the event long after that.
    //
    // The cost is one `OpenProcess` plus one `NtQueryInformationProcess` per
    // process start -- both microseconds, and a process start is not a hot
    // event. Nothing here can block: the driver does not wait for an event's
    // acknowledgement (`reply_length` is zero for one).
    if event.action == DriverEventAction::ProcessStarted {
        #[cfg(windows)]
        {
            event.command_line = crate::win32::command_line(event.process_id);
        }
    }
    event
}

/// The action half of [`translate`].
fn action_from_wire(code: u32) -> DriverEventAction {
    use av_driver_proto::event::EventAction;
    match EventAction::from_wire(code) {
        Some(EventAction::ExecutionBlocked) => DriverEventAction::ExecutionBlocked,
        Some(EventAction::FileWritten) => DriverEventAction::FileWritten,
        Some(EventAction::ImageLoaded) => DriverEventAction::ImageLoaded,
        Some(EventAction::ProcessStarted) => DriverEventAction::ProcessStarted,
        Some(EventAction::WriteBlocked) => DriverEventAction::WriteBlocked,
        Some(EventAction::Heartbeat) => DriverEventAction::Heartbeat,
        Some(EventAction::StateChanged) => DriverEventAction::StateChanged,
        Some(EventAction::EventsDropped) => DriverEventAction::EventsDropped,
        Some(EventAction::FileRenamed) => DriverEventAction::FileRenamed,
        Some(EventAction::FileDeleted) => DriverEventAction::FileDeleted,
        Some(EventAction::RegistryChanged) => DriverEventAction::RegistryChanged,
        None => DriverEventAction::Unrecognised { code },
    }
}

/// The subject half of [`translate`].
fn subject_from_wire(code: u32) -> DriverSubject {
    use av_driver_proto::event::SubjectKind;
    match SubjectKind::from_wire(code) {
        Some(SubjectKind::File) => DriverSubject::File,
        Some(SubjectKind::Process) => DriverSubject::Process,
        Some(SubjectKind::Image) => DriverSubject::Image,
        Some(SubjectKind::Driver) => DriverSubject::Driver,
        Some(SubjectKind::Protection) => DriverSubject::Protection,
        Some(SubjectKind::Registry) => DriverSubject::Registry,
        None => DriverSubject::Unrecognised { code },
    }
}

/// The value an event carries, if it carries one.
///
/// Same discipline as [`path_of`], and the same reason: the field is a fixed
/// array with a *used length*, so a hostile or stale `value_units` is clamped
/// by the array rather than trusted. An event that names no value yields
/// `None` rather than an empty string, because "this key has a value whose data
/// is empty" and "this event carried no value" are different facts and a rule
/// already treats them differently: a `value_*` condition is not satisfied by
/// an event with no value.
///
/// A truncated value (the driver's `EVENT_VALUE_TRUNCATED`) arrives as the
/// prefix it is. That is deliberate and is not flagged further: every rule
/// written against a value matches a prefix of it, and the alternative —
/// refusing the event — would lose the very fact the field was added to carry.
fn value_of(message: &av_driver_proto::wire::EventMessage) -> Option<String> {
    let units = message.value_units as usize;
    if units == 0 {
        return None;
    }
    let used = units.min(message.value.len());
    let text = String::from_utf16_lossy(&message.value[..used]);
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// The path an event names, if it names one.
///
/// The driver's path field is a `[u16; 1024]` with a *used length* — not an
/// allocation size, which is `av-driver-proto`'s whole buffer discipline — so
/// this reads exactly `path_units` code units and never more. A `path_units` of
/// `u32::MAX` is truncated to the array, which is what makes the field safe by
/// construction rather than by a check here.
fn path_of(message: &av_driver_proto::wire::EventMessage) -> Option<std::path::PathBuf> {
    let units = message.path_units as usize;
    if units == 0 {
        return None;
    }
    let used = units.min(message.path.len());
    let text = String::from_utf16_lossy(&message.path[..used]);
    if text.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_driver_proto::event::{EventAction, SubjectKind};
    use av_driver_proto::wire::{EventMessage, MAX_PATH_UNITS};

    fn message(action: EventAction, subject: SubjectKind, path: &str) -> EventMessage {
        let mut message = EventMessage::new(7, 133_000_000_000_000_000, subject, action);
        let units: Vec<u16> = path.encode_utf16().collect();
        let used = units.len().min(MAX_PATH_UNITS);
        message.path[..used].copy_from_slice(&units[..used]);
        message.path_units = used as u32;
        message.process_id = 4321;
        message.parent_process_id = 4000;
        message.thread_id = 1234;
        message
    }

    #[test]
    fn every_driver_action_has_a_name_on_the_protocol_side() {
        // Exhaustive on purpose: a new `EventAction` on the driver's side stops
        // this build here rather than being silently dropped by a wildcard.
        let named = [
            (
                EventAction::ExecutionBlocked,
                DriverEventAction::ExecutionBlocked,
            ),
            (EventAction::FileWritten, DriverEventAction::FileWritten),
            (EventAction::ImageLoaded, DriverEventAction::ImageLoaded),
            (
                EventAction::ProcessStarted,
                DriverEventAction::ProcessStarted,
            ),
            (EventAction::WriteBlocked, DriverEventAction::WriteBlocked),
            (EventAction::Heartbeat, DriverEventAction::Heartbeat),
            (EventAction::StateChanged, DriverEventAction::StateChanged),
            (EventAction::EventsDropped, DriverEventAction::EventsDropped),
            (EventAction::FileRenamed, DriverEventAction::FileRenamed),
            (EventAction::FileDeleted, DriverEventAction::FileDeleted),
            (
                EventAction::RegistryChanged,
                DriverEventAction::RegistryChanged,
            ),
        ];
        for (driver_side, protocol_side) in named {
            assert_eq!(
                action_from_wire(driver_side.as_wire()),
                protocol_side,
                "{driver_side:?}"
            );
        }
        // And a code from a later protocol is carried rather than dropped.
        assert_eq!(
            action_from_wire(9999),
            DriverEventAction::Unrecognised { code: 9999 }
        );
    }

    #[test]
    fn every_subject_has_a_name_and_an_unknown_one_is_carried() {
        let named = [
            (SubjectKind::File, DriverSubject::File),
            (SubjectKind::Process, DriverSubject::Process),
            (SubjectKind::Image, DriverSubject::Image),
            (SubjectKind::Driver, DriverSubject::Driver),
            (SubjectKind::Protection, DriverSubject::Protection),
            (SubjectKind::Registry, DriverSubject::Registry),
        ];
        for (driver_side, protocol_side) in named {
            assert_eq!(subject_from_wire(driver_side.as_wire()), protocol_side);
        }
        assert_eq!(
            subject_from_wire(0),
            DriverSubject::Unrecognised { code: 0 }
        );
        assert_eq!(
            subject_from_wire(u32::MAX),
            DriverSubject::Unrecognised { code: u32::MAX }
        );
    }

    #[test]
    fn an_event_carries_its_path_and_its_ids_and_nothing_it_did_not_have() {
        let translated = translate(&message(
            EventAction::ExecutionBlocked,
            SubjectKind::Process,
            r"\Device\HarddiskVolume3\Users\me\Downloads\invoice.exe",
        ));
        assert_eq!(translated.sequence, 7);
        assert_eq!(translated.timestamp_100ns, 133_000_000_000_000_000);
        assert_eq!(translated.action, DriverEventAction::ExecutionBlocked);
        assert_eq!(translated.subject, DriverSubject::Process);
        assert_eq!(translated.process_id, 4321);
        // The creator, carried rather than looked up later: it is only knowable
        // at creation time and the parent may be gone by the time a rule reads
        // the event.
        assert_eq!(translated.parent_process_id, 4000);
        assert_eq!(translated.thread_id, 1234);
        assert!(translated.path.is_some());
        // The one thing this build must not invent: a driver status it never
        // received. The filter port carries it and the filter port is not
        // connected.
        assert!(translated.driver_state.is_none());
        // A heartbeat carries no subject path, and `None` is the honest answer.
        let heartbeat = translate(&message(EventAction::Heartbeat, SubjectKind::Driver, ""));
        assert!(heartbeat.path.is_none());
        assert_eq!(heartbeat.detail, 0);
        // And no value, for the same reason: this event carried none.
        assert!(translated.value.is_none());
    }

    #[test]
    fn a_registry_value_write_carries_what_was_written() {
        // The whole point of the field: two `Run` writes that a rule must tell
        // apart arrive as two different strings, where before they arrived as
        // the same key path and nothing else.
        let mut raw = message(
            EventAction::RegistryChanged,
            SubjectKind::Registry,
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom",
        );
        raw.detail = EventAction::REGISTRY_VALUE_SET;
        // Type 1 is `REG_SZ`; the service does not interpret it, but it is
        // what the driver puts in the field and a test should not pretend
        // otherwise.
        raw.set_value(
            &r"C:\Program Files\Zoom\bin\Zoom.exe".encode_utf16().collect::<Vec<_>>(),
            1,
        );
        assert_eq!(
            translate(&raw).value.as_deref(),
            Some(r"C:\Program Files\Zoom\bin\Zoom.exe")
        );

        raw.set_value(
            &r"%TEMP%\evil.exe".encode_utf16().collect::<Vec<_>>(),
            2,
        );
        assert_eq!(translate(&raw).value.as_deref(), Some(r"%TEMP%\evil.exe"));

        // A value is not a path: neither of those moved the path field.
        assert!(translate(&raw)
            .path
            .expect("a path")
            .to_string_lossy()
            .ends_with(r"Run\Zoom"));

        // A blocked key event carries no value at all, and `None` is the
        // honest answer rather than an empty string a rule could match.
        let key_only = message(
            EventAction::RegistryChanged,
            SubjectKind::Registry,
            r"\REGISTRY\MACHINE\SOFTWARE\Vendor",
        );
        assert!(translate(&key_only).value.is_none());

        // A length longer than the array is clamped, exactly as for a path.
        let mut lying = raw;
        lying.value_units = u32::MAX;
        assert!(translate(&lying).value.is_some());
    }

    #[test]
    fn a_path_length_larger_than_the_buffer_is_a_used_length_and_not_an_allocation() {
        // The driver's field is a fixed array with a claimed length, and the
        // claim is not trusted. `u32::MAX` produces the whole 1024-unit array
        // and nothing more: no allocation sized from a hostile number, which is
        // the property `av-driver-proto` is built on.
        let mut raw = message(
            EventAction::FileWritten,
            SubjectKind::File,
            r"C:\Windows\Temp\x.dll",
        );
        raw.path_units = u32::MAX;
        let translated = translate(&raw);
        let path = translated.path.expect("a path");
        assert!(path.to_string_lossy().contains("Windows"));
        assert!(path.to_string_lossy().len() <= MAX_PATH_UNITS);
    }

    #[test]
    fn the_products_own_directories_are_excluded_from_driver_decisions() {
        // The bug this test exists for, stated as the bug rather than as the
        // fix: the driver's built-in list said `C:\ProgramData\Wenle` while the
        // product's data directory is `C:\ProgramData\WenleAV`, and
        // `matches_prefix` compares whole components, so the entry matched
        // nothing. The driver reported an exclusion table with four entries and
        // excluded its own data directory not at all — which means it asked the
        // service to decide on every file the service wrote: the rule database,
        // the cache, the quarantine payloads, the logs.
        //
        // This test is in av-service and not in either of the two crates it is
        // about, because it is the only crate that depends on both: the
        // protocol crate has no dependencies at all (the driver links it) and
        // cannot see `av_core::paths`, and the driver cannot depend on a
        // std-using crate. A test that needs two crates to agree has to live in
        // a third that can see both.
        //
        // What it asserts is deliberately machine-independent — the drive letter
        // and the location of `%ProgramData%` are the same question as whether
        // the built-in list works on a system drive that is not `C:`, which is a
        // limitation `BUILT_IN`'s own documentation states and this test cannot
        // fix. What it *can* pin is the spelling of the product's directory name,
        // which is the thing that drifted.
        use av_core::paths::{default_data_dir, PRODUCT_DIR};

        let entries: Vec<Vec<u16>> = av_driver_proto::exclusions::BUILT_IN
            .iter()
            .map(|entry| entry.encode_utf16().collect())
            .collect();
        let entries: Vec<&[u16]> = entries.iter().map(|e| e.as_slice()).collect();
        let excluded = |path: &str| {
            let units: Vec<u16> = path.encode_utf16().collect();
            av_driver_proto::exclusions::is_excluded(&units, entries.iter().copied())
        };

        // The two directories of a default installation, and the product's own
        // answer to where its data goes. `default_data_dir()` is the authority
        // on the second: if av-core ever moves it, this catches the list not
        // moving with it.
        let data_tail = format!(r"\{PRODUCT_DIR}");
        assert!(
            default_data_dir()
                .to_string_lossy()
                .ends_with(&data_tail),
            "av-core's data directory is no longer a directory named {PRODUCT_DIR}, so this test's \
             idea of where the product writes is out of date"
        );
        assert!(
            av_driver_proto::exclusions::BUILT_IN
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(&format!(r"C:\ProgramData\{PRODUCT_DIR}"))),
            "the driver's built-in list has no entry for C:\\ProgramData\\{PRODUCT_DIR}, the \
             directory the product writes everything to. The list is {}",
            av_driver_proto::exclusions::BUILT_IN.join(", ")
        );

        // The paths themselves, through the same matcher the driver uses.
        for path in [
            r"C:\ProgramData\WenleAV\db\rules.avdb",
            r"C:\ProgramData\WenleAV\quarantine\items\0000000000000000.qtn",
            r"C:\ProgramData\WenleAV\logs\wenle.log",
            r"C:\Program Files\WenleAV\wenle.exe",
        ] {
            assert!(
                excluded(path),
                "{path} is a file the product itself creates, and the driver would ask the \
                 service to decide on it"
            );
        }

        // And the near-miss, kept as its own assertion so that a future edit
        // which shortens the entry to a prefix of the product's name fails here
        // with the reason rather than only in the loop above.
        assert!(
            !excluded(r"C:\ProgramData\WenleAV-backup\x.txt"),
            "an entry that matched a directory merely *starting* with the product's name would \
             be a hole over an unrelated directory"
        );
    }

    #[test]
    fn a_driver_that_was_not_looked_for_is_not_reported_as_absent() {
        // The check itself, run on this machine. Whatever it answers, the two
        // possible answers must be distinguishable and neither may be a
        // confident "no" without a device name to back it up.
        let status = check();
        if status.presence == DriverPresence::Loaded {
            assert!(status.detail.contains(CONTROL_DEVICE));
        } else {
            assert!(status.device.is_some() || status.presence == DriverPresence::Unknown);
        }
        // And nothing here claims a protection: `is_loaded` is about the
        // device, not about what the driver is doing.
        assert_eq!(
            status.presence.is_loaded(),
            status.presence == DriverPresence::Loaded
        );
    }
}