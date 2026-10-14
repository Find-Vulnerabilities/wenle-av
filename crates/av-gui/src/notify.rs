//! Telling a user about a block when they are not looking at the window.
//!
//! # Why this is a Windows notification and not a corner of the window
//!
//! The window can draw its own panel in its bottom-right corner, and it did.
//! That panel has one property that makes it the wrong answer for the one
//! notification that matters: it only exists while the window does. A user who
//! has closed the window — or who never opened it, because the service is what
//! found the file — is told nothing at all, and the file that was taken off
//! their disk is taken silently. The moment the product most needs to be seen
//! is the moment a window cannot be relied on to be there.
//!
//! So a block is announced through the shell's own notification, which is drawn
//! by `explorer.exe`, survives the window being closed, and lands in the Action
//! Center where it can be read later.
//!
//! # The two measurements this module is built on
//!
//! Both were taken on a Windows 11 machine with the `windows` 0.62 crate before
//! any of this was written, because the obvious design is wrong in a way that
//! fails silently:
//!
//! **A notification needs no registration.** `CreateToastNotifierWithId` and
//! `Show` both succeed for an application identifier nothing has ever
//! registered, and the toast appears and is recorded in the history that
//! `ToastNotificationManager.History` reports. Registration is what makes the
//! *name* the notification is attributed to, and its icon, correct. It is not
//! what makes the notification appear.
//!
//! **`ToastNotifier::Setting` is the exception, and it is a trap.**
//! `Setting()` returns the shell's answer to "may this application post
//! notifications at all" — and for an unregistered identifier it does not
//! return `Enabled`, it fails with `ELEMENT_NOT_FOUND`. A notifier that asked
//! `Setting()` first and treated any answer other than `Enabled` as a refusal
//! would therefore never post anything on a machine where
//! `wenle integrate notifications` had not been run, and it would do it without
//! an error anywhere: the guard would look like a policy check and behave like
//! an off switch. `toast::deliver` therefore treats a failed `Setting()` as
//! *no answer* and posts anyway, and honours only the definite refusals the
//! shell does return once the identifier is registered.
//!
//! # What this module does not do
//!
//! **No buttons.** A toast with a "Restore" button needs a COM activator
//! registered for the identifier — a class in the registry, an `IDropTarget`
//! and a locally-registered server — and this product has none of that. A toast
//! click therefore does nothing, and the notification says so by not offering
//! anything: it states what happened and leaves the actions in the window's
//! Quarantine tab, which is where the file can actually be restored from. A
//! toast that offered a button that did nothing would be worse than one that
//! offered none.
//!
//! **No queueing for a user who is not there.** The notification is posted to
//! the shell of the session this process runs in. A process with no interactive
//! session — a service, a scheduled task — has no shell to post to, which is
//! one of the reasons this lives in the window rather than in the service; see
//! [`Notifier::for_this_process`].
//!
//! **No notification while the machine says no.** A user who has turned this
//! application's notifications off in Settings, or who has Focus Assist on, has
//! said what they want. The block is still in the log, still in the vault and
//! still in the window's list; it is only the popup that does not happen, and
//! the log says why once.

use std::sync::mpsc;

/// The application identifier every notification this product posts carries.
///
/// `wenle integrate notifications` registers this name under
/// `HKCU\Software\Classes\AppUserModelId`, which is what makes the shell
/// attribute the notification to "Wenle Antivirus" rather than to the path of
/// the executable that posted it. It is one string in two crates — here and
/// `av-integration`'s notification module — and the two must agree, so both
/// name [`av_core::APP_USER_MODEL_ID`] rather than repeating the literal.
pub const AUMID: &str = av_core::APP_USER_MODEL_ID;

/// Which earlier notification an announcement supersedes.
///
/// # Why this exists at all
///
/// A scan that quarantines forty files raises forty announcements, and forty
/// notifications is not a product telling a user something, it is a product
/// shouting. The shell has a mechanism for exactly this: two notifications
/// posted with the same *tag* are the same notification, and the second
/// replaces the first rather than appearing beside it. So a burst of blocks
/// updates one banner and leaves one entry in the Action Center, with the
/// running count in its text.
///
/// # Why the coalescing is the shell's and not a timer of ours
///
/// The obvious alternative is to hold a burst open in the window for a few
/// seconds and post one summary when it closes. It was rejected for a reason
/// that is not about code size: closing that burst requires a frame to run after
/// the window has elapsed, and the frames of a window that is out of the way are
/// the ones the vault poll happens to bring round — one a second while this
/// process is idle, and none at all once the window has been closed. A summary
/// that depends on the drawing loop is a summary that goes missing exactly when
/// it is needed. The shell's own replacement has no such dependency.
///
/// # The sixteen-character limit
///
/// `SetTag` refuses a tag longer than sixteen characters, which is why this is
/// an enum with fixed short names rather than a string a caller composes. A
/// tag that was too long would make `Show` fail for every notification of that
/// kind, and it would do it at the moment a virus was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// A file was blocked and taken. A burst updates one notification.
    Blocked,
    /// The middle band, reported in one notification at the end of a scan.
    Suspicious,
}

impl Tag {
    /// The name the shell is given.
    pub const fn as_str(self) -> &'static str {
        match self {
            Tag::Blocked => "blocked",
            Tag::Suspicious => "suspicious",
        }
    }
}

/// What the product has to say.
///
/// A value rather than a call so that what is said can be tested without a
/// desktop to say it to: [`toast_xml`] is a pure function of one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The headline, in the shell's own bold first line.
    pub title: String,
    /// The sentence under it.
    pub body: String,
    /// The notification this one replaces, if any. See [`Tag`].
    pub tag: Option<Tag>,
}

impl Announcement {
    /// An announcement with a headline and a sentence, beside any other.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            tag: None,
        }
    }

    /// An announcement that replaces the last one carrying `tag`.
    pub fn replacing(tag: Tag, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            tag: Some(tag),
        }
    }
}

/// The toast document for an announcement.
///
/// # Why the sound is always written out
///
/// The schema's default for a toast with no `<audio>` element is to play the
/// default notification sound. So a silent notification has to say so, and
/// leaving the element out is not a way of being quiet — it is the opposite.
///
/// # Why `duration="long"`
///
/// The default is five seconds and this is a virus alert: a user who is looking
/// at their keyboard rather than the corner of the screen needs it to still be
/// there when they look up. `long` is twenty-five seconds, and it is the
/// longest the schema offers — `scenario="urgent"` would keep it there
/// indefinitely, and it also overrides Focus Assist, which is a decision about
/// the user's attention that a file being quarantined does not earn. A block is
/// worth being told about; it is not worth breaking the user's do-not-disturb.
pub fn toast_xml(announcement: &Announcement, sound: bool) -> String {
    let mut xml = String::with_capacity(announcement.body.len() + announcement.title.len() + 256);
    xml.push_str(r#"<toast duration="long"><visual><binding template="ToastGeneric">"#);
    xml.push_str("<text>");
    escape(&announcement.title, &mut xml);
    xml.push_str("</text><text>");
    escape(&announcement.body, &mut xml);
    xml.push_str("</text></binding></visual><audio ");
    if sound {
        xml.push_str(r#"src="ms-winsoundevent:Notification.Default""#);
    } else {
        xml.push_str(r#"silent="true""#);
    }
    xml.push_str("/></toast>");
    xml
}

/// Append `text` with the five characters XML reserves replaced, and with
/// anything XML cannot carry at all left out.
///
/// The escaping is not decoration. The body carries a file name and a detection
/// name, both of which are strings this product did not choose: a file called
/// `a&b.exe` produces a document that is not well-formed, and `LoadXml` refuses
/// the whole notification — so a user whose download is called `Tom & Jerry.exe`
/// would be told nothing at all, for a reason no log would explain. A detection
/// name out of the rule corpus has the same reach.
///
/// The control characters are dropped rather than escaped, because XML 1.0 has
/// no escaping for them: they cannot appear in a well-formed document by any
/// means. They cannot appear in a Windows file name either — but a detection
/// name is a string out of a database this crate does not own, and a
/// notification that silently fails to parse is a notification that was never
/// sent.
fn escape(text: &str, out: &mut String) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
}

/// How many of the announcements this process raised are remembered.
///
/// Bounded because a scan that quarantines ten thousand files raises ten
/// thousand of them and this is a diagnostic, not a log. [`Notifier::announced`]
/// is what a test asserts against and what a future "what has this session
/// reported" view would read; `log` is where the durable copy is.
pub const REMEMBERED: usize = 64;

/// Sends the product's announcements to the desktop, or decides not to.
#[derive(Debug)]
pub struct Notifier {
    /// `general.notifications`, read from the configuration and re-read when
    /// the settings are saved.
    enabled: bool,
    /// `general.notification_sound`, the same way.
    sound: bool,
    /// Where an announcement goes. `None` is a notifier that posts nothing:
    /// a test, a platform with no shell, or a thread that could not be started.
    outbox: Option<mpsc::Sender<toast::Envelope>>,
    /// Every announcement raised, whether or not it was posted.
    announced: Vec<Announcement>,
    /// How many of them were handed to the shell to post.
    posted: u64,
}

impl Notifier {
    /// A notifier for this process, as the configuration asks for.
    ///
    /// # Why the test build never posts
    ///
    /// `cargo test -p av-gui` constructs a window and drives it through the
    /// states a real one goes through, and one of those states is a block. A
    /// test that posted a notification would put a real popup on the screen of
    /// whoever ran it, which is both a surprise and a way for a failing test to
    /// be mistaken for the product working. So a test build gets the silent
    /// transport, and [`Notifier::announced`] is what the tests read instead —
    /// which is the better assertion anyway, because it is about what the
    /// product decided to say rather than about whether the shell drew it.
    pub fn for_this_process(enabled: bool, sound: bool) -> Self {
        if cfg!(test) {
            return Self::silent();
        }
        Self {
            enabled,
            sound,
            outbox: toast::start(),
            announced: Vec::new(),
            posted: 0,
        }
    }

    /// A notifier that posts nothing, for tests and for a build with no shell.
    pub fn silent() -> Self {
        Self {
            enabled: false,
            sound: false,
            outbox: None,
            announced: Vec::new(),
            posted: 0,
        }
    }

    /// Take the two settings, after they have been changed and saved.
    ///
    /// Called with what the configuration now says rather than with a delta,
    /// because the two can be edited in either order on the settings screen and
    /// a notifier that applied changes one at a time could end up in a state
    /// neither the file nor the screen describes.
    pub fn configure(&mut self, enabled: bool, sound: bool) {
        self.enabled = enabled;
        self.sound = sound;
    }

    /// Say something, if the settings allow it.
    ///
    /// Returns whether the announcement was handed to the shell. The caller
    /// does not need the answer — the record in [`Notifier::announced`] and in
    /// the log is the product's account of what happened, and a block is
    /// reported by the vault whether or not a popup appeared — so this is
    /// deliberately not a `Result`: a failure to draw a notification is not a
    /// failure to do the thing the notification is about.
    pub fn announce(&mut self, announcement: Announcement) -> bool {
        if self.announced.len() == REMEMBERED {
            self.announced.remove(0);
        }
        self.announced.push(announcement.clone());
        let (Some(outbox), true) = (&self.outbox, self.enabled) else {
            return false;
        };
        let envelope = toast::Envelope {
            announcement,
            sound: self.sound,
        };
        match outbox.send(envelope) {
            Ok(()) => {
                self.posted += 1;
                true
            }
            Err(_) => {
                // The delivery thread is gone. That happens once, at shutdown,
                // and never on a path a user can reach.
                log::debug!("the notification thread is no longer running");
                false
            }
        }
    }

    /// Everything raised through this notifier, oldest first.
    ///
    /// A test's way of reading what a window would have put on the desktop,
    /// which is the only part of a notification a test can see — there is no
    /// shell in a test binary, and a notification is not drawn by this crate
    /// in any case. Gated rather than left as dead product code for the reason
    /// its siblings are: nothing in the product reads it back.
    #[cfg(test)]
    pub fn announced(&self) -> &[Announcement] {
        &self.announced
    }

    /// How many announcements were handed to the shell.
    #[cfg(test)]
    pub fn posted(&self) -> u64 {
        self.posted
    }

    /// Whether the configuration currently asks for notifications at all.
    #[cfg(test)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(windows)]
mod toast {
    use super::{toast_xml, Announcement, AUMID};
    use std::sync::mpsc::{self, Receiver, Sender};

    /// One thing to post.
    ///
    /// The sound travels with the announcement rather than being read from the
    /// notifier at the far end, so that a setting changed between raising a
    /// notification and posting it cannot change what the user hears after the
    /// fact: the sound is part of what was decided.
    #[derive(Debug)]
    pub(super) struct Envelope {
        pub(super) announcement: Announcement,
        pub(super) sound: bool,
    }

    /// Start the thread that posts notifications, or report that it could not
    /// be started.
    ///
    /// # Why a thread of its own
    ///
    /// Two reasons, and the second is the one that decided it.
    ///
    /// `Show` is not a local call: it is an out-of-process call to the shell,
    /// and on a busy machine it can take tens of milliseconds, which the window
    /// would spend unable to draw a frame. The notification is worth that
    /// nowhere.
    ///
    /// The other reason is the apartment. WinRT has to be initialized on the
    /// thread that uses it, and the window's thread has already been claimed by
    /// `winit`, which initializes OLE as a single-threaded apartment for
    /// drag-and-drop. Initializing a *different* model on that thread fails with
    /// `RPC_E_CHANGED_MODE`, and which of the two calls wins is a race that
    /// depends on the order the window happens to start in. A thread this module
    /// owns has no such history and can be initialized multi-threaded, once,
    /// deliberately.
    ///
    /// The channel is what stops the thread: when the [`Notifier`] is dropped
    /// its sender goes with it and the receive below ends. There is deliberately
    /// no join — a thread blocked in a call to a shell that has stopped
    /// answering would hold up process exit for as long as it stayed blocked,
    /// and it has nothing to flush that the log does not already hold.
    ///
    /// [`Notifier`]: super::Notifier
    pub(super) fn start() -> Option<Sender<Envelope>> {
        let (outbox, inbox) = mpsc::channel::<Envelope>();
        let spawned = std::thread::Builder::new()
            .name("wenle-notify".to_owned())
            .spawn(move || run(inbox));
        match spawned {
            Ok(_) => Some(outbox),
            Err(error) => {
                log::warn!("notifications will not be shown: no thread could be started: {error}");
                None
            }
        }
    }

    /// Post everything that arrives until the sender is dropped.
    fn run(inbox: Receiver<Envelope>) {
        for envelope in inbox {
            deliver(&envelope);
        }
    }

    /// Post one notification, and say in the log what happened to it.
    ///
    /// Nothing here is fatal and nothing here is retried. A notification that
    /// could not be shown is a popup that did not appear; the file it is about
    /// was still quarantined, the entry is still in the vault, and the line in
    /// the log below is the record that the user was not told.
    fn deliver(envelope: &Envelope) {
        match post(envelope) {
            Ok(()) => log::debug!("posted a notification: {}", envelope.announcement.body),
            Err(Outcome::Refused(reason)) => log::info!(
                "the notification was not posted: {reason}. The block itself is unaffected and \
                 is in the quarantine log."
            ),
            Err(Outcome::Failed(error)) => log::warn!(
                "the notification could not be posted: {error}. The block itself is unaffected \
                 and is in the quarantine log."
            ),
        }
    }

    /// Why a notification did not appear.
    enum Outcome {
        /// The user or a policy said no. Not a fault, and reported as
        /// information once per notification rather than as a warning.
        Refused(String),
        /// Something went wrong.
        Failed(String),
    }

    fn post(envelope: &Envelope) -> Result<(), Outcome> {
        use windows::core::HSTRING;
        use windows::Data::Xml::Dom::XmlDocument;
        use windows::UI::Notifications::{NotificationSetting, ToastNotification};
        use windows::UI::Notifications::ToastNotificationManager;
        use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

        // SAFETY: `RoInitialize` and everything under it is an ordinary WinRT
        // call on a thread this module owns. The thread was started for this and
        // does nothing else, so there is no apartment for it to conflict with;
        // the only case handled specially is a machine that has already
        // initialized this thread some other way, which is not a reason to skip
        // posting.
        unsafe {
            match RoInitialize(RO_INIT_MULTITHREADED) {
                Ok(()) => {}
                Err(error) if error.code() == windows::Win32::Foundation::RPC_E_CHANGED_MODE => {}
                Err(error) => {
                    return Err(Outcome::Failed(format!("WinRT could not start: {error}")));
                }
            }

            let document = XmlDocument::new()
                .map_err(|error| Outcome::Failed(format!("no XML document: {error}")))?;
            document
                .LoadXml(&HSTRING::from(toast_xml(
                    &envelope.announcement,
                    envelope.sound,
                )))
                .map_err(|error| Outcome::Failed(format!("the notification was malformed: {error}")))?;
            let notification = ToastNotification::CreateToastNotification(&document)
                .map_err(|error| Outcome::Failed(format!("no notification: {error}")))?;
            // The tag is what makes a burst one notification instead of forty.
            // Its failure is not fatal: an untagged notification still appears,
            // it just stacks, so the worst case of this call failing is the
            // behaviour there would have been without it.
            if let Some(tag) = envelope.announcement.tag {
                if let Err(error) = notification.SetTag(&HSTRING::from(tag.as_str())) {
                    log::warn!("the notification will not replace an earlier one: {error}");
                }
            }
            let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
                AUMID,
            ))
            .map_err(|error| Outcome::Failed(format!("no notifier: {error}")))?;

            // Asked, and believed only when the answer is definite. An
            // unregistered application identifier makes this call *fail* — see
            // the module documentation — and a failure to ask is not an answer
            // of "no". Only the three refusals the shell actually returns stop
            // the notification.
            if let Ok(setting) = notifier.Setting() {
                if setting != NotificationSetting::Enabled {
                    return Err(Outcome::Refused(refusal(setting)));
                }
            }

            notifier
                .Show(&notification)
                .map_err(|error| Outcome::Failed(format!("the shell refused it: {error}")))
        }
    }

    /// What to tell the log about a refusal, in words rather than a number.
    fn refusal(setting: windows::UI::Notifications::NotificationSetting) -> String {
        use windows::UI::Notifications::NotificationSetting as S;
        let who = match setting {
            S::DisabledForApplication => "notifications from this application are turned off",
            S::DisabledForUser => "notifications are turned off for this user",
            S::DisabledByGroupPolicy => "a group policy turns notifications off",
            S::DisabledByManifest => "the application's manifest turns notifications off",
            _ => "the shell is not accepting notifications",
        };
        who.to_owned()
    }
}

#[cfg(not(windows))]
mod toast {
    use super::Announcement;
    use std::sync::mpsc::Sender;

    /// There is no shell to post to, so there is no thread to start.
    ///
    /// The window is the only front end this crate builds and it is built for
    /// Windows; this exists so that the crate still compiles where it is
    /// inspected rather than built. [`Notifier::for_this_process`] therefore
    /// returns a silent notifier there, and the announcements are still
    /// recorded.
    ///
    /// [`Notifier::for_this_process`]: super::Notifier::for_this_process
    #[derive(Debug)]
    pub(super) struct Envelope {
        #[allow(dead_code)]
        pub(super) announcement: Announcement,
        #[allow(dead_code)]
        pub(super) sound: bool,
    }

    pub(super) fn start() -> Option<Sender<Envelope>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement() -> Announcement {
        Announcement::new(
            "Blocked and quarantined",
            "evil.exe — Trojan.Win32.Wacatac. The file was blocked and moved to quarantine.",
        )
    }

    #[test]
    fn the_document_is_well_formed_enough_to_carry_both_lines() {
        let xml = toast_xml(&announcement(), false);
        assert!(xml.starts_with("<toast "));
        assert!(xml.ends_with("</toast>"));
        assert!(xml.contains("<text>Blocked and quarantined</text>"));
        assert!(xml.contains("Trojan.Win32.Wacatac"));
        assert_eq!(
            xml.matches("<text>").count(),
            2,
            "a ToastGeneric binding takes two lines here and no more: {xml}"
        );
    }

    /// The one that would have been a silent failure: a file whose name the
    /// user chose, carrying a character XML reserves.
    #[test]
    fn a_file_name_that_would_break_the_document_does_not() {
        let xml = toast_xml(
            &Announcement::new(
                "Blocked and quarantined",
                "Tom & Jerry <1>.exe — \"a\" 'b'. The file was blocked.",
            ),
            false,
        );
        assert!(!xml.contains("Tom & Jerry"), "{xml}");
        assert!(xml.contains("Tom &amp; Jerry &lt;1&gt;.exe"));
        assert!(xml.contains("&quot;a&quot; &apos;b&apos;"));
        assert_eq!(
            xml.matches('&').count(),
            xml.matches("&amp;").count()
                + xml.matches("&lt;").count()
                + xml.matches("&gt;").count()
                + xml.matches("&quot;").count()
                + xml.matches("&apos;").count(),
            "every ampersand in the document is the start of an entity: {xml}"
        );
    }

    /// A control character cannot be carried by XML at all, so it has to be
    /// dropped rather than escaped — and a detection name out of the rule
    /// database is a string this crate did not write.
    ///
    /// The three whitespace controls are the exception and are kept: XML's own
    /// line endings are legal in content, and a tab or a newline in a detection
    /// name is something a reader should see rather than something to silently
    /// join two words over.
    #[test]
    fn a_control_character_is_left_out_rather_than_escaped() {
        let xml = toast_xml(&Announcement::new("t", "a\u{1}b\u{7}c"), false);
        assert!(xml.contains("<text>abc</text>"), "{xml}");
        assert!(!xml.contains('\u{1}'));
        assert!(!xml.contains('\u{7}'));
        let spaced = toast_xml(&Announcement::new("t", "a\tb\nc"), false);
        assert!(spaced.contains("a\tb\nc"), "{spaced}");
    }

    /// Silence is written out. Leaving `<audio>` off is the schema's way of
    /// asking for the default sound, which is the opposite of quiet.
    #[test]
    fn silence_is_stated_and_not_merely_left_out() {
        assert!(toast_xml(&announcement(), false).contains(r#"<audio silent="true"/>"#));
        let loud = toast_xml(&announcement(), true);
        assert!(loud.contains(r#"<audio src="ms-winsoundevent:Notification.Default"/>"#));
        assert!(!loud.contains("silent"));
    }

    /// Long enough to still be there when a user looks up: the schema's
    /// default is five seconds.
    #[test]
    fn the_notification_asks_to_stay_on_screen() {
        assert!(toast_xml(&announcement(), false).contains(r#"duration="long""#));
    }

    #[test]
    fn a_silent_notifier_posts_nothing_but_still_remembers() {
        let mut notifier = Notifier::silent();
        assert_eq!(notifier.posted(), 0);
        notifier.announce(announcement());
        assert_eq!(notifier.announced(), [announcement()]);
        assert_eq!(notifier.posted(), 0);
    }

    /// The settings are what decides, and the record is kept either way: this
    /// is what the window's tests assert a block was announced through.
    #[test]
    fn turning_notifications_off_stops_the_post_and_not_the_record() {
        let mut notifier = Notifier::silent();
        notifier.configure(true, false);
        assert!(notifier.is_enabled());
        notifier.configure(false, false);
        assert!(!notifier.is_enabled());
        assert!(!notifier.announce(announcement()));
    }

    /// The tag is a delivery property and must not leak into the document: the
    /// schema has no element for it, and `LoadXml` refuses unknown attributes
    /// rather than ignoring them.
    #[test]
    fn the_tag_is_not_in_the_document() {
        let xml = toast_xml(
            &Announcement::replacing(Tag::Blocked, "Blocked and quarantined", "a.exe"),
            false,
        );
        assert!(!xml.contains("blocked\"") && !xml.contains("tag"), "{xml}");
        assert!(xml.contains("<text>a.exe</text>"));
        assert_eq!(
            Announcement::replacing(Tag::Blocked, "t", "b").tag,
            Some(Tag::Blocked)
        );
        assert_eq!(Announcement::new("t", "b").tag, None);
    }

    /// `SetTag` refuses anything longer than sixteen characters, and a tag it
    /// refuses would make `Show` fail for every block — so the names are fixed
    /// and short rather than composed.
    #[test]
    fn every_tag_fits_the_limit_the_shell_enforces() {
        for tag in [Tag::Blocked, Tag::Suspicious] {
            assert!(
                tag.as_str().len() <= 16,
                "{} is {} characters",
                tag.as_str(),
                tag.as_str().len()
            );
            assert!(!tag.as_str().is_empty());
        }
    }

    /// A long session must not accumulate every block it ever saw.
    #[test]
    fn the_record_is_bounded_and_keeps_the_newest() {
        let mut notifier = Notifier::silent();
        for index in 0..(REMEMBERED + 10) {
            notifier.announce(Announcement::new("t", format!("file {index}")));
        }
        assert_eq!(notifier.announced().len(), REMEMBERED);
        assert_eq!(
            notifier.announced().last().map(|a| a.body.as_str()),
            Some(format!("file {}", REMEMBERED + 9).as_str())
        );
        assert_eq!(notifier.announced()[0].body, "file 10");
    }

    /// The window's own construction path must not put a popup on the desktop
    /// of whoever runs the tests.
    #[test]
    fn the_process_notifier_is_silent_in_a_test_build() {
        let notifier = Notifier::for_this_process(true, true);
        assert!(
            notifier.outbox.is_none(),
            "a test build must not reach the shell"
        );
    }
}
