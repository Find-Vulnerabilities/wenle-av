//! The blocking decision: how the driver asks user mode, waits, and gives up.
//!
//! # The shape of the problem
//!
//! A minifilter's pre-operation callback runs *on the thread that is trying to
//! open the file*, before the open succeeds. To refuse the open, the callback
//! returns `FLT_PREOP_COMPLETE` and fills in a status; to allow it, it returns
//! `FLT_PREOP_SUCCESS_WITH_CALLBACK` or lets the operation proceed. Either way
//! the answer must be produced before the callback returns — there is no
//! "decide later" for a create that has not happened yet.
//!
//! The driver cannot produce that answer. It cannot hash a file, cannot match a
//! rule, cannot parse a PE. So it must ask user mode and **wait**, and the wait
//! is the entire risk of this design.
//!
//! # The state machine
//!
//! ```text
//!                      register()                resolve()
//!   (no slot)  ──────────────────────▶  Pending  ──────────▶ Applied
//!                                          │
//!                                          │ expire()  — deadline reached
//!                                          ▼
//!                                       Retired ──────▶ (a late resolve() is
//!                                                          discarded, see below)
//! ```
//!
//! A request occupies a slot from [`PendingTable::register`] until something
//! ends it: a reply ([`PendingTable::resolve`]) or a deadline
//! ([`PendingTable::expire`]). Both go through the same slot, both check the
//! id, and only one of them can win — the slot is cleared by whichever gets
//! there first, so the second finds either nothing or a *different* request.
//!
//! # The timeout, and why the default answer is "allow"
//!
//! [`DecisionPolicy::on_timeout`] defaults to [`Decision::Allow`], and that is
//! the single most important decision in this crate.
//!
//! A driver that blocks by default has made every one of its own failure modes
//! into a machine that does not work:
//!
//! * the service crashes → every execution and every open waits out the timeout
//!   and is then refused → the machine cannot start a program;
//! * the service is slow (a signature update, memory pressure, a full scan
//!   running) → the same, intermittently, which is worse because it is
//!   unpredictable;
//! * the request table fills → refusals under exactly the load that filled it;
//! * the driver's own wait is buggy → refusals;
//! * at boot, before the service has started, every driver and every service
//!   load is an execution → **the machine does not boot.**
//!
//! Against that: a default of allow means a missed detection. And a missed
//! detection is *recoverable*. The file is still on disk. The real-time scanner
//! still sees it when it is written, the memory scanner still sees it if it
//! runs, a full scan still sees it later, and the user can still be told. The
//! product has four other layers whose job this is not.
//!
//! The asymmetry is therefore not "false positive against false negative". It
//! is **a machine that works and missed one thing** against **a machine that
//! does not work at all**, and only one of those has a way back.
//!
//! So the default is allow — and the driver allows *loudly*. Every expiry
//! increments [`crate::wire::DriverStatus::decisions_unanswered`], ticks
//! [`crate::wire::DriverStats::timed_out`], and emits an
//! [`crate::event::EventAction::EventsDropped`] event, so a service that is
//! failing to answer sees that it is failing rather than seeing a quiet
//! machine. An operator who wants the opposite policy can set it, and the doc
//! comment here is what they are expected to have read.
//!
//! # Why the port's own correlation cannot replace the id here
//!
//! `FltSendMessage` generates a `MessageId` and user mode echoes it back in the
//! reply header; the filter manager uses it to pair the two. That correlation
//! is exact and it is not enough, because it only holds *while the driver is
//! still waiting*. When the wait times out the driver stops waiting and the
//! reply is dropped by the filter manager — or, if the driver's wait and the
//! reply thread are separate, the reply arrives with nobody expecting it.
//!
//! Either way the driver needs its own record of "which request was that, and
//! is it still the one I care about", and that record is [`RequestId`]. The two
//! ids coexist: the port's pairs a reply with a message, and this one pairs a
//! message with a *file*. See
//! `a_reply_for_an_expired_request_is_not_applied_to_its_replacement`.

use core::fmt;

use crate::event::SubjectKind;

/// A monotonic request identifier.
///
/// Issued once per request, never reused, never zero. The "never reused"
/// property is what makes [`PendingTable::resolve`] able to tell a live reply
/// from a stale one: an id is not a slot index that can be handed out again, it
/// is a name that belongs to one request for the lifetime of the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// The value that goes on the wire.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What user mode told the driver to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Decision {
    /// Let it happen.
    #[default]
    Allow,
    /// Refuse it.
    Block,
}

impl Decision {
    /// The value that goes on the wire.
    pub const fn as_wire(self) -> u32 {
        match self {
            Decision::Allow => 0,
            Decision::Block => 1,
        }
    }

    /// Decode a wire value. `None` for anything unrecognised — and the caller
    /// must not read that as [`Decision::Block`].
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Decision::Allow),
            1 => Some(Decision::Block),
            _ => None,
        }
    }

    /// Decode a wire value, treating anything unrecognised as
    /// [`Decision::Allow`].
    ///
    /// The safe direction, for the reasons in the module documentation: a
    /// decision the driver cannot interpret is a decision it must not act on
    /// destructively. Note that this is a *different* choice from
    /// [`crate::event::VerdictCode::from_wire_lossy`], which sends an unknown
    /// value to `Unknown` — that one is choosing what to report, this one is
    /// choosing whether to refuse a file operation, and the conservative
    /// direction is the opposite in each case.
    pub const fn from_wire_lossy(value: u32) -> Self {
        match Self::from_wire(value) {
            Some(decision) => decision,
            None => Decision::Allow,
        }
    }

    /// The word used in a report.
    pub const fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Block => "block",
        }
    }
}

/// How many 100-nanosecond units there are in a millisecond.
///
/// The filter manager states a timeout in 100-nanosecond units and a
/// [`DecisionPolicy`] states its own in milliseconds; this is the conversion
/// between the two, kept beside the policy so the unit changes in one place.
pub const UNITS_PER_MS: i64 = 10_000;

/// How long the driver waits, and what it does when the wait runs out.
///
/// See the module documentation for why [`DecisionPolicy::on_timeout`] is
/// [`Decision::Allow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionPolicy {
    /// How long a request may stay pending, in milliseconds.
    pub timeout_ms: u32,
    /// What to do when it does. `Allow`, and not because it is a placeholder.
    pub on_timeout: Decision,
}

impl DecisionPolicy {
    /// The default wait.
    ///
    /// **This number is a policy choice, not a measurement.** Measuring it
    /// would mean loading the driver and timing real executions against a real
    /// service, which this crate's tests cannot do and which the driver crate
    /// documents as unverified.
    ///
    /// What it is chosen against: the callback it bounds is a file open, and
    /// the user is waiting on it. Five seconds is long enough for a cold-cache
    /// scan of a large binary plus a signature lookup — the case that would
    /// otherwise produce a false "unknown" on exactly the big installers users
    /// notice — and short enough that a service that has died produces an
    /// obviously-wrong-feeling pause rather than a hang. An operator tuning
    /// this trades detection coverage against responsiveness, and
    /// [`DecisionPolicy::clamp`] is the ceiling that stops the trade being made
    /// badly.
    pub const DEFAULT_TIMEOUT_MS: u32 = 5_000;

    /// The longest wait this protocol permits.
    ///
    /// The pre-operation callback runs on the thread performing the file
    /// operation and blocks it for the duration, so the timeout is a bound on
    /// how long a user's operation can be stalled. Fifteen seconds is chosen as
    /// a ceiling that is already far past what a user experiences as
    /// responsiveness; permitting longer would let a misconfigured service turn
    /// a slow machine into one that appears hung, and the failure would be
    /// attributed to the product because it is.
    ///
    /// Not measured, for the same reason as the default.
    pub const MAX_TIMEOUT_MS: u32 = 15_000;

    /// The default policy: five seconds, then allow.
    pub const DEFAULT: DecisionPolicy = DecisionPolicy {
        timeout_ms: Self::DEFAULT_TIMEOUT_MS,
        on_timeout: Decision::Allow,
    };

    /// A policy that refuses on timeout.
    ///
    /// Provided because an operator may want it, and set apart because it is
    /// the dangerous one. Everything in the module documentation about machines
    /// that do not boot applies to a driver configured with this.
    pub const FAIL_CLOSED: DecisionPolicy = DecisionPolicy {
        timeout_ms: Self::DEFAULT_TIMEOUT_MS,
        on_timeout: Decision::Block,
    };

    /// Clamp the timeout into the permitted range.
    ///
    /// Applied by the driver to whatever
    /// [`crate::wire::SetModeRequest`] carried, *before* it is stored. Clamping
    /// at the point of use instead would leave an out-of-range value visible in
    /// the driver's own status, and the whole reason to clamp is that the
    /// value's consequences are invisible until something is already hung.
    #[must_use]
    pub const fn clamp(self) -> Self {
        Self {
            timeout_ms: if self.timeout_ms > Self::MAX_TIMEOUT_MS {
                Self::MAX_TIMEOUT_MS
            } else {
                self.timeout_ms
            },
            on_timeout: self.on_timeout,
        }
    }

    /// The deadline a request made at `now` gets.
    ///
    /// Saturating, so a policy at [`DecisionPolicy::MAX_TIMEOUT_MS`] and a tick
    /// source near `u64::MAX` produce a deadline in the far future rather than
    /// one that has already passed — wrapping here would turn the longest
    /// possible wait into an instant timeout, which is the opposite of what was
    /// asked for and would look like the service being down.
    pub const fn deadline_ticks(self, now: u64) -> u64 {
        now.saturating_add(self.timeout_ms as u64)
    }

    /// This policy as the filter manager's `FltSendMessage` wants it.
    ///
    /// **The sign is the whole value.** `FltSendMessage` takes a
    /// `PLARGE_INTEGER` whose unit is 100 nanoseconds, and its sign selects the
    /// meaning rather than merely the direction: a **positive** value is an
    /// absolute time counted from 1601-01-01, and a **negative** value is an
    /// interval from now. A policy stated in milliseconds is an interval, so
    /// this is negative.
    ///
    /// Sending `+50_000_000` for the five-second default is not a five-second
    /// wait. It is the absolute instant "1601-01-01 plus five seconds", which
    /// passed before this machine existed, so `FltSendMessage` returns
    /// `STATUS_TIMEOUT` at once — and that is what the VM showed on 2026-10-01:
    /// the message still reaches the port, the service still scans the file and
    /// still decides, and every single reply comes back
    /// `ERROR_FLT_NO_WAITER_FOR_REPLY` (`0x801F0020`) because the driver stopped
    /// waiting in the same instant it asked. It is worth naming what that
    /// failure looks like from the outside, because it is not what a broken
    /// protocol looks like: the whole feature reads as wired up and working,
    /// with a warning per file and every file allowed.
    ///
    /// [`STATUS_TIMEOUT`] is a success code, so a caller that tests only for
    /// `STATUS_SUCCESS` still lands in its expiry branch. That is why the sign
    /// was invisible for so long: the driver's own "the wait ran out" path is
    /// correct, and it was simply taken every time.
    ///
    /// [`STATUS_TIMEOUT`]: https://learn.microsoft.com/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage
    #[must_use]
    pub const fn relative_timeout_100ns(self) -> i64 {
        // Negated, and the negation is the entire point of this function. See
        // `the_default_policy_is_a_relative_interval_not_an_absolute_instant`.
        -((self.timeout_ms as i64) * UNITS_PER_MS)
    }
}

impl Default for DecisionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a request could not be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// Every slot is occupied.
    ///
    /// The caller takes [`DecisionPolicy::on_timeout`] — allow. It must *not*
    /// evict the oldest pending request to make room: eviction and refusal have
    /// the same effect on the new request (it is allowed), but eviction also
    /// throws away a request that might still have been answered, and it makes
    /// the table's contents a function of arrival order under load rather than
    /// a set of live questions. Refusing is the simpler rule to reason about,
    /// which is worth more here than the marginal extra answers.
    TableFull,
    /// The id counter reached `u64::MAX`.
    ///
    /// Unreachable in practice — the counter starts at one and issues one id
    /// per file operation, so at a million requests a second it lasts six
    /// hundred thousand years. It is a returned error rather than a wrapping
    /// add because the property it protects is the one the whole module rests
    /// on: id 5 belongs to one request, forever. A wrap would silently make
    /// that false, and the bug it would produce is a verdict for one file
    /// applied to another.
    IdSpaceExhausted,
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RegisterError::TableFull => "no free pending-decision slot",
            RegisterError::IdSpaceExhausted => "request id space exhausted",
        })
    }
}

/// What happened to a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The reply matched a live request and its decision is the answer.
    Applied(Decision),
    /// The request this answers is no longer live — it timed out, or its reply
    /// already arrived. **The decision was discarded.**
    Retired,
    /// The id matched nothing this table has ever issued.
    ///
    /// A protocol violation, or a reply so late that its record has fallen out
    /// of the retired ring. See [`PendingTable`] for which.
    Unknown,
    /// The reply matched a live request but described a different subject or
    /// path than that request was about.
    ///
    /// Discarded, and the request is **left pending** rather than ended: a
    /// confused reply is not an answer, and ending the request on it would
    /// throw away the wait for a real one. It will still time out and take the
    /// timeout default.
    Mismatch,
}

/// One pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    id: RequestId,
    /// Tick at which this request stops being answerable.
    deadline: u64,
    subject: SubjectKind,
    /// Tag of the path this request was about. Checked against the reply's
    /// echo — see [`ResolveOutcome::Mismatch`].
    path_tag: u64,
}

/// How many retired ids are remembered.
///
/// The ring exists so that [`ResolveOutcome::Retired`] and
/// [`ResolveOutcome::Unknown`] can be told apart, which is the difference
/// between "the service was too slow" and "something replied to a request that
/// was never made". The second is a protocol violation worth an event; the
/// first is a performance figure worth a counter.
///
/// The cost of the ring being finite: after 64 further requests have been
/// retired, a very late reply for an older id reports `Unknown` rather than
/// `Retired`. That is a mislabelled diagnostic, not a wrong decision — both
/// outcomes discard the reply, and `Unknown` is the more alarming of the two,
/// so the mislabelling errs towards telling an operator to look.
const RETIRED_RING: usize = 64;

/// The bounded table of requests waiting for a verdict.
///
/// # Why bounded, and what happens when it is full
///
/// Unbounded would mean an allocation per pending request, sized by the rate at
/// which a hostile program can call `CreateProcess`, in a driver that runs at
/// `APC_LEVEL` in the create path of every file on the machine. A driver that
/// can be made to exhaust nonpaged pool by opening files has handed an attacker
/// a bugcheck. So `SLOTS` is a compile-time constant and registering into a
/// full table fails with [`RegisterError::TableFull`]; the caller takes the
/// timeout default.
///
/// The driver's value for `SLOTS` is set out in `crates/av-driver`, where the
/// memory it costs can be seen next to the pool it is allocated from.
///
/// # The invariant that matters
///
/// **A decision is applied only to the request that asked for it.** Two things
/// enforce that, and both are needed:
///
/// 1. The slot's stored id must equal the reply's id.
///    [`RequestId`]s are never reused, so an id that matches is the same
///    request. This is what stops a late reply for an expired request being
///    applied to whatever request took that request's slot — the bug that
///    would block an innocent file because a different file's verdict arrived
///    late.
/// 2. The reply's subject and path tag must equal the request's. This is
///    defence in depth against a service whose own bookkeeping is scrambled and
///    which answers the right id with the wrong file's verdict. It is *not*
///    load-bearing for (1) — the id check already covers the recycled-slot case
///    — and the tag is a 64-bit hash rather than a digest, so it is a guard
///    against confusion and not against an adversary.
///
/// # Allocation
///
/// First free slot, lowest index first. That is a linear scan, and with the
/// driver's slot count it is a handful of comparisons over a structure already
/// in cache. A free list would be faster and would make the slot a request
/// lands in depend on the *history* of the table rather than on its current
/// contents, which makes the recycled-slot case in the tests harder to state
/// and the invariant harder to check.
pub struct PendingTable<const SLOTS: usize> {
    slots: [Option<Slot>; SLOTS],
    /// Ids recently spent, for [`ResolveOutcome::Retired`]. A ring: the oldest
    /// is overwritten.
    retired: [u64; RETIRED_RING],
    retired_next: usize,
    retired_len: usize,
    /// The next id to issue. Starts at one so that a defaulted [`RequestId`] of
    /// zero is not a valid id.
    next_id: u64,
}

impl<const SLOTS: usize> PendingTable<SLOTS> {
    /// An empty table. `const`, so the driver can put one in a `static` and the
    /// tests can build one without a fixture.
    ///
    /// Note for the driver: this returns the table *by value*, and a table of
    /// the driver's size is larger than a kernel stack. It belongs in a pool
    /// allocation or a `static`, not in a local. `crates/av-driver` says which
    /// it uses.
    pub const fn new() -> Self {
        Self {
            slots: [None; SLOTS],
            retired: [0; RETIRED_RING],
            retired_next: 0,
            retired_len: 0,
            next_id: 1,
        }
    }

    /// How many requests may be pending at once.
    pub const fn capacity(&self) -> usize {
        SLOTS
    }

    /// How many are pending now.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Whether nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|s| s.is_none())
    }

    /// Whether every slot is occupied. A caller can check this before doing the
    /// work of resolving a path, but must still handle
    /// [`RegisterError::TableFull`] — the check and the registration are not
    /// atomic, and treating them as if they were is a bug that only appears
    /// under the load that makes it matter.
    pub fn is_full(&self) -> bool {
        self.len() == SLOTS
    }

    /// Which slot an id occupies, for diagnostics and tests. `None` if it is
    /// not pending.
    pub fn slot_of(&self, id: RequestId) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| matches!(s, Some(slot) if slot.id == id))
    }

    /// How many ticks remain before `id` expires, or `None` if it is not
    /// pending. Saturates at zero.
    pub fn remaining(&self, id: RequestId, now: u64) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.id == id)
            .map(|slot| slot.deadline.saturating_sub(now))
    }

    /// Register a request and return its id.
    ///
    /// `path_tag` is [`crate::path::path_tag`] of the path the request is
    /// about. It is checked when a reply comes back — see
    /// [`ResolveOutcome::Mismatch`].
    ///
    /// A `timeout_ticks` of zero makes the request expire at `now`, which is a
    /// legitimate configuration (it means "ask, do not wait") and is why the
    /// expiry comparison in [`PendingTable::resolve`] is `>=` rather than `>`.
    pub fn register(
        &mut self,
        subject: SubjectKind,
        path_tag: u64,
        now: u64,
        timeout_ticks: u64,
    ) -> Result<RequestId, RegisterError> {
        let free = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(RegisterError::TableFull)?;

        // Checked, not wrapping. See `RegisterError::IdSpaceExhausted`.
        let raw = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(RegisterError::IdSpaceExhausted)?;
        let id = RequestId(raw);

        self.slots[free] = Some(Slot {
            id,
            deadline: now.saturating_add(timeout_ticks),
            subject,
            path_tag,
        });
        Ok(id)
    }

    /// End the oldest request that has reached its deadline and return its id.
    ///
    /// The caller applies [`DecisionPolicy::on_timeout`] to it. Returning the
    /// id rather than applying the decision here keeps this crate free of the
    /// policy — the table knows *when* a request ended, and the policy knows
    /// *what that means*, and the two are separate questions.
    pub fn next_expired(&mut self, now: u64) -> Option<RequestId> {
        let index = self
            .slots
            .iter()
            .position(|s| matches!(s, Some(slot) if now >= slot.deadline))?;
        let slot = self.slots[index].take()?;
        self.retire(slot.id);
        Some(slot.id)
    }

    /// End every request that has reached its deadline and return how many.
    ///
    /// The driver calls this on a timer and once at the top of each request, so
    /// that a table full of requests nobody ever answered drains at the rate
    /// they time out rather than staying full forever.
    pub fn expire(&mut self, now: u64) -> u32 {
        let mut count = 0;
        while self.next_expired(now).is_some() {
            count += 1;
        }
        count
    }

    /// End every request, whatever its deadline, and return how many.
    ///
    /// Used when the service disconnects — every waiting thread must be
    /// released to take the timeout default rather than waiting out a reply
    /// that can no longer come — and on unload.
    pub fn clear(&mut self) -> u32 {
        let mut count = 0;
        // By index rather than by iterator: `retire` writes to other fields of
        // `self`, and a live `&mut self.slots` borrow would forbid it.
        for index in 0..SLOTS {
            if let Some(slot) = self.slots[index].take() {
                self.retire(slot.id);
                count += 1;
            }
        }
        count
    }

    /// Apply a reply.
    ///
    /// `subject` and `path_tag` are the reply's echo of what the request was
    /// about; see [`ResolveOutcome::Mismatch`].
    pub fn resolve(
        &mut self,
        id: RequestId,
        decision: Decision,
        subject: SubjectKind,
        path_tag: u64,
        now: u64,
    ) -> ResolveOutcome {
        let Some(index) = self.slot_of(id) else {
            // Nothing live with this id. Either it was spent — in which case
            // the ring still remembers it — or it was never issued.
            return if self.was_retired(id) {
                ResolveOutcome::Retired
            } else {
                ResolveOutcome::Unknown
            };
        };

        // Read the slot out before any early return, so the borrow ends and the
        // branches below are free to mutate `self`.
        let slot = match self.slots[index] {
            Some(slot) => slot,
            // Unreachable: `slot_of` found it and nothing between the two lines
            // can clear it. Written as a match rather than an unwrap because
            // this crate is compiled into a kernel driver, where a panic is a
            // bugcheck.
            None => return ResolveOutcome::Unknown,
        };

        // The deadline is checked here as well as in `expire`, because the
        // driver may not have swept since it passed. A reply that arrives after
        // its own deadline is a reply the driver has already stopped waiting
        // for, and applying it would mean the wait's outcome depended on
        // whether a timer had fired — the same request would be answered on one
        // machine and allowed on another.
        if now >= slot.deadline {
            self.slots[index] = None;
            self.retire(slot.id);
            return ResolveOutcome::Retired;
        }

        if slot.subject != subject || slot.path_tag != path_tag {
            // Leave the request pending: a confused reply is not an answer.
            return ResolveOutcome::Mismatch;
        }

        self.slots[index] = None;
        self.retire(slot.id);
        ResolveOutcome::Applied(decision)
    }

    /// Whether an id has been spent. Scans the ring, which is 64 `u64`
    /// comparisons — done only on the path where an id was *not* found among
    /// the live slots, which is the rare one.
    fn was_retired(&self, id: RequestId) -> bool {
        self.retired[..self.retired_len.min(RETIRED_RING)].contains(&id.0)
    }

    /// Record an id as spent, overwriting the oldest when the ring is full.
    fn retire(&mut self, id: RequestId) {
        self.retired[self.retired_next] = id.0;
        self.retired_next = (self.retired_next + 1) % RETIRED_RING;
        if self.retired_len < RETIRED_RING {
            self.retired_len += 1;
        }
    }
}

impl<const SLOTS: usize> Default for PendingTable<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> fmt::Debug for PendingTable<SLOTS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately not the slots. A kernel debugger's `!analyze` output
        // wants to know how full the table is and what id is next, not the
        // sixteen paths inside it.
        f.debug_struct("PendingTable")
            .field("pending", &self.len())
            .field("capacity", &SLOTS)
            .field("next_id", &self.next_id)
            .field("retired_remembered", &self.retired_len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::path_tag;

    fn tag(path: &str) -> u64 {
        // The test paths are ASCII, so this widening is lossless and keeps the
        // fixtures readable. The real caller passes `&[u16]` straight from the
        // wire structure.
        let units: Vec<u16> = path.encode_utf16().collect();
        path_tag(&units)
    }

    const CMD: &str = r"C:\Windows\System32\cmd.exe";
    const INVOICE: &str = r"C:\Users\me\Downloads\invoice.pdf";

    /// `FltSendMessage` reads its timeout's *sign* as the meaning: positive is
    /// an absolute time counted from 1601-01-01, negative is an interval from
    /// now. A policy stated in milliseconds is an interval, so the conversion
    /// has to come out negative.
    ///
    /// This is the test that would have caught the 2026-10-01 VM run. The
    /// default policy was handed over as `+50_000_000`, i.e. the absolute
    /// instant "1601-01-01 plus five seconds", which is always in the past: the
    /// send returned `STATUS_TIMEOUT` in the instant it was made, and every
    /// reply the service produced came back `ERROR_FLT_NO_WAITER_FOR_REPLY`
    /// (`0x801F0020`). Nothing looked broken — the service scanned the file,
    /// decided, and logged a decision — which is why the sign, and not the
    /// protocol, was the thing to check.
    #[test]
    fn the_default_policy_is_a_relative_interval_not_an_absolute_instant() {
        let timeout = DecisionPolicy::DEFAULT.relative_timeout_100ns();
        assert!(
            timeout < 0,
            "a positive timeout is an absolute time since 1601-01-01, which has already passed"
        );
        assert_eq!(timeout, -50_000_000, "five seconds, in 100-nanosecond units");
        assert_eq!(
            timeout,
            -(DecisionPolicy::DEFAULT_TIMEOUT_MS as i64) * UNITS_PER_MS,
            "the magnitude is the policy's own milliseconds, converted"
        );
    }

    /// The ceiling converts the same way, so a longer wait is a longer wait and
    /// not a more distant date in the past.
    #[test]
    fn the_longest_permitted_wait_is_the_most_negative() {
        let max = DecisionPolicy { timeout_ms: u32::MAX, on_timeout: Decision::Allow }
            .clamp()
            .relative_timeout_100ns();
        assert_eq!(max, -(DecisionPolicy::MAX_TIMEOUT_MS as i64) * UNITS_PER_MS);
        assert!(max < DecisionPolicy::DEFAULT.relative_timeout_100ns());
    }

    /// The test the module's whole design exists for.
    ///
    /// A request times out. Its slot is handed to a different file's request.
    /// The first request's verdict arrives late. If the driver applied replies
    /// by *slot* rather than by *id*, that verdict — `Block`, for `cmd.exe` —
    /// would be applied to the second file, and the second file is the one the
    /// user is waiting on.
    ///
    /// This is the most dangerous bug this unit can have: the driver would
    /// refuse an innocent file on the strength of a malicious one's verdict,
    /// and it would be unreproducible, because it needs a timeout and a
    /// subsequent request that happens to land on the same slot.
    #[test]
    fn a_reply_for_an_expired_request_is_not_applied_to_its_replacement() {
        let mut table = PendingTable::<4>::new();
        let policy = DecisionPolicy::default();

        // Request A: cmd.exe, at tick 0, with a deadline of tick 5000.
        let a = table
            .register(SubjectKind::File, tag(CMD), 0, policy.deadline_ticks(0))
            .expect("empty table");
        assert_eq!(table.slot_of(a), Some(0));

        // A's service never answers and A expires.
        assert_eq!(
            table.expire(5_000),
            1,
            "A should have expired at its deadline"
        );
        assert_eq!(table.len(), 0);
        assert_eq!(table.slot_of(a), None, "A's slot must be free after expiry");

        // Request B: an ordinary document, issued later. First-free allocation
        // puts it in the slot A just vacated.
        let b = table
            .register(
                SubjectKind::File,
                tag(INVOICE),
                5_001,
                policy.deadline_ticks(5_001),
            )
            .expect("table has three free slots");
        assert_eq!(table.slot_of(b), Some(0), "B must have taken A's slot");
        assert_ne!(a, b, "ids are never reused");

        // A's verdict finally arrives, saying Block.
        let outcome = table.resolve(a, Decision::Block, SubjectKind::File, tag(CMD), 5_002);
        assert_eq!(
            outcome,
            ResolveOutcome::Retired,
            "the late verdict for A must be discarded"
        );

        // And B is untouched: still pending, still answerable, and answered
        // with what B's own scan said.
        assert_eq!(table.slot_of(b), Some(0), "B must still be pending");
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.resolve(b, Decision::Allow, SubjectKind::File, tag(INVOICE), 5_003),
            ResolveOutcome::Applied(Decision::Allow),
        );
        assert!(table.is_empty());
    }

    /// The same hazard one step further: the recycled slot must also not be
    /// ended by the stale reply. In the test above `Retired` discards and
    /// leaves B alone; this asserts the *slot contents* directly, so a future
    /// change that discarded the decision but cleared the slot anyway fails
    /// here even if it still returns `Retired`.
    #[test]
    fn a_stale_reply_does_not_clear_the_replacement_slot() {
        let mut table = PendingTable::<4>::new();
        let a = table
            .register(SubjectKind::File, tag(CMD), 0, 10)
            .expect("room");
        assert_eq!(table.expire(10), 1);
        let b = table
            .register(SubjectKind::File, tag(INVOICE), 11, 10)
            .expect("room");
        assert_eq!(table.slot_of(b), Some(0));

        // The stale reply arrives, repeated, in every shape: at the old
        // deadline, long after, with matching subject and tag, with a decision
        // of each kind.
        for (decision, now) in [
            (Decision::Block, 10),
            (Decision::Allow, 11),
            (Decision::Block, u64::MAX),
        ] {
            assert_eq!(
                table.resolve(a, decision, SubjectKind::File, tag(CMD), now),
                ResolveOutcome::Retired,
                "a={a} now={now}"
            );
            assert_eq!(
                table.slot_of(b),
                Some(0),
                "the stale reply cleared B's slot at now={now}"
            );
            assert_eq!(table.len(), 1);
        }
    }

    /// A reply that arrives after the deadline but before the sweep must be
    /// discarded by `resolve` itself. If it were not, whether a request was
    /// answered would depend on whether a timer happened to have fired, and the
    /// same machine state would produce different outcomes on different runs.
    #[test]
    fn resolve_enforces_the_deadline_without_waiting_for_a_sweep() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 100)
            .expect("room");

        // One tick past the deadline, no `expire` call.
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::File, tag(CMD), 100),
            ResolveOutcome::Retired,
            "a reply at the deadline must be discarded"
        );
        assert!(table.is_empty(), "and must have ended the request");

        // One tick before, the same reply is applied.
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 100)
            .expect("room");
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::File, tag(CMD), 99),
            ResolveOutcome::Applied(Decision::Block),
        );
    }

    /// A timeout of zero expires immediately, which is a legitimate
    /// configuration meaning "ask, do not wait". The comparison is `>=` so that
    /// it does, and a request registered with a zero timeout can never be
    /// answered — by the time a reply could arrive, the deadline has passed.
    #[test]
    fn a_zero_timeout_is_a_valid_poll() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 7, 0)
            .expect("room");
        assert_eq!(table.remaining(id, 7), Some(0));
        assert_eq!(
            table.resolve(id, Decision::Allow, SubjectKind::File, tag(CMD), 7),
            ResolveOutcome::Retired
        );
    }

    /// `remaining` counts down and saturates rather than wrapping.
    #[test]
    fn remaining_saturates_at_zero() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 1_000, 250)
            .expect("room");
        assert_eq!(table.remaining(id, 1_000), Some(250));
        assert_eq!(table.remaining(id, 1_100), Some(150));
        assert_eq!(table.remaining(id, 1_250), Some(0));
        assert_eq!(table.remaining(id, 9_999), Some(0), "must not wrap");
        assert_eq!(table.remaining(RequestId(999), 0), None, "not pending");
    }

    /// A reply for an id that was never issued is `Unknown`, not `Retired`.
    /// The two mean different things to an operator — one is a slow service,
    /// the other is a peer replying to a request nobody made — and collapsing
    /// them would hide a protocol violation inside a performance number.
    #[test]
    fn an_id_that_was_never_issued_is_unknown_not_retired() {
        let mut table = PendingTable::<4>::new();
        assert_eq!(
            table.resolve(RequestId(1), Decision::Allow, SubjectKind::File, 0, 0),
            ResolveOutcome::Unknown,
            "id 1 has not been issued yet"
        );
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 10)
            .expect("room");
        assert_eq!(id, RequestId(1), "the first id issued is one");
        assert_eq!(table.expire(10), 1);
        // Now it has been issued and spent.
        assert_eq!(
            table.resolve(id, Decision::Allow, SubjectKind::File, tag(CMD), 11),
            ResolveOutcome::Retired
        );
        // And an id past the issued range is still unknown.
        assert_eq!(
            table.resolve(RequestId(0), Decision::Allow, SubjectKind::File, 0, 0),
            ResolveOutcome::Unknown,
            "zero is never issued"
        );
    }

    /// An applied reply also retires the id, so a duplicate reply is `Retired`
    /// rather than `Unknown` — the service *did* answer, twice, and that is the
    /// less alarming of the two diagnoses.
    #[test]
    fn a_duplicate_reply_is_retired_not_unknown() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 100)
            .expect("room");
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::File, tag(CMD), 1),
            ResolveOutcome::Applied(Decision::Block)
        );
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::File, tag(CMD), 2),
            ResolveOutcome::Retired,
            "the same reply twice must not be applied twice"
        );
    }

    /// A reply naming a different file is discarded and leaves the request
    /// pending, because a confused reply is not an answer.
    #[test]
    fn a_reply_describing_a_different_file_is_discarded_and_leaves_the_request_pending() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 100)
            .expect("room");

        // Right id, wrong path.
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::File, tag(INVOICE), 1),
            ResolveOutcome::Mismatch
        );
        assert_eq!(table.slot_of(id), Some(0), "the request must stay pending");

        // Right id, right path, wrong subject.
        assert_eq!(
            table.resolve(id, Decision::Block, SubjectKind::Process, tag(CMD), 2),
            ResolveOutcome::Mismatch
        );
        assert_eq!(table.slot_of(id), Some(0));

        // The real answer still gets through.
        assert_eq!(
            table.resolve(id, Decision::Allow, SubjectKind::File, tag(CMD), 3),
            ResolveOutcome::Applied(Decision::Allow)
        );
    }

    /// A mismatched reply must not extend the deadline either — a service that
    /// answered nonsense cannot buy its request more time by doing so.
    #[test]
    fn a_mismatched_reply_does_not_extend_the_deadline() {
        let mut table = PendingTable::<4>::new();
        let id = table
            .register(SubjectKind::File, tag(CMD), 0, 50)
            .expect("room");
        for now in [1, 10, 20] {
            assert_eq!(
                table.resolve(id, Decision::Block, SubjectKind::File, tag(INVOICE), now),
                ResolveOutcome::Mismatch
            );
        }
        // The original deadline still stands.
        assert_eq!(table.expire(50), 1);
        assert_eq!(
            table.resolve(id, Decision::Allow, SubjectKind::File, tag(CMD), 51),
            ResolveOutcome::Retired
        );
    }

    /// Registering into a full table fails, does not evict, and does not
    /// disturb what is already there. The caller takes the timeout default.
    #[test]
    fn a_full_table_refuses_rather_than_evicting() {
        let mut table = PendingTable::<2>::new();
        let first = table
            .register(SubjectKind::File, tag(CMD), 0, 10_000)
            .expect("room");
        let second = table
            .register(SubjectKind::File, tag(INVOICE), 0, 10_000)
            .expect("room");
        assert!(table.is_full());

        assert_eq!(
            table.register(SubjectKind::File, tag(r"C:\third.exe"), 0, 10_000),
            Err(RegisterError::TableFull)
        );

        // The two that were there are untouched and still answerable.
        assert_eq!(table.len(), 2);
        assert_eq!(table.slot_of(first), Some(0));
        assert_eq!(table.slot_of(second), Some(1));
        assert_eq!(
            table.resolve(second, Decision::Block, SubjectKind::File, tag(INVOICE), 1),
            ResolveOutcome::Applied(Decision::Block)
        );
    }

    /// Ids increase by one and are never reused, including across a wrap of the
    /// retired ring — which is the case where a naive "reuse the index"
    /// implementation would start handing out ids that are still remembered as
    /// spent.
    #[test]
    fn ids_are_monotonic_and_never_reused_across_ring_wraparound() {
        let mut table = PendingTable::<2>::new();
        let mut seen: Vec<u64> = Vec::new();
        for i in 0..(RETIRED_RING * 2) {
            let path = format!(r"C:\file{i}.exe");
            let id = table
                .register(SubjectKind::File, tag(&path), 0, 1)
                .expect("expired each round");
            assert!(!seen.contains(&id.get()), "id {} was reused", id.get());
            seen.push(id.get());
            table.expire(1);
        }
        assert!(
            seen.windows(2).all(|w| w[1] == w[0] + 1),
            "ids must be consecutive"
        );
    }

    /// The retired ring is finite and says so through its behaviour: once 64
    /// further requests have been retired, an old id reports `Unknown`. Both
    /// outcomes discard, so the ring's size is a diagnostic-accuracy question
    /// and not a correctness one — which is what the test pins.
    #[test]
    fn the_retired_ring_forgets_the_oldest_id_and_then_reports_unknown() {
        let mut table = PendingTable::<1>::new();
        let oldest = table
            .register(SubjectKind::File, tag(CMD), 0, 0)
            .expect("room");
        table.expire(0);

        // Fill and retire the ring.
        for i in 0..RETIRED_RING {
            let path = format!(r"C:\f{i}");
            let id = table
                .register(SubjectKind::File, tag(&path), 0, 0)
                .expect("room");
            table.expire(0);
            assert_eq!(
                table.resolve(id, Decision::Allow, SubjectKind::File, tag(&path), 0),
                ResolveOutcome::Retired
            );
        }

        // `oldest` has been pushed out of the ring.
        assert_eq!(
            table.resolve(oldest, Decision::Block, SubjectKind::File, tag(CMD), 0),
            ResolveOutcome::Unknown,
            "the ring is finite and the oldest id is gone"
        );

        // But it is still discarded — `Unknown` is not a licence to apply it.
        assert!(table.is_empty());
    }

    /// `clear` ends everything, which is what a service disconnect needs: every
    /// waiting thread must be released to take the default rather than waiting
    /// out a reply that can no longer come.
    #[test]
    fn clear_ends_every_pending_request() {
        let mut table = PendingTable::<4>::new();
        let ids: Vec<RequestId> = (0..3)
            .map(|i| {
                let path = format!(r"C:\f{i}");
                table
                    .register(SubjectKind::File, tag(&path), 0, 10_000)
                    .expect("room")
            })
            .collect();
        assert_eq!(table.len(), 3);
        assert_eq!(table.clear(), 3);
        assert!(table.is_empty());
        for id in ids {
            assert_eq!(
                table.resolve(id, Decision::Block, SubjectKind::File, 0, 1),
                ResolveOutcome::Retired
            );
        }
    }

    /// Expiry is a count and drains completely, so a caller looping on it
    /// terminates.
    #[test]
    fn expire_drains_everything_that_is_due_and_counts_it() {
        let mut table = PendingTable::<8>::new();
        for i in 0..5 {
            let path = format!(r"C:\f{i}");
            let timeout = if i < 3 { 100 } else { 10_000 };
            table
                .register(SubjectKind::File, tag(&path), 0, timeout)
                .expect("room");
        }
        assert_eq!(table.expire(50), 0, "nothing is due yet");
        assert_eq!(table.len(), 5);
        assert_eq!(table.expire(100), 3, "three are due at their deadline");
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.expire(u64::MAX),
            2,
            "sweeping far ahead drains the rest"
        );
        assert_eq!(table.expire(u64::MAX), 0);
        assert!(table.is_empty());
    }

    /// A deadline computed from a tick source near `u64::MAX` must not wrap
    /// into the past. A wrap would turn the longest possible configured wait
    /// into an instant timeout, and the symptom — every request allowed
    /// instantly — looks like a service that is simply fast.
    #[test]
    fn a_deadline_near_the_end_of_the_tick_space_does_not_wrap() {
        let policy = DecisionPolicy {
            timeout_ms: DecisionPolicy::MAX_TIMEOUT_MS,
            on_timeout: Decision::Allow,
        };
        let deadline = policy.deadline_ticks(u64::MAX - 1);
        assert_eq!(deadline, u64::MAX, "must saturate, not wrap");
        assert!(deadline >= u64::MAX - 1);

        // And `register` saturates too, so a saturated deadline is reachable
        // through the public API rather than only through the helper.
        let mut table = PendingTable::<1>::new();
        let id = table
            .register(SubjectKind::File, 0, u64::MAX - 1, policy.deadline_ticks(0))
            .expect("room");
        assert!(table.remaining(id, u64::MAX - 1).is_some());
        assert_eq!(
            table.expire(u64::MAX - 1),
            0,
            "not due at the saturation point"
        );
    }

    /// The table's own saturation: a `timeout_ticks` big enough to overflow
    /// must produce a deadline far in the future rather than one in the past.
    #[test]
    fn a_register_timeout_that_would_overflow_saturates() {
        let mut table = PendingTable::<1>::new();
        let id = table
            .register(SubjectKind::File, 0, 5, u64::MAX)
            .expect("room");
        assert_eq!(table.expire(5), 0, "must not be due");
        assert_eq!(
            table.expire(u64::MAX),
            1,
            "and is due at the end of the space"
        );
        assert_eq!(table.remaining(id, 0), None, "already expired");
    }

    /// The default policy allows on timeout. Asserted separately from the
    /// `Default` impl so that a change to one without the other fails
    /// something.
    #[test]
    fn the_default_policy_allows_on_timeout() {
        assert_eq!(DecisionPolicy::default().on_timeout, Decision::Allow);
        assert_eq!(DecisionPolicy::DEFAULT.on_timeout, Decision::Allow);
        assert_eq!(DecisionPolicy::default().timeout_ms, 5_000);
        assert_eq!(Decision::default(), Decision::Allow);
        // The dangerous one exists, is reachable, and is not the default.
        assert_eq!(DecisionPolicy::FAIL_CLOSED.on_timeout, Decision::Block);
        assert_ne!(DecisionPolicy::FAIL_CLOSED, DecisionPolicy::default());
    }

    /// Clamping bounds the wait above and leaves everything else alone.
    #[test]
    fn timeout_clamping_bounds_the_wait_above_only() {
        let too_long = DecisionPolicy {
            timeout_ms: u32::MAX,
            on_timeout: Decision::Block,
        };
        assert_eq!(too_long.clamp().timeout_ms, DecisionPolicy::MAX_TIMEOUT_MS);
        assert_eq!(
            too_long.clamp().on_timeout,
            Decision::Block,
            "clamping must not touch the policy's direction"
        );

        let fine = DecisionPolicy {
            timeout_ms: 1_234,
            on_timeout: Decision::Allow,
        };
        assert_eq!(fine.clamp(), fine);

        let zero = DecisionPolicy {
            timeout_ms: 0,
            on_timeout: Decision::Allow,
        };
        assert_eq!(
            zero.clamp(),
            zero,
            "zero is a valid poll, not a value to raise"
        );
    }

    /// An unrecognised decision must decode to `Allow`. This is the direction
    /// that cannot brick a machine, and it is the opposite direction from
    /// `VerdictCode::from_wire_lossy`, which is why both have their own test.
    #[test]
    fn an_unknown_decision_decodes_to_allow() {
        assert_eq!(Decision::from_wire(2), None);
        assert_eq!(Decision::from_wire_lossy(2), Decision::Allow);
        assert_eq!(Decision::from_wire_lossy(u32::MAX), Decision::Allow);
        assert_eq!(Decision::from_wire_lossy(1), Decision::Block);
        assert_eq!(Decision::from_wire_lossy(0), Decision::Allow);
    }

    /// A `Debug` rendering of the table must not include the slots: the
    /// interesting facts are how full it is and what id is next.
    #[test]
    fn table_debug_reports_occupancy_not_contents() {
        let mut table = PendingTable::<8>::new();
        table
            .register(SubjectKind::File, tag(CMD), 0, 100)
            .expect("room");
        let rendered = format!("{table:?}");
        assert!(rendered.contains("pending: 1"), "{rendered}");
        assert!(rendered.contains("capacity: 8"), "{rendered}");
        assert!(!rendered.contains("cmd"), "the path leaked into Debug");
    }

    /// The `RequestId` renderings.
    #[test]
    fn request_id_displays_as_its_number() {
        assert_eq!(RequestId(42).to_string(), "42");
        assert_eq!(RequestId(42).get(), 42);
        assert!(RequestId(1) < RequestId(2));
    }
}
