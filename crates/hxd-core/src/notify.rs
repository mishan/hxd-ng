//! Where push notifications attach.
//!
//! `docs/push-notifications.md` §9 stages the gateway itself — the device
//! registry, the payload shaping, the uniqush HTTP client — as later work
//! in its own crate. What belongs here, and only here, is the *decision*:
//! that §11 of that document names the hazard exactly, "the notify
//! decision must live in the domain rather than in `hxd-ng-session`, or
//! the legacy path silently skips it." A private message arriving for
//! someone who is not attentive is one rule, computed in one place, and
//! both wires reach it by calling the same function.
//!
//! **The trait is synchronous, and it deviates from the sketch in
//! push-notifications.md §4 on purpose.** That sketch has it
//! `#[async_trait]`; it cannot be, because [`crate::Core`] is sync all the
//! way down and its state sits behind a `std::sync::Mutex`. But the
//! deviation is smaller than it looks: §4 already requires that `notify`
//! never be awaited on the message path — "the gateway call is spawned,
//! its outcome logged, its failure not the sender's problem", because
//! uniqush's `/push` answers only after a first delivery attempt at every
//! delivery point and the Web Push path allows tens of seconds per point.
//! So the spawn happens either way. This puts it on the implementation's
//! side of the trait, where the runtime handle lives, instead of on the
//! domain's.
//!
//! The contract, therefore: **`notify` must not block.** An implementation
//! hands the work to a task and returns.
//!
//! There is no `NoopGateway`. A gateway that does nothing and an `Option`
//! that means the same thing are one state too many; a `Core` with no
//! gateway configured is the no-op, and that is the default.

use crate::inbox::MessageId;

/// A private message that reached someone who wasn't watching.
///
/// It carries the message in full. Content policy — whether the push says
/// "Message from alice", the whole text, or only that something arrived —
/// is the gateway's to apply when it builds the payload, because the
/// answer differs per backend: Web Push encrypts to the device's own
/// keypair and the provider cannot read it, while APNs and FCM hand the
/// payload to Apple or Google in the clear (push-notifications.md §6).
/// The domain does not pre-empt that choice by withholding the text.
#[derive(Debug, Clone, Copy)]
pub struct Notification<'a> {
    /// Whose mailbox this arrived in — the address the gateway maps to a
    /// subscriber id.
    ///
    /// **A gateway keys its device registry on the fingerprint where
    /// there is one**, not on the login beside it. uids recycle in
    /// minutes and logins recycle on a rename, and a push addressed by
    /// either is a stranger's private message on the wrong person's
    /// phone — the failure push-notifications.md §5 calls the worst bug
    /// this subsystem can have. The login is there for the log.
    pub to: &'a crate::inbox::Mailbox,
    /// The sender, when the sender has a mailbox to be replied to.
    pub from: Option<&'a crate::inbox::Mailbox>,
    /// The sender's nickname as displayed when it was sent.
    pub from_nick: &'a str,
    pub text: &'a str,
    /// The stored message, so a client woken by this can name it.
    pub id: MessageId,
    /// The recipient's unread count *after* this message — a badge number
    /// the gateway can pass through without asking us again.
    pub unread: usize,
}

/// The seam `hxd-push-uniqush` (or any other gateway) implements.
pub trait NotificationGateway: Send + Sync + 'static {
    /// A message arrived for someone who is not attentive.
    ///
    /// **Best effort, and must not block.** It is called on the private
    /// message path with no lock held, and a slow provider must not become
    /// this server's latency: an implementation spawns and returns. A push
    /// that never arrives is a degraded notification, not a lost message —
    /// the message is in the inbox either way.
    fn notify(&self, n: &Notification<'_>);
}
